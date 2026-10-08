"""SendGrid as a sink (``docs/EPIC3_DESIGN.md`` §4.2).

A sink of kind ``sendgrid`` admits one operation, ``mail.send``, with a strict
payload of its own: ``to``, ``cc`` and ``bcc`` (lists of addresses), ``from``
and ``reply_to`` (an address each), ``subject``, ``text`` and ``html`` (at
least one of the two), and ``categories``. An address is ``{"email": ...}``
with an optional ``"name"``.

**At most once, by default.** SendGrid has no idempotency keys: a call made
twice sends the email twice. So the kind's sinks have ``idempotency = "none"``,
always, and ``unknown_outcome = "dead-letter"`` unless configured otherwise:
a call whose outcome is unknown (a timeout after sending, a 5xx, a relay that
died mid-call) is not made again; the message is dead, for an operator to
resolve. A sink configured to ``redeliver`` accepts a duplicate email instead
of a lost one.

**The adapter** (:class:`SendGridAdapter`) maps the payload to SendGrid's v3
body, and adds ``custom_args`` carrying the message's id and idempotency key,
so a duplicate can be traced in SendGrid's event webhook. ``sandbox`` sets
``mail_settings.sandbox_mode``: SendGrid validates the request and sends
nothing, for live tests.

=====================  ==============  ======================================
SendGrid answered      Outcome
=====================  ==============  ======================================
2xx                    ``delivered``   ``X-Message-Id`` is the ``remote_ref``
429                    ``retryable``   no sooner than ``X-RateLimit-Reset``
5xx                    ``unknown``     SendGrid may have accepted the email
any other status       ``permanent``   invalid, unauthorized, too large
=====================  ==============  ======================================
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Final

from agentgov.receipts.canonical import loads_strict

from interlock.adapters import Reply, exchange, trace_headers
from interlock.outbound import DEAD_LETTER, OperationSpec, SinkSpec, placeholders
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = [
    "API",
    "CATALOG",
    "MAIL_SEND",
    "SendGridAdapter",
    "classify",
    "compensation_problem",
    "payload_problem",
    "sendgrid_sink",
    "v3_body",
]

API: Final = "https://api.sendgrid.com"
MAIL_SEND: Final = "mail.send"
MAX_RECIPIENTS: Final = 1000

IDEMPOTENCY: Final = "none"
"""SendGrid has no idempotency keys: a call made twice sends twice."""
UNKNOWN_OUTCOME: Final = DEAD_LETTER
"""And so, by default, an unknown outcome is not redelivered: at most once."""

_ADDRESS: Final = {
    "type": "object",
    "additionalProperties": False,
    "required": ["email"],
    "properties": {
        "email": {
            "type": "string",
            "minLength": 3,
            "maxLength": 320,
            "pattern": r"\A[^@\s]+@[^@\s]+\Z",
        },
        "name": {"type": "string", "minLength": 1, "maxLength": 256},
    },
}
_ADDRESSES: Final = {"type": "array", "items": _ADDRESS, "minItems": 1, "maxItems": MAX_RECIPIENTS}

CATALOG: Final[Mapping[str, OperationSpec]] = {
    MAIL_SEND: OperationSpec(
        MAIL_SEND,
        schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["to", "from", "subject"],
            "properties": {
                "to": _ADDRESSES,
                "cc": _ADDRESSES,
                "bcc": _ADDRESSES,
                "from": _ADDRESS,
                "reply_to": _ADDRESS,
                "subject": {"type": "string", "minLength": 1, "maxLength": 998},
                "text": {"type": "string", "minLength": 1},
                "html": {"type": "string", "minLength": 1},
                "categories": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 255},
                    "maxItems": 10,
                },
            },
        },
    ),
}


def sendgrid_sink(name: str = "sendgrid", **settings: Any) -> SinkSpec:
    """A sink of kind ``sendgrid``: ``mail.send``, at most once unless
    ``unknown_outcome = "redeliver"`` is passed.

    :param settings: Any other :class:`~interlock.outbound.SinkSpec` field.
    """
    return SinkSpec(name, (CATALOG[MAIL_SEND],), kind="sendgrid", **settings)


def payload_problem(operation: str, payload: Mapping[str, Any]) -> str | None:
    """What the schema subset cannot say about an email, or ``None``."""
    if "text" not in payload and "html" not in payload:
        return "an email has a text body, an html body, or both"
    recipients = sum(len(payload.get(field) or ()) for field in ("to", "cc", "bcc"))
    if recipients > MAX_RECIPIENTS:
        return f"an email has at most {MAX_RECIPIENTS} recipients, not {recipients}"
    return None


def compensation_problem(
    operation: str, payload: Mapping[str, Any], compensation: Mapping[str, Any] | None
) -> str | None:
    """An email cannot be unsent: nothing to check."""
    return None


def v3_body(payload: Mapping[str, Any], delivery: Delivery, *, sandbox: bool) -> dict[str, Any]:
    """SendGrid's v3 ``mail/send`` body for ``payload``."""
    personalization: dict[str, Any] = {
        "to": [dict(a) for a in payload["to"]],
        "custom_args": {
            "interlock_message_id": str(delivery.message_id),
            "interlock_idempotency_key": delivery.idempotency_key,
        },
    }
    for field in ("cc", "bcc"):
        if field in payload:
            personalization[field] = [dict(a) for a in payload[field]]
    body: dict[str, Any] = {
        "personalizations": [personalization],
        "from": dict(payload["from"]),
        "subject": payload["subject"],
        # text/plain first: SendGrid refuses another order.
        "content": [
            {"type": kind, "value": payload[field]}
            for field, kind in (("text", "text/plain"), ("html", "text/html"))
            if field in payload
        ],
    }
    if "reply_to" in payload:
        body["reply_to"] = dict(payload["reply_to"])
    if "categories" in payload:
        body["categories"] = list(payload["categories"])
    if sandbox:
        body["mail_settings"] = {"sandbox_mode": {"enable": True}}
    return body


_MESSAGE_ID: Final = re.compile(r"\A[A-Za-z0-9_.\-]{1,255}\Z")


class SendGridAdapter:
    """Delivers a SendGrid sink's emails through the v3 API.

    :param api_key: The API key, from the relay's environment; a callable is
        asked on every call.
    :param base_url: SendGrid's API. A test points it at a fake.
    :param sandbox: Validate and send nothing (``sandbox_mode``).
    """

    __slots__ = ("_base", "_key", "_sandbox")

    def __init__(
        self, api_key: str | Callable[[], str], *, base_url: str = API, sandbox: bool = False
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"an endpoint is an http(s) URL, not {base_url!r}")
        if not api_key:
            raise ValueError("a SendGrid adapter needs an API key")
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._sandbox = sandbox

    def send(self, delivery: Delivery) -> DeliveryResult:
        if delivery.operation != MAIL_SEND:
            return DeliveryResult(
                PERMANENT, detail=f"SendGrid has no operation {delivery.operation!r}"
            )
        payload = loads_strict(delivery.payload)
        if not isinstance(payload, Mapping) or placeholders(payload):
            return DeliveryResult(
                PERMANENT,
                detail="the payload holds an unbound placeholder, which is never sent",
            )
        key = self._key() if callable(self._key) else self._key
        body = json.dumps(
            v3_body(payload, delivery, sandbox=self._sandbox),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        reply = exchange(
            self._base + "/v3/mail/send",
            body,
            {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                **trace_headers(delivery),
            },
            "POST",
            delivery.timeout,
        )
        if isinstance(reply, DeliveryResult):
            return reply
        return classify(reply)


def classify(reply: Reply) -> DeliveryResult:
    status, digest = reply.status, reply.digest
    if 200 <= status < 300:
        ref = reply.header("X-Message-Id")
        return DeliveryResult(
            DELIVERED,
            status_code=status,
            response_digest=digest,
            remote_ref=ref if ref and _MESSAGE_ID.match(ref) else None,
        )
    if status == 429:
        return DeliveryResult(
            RETRYABLE,
            status_code=status,
            response_digest=digest,
            detail="HTTP 429: rate limited",
            retry_after=_reset(reply.header("X-RateLimit-Reset")),
        )
    if status >= 500:
        return DeliveryResult(
            UNKNOWN,
            status_code=status,
            response_digest=digest,
            detail=f"HTTP {status}: SendGrid may have accepted the email",
        )
    return DeliveryResult(
        PERMANENT, status_code=status, response_digest=digest, detail=f"HTTP {status}"
    )


def _reset(value: str | None) -> float | None:
    """``X-RateLimit-Reset``, a Unix time, as seconds from now."""
    if not value or not value.strip().isdigit():
        return None
    return max(0.0, int(value.strip()) - time.time())
