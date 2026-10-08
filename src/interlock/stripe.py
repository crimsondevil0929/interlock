"""Stripe as a sink (``docs/EPIC3_DESIGN.md`` §4.1).

A sink of kind ``stripe`` admits Stripe's operations and no others, each with
a strict payload schema of its own. Configuration names the operations a sink
allows (:func:`stripe_sink`); it never writes their schemas.

===========================  ==============================  =========================
Operation                    Calls                           Undone by
===========================  ==============================  =========================
``payment_intents.create``   ``POST /v1/payment_intents``    ``refunds.create``
``charges.create``           ``POST /v1/charges``            ``refunds.create``
``refunds.create``           ``POST /v1/refunds``            nothing: a refund is final
===========================  ==============================  =========================

**The compensation rule.** A request that takes money carries the refund that
gives it back, written into the plan before the charge is staged (E4-3), and
the refund undoes *this* charge and no more:

- it names the charge by the placeholder ``{"$bind": "delivered.id"}``: in
  ``payment_intent`` for a payment intent, in ``charge`` for a charge. Never a
  literal id, so a plan cannot point its undo at another customer's payment.
  ``interlock outbox compensate`` binds it to the id Stripe returned when the
  charge was delivered;
- it refunds at most the charge's ``amount``, or leaves ``amount`` out (all of
  it);
- it names no ``currency``: a refund is in the charge's.

:func:`compensation_problem` is the rule. The registry applies it at
admission; the outbox applies it again when the request is written, from the
sink kind the database holds, so an engine with a stale registry cannot stage
a charge without its refund either.

**The adapter** (:class:`StripeAdapter`) sends Stripe's form encoding, built
deterministically from the canonical payload, with the request's idempotency
key in ``Idempotency-Key``, a pinned ``Stripe-Version``, and the secret key
from the relay's environment. It classifies the reply:

=======================================  ==============  ===============================
Stripe answered                          Outcome         Why
=======================================  ==============  ===============================
2xx, a replay (``Idempotent-Replayed``)  ``delivered``   the object's ``id`` is recorded
                                                         as the call's ``remote_ref``
an ``idempotency_error`` (not a 409)     ``permanent``   the key was first used with
                                                         other parameters: the request
                                                         stored is not the one sent
5xx                                      ``unknown``     Stripe may have acted
4xx, ``Stripe-Should-Retry: true``       ``retryable``   Stripe says so
4xx, ``Stripe-Should-Retry: false``      ``permanent``   Stripe says so
409, 429                                 ``retryable``   a call with the key in flight;
                                                         a rate limit
any other 4xx                            ``permanent``   declined, invalid, unauthorized
=======================================  ==============  ===============================

A 5xx is ``unknown`` whatever else the reply says: Stripe stores the result of
a request that began executing, and a later call with the key replays it, so
the sink's ``unknown_outcome`` decides, with the idempotency key keeping a
redelivery to one charge.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from agentgov.receipts.canonical import loads_strict

from interlock.adapters import Reply, exchange, retry_after_seconds, trace_headers
from interlock.outbound import NONE_POSSIBLE, REDELIVER, OperationSpec, SinkSpec, placeholders
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = [
    "API",
    "CATALOG",
    "CHARGES",
    "CHARGES_CREATE",
    "PAYMENT_INTENTS_CREATE",
    "REFUNDS_CREATE",
    "STRIPE_VERSION",
    "StripeAdapter",
    "classify",
    "compensation_problem",
    "form_encode",
    "payload_problem",
    "stripe_sink",
]

API: Final = "https://api.stripe.com"
STRIPE_VERSION: Final = "2024-06-20"
"""The API version every call pins: a payload is validated against the
version it will be read by, never whatever the account defaults to."""

PAYMENT_INTENTS_CREATE: Final = "payment_intents.create"
CHARGES_CREATE: Final = "charges.create"
REFUNDS_CREATE: Final = "refunds.create"
CHARGES: Final = frozenset({PAYMENT_INTENTS_CREATE, CHARGES_CREATE})
"""The operations that take money, and so carry a refund."""

IDEMPOTENCY: Final = "header"
"""Stripe honours ``Idempotency-Key``: a redelivery replays, never re-charges."""
UNKNOWN_OUTCOME: Final = REDELIVER
"""And so an unknown outcome is redelivered by default: the key keeps it to
one charge."""

_PATHS: Final = {
    PAYMENT_INTENTS_CREATE: "/v1/payment_intents",
    CHARGES_CREATE: "/v1/charges",
    REFUNDS_CREATE: "/v1/refunds",
}
_CHARGED_AS: Final = {PAYMENT_INTENTS_CREATE: "payment_intent", CHARGES_CREATE: "charge"}

_ID: Final = {"type": "string", "minLength": 3, "maxLength": 255, "pattern": r"\A[A-Za-z0-9_]+\Z"}
_AMOUNT: Final = {"type": "integer", "minimum": 1, "maximum": 99_999_999}
_CURRENCY: Final = {"type": "string", "pattern": r"\A[a-z]{3}\Z"}
_TEXT: Final = {"type": "string", "maxLength": 1000}
_EMAIL: Final = {"type": "string", "maxLength": 512, "pattern": r"\A[^@\s]+@[^@\s]+\Z"}
_METADATA: Final = {"type": "object"}
"""Up to 50 string values (checked by :func:`_metadata_problem`: the schema
subset cannot type the values of arbitrary keys)."""

CATALOG: Final[Mapping[str, OperationSpec]] = {
    PAYMENT_INTENTS_CREATE: OperationSpec(
        PAYMENT_INTENTS_CREATE,
        compensation=REFUNDS_CREATE,
        schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["amount", "currency"],
            "properties": {
                "amount": _AMOUNT,
                "currency": _CURRENCY,
                "customer": _ID,
                "payment_method": _ID,
                "payment_method_types": {
                    "type": "array",
                    "items": {"type": "string", "pattern": r"\A[a-z_]+\Z"},
                    "minItems": 1,
                    "maxItems": 10,
                },
                "confirm": {"type": "boolean"},
                "off_session": {"type": "boolean"},
                "description": _TEXT,
                "statement_descriptor_suffix": {"type": "string", "maxLength": 22},
                "receipt_email": _EMAIL,
                "metadata": _METADATA,
            },
        },
    ),
    CHARGES_CREATE: OperationSpec(
        CHARGES_CREATE,
        compensation=REFUNDS_CREATE,
        schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["amount", "currency"],
            "properties": {
                "amount": _AMOUNT,
                "currency": _CURRENCY,
                "customer": _ID,
                "source": _ID,
                "description": _TEXT,
                "statement_descriptor_suffix": {"type": "string", "maxLength": 22},
                "receipt_email": _EMAIL,
                "metadata": _METADATA,
            },
        },
    ),
    REFUNDS_CREATE: OperationSpec(
        REFUNDS_CREATE,
        compensation=NONE_POSSIBLE,
        schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "payment_intent": _ID,
                "charge": _ID,
                "amount": _AMOUNT,
                "reason": {"enum": ["duplicate", "fraudulent", "requested_by_customer"]},
                "metadata": _METADATA,
            },
        },
    ),
}


def stripe_sink(
    name: str = "stripe",
    operations: Sequence[str] = (PAYMENT_INTENTS_CREATE, REFUNDS_CREATE),
    **settings: Any,
) -> SinkSpec:
    """A sink of kind ``stripe`` allowing ``operations``, with their schemas.

    :param settings: Any other :class:`~interlock.outbound.SinkSpec` field:
        ``cost_per_call``, ``not_after``, ``max_attempts``...
    :raises ValueError: On an operation Stripe's catalog lacks, or a charge
        without ``refunds.create`` to undo it.
    """
    unknown = sorted(set(operations) - set(CATALOG))
    if unknown:
        raise ValueError(f"sink {name!r}: Stripe has no operation {', '.join(unknown)}")
    return SinkSpec(name, tuple(CATALOG[op] for op in operations), kind="stripe", **settings)


# --------------------------------------------------------------------------
# The rules a typed sink adds to admission
# --------------------------------------------------------------------------


def payload_problem(operation: str, payload: Mapping[str, Any]) -> str | None:
    """What the schema subset cannot say about a Stripe payload, or ``None``."""
    metadata = payload.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, Mapping) or len(metadata) > 50:
            return "metadata is at most 50 keys"
        for key, value in metadata.items():
            if len(key) > 40 or not isinstance(value, str) or len(value) > 500:
                return "metadata maps keys of at most 40 characters to strings of at most 500"
    if operation == REFUNDS_CREATE:
        named = [key for key in ("payment_intent", "charge") if key in payload]
        if len(named) != 1:
            return "a refund names exactly one of the payment_intent or the charge it refunds"
    return None


def compensation_problem(
    operation: str, charge: Mapping[str, Any], compensation: Mapping[str, Any] | None
) -> str | None:
    """Whether ``compensation`` (as the outbox stores it: a request document)
    undoes exactly the charge ``operation`` makes with ``charge``. Only a
    charge is checked: any other operation passes.

    :returns: What is wrong with it, or ``None``.
    """
    if operation not in CHARGES:
        return None
    if compensation is None:
        return f"{operation} takes money, and the request carries no refund to give it back"
    if compensation.get("operation") != REFUNDS_CREATE:
        return f"{operation} is undone by {REFUNDS_CREATE}, not {compensation.get('operation')}"
    refund = compensation.get("payload")
    if not isinstance(refund, Mapping):
        return "the refund has no payload"
    named = _CHARGED_AS[operation]
    other = "charge" if named == "payment_intent" else "payment_intent"
    if refund.get(named) != {"$bind": "delivered.id"}:
        return (
            f'the refund names the {named} it undoes by {{"$bind": "delivered.id"}}, '
            f"never by a literal id"
        )
    if other in refund:
        return f"the refund of a {named} names no {other}"
    if "currency" in refund:
        return "the refund names no currency: a refund is in the charge's"
    amount, charged = refund.get("amount"), charge.get("amount")
    if amount is not None and (
        isinstance(amount, bool)
        or not isinstance(amount, int)
        or not isinstance(charged, int)
        or not 0 < amount <= charged
    ):
        return f"the refund gives back at most the {charged} charged, not {amount}"
    return None


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------


def form_encode(payload: Mapping[str, Any]) -> bytes:
    """Stripe's ``application/x-www-form-urlencoded`` body: nested objects and
    arrays in bracket notation (``metadata[order]=17``, ``items[0]=a``),
    booleans as ``true``/``false``. Deterministic: fields in the order of the
    canonical payload."""
    pairs: list[tuple[str, str]] = []

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                walk(f"{prefix}[{key}]" if prefix else str(key), item)
        elif isinstance(value, list | tuple):
            for index, item in enumerate(value):
                walk(f"{prefix}[{index}]", item)
        elif isinstance(value, bool):
            pairs.append((prefix, "true" if value else "false"))
        elif value is None:
            pairs.append((prefix, ""))
        else:
            pairs.append((prefix, str(value)))

    walk("", payload)
    return urllib.parse.urlencode(pairs).encode("ascii")


_OBJECT_ID: Final = re.compile(r"\A[A-Za-z0-9_]{3,255}\Z")


class StripeAdapter:
    """Delivers a Stripe sink's requests to Stripe's API.

    :param api_key: The secret or restricted key, from the relay's environment;
        a callable is asked on every call, for a key that rotates.
    :param base_url: Stripe's API. A test points it at a fake.
    :param version: The ``Stripe-Version`` every call pins.
    :raises ValueError: On a URL that is not http(s), or no key.
    """

    __slots__ = ("_base", "_key", "_version")

    def __init__(
        self,
        api_key: str | Callable[[], str],
        *,
        base_url: str = API,
        version: str = STRIPE_VERSION,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"an endpoint is an http(s) URL, not {base_url!r}")
        if not api_key:
            raise ValueError("a Stripe adapter needs the account's secret key")
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._version = version

    def send(self, delivery: Delivery) -> DeliveryResult:
        path = _PATHS.get(delivery.operation)
        if path is None:
            return DeliveryResult(
                PERMANENT, detail=f"Stripe has no operation {delivery.operation!r}"
            )
        payload = loads_strict(delivery.payload)
        if not isinstance(payload, Mapping) or placeholders(payload):
            return DeliveryResult(
                PERMANENT,
                detail="the payload holds an unbound placeholder, which is never sent",
            )
        key = self._key() if callable(self._key) else self._key
        reply = exchange(
            self._base + path,
            form_encode(payload),
            {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": delivery.idempotency_key,
                "Stripe-Version": self._version,
                **trace_headers(delivery),
            },
            "POST",
            delivery.timeout,
        )
        if isinstance(reply, DeliveryResult):
            return reply
        return classify(reply)


def classify(reply: Reply) -> DeliveryResult:
    """What a Stripe reply means for the call (the table above)."""
    status, digest = reply.status, reply.digest
    document = _json(reply.body)
    if 200 <= status < 300:
        ref = document.get("id")
        replayed = reply.header("Idempotent-Replayed") == "true"
        return DeliveryResult(
            DELIVERED,
            status_code=status,
            response_digest=digest,
            detail="an idempotent replay" if replayed else "",
            remote_ref=ref if isinstance(ref, str) and _OBJECT_ID.match(ref) else None,
        )
    error = document.get("error")
    error = error if isinstance(error, Mapping) else {}
    kind = str(error.get("type") or "")
    code = str(error.get("code") or kind or "")
    if kind == "idempotency_error" and status != 409:
        return DeliveryResult(
            PERMANENT,
            status_code=status,
            response_digest=digest,
            detail="Stripe refused the idempotency key: it was first used with other "
            "parameters, so the request stored is not the one first sent",
        )
    if status >= 500:
        return DeliveryResult(
            UNKNOWN,
            status_code=status,
            response_digest=digest,
            detail=f"HTTP {status}: Stripe may have acted",
        )
    should = reply.header("Stripe-Should-Retry")
    if should == "true" or (should is None and status in (409, 429)):
        return DeliveryResult(
            RETRYABLE,
            status_code=status,
            response_digest=digest,
            detail=f"HTTP {status}" + (f": {code}" if code else ""),
            retry_after=retry_after_seconds(reply.header("Retry-After")),
        )
    return DeliveryResult(
        PERMANENT,
        status_code=status,
        response_digest=digest,
        detail=f"HTTP {status}" + (f": {code}" if code else ""),
    )


def _json(body: bytes) -> Mapping[str, Any]:
    try:
        document = json.loads(body)
    except ValueError:
        return {}
    return document if isinstance(document, Mapping) else {}
