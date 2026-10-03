"""SendGrid as a sink (``docs/EPIC3_DESIGN.md`` §4.2).

- **Admission.** One operation, ``mail.send``, with SendGrid's own strict
  payload: addresses, a subject, a text or an html body, at most a thousand
  recipients. An email cannot be undone, so it carries no compensation.
- **At most once, by default.** SendGrid has no idempotency keys, so the kind
  has none, and an unknown outcome is dead-lettered unless the sink says
  ``redeliver``: an email may be lost to an operator's decision, never sent
  twice by the relay's.
- **The adapter** builds SendGrid's v3 body, with ``custom_args`` naming the
  message and its key, and records ``X-Message-Id``. It is held to the
  classification table against a fake that, like SendGrid, sends every call
  it accepts.
- **End to end**, on both stores.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts.canonical import canonical_bytes

from interlock import PlanBuilder
from interlock.exceptions import OutboundRequestError
from interlock.outbound import DEAD_LETTER, REDELIVER, SinkRegistry
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, NoBreaker, Relay
from interlock.sendgrid import MAIL_SEND, SendGridAdapter, sendgrid_sink, v3_body
from interlock.types import EffectId, OutboundRequest, outbound_key
from tests.fakesendgrid import KEY, FakeSendGrid, rate_limited, send_then
from tests.fakesink import hang, status
from tests.outbox_env import BACKENDS, RELAY_SINKS, SCOPE, Outbox, build_either

EMAIL: dict[str, Any] = {
    "to": [{"email": "ann@acme.test", "name": "Ann"}],
    "cc": [{"email": "ops@acme.test"}],
    "from": {"email": "orders@shop.test", "name": "Shop"},
    "reply_to": {"email": "support@shop.test"},
    "subject": "Your order shipped",
    "text": "It is on its way.",
    "html": "<p>It is on its way.</p>",
    "categories": ["shipping"],
}

SENDGRID = sendgrid_sink(
    "sendgrid",
    cost_per_call=Decimal("0.001"),
    max_payload_bytes=64 * 1024,
    backoff_base=timedelta(milliseconds=20),
    backoff_cap=timedelta(milliseconds=160),
)
REGISTRY = SinkRegistry([SENDGRID])


def email(payload: dict[str, Any] | None = None, **compensation: Any) -> OutboundRequest:
    return OutboundRequest(
        "sendgrid",
        MAIL_SEND,
        EMAIL if payload is None else payload,
        compensation=OutboundRequest("sendgrid", MAIL_SEND, EMAIL) if compensation else None,
    )


# --------------------------------------------------------------------------
# admission
# --------------------------------------------------------------------------


def test_an_email_is_admitted_and_at_most_once_by_default() -> None:
    assert REGISTRY.check(email()) is SENDGRID
    assert (SENDGRID.kind, SENDGRID.idempotency, SENDGRID.unknown_outcome) == (
        "sendgrid",
        "none",
        DEAD_LETTER,
    )
    assert sendgrid_sink(unknown_outcome=REDELIVER).unknown_outcome == REDELIVER
    with pytest.raises(ValueError, match="idempotency is 'none'"):
        sendgrid_sink(idempotency="header")


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({k: v for k, v in EMAIL.items() if k not in ("text", "html")}, "text body, an html"),
        ({**EMAIL, "to": []}, "fewer than 1 items"),
        ({**EMAIL, "to": [{"email": "not an address"}]}, "pattern"),
        ({**EMAIL, "from": {"email": "a@b.c", "display": "x"}}, "not an allowed field"),
        ({**EMAIL, "subject": ""}, "shorter than 1"),
        ({**EMAIL, "attachments": []}, "not an allowed field"),
        ({**EMAIL, "categories": [str(i) for i in range(11)]}, "more than 10 items"),
        (
            {
                **EMAIL,
                "to": [{"email": f"u{i}@acme.test"} for i in range(600)],
                "bcc": [{"email": f"b{i}@acme.test"} for i in range(401)],
            },
            "at most 1000 recipients",
        ),
    ],
)
def test_an_email_is_sendgrids_own(payload: dict[str, Any], match: str) -> None:
    with pytest.raises(OutboundRequestError, match=match) as caught:
        REGISTRY.check(email(payload))
    assert caught.value.reason == "payload_schema"


def test_an_email_cannot_be_undone() -> None:
    with pytest.raises(OutboundRequestError, match="impossible to undo") as caught:
        REGISTRY.check(email(undo=True))
    assert caught.value.reason == "compensation"


# --------------------------------------------------------------------------
# the adapter
# --------------------------------------------------------------------------


@pytest.fixture
def sendgrid() -> Iterator[FakeSendGrid]:
    fake = FakeSendGrid()
    try:
        yield fake
    finally:
        fake.close()


def delivery(
    payload: dict[str, Any] | None = None,
    *,
    key: str = "key-1",
    timeout: float = 2.0,
    operation: str = MAIL_SEND,
) -> Delivery:
    body = canonical_bytes(EMAIL if payload is None else payload)
    return Delivery(
        message_id=uuid.UUID(int=7),
        sink="sendgrid",
        operation=operation,
        idempotency_key=key,
        payload=body,
        payload_hash=hashlib.sha256(body).hexdigest(),
        attempt=1,
        tenant_id=None,
        timeout=timeout,
    )


def test_the_v3_body_is_sendgrids() -> None:
    body = v3_body(json.loads(canonical_bytes(EMAIL)), delivery(), sandbox=False)
    assert body == {
        "personalizations": [
            {
                "to": [{"email": "ann@acme.test", "name": "Ann"}],
                "cc": [{"email": "ops@acme.test"}],
                "custom_args": {
                    "interlock_message_id": str(uuid.UUID(int=7)),
                    "interlock_idempotency_key": "key-1",
                },
            }
        ],
        "from": {"email": "orders@shop.test", "name": "Shop"},
        "reply_to": {"email": "support@shop.test"},
        "subject": "Your order shipped",
        "content": [
            {"type": "text/plain", "value": "It is on its way."},
            {"type": "text/html", "value": "<p>It is on its way.</p>"},
        ],
        "categories": ["shipping"],
    }
    html_only = {k: v for k, v in EMAIL.items() if k != "text"}
    sandboxed = v3_body(html_only, delivery(), sandbox=True)
    assert sandboxed["content"] == [{"type": "text/html", "value": "<p>It is on its way.</p>"}]
    assert sandboxed["mail_settings"] == {"sandbox_mode": {"enable": True}}


def test_an_email_is_sent_and_its_message_id_recorded(sendgrid: FakeSendGrid) -> None:
    result = SendGridAdapter(KEY, base_url=sendgrid.url).send(delivery())
    assert (result.outcome, result.status_code) == (DELIVERED, 202)
    assert result.remote_ref is not None and len(result.remote_ref) == 22
    (sent,) = sendgrid.sent
    assert sent["personalizations"][0]["custom_args"]["interlock_idempotency_key"] == "key-1"
    assert sendgrid.calls[0].authorization == f"Bearer {KEY}"
    # SendGrid has no keys: the same call again is a second email.
    SendGridAdapter(KEY, base_url=sendgrid.url).send(delivery())
    assert sendgrid.effects["key-1"] == 2


def test_the_sandbox_sends_nothing(sendgrid: FakeSendGrid) -> None:
    result = SendGridAdapter(KEY, base_url=sendgrid.url, sandbox=True).send(delivery())
    assert (result.outcome, result.status_code) == (DELIVERED, 200)
    assert sendgrid.sent == [] and len(sendgrid.sandboxed) == 1


@pytest.mark.parametrize(
    ("behaviour", "outcome", "code"),
    [
        (status(400), PERMANENT, 400),
        (status(413), PERMANENT, 413),
        (status(500), UNKNOWN, 500),
        (send_then(502), UNKNOWN, 502),
        (rate_limited(30), RETRYABLE, 429),
    ],
)
def test_sendgrids_replies_are_classified(
    sendgrid: FakeSendGrid, behaviour: tuple[Any, ...], outcome: str, code: int
) -> None:
    sendgrid.script(behaviour)
    result = SendGridAdapter(KEY, base_url=sendgrid.url).send(delivery())
    assert (result.outcome, result.status_code) == (outcome, code)
    if code == 429:
        assert result.retry_after is not None and 25 <= result.retry_after <= 30


def test_what_the_adapter_never_sends(sendgrid: FakeSendGrid) -> None:
    adapter = SendGridAdapter(KEY, base_url=sendgrid.url)
    placeholder = {**EMAIL, "subject": {"$bind": "delivered.id"}}
    assert adapter.send(delivery(placeholder)).outcome == PERMANENT
    assert adapter.send(delivery(operation="mail.unsend")).outcome == PERMANENT
    assert sendgrid.calls == []
    wrong = SendGridAdapter("SG.wrong", base_url=sendgrid.url).send(delivery())
    assert (wrong.outcome, wrong.status_code) == (PERMANENT, 401)
    with pytest.raises(ValueError, match="API key"):
        SendGridAdapter("", base_url=sendgrid.url)


def test_a_timeout_after_sending_is_unknown(sendgrid: FakeSendGrid) -> None:
    sendgrid.script(hang(1.0))
    started = time.monotonic()
    result = SendGridAdapter(KEY, base_url=sendgrid.url).send(delivery(timeout=0.3))
    assert result.outcome == UNKNOWN and time.monotonic() - started < 1.0
    assert sendgrid.effects["key-1"] == 1, "SendGrid sent it: the relay cannot know"


# --------------------------------------------------------------------------
# end to end, on each store
# --------------------------------------------------------------------------


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


TYPED = (*RELAY_SINKS, SENDGRID)


def mail_plan() -> Any:
    return (
        PlanBuilder(SCOPE, intent="tell Ann")
        .enqueue(sink="sendgrid", operation=MAIL_SEND, payload=EMAIL, effect_id=EffectId("notify"))
        .build()
    )


def relay(outbox: Outbox, sendgrid: FakeSendGrid) -> Relay:
    return Relay(
        outbox.store(),
        adapters={"sendgrid": SendGridAdapter(KEY, base_url=sendgrid.url)},
        breaker=NoBreaker(),
        lease=timedelta(seconds=2),
        timeout=timedelta(seconds=0.5),
    )


def test_an_email_is_delivered_once_with_its_message_id(
    outbox: Outbox, sendgrid: FakeSendGrid
) -> None:
    outbox.reinstall(TYPED)
    plan = mail_plan()
    assert outbox.engine(sinks=SinkRegistry(TYPED)).execute(plan).committed
    (message,) = outbox.messages(plan.plan_id)
    sendgrid.script(rate_limited(0))
    with relay(outbox, sendgrid) as r:
        outbox.drain(r)
    assert outbox.events(message) == [
        ("sending", 1),
        ("retryable", 1),
        ("sending", 2),
        ("delivered", 2),
    ]
    delivered = next(e for e in outbox.log(message) if e.event == "delivered")
    assert delivered.remote_ref is not None
    assert sendgrid.effects[outbound_key(plan.plan_id, EffectId("notify"))] == 1
    outbox.verify()


def test_an_unknown_outcome_is_never_sent_again(outbox: Outbox, sendgrid: FakeSendGrid) -> None:
    """The call timed out after SendGrid accepted it. Redelivering would send
    a second email; the message is dead instead, for an operator."""
    outbox.reinstall(TYPED)
    plan = mail_plan()
    assert outbox.engine(sinks=SinkRegistry(TYPED)).execute(plan).committed
    (message,) = outbox.messages(plan.plan_id)
    sendgrid.script(hang(1.0))
    with relay(outbox, sendgrid) as r:
        outbox.drain(r)
    assert outbox.state(message) == "dead"
    assert outbox.events(message) == [("sending", 1), ("unknown", 1)]
    assert "not redelivered" in str(outbox.row(message)["reason"])
    assert sendgrid.effects[outbound_key(plan.plan_id, EffectId("notify"))] == 1
    outbox.verify()
