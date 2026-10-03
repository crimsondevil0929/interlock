"""Stripe as a sink (``docs/EPIC3_DESIGN.md`` §4.1).

- **Admission.** A Stripe sink admits Stripe's operations with Stripe's
  schemas, and a charge only with the refund that undoes exactly it: named by
  the placeholder, no more than was charged, in no other currency.
- **The outbox checks it again**, from the kind the database holds: an engine
  whose registry admits a charge without its refund still cannot stage it.
- **The adapter** speaks Stripe's protocol: form encoding, the idempotency
  key, a pinned version; and records the id of what a delivered call created.
  It is held to the classification table against a fake that keeps Stripe's
  idempotency rules: a replay is a delivery, a key reused with other
  parameters is not.
- **End to end**, on both stores: committed with its refund, charged once,
  the payment intent's id in the delivery log, the log verifying.
"""

from __future__ import annotations

import hashlib
import socket
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
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec, bind, placeholders
from interlock.relay import (
    DELIVERED,
    PERMANENT,
    RETRYABLE,
    UNKNOWN,
    Delivery,
    NoBreaker,
    Relay,
)
from interlock.stripe import (
    CATALOG,
    CHARGES_CREATE,
    PAYMENT_INTENTS_CREATE,
    REFUNDS_CREATE,
    STRIPE_VERSION,
    StripeAdapter,
    form_encode,
    stripe_sink,
)
from interlock.types import EffectId, OutboundRequest, outbound_key
from tests.fakesink import DROP, hang, status
from tests.fakestripe import KEY, FakeStripe, act_then, parse_form, stripe_error
from tests.outbox_env import BACKENDS, RELAY_SINKS, SCOPE, Outbox, build_either
from tests.schemas import TEST_SINKS

CHARGE: dict[str, Any] = {
    "amount": 5000,
    "currency": "usd",
    "customer": "cus_ann",
    "payment_method": "pm_card_visa",
    "confirm": True,
    "metadata": {"order": "500"},
}
REFUND: dict[str, Any] = {"payment_intent": {"$bind": "delivered.id"}, "amount": 5000}

STRIPE = stripe_sink(
    "stripe",
    (PAYMENT_INTENTS_CREATE, CHARGES_CREATE, REFUNDS_CREATE),
    cost_per_call=Decimal("0.30"),
    backoff_base=timedelta(milliseconds=20),
    backoff_cap=timedelta(milliseconds=160),
)
REGISTRY = SinkRegistry([STRIPE])


def charge(
    payload: dict[str, Any] | None = None,
    refund: dict[str, Any] | None = REFUND,
    *,
    operation: str = PAYMENT_INTENTS_CREATE,
) -> OutboundRequest:
    return OutboundRequest(
        "stripe",
        operation,
        CHARGE if payload is None else payload,
        compensation=None if refund is None else OutboundRequest("stripe", REFUNDS_CREATE, refund),
    )


def refused(request: OutboundRequest, registry: SinkRegistry = REGISTRY) -> OutboundRequestError:
    with pytest.raises(OutboundRequestError) as caught:
        registry.check(request)
    return caught.value


# --------------------------------------------------------------------------
# admission
# --------------------------------------------------------------------------


def test_a_charge_carrying_the_refund_that_undoes_it_is_admitted() -> None:
    assert REGISTRY.check(charge()) is STRIPE
    assert REGISTRY.check(charge(refund={"payment_intent": {"$bind": "delivered.id"}}))
    legacy = charge(
        {"amount": 700, "currency": "eur", "source": "tok_visa"},
        {"charge": {"$bind": "delivered.id"}, "reason": "requested_by_customer"},
        operation=CHARGES_CREATE,
    )
    assert REGISTRY.check(legacy) is STRIPE


@pytest.mark.parametrize(
    ("refund", "match"),
    [
        (None, "carries no refund"),
        ({"payment_intent": "pi_somebody_else", "amount": 5000}, "never by a literal id"),
        ({"charge": {"$bind": "delivered.id"}}, "never by a literal id"),
        ({"payment_intent": {"$bind": "delivered.id"}, "charge": "ch_1"}, "names no charge"),
        ({"payment_intent": {"$bind": "delivered.id"}, "currency": "usd"}, "no currency"),
        ({"payment_intent": {"$bind": "delivered.id"}, "amount": 5001}, "at most the 5000"),
        ({"payment_intent": {"$bind": "delivered.id"}, "amount": 0}, "at most the 5000"),
    ],
)
def test_a_charge_must_carry_the_refund_that_undoes_exactly_it(
    refund: dict[str, Any] | None, match: str
) -> None:
    error = refused(charge(refund=refund))
    assert error.reason == "compensation"
    assert match in str(error)


def test_a_charges_refund_is_a_refund() -> None:
    wrong = OutboundRequest(
        "stripe",
        PAYMENT_INTENTS_CREATE,
        CHARGE,
        compensation=OutboundRequest("stripe", CHARGES_CREATE, {"amount": 1, "currency": "usd"}),
    )
    error = refused(wrong)
    assert (error.reason, "is undone by refunds.create, not charges.create" in str(error)) == (
        "compensation",
        True,
    )


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({**CHARGE, "currency": "USD"}, "pattern"),
        ({**CHARGE, "amount": 0}, "below its minimum"),
        ({**CHARGE, "amount": "50.00"}, "is string, not integer"),
        ({**CHARGE, "application_fee_amount": 10}, "not an allowed field"),
        ({**CHARGE, "metadata": {str(i): "x" for i in range(51)}}, "50 keys"),
        ({**CHARGE, "metadata": {"order": 500}}, "strings of at most 500"),
    ],
)
def test_a_payload_is_stripes_own(payload: dict[str, Any], match: str) -> None:
    error = refused(charge(payload))
    assert error.reason == "payload_schema"
    assert match in str(error)


def test_a_refund_names_one_payment_by_its_id() -> None:
    direct = OutboundRequest("stripe", REFUNDS_CREATE, {"payment_intent": "pi_123", "amount": 100})
    assert REGISTRY.check(direct) is STRIPE
    for payload in ({"payment_intent": "pi_1", "charge": "ch_1"}, {"amount": 100}):
        error = refused(OutboundRequest("stripe", REFUNDS_CREATE, payload))
        assert (error.reason, "exactly one" in str(error)) == ("payload_schema", True)


def test_only_a_compensation_holds_a_placeholder() -> None:
    """A request the relay sends is concrete; a placeholder is bound only
    when a compensation is executed."""
    error = refused(OutboundRequest("stripe", REFUNDS_CREATE, REFUND))
    assert error.reason == "placeholder" and "$.payment_intent" in str(error)
    # On any sink, and anywhere in the payload.
    mail = OutboundRequest("mail", "send", {"to": "a@b.c", "subject": {"$bind": "delivered.id"}})
    assert refused(mail, SinkRegistry(TEST_SINKS)).reason == "placeholder"


def test_a_compensations_placeholder_is_the_one_there_is() -> None:
    payments = SinkRegistry(TEST_SINKS)
    undo = OutboundRequest("payments", "refund.reverse", {"refund": {"$bind": "delivered.id"}})
    request = OutboundRequest("payments", "refund", {"amount": "5.00"}, compensation=undo)
    assert payments.check(request).name == "payments"
    other = OutboundRequest("payments", "refund.reverse", {"refund": {"$bind": "delivered.amount"}})
    error = refused(
        OutboundRequest("payments", "refund", {"amount": "5.00"}, compensation=other), payments
    )
    assert error.reason == "placeholder"


def test_placeholders_are_found_and_bound() -> None:
    nested = {"a": [{"b": {"$bind": "delivered.id"}}, 2], "c": {"$bind": "delivered.id"}}
    assert placeholders(nested) == ["$.a[0].b", "$.c"]
    assert bind(nested, "pi_9") == {"a": [{"b": "pi_9"}, 2], "c": "pi_9"}
    assert placeholders(bind(nested, "pi_9")) == []


def test_a_stripe_sinks_operations_are_stripes_own() -> None:
    spec = stripe_sink()
    assert (spec.kind, spec.idempotency, spec.unknown_outcome) == ("stripe", "header", "redeliver")
    with pytest.raises(ValueError, match=r"Stripe has no operation customers\.delete"):
        stripe_sink(operations=("customers.delete",))
    with pytest.raises(ValueError, match="does not register"):
        stripe_sink(operations=(PAYMENT_INTENTS_CREATE,))
    lax = OperationSpec(PAYMENT_INTENTS_CREATE, compensation=REFUNDS_CREATE)
    with pytest.raises(ValueError, match="stripe's own"):
        SinkSpec("stripe", (lax, CATALOG[REFUNDS_CREATE]), kind="stripe")
    with pytest.raises(ValueError, match="idempotency is 'header'"):
        stripe_sink(idempotency="none")
    with pytest.raises(ValueError, match="kind is one of"):
        SinkSpec("paypal", (OperationSpec("pay"),), kind="paypal")
    # The kind is part of what the sink permits, so of its hash.
    assert SinkSpec("stripe", spec.operations).config_hash() != spec.config_hash()


# --------------------------------------------------------------------------
# the wire format
# --------------------------------------------------------------------------


def test_the_form_encoding_is_stripes_and_deterministic() -> None:
    payload = {
        "amount": 5000,
        "confirm": True,
        "currency": "usd",
        "metadata": {"note": "a b&c", "order": "500"},
        "payment_method_types": ["card", "link"],
    }
    body = form_encode(payload)
    assert body == (
        b"amount=5000&confirm=true&currency=usd&metadata%5Bnote%5D=a+b%26c&"
        b"metadata%5Border%5D=500&payment_method_types%5B0%5D=card&"
        b"payment_method_types%5B1%5D=link"
    )
    assert parse_form(body) == {
        "amount": "5000",
        "confirm": "true",
        "currency": "usd",
        "metadata": {"note": "a b&c", "order": "500"},
        "payment_method_types": ["card", "link"],
    }
    assert form_encode({"description": None, "off_session": False}) == (
        b"description=&off_session=false"
    )


# --------------------------------------------------------------------------
# the adapter
# --------------------------------------------------------------------------


@pytest.fixture
def stripe() -> Iterator[FakeStripe]:
    fake = FakeStripe()
    try:
        yield fake
    finally:
        fake.close()


def delivery(
    payload: dict[str, Any] | None = None,
    *,
    operation: str = PAYMENT_INTENTS_CREATE,
    key: str = "key-1",
    timeout: float = 2.0,
) -> Delivery:
    body = canonical_bytes(CHARGE if payload is None else payload)
    return Delivery(
        message_id=uuid.uuid4(),
        sink="stripe",
        operation=operation,
        idempotency_key=key,
        payload=body,
        payload_hash=hashlib.sha256(body).hexdigest(),
        attempt=1,
        tenant_id=None,
        timeout=timeout,
    )


def test_a_charge_is_made_once_and_its_id_recorded(stripe: FakeStripe) -> None:
    adapter = StripeAdapter(KEY, base_url=stripe.url)
    first = adapter.send(delivery())
    assert (first.outcome, first.status_code, first.remote_ref) == (DELIVERED, 200, "pi_000001")
    (call,) = stripe.calls
    assert (call.path, call.key, call.authorization) == (
        "/v1/payment_intents",
        "key-1",
        f"Bearer {KEY}",
    )
    assert parse_form(call.body)["metadata"] == {"order": "500"}
    assert stripe.versions == {STRIPE_VERSION: 1}
    # Again, with the key: Stripe replays, and nothing is charged twice.
    again = adapter.send(delivery())
    assert (again.outcome, again.remote_ref, again.detail) == (
        DELIVERED,
        "pi_000001",
        "an idempotent replay",
    )
    assert stripe.effects["key-1"] == 1 and len(stripe.of("payment_intent")) == 1


def test_a_key_reused_with_other_parameters_is_permanent(stripe: FakeStripe) -> None:
    adapter = StripeAdapter(KEY, base_url=stripe.url)
    assert adapter.send(delivery()).outcome == DELIVERED
    tampered = adapter.send(delivery({**CHARGE, "amount": 9999}))
    assert tampered.outcome == PERMANENT and "other parameters" in tampered.detail
    assert len(stripe.of("payment_intent")) == 1


@pytest.mark.parametrize(
    ("behaviour", "outcome", "code"),
    [
        (stripe_error(402, "card_error"), PERMANENT, 402),
        (stripe_error(400, "invalid_request_error"), PERMANENT, 400),
        (stripe_error(429, "rate_limit_error"), RETRYABLE, 429),
        (stripe_error(409, "invalid_request_error"), RETRYABLE, 409),
        (stripe_error(400, "invalid_request_error", should_retry=True), RETRYABLE, 400),
        (stripe_error(409, "invalid_request_error", should_retry=False), PERMANENT, 409),
        (stripe_error(500, "api_error"), UNKNOWN, 500),
        (stripe_error(500, "api_error", should_retry=True), UNKNOWN, 500),
        (stripe_error(503, "api_error", should_retry=False), UNKNOWN, 503),
        (status(429, retry_after=3), RETRYABLE, 429),
        (act_then(502), UNKNOWN, 502),
    ],
)
def test_stripes_replies_are_classified(
    stripe: FakeStripe, behaviour: tuple[Any, ...], outcome: str, code: int
) -> None:
    stripe.script(behaviour)
    result = StripeAdapter(KEY, base_url=stripe.url).send(delivery())
    assert (result.outcome, result.status_code) == (outcome, code)
    assert result.remote_ref is None
    if behaviour == status(429, retry_after=3):
        assert result.retry_after == 3


def test_a_call_whose_reply_was_lost_is_found_by_its_replay(stripe: FakeStripe) -> None:
    """Executed, and the reply lost (dropped, or a gateway's 502): unknown.
    The retry with the key is answered from Stripe's store: the same payment
    intent, delivered, charged once."""
    adapter = StripeAdapter(KEY, base_url=stripe.url)
    for behaviour, key in ((DROP, "dropped"), (act_then(502), "gateway"), (hang(1.0), "slow")):
        stripe.script(behaviour, key=key)
        lost = adapter.send(delivery(key=key, timeout=0.4))
        assert lost.outcome == UNKNOWN
        found = adapter.send(delivery(key=key))
        assert (found.outcome, found.detail) == (DELIVERED, "an idempotent replay")
        assert found.remote_ref is not None and stripe.effects[key] == 1
    assert len(stripe.of("payment_intent")) == 3


def test_a_refund_gives_back_what_was_charged(stripe: FakeStripe) -> None:
    adapter = StripeAdapter(KEY, base_url=stripe.url)
    made = adapter.send(delivery())
    assert made.remote_ref is not None
    part = {"payment_intent": made.remote_ref, "amount": 3000}
    refund = adapter.send(delivery(part, operation=REFUNDS_CREATE, key="refund-1"))
    assert (refund.outcome, refund.remote_ref) == (DELIVERED, "re_000001")
    too_much = adapter.send(
        delivery({**part, "amount": 2001}, operation=REFUNDS_CREATE, key="refund-2")
    )
    assert (too_much.outcome, too_much.status_code) == (PERMANENT, 400)


def test_what_the_adapter_never_sends(stripe: FakeStripe) -> None:
    adapter = StripeAdapter(KEY, base_url=stripe.url)
    unbound = adapter.send(delivery(REFUND, operation=REFUNDS_CREATE))
    assert unbound.outcome == PERMANENT and "placeholder" in unbound.detail
    unknown = adapter.send(delivery(operation="customers.delete"))
    assert unknown.outcome == PERMANENT
    assert stripe.calls == []
    wrong = StripeAdapter("sk_test_wrong", base_url=stripe.url).send(delivery())
    assert (wrong.outcome, wrong.status_code) == (PERMANENT, 401)
    with pytest.raises(ValueError, match="http"):
        StripeAdapter(KEY, base_url="ftp://stripe")
    with pytest.raises(ValueError, match="secret key"):
        StripeAdapter("", base_url=stripe.url)


def test_a_call_that_never_left_is_retryable() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    result = StripeAdapter(KEY, base_url=f"http://127.0.0.1:{port}").send(delivery())
    assert result.outcome == RETRYABLE and result.detail.startswith("not sent")


def test_a_key_that_rotates_is_read_on_every_call(stripe: FakeStripe) -> None:
    keys = iter(["sk_test_old", KEY])
    adapter = StripeAdapter(lambda: next(keys), base_url=stripe.url)
    assert adapter.send(delivery(key="a")).status_code == 401
    assert adapter.send(delivery(key="b")).outcome == DELIVERED


# --------------------------------------------------------------------------
# end to end, on each store
# --------------------------------------------------------------------------


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


TYPED = (*RELAY_SINKS, STRIPE)


def charge_plan(refund: dict[str, Any] | None = REFUND) -> Any:
    return (
        PlanBuilder(SCOPE, intent="charge order 500")
        .enqueue(
            sink="stripe",
            operation=PAYMENT_INTENTS_CREATE,
            payload=CHARGE,
            compensation=None
            if refund is None
            else OutboundRequest("stripe", REFUNDS_CREATE, refund),
            effect_id=EffectId("charge"),
        )
        .build()
    )


def test_a_charge_commits_with_its_refund_and_is_charged_once(
    outbox: Outbox, stripe: FakeStripe
) -> None:
    outbox.reinstall(TYPED)
    plan = charge_plan()
    result = outbox.engine(sinks=SinkRegistry(TYPED)).execute(plan)
    assert result.committed
    (message,) = outbox.messages(plan.plan_id)
    stripe.script(DROP)  # the first reply is lost: the relay must find the charge again
    relay = Relay(
        outbox.store(),
        adapters={"stripe": StripeAdapter(KEY, base_url=stripe.url)},
        breaker=NoBreaker(),
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
    )
    with relay:
        outbox.drain(relay)
    assert outbox.state(message) == "delivered"
    assert outbox.events(message) == [
        ("sending", 1),
        ("unknown", 1),
        ("sending", 2),
        ("delivered", 2),
    ]
    delivered = next(e for e in outbox.log(message) if e.event == "delivered")
    assert (delivered.remote_ref, delivered.detail) == ("pi_000001", "an idempotent replay")
    assert stripe.effects[outbound_key(plan.plan_id, EffectId("charge"))] == 1
    assert len(stripe.of("payment_intent")) == 1
    outbox.verify()


@pytest.mark.parametrize(
    ("compensation", "refund", "match"),
    [
        ("none-possible", None, "carries no refund"),
        (REFUNDS_CREATE, {"payment_intent": "pi_somebody_else"}, "never by a literal id"),
    ],
)
def test_the_outbox_refuses_a_charge_without_its_refund_whatever_the_engine_admits(
    outbox: Outbox, compensation: str, refund: dict[str, Any] | None, match: str
) -> None:
    """The engine's registry declares the sink as plain http, admitting the
    charge as it is. The database holds the sink's kind, and refuses."""
    outbox.reinstall(TYPED)
    lax = SinkSpec(
        "stripe",
        (
            OperationSpec(PAYMENT_INTENTS_CREATE, compensation=compensation),
            OperationSpec(REFUNDS_CREATE),
        ),
        cost_per_call=Decimal("0.30"),
    )
    engine = outbox.engine(sinks=SinkRegistry((*RELAY_SINKS, lax)))
    with pytest.raises(OutboundRequestError) as caught:
        engine.execute(charge_plan(refund))
    assert caught.value.reason == "compensation" and match in str(caught.value)
    assert outbox.requests() == 0
