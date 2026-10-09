"""W3C trace context (``docs/EPIC7_DESIGN.md`` §1), on both stores.

- A plan's ``traceparent`` is checked where it is written, and a received
  one read as W3C says a receiver must.
- No hash moves: every hash family, traced or not, is the value it was before
  trace context existed.
- A traced plan's requests carry its context to the sink, every adapter's
  header included; a compensation is in the trace of what it undoes.
- A webhook's context is kept beside its event, and decides a fact's when it
  carries the same trace as the delivery the fact is bound to.
- Trace context goes with what it describes, the agent cannot write it, and an
  outbox of version 5 is upgraded in place.
"""

from __future__ import annotations

import dataclasses
import hashlib
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts.canonical import canonical_bytes

from interlock import BlastRadius, PlanBuilder
from interlock.deliveries import event_hash as log_hash
from interlock.deliveries import genesis_hash
from interlock.exceptions import InterlockError, PlanError, SubstrateConfigurationError
from interlock.inbox import _event_statement, _fact_statement
from interlock.inbox import event_hash as inbox_hash
from interlock.outbound import SinkRegistry
from interlock.relay import DeliveryResult, Lease, NoBreaker, Relay, attested_outcome
from interlock.repair import subplan
from interlock.sqlite_outbox import SqliteOutboxStore, install_sqlite_outbox, installed_version
from interlock.stripe import StripeAdapter
from interlock.trace import (
    child_traceparent,
    fact_traceparent,
    new_traceparent,
    parse_traceparent,
    require_traceparent,
    span_id,
    trace_id,
)
from interlock.types import EffectId, InboundFact, OutboundRequest, PlanId
from tests.fakestripe import KEY, FakeStripe
from tests.inbox_env import INBOX_KEYS, InboxSite, inbox_site, refund_event, stripe_webhook
from tests.outbox_env import (
    BACKENDS,
    RELAY_SINKS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    build_either,
    mail,
    relay_signer,
    sms,
)
from tests.plans import sqlite_engine, support_batch
from tests.settling import Bench
from tests.test_operators import TYPED, charge, charged

TP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
"""W3C's own example."""
OTHER = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


# --------------------------------------------------------------------------
# the context itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "why"),
    [
        (TP.upper(), "lowercase"),
        ("01" + TP[2:], "not a traceparent"),
        (TP + "-extra", "not a traceparent"),
        (TP[:-1], "not a traceparent"),
        (f"00-{'0' * 32}-00f067aa0ba902b7-01", "trace id"),
        (f"00-4bf92f3577b34da6a3ce929d0e0e4736-{'0' * 16}-01", "parent id"),
        (TP + "\r\nX-Injected: 1", "not a traceparent"),
        ("", "not a traceparent"),
    ],
)
def test_a_plans_trace_context_is_checked_where_it_is_written(value: str, why: str) -> None:
    with pytest.raises(PlanError, match=why):
        PlanBuilder("agent", traceparent=value)
    # A plan built without the builder is refused at admission, before anything.
    plan = dataclasses.replace(_plan(), traceparent=value)
    with pytest.raises(PlanError, match=why):
        _sqlite_engine().admit(plan)


def test_a_received_traceparent_is_read_as_a_receiver_must() -> None:
    assert parse_traceparent(TP) == TP
    assert parse_traceparent(f" \t{TP} ") == TP
    assert parse_traceparent(None) is None
    zero_trace = f"00-{'0' * 32}-00f067aa0ba902b7-01"
    zero_span = f"00-4bf92f3577b34da6a3ce929d0e0e4736-{'0' * 16}-01"
    for invalid in (
        TP.upper(),
        TP + "-x",
        TP[:-1],
        "ff" + TP[2:],
        zero_trace,
        zero_span,
        "garbage",
        "",
    ):
        assert parse_traceparent(invalid) is None, invalid
    # A later version is read for its 00 fields, whatever it adds after them.
    assert parse_traceparent("cc" + TP[2:] + "-what-comes-next") == TP
    assert parse_traceparent("cc" + TP[2:]) == TP
    assert parse_traceparent("cc" + TP[2:] + "x") is None


def test_a_trace_is_started_and_continued() -> None:
    started = new_traceparent()
    assert require_traceparent(started) == started and started.endswith("-01")
    assert new_traceparent(sampled=False).endswith("-00")
    child = child_traceparent(TP)
    assert trace_id(child) == trace_id(TP) and span_id(child) != span_id(TP)
    assert child[-2:] == TP[-2:]
    assert (trace_id(TP), span_id(TP)) == ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7")


def test_a_fact_continues_the_trace_of_the_plan_whose_delivery_it_is() -> None:
    echoed = child_traceparent(TP)
    assert fact_traceparent(TP, echoed) == echoed  # the vendor propagated ours
    assert fact_traceparent(TP, None) == TP
    assert fact_traceparent(TP, OTHER) == TP  # the vendor's own trace detaches nothing
    assert fact_traceparent(None, OTHER) == OTHER
    assert fact_traceparent(None, None) is None


def test_a_repair_keeps_the_trace_of_the_plan_it_repairs(back_office: str) -> None:
    plan = dataclasses.replace(_plan(), traceparent=TP)
    kept = frozenset({plan.effects[0].effect_id})
    assert subplan(plan, kept).traceparent == TP
    # And the proposal the engine's own search makes: the same work, tried again.
    repair = sqlite_engine(back_office).repair(dataclasses.replace(support_batch(), traceparent=TP))
    assert repair.proposal is not None and repair.proposal.traceparent == TP


# --------------------------------------------------------------------------
# no hash moves
# --------------------------------------------------------------------------

AT = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
MESSAGE = uuid.UUID("11111111-2222-4333-8444-555555555555")
STAGE = uuid.UUID("66666666-7777-4888-9999-aaaaaaaaaaaa")
FACT = uuid.UUID("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
GOLDEN = {
    # Computed at v0.6.0, before trace context existed.
    "plan": "f7303249916af4090ce365a5510f206349858c8f8c4d2ce25ff2f2714947bf06",
    "request": "94b89d701af9c4c06aa30a58088ae7de3042fd451332746b686691cde0cd47f2",
    "genesis": "a8f783f1f08a0ed9dde806366b54104c841b453b9ac9a6295ed4b844b6cd67c5",
    "log_event": "1347f56a46df8f893d58e7402390a128c2b9901e0d31f368c31864d4a32d5141",
    "attestation": "531ac45c940738673a98c59c9ba983f7a64a755b0dc4643c0e4fb70cdca5e10a",
    "inbox_event": "a6b8307b8c4432c26129be3845e5b33f296433382eba58edbe31e4cf10fd6c9d",
    "event_statement": "989e566be68ac93d226dba4bc9ca53bd0b907f7de0f4ff59feee37580f002e95",
    "fact_statement": "a6a42dbde612243fea12824e7c999157cc31fed86550f9624f80d976a0f06eb2",
}


def _plan(traceparent: str | None = None) -> Any:
    return (
        PlanBuilder(
            "agent",
            trajectory_id="traj-golden",
            intent="golden",
            plan_id=PlanId("plan-golden"),
            created_at=AT,
            traceparent=traceparent,
        )
        .update(
            table="orders",
            statement="UPDATE orders SET status = :s WHERE id = 1",
            parameters={"s": "paid"},
            tenant_id="acme",
            stated_rows=1,
            effect_id=EffectId("eff-update"),
        )
        .enqueue(
            sink="payments",
            operation="payment_intents.create",
            payload={"amount": 500, "currency": "usd"},
            tenant_id="acme",
            effect_id=EffectId("eff-charge"),
            compensation=OutboundRequest(
                "payments", "refunds.create", {"payment_intent": {"$bind": "delivered.id"}}
            ),
        )
        .build()
    )


def _hashes(traceparent: str | None) -> dict[str, str]:
    plan = _plan(traceparent)
    request = next(e.request for e in plan.effects if e.request is not None)
    lease = Lease(
        message_id=MESSAGE,
        fence=1,
        attempts=0,
        attempt_floor=0,
        plan_id="plan-golden",
        scope_id="agent",
        effect_id="eff-charge",
        sink="payments",
        operation="payment_intents.create",
        tenant_id="acme",
        payload_text=request.canonical_payload.decode(),
        payload_hash=request.payload_hash,
        idempotency_key="idem-golden",
        not_after=AT,
        idempotency="key",
        max_attempts=5,
        backoff_base=timedelta(milliseconds=50),
        backoff_cap=timedelta(seconds=1),
        unknown_outcome="redeliver",
        lease_expires=AT,
        deadline=0.0,
        traceparent=traceparent,
    )
    attestation = attested_outcome(
        lease, 1, DeliveryResult("delivered", 200, "d" * 64, remote_ref="pi_1")
    )
    fact = InboundFact(
        fact_id=FACT,
        source="stripe",
        event_seq=1,
        event_hash="e" * 64,
        message_id=MESSAGE,
        delivery_seq=2,
        delivery_hash="f" * 64,
        remote_ref="pi_1",
        scope_id="agent",
        plan_id="plan-golden",
        tenant_id="acme",
        attestation="{}",
        event_id="evt_1",
        kind="payment_intent.succeeded",
        vendor_at=AT,
        received_at=AT,
        body_hash="b" * 64,
        part=0,
        refs=("pi_1",),
        fields={"status": "succeeded"},
        withheld=(),
        event_attestation="{}",
        traceparent=traceparent,
    )

    def sha(document: Any) -> str:
        return hashlib.sha256(canonical_bytes(document)).hexdigest()

    return {
        "plan": plan.content_hash(),
        "request": request.content_hash(),
        "genesis": genesis_hash(
            MESSAGE,
            STAGE,
            "plan-golden",
            "agent",
            "eff-charge",
            "payments",
            "payment_intents.create",
            "idem-golden",
            request.payload_hash,
        ),
        "log_event": log_hash(
            "0" * 64,
            MESSAGE,
            2,
            1,
            "delivered",
            "relay:a",
            AT,
            200,
            "d" * 64,
            "ok",
            "delivered",
            "pi_1",
            None,
            '{"alg":"ed25519"}',
        ),
        "attestation": sha(attestation.to_json()),
        "inbox_event": inbox_hash(
            "0" * 64,
            "stripe",
            1,
            "evt_1",
            "payment_intent.succeeded",
            AT,
            AT,
            "b" * 64,
            0,
            ["pi_1"],
            {"status": "succeeded"},
            [],
            "{}",
        ),
        "event_statement": sha(
            _event_statement(
                "stripe",
                "evt_1",
                "payment_intent.succeeded",
                AT,
                AT,
                "b" * 64,
                0,
                ["pi_1"],
                {"status": "succeeded"},
                [],
                "ed25519",
                "k1",
            )
        ),
        "fact_statement": sha(_fact_statement(fact, "ed25519", "k1")),
    }


@pytest.mark.parametrize("traceparent", [None, TP, OTHER])
def test_no_hash_moves_with_trace_context(traceparent: str | None) -> None:
    assert _hashes(traceparent) == GOLDEN


# --------------------------------------------------------------------------
# the outbound path
# --------------------------------------------------------------------------


def traces(outbox: Outbox) -> dict[uuid.UUID, str]:
    """Every request's trace context, as the database keeps it."""
    table = (
        "interlock.outbox_traces"
        if isinstance(outbox, PostgresOutbox)
        else "_interlock_outbox_traces"
    )
    return {
        m if isinstance(m, uuid.UUID) else uuid.UUID(str(m)): str(t)
        for m, t in outbox.fetch(f"SELECT message_id, traceparent FROM {table}")
    }


def test_a_traced_plans_requests_carry_its_context_to_the_sink(outbox: Outbox) -> None:
    _, traced = outbox.commit(mail(1), sms(2), traceparent=TP)
    _, plain = outbox.commit(mail(3))
    assert traces(outbox) == dict.fromkeys(traced, TP)
    with outbox.relay() as relay:
        outbox.drain(relay)
    calls = [c for sink in outbox.sinks.values() for c in sink.calls]
    by_message = {uuid.UUID(c.message): c.traceparent for c in calls}
    assert by_message == {traced[0]: TP, traced[1]: TP, plain[0]: None}
    # The relay attested every outcome, and every log verifies, as ever.
    outbox.verify()


def test_a_plan_with_no_requests_or_no_context_keeps_none(outbox: Outbox) -> None:
    outbox.commit(mail(1))
    assert traces(outbox) == {}
    plan = (
        PlanBuilder(SCOPE, traceparent=TP)
        .update(table="orders", statement="UPDATE orders SET status = 'seen' WHERE id = 500")
        .build()
    )
    assert outbox.engine(checkers=[BlastRadius(100)]).execute(plan).committed
    assert traces(outbox) == {}


@pytest.fixture
def stripe() -> Iterator[FakeStripe]:
    fake = FakeStripe()
    try:
        yield fake
    finally:
        fake.close()


def test_every_adapter_sends_the_context_and_a_compensation_inherits_it(
    outbox: Outbox, stripe: FakeStripe
) -> None:
    (original,) = charged(
        outbox, stripe, charge(PlanBuilder(SCOPE, traceparent=TP), "charge", 5000)
    )
    with outbox.signed("alice") as alice:
        outcome = alice.compensate([original], registry=SinkRegistry(TYPED), reason="refund")
    refund = uuid.UUID(outcome.intent.body["targets"][0]["compensation"]["message"])
    assert traces(outbox) == {original: TP, refund: TP}
    relay = Relay(
        outbox.store(),
        adapters={"stripe": StripeAdapter(KEY, base_url=stripe.url)},
        breaker=NoBreaker(),
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
        signer=relay_signer(),
    )
    with relay:
        outbox.drain(relay)
    assert [(c.path, c.traceparent) for c in stripe.calls] == [
        ("/v1/payment_intents", TP),
        ("/v1/refunds", TP),
    ]
    outbox.verify()


def test_a_header_is_sent_only_for_a_context_that_is_one() -> None:
    from interlock.adapters import trace_headers
    from interlock.relay import Delivery

    def delivery(traceparent: str | None) -> Delivery:
        return Delivery(MESSAGE, "s", "op", "k", b"{}", "h", 1, None, 1.0, traceparent)

    assert trace_headers(delivery(TP)) == {"traceparent": TP}
    assert trace_headers(delivery(None)) == {}
    assert trace_headers(delivery(TP + "\r\nX: y")) == {}


# --------------------------------------------------------------------------
# the inbound path
# --------------------------------------------------------------------------


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _webhook(ref: str, event_id: str, traceparent: str | None) -> tuple[dict[str, str], bytes]:
    headers, body = stripe_webhook(refund_event(ref, event_id=event_id))
    if traceparent is not None:
        headers = {**headers, "traceparent": traceparent}
    return headers, body


def test_a_webhooks_context_is_kept_and_decides_the_facts(site: InboxSite) -> None:
    echoed = child_traceparent(TP)
    site.deliver("re_echo", "re_quiet", "re_foreign", "re_bad", traceparent=TP)
    site.deliver("re_untraced")
    inbox = site.inbox()
    for ref, header in (
        ("re_echo", echoed),
        ("re_quiet", None),
        ("re_foreign", OTHER),
        ("re_bad", TP.upper()),
        ("re_untraced", OTHER),
    ):
        answer = site.receive(inbox, "stripe", _webhook(ref, f"evt_{ref}", header))
        assert answer.status == 200 and answer.body == {"recorded": 1, "matched": 1}, ref
    engine = site.outbox.engine(inbox=INBOX_KEYS, checkers=[BlastRadius(10)])
    by_ref = {f.remote_ref: f.traceparent for f in engine.facts("agent")}
    assert by_ref == {
        "re_echo": echoed,  # the vendor propagated ours: its span is the parent
        "re_quiet": TP,  # it sent none: the delivery's
        "re_foreign": TP,  # it sent its own trace: ours stands
        "re_bad": TP,  # an invalid header is ignored, never refused
        "re_untraced": OTHER,  # the plan had none: the webhook's
    }
    # A duplicate delivery of an event keeps the first context it came with.
    again = site.receive(inbox, "stripe", _webhook("re_quiet", "evt_re_quiet", OTHER))
    assert again.status == 200 and again.body["recorded"] == 0
    assert {f.remote_ref: f.traceparent for f in engine.facts("agent")}["re_quiet"] == TP


def test_trace_context_goes_with_what_it_describes(outbox: Outbox, tmp_path: Path) -> None:
    bench = Bench(outbox, tmp_path)
    try:
        (booked,) = bench.book_together(1, traceparent=TP)
        (other,) = bench.book_together(2, traceparent=TP)
        bench.deliver()
        cancel = bench.compensate(booked)
        bench.deliver()
        assert bench.settler().settle().credits == 1
        (pending,) = bench.book_together(3, traceparent=OTHER)
        assert traces(outbox) == {booked: TP, other: TP, cancel: TP, pending: OTHER}
        with outbox.vacuum() as vacuum:
            report = vacuum.run(reason="monthly")
        assert report.outcome == "applied" and report.messages == 3
        assert traces(outbox) == {pending: OTHER}
    finally:
        bench.close()


# --------------------------------------------------------------------------
# guarded, and upgraded in place
# --------------------------------------------------------------------------


def test_the_agent_cannot_write_trace_context(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1), traceparent=TP)
    table = (
        "interlock.outbox_traces"
        if isinstance(outbox, PostgresOutbox)
        else "_interlock_outbox_traces"
    )
    # Labelled as an observed table, so only the statement itself is refused.
    plan = (
        PlanBuilder(SCOPE)
        .update(table="orders", statement=f"UPDATE {table} SET traceparent = '{OTHER}'")
        .build()
    )
    try:
        result = outbox.engine(checkers=[BlastRadius(100)]).execute(plan)
    except InterlockError:
        pass
    else:
        assert not result.committed
    assert traces(outbox) == {message: TP}


def test_a_sqlite_outbox_of_version_5_is_upgraded_in_place(tmp_path: Path) -> None:
    path = tmp_path / "outbox.db"
    sqlite3.connect(path).close()
    install_sqlite_outbox(path, RELAY_SINKS)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("DROP TABLE _interlock_inbox_traces")
        conn.execute("DROP TABLE _interlock_outbox_traces")
        conn.commit()
        assert installed_version(conn) == 5
    with pytest.raises(SubstrateConfigurationError, match="upgrade it in place to version 6"):
        SqliteOutboxStore(path)
    install_sqlite_outbox(path, RELAY_SINKS)
    with closing(sqlite3.connect(path)) as conn:
        assert installed_version(conn) == 6
    SqliteOutboxStore(path).close()


def test_a_postgresql_install_of_version_5_is_upgraded_in_place(outbox: Outbox) -> None:
    if not isinstance(outbox, PostgresOutbox):
        pytest.skip("PostgreSQL's installation")
    from interlock.postgres import installed_version as pg_version

    with outbox.admin() as conn:
        conn.execute("DROP TABLE interlock.inbox_traces, interlock.outbox_traces")
        assert pg_version(conn) == 5
    outbox.reinstall(RELAY_SINKS)
    with outbox.admin() as conn:
        assert pg_version(conn) == 6
    _, (message,) = outbox.commit(mail(1), traceparent=TP)
    assert traces(outbox) == {message: TP}


def _sqlite_engine() -> Any:
    from interlock import EscrowEngine, SqliteSubstrate, TableSpec

    spec = TableSpec(name="orders", primary_key="id", columns=("id", "status"))
    return EscrowEngine(SqliteSubstrate(":memory:", tables=[spec]), checkers=[BlastRadius(5)])
