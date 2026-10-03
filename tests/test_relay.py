"""The relay (Epic 2, phase 3), against a real PostgreSQL and a real HTTP sink.

What is checked, in the order the file goes:

- A committed request is delivered once, with its idempotency key and its
  adjudicated bytes, and every step is in its hash-linked delivery log.
- Nothing is sent before its stage commits (OB-7).
- Relays racing for work never share a message: no duplicate call without a
  crash.
- Retries back off, honour ``Retry-After``, stop at ``max_attempts`` and at the
  deadline; a permanent failure is dead at once.
- An unknown outcome is redelivered with the same key (absorbed by a sink that
  honours it, duplicated by one that does not), or dead-lettered.
- The breaker: tripped at the moment of sending, the message is held, not
  sent; unreadable, nothing is sent; an operator releases what was held.
- Order within a plan, and a dead dependency.
- A tampered payload is refused. A lease taken over cannot be overwritten.
- Operators cancel and requeue; the delivery log catches a rewritten row.
- The relay role can do nothing but relay.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")

from interlock.deliveries import (  # noqa: E402
    verify_delivery_log,
)
from interlock.outbox_store import PostgresOutboxStore  # noqa: E402
from interlock.relay import (  # noqa: E402
    BreakerReading,
    NoBreaker,
    Relay,
    retry_delay,
)
from interlock.types import outbound_key  # noqa: E402
from tests.fakesink import DROP, hang, status  # noqa: E402
from tests.outbox_env import (  # noqa: E402
    BACKENDS,
    RELAY_SINKS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    build_either,
    mail,
    page,
    sms,
)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    """The outbox on each store: every test that takes it runs on both."""
    yield from build_either(request, tmp_path)


POSTGRES_ONLY = pytest.mark.parametrize("outbox", ["postgres"], indirect=True)
"""For what only PostgreSQL has: roles, SKIP LOCKED, its triggers, its sessions."""


# --------------------------------------------------------------------------
# delivering
# --------------------------------------------------------------------------


def test_a_committed_request_is_delivered_once_with_its_key(outbox: Outbox) -> None:
    plan, (message,) = outbox.commit(mail(1))
    sink = outbox.sink("mail")
    with outbox.relay() as relay:
        report = relay.run_once()
    assert (report.claimed, report.delivered) == (1, 1)
    (call,) = sink.calls
    request = plan.effects[0].request
    assert request is not None
    assert call.key == outbound_key(plan.plan_id, plan.effects[0].effect_id)
    assert call.body == request.canonical_payload
    assert hashlib.sha256(call.body).hexdigest() == request.payload_hash
    assert (call.message, call.attempt, call.path) == (str(message), 1, "/mail/send")
    assert outbox.state(message) == "delivered"
    log = outbox.log(message)
    assert [(e.event, e.attempt, e.state_after) for e in log] == [
        ("sending", 1, "leased"),
        ("delivered", 1, "delivered"),
    ]
    assert log[0].detail is not None and log[0].detail.startswith("breaker clear at agentgov entry")
    assert log[1].status_code == 201 and log[1].response_digest is not None
    outbox.verify()


class Paused:
    """Holds a stage between its verdict and its commit, until released."""

    def __init__(self) -> None:
        self.staged = threading.Event()
        self.gate = threading.Event()


@POSTGRES_ONLY
def test_nothing_is_sent_before_its_stage_commits(outbox: PostgresOutbox) -> None:
    """OB-7: the relay reads committed rows only. A stage that has written its
    request and not committed has, to the relay, written nothing."""
    from interlock import PostgresSubstrate
    from tests.conftest import OBSERVED
    from tests.schemas import specs

    pause = Paused()

    class Holding(PostgresSubstrate):
        def commit(self, handle: Any) -> Any:
            pause.staged.set()
            assert pause.gate.wait(10)
            return super().commit(handle)

    from interlock import BlastRadius, EscrowEngine, PlanBuilder
    from tests.outbox_env import REGISTRY

    engine = EscrowEngine(
        Holding(outbox.pg.agent, tables=specs(*OBSERVED)), checkers=[BlastRadius(0)], sinks=REGISTRY
    )
    request = mail(1)
    plan = (
        PlanBuilder(SCOPE).enqueue(sink="mail", operation="send", payload=request.payload).build()
    )
    results: list[Any] = []
    stager = threading.Thread(target=lambda: results.append(engine.execute(plan)))
    stager.start()
    try:
        assert pause.staged.wait(10)
        with outbox.relay() as relay:
            assert relay.run_once().claimed == 0
            assert outbox.sink("mail").calls == []
            pause.gate.set()
            stager.join(10)
            assert results and results[0].committed
            assert relay.run_once().delivered == 1
    finally:
        pause.gate.set()
        stager.join(10)
    assert len(outbox.sink("mail").calls) == 1


@pytest.mark.parametrize("sink", ["mail", "sms"])
def test_relays_racing_never_share_a_message(outbox: Outbox, sink: str) -> None:
    """Eight relays, one hundred and twenty messages: each is called exactly
    once, by exactly one relay, whether or not the sink honours keys. Without
    a crash there is no duplicate to absorb."""
    make = mail if sink == "mail" else sms
    for batch in range(12):
        outbox.commit(*(make(batch * 10 + n) for n in range(10)))
    fake = outbox.sink(sink)
    relays = [outbox.relay(relay_id=f"racer-{n}") for n in range(8)]
    errors: list[BaseException] = []

    def work(relay: Relay) -> None:
        try:
            idle = 0
            while idle < 3:
                report = relay.run_once(limit=3)
                idle = idle + 1 if report.claimed == 0 else 0
                if report.claimed == 0:
                    time.sleep(0.02)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(r,)) for r in relays]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    for relay in relays:
        relay.close()
    assert errors == []
    assert outbox.states() == {"delivered": 120}
    assert len(fake.calls) == 120
    assert Counter(c.key for c in fake.calls).most_common(1)[0][1] == 1
    assert sum(fake.effects.values()) == 120
    callers = {e.actor for m in _all_messages(outbox) for e in outbox.log(m)}
    assert len(callers) > 1, "the work was shared"
    outbox.verify()


def _all_messages(outbox: Outbox) -> list[uuid.UUID]:
    from interlock.deliveries import messages

    return [m.message_id for m in messages(outbox.operator(), limit=100_000)]


# --------------------------------------------------------------------------
# retrying
# --------------------------------------------------------------------------


def test_a_retryable_failure_is_retried_after_its_backoff(outbox: Outbox) -> None:
    plan, (message,) = outbox.commit(mail(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    sink = outbox.sink("mail")
    sink.script(status(503), status(503), key=key)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [
        ("sending", 1),
        ("retryable", 1),
        ("sending", 2),
        ("retryable", 2),
        ("sending", 3),
        ("delivered", 3),
    ]
    assert len(sink.calls) == 3 and sink.effects[key] == 1
    log = outbox.log(message)
    for failed, next_call in ((1, 2), (3, 4)):
        attempt = log[next_call].attempt
        assert attempt is not None
        waited = log[next_call].at - log[failed].at
        due = retry_delay(
            attempt - 1,
            base=timedelta(milliseconds=20),
            cap=timedelta(milliseconds=160),
            key=key,
        )
        assert waited >= due, (waited, due)
    outbox.verify()


def test_retry_after_is_a_floor(outbox: Outbox) -> None:
    plan, (message,) = outbox.commit(mail(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    outbox.sink("mail").script(status(429, retry_after=1), key=key)
    with outbox.relay() as relay:
        relay.run_once()
        row = outbox.row(message)
        assert row["state"] == "pending" and row["reason"] == "retryable 429"
        assert relay.run_once().claimed == 0, "not due before its Retry-After"
        outbox.drain(relay)
    log = outbox.log(message)
    assert log[2].at - log[1].at >= timedelta(seconds=1)
    assert outbox.state(message) == "delivered"


def test_a_permanent_failure_is_dead_after_one_call(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    outbox.sink("mail").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [("sending", 1), ("permanent", 1)]
    row = outbox.row(message)
    assert (row["state"], row["reason"]) == ("dead", "permanent failure")
    assert len(outbox.sink("mail").calls) == 1
    outbox.verify()


def test_attempts_are_bounded(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(sms(1))
    outbox.sink("sms").script(*[status(503)] * 10)
    with outbox.relay() as relay:
        outbox.drain(relay)
    row = outbox.row(message)
    assert (row["state"], row["reason"], row["attempts"]) == ("dead", "attempts exhausted", 5)
    assert len(outbox.sink("sms").calls) == 5
    outbox.verify()


def test_a_request_past_its_deadline_is_not_sent(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1), not_after=timedelta(seconds=1))
    time.sleep(1.2)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [("expired", None)]
    assert (outbox.state(message), outbox.sink("mail").calls) == ("dead", [])
    outbox.verify()


def test_a_retry_due_after_the_deadline_is_dead_now(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1), not_after=timedelta(seconds=2))
    outbox.sink("mail").script(status(503, retry_after=5))
    with outbox.relay() as relay:
        outbox.drain(relay)
    row = outbox.row(message)
    assert row["state"] == "dead"
    assert row["reason"] == "its deadline passes before its next attempt is due"
    assert len(outbox.sink("mail").calls) == 1


# --------------------------------------------------------------------------
# unknown outcomes: what each sink's guarantee means
# --------------------------------------------------------------------------


def test_an_unknown_outcome_is_redelivered_and_absorbed_by_its_key(outbox: Outbox) -> None:
    """The sink acted and the answer was lost. Called again with the same
    key, a sink that honours keys does not act again: one effect, two calls."""
    plan, (message,) = outbox.commit(mail(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    sink = outbox.sink("mail")
    sink.script(DROP, key=key)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [
        ("sending", 1),
        ("unknown", 1),
        ("sending", 2),
        ("delivered", 2),
    ]
    assert [c.acted for c in sink.calls] == [True, False]
    assert sink.effects[key] == 1
    outbox.verify()


def test_an_unknown_outcome_on_a_keyless_sink_acts_twice(outbox: Outbox) -> None:
    """The same redelivery to a sink that does not honour keys: the duplicate
    the design admits (§7.5), and the log shows the call it came from."""
    plan, (message,) = outbox.commit(sms(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    sink = outbox.sink("sms")
    sink.script(DROP, key=key)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.state(message) == "delivered"
    assert [c.acted for c in sink.calls] == [True, True]
    assert sink.effects[key] == 2
    assert ("unknown", 1) in outbox.events(message)


def test_dead_letter_makes_an_unknown_outcome_at_most_once(outbox: Outbox) -> None:
    plan, (message,) = outbox.commit(page(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    sink = outbox.sink("pager")
    sink.script(DROP, key=key)
    with outbox.relay() as relay:
        outbox.drain(relay)
    row = outbox.row(message)
    assert row["state"] == "dead" and row["reason"].startswith("outcome unknown")
    assert len(sink.calls) == 1 and sink.effects[key] == 1
    assert outbox.events(message) == [("sending", 1), ("unknown", 1)]


def test_a_call_that_outlives_its_timeout_is_unknown(outbox: Outbox) -> None:
    plan, (message,) = outbox.commit(mail(1))
    key = outbound_key(plan.plan_id, plan.effects[0].effect_id)
    outbox.sink("mail").script(hang(1.5), key=key)
    with outbox.relay(timeout=timedelta(milliseconds=500), lease=timedelta(seconds=3)) as relay:
        relay.run_once()
        log = outbox.log(message)
        assert [e.event for e in log] == ["sending", "unknown"]
        assert "after sending" in (log[1].detail or "")
        outbox.drain(relay)
    assert outbox.state(message) == "delivered"
    assert outbox.sink("mail").effects[key] == 1


# --------------------------------------------------------------------------
# the breaker
# --------------------------------------------------------------------------


def test_a_tripped_breaker_holds_instead_of_sending(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    outbox.governor.trip(SCOPE, "ops halt")
    with outbox.relay() as relay:
        assert relay.run_once().held == 1
        assert relay.run_once().claimed == 0, "held is not pending"
    assert outbox.sink("mail").calls == []
    (held,) = outbox.log(message)
    assert (held.event, held.state_after) == ("held", "held")
    assert held.detail is not None
    assert held.detail.startswith("AgentGov has halted 'agent'")
    assert "at agentgov entry" in held.detail
    # The operator resets the breaker and releases what it held.
    outbox.governor.reset(SCOPE)
    assert outbox.release(message, actor="ops") is True
    assert outbox.release(message, actor="ops") is False, "released once"
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.state(message) == "delivered"
    assert [e.event for e in outbox.log(message)] == ["held", "released", "sending", "delivered"]
    assert outbox.log(message)[1].actor == "operator:ops"
    outbox.verify()


class TripsFirst:
    """Trips the scope's breaker the moment the relay asks: after the claim,
    before the call."""

    def __init__(self, outbox: Outbox) -> None:
        self.outbox = outbox
        self.inner = outbox.breaker()

    def check(self, scope_id: str) -> BreakerReading:
        self.outbox.governor.trip(scope_id, "tripped mid-delivery")
        return self.inner.check(scope_id)

    def close(self) -> None:
        self.inner.close()


def test_a_trip_after_the_claim_still_holds(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    breaker = TripsFirst(outbox)
    with outbox.relay(breaker=breaker) as relay:
        assert relay.run_once().held == 1
    breaker.close()
    assert outbox.sink("mail").calls == []
    assert outbox.state(message) == "held"


def test_a_trip_racing_deliveries_stops_every_call_after_it(outbox: Outbox) -> None:
    """The guarantee, exactly: every call is made under a breaker reading
    that predates the trip, and every message not called once the trip is
    in the ledger is held. Each call's reading is in its log."""
    for batch in range(6):
        outbox.commit(*(mail(batch * 10 + n) for n in range(10)))
    relays = [outbox.relay(relay_id=f"r{n}") for n in range(4)]
    stop = threading.Event()

    def work(relay: Relay) -> None:
        while not stop.is_set():
            if relay.run_once(limit=1).claimed == 0:
                time.sleep(0.01)

    threads = [threading.Thread(target=work, args=(r,)) for r in relays]
    for thread in threads:
        thread.start()
    while len(outbox.sink("mail").calls) < 15:
        time.sleep(0.005)
    outbox.governor.trip(SCOPE, "racing halt")
    tripped_at = len(outbox.governor.ledger)  # the trip is entry number tripped_at
    deadline = time.monotonic() + 30
    while outbox.unsettled() and time.monotonic() < deadline:
        time.sleep(0.02)
    stop.set()
    for thread in threads:
        thread.join(10)
    for relay in relays:
        relay.close()
    states = outbox.states()
    assert set(states) <= {"delivered", "held"} and sum(states.values()) == 60
    assert states.get("held", 0) > 0, "the trip landed before the queue drained"
    import re

    for message in _all_messages(outbox):
        for event in outbox.log(message):
            if event.event in ("sending", "held"):
                seen = int(re.search(r"agentgov entry (\d+)", event.detail or "")[1])  # type: ignore[index]
                if event.event == "sending":
                    assert seen < tripped_at, "a call was made after the trip"
                else:
                    assert seen >= tripped_at
    assert len(outbox.sink("mail").calls) == states["delivered"]
    outbox.verify()


class Unreadable:
    def check(self, scope_id: str) -> BreakerReading:
        raise RuntimeError("ledger unreachable")


def test_a_breaker_that_cannot_be_read_sends_nothing(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    with outbox.relay(breaker=Unreadable(), breaker_retry=timedelta(milliseconds=200)) as relay:
        assert relay.run_once().deferred == 1
        assert relay.run_once().claimed == 0, "deferred, not due yet"
    row = outbox.row(message)
    assert (row["state"], row["attempts"]) == ("pending", 0)
    assert outbox.sink("mail").calls == []
    time.sleep(0.25)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [("deferred", None), ("sending", 1), ("delivered", 1)]


def test_a_scope_agentgov_does_not_know_is_held(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1), scope="stranger")
    with outbox.relay() as relay:
        assert relay.run_once().held == 1
    (held,) = outbox.log(message)
    assert held.detail is not None and "not one AgentGov knows" in held.detail
    assert outbox.sink("mail").calls == []


def test_no_breaker_is_a_choice(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1), scope="stranger")
    with outbox.relay(breaker=NoBreaker()) as relay:
        assert relay.run_once().delivered == 1
    assert outbox.log(message)[0].detail == "breaker clear at no breaker"


# --------------------------------------------------------------------------
# order
# --------------------------------------------------------------------------


def test_requests_are_delivered_in_plan_order(outbox: Outbox) -> None:
    plan, (first, second) = outbox.commit(mail(1), mail(2), independent=False)
    keys = [outbound_key(plan.plan_id, e.effect_id) for e in plan.effects]
    sink = outbox.sink("mail")
    sink.script(status(503), key=keys[0])
    with outbox.relay() as relay:
        report = relay.run_once(limit=10)
        assert report.claimed == 1, "the second waits for the first"
        outbox.drain(relay)
    assert [c.key for c in sink.calls] == [keys[0], keys[0], keys[1]]
    assert outbox.state(first) == outbox.state(second) == "delivered"
    assert outbox.depends(second) == ["r0"]


def test_a_dependency_that_dies_takes_its_dependants_with_it(outbox: Outbox) -> None:
    _, (first, second, third) = outbox.commit(mail(1), mail(2), mail(3), independent=False)
    outbox.sink("mail").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert [outbox.state(m) for m in (first, second, third)] == ["dead", "dead", "dead"]
    assert outbox.events(second) == [("dependency_failed", None)]
    assert outbox.row(third)["reason"] == "dependency failed: r1"
    assert len(outbox.sink("mail").calls) == 1
    outbox.verify()


# --------------------------------------------------------------------------
# integrity and fencing
# --------------------------------------------------------------------------


def test_a_tampered_payload_is_refused(outbox: Outbox) -> None:
    """OB-2: what is sent is what was adjudicated. The outbox is append-only,
    even for its owner; one who lifts the trigger to rewrite a payload gets a
    refusal, not a delivery."""
    _, (message,) = outbox.commit(mail(1))
    outbox.tamper_payload(message, '{"subject": "s", "to": "attacker@evil.test"}')
    with outbox.relay() as relay:
        assert relay.run_once().refused == 1
    assert outbox.sink("mail").calls == []
    row = outbox.row(message)
    assert row["state"] == "dead" and row["reason"].startswith("refused: the stored payload")


def test_a_lease_taken_over_is_not_acted_on(outbox: Outbox) -> None:
    """A relay that stalls past its lease finds, when it comes back, that the
    message is another's: it does not call."""
    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    time.sleep(1.1)
    with outbox.relay(relay_id="fast") as fast:
        assert fast.run_once().delivered == 1
    assert slow._deliver(lease) == "skipped"
    slow.close()
    assert len(outbox.sink("mail").calls) == 1
    assert [e.actor for e in outbox.log(message)] == ["fast", "fast"]
    outbox.verify()


def test_a_call_whose_relay_stalled_is_recorded_lost_and_made_again(outbox: Outbox) -> None:
    """The slow relay recorded its call, and its lease ran out before its
    outcome. The next relay records the call as lost, and calls again with the
    same key. The slow relay's outcome, when it comes, is recorded too, and
    changes nothing: the message is no longer its."""
    from interlock.relay import DeliveryResult

    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    assert slow._sending(lease, "breaker clear at test") == 1
    time.sleep(1.1)
    with outbox.relay(relay_id="fast") as fast:
        assert fast.run_once().delivered == 1
    late = slow._outcome(lease, 1, DeliveryResult("delivered", status_code=201), timedelta(0))
    assert late is None
    slow.close()
    log = outbox.log(message)
    assert [(e.event, e.attempt, e.actor, e.state_after) for e in log] == [
        ("sending", 1, "slow", "leased"),
        ("lost", 1, "fast", "pending"),
        ("sending", 2, "fast", "leased"),
        ("delivered", 2, "fast", "delivered"),
        ("delivered", 1, "slow", None),
    ]
    outbox.verify()


def test_a_late_failure_cannot_undo_a_delivery(outbox: Outbox) -> None:
    from interlock.relay import DeliveryResult

    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    slow._sending(lease, "breaker clear at test")
    time.sleep(1.1)
    with outbox.relay(relay_id="fast") as fast:
        fast.run_once()
    assert (
        slow._outcome(lease, 1, DeliveryResult("permanent", status_code=400), timedelta(0)) is None
    )
    slow.close()
    assert outbox.state(message) == "delivered"
    outbox.verify()


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


def test_cancelling_a_held_request_cancels_what_waits_for_it(outbox: Outbox) -> None:
    _, (first, second) = outbox.commit(mail(1), mail(2), independent=False)
    outbox.governor.trip(SCOPE, "ops halt")
    with outbox.relay() as relay:
        assert relay.run_once(limit=10).held == 1
        assert relay.run_once(limit=10).claimed == 0, "the second waits for the held first"
    assert (outbox.state(first), outbox.state(second)) == ("held", "pending")
    assert outbox.cancel(first, actor="ops", reason="customer withdrew") is True
    assert outbox.cancel(first, actor="ops", reason="again") is False
    assert (outbox.state(first), outbox.state(second)) == ("cancelled", "dead")
    assert outbox.events(first) == [("held", None), ("cancelled", None)]
    assert outbox.row(first)["reason"] == "customer withdrew"
    outbox.verify()


def test_requeueing_a_dead_request_brings_back_what_died_waiting(outbox: Outbox) -> None:
    _, (first, second) = outbox.commit(mail(1), mail(2), independent=False)
    outbox.sink("mail").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert (outbox.state(first), outbox.state(second)) == ("dead", "dead")
    assert outbox.requeue(first, actor="ops") == 2
    assert outbox.requeue(first, actor="ops") == 0, "no longer dead"
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert (outbox.state(first), outbox.state(second)) == ("delivered", "delivered")
    assert outbox.events(first) == [
        ("sending", 1),
        ("permanent", 1),
        ("requeued", None),
        ("sending", 2),
        ("delivered", 2),
    ]
    assert outbox.row(first)["attempt_floor"] == 1
    outbox.verify()


def test_release_by_scope(outbox: Outbox) -> None:
    _, messages = outbox.commit(mail(1), mail(2))
    outbox.governor.trip(SCOPE, "ops halt")
    with outbox.relay() as relay:
        outbox.drain(relay)
    outbox.governor.reset(SCOPE)
    assert outbox.release_scope(SCOPE, actor="ops") == 2
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert [outbox.state(m) for m in messages] == ["delivered", "delivered"]


# --------------------------------------------------------------------------
# the delivery log
# --------------------------------------------------------------------------


@POSTGRES_ONLY
def test_a_rewritten_delivery_log_does_not_verify(outbox: PostgresOutbox) -> None:
    """The log is append-only, even for its owner. One who lifts the trigger
    to rewrite a row, or to remove the last, is caught by recomputation."""
    _, (message,) = outbox.commit(mail(1))
    with outbox.relay() as relay:
        outbox.drain(relay)
    outbox.verify()
    with outbox.admin() as conn:
        conn.execute("ALTER TABLE interlock.outbox_attempts DISABLE TRIGGER attempts_append_only")
        original = conn.execute(
            "SELECT detail FROM interlock.outbox_attempts WHERE message_id = %s AND seq = 1",
            (message,),
        ).fetchone()
        conn.execute(
            "UPDATE interlock.outbox_attempts SET detail = 'breaker clear, honest' "
            "WHERE message_id = %s AND seq = 1",
            (message,),
        )
        assert verify_delivery_log(conn) == (
            f"message {message}: row 1 (sending) does not hash to what it records",
        )
        assert original is not None
        conn.execute(
            "UPDATE interlock.outbox_attempts SET detail = %s WHERE message_id = %s AND seq = 1",
            (original[0], message),
        )
        assert verify_delivery_log(conn) == ()
        conn.execute(
            "DELETE FROM interlock.outbox_attempts WHERE message_id = %s AND seq = 2", (message,)
        )
        problems = verify_delivery_log(conn)
    assert any("a row was removed or rewritten" in p for p in problems), problems
    assert any("records no delivery" in p for p in problems), problems


@POSTGRES_ONLY
def test_the_log_is_linked_by_the_database_not_the_writer(outbox: PostgresOutbox) -> None:
    """Even the owner, inserting a row by hand with a forged link, gets a row
    the trigger linked properly: the chain cannot be forked or skipped."""
    _, (message,) = outbox.commit(mail(1))
    with outbox.admin() as conn:
        conn.execute(
            "INSERT INTO interlock.outbox_attempts (message_id, seq, event, actor, at, "
            "prev_hash, event_hash, state_after) VALUES (%s, 99, 'held', 'owner', now(), "
            "'forged', 'forged', 'held')",
            (message,),
        )
    (row,) = outbox.log(message)
    assert row.seq == 1 and row.prev_hash != "forged" and row.event_hash != "forged"
    assert row.recomputed() == row.event_hash


# --------------------------------------------------------------------------
# privileges
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE interlock.outbox_state SET state = 'delivered'",
        "INSERT INTO interlock.outbox_attempts (message_id, seq, event, actor, at, prev_hash, "
        "event_hash) SELECT message_id, 1, 'delivered', 'x', now(), '', '' "
        "FROM interlock.outbox",
        "SELECT interlock.outbox_release(message_id, 'x') FROM interlock.outbox",
        "SELECT interlock.outbox_requeue(message_id, 'x') FROM interlock.outbox",
        "SELECT interlock.outbox_log(message_id, 1, 'delivered', 'x', NULL, NULL, NULL, "
        "'delivered') FROM interlock.outbox",
        "UPDATE interlock.sinks SET enabled = true",
    ],
)
@POSTGRES_ONLY
def test_the_relay_role_can_only_relay(outbox: PostgresOutbox, statement: str) -> None:
    outbox.commit(mail(1))
    with (
        psycopg.connect(outbox.relay_dsn) as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute(statement)


@POSTGRES_ONLY
def test_the_stage_role_cannot_relay(outbox: PostgresOutbox) -> None:
    with (
        psycopg.connect(outbox.pg.agent) as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute("SELECT * FROM interlock.relay_claim('agent', 10, 1)")


# --------------------------------------------------------------------------
# retry_delay and the adapter, without a database
# --------------------------------------------------------------------------


def test_retry_delay_doubles_jitters_and_caps() -> None:
    base, cap = timedelta(seconds=1), timedelta(seconds=30)
    for attempt in range(1, 12):
        ceiling = min(cap, base * 2 ** (attempt - 1))
        wait = retry_delay(attempt, base=base, cap=cap, key="k")
        assert ceiling / 2 <= wait < ceiling or (wait == ceiling == cap / 1)
        assert wait == retry_delay(attempt, base=base, cap=cap, key="k"), "deterministic"
    spread = {retry_delay(3, base=base, cap=cap, key=f"k{n}") for n in range(20)}
    assert len(spread) == 20, "uncorrelated between requests"
    assert retry_delay(1, base=base, cap=cap, key="k", retry_after=7) == timedelta(seconds=7)
    assert retry_delay(60, base=base, cap=cap, key="k") <= cap
    with pytest.raises(ValueError, match="numbered from 1"):
        retry_delay(0, base=base, cap=cap, key="k")


def _delivery(**overrides: Any) -> Any:
    from interlock.relay import Delivery

    fields: dict[str, Any] = {
        "message_id": uuid.uuid4(),
        "sink": "mail",
        "operation": "send",
        "idempotency_key": "key-1",
        "payload": b'{"a":1}',
        "payload_hash": hashlib.sha256(b'{"a":1}').hexdigest(),
        "attempt": 1,
        "tenant_id": None,
        "timeout": 2.0,
    }
    return Delivery(**(fields | overrides))


@pytest.mark.parametrize(
    ("behaviour", "outcome", "code"),
    [
        (("ok",), "delivered", 201),
        (status(503), "retryable", 503),
        (status(429), "retryable", 429),
        (status(409), "retryable", 409),
        (status(404), "permanent", 404),
        (status(302), "permanent", 302),
        (DROP, "unknown", None),
    ],
)
def test_the_http_adapter_classifies(behaviour: Any, outcome: str, code: int | None) -> None:
    from interlock.adapters import HttpAdapter
    from tests.fakesink import FakeSink

    sink = FakeSink()
    try:
        sink.script(behaviour)
        result = HttpAdapter(sink.url, routes={"send": "POST /send"}).send(_delivery())
    finally:
        sink.close()
    assert (result.outcome, result.status_code) == (outcome, code)
    (call,) = sink.calls
    assert (call.key, call.attempt, call.path) == ("key-1", 1, "/send")


def test_the_http_adapter_carries_retry_after_and_credentials() -> None:
    from interlock.adapters import HttpAdapter
    from tests.fakesink import FakeSink

    sink = FakeSink()
    try:
        sink.script(status(503, retry_after=7))
        seen: list[int] = []

        def credentials() -> dict[str, str]:
            seen.append(1)
            return {"Authorization": "Bearer from-env"}

        adapter = HttpAdapter(sink.url, routes={"send": "PUT /send"}, headers=credentials)
        result = adapter.send(_delivery())
    finally:
        sink.close()
    assert result.retry_after == 7 and seen == [1]


def test_the_http_adapter_knows_what_was_not_sent() -> None:
    from interlock.adapters import HttpAdapter

    with socket_closed_port() as port:
        result = HttpAdapter(f"http://127.0.0.1:{port}", routes={"send": "POST /s"}).send(
            _delivery()
        )
    assert result.outcome == "retryable" and "not sent" in result.detail
    no_route = HttpAdapter("http://127.0.0.1:9", routes={"send": "POST /s"}).send(
        _delivery(operation="cancel")
    )
    assert no_route.outcome == "permanent"
    with pytest.raises(ValueError, match="http"):
        HttpAdapter("file:///etc/passwd", routes={})
    with pytest.raises(ValueError, match="METHOD /path"):
        HttpAdapter("http://x", routes={"send": "send"})


def socket_closed_port() -> Any:
    import contextlib
    import socket

    @contextlib.contextmanager
    def closed() -> Iterator[int]:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        yield port

    return closed()


def test_a_relay_refuses_a_lease_shorter_than_two_timeouts(outbox: Outbox) -> None:
    with pytest.raises(ValueError, match="twice"):
        outbox.relay(lease=timedelta(seconds=3), timeout=timedelta(seconds=2))
    with pytest.raises(ValueError, match="adapter"):
        Relay(outbox.store(), adapters={}, breaker=NoBreaker())


# --------------------------------------------------------------------------
# running for real: the long-lived loop, and the command
# --------------------------------------------------------------------------


@POSTGRES_ONLY
def test_a_running_relay_survives_losing_its_database(outbox: PostgresOutbox) -> None:
    """``run`` delivers until stopped. A connection the server ends is a
    pause, not a death: the relay reconnects and carries on."""
    relay = outbox.relay(relay_id="long-lived")
    stop = threading.Event()
    reports: list[Any] = []
    worker = threading.Thread(target=lambda: reports.append(relay.run(stop, poll=0.05)))
    worker.start()
    try:
        outbox.commit(mail(1))
        deadline = time.monotonic() + 20
        while outbox.states().get("delivered", 0) < 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        with outbox.admin() as conn:
            killed = conn.execute(
                "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = %s",
                (outbox.relay_role,),
            ).fetchone()
        assert killed is not None and killed[0] >= 1
        outbox.commit(mail(2))
        while outbox.states().get("delivered", 0) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stop.set()
        worker.join(30)
        relay.close()
    assert outbox.states() == {"delivered": 2}
    assert reports and reports[0].delivered == 2


CONFIG = """
substrate = "postgres"
database = "{admin}"

[[tables]]
name = "orders"
columns = ["id", "customer_id", "tenant", "status", "total"]
tenant_column = "tenant"

[[sinks]]
name = "mail"
cost_per_call = "0.002"
max_payload_bytes = 4096
max_attempts = 5
backoff_base_seconds = 0.02
backoff_cap_seconds = 0.16

[[sinks.operations]]
name = "send"
schema = "mail-send.json"

[[sinks]]
name = "sms"
idempotency = "none"

[[sinks.operations]]
name = "send"

[relay]
database = "{relay}"
ledger = "{ledger}"
lease_seconds = 4
timeout_seconds = 1
poll_seconds = 0.05

[[relay.endpoints]]
sink = "mail"
url = "{mail}"
routes = {{ send = "POST /mail/send" }}
header_env = {{ Authorization = "INTERLOCK_TEST_MAIL_AUTH" }}

[[relay.endpoints]]
sink = "sms"
url = "{sms}"
routes = {{ send = "POST /sms/send" }}
"""


def write_config(outbox: PostgresOutbox, tmp_path: Path) -> Path:
    import json

    from tests.schemas import MAIL_SEND_SCHEMA

    (tmp_path / "mail-send.json").write_text(json.dumps(MAIL_SEND_SCHEMA))
    path = tmp_path / "interlock.toml"
    path.write_text(
        CONFIG.format(
            admin=outbox.pg.admin,
            relay=outbox.relay_dsn,
            ledger=outbox.ledger_path,
            mail=outbox.sink("mail").url,
            sms=outbox.sink("sms").url,
        )
    )
    return path


def cli(*argv: str) -> tuple[int, str]:
    import io

    from interlock.cli import main

    out = io.StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


@POSTGRES_ONLY
def test_interlock_relay_delivers_with_credentials_from_its_environment(
    outbox: PostgresOutbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(outbox, tmp_path)
    _, (message,) = outbox.commit(mail(1))
    monkeypatch.delenv("INTERLOCK_TEST_MAIL_AUTH", raising=False)
    code, _ = cli("relay", "--config", str(path), "--once")
    assert code == 3, "a credential missing from the environment is a configuration error"
    assert outbox.state(message) == "pending"
    monkeypatch.setenv("INTERLOCK_TEST_MAIL_AUTH", "Bearer from-the-environment")
    code, out = cli("relay", "--config", str(path), "--once", "--relay-id", "cli")
    assert code == 0, out
    assert "claimed 1: delivered 1" in out
    (call,) = outbox.sink("mail").calls
    assert call.authorization == "Bearer from-the-environment"
    assert [e.actor for e in outbox.log(message)] == ["cli:0", "cli:0"]


@POSTGRES_ONLY
def test_interlock_outbox_inspects_verifies_and_acts(
    outbox: PostgresOutbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INTERLOCK_TEST_MAIL_AUTH", "Bearer x")
    path = str(write_config(outbox, tmp_path))
    _, (held, failing) = outbox.commit(mail(1), sms(2))
    outbox.sink("sms").script(status(400))
    outbox.governor.trip(SCOPE, "ops halt")
    assert cli("relay", "--config", path, "--once")[0] == 0
    code, out = cli("outbox", "status", "--config", path)
    assert code == 0 and "held       2" in out
    outbox.governor.reset(SCOPE)
    assert cli("outbox", "release", str(failing), "--config", path, "--actor", "ops")[0] == 0
    assert cli("relay", "--config", path, "--once")[0] == 0
    code, out = cli("outbox", "list", "--config", path, "--state", "dead")
    assert code == 0 and str(failing) in out and "permanent failure" in out
    code, out = cli("outbox", "show", str(failing), "--config", path)
    assert code == 0
    assert [line.split()[2] for line in out.splitlines()] == [
        "held",
        "released",
        "sending",
        "permanent",
    ]
    assert cli("outbox", "requeue", str(failing), "--config", path, "--actor", "ops")[0] == 0
    assert (
        cli("outbox", "cancel", str(failing), "--config", path, "--reason", "wrong number")[0] == 0
    )
    assert cli("outbox", "cancel", str(failing), "--config", path, "--reason", "again")[0] == 1
    code, out = cli("outbox", "release", "--scope", SCOPE, "--config", path, "--actor", "ops")
    assert code == 0 and "released 1 message(s)" in out
    assert cli("relay", "--config", path, "--once")[0] == 0
    assert (outbox.state(held), outbox.state(failing)) == ("delivered", "cancelled")
    code, out = cli("outbox", "verify", "--config", path)
    assert (code, out.strip()) == (0, "every delivery log verifies")
    with outbox.admin() as conn:
        conn.execute("ALTER TABLE interlock.outbox_attempts DISABLE TRIGGER attempts_append_only")
        conn.execute("DELETE FROM interlock.outbox_attempts WHERE message_id = %s", (held,))
    code, out = cli("outbox", "verify", "--config", path)
    assert code == 1 and str(held) in out


@POSTGRES_ONLY
def test_a_claim_never_waits_on_another(outbox: PostgresOutbox) -> None:
    """``FOR UPDATE SKIP LOCKED``: a relay whose claim is still open holds its
    messages' rows, and another relay's claim skips them instead of waiting,
    taking what is free."""
    outbox.commit(mail(1), mail(2))
    inside = threading.Event()
    leave = threading.Event()

    class Slow(Relay):
        __slots__ = ()

        def _reached(self, point: str, lease: Any) -> None:
            if point == "claim-uncommitted":
                inside.set()
                assert leave.wait(10)

    slow = Slow(
        outbox.relay_dsn,
        adapters=outbox.adapters(),
        breaker=outbox.breaker(),
        relay_id="slow",
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
    )
    holder = threading.Thread(target=lambda: slow._claim(1))
    holder.start()
    try:
        assert inside.wait(10)
        with outbox.relay(relay_id="quick") as quick:
            started = time.monotonic()
            leases = quick._claim(2)
            waited = time.monotonic() - started
        assert len(leases) == 1, "took the free message, skipped the locked one"
        assert waited < 1.0, f"waited {waited:.2f}s on another relay's claim"
    finally:
        leave.set()
        holder.join(10)
        slow.close()


def test_a_late_delivery_is_the_truth_even_after_a_dead_letter(outbox: Outbox) -> None:
    """A relay stalls mid-call on an at-most-once sink; its lease runs out and
    the call is declared lost, so the message is dead. Then the call's answer
    arrives: delivered. The sink acted, so the message is delivered, and the
    log says how it got there."""
    from interlock.relay import DeliveryResult

    _, (message,) = outbox.commit(page(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    assert slow._sending(lease, "breaker clear at test") == 1
    time.sleep(1.1)
    with outbox.relay(relay_id="sweeper") as sweeper:
        assert sweeper.run_once().claimed == 0
    assert outbox.state(message) == "dead"
    state = slow._outcome(lease, 1, DeliveryResult("delivered", status_code=201), timedelta(0))
    slow.close()
    assert state == "delivered" and outbox.state(message) == "delivered"
    (*_, late) = outbox.log(message)
    assert late.detail is not None and "delivered after the message was dead" in late.detail
    outbox.verify()


# --------------------------------------------------------------------------
# the edges of one delivery
# --------------------------------------------------------------------------


@POSTGRES_ONLY
def test_an_outcome_is_recorded_through_a_lost_connection(outbox: PostgresOutbox) -> None:
    """The call was made, and the relay's connection is ended before it can
    record what came back. It reconnects and records it, still holding the
    lease: no lost call, no second call."""

    class Severed(Relay):
        __slots__ = ()

        def _reached(self, point: str, lease: Any) -> None:
            if point == "called":
                store = self.store
                assert isinstance(store, PostgresOutboxStore)
                pid = store.connection().info.backend_pid
                with outbox.admin() as conn:
                    conn.execute("SELECT pg_terminate_backend(%s)", (pid,))

    _, (message,) = outbox.commit(mail(1))
    relay = Severed(outbox.relay_dsn, adapters=outbox.adapters(), breaker=outbox.breaker())
    try:
        assert relay.run_once().delivered == 1
    finally:
        relay.close()
    assert outbox.events(message) == [("sending", 1), ("delivered", 1)]
    assert len(outbox.sink("mail").calls) == 1


def test_recording_an_outcome_twice_records_it_once(outbox: Outbox) -> None:
    """A reply lost after the commit makes the retry find the outcome already
    recorded: that is success, and the log holds one outcome."""
    from interlock.relay import DeliveryResult

    _, (message,) = outbox.commit(mail(1))
    relay = outbox.relay(relay_id="twice")
    (lease,) = relay._claim(1)
    attempt = relay._sending(lease, "breaker clear at test")
    assert attempt == 1
    done = DeliveryResult("delivered", status_code=201)
    assert relay._outcome(lease, attempt, done, timedelta(0)) == "delivered"
    assert relay._outcome(lease, attempt, done, timedelta(0)) is None
    relay.close()
    assert outbox.events(message) == [("sending", 1), ("delivered", 1)]


def test_a_lease_about_to_run_out_is_not_used_for_a_call(outbox: Outbox) -> None:
    """A call is only made with time left on the lease to record it: a relay
    that got there late gives the message back instead."""

    class Late(Relay):
        __slots__ = ()

        def _reached(self, point: str, lease: Any) -> None:
            if point == "checked":
                time.sleep(lease.deadline - time.monotonic())

    _, (message,) = outbox.commit(mail(1))
    late = Late(
        outbox.store(),
        adapters=outbox.adapters(),
        breaker=outbox.breaker(),
        lease=timedelta(seconds=1),
        timeout=timedelta(seconds=0.4),
    )
    try:
        assert late.run_once().deferred == 1
    finally:
        late.close()
    assert outbox.sink("mail").calls == []
    assert outbox.events(message) == [("deferred", None)]
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.state(message) == "delivered"


class Raising:
    def send(self, delivery: Any) -> Any:
        raise RuntimeError("socket on fire")


def test_an_adapter_that_raises_is_an_unknown_outcome(outbox: Outbox) -> None:
    """Whatever an adapter raises, the call may have been made."""
    _, (message,) = outbox.commit(page(1))
    relay = Relay(outbox.store(), adapters={"pager": Raising()}, breaker=outbox.breaker())
    try:
        relay.run_once()
    finally:
        relay.close()
    (_, unknown) = outbox.log(message)
    assert unknown.event == "unknown" and "socket on fire" in (unknown.detail or "")
    assert outbox.state(message) == "dead", "the pager does not redeliver an unknown outcome"


@POSTGRES_ONLY
def test_the_breaker_reads_a_ledger_shared_through_postgresql(outbox: PostgresOutbox) -> None:
    from agentgov import BudgetManager

    from interlock.relay import LedgerBreaker

    with BudgetManager.open_postgres(outbox.pg.admin) as governor:
        governor.open_root("fleet", "10")
        # The relay reads the ledger as itself, with read access and no more.
        with outbox.admin() as conn:
            conn.execute(f"GRANT USAGE ON SCHEMA agentgov TO {outbox.relay_role}")
            conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA agentgov TO {outbox.relay_role}")
        _, (first,) = outbox.commit(mail(1), scope="fleet")
        breaker = LedgerBreaker.open(outbox.relay_dsn)
        with outbox.relay(breaker=breaker) as relay:
            assert relay.run_once().delivered == 1
            governor.trip("fleet", "fleet halt")
            _, (second,) = outbox.commit(mail(2), scope="fleet")
            assert relay.run_once().held == 1
        breaker.close()
    assert (outbox.state(first), outbox.state(second)) == ("delivered", "held")


def test_a_redirect_is_never_followed(outbox: Outbox) -> None:
    """An endpoint is configured, not discovered: a sink that redirects is
    answered as a permanent failure, and the address it names is never called."""
    from tests.fakesink import FakeSink, redirect

    elsewhere = FakeSink()
    try:
        _, (message,) = outbox.commit(mail(1))
        outbox.sink("mail").script(redirect(elsewhere.url + "/internal/admin"))
        with outbox.relay() as relay:
            outbox.drain(relay)
        assert elsewhere.calls == []
    finally:
        elsewhere.close()
    row = outbox.row(message)
    assert row["state"] == "dead"
    (_, failed) = outbox.log(message)
    assert failed.status_code == 302 and "not followed" in (failed.detail or "")


def test_retry_after_as_an_http_date() -> None:
    from email.utils import format_datetime

    from interlock.adapters import _seconds

    soon = format_datetime(datetime.now(UTC) + timedelta(seconds=90), usegmt=True)
    seconds = _seconds(soon)
    assert seconds is not None and 85 <= seconds <= 90
    assert _seconds("120") == 120
    assert _seconds("next tuesday") is None
    assert _seconds(None) is None
    past = format_datetime(datetime.now(UTC) - timedelta(seconds=90), usegmt=True)
    assert _seconds(past) == 0


@POSTGRES_ONLY
def test_what_a_relay_refuses_to_be(outbox: PostgresOutbox) -> None:
    from interlock.exceptions import SubstrateUnavailableError
    from interlock.relay import DeliveryResult

    with pytest.raises(ValueError, match="at least one message"):
        outbox.relay(batch=0)
    with pytest.raises(SubstrateUnavailableError, match="cannot reach"):
        Relay(
            "postgresql://nobody@127.0.0.1:1/none?connect_timeout=1",
            adapters={"mail": Raising()},
            breaker=NoBreaker(),
        )
    with pytest.raises(ValueError, match="not an outcome"):
        DeliveryResult("maybe")


@POSTGRES_ONLY
def test_a_relay_process_stops_cleanly_on_sigterm(
    outbox: PostgresOutbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``interlock relay`` as an operator runs it: until told to stop. On
    SIGTERM it finishes the call in hand, records it, reports, and exits 0."""
    import os
    import signal
    import subprocess
    import sys

    monkeypatch.setenv("INTERLOCK_TEST_MAIL_AUTH", "Bearer x")
    path = write_config(outbox, tmp_path)
    outbox.commit(mail(1), mail(2))
    root = Path(__file__).resolve().parent.parent
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-c",
            "from interlock.cli import main_entry; main_entry()",
            "relay",
            "--config",
            str(path),
            "--workers",
            "2",
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "INTERLOCK_TEST_MAIL_AUTH": "Bearer x"},
    )
    try:
        deadline = time.monotonic() + 30
        while outbox.states().get("delivered", 0) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert outbox.states() == {"delivered": 2}
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    assert process.returncode == 0, err.decode()
    assert b"relaying with 2 worker(s)" in out
    assert b"claimed 2: delivered 2" in out


def test_an_expired_lease_records_no_call(outbox: Outbox) -> None:
    """The database refuses a call on a lease that has run out, even before
    another relay has taken it: the message may be claimed at any moment."""
    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    time.sleep(1.1)
    assert slow._sending(lease, "breaker clear at test") is None
    slow.close()
    assert outbox.events(message) == []
    assert outbox.row(message)["attempts"] == 0


def test_a_deadline_that_passes_after_the_claim_sends_nothing(outbox: Outbox) -> None:
    """The deadline is checked again when the call is recorded: a message
    whose deadline passed while it sat leased expires, unsent."""
    _, (message,) = outbox.commit(mail(1), not_after=timedelta(seconds=1))
    relay = outbox.relay(breaker=NoBreaker())
    (lease,) = relay._claim(1)
    time.sleep(1.1)
    assert relay._sending(lease, "breaker clear at test") is None
    relay.close()
    assert outbox.state(message) == "dead"
    assert outbox.events(message) == [("expired", None)]
    assert outbox.sink("mail").calls == []
    outbox.verify()


def test_a_sink_disabled_after_the_claim_holds_its_message(outbox: Outbox) -> None:
    """Installing without a sink disables it at once, even for a message a
    relay has already leased: the call is not made, and the message waits for
    an operator."""
    _, (message,) = outbox.commit(mail(1))
    relay = outbox.relay(breaker=NoBreaker())
    (lease,) = relay._claim(1)
    outbox.reinstall(tuple(s for s in RELAY_SINKS if s.name != "mail"))
    assert relay._sending(lease, "breaker clear at test") is None
    assert outbox.state(message) == "held"
    assert outbox.events(message) == [("held", None)]
    assert outbox.row(message)["reason"] == "sink disabled"
    outbox.reinstall(RELAY_SINKS)
    assert outbox.release(message, actor="ops")
    outbox.drain(relay)
    relay.close()
    assert outbox.state(message) == "delivered"
    outbox.verify()


def test_a_call_cut_off_on_its_last_attempt_is_dead(outbox: Outbox) -> None:
    """A relay that died with its call recorded has spent that attempt: when
    it was the last one, the relay that takes the message over records the
    call lost and the message dead, and makes no call."""
    outbox.reinstall(
        tuple(replace(s, max_attempts=1) if s.name == "mail" else s for s in RELAY_SINKS)
    )
    _, (message,) = outbox.commit(mail(1))
    stalled = outbox.relay(
        relay_id="stalled",
        breaker=NoBreaker(),
        lease=timedelta(seconds=1),
        timeout=timedelta(seconds=0.4),
    )
    (lease,) = stalled._claim(1)
    assert stalled._sending(lease, "breaker clear at test") == 1
    stalled.close()  # dead here: the call recorded, never made
    time.sleep(1.1)
    with outbox.relay(relay_id="survivor", breaker=NoBreaker()) as survivor:
        assert survivor.run_once().claimed == 0
    assert outbox.state(message) == "dead"
    assert outbox.events(message) == [("sending", 1), ("lost", 1)]
    assert outbox.row(message)["reason"] == "attempts exhausted"
    assert outbox.sink("mail").calls == []
    outbox.verify()


def test_a_lease_taken_over_can_neither_hold_nor_defer_nor_refuse(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4))
    (lease,) = slow._claim(1)
    time.sleep(1.1)
    with outbox.relay(relay_id="fast", breaker=NoBreaker()) as fast:
        (taken,) = fast._claim(1)
        assert slow._hold(lease, "tripped, says the slow relay") == "skipped"
        assert slow._defer(lease, "later, says the slow relay", timedelta(0)) == "skipped"
        assert slow._refuse(lease, "tampered, says the slow relay") == "skipped"
        assert outbox.state(message) == "leased"
        assert fast._deliver(taken) == "delivered"
    slow.close()
    assert outbox.events(message) == [("sending", 1), ("delivered", 1)]
    outbox.verify()


# --------------------------------------------------------------------------
# without a database: the breaker over a SQLite ledger, and the command's
# configuration errors
# --------------------------------------------------------------------------


def test_the_breaker_reads_a_sqlite_ledger_fresh_every_time(tmp_path: Path) -> None:
    from agentgov import BudgetManager

    from interlock.relay import LedgerBreaker

    path = str(tmp_path / "ledger.db")
    with BudgetManager.open_sqlite(path) as governor:
        governor.open_root("agent", "10")
        breaker = LedgerBreaker.open(path)
        try:
            live = breaker.check("agent")
            assert live.halted is None and live.position.startswith("agentgov entry ")
            governor.trip("agent", "ops halt")
            halted = breaker.check("agent")
            assert halted.halted is not None and "'agent'" in halted.halted
            assert halted.position != live.position, "the trip was read, not a stale view"
            stranger = breaker.check("stranger")
            assert stranger.halted == "scope 'stranger' is not one AgentGov knows"
        finally:
            breaker.close()
    assert NoBreaker().check("anyone").halted is None


def test_a_relay_report_adds_up() -> None:
    from interlock.relay import RelayReport

    report = RelayReport(claimed=3).counted("delivered").counted("pending").counted("held")
    report = report.counted("deferred").counted("refused").counted("dead").counted("leased")
    assert report == RelayReport(
        claimed=3, delivered=1, retrying=1, dead=1, held=1, deferred=1, refused=1, skipped=1
    )
    assert report + RelayReport(claimed=1) == RelayReport(
        claimed=4, delivered=1, retrying=1, dead=1, held=1, deferred=1, refused=1, skipped=1
    )


NO_RELAY = """
substrate = "postgres"
database = "postgresql://agent@127.0.0.1:1/none"

[[tables]]
name = "orders"
columns = ["id"]
"""


@pytest.mark.parametrize(
    ("extra", "argv", "message"),
    [
        ("", ("relay",), "no [relay] section"),
        (
            '\n[[sinks]]\nname = "mail"\n[[sinks.operations]]\nname = "send"\n'
            '[relay]\nbreaker = "none"\n[[relay.endpoints]]\nsink = "mail"\n'
            'url = "http://127.0.0.1:1"\nroutes = { send = "POST /s" }\n',
            ("relay",),
            "no database for the relay",
        ),
        (
            '\n[[sinks]]\nname = "mail"\n[[sinks.operations]]\nname = "send"\n'
            '[relay]\ndatabase = "postgresql://relay@127.0.0.1:1/none"\nbreaker = "none"\n'
            '[[relay.endpoints]]\nsink = "mail"\nurl = "http://127.0.0.1:1"\n'
            'routes = { send = "POST /s" }\nheader_env = { Authorization = "NOT_SET_ANYWHERE" }\n',
            ("relay",),
            "NOT_SET_ANYWHERE",
        ),
    ],
)
def test_the_relay_command_names_what_is_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    extra: str,
    argv: tuple[str, ...],
    message: str,
) -> None:
    monkeypatch.delenv("INTERLOCK_RELAY_DATABASE", raising=False)
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    path = tmp_path / "interlock.toml"
    path.write_text(NO_RELAY + extra)
    code, _ = cli(*argv, "--config", str(path), "--once")
    assert code == 3
    assert message in capsys.readouterr().err


def test_the_outbox_command_on_a_missing_sqlite_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(
        NO_RELAY.replace('substrate = "postgres"', 'substrate = "sqlite"').replace(
            "postgresql://agent@127.0.0.1:1/none", str(tmp_path / "missing.sqlite")
        )
    )
    code, _ = cli("outbox", "status", "--config", str(path))
    assert code == 4 and "cannot open the outbox" in capsys.readouterr().err
