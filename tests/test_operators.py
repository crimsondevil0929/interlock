"""Operators, and the signed log of everything they do (``docs/EPIC3_DESIGN.md`` §6).

On both stores:

- **Signed before applied.** Every action is an intent signed with the
  operator's own key, the database action under its hash, and an outcome
  record naming the rows it wrote. Operators share one log, each signing with
  their own key; a key the configuration does not register cannot write it.
- **The database holds the line.** It refuses an operator's row without a
  signed intent's authority, and an action on a log that moved since the
  operator read it.
- **A command killed mid-way** leaves an intent the next operator resolves:
  abandoned if nothing carries its authority, applied if rows do.
- **Compensation** enqueues exactly the undo the plan carried, bound to what
  the delivery created, in reverse order, once, and late only when asked.
- **Every ghost edit is named**: an owner writing around Interlock, however
  carefully, leaves a row no signed intent accounts for; an operator log
  rewritten or cut short disagrees with its signatures or its ledger anchors.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
import pytest
from agentgov.receipts.canonical import canonical_bytes
from agentgov.receipts.signing import Ed25519Signer

from interlock import PlanBuilder
from interlock.cli import main
from interlock.deliveries import verify_delivery_log
from interlock.exceptions import OutboundRequestError, RecordIntegrityError
from interlock.operators import (
    OPERATOR_LOG,
    OperatorLog,
    OperatorRefusedError,
    load_key,
    verify_operators,
)
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.records import Keyring, RecordKind, RecordLog, read_records
from interlock.relay import NoBreaker, Relay
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE, StripeAdapter, stripe_sink
from interlock.types import EffectId, OutboundRequest
from tests.fakesink import status
from tests.fakestripe import KEY, FakeStripe
from tests.outbox_env import (
    BACKENDS,
    RELAY_SINKS,
    SCOPE,
    Outbox,
    SqliteOutbox,
    build_either,
    mail,
    sms,
)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def held(outbox: Outbox, *requests: OutboundRequest) -> list[uuid.UUID]:
    """Committed, and held by a tripped breaker."""
    _, messages = outbox.commit(*(requests or (mail(1),)))
    outbox.governor.trip(SCOPE, "ops halt")
    with outbox.relay() as relay:
        relay.run_once(limit=10)
    outbox.governor.reset(SCOPE)
    assert {outbox.state(m) for m in messages} == {"held"}
    return messages


class KilledError(Exception):
    """Where a test stops an operator command, as a kill would."""


def stop_at(point: str) -> Any:
    def check(reached: str) -> None:
        if reached == point:
            raise KilledError(point)

    return check


# --------------------------------------------------------------------------
# signed before applied
# --------------------------------------------------------------------------


def test_an_action_is_signed_before_it_is_applied(outbox: Outbox) -> None:
    (message,) = held(outbox)
    with outbox.signed("alice") as alice:
        outcome = alice.release([message], reason="the breaker tripped on a false alarm")
    assert (outcome.intent.kind, outcome.record.kind) == ("operator.intent", "operator.applied")
    (row,) = outcome.rows
    assert (row.message_id, row.event) == (message, "released")
    released = next(e for e in outbox.log(message) if e.event == "released")
    assert (released.actor, released.authority) == ("operator:alice", outcome.intent.record_hash)
    assert outcome.intent.body == {
        "action": "release",
        "targets": [{"message": str(message), "head": released.prev_hash}],
        "reason": "the breaker tripped on a false alarm",
        "operator": "alice",
    }
    assert outcome.record.body["rows"] == [
        {
            "message": str(message),
            "seq": released.seq,
            "event": "released",
            "hash": released.event_hash,
        }
    ]
    report = outbox.verify_operators()
    assert (report.problems, report.records, report.actions, report.legacy) == ((), 2, 1, 0)
    outbox.verify()


def test_operators_share_one_log_each_with_their_own_key(outbox: Outbox) -> None:
    first, second = held(outbox, mail(1), mail(2))
    with outbox.signed("alice") as alice:
        alice.release([first])
    with outbox.signed("bob") as bob:
        bob.release([second])
    records = read_records(outbox.operator_log)
    keyring = outbox.keyring()
    assert [keyring.name(r.key_id) for r in records] == ["alice", "alice", "bob", "bob"]
    RecordLog.load(outbox.operator_log, keyring)  # every record, under its own key
    # A key the configuration does not register cannot write the log.
    stranger = Ed25519Signer.generate()
    with pytest.raises(ValueError, match="no registered operator"):
        OperatorLog(outbox.operator_log, stranger, keyring)
    # Nor slip a record into it: one signed with a key of its own is named.
    rogue = Keyring(
        {**{n: k.public_key() for n, k in outbox.keys.items()}, "mallory": stranger.public_key()}
    )
    with RecordLog(stranger, log_id=OPERATOR_LOG, path=outbox.operator_log, keyring=rogue) as log:
        log.append(RecordKind.OPERATOR_INTENT, scope="operators", body={"action": "release"})
    with pytest.raises(RecordIntegrityError, match="not a registered key"):
        RecordLog.load(outbox.operator_log, keyring)
    assert any("no registered operator's" in p for p in outbox.verify_operators().problems)


def test_a_requeue_signs_for_what_died_waiting(outbox: Outbox) -> None:
    _, (first, second) = outbox.commit(mail(1), sms(2), independent=False)
    outbox.sink("mail").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert (outbox.state(first), outbox.state(second)) == ("dead", "dead")
    with outbox.signed("alice") as alice:
        outcome = alice.requeue(first)
    assert outcome.count("requeued") == 2
    assert {row.message_id for row in outcome.rows} == {first, second}
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert (outbox.state(first), outbox.state(second)) == ("delivered", "delivered")
    outbox.verify()


# --------------------------------------------------------------------------
# the database holds the line
# --------------------------------------------------------------------------


def test_the_database_refuses_an_unsigned_or_stale_action(outbox: Outbox) -> None:
    (message,) = held(outbox)
    actions = outbox.operations()
    head = actions.heads([message])[message]
    for authority in ("", "not a hash", "A" * 64):
        with pytest.raises((psycopg.Error, sqlite3.Error), match="authority"):
            actions.release(message, actor="dba", authority=authority, expected_head=head)
    # A head the log has moved past: nothing done.
    assert not actions.release(message, actor="dba", authority="a" * 64, expected_head="0" * 64)
    assert outbox.state(message) == "held"
    assert [e for e, _ in outbox.events(message)] == ["held"]


def test_an_action_on_a_log_that_moved_is_refused_and_recorded(outbox: Outbox) -> None:
    (message,) = held(outbox)

    def meanwhile(point: str) -> None:
        if point == "intent":  # someone else acts between the read and the write
            actions = outbox.operations()
            head = actions.heads([message])[message]
            assert actions.release(message, actor="other", authority="c" * 64, expected_head=head)

    with outbox.signed("alice", checkpoint=meanwhile) as alice:
        outcome = alice.release([message])
    assert not outcome.applied and outcome.record.kind == "operator.refused"
    assert outcome.skipped == ((message, "its delivery log moved after the operator read it"),)
    with outbox.signed("alice") as alice:
        refused = alice.release([message])
    assert refused.skipped == ((message, "it is pending: release does not apply"),)


def test_nothing_to_act_on_is_refused_before_anything_is_signed(outbox: Outbox) -> None:
    with outbox.signed("alice") as alice:
        with pytest.raises(OperatorRefusedError, match="no message"):
            alice.release([uuid.uuid4()])
        with pytest.raises(OperatorRefusedError, match="is held"):
            alice.release_scope("nobody")
    assert read_records(outbox.operator_log) == ()


# --------------------------------------------------------------------------
# a command killed mid-way
# --------------------------------------------------------------------------


def test_an_intent_a_killed_command_left_is_resolved_by_the_next(outbox: Outbox) -> None:
    first, second = held(outbox, mail(1), mail(2))
    # Stopped after signing, before acting: nothing carries its authority.
    with outbox.signed("alice", checkpoint=stop_at("intent")) as alice:
        with pytest.raises(KilledError):
            alice.release([first])
    assert outbox.state(first) == "held"
    assert any("has no outcome" in p for p in outbox.verify_operators().problems)
    # The next command resolves it first (abandoned), then is itself stopped
    # after acting, before recording: rows carry its authority.
    with outbox.signed("alice", checkpoint=stop_at("acted")) as alice:
        with pytest.raises(KilledError):
            alice.release([second])
    assert outbox.state(second) == "pending"
    with outbox.signed("bob") as bob:
        (applied,) = bob.resolve()
        assert bob.resolve() == []
    kinds = [r.kind for r in read_records(outbox.operator_log)]
    assert kinds == [
        "operator.intent",
        "operator.abandoned",
        "operator.intent",
        "operator.applied",
    ]
    assert applied.body["operator"] == "bob"
    assert [r["message"] for r in applied.body["rows"]] == [str(second)]
    outbox.verify()


# --------------------------------------------------------------------------
# ghost edits
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("edit", "named"),
    [
        ("unsigned", "carries no authority: it was written around Interlock"),
        ("unknown authority", "which no signed intent holds"),
        ("replayed authority", "carries the authority of an intent that does not name it"),
        ("another action", "is under the authority of a release intent"),
        ("direct state", "the message is pending, and its log leads to held"),
    ],
)
def test_every_ghost_edit_is_named(outbox: Outbox, edit: str, named: str) -> None:
    """The database's owner releases a held message around Interlock: as
    carefully as they like, the delivery log linked and hashed as Interlock
    would have. No signed intent accounts for it."""
    signed_for, victim = held(outbox, mail(1), mail(2))
    with outbox.signed("alice") as alice:
        authority = alice.release([signed_for]).intent.record_hash
    if edit == "unsigned":
        outbox.forge(victim, "released", authority=None, state_after="pending")
    elif edit == "unknown authority":
        outbox.forge(victim, "released", authority="f" * 64, state_after="pending")
    elif edit == "replayed authority":
        outbox.forge(victim, "released", authority=authority, state_after="pending")
    elif edit == "another action":
        outbox.forge(victim, "cancelled", authority=authority, state_after="cancelled")
    else:
        set_state(outbox, victim, "pending")
    problems = verify_delivery_log(outbox.operator()) + outbox.verify_operators().problems
    assert any(named in p and str(victim) in p for p in problems), problems
    if edit != "direct state":
        assert verify_delivery_log(outbox.operator()) == (), "a perfect forgery, as logs go"


def set_state(outbox: Outbox, message: uuid.UUID, state: str) -> None:
    if isinstance(outbox, SqliteOutbox):
        with closing(outbox.raw()) as conn:
            conn.execute(
                "UPDATE _interlock_outbox_state SET state = ? WHERE message_id = ?",
                (state, str(message)),
            )
    else:
        outbox.operator().execute(
            "UPDATE interlock.outbox_state SET state = %s WHERE message_id = %s", (state, message)
        )


def test_an_edited_operator_log_does_not_verify(outbox: Outbox) -> None:
    (message,) = held(outbox)
    with outbox.signed("alice") as alice:
        alice.release([message], reason="judged spurious")
    lines = outbox.operator_log.read_text().splitlines()
    record = json.loads(lines[0])
    record["body"]["reason"] = "the customer asked"
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    outbox.operator_log.write_text("\n".join(lines) + "\n")
    problems = outbox.verify_operators().problems
    assert any("altered after signing" in p for p in problems), problems


def test_a_signed_claim_the_database_contradicts_is_named(outbox: Outbox) -> None:
    """An operator (an insider, with a real key) signs that rows exist that
    do not: the database is the check on the log, as the log is on it."""
    (message,) = held(outbox)
    with outbox.signed("alice") as alice:
        alice.release([message])
    key = outbox.operator_key("alice")
    with OperatorLog(outbox.operator_log, key, outbox.keyring(), scope="operators") as log:
        intent = log.append(
            RecordKind.OPERATOR_INTENT,
            {"action": "cancel", "targets": [{"message": str(message), "head": "0" * 64}]},
        )
        log.append(
            RecordKind.OPERATOR_APPLIED,
            {
                "intent": {"seq": intent.seq, "hash": intent.record_hash},
                "rows": [
                    {"message": str(message), "seq": 9, "event": "cancelled", "hash": "e" * 64}
                ],
                "skipped": [],
            },
        )
    problems = outbox.verify_operators().problems
    assert any("which the delivery log does not hold as recorded" in p for p in problems), problems


def test_records_are_anchored_and_a_log_cut_short_is_named(outbox: Outbox) -> None:
    outbox.governor.open_root("operators", "1")
    first, second = held(outbox, mail(1), mail(2))
    with outbox.signed("alice", ledger=outbox.governor) as alice:
        alice.release([first])
        alice.release([second])
    records = read_records(outbox.operator_log)
    anchored = [e.memo for e in outbox.governor.audit_trail() if e.memo.startswith("ILOK1 ")]
    assert len(anchored) == len(records) == 4
    entries = list(outbox.governor.audit_trail())
    assert (
        verify_operators(outbox.operator(), records, outbox.keyring(), ledger=entries).problems
        == ()
    )
    # The owner deletes the second action from the log: its rows are now
    # unaccounted for, and the ledger still anchors the records cut off.
    kept = outbox.operator_log.read_text().splitlines()[:2]
    outbox.operator_log.write_text("\n".join(kept) + "\n")
    problems = verify_operators(
        outbox.operator(), read_records(outbox.operator_log), outbox.keyring(), ledger=entries
    ).problems
    assert any("it was truncated" in p for p in problems), problems
    assert any(str(second) in p and "no signed intent" in p for p in problems), problems


def test_a_record_the_ledger_could_not_take_is_anchored_later(outbox: Outbox) -> None:
    outbox.governor.open_root("operators", "1")

    class Busy:
        def anchor(self, scope: str, memo: str) -> None:
            raise RuntimeError("the ledger is held by another process")

        def audit_trail(self) -> list[Any]:
            return []

    (message,) = held(outbox)
    with outbox.signed("alice", ledger=Busy()) as alice:  # type: ignore[arg-type]
        alice.release([message])
    assert not [e for e in outbox.governor.audit_trail() if e.memo.startswith("ILOK1 ")]
    with outbox.signed("alice", ledger=outbox.governor):
        pass  # opening the log anchors what is pending
    assert len([e for e in outbox.governor.audit_trail() if e.memo.startswith("ILOK1 ")]) == 2


def test_a_registry_changed_around_a_signed_install_is_named(outbox: Outbox) -> None:
    with outbox.signed("alice") as alice:
        assert alice.installed().kind == "operator.installed"
    assert outbox.verify_operators().problems == ()
    # Installed again through Interlock, without two sinks, and signed: clean.
    outbox.reinstall(RELAY_SINKS[:2])
    with outbox.signed("alice") as alice:
        alice.installed()
    assert outbox.verify_operators().problems == ()
    # The owner turns one back on in the database itself.
    if isinstance(outbox, SqliteOutbox):
        with closing(outbox.raw()) as conn:
            conn.execute("UPDATE _interlock_sinks SET enabled = 1 WHERE name = 'pager'")
    else:
        outbox.operator().execute("UPDATE interlock.sinks SET enabled = true WHERE name = 'pager'")
    (problem,) = outbox.verify_operators().problems
    assert "sink pager changed around Interlock" in problem


# --------------------------------------------------------------------------
# compensation
# --------------------------------------------------------------------------

STRIPE = stripe_sink(
    "stripe",
    (PAYMENT_INTENTS_CREATE, REFUNDS_CREATE),
    cost_per_call=Decimal("0.30"),
    backoff_base=timedelta(milliseconds=20),
    backoff_cap=timedelta(milliseconds=160),
)
TYPED = (*RELAY_SINKS, STRIPE)
UNDO = {"payment_intent": {"$bind": "delivered.id"}}


@pytest.fixture
def stripe() -> Iterator[FakeStripe]:
    fake = FakeStripe()
    try:
        yield fake
    finally:
        fake.close()


def charge(
    builder: PlanBuilder, effect: str, amount: int, *, after: str | None = None, **kwargs: Any
) -> PlanBuilder:
    return builder.enqueue(
        sink="stripe",
        operation=PAYMENT_INTENTS_CREATE,
        payload={"amount": amount, "currency": "usd", "description": effect},
        compensation=OutboundRequest("stripe", REFUNDS_CREATE, {**UNDO, "amount": amount}),
        effect_id=EffectId(effect),
        after=None if after is None else [EffectId(after)],
        independent=after is None,
        **kwargs,
    )


def deliver(outbox: Outbox, stripe: FakeStripe) -> None:
    relay = Relay(
        outbox.store(),
        adapters={"stripe": StripeAdapter(KEY, base_url=stripe.url)},
        breaker=NoBreaker(),
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
    )
    with relay:
        outbox.drain(relay)


def charged(outbox: Outbox, stripe: FakeStripe, builder: PlanBuilder) -> list[uuid.UUID]:
    outbox.reinstall(TYPED)
    plan = builder.build()
    assert outbox.engine(sinks=SinkRegistry(TYPED)).execute(plan).committed
    deliver(outbox, stripe)
    messages = outbox.messages(plan.plan_id)
    assert {outbox.state(m) for m in messages} == {"delivered"}
    return messages


def test_a_charge_is_undone_by_its_refund_bound_to_the_payment(
    outbox: Outbox, stripe: FakeStripe
) -> None:
    (original,) = charged(outbox, stripe, charge(PlanBuilder(SCOPE), "charge", 5000))
    with outbox.signed("alice") as alice:
        outcome = alice.compensate([original], registry=SinkRegistry(TYPED), reason="refund asked")
    ((compensated,),) = [outcome.rows]
    assert (compensated.message_id, compensated.event) == (original, "compensated")
    target = outcome.intent.body["targets"][0]
    refund = uuid.UUID(target["compensation"]["message"])
    assert outbox.events(original)[-1] == ("compensated", None)
    deliver(outbox, stripe)
    assert outbox.state(refund) == "delivered"
    (made,) = stripe.of("refund")
    assert (made["payment_intent"], made["amount"]) == ("pi_000001", 5000)
    outbox.verify()
    # Once: a second compensation is refused before anything is signed.
    with outbox.signed("alice") as alice, pytest.raises(OperatorRefusedError, match="already"):
        alice.compensate([original])
    # And the refund is not itself compensable.
    with outbox.signed("alice") as alice, pytest.raises(OperatorRefusedError, match="itself"):
        alice.compensate([refund])


def test_a_plan_is_undone_in_reverse_order(outbox: Outbox, stripe: FakeStripe) -> None:
    """The second charge waited for the first, so the first's refund waits
    for the second's (E4-4)."""
    builder = charge(PlanBuilder(SCOPE), "deposit", 1000)
    first, second = charged(outbox, stripe, charge(builder, "balance", 4000, after="deposit"))
    with outbox.signed("alice") as alice, pytest.raises(OperatorRefusedError, match="first"):
        alice.compensate([first])
    with outbox.signed("alice") as alice:
        outcome = alice.compensate(plan_id=_plan_of(outbox, first))
    assert [t["message"] for t in outcome.intent.body["targets"]] == [str(second), str(first)]
    deliver(outbox, stripe)
    refunds = stripe.of("refund")
    assert [(r["payment_intent"], r["amount"]) for r in refunds] == [
        ("pi_000002", 4000),
        ("pi_000001", 1000),
    ]
    outbox.verify()


def _plan_of(outbox: Outbox, message: uuid.UUID) -> str:
    plan = outbox.operations().plan_of(message)
    assert plan is not None
    return plan


def test_a_late_undo_is_a_decision(outbox: Outbox, stripe: FakeStripe) -> None:
    (original,) = charged(
        outbox,
        stripe,
        charge(PlanBuilder(SCOPE), "charge", 700, not_after=timedelta(seconds=1)),
    )
    time.sleep(1.1)
    with outbox.signed("alice") as alice, pytest.raises(OperatorRefusedError, match="--late"):
        alice.compensate([original])
    with outbox.signed("alice") as alice:
        assert alice.compensate([original], late=True).applied


def test_the_database_enqueues_only_the_compensation_the_plan_carried(
    outbox: Outbox, stripe: FakeStripe
) -> None:
    (original,) = charged(outbox, stripe, charge(PlanBuilder(SCOPE), "charge", 5000))
    actions = outbox.operations()
    head = actions.heads([original])[original]
    elsewhere = canonical_bytes({"payment_intent": "pi_somebody_else", "amount": 5000})
    with pytest.raises(OutboundRequestError) as caught:
        actions.compensate(
            original,
            actor="dba",
            authority="d" * 64,
            expected_head=head,
            message_id=uuid.uuid4(),
            payload=elsewhere,
            idempotency_key="k",
        )
    assert caught.value.reason == "compensation"
    assert outbox.events(original)[-1] == ("delivered", 1)


def test_a_placeholder_with_nothing_to_bind_is_refused(outbox: Outbox) -> None:
    """An http sink records no reference of what it created: a compensation
    that needs one cannot be bound, and is refused; one that does not, runs."""
    orders = SinkSpec(
        "orders",
        (OperationSpec("hold", compensation="release"), OperationSpec("release")),
    )
    sinks = (*RELAY_SINKS, orders)
    outbox.reinstall(sinks)
    plan = (
        PlanBuilder(SCOPE)
        .enqueue(
            sink="orders",
            operation="hold",
            payload={"order": 500},
            compensation=OutboundRequest("orders", "release", {"hold": {"$bind": "delivered.id"}}),
            effect_id=EffectId("bound"),
        )
        .enqueue(
            sink="orders",
            operation="hold",
            payload={"order": 501},
            compensation=OutboundRequest("orders", "release", {"order": 501}),
            effect_id=EffectId("plain"),
            independent=True,
        )
        .build()
    )
    assert outbox.engine(sinks=SinkRegistry(sinks)).execute(plan).committed
    from interlock.adapters import HttpAdapter

    sink = outbox.sink("orders", honour_keys=True)
    relay = Relay(
        outbox.store(),
        adapters={
            "orders": HttpAdapter(sink.url, routes={"hold": "POST /h", "release": "POST /r"})
        },
        breaker=NoBreaker(),
    )
    with relay:
        outbox.drain(relay)
    bound, plain = outbox.messages(plan.plan_id)
    with outbox.signed("alice") as alice, pytest.raises(OperatorRefusedError, match="bind"):
        alice.compensate([bound])
    with outbox.signed("alice") as alice:
        assert alice.compensate([plain]).applied
    outbox.verify()


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def test_keygen_writes_a_key_only_its_owner_reads(tmp_path: Path) -> None:
    out = io.StringIO()
    path = tmp_path / "carol.key"
    assert main(["operator", "keygen", "--out", str(path), "--name", "carol"], out=out) == 0
    signer = load_key(path)
    assert f'carol = "{signer.public_key().spec()}"' in out.getvalue()
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert main(["operator", "keygen", "--out", str(path), "--name", "carol"], out=out) == 2
    assert load_key(path).key_id == signer.key_id, "never overwritten"
