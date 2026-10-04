"""Settlement (``docs/EPIC4_DESIGN.md`` §4), on both stores.

- A delivered request is receipted: an ARC1 delivery receipt, carrying the
  relay's attestation, bound to the action receipt of the plan that committed
  it, which agentgov's own verifier passes, and fails against another plan's.
- A delivered compensation credits the agent's scope with the
  ``cost_per_call`` the ledger charged for the original request: never the
  customer's money the request moved.
- Settling again settles nothing twice.
- A ghost compensation earns nothing and is not settled; one whose operator
  intent awaits resolution waits for it; one whose plan was never charged, or
  that a settler without a ledger settles, is settled without a credit, and
  says why.
- The settlement row is written once, for a delivered request only; the
  settler role on PostgreSQL may record settlements and do nothing else.
- :func:`~interlock.settlement.verify_settlements` holds the settlements, the
  receipt log and the ledger to each other.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov.core import EntryType
from agentgov.receipts import verify_bundle

from interlock.deliveries import Settled
from interlock.deliveries import settlements as wrap
from interlock.settlement import CREDIT_MEMO, verify_settlements
from tests.outbox_env import (
    BACKENDS,
    RELAYS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    build_either,
    relay_signer,
)
from tests.settling import BOOKINGS, LOG_KEY, Bench
from tests.test_attestations import ghost

POSTGRES_ONLY = pytest.mark.parametrize("outbox", ["postgres"], indirect=True)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def bench(outbox: Outbox, tmp_path: Path) -> Iterator[Bench]:
    built = Bench(outbox, tmp_path)
    try:
        yield built
    finally:
        built.close()


def credits(bench: Bench) -> list[Any]:
    return [
        e
        for e in bench.outbox.governor.audit_trail(SCOPE)
        if e.entry_type is EntryType.REVERSAL and e.memo.startswith(CREDIT_MEMO)
    ]


def settlements(bench: Bench) -> dict[uuid.UUID, Settled]:
    return wrap(bench.source()).settlements()


def test_a_delivery_is_receipted_bound_to_its_plans_action_receipt(bench: Bench) -> None:
    first, second = bench.book(1), bench.book(2)
    bench.deliver()
    report = bench.settler().settle()
    assert (sorted(report.settled), report.receipts, report.credits, report.problems) == (
        sorted([first, second]),
        2,
        0,
        (),
    )
    receipts = bench.deliveries()
    assert sorted(receipts) == sorted([str(first), str(second)])
    for message, (receipt,) in receipts.items():
        # agentgov's verifier passes it: the log's signature, the relay's
        # attestation, inclusion, and the binding to its plan's receipt.
        assert bench.verified(receipt) == 0
        rows = settlements(bench)
        assert rows[uuid.UUID(message)].receipt_id == receipt.receipt_id
    # And against another plan's action receipt, the binding fails.
    one, two = receipts[str(first)][0], receipts[str(second)][0]
    index = bench.log.index_of(one.receipt_id)
    other = bench.log.index_of(two.action.receipt_id)
    assert index is not None and other is not None
    wrong = verify_bundle(
        bench.log.bundle(index),
        issuer_key=LOG_KEY,
        relay_keys=[relay_signer().public_key()],
        action=bench.log.bundle(other),
    )
    assert wrong.exit_code == 10  # BINDING
    assert verify_settlements(bench.source(), log=bench.log, relays=RELAYS) == ()


def test_a_delivered_compensation_credits_what_the_ledger_charged(bench: Bench) -> None:
    booked = bench.book(1)
    bench.deliver()
    before = bench.outbox.governor.available(SCOPE)
    cancel = bench.compensate(booked)
    bench.deliver()
    report = bench.settler().settle()
    assert (sorted(report.settled), report.receipts, report.credits, report.problems) == (
        sorted([booked, cancel]),
        2,
        1,
        (),
    )
    (credit,) = credits(bench)
    # The cost_per_call the plan was charged for the request, not the 500.00
    # the booking moved.
    assert credit.amount == BOOKINGS.cost_per_call == Decimal("0.25")
    assert credit.memo.startswith(f"{CREDIT_MEMO}{cancel} compensates {booked}")
    assert bench.outbox.governor.available(SCOPE) == before + Decimal("0.25")
    rows = settlements(bench)
    assert rows[cancel].credit == credit.entry_hash and rows[cancel].note == ""
    assert rows[booked].credit is None and rows[booked].receipt_id is not None
    # The compensation is receipted against the plan that committed it.
    (receipt,) = bench.deliveries()[str(cancel)]
    (original,) = bench.deliveries()[str(booked)]
    assert receipt.action == original.action
    assert bench.verified(receipt) == 0
    assert (
        verify_settlements(
            bench.source(),
            log=bench.log,
            relays=RELAYS,
            ledger=bench.outbox.governor.audit_trail(),
        )
        == ()
    )


def test_settling_again_settles_nothing_twice(bench: Bench) -> None:
    booked = bench.book(1)
    bench.deliver()
    bench.compensate(booked)
    bench.deliver()
    assert bench.settler().settle().credits == 1
    again = bench.settler().settle()
    assert (again.settled, again.receipts, again.credits, again.problems) == ((), 0, 0, ())
    assert len(credits(bench)) == 1
    assert sum(len(r) for r in bench.deliveries().values()) == 2


def test_a_ghost_compensation_earns_nothing(bench: Bench) -> None:
    """A compensation's delivery no relay reported: not settled, not
    credited, reported every run."""
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    ghost(bench.outbox, cancel, None)
    report = bench.settler().settle()
    assert report.settled == (booked,) and report.credits == 0
    (problem,) = report.problems
    assert f"message {cancel}" in problem and "no relay attestation" in problem
    assert credits(bench) == []
    assert cancel not in settlements(bench)
    assert bench.settler().settle().problems == report.problems


def test_a_compensation_whose_intent_awaits_resolution_waits(bench: Bench) -> None:
    """The operator's process died after acting, before recording the intent
    applied: no credit until the next operator command resolves it."""
    booked = bench.book(1)
    bench.deliver()

    class DiedError(Exception):
        pass

    def die(point: str) -> None:
        if point == "acted":
            raise DiedError

    with pytest.raises(DiedError):
        bench.compensate(booked, checkpoint=die)
    (cancel,) = [m for m in bench.outbox.messages(_plan(bench, booked)) if m != booked]
    bench.deliver()
    report = bench.settler().settle()
    assert report.settled == (booked,) and report.credits == 0
    (problem,) = report.problems
    assert f"message {cancel}" in problem and "has no outcome recorded yet" in problem
    # Nothing issued for it while it waits: no receipt that no settlement names.
    assert str(cancel) not in bench.deliveries()
    assert verify_settlements(bench.source(), log=bench.log, relays=RELAYS) == ()
    with bench.outbox.signed("ops") as operator:
        assert len(operator.resolve()) == 1
    resolved = bench.settler().settle()
    assert (resolved.settled, resolved.credits, resolved.problems) == ((cancel,), 1, ())


def _plan(bench: Bench, message: uuid.UUID) -> str:
    table = "interlock.outbox" if bench.outbox.backend == "postgres" else "_interlock_outbox"
    mark = "%s" if bench.outbox.backend == "postgres" else "?"
    key: object = message if bench.outbox.backend == "postgres" else str(message)
    ((plan,),) = bench.outbox.fetch(f"SELECT plan_id FROM {table} WHERE message_id = {mark}", key)
    return str(plan)


def test_without_a_ledger_nothing_is_credited(bench: Bench) -> None:
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    report = bench.settler(ledger=False).settle()
    assert report.credits == 0 and report.problems == ()
    assert settlements(bench)[cancel].note == "no credit: no ledger to credit"
    assert credits(bench) == []


def test_a_plan_never_charged_earns_no_credit(bench: Bench) -> None:
    """Credits reverse what the ledger charged; an engine that charged
    nothing leaves nothing to reverse."""
    booked = bench.book(1, charged=False)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    report = bench.settler().settle()
    assert report.credits == 0 and report.problems == ()
    assert "the ledger holds no charge for plan" in settlements(bench)[cancel].note


def test_a_compensation_settles_only_with_the_operator_log(bench: Bench) -> None:
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    report = bench.settler(operators=False).settle()
    assert report.settled == (booked,)
    (problem,) = report.problems
    assert f"message {cancel}" in problem and "none is configured" in problem


def test_only_a_delivered_request_is_settled(bench: Bench) -> None:
    pending = bench.book(1)
    with pytest.raises(Exception, match="only a delivered request is settled"):
        wrap(bench.source()).settle(pending, receipt_id=None, credit=None, note="")
    bench.deliver()
    source = wrap(bench.source())
    assert source.settle(pending, receipt_id=None, credit=None, note="first")
    assert not source.settle(pending, receipt_id="x", credit=None, note="second")
    assert source.settlements()[pending].note == "first"


@POSTGRES_ONLY
def test_the_settler_role_records_settlements_and_nothing_else(outbox: Outbox) -> None:
    assert isinstance(outbox, PostgresOutbox)

    def may(privilege: str, target: str) -> bool:
        kind = "function" if "(" in target else "table"
        (row,) = outbox.fetch(
            f"SELECT has_{kind}_privilege(%s, %s, %s)", outbox.settler_role, target, privilege
        )
        return bool(row[0])

    assert may("EXECUTE", "interlock.outbox_settle(uuid, text, text, text)")
    assert may("SELECT", "interlock.outbox_settlements") and may("SELECT", "interlock.outbox")
    for table in ("interlock.outbox_settlements", "interlock.outbox_attempts", "interlock.outbox"):
        assert not any(may(p, table) for p in ("INSERT", "UPDATE", "DELETE"))
    assert not may(
        "EXECUTE", "interlock.outbox_compensate(uuid, text, text, text, uuid, text, text, text)"
    )


def test_verify_settlements_names_a_credit_no_settlement_made(bench: Bench) -> None:
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    bench.settler().settle()
    # A second credit for the same compensation, posted around settlement.
    bench.outbox.governor.refund(SCOPE, "0.25", memo=f"{CREDIT_MEMO}{cancel} again")
    found = verify_settlements(
        bench.source(), log=bench.log, relays=RELAYS, ledger=bench.outbox.governor.audit_trail()
    )
    assert any(f"compensation {cancel} was credited 2 times" in p for p in found)


def test_a_compensation_attested_by_no_registered_relay_earns_nothing(bench: Bench) -> None:
    """Its delivery written around Interlock, signed by a key of the forger's
    own: not settled, not credited."""
    from agentgov.receipts.signing import Ed25519Signer

    from tests.test_attestations import signature_json, statement

    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    rogue = Ed25519Signer.generate()
    ghost(bench.outbox, cancel, signature_json(statement(bench.outbox, cancel, attempt=1), rogue))
    report = bench.settler().settle()
    assert report.settled == (booked,) and report.credits == 0
    (problem,) = report.problems
    assert f"message {cancel}" in problem and "not attested by a registered relay" in problem
    assert credits(bench) == []


def test_a_compensation_with_an_attestation_copied_from_another_delivery_earns_nothing(
    bench: Bench,
) -> None:
    """A registered relay's genuine signature, over another request: the
    signature does not hold for this one, so nothing is settled or credited."""
    booked, other = bench.book(1), bench.book(2)
    bench.deliver()
    cancel = bench.compensate(booked)
    (delivered,) = [e for e in bench.outbox.log(other) if e.event == "delivered"]
    ghost(bench.outbox, cancel, delivered.attestation)
    report = bench.settler().settle()
    assert sorted(report.settled) == sorted([booked, other]) and report.credits == 0
    (problem,) = report.problems
    assert f"message {cancel}" in problem and "not attested by a registered relay" in problem
    assert credits(bench) == []
