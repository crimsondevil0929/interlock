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
- No column the database's owner can rewrite sets a credit: a compensation
  enqueued around the operators is receipted and earns nothing, whatever
  authority its row carries; the amount is the price the engine's sink
  registry and the outbox row agree on, never more than the plan's charge
  left; the plan is the one the compensation's attested key was derived
  from; the scope is the one the ledger charged. A delivery whose attested
  key its row's plan does not derive, or whose log no longer verifies, is
  not settled at all.
- The settlement row is written once, for a delivered request only; the
  settler role on PostgreSQL may record settlements and do nothing else.
- :func:`~interlock.settlement.verify_settlements` holds the settlements, the
  receipt log and the ledger to each other: it names an orphaned receipt or
  credit, a settlement naming another message's receipt, a receipt or a
  credit that does not exist, a credit of another amount, and an attestation
  no registered relay made.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.core import EntryType
from agentgov.receipts import ActionReceipt, verify_bundle

from interlock import BlastRadius
from interlock.deliveries import Settled
from interlock.deliveries import settlements as wrap
from interlock.outbound import SinkRegistry, SinkSpec
from interlock.records import Keyring
from interlock.settlement import CREDIT_MEMO, Settler, verify_settlements
from tests.conftest import Pg
from tests.outbox_env import (
    BACKENDS,
    RELAY_SINKS,
    RELAYS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    build_either,
    relay_signer,
)
from tests.settling import BOOKINGS, LOG_KEY, REGISTRY, SETTLE_COST, Bench
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


@pytest.mark.parametrize("missing", ["signed operator log", "sink registry"])
def test_a_compensation_settles_only_with_the_operator_log_and_the_registry(
    bench: Bench, missing: str
) -> None:
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    if missing == "signed operator log":
        report = bench.settler(operators=False).settle()
    else:
        report = bench.settler(sinks=None).settle()
    assert report.settled == (booked,)
    (problem,) = report.problems
    assert f"message {cancel}" in problem and f"held to the {missing}, and none is" in problem
    # Configured, the settler settles and credits it.
    assert bench.settler().settle().credits == 1


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


# --------------------------------------------------------------------------
# no column the database's owner rewrites sets a credit
# --------------------------------------------------------------------------

AROUND = {
    "made-up": "no signed intent holds the authority its compensated row carries",
    "a-cancel-intent": "its authority is a cancel intent",
    "another-compensations-intent": "the signed intent does not name this compensation",
}


@pytest.mark.parametrize("authority", sorted(AROUND))
def test_a_compensation_enqueued_around_the_operators_earns_nothing(
    bench: Bench, authority: str
) -> None:
    """The database's owner enqueues a compensation through the outbox's own
    function, and a relay honestly delivers it. The delivery is receipted, as
    every attested delivery is; the ledger is not touched. The authority its
    original's ``compensated`` row carries is made up, or a signed intent of
    another kind, or the signed intent of another compensation."""
    booked = bench.book(1)
    bench.deliver()
    genuine = 0
    if authority == "made-up":
        held = "0" * 64
    elif authority == "a-cancel-intent":
        pending = bench.book(2)
        with bench.outbox.signed("ops") as operator:
            held = operator.cancel(pending, reason="not wanted").intent.record_hash
    else:
        other = bench.book(2)
        bench.deliver()
        with bench.outbox.signed("ops") as operator:
            held = operator.compensate([other], registry=REGISTRY).intent.record_hash
        genuine = 1
    forged = bench.compensate_around(booked, held)
    bench.deliver()
    report = bench.settler().settle()
    assert forged in report.settled and report.problems == ()
    assert report.credits == genuine
    row = settlements(bench)[forged]
    assert (
        row.credit is None
        and row.note == f"no credit: its authority does not hold: {AROUND[authority]}"
    )
    (receipt,) = bench.deliveries()[str(forged)]
    assert row.receipt_id == receipt.receipt_id and bench.verified(receipt) == 0
    assert [c for c in credits(bench) if str(forged) in c.memo] == []
    assert len(credits(bench)) == genuine


def test_a_delivery_whose_key_no_plan_derives_is_not_settled(bench: Bench) -> None:
    """A compensation enqueued around the operators under a key of the
    forger's choosing: the relay attests the key it was handed, and the plan
    its row names did not derive it, so no receipt binds it to that plan."""
    booked = bench.book(1)
    bench.deliver()
    forged = bench.compensate_around(booked, "0" * 64, key="ab" * 32)
    bench.deliver()
    report = bench.settler().settle()
    assert report.settled == (booked,) and report.credits == 0
    (problem,) = report.problems
    assert problem.startswith(f"message {forged}: its row names plan {_plan(bench, booked)}")
    assert "its attested idempotency key was not derived from" in problem
    assert str(forged) not in bench.deliveries()


@pytest.mark.parametrize("disagrees", ["row", "registry"])
def test_a_credit_is_the_price_the_registry_and_the_row_agree_on(
    bench: Bench, disagrees: str
) -> None:
    """The database's owner raises the original's recorded cost to its plan's
    whole charge, settle cost and all; or the engine's registry no longer
    prices the sink as the plan was charged. Either way the two disagree, and
    nothing is credited: never more than the sink's ``cost_per_call``, and
    never a price the outbox does not record."""
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    whole = SETTLE_COST + BOOKINGS.cost_per_call
    if disagrees == "row":
        bench.outbox.tamper(booked, cost=whole)
        settler = bench.settler()
        recorded, priced = whole, BOOKINGS.cost_per_call
    else:
        repriced = SinkSpec(
            BOOKINGS.name,
            BOOKINGS.operations,
            cost_per_call=whole,
            backoff_base=BOOKINGS.backoff_base,
            backoff_cap=BOOKINGS.backoff_cap,
        )
        settler = bench.settler(sinks=SinkRegistry((*RELAY_SINKS, repriced)))
        recorded, priced = BOOKINGS.cost_per_call, whole
    report = settler.settle()
    assert (sorted(report.settled), report.credits, report.problems) == (
        sorted([booked, cancel]),
        0,
        (),
    )
    note = settlements(bench)[cancel].note
    assert note.startswith("no credit: the outbox records its original at ")
    assert Decimal(note.split(" at ")[1].split(",")[0]) == recorded
    assert note.endswith(f"the sink registry prices a bookings request at {priced}")
    assert credits(bench) == []


def test_an_original_moved_to_another_plan_earns_its_compensation_nothing(bench: Bench) -> None:
    """Settled, the original's row is moved to another charged plan. Its log
    is not read again; but the compensation's key, attested and named in the
    signed intent, was derived from the plan the original came from."""
    booked, other = bench.book(1), bench.book(2)
    bench.deliver()
    bench.settler().settle()
    cancel = bench.compensate(booked)
    bench.deliver()
    moved = _plan(bench, other)
    bench.outbox.tamper(booked, plan_id=moved)
    report = bench.settler().settle()
    assert (report.settled, report.credits, report.problems) == ((cancel,), 0, ())
    assert settlements(bench)[cancel].note.startswith(
        f"no credit: its original's row names plan {moved}"
    )
    assert credits(bench) == []


@pytest.mark.parametrize(
    ("column", "value", "why"),
    [
        ("operation", "cancel", "does not undo bookings.cancel with bookings.cancel"),
        ("sink", "payments", "does not undo payments.book with bookings.cancel"),
    ],
    ids=["operation", "sink"],
)
def test_an_original_rewritten_as_another_request_earns_its_compensation_nothing(
    bench: Bench, column: str, value: str, why: str
) -> None:
    """Settled, the original's row is rewritten as another operation, or as a
    request to another sink, one priced too: the registry does not undo that
    with the compensation the relay attested."""
    booked = bench.book(1)
    bench.deliver()
    bench.settler().settle()
    cancel = bench.compensate(booked)
    bench.deliver()
    bench.outbox.tamper(booked, **{column: value})
    report = bench.settler().settle()
    assert (report.settled, report.credits, report.problems) == ((cancel,), 0, ())
    assert settlements(bench)[cancel].note == f"no credit: the sink registry {why}"
    assert credits(bench) == []


def test_a_compensation_of_a_request_that_cost_nothing_earns_nothing(bench: Bench) -> None:
    """A registry that prices the sink at nothing: there is nothing to credit
    back, and the ledger is not asked to post a credit of nothing."""
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()
    free = SinkSpec(
        BOOKINGS.name,
        BOOKINGS.operations,
        backoff_base=BOOKINGS.backoff_base,
        backoff_cap=BOOKINGS.backoff_cap,
    )
    report = bench.settler(sinks=SinkRegistry((*RELAY_SINKS, free))).settle()
    assert (report.credits, report.problems) == (0, ())
    assert settlements(bench)[cancel].note == "no credit: its original cost nothing"


def test_a_credit_goes_to_the_scope_the_ledger_charged(bench: Bench) -> None:
    """The original's row names another scope, one the ledger knows: the
    credit goes to the scope its plan was charged to, found by the charge's
    memo alone."""
    bench.outbox.governor.open_root("elsewhere", "1")
    booked = bench.book(1)
    bench.deliver()
    bench.settler().settle()
    cancel = bench.compensate(booked)
    bench.deliver()
    bench.outbox.tamper(booked, scope_id="elsewhere")
    report = bench.settler().settle()
    assert (report.settled, report.credits, report.problems) == ((cancel,), 1, ())
    (credit,) = credits(bench)
    assert credit.scope_id == SCOPE and credit.amount == BOOKINGS.cost_per_call
    # The scope the row names is credited nothing.
    assert [
        e
        for e in bench.outbox.governor.audit_trail("elsewhere")
        if e.entry_type is EntryType.REVERSAL
    ] == []


def test_a_delivery_whose_log_no_longer_verifies_is_not_settled(bench: Bench) -> None:
    """Its row moved to another plan, unlinked: the genesis its log grew from
    no longer holds. Not settled, and reported."""
    first, second = bench.book(1), bench.book(2)
    bench.deliver()
    bench.outbox.tamper(first, plan_id=_plan(bench, second))
    report = bench.settler().settle()
    assert report.settled == (second,) and report.problems
    assert all(p.startswith(f"message {first}:") for p in report.problems)
    assert str(first) not in bench.deliveries()


def test_a_plans_charge_caps_what_its_compensations_earn(bench: Bench) -> None:
    """Credits reverse a plan's charge and never exceed it. A credit posted
    around the settler for one of the plan's two compensations takes the
    whole charge; the other earns nothing, and the verifier names the first."""
    first, second = bench.book_together(1, 2)
    bench.deliver()
    # The second waited for the first: it is undone first.
    two = bench.compensate(second)
    one = bench.compensate(first)
    bench.deliver()
    charge = SETTLE_COST + 2 * BOOKINGS.cost_per_call
    bench.outbox.governor.refund(SCOPE, charge, memo=f"{CREDIT_MEMO}{one} compensates {first}")
    report = bench.settler().settle()
    assert report.credits == 0 and report.problems == ()
    note = settlements(bench)[two].note
    assert note.startswith(f"no credit: plan {_plan(bench, first)}'s charge of ")
    assert note.endswith(f"left, less than the {BOOKINGS.cost_per_call} the original cost")
    found = verify_settlements(
        bench.source(), log=bench.log, relays=RELAYS, ledger=bench.outbox.governor.audit_trail()
    )
    assert found == (f"the credit for compensation {one} is not its original's cost",)


# --------------------------------------------------------------------------
# verify_settlements
# --------------------------------------------------------------------------


def test_verify_settlements_names_an_orphaned_receipt_and_credit(bench: Bench) -> None:
    """A settler that died after the compensation's receipt and credit, before
    its settlement row: both are orphans until the next run records them."""
    booked = bench.book(1)
    bench.deliver()
    cancel = bench.compensate(booked)
    bench.deliver()

    class DiedError(Exception):
        pass

    def die(point: str, message: uuid.UUID) -> None:
        if (point, message) == ("credit", cancel):
            raise DiedError

    with pytest.raises(DiedError):
        bench.settler(checkpoint=die).settle()

    def found() -> tuple[str, ...]:
        return verify_settlements(
            bench.source(),
            log=bench.log,
            relays=RELAYS,
            ledger=bench.outbox.governor.audit_trail(),
        )

    (receipt,) = bench.deliveries()[str(cancel)]
    assert set(found()) == {
        f"delivery receipt {receipt.receipt_id} (message {cancel}) is named by no settlement",
        f"a credit for compensation {cancel} is named by no settlement",
    }
    resumed = bench.settler().settle()
    assert (resumed.settled, resumed.receipts, resumed.credits) == ((cancel,), 0, 0)
    assert found() == ()


def test_verify_settlements_holds_each_settlement_to_the_log_and_the_ledger(
    bench: Bench,
) -> None:
    """Settlement rows written around the settler, as its database role could:
    one naming another message's receipt, one naming a receipt the log never
    issued, one naming a credit the ledger does not hold; and a credit posted
    around it, of another amount. Then every receipt held to relay keys that
    no longer register its relay."""
    first, _ = bench.book(1), bench.book(2)
    bench.deliver()
    bench.settler().settle()
    third, fourth = bench.book(3), bench.book(4)
    cancel = bench.compensate(first)
    bench.deliver()
    (receipt,) = bench.deliveries()[str(first)]
    rows = wrap(bench.source())
    missing = str(uuid.uuid4())
    assert rows.settle(third, receipt_id=receipt.receipt_id, credit=None, note="")
    assert rows.settle(fourth, receipt_id=missing, credit=None, note="")
    assert rows.settle(cancel, receipt_id=None, credit="f" * 64, note="")
    bench.outbox.governor.refund(SCOPE, "0.30", memo=f"{CREDIT_MEMO}{cancel} compensates {first}")
    ledger = bench.outbox.governor.audit_trail()
    found = verify_settlements(bench.source(), log=bench.log, relays=RELAYS, ledger=ledger)
    assert set(found) == {
        f"message {third}: its settlement names delivery receipt {receipt.receipt_id}, "
        f"which receipts message {first}",
        f"message {fourth}: its settlement names delivery receipt {missing}, which the "
        f"receipt log does not hold",
        f"a credit for compensation {cancel} is named by no settlement",
        f"the credit for compensation {cancel} is not its original's cost",
        f"message {cancel}: its settlement names credit {'f' * 16}, which the ledger does not hold",
    }
    unregistered = verify_settlements(bench.source(), log=bench.log, relays=Keyring({}))
    attested = [p for p in unregistered if p.endswith("its attestation: no registered relay's key")]
    # The receipts first, second and third's settlements name.
    assert len(attested) == 3


def test_verify_settlements_holds_each_attestation_to_its_relay(bench: Bench) -> None:
    """A delivery receipt the receipt log signed over another delivery's
    attestation, a registered relay's genuine signature: the log's signature
    is not the relay's, and the verifier checks the relay's itself."""
    first, second = bench.book(1), bench.book(2)
    bench.deliver()

    class DiedError(Exception):
        pass

    def die(point: str, message: uuid.UUID) -> None:
        if (point, message) == ("receipt", second):
            raise DiedError

    with pytest.raises(DiedError):
        bench.settler(checkpoint=die).settle()
    ((genuine,), (issued,)) = bench.deliveries()[str(first)], bench.deliveries()[str(second)]
    index = bench.log.index_of(issued.action.receipt_id)
    assert index is not None
    action = bench.log.receipt(index)
    assert isinstance(action, ActionReceipt)
    forged = bench.issuer.issue_delivery(
        action=action,
        request=issued.request,
        delivery=issued.delivery,
        attestation=genuine.attestation,
    )
    assert wrap(bench.source()).settle(second, receipt_id=forged.receipt_id, credit=None, note="")
    found = verify_settlements(bench.source(), log=bench.log, relays=RELAYS)
    assert len(found) == 2
    assert found[0].startswith(f"delivery receipt {forged.receipt_id}: its attestation: ")
    assert found[1] == (
        f"delivery receipt {issued.receipt_id} (message {second}) is named by no settlement"
    )


# --------------------------------------------------------------------------
# a ledger every part shares (the daemon's, on PostgreSQL)
# --------------------------------------------------------------------------


@contextmanager
def shared_ledger(pg: Pg) -> Iterator[Callable[[], BudgetManager]]:
    """Governors of one AgentGov ledger on PostgreSQL, as the daemon's parts
    each hold one: every call opens another, closed after the test."""
    opened: list[BudgetManager] = []

    def governor() -> BudgetManager:
        opened.append(BudgetManager.open_postgres(pg.admin))
        return opened[-1]

    try:
        yield governor
    finally:
        for each in opened:
            each.close()


def _settler(bench: Bench, ledger: BudgetManager) -> Settler:
    return Settler(
        bench.source(),
        receipts=bench.issuer,
        chain=bench.chain,
        relays=RELAYS,
        ledger=ledger,
        operator_log=bench.outbox.operator_log,
        operators=bench.outbox.keyring(),
        sinks=REGISTRY,
    )


@POSTGRES_ONLY
def test_a_settler_reads_a_shared_ledger_as_it_stands_when_it_settles(bench: Bench, pg: Pg) -> None:
    """The settler's governor was opened before the plan was charged, through
    another: it catches up before it settles, and the compensation is
    credited, not settled for good as the compensation of a plan never
    charged."""
    with shared_ledger(pg) as governor:
        engines = governor()
        engines.open_root(SCOPE, "100")
        settles = governor()  # before any charge
        local, bench.outbox.governor = bench.outbox.governor, engines
        try:
            booked = bench.book(1)
        finally:
            bench.outbox.governor = local
        bench.deliver()
        cancel = bench.compensate(booked)
        bench.deliver()
        report = _settler(bench, settles).settle()
        assert (report.credits, report.problems) == (1, ())
        credit = settlements(bench)[cancel].credit
        assert credit is not None
        engines.refresh()
        (entry,) = [e for e in engines.audit_trail(SCOPE) if e.entry_type is EntryType.REVERSAL]
        assert entry.entry_hash == credit and entry.amount == BOOKINGS.cost_per_call


@POSTGRES_ONLY
def test_a_charge_claimed_and_not_booked_yet_holds_its_compensation(
    bench: Bench, pg: Pg, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claim and settle: an engine killed between its commit and booking the
    claim leaves the plan's charge a claim, until recovery redeems it. The
    compensation of that plan waits for it; it is never settled for good as
    uncharged."""
    from agentgov.postgres import PostgresStore

    from interlock import EscrowEngine, LedgerAnchor
    from tests.settling import booking

    with shared_ledger(pg) as governor:
        engines = governor()
        engines.open_root(SCOPE, "100")
        store = engines.store
        assert isinstance(store, PostgresStore)
        store.grant_join(pg.role)
        engine = bench.outbox.engine(
            checkers=[BlastRadius(100)],
            sinks=REGISTRY,
            receipts=bench.issuer,
            chain=bench.chain,
            anchor=LedgerAnchor(governed=engines, same_transaction=True),
            settle_cost=str(SETTLE_COST),
        )
        # Killed after the commit, before the claim is booked.
        monkeypatch.setattr(EscrowEngine, "_redeem", lambda self, plan, claim: None)
        plan = booking(1).build()
        assert engine.execute(plan).committed
        monkeypatch.undo()
        (booked,) = bench.outbox.messages(plan.plan_id)
        bench.deliver()
        cancel = bench.compensate(booked)
        bench.deliver()
        settler = _settler(bench, governor())
        report = settler.settle()
        assert cancel not in report.settled and report.credits == 0
        assert any("is claimed and not booked yet" in p for p in report.problems), report
        assert cancel not in settlements(bench)
        # Recovery books the claim; the compensation earns its credit.
        assert len(engines.redeem()) > 0
        report = settler.settle()
        assert (report.settled, report.credits, report.problems) == ((cancel,), 1, ())
        assert settlements(bench)[cancel].credit is not None
