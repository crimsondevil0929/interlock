"""The settlement crash matrix (``docs/EPIC4_DESIGN.md`` §4, §5), on both stores.

Each case prepares one back office: two bookings committed by an engine that
issues ARC1 receipts and charges every plan to the AgentGov ledger, both
delivered; one of them compensated by a signed operator, and the compensation
delivered. Then a settler runs in a process of its own and SIGKILLs itself the
moment one step of one message's settlement is durable: the delivery receipt
issued, the credit posted, the settlement recorded. Another settler, from
scratch, settles what is left; and the test checks:

- every delivered request is settled, once;
- the receipt log holds exactly one delivery receipt for each: none issued
  twice, none orphaned (each is named by its settlement), each passing
  agentgov's verifier, bound to the action receipt of the plan that committed
  the request;
- the ledger holds exactly one credit, the original request's
  ``cost_per_call``, for the compensation, never two, and verifies;
- :func:`~interlock.settlement.verify_settlements` finds nothing.

A case killed twice, at the receipt and then at the credit, resumes twice.
"""

from __future__ import annotations

import signal
import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.core import EntryType
from agentgov.receipts import ReceiptLog, verify_bundle

from interlock.deliveries import settlements
from interlock.settlement import CREDIT_MEMO, verify_settlements
from tests.children import Child
from tests.outbox_env import BACKENDS, RELAYS, SCOPE, Outbox, build_either, relay_signer
from tests.settling import BOOKINGS, LOG_ID, LOG_KEY, Bench

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@dataclass
class Prepared:
    """A back office with three delivered requests, none settled, and the
    files the engine's process held, released for the settlers'."""

    outbox: Outbox
    workdir: Path
    scenario: dict[str, Any]
    booked: uuid.UUID
    """Compensated."""
    other: uuid.UUID
    cancel: uuid.UUID
    """The compensation of ``booked``."""
    children: int = 0

    def victim(self, which: str) -> uuid.UUID:
        return {"booking": self.booked, "other": self.other, "cancel": self.cancel}[which]

    def settle(self, *, kill_at: str = "", message: uuid.UUID | None = None) -> dict[str, Any]:
        """Run a settler in a process of its own: killed at ``kill_at`` on
        ``message``, or to the end. What it said last."""
        child = Child(
            {**self.scenario, "kill_at": kill_at, "message": str(message or "")},
            self.workdir,
            self.children,
            module="tests.settle_child",
        )
        self.children += 1
        last = child.wait_for("started")
        end = "killed" if kill_at else "finished"
        last = child.wait_for(end, timeout=120)
        code = child.process.wait(timeout=60)
        if kill_at:
            assert code == -signal.SIGKILL, child.stderr()
            assert (last.raw["at"], last.raw["message"]) == (kill_at, str(message))
        else:
            assert code == 0, child.stderr()
        return last.raw


@pytest.fixture
def prepared(outbox: Outbox, tmp_path: Path) -> Prepared:
    bench = Bench(outbox, tmp_path)
    try:
        booked, other = bench.book(1), bench.book(2)
        bench.deliver()
        cancel = bench.compensate(booked)
        bench.deliver()
        scenario = bench.scenario()
    finally:
        bench.close()
    # The ledger is the settler process's now: one governor at a time.
    outbox.governor.close()
    return Prepared(outbox, tmp_path, scenario, booked, other, cancel)


def check_settled_once(prepared: Prepared) -> None:
    """Everything delivered settled once: one receipt each, one credit."""
    outbox = prepared.outbox
    log = ReceiptLog(LOG_ID, LOG_KEY, path=str(prepared.scenario["receipts"]))
    governor = BudgetManager.open_sqlite(outbox.ledger_path)
    source = outbox.settler()
    try:
        rows = settlements(source).settlements()
        assert set(rows) == {prepared.booked, prepared.other, prepared.cancel}
        receipts: dict[str, list[Any]] = {}
        for receipt in log.deliveries():
            receipts.setdefault(receipt.request.message_id, []).append(receipt)
        assert {m: len(r) for m, r in receipts.items()} == {
            str(m): 1 for m in (prepared.booked, prepared.other, prepared.cancel)
        }, "a delivery receipt issued twice, or never"
        for message, (receipt,) in receipts.items():
            assert rows[uuid.UUID(message)].receipt_id == receipt.receipt_id, "an orphan"
            index = log.index_of(receipt.receipt_id)
            action = log.index_of(receipt.action.receipt_id)
            assert index is not None and action is not None
            report = verify_bundle(
                log.bundle(index),
                issuer_key=LOG_KEY,
                relay_keys=[relay_signer().public_key()],
                action=log.bundle(action),
            )
            assert report.passed, report.to_json()
        credits = [
            e
            for e in governor.audit_trail(SCOPE)
            if e.entry_type is EntryType.REVERSAL and e.memo.startswith(CREDIT_MEMO)
        ]
        assert [(c.memo.split()[0], c.amount) for c in credits] == [
            (f"{CREDIT_MEMO}{prepared.cancel}", Decimal("0.25"))
        ], "a credit posted twice, or never, or of another amount"
        assert credits[0].amount == BOOKINGS.cost_per_call
        assert rows[prepared.cancel].credit == credits[0].entry_hash
        governor.verify_integrity()
        assert (
            verify_settlements(source, log=log, relays=RELAYS, ledger=governor.audit_trail()) == ()
        )
    finally:
        source.close()
        log.close()
        governor.close()


POINTS = [
    ("receipt", "booking"),
    ("settled", "booking"),
    ("receipt", "cancel"),
    ("credit", "cancel"),
    ("settled", "cancel"),
    ("receipt", "other"),
]


@pytest.mark.parametrize(("point", "which"), POINTS, ids=[f"{p}-{w}" for p, w in POINTS])
def test_a_kill_at_each_step_of_settlement_settles_once(
    prepared: Prepared, point: str, which: str
) -> None:
    prepared.settle(kill_at=point, message=prepared.victim(which))
    finished = prepared.settle()
    assert finished["problems"] == []
    check_settled_once(prepared)
    # And a third settler finds nothing left to do.
    again = prepared.settle()
    assert (again["settled"], again["receipts"], again["credits"]) == ([], 0, 0)


def test_a_settlement_killed_twice_resumes_twice(prepared: Prepared) -> None:
    prepared.settle(kill_at="receipt", message=prepared.cancel)
    prepared.settle(kill_at="credit", message=prepared.cancel)
    finished = prepared.settle()
    # The receipt and the credit were made by the settlers that died: this one
    # only records them.
    assert (finished["receipts"], finished["credits"]) == (0, 0)
    assert str(prepared.cancel) in finished["settled"]
    check_settled_once(prepared)


def test_a_settlement_undisturbed_settles_once(prepared: Prepared) -> None:
    finished = prepared.settle()
    assert (len(finished["settled"]), finished["receipts"], finished["credits"]) == (3, 3, 1)
    check_settled_once(prepared)
