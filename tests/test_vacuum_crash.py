"""The vacuum killed at each point of its two phases (``docs/EPIC5_DESIGN.md`` §1.4, §5).

A back office with three settled messages and one live one; then a vacuum in a
process of its own (``tests/vacuum_child.py``) SIGKILLs itself after signing
its intent, after checking its anchor, inside the database's transaction with
everything done but the commit, after the commit, and after recording its
outcome. After each, on both stores:

- the database is wholly compacted, or wholly untouched: the checkpoint, its
  tombstones and the deletions are one transaction;
- the next operator command resolves the intent exactly: ``abandoned`` when
  the transaction never committed, ``applied`` (naming the checkpoint) when it
  did;
- every verifier passes: the delivery logs, the relays' attestations, the
  operator log and its AgentGov anchors, the settlements against the receipt
  log and the ledger;
- a second vacuum prunes whatever is left, once: no message is tombstoned
  twice, and the chain of checkpoints has no gap.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from agentgov import BudgetManager
from agentgov.receipts import ReceiptLog

from interlock.operators import generate_key, verify_operators
from interlock.records import read_records
from interlock.settlement import verify_settlements
from tests.children import Child
from tests.outbox_env import BACKENDS, RELAYS, Outbox, build_either
from tests.settling import LOG_ID, LOG_KEY, Bench

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


POINTS = [
    ("intent", False, ["operator.abandoned"]),
    ("anchored", False, ["operator.abandoned"]),
    ("transaction", False, ["operator.abandoned"]),
    ("acted", True, ["operator.applied"]),
    ("recorded", True, []),
]


@pytest.mark.parametrize(("kill_at", "pruned", "resolution"), POINTS, ids=[p[0] for p in POINTS])
def test_a_vacuum_killed_at_each_point_leaves_all_or_nothing(
    outbox: Outbox, tmp_path: Path, kill_at: str, pruned: bool, resolution: list[str]
) -> None:
    bench = Bench(outbox, tmp_path)
    try:
        booked, other = bench.book(1), bench.book(2)
        bench.deliver()
        cancel = bench.compensate(booked)
        bench.deliver()
        assert bench.settler().settle().credits == 1
        pending = bench.book(3)
    finally:
        bench.close()
    settled = {booked, other, cancel}
    outbox.governor.open_root("operators", "1")
    # The ledger is the vacuum's process's now: one governor at a time.
    outbox.governor.close()
    key = tmp_path / "vac.key"
    outbox.keys["vac"] = generate_key(key)
    outbox.operator_key("bob")
    child = Child(
        {
            **outbox.operator_target(),
            "log": str(outbox.operator_log),
            "key": str(key),
            "keys": {name: k.public_key().spec() for name, k in outbox.keys.items()},
            "ledger": outbox.ledger_path,
            "kill_at": kill_at,
        },
        tmp_path,
        0,
        module="tests.vacuum_child",
    )
    child.wait_for("started")
    assert child.wait_for("killed").at == kill_at
    assert child.process.wait(timeout=30) < 0, child.stderr()
    outbox.settle()
    outbox.governor = BudgetManager.open_sqlite(outbox.ledger_path)

    # All, or nothing.
    compactor = outbox.compactor()
    assert (len(compactor.checkpoints()), set(compactor.compacted())) == (
        (1, settled) if pruned else (0, set())
    )
    assert outbox.requests() == (1 if pruned else 4)
    assert outbox.state(pending) == "pending"

    # The next operator resolves the dead vacuum's intent exactly.
    with outbox.signed("bob", ledger=outbox.governor) as bob:
        assert [r.kind for r in bob.resolve()] == resolution
    records = read_records(outbox.operator_log)
    (intent,) = [r for r in records if r.body.get("action") == "compact"]
    outcomes = [r for r in records if r.body.get("intent", {}).get("hash") == intent.record_hash]
    assert [r.kind for r in outcomes] == (
        ["operator.applied"] if pruned else ["operator.abandoned"]
    )
    if kill_at == "acted":
        assert outcomes[0].body["checkpoint"]["seq"] == 1

    def verified() -> None:
        outbox.verify()
        entries = list(outbox.governor.audit_trail())
        report = verify_operators(
            outbox.operator(), read_records(outbox.operator_log), outbox.keyring(), ledger=entries
        )
        assert report.problems == ()
        log = ReceiptLog(LOG_ID, LOG_KEY, path=str(tmp_path / "receipts.jsonl"))
        source = outbox.settler()
        try:
            assert verify_settlements(source, log=log, relays=RELAYS, ledger=entries) == ()
        finally:
            source.close()
            log.close()

    verified()

    # A second vacuum prunes what is left, once.
    with outbox.vacuum("bob") as vacuum:
        second = vacuum.run()
    assert second.outcome == ("nothing" if pruned else "applied")
    rows = compactor.checkpoints()
    assert [r.seq for r in rows] == [1]
    assert set(compactor.compacted()) == settled
    assert all(isinstance(m, uuid.UUID) for m in compactor.compacted())
    verified()
