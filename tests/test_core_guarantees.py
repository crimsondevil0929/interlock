"""The v0.1.2 guarantees, each tested against the failure that broke it.

- **R4.** A read-only anchor was a snapshot of the governor taken at attach
  time. The governor halted the scope afterwards, and the "re-read the breaker
  immediately before commit" step read the snapshot and committed anyway. Now
  the anchor refreshes, verified, before every head read and every breaker
  check, and a governed anchor holds the governor's lock from the check
  through the commit.
- **R5.** ``EscrowRuntime`` appended to an existing chain file without reading
  it, so a second process lifetime restarted the chain at sequence 1: the
  chain forked at its first record, ``load()`` raised, and
  ``unresolved_intents()`` came back empty. Now a chain resumes its file,
  verified; one file has one writer; and a crash between a commit intent and
  its record is resolved exactly, from a marker written inside the stage's
  own transaction.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest
from agentgov import BudgetManager, money
from agentgov.core import EntryType
from agentgov.exceptions import AgentGovError

from interlock import (
    BlastRadius,
    ChainIntegrityError,
    ChainInUseError,
    EffectKind,
    EscrowChain,
    EscrowEngine,
    EscrowRuntime,
    InvariantChecker,
    LedgerAnchor,
    LedgerUnverifiedError,
    PlanBuilder,
    PlanId,
    SqliteSubstrate,
    StageState,
    TableSpec,
)
from interlock.chain import EscrowRecord, RecordType
from interlock.exceptions import AnchorError, ForbiddenStatementError, InterlockError
from interlock.types import (
    CommitReceipt,
    EffectDiff,
    EffectPlan,
    InvariantViolation,
    StageHandle,
)

TABLES = [TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")]


@pytest.fixture
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "prod.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, tenant TEXT, total REAL)")
    conn.executemany(
        "INSERT INTO orders VALUES (?,?,?)",
        [(1, "acme", 100.0), (2, "acme", 200.0), (3, "globex", 300.0)],
    )
    conn.commit()
    conn.close()
    return path


def totals(path: str) -> list[tuple[int, float]]:
    conn = sqlite3.connect(path)
    try:
        return [(int(r[0]), float(r[1])) for r in conn.execute("SELECT id, total FROM orders")]
    finally:
        conn.close()


def plan(total: float = 777.0, *, scope: str = "agent") -> EffectPlan:
    return (
        PlanBuilder(scope)
        .add(
            EffectKind.UPDATE,
            table="orders",
            statement="UPDATE orders SET total = :total WHERE id = 1",
            parameters={"total": total},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )


def engine(
    db: str,
    *,
    anchor: LedgerAnchor | None = None,
    chain: EscrowChain | None = None,
    substrate: SqliteSubstrate | None = None,
    checkers: Sequence[InvariantChecker] | None = None,
) -> EscrowEngine:
    return EscrowEngine(
        substrate if substrate is not None else SqliteSubstrate(db, tables=TABLES),
        checkers=checkers if checkers is not None else [BlastRadius(8)],
        anchor=anchor,
        chain=chain,
    )


@pytest.fixture
def governor(tmp_path: Path) -> Iterator[tuple[str, BudgetManager]]:
    """A governor another process runs: Interlock attaches to its file read-only."""
    path = str(tmp_path / "gov.db")
    writer = BudgetManager.open_sqlite(path)
    writer.open_root("root", money("5.00"))
    writer.delegate("root", "agent", money("1.00"))
    yield path, writer
    writer.close()


class _Checker:
    """An invariant that does something while the stage is open, then passes."""

    def __init__(self, during_stage: Callable[[], object]) -> None:
        self._during = during_stage

    @property
    def name(self) -> str:
        return "side_effect"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        self._during()
        return ()


# --------------------------------------------------------------------------
# R4: the pre-commit breaker check reads the governor as it is now
# --------------------------------------------------------------------------


def test_a_halt_written_after_interlock_attached_stops_the_commit(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    """R4, reproduced: v0.1.1 committed this plan."""
    path, writer = governor
    anchor = LedgerAnchor(path)
    escrow = engine(db, anchor=anchor)
    writer.trip("agent", "operator halt, after Interlock attached")

    result = escrow.execute(plan())

    assert not result.committed
    assert result.state is StageState.ABORTED
    assert (1, 777.0) not in totals(db)
    aborted = escrow.chain.records()[-1]
    assert aborted.record_type is RecordType.ABORTED
    assert "operator halt, after Interlock attached" in aborted.note
    anchor.close()


def test_a_halt_on_an_ancestor_written_after_attach_stops_the_commit(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    path, writer = governor
    anchor = LedgerAnchor(path)
    writer.trip("root", "the whole tree is halted")

    result = engine(db, anchor=anchor).execute(plan())

    assert not result.committed
    assert (1, 777.0) not in totals(db)
    anchor.close()


def test_a_halt_that_lands_while_the_plan_is_staged_stops_the_commit(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    """The staging window is exactly where a trip has to be observed."""
    path, writer = governor
    anchor = LedgerAnchor(path)
    halt = _Checker(lambda: writer.trip("agent", "halted mid-stage"))

    result = engine(db, anchor=anchor, checkers=[halt]).execute(plan())

    assert result.verdict is not None and result.verdict.admitted, "the checkers passed"
    assert not result.committed, "the breaker still stopped it"
    assert (1, 777.0) not in totals(db)
    anchor.close()


def test_records_anchor_to_the_governors_current_head(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    path, writer = governor
    anchor = LedgerAnchor(path)
    escrow = engine(db, anchor=anchor)
    escrow.execute(plan(1.0))
    first = escrow.chain.records()[-1]
    assert first.agentgov_sequence == len(writer.ledger)

    writer.fund("root", money("1.00"))
    writer.spend("root", money("0.25"))
    escrow.execute(plan(2.0))
    second = escrow.chain.records()[-1]

    assert second.agentgov_sequence == len(writer.ledger) > first.agentgov_sequence
    assert second.agentgov_head_hash == writer.ledger.head_hash
    escrow.chain.verify_anchors()
    anchor.close()


def test_a_ledger_rewritten_under_the_anchor_fails_the_stage_closed(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    path, _ = governor
    anchor = LedgerAnchor(path)

    def rewrite() -> None:
        """Any consistent rewrite changes the entry the anchor last verified."""
        conn = sqlite3.connect(path)
        with conn:
            conn.execute(
                "UPDATE entries SET entry_hash = ? "
                "WHERE sequence = (SELECT MAX(sequence) FROM entries)",
                ("0" * 64,),
            )
        conn.close()

    escrow = engine(db, anchor=anchor, checkers=[_Checker(rewrite)])
    with pytest.raises(LedgerUnverifiedError, match="rewritten under this reader"):
        escrow.execute(plan())

    assert (1, 777.0) not in totals(db), "rolled back"
    aborted = escrow.chain.records()[-1]
    assert aborted.record_type is RecordType.ABORTED
    assert not aborted.anchored, "recorded, honestly unanchored"
    escrow.chain.verify()
    with pytest.raises(LedgerUnverifiedError):
        anchor.observe()
    anchor.close()


def test_a_governed_commit_holds_the_governor_until_it_lands(db: str) -> None:
    """In-process, a trip lands strictly before the check or after the commit."""
    gov = BudgetManager()
    gov.open_root("agent", money("1.00"))
    tripper = threading.Thread(target=gov.trip, args=("agent", "tripped during commit"))
    blocked: list[bool] = []

    class TripsDuringCommit(SqliteSubstrate):
        def commit(self, handle: StageHandle) -> CommitReceipt:
            tripper.start()
            tripper.join(timeout=0.2)
            blocked.append(tripper.is_alive())
            return super().commit(handle)

    escrow = engine(
        db,
        anchor=LedgerAnchor(governed=gov),
        substrate=TripsDuringCommit(db, tables=TABLES),
    )
    result = escrow.execute(plan())
    tripper.join(timeout=5)

    assert blocked == [True], "the trip waited for the guarded commit"
    assert result.committed and (1, 777.0) in totals(db)
    assert gov.is_halted("agent"), "and landed after it"
    assert not escrow.execute(plan(5.0)).committed


def test_a_halt_racing_an_audit_commit_is_recorded_on_the_commit(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    """No lock spans another process's database and the substrate, so a trip
    landing between the check and the commit cannot be excluded. It is not
    silent: the commit record says the scope was halted when re-read."""
    path, writer = governor
    anchor = LedgerAnchor(path)

    class TripsAtCommit(SqliteSubstrate):
        def commit(self, handle: StageHandle) -> CommitReceipt:
            writer.trip("agent", "raced the commit")
            return super().commit(handle)

    escrow = engine(db, anchor=anchor, substrate=TripsAtCommit(db, tables=TABLES))
    result = escrow.execute(plan())

    assert result.committed
    committed = escrow.chain.records()[-1]
    assert committed.record_type is RecordType.COMMITTED
    assert "a halt on 'agent'" in committed.note and "raced the commit" in committed.note
    anchor.close()


def test_a_halt_in_either_attached_view_stops_the_commit(
    db: str, governor: tuple[str, BudgetManager]
) -> None:
    path, writer = governor
    live = BudgetManager()
    live.open_root("agent", money("1.00"))
    anchor = LedgerAnchor(path, governed=live)
    writer.trip("agent", "halted in the audited governor")

    assert not engine(db, anchor=anchor).execute(plan()).committed
    anchor.close()


# --------------------------------------------------------------------------
# R5: one chain, resumed, with one writer
# --------------------------------------------------------------------------


def runtime(db: str, chain_path: Path, **kwargs: object) -> EscrowRuntime:
    return EscrowRuntime(
        db,
        tables=TABLES,
        scope_id="agent",
        checkers=[BlastRadius(8)],
        chain_path=chain_path,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_second_process_lifetime_continues_the_chain(db: str, tmp_path: Path) -> None:
    """R5, reproduced: v0.1.1 restarted the chain at sequence 1 here."""
    chain_path = tmp_path / "escrow.jsonl"
    with runtime(db, chain_path) as first:
        first.execute(plan(1.0))
        head, count = first.chain.head_hash, len(first.chain)

    with runtime(db, chain_path) as second:
        assert len(second.chain) == count and second.chain.head_hash == head
        second.execute(plan(2.0))
        resumed = second.chain.records()[count]
        assert resumed.sequence == count + 1 and resumed.prev_hash == head

    reloaded = EscrowChain.load(chain_path)
    assert len(reloaded) == 2 * count
    reloaded.verify()
    assert reloaded.unresolved_intents() == ()


def test_one_chain_file_has_one_writer(db: str, tmp_path: Path) -> None:
    path = tmp_path / "escrow.jsonl"
    writer = EscrowChain(path)
    writer.append(RecordType.VERDICT, plan_id=PlanId("p1"), payload_hash="a" * 64)

    with pytest.raises(ChainInUseError, match=f"pid {os.getpid()}"):
        EscrowChain(path)
    with pytest.raises(ChainInUseError):
        runtime(db, path)

    reader = EscrowChain.load(path)  # a reader claims nothing
    assert reader.read_only and len(reader) == 1
    with pytest.raises(AnchorError, match="cannot append"):
        reader.append(RecordType.VERDICT, plan_id=PlanId("p2"), payload_hash="b" * 64)
    with pytest.raises(ValueError, match="read-only snapshot"):
        engine(db, chain=reader)

    writer.close()
    with pytest.raises(AnchorError, match="closed"):
        writer.append(RecordType.VERDICT, plan_id=PlanId("p3"), payload_hash="c" * 64)
    with EscrowChain(path) as successor:
        assert len(successor) == 1


def test_a_torn_final_record_is_cut_off_by_the_next_writer(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "escrow.jsonl"
    with EscrowChain(path) as chain:
        for n in range(2):
            chain.append(RecordType.VERDICT, plan_id=PlanId(f"p{n}"), payload_hash="a" * 64)
    good = path.read_bytes()
    path.write_bytes(good + b'{"v":"ILOK1","sequence":3,"record_id":"7c1')  # died mid-append

    snapshot = EscrowChain.load(path)
    assert len(snapshot) == 2, "a reader skips the record in flight"
    assert path.read_bytes() != good, "and touches nothing"

    with caplog.at_level(logging.WARNING, logger="interlock.chain"):
        chain = EscrowChain(path)
    assert "torn record" in caplog.text
    assert path.read_bytes() == good
    chain.append(RecordType.VERDICT, plan_id=PlanId("p2"), payload_hash="b" * 64)
    chain.close()
    assert len(EscrowChain.load(path)) == 3


@pytest.mark.parametrize(
    ("corrupt", "message"),
    [
        (lambda lines: [lines[0], b"not a record\n", lines[1]], "line 2 is not an escrow record"),
        (lambda lines: [lines[1], lines[0]], "sequence"),
        (lambda lines: [lines[0], lines[1].replace(b'"p1"', b'"px"')], "contents were edited"),
    ],
    ids=["garbage", "reordered", "edited"],
)
def test_a_damaged_chain_is_refused_and_its_claim_released(
    tmp_path: Path, corrupt: Callable[[list[bytes]], list[bytes]], message: str
) -> None:
    path = tmp_path / "escrow.jsonl"
    with EscrowChain(path) as chain:
        for n in range(2):
            chain.append(RecordType.VERDICT, plan_id=PlanId(f"p{n}"), payload_hash="a" * 64)
    good = path.read_bytes()
    path.write_bytes(b"".join(corrupt(good.splitlines(keepends=True))))

    with pytest.raises(ChainIntegrityError, match=message):
        EscrowChain(path)
    path.write_bytes(good)
    EscrowChain(path).close()  # the refused open did not keep the claim


def _append_all(chain: EscrowChain) -> dict[RecordType, bool]:
    synced: dict[RecordType, bool] = {}
    for kind in RecordType:
        before = len(_FSYNCS)
        chain.append(kind, plan_id=PlanId("p"), payload_hash="a" * 64, stage_id=uuid.uuid4())
        synced[kind] = len(_FSYNCS) > before
    return synced


_FSYNCS: list[int] = []


def _record_fsync(fd: int) -> None:
    _FSYNCS.append(fd)


def test_intents_and_outcomes_reach_stable_storage_before_append_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "fsync", _record_fsync)
    with EscrowChain(tmp_path / "synced.jsonl") as chain:
        synced = _append_all(chain)
    assert {kind for kind, forced in synced.items() if forced} == {
        RecordType.COMMIT_INTENT,
        RecordType.COMMITTED,
        RecordType.ABORTED,
        RecordType.ORPHANED,
        RecordType.COMPENSATED,
    }

    with EscrowChain(tmp_path / "unsynced.jsonl", fsync=False) as chain:
        assert not any(_append_all(chain).values())


def test_a_failed_write_leaves_neither_a_torn_line_nor_a_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "escrow.jsonl"
    chain = EscrowChain(path)
    chain.append(RecordType.VERDICT, plan_id=PlanId("p1"), payload_hash="a" * 64)
    good, head = path.read_bytes(), chain.head_hash

    def disk_full(fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", disk_full)
    with pytest.raises(OSError, match="No space"):
        chain.append(RecordType.COMMIT_INTENT, plan_id=PlanId("p1"), payload_hash="b" * 64)
    assert path.read_bytes() == good
    assert len(chain) == 1 and chain.head_hash == head

    monkeypatch.undo()
    chain.append(RecordType.COMMIT_INTENT, plan_id=PlanId("p1"), payload_hash="b" * 64)
    chain.close()
    EscrowChain.load(path).verify()


# --------------------------------------------------------------------------
# R5: a crashed commit is resolved exactly
# --------------------------------------------------------------------------


_CRASHING_COMMIT = r"""
import os, sys
from interlock import (
    BlastRadius, EffectKind, EscrowChain, EscrowEngine, PlanBuilder, SqliteSubstrate, TableSpec,
)

db, chain_path, when = sys.argv[1], sys.argv[2], sys.argv[3]

# Dies at the substrate's COMMIT, before or after it executes: no rollback,
# no cleanup, no chance to write another record.
class Dying:
    def __init__(self, inner):
        self._inner = inner
    def execute(self, sql, *args):
        if sql == "COMMIT" and when == "before":
            os._exit(3)
        cursor = self._inner.execute(sql, *args)
        if sql == "COMMIT" and when == "after":
            os._exit(3)
        return cursor
    def __getattr__(self, name):
        return getattr(self._inner, name)

class Substrate(SqliteSubstrate):
    def commit(self, handle):
        self._conn = Dying(self._conn)
        return super().commit(handle)

tables = [TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")]
engine = EscrowEngine(
    Substrate(db, tables=tables), checkers=[BlastRadius(8)], chain=EscrowChain(chain_path)
)
engine.execute(
    PlanBuilder("agent")
    .add(
        EffectKind.UPDATE,
        table="orders",
        statement="UPDATE orders SET total = 777 WHERE id = 1",
        tenant_id="acme",
        stated_rows=1,
    )
    .build()
)
os._exit(0)
"""


@pytest.mark.parametrize(
    ("when", "outcome", "durable"),
    [("before", RecordType.ABORTED, False), ("after", RecordType.COMMITTED, True)],
)
def test_a_process_killed_at_commit_is_resolved_exactly_on_restart(
    db: str, tmp_path: Path, when: str, outcome: RecordType, durable: bool
) -> None:
    """Killed with the marker written but not committed, the stage rolled back;
    killed just after COMMIT, it landed. The restarted runtime reads which."""
    chain_path = tmp_path / "escrow.jsonl"
    child = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CRASHING_COMMIT, db, str(chain_path), when],
        capture_output=True,
        text=True,
        check=False,
    )
    assert child.returncode == 3, child.stderr
    (intent,) = EscrowChain.load(chain_path).unresolved_intents()
    assert intent.note.endswith("; commit marker armed")

    with runtime(db, chain_path) as restarted:
        (resolution,) = restarted.recovered
        assert resolution.record_type is outcome
        assert resolution.stage_id == intent.stage_id
        assert resolution.note.startswith("recovered:")
        assert restarted.chain.unresolved_intents() == ()
        restarted.chain.verify()
        assert ((1, 777.0) in totals(db)) is durable

    with runtime(db, chain_path) as again:
        assert again.recovered == (), "resolved once, not on every start"


def test_bookkeeping_that_fails_after_a_durable_commit_never_records_a_rollback(
    db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    escrow = engine(db, chain=EscrowChain(tmp_path / "escrow.jsonl"))
    real_write = EscrowChain._write

    def lose_the_committed_record(self: EscrowChain, path: Path, record: EscrowRecord) -> None:
        if record.record_type is RecordType.COMMITTED:
            raise OSError(5, "I/O error")
        real_write(self, path, record)

    monkeypatch.setattr(EscrowChain, "_write", lose_the_committed_record)
    with pytest.raises(OSError, match="I/O error"):
        escrow.execute(plan())

    kinds = [record.record_type for record in escrow.chain.records()]
    assert kinds[-1] is RecordType.COMMIT_INTENT
    assert RecordType.ABORTED not in kinds, "the effects are durable; never say otherwise"
    assert (1, 777.0) in totals(db)

    monkeypatch.undo()
    (resolution,) = escrow.recover()
    assert resolution.record_type is RecordType.COMMITTED
    assert escrow.chain.unresolved_intents() == ()


def test_recovery_leaves_an_intent_that_is_still_in_flight_alone(db: str) -> None:
    seen: list[tuple[EscrowRecord, ...]] = []
    holder: list[EscrowEngine] = []

    class RecoversMidCommit(SqliteSubstrate):
        def commit(self, handle: StageHandle) -> CommitReceipt:
            seen.append(holder[0].recover())
            return super().commit(handle)

    escrow = engine(db, substrate=RecoversMidCommit(db, tables=TABLES))
    holder.append(escrow)
    assert escrow.execute(plan()).committed
    assert seen == [()]
    kinds = [record.record_type for record in escrow.chain.records()]
    assert kinds.count(RecordType.COMMITTED) == 1


def test_an_intent_without_an_armed_marker_is_left_for_an_operator(
    db: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A v0.1.1 intent, or one from a substrate without markers: the marker's
    absence proves nothing, so recovery does not guess."""
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        chain.append(
            RecordType.COMMIT_INTENT,
            plan_id=PlanId("legacy"),
            payload_hash="a" * 64,
            stage_id=uuid.uuid4(),
            note="about to commit 1 rows",
        )

    with caplog.at_level(logging.WARNING, logger="interlock.engine"):
        restarted = runtime(db, chain_path)
    assert restarted.recovered == ()
    assert len(restarted.chain.unresolved_intents()) == 1
    assert "resolve it by hand" in caplog.text
    restarted.close()

    unmarked = SqliteSubstrate(db, tables=TABLES, commit_markers=False)
    escrow = engine(db, substrate=unmarked)
    escrow.execute(plan())
    intent = next(r for r in escrow.chain.records() if r.record_type is RecordType.COMMIT_INTENT)
    assert not intent.note.endswith("commit marker armed")


def test_a_statement_cannot_forge_a_commit_marker(db: str) -> None:
    forged = (
        PlanBuilder("agent")
        .add(
            EffectKind.INSERT,
            table="orders",
            statement="INSERT INTO _interlock_commits VALUES ('stage', 'plan', 'now')",
        )
        .build()
    )
    with pytest.raises(ForbiddenStatementError, match="_interlock_commits"):
        engine(db).execute(forged)
    assert SqliteSubstrate(db, tables=TABLES).resolve_intent(uuid.uuid4()) is False


def test_a_database_that_never_armed_a_marker_cannot_answer(db: str) -> None:
    assert SqliteSubstrate(db, tables=TABLES).resolve_intent(uuid.uuid4()) is None


def test_every_error_on_the_recovery_path_is_an_interlock_error(tmp_path: Path) -> None:
    missing = SqliteSubstrate(str(tmp_path / "absent.db"), tables=TABLES)
    with pytest.raises(InterlockError):
        missing.resolve_intent(uuid.uuid4())


# --------------------------------------------------------------------------
# 0.3 on this side: the reverse anchor is free
# --------------------------------------------------------------------------


def test_a_runtime_anchors_every_plan_into_the_governor_for_free(db: str, tmp_path: Path) -> None:
    gov = BudgetManager.open_sqlite(str(tmp_path / "gov.db"))
    gov.open_root("agent", money("1.00"))
    with runtime(db, tmp_path / "escrow.jsonl", governed=gov) as escrow:
        first, second = escrow.execute(plan(1.0)), escrow.execute(plan(2.0))
        assert first.committed and second.committed

        anchors = escrow.anchor.find_reverse_anchors() if escrow.anchor else ()
        assert [entry.entry_type for entry in anchors] == [EntryType.ANCHOR] * 2
        assert anchors[0].memo == f"interlock:{first.chain_head[:16]}"
        assert [first.anchored_to, second.anchored_to] == [e.entry_hash for e in anchors]
    assert gov.available("agent") == money("1.00")
    gov.verify_integrity()
    gov.close()


# --------------------------------------------------------------------------
# The new seams fail closed, and with this package's own types
# --------------------------------------------------------------------------


def test_a_runtime_that_fails_to_start_releases_what_it_claimed(
    db: str, tmp_path: Path, governor: tuple[str, BudgetManager]
) -> None:
    path, _ = governor
    chain_path = tmp_path / "escrow.jsonl"
    with pytest.raises(ValueError, match="cannot be negative"):
        runtime(db, chain_path, audit_path=path, settle_cost="-1")
    with EscrowChain(chain_path) as chain:  # the claim was released
        assert chain.path == chain_path


def test_an_in_memory_chain_has_nothing_to_close() -> None:
    chain = EscrowChain()
    chain.close()
    chain.append(RecordType.VERDICT, plan_id=PlanId("p"), payload_hash="a" * 64)
    assert chain.path is None and not chain.read_only


def test_a_chain_claim_that_cannot_be_taken_is_an_anchor_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = tmp_path / "blocked.jsonl"
    (tmp_path / "blocked.jsonl.lock").mkdir()
    with pytest.raises(AnchorError, match="cannot create"):
        EscrowChain(blocked)

    def no_locking(fd: int) -> None:
        raise OSError(37, "No locks available")

    monkeypatch.setattr("interlock.chain._lock_exclusive_nonblocking", no_locking)
    with pytest.raises(AnchorError, match="advisory locking"):
        EscrowChain(tmp_path / "nfs.jsonl")


def test_a_claim_held_without_an_identity_is_still_refused(tmp_path: Path) -> None:
    import fcntl

    path = tmp_path / "escrow.jsonl"
    holder = os.open(tmp_path / "escrow.jsonl.lock", os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(ChainInUseError) as refused:
            EscrowChain(path)
        assert "held by" not in str(refused.value)
    finally:
        os.close(holder)


def _locked(db: str) -> sqlite3.Connection:
    """Another connection holding the database exclusively."""
    blocker = sqlite3.connect(db, isolation_level=None)
    blocker.execute("BEGIN EXCLUSIVE")
    return blocker


def test_a_marker_table_that_cannot_be_created_refuses_the_stage(db: str) -> None:
    blocker = _locked(db)
    try:
        substrate = SqliteSubstrate(db, tables=TABLES, max_stage_seconds=0.05)
        with pytest.raises(InterlockError, match="commit-marker table"):
            engine(db, substrate=substrate).execute(plan())
    finally:
        blocker.rollback()
        blocker.close()
    assert (1, 777.0) not in totals(db)


def test_markers_that_cannot_be_read_are_an_interlock_error(db: str) -> None:
    engine(db).execute(plan())  # creates the marker table
    blocker = _locked(db)
    try:
        substrate = SqliteSubstrate(db, tables=TABLES, max_stage_seconds=0.05)
        with pytest.raises(InterlockError, match="cannot read commit markers"):
            substrate.resolve_intent(uuid.uuid4())
    finally:
        blocker.rollback()
        blocker.close()


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (sqlite3.OperationalError("disk I/O error"), "unreachable during a refresh"),
        (AgentGovError("store closed"), "refused a refresh"),
    ],
    ids=["driver", "agentgov"],
)
def test_a_refresh_that_fails_is_an_anchor_error(
    governor: tuple[str, BudgetManager],
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    message: str,
) -> None:
    path, _ = governor
    anchor = LedgerAnchor(path)

    def refresh() -> int:
        raise failure

    assert anchor._audit is not None
    monkeypatch.setattr(anchor._audit, "refresh", refresh)
    with pytest.raises(AnchorError, match=message):
        anchor.observe()
    assert anchor.halted_after_commit("agent") == "", "never raises after a commit"
    anchor.close()


def test_every_other_agentgov_refusal_on_the_seam_is_an_anchor_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gov = BudgetManager()
    gov.open_root("agent", money("1.00"))
    anchor = LedgerAnchor(governed=gov)

    def refuse(*_: object) -> None:
        raise AgentGovError("refused")

    monkeypatch.setattr(gov, "node", refuse)
    with pytest.raises(AnchorError, match="refused a scope lookup"):
        anchor.assert_scope_known("agent")
    monkeypatch.setattr(gov, "verify_integrity", refuse)
    with pytest.raises(AnchorError, match="refused a verification read"):
        anchor.verify()

    closed = BudgetManager.open_sqlite(":memory:")
    closed.open_root("agent", money("1.00"))
    detached = LedgerAnchor(governed=closed)
    closed.close()
    with pytest.raises(AnchorError, match="agent"):
        detached.reverse_anchor("agent", "a" * 64)
