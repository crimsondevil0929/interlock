"""Crash consistency: SIGKILL a real process at every step of a PostgreSQL commit.

Each test starts a child process (``tests/crash_child.py``) that builds the
stack a production process builds: a PostgreSQL substrate staging as the
agent's role on the back-office schema, a durable escrow chain, a governed
AgentGov ledger settling each plan's cost, and a durable ARC1 receipt log with
a witness. The child runs a three-table refund and stops at a named point on
the commit path; the parent kills it with ``SIGKILL``. Nothing in the child
gets to clean up. A fresh engine then resumes every file, runs
``recover()``, and the test checks the outcome exactly:

- the records the chain held when the process died, and the one recovery
  appended, with its note;
- whether the three rows and the stage's commit marker are in the database,
  and that nothing else in fifteen tables moved;
- what ``reconcile-effects`` says before and after recovery;
- that the server ended the dead session and released its locks, and the
  kernel released the chain's, the ledger's and the receipt log's claims;
- that the ledger and the receipt log reopen and verify, and every receipt
  still names the chain record that names it.

The rule the tests hold the system to: the chain says ``COMMITTED`` exactly
when the database committed, ``ABORTED`` exactly when it rolled back, and
nothing while the server has not decided. A random-instant soak then kills
the process wherever it happens to be, over and over, and checks the same
rule over the whole history.

A process can also lose its commit's outcome without dying: the connection
drops with ``COMMIT`` in flight. A TCP hop that loses exactly the ``COMMIT``,
or exactly its reply, checks the same rule for the engine that lived.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import random
import secrets
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")
from agentgov import BudgetManager  # noqa: E402
from agentgov.core import EntryType  # noqa: E402
from agentgov.receipts import (  # noqa: E402
    ActionReceipt,
    FileWitness,
    HmacKey,
    OutcomeStatus,
    ReceiptLog,
    load_cosignatures,
    verify_bundle,
)
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from interlock import (  # noqa: E402
    AgentFeedback,
    EscrowChain,
    EscrowEngine,
    LedgerAnchor,
    PostgresSubstrate,
    ReceiptIssuer,
    StageState,
)
from interlock.chain import EscrowRecord, RecordType  # noqa: E402
from interlock.exceptions import (  # noqa: E402
    ChainInUseError,
    CommitUnsettledError,
    StageError,
)
from interlock.reconcile import Reconciliation, StageFinding, reconcile_postgres  # noqa: E402
from tests.conftest import OBSERVED, Pg  # noqa: E402
from tests.crash_child import (  # noqa: E402
    ACKNOWLEDGED,
    LOG_ID,
    SCOPE,
    WITNESS_ID,
    Refund,
    checkers,
)
from tests.schemas import BACK_OFFICE_ROWS, specs  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")

ROOT = Path(__file__).resolve().parent.parent
TABLES = tuple(table for table, _ in BACK_OFFICE_ROWS)
GATE = 7_340_301
"""The advisory lock a gated commit waits on, server side."""

PA, SO, DC, VE, CI, CO, AB = (
    RecordType.PLAN_ADMITTED,
    RecordType.STAGE_OPENED,
    RecordType.DIFF_COMPUTED,
    RecordType.VERDICT,
    RecordType.COMMIT_INTENT,
    RecordType.COMMITTED,
    RecordType.ABORTED,
)
STAGED = (PA, SO, DC, VE)
REVERSE_ANCHORS = (EntryType.ANCHOR, EntryType.SPEND)
"""A reverse anchor is a free ANCHOR entry or the SPEND settling the plan; the
hold before a paid one carries the same memo and is not one."""

COMMITTED_NOTE = "recovered: commit marker present, stage committed (intent {})"
ABORTED_NOTE = "recovered: no commit marker, stage rolled back (intent {})"


def refund(n: int, amount: str = "3.00", *, globex: bool = False) -> Refund:
    return Refund(f"refund-{n:04d}", 9100 + n, Decimal(amount), globex=globex)


# --------------------------------------------------------------------------
# the child process
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    """One line the child printed: where it is, and what it knew there."""

    raw: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.raw["event"])

    @property
    def at(self) -> str:
        return str(self.raw.get("at", ""))

    @property
    def stage_id(self) -> uuid.UUID:
        return uuid.UUID(str(self.raw["stage_id"]))

    @property
    def txid(self) -> str:
        return str(self.raw["txid"])

    @property
    def backend_pid(self) -> int:
        return int(self.raw["backend_pid"])


class Child:
    """A child process running a scenario. Never asked to stop: killed."""

    def __init__(self, scenario: dict[str, Any], workdir: Path, number: int) -> None:
        path = workdir / f"scenario-{number}.json"
        path.write_text(json.dumps(scenario))
        self.stderr_path = workdir / f"child-{number}.stderr"
        with self.stderr_path.open("wb") as stderr:
            self.process = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", "tests.crash_child", str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=stderr,
            )
        assert self.process.stdout is not None
        self._fd = self.process.stdout.fileno()
        self._buffer = b""

    @property
    def pid(self) -> int:
        return self.process.pid

    def next_event(self, timeout: float = 60.0) -> Event:
        """The child's next line. Fails with its stderr if it died first."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"child printed nothing for {timeout}s\n{self.stderr()}")
            ready, _, _ = select.select([self._fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(self._fd, 65536)
            if not chunk:
                code = self.process.wait()
                raise AssertionError(f"child exited {code} before its kill point\n{self.stderr()}")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return Event(json.loads(line))

    def wait_for(self, name: str, timeout: float = 60.0) -> Event:
        while True:
            event = self.next_event(timeout)
            if event.name == name:
                return event

    def kill(self) -> None:
        """SIGKILL: the process ends where it is, with nothing run after."""
        os.kill(self.process.pid, signal.SIGKILL)
        code = self.process.wait(timeout=30)
        assert code == -signal.SIGKILL, f"child ended {code}, not by SIGKILL\n{self.stderr()}"
        if self.process.stdout is not None:
            self.process.stdout.close()

    def stderr(self) -> str:
        return self.stderr_path.read_text(errors="replace")[-4000:]


# --------------------------------------------------------------------------
# the database, read as an administrator
# --------------------------------------------------------------------------


def rows(dsn: str, statement: str, *params: object) -> list[tuple[Any, ...]]:
    with psycopg.connect(dsn, autocommit=True) as conn:
        found: list[tuple[Any, ...]] = conn.execute(statement, params).fetchall()
        return found


def one(dsn: str, statement: str, *params: object) -> Any:
    return rows(dsn, statement, *params)[0][0]


def eventually(check: Callable[[], bool], what: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        time.sleep(0.02)


def status(env: Pg, txid: str) -> str:
    return str(one(env.admin, "SELECT pg_xact_status(%s::xid8)", txid))


def sessions(env: Pg) -> int:
    """Sessions open as the stage role: the child's, while any survive."""
    return int(one(env.admin, "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", env.role))


def waiting_on_gate(env: Pg, pid: int) -> bool:
    return bool(
        one(
            env.admin,
            "SELECT count(*) FROM pg_locks WHERE pid = %s AND locktype = 'advisory' "
            "AND NOT granted",
            pid,
        )
    )


def row_locked(env: Pg) -> bool:
    """Whether some transaction holds account 100's row: NOWAIT is refused."""
    with psycopg.connect(env.admin) as conn:
        try:
            conn.execute("SELECT 1 FROM accounts WHERE id = 100 FOR UPDATE NOWAIT")
        except psycopg.errors.LockNotAvailable:
            return True
        finally:
            conn.rollback()
    return False


def snapshot(env: Pg) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of all fifteen tables, and Interlock's own two logs."""
    with psycopg.connect(env.admin) as conn:
        tables = {t: conn.execute(f"SELECT * FROM {t} ORDER BY 1, 2").fetchall() for t in TABLES}
        tables["interlock.stages"] = conn.execute(
            "SELECT stage_id, plan_id FROM interlock.stages ORDER BY 1"
        ).fetchall()
        tables["interlock.unmediated"] = conn.execute(
            "SELECT id, tbl, pk FROM interlock.unmediated ORDER BY 1"
        ).fetchall()
        return tables


@dataclass(frozen=True)
class Books:
    """What the database says the refunds did."""

    balance: Decimal
    qty: int
    globex: Decimal
    refunds: dict[int, Decimal]
    markers: frozenset[str]

    @classmethod
    def read(cls, env: Pg) -> Books:
        with psycopg.connect(env.admin, autocommit=True) as conn:

            def value(statement: str) -> Any:
                row = conn.execute(statement).fetchone()
                assert row is not None
                return row[0]

            return cls(
                balance=Decimal(value("SELECT balance FROM accounts WHERE id = 100")),
                qty=int(value("SELECT qty FROM order_items WHERE id = 5000")),
                globex=Decimal(value("SELECT balance FROM accounts WHERE id = 200")),
                refunds={
                    int(r[0]): Decimal(r[1])
                    for r in conn.execute("SELECT id, amount FROM refunds WHERE id >= 9100")
                },
                markers=frozenset(
                    str(r[0]) for r in conn.execute("SELECT stage_id::text FROM interlock.stages")
                ),
            )

    @classmethod
    def after(cls, committed: Iterable[Refund], markers: Iterable[str]) -> Books:
        """The books if exactly ``committed`` committed, each exactly once."""
        done = list(committed)
        return cls(
            balance=Decimal("500.00") + sum((r.amount for r in done), Decimal(0)),
            qty=2 + len(done),
            globex=Decimal("900.00"),
            refunds={r.refund_id: r.amount for r in done},
            markers=frozenset(markers),
        )


def reconcile(env: Pg, records: Iterable[EscrowRecord]) -> Reconciliation:
    with psycopg.connect(env.admin, autocommit=True) as conn:
        return reconcile_postgres(conn, records)


# --------------------------------------------------------------------------
# the environment: one back office, and the processes that crash against it
# --------------------------------------------------------------------------


@dataclass
class Restarted:
    """What a restarted process opens: every file resumed, one engine."""

    chain: EscrowChain
    governor: BudgetManager
    log: ReceiptLog
    witness: FileWitness
    engine: EscrowEngine

    def close(self) -> None:
        self.log.close()
        self.chain.close()
        self.governor.close()


@dataclass
class Crash:
    pg: Pg
    workdir: Path
    log_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    witness_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    row_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    children: list[Child] = field(default_factory=list)

    def __post_init__(self) -> None:
        governor = BudgetManager.open_sqlite(str(self.ledger))
        try:
            governor.open_root(SCOPE, "1000")
        finally:
            governor.close()

    @property
    def chain(self) -> Path:
        return self.workdir / "escrow.jsonl"

    @property
    def ledger(self) -> Path:
        return self.workdir / "governor.db"

    @property
    def receipts(self) -> Path:
        return self.workdir / "receipts.jsonl"

    @property
    def witness_file(self) -> Path:
        return self.workdir / "witness.jsonl"

    def start(
        self,
        plans: Sequence[Refund],
        *,
        kill: dict[str, object] | None = None,
        recover: bool = True,
        dsn: str | None = None,
        stage_seconds: float = 10.0,
        lock_seconds: float = 2.0,
    ) -> Child:
        scenario = {
            "dsn": dsn or self.pg.agent,
            "chain": str(self.chain),
            "ledger": str(self.ledger),
            "receipts": str(self.receipts),
            "witness": str(self.witness_file),
            "log_key": self.log_key.hex(),
            "witness_key": self.witness_key.hex(),
            "row_secret": self.row_secret.hex(),
            "stage_seconds": stage_seconds,
            "lock_seconds": lock_seconds,
            "recover": recover,
            "plans": [p.to_json() for p in plans],
            "kill": kill or {},
        }
        child = Child(scenario, self.workdir, len(self.children))
        self.children.append(child)
        return child

    def settle(self) -> None:
        """Wait for the server to end every session the dead child left."""
        eventually(lambda: sessions(self.pg) == 0, "the dead child's sessions to end")

    def restart(self, dsn: str | None = None) -> Restarted:
        """Open everything a restarted process opens, as it opens it.

        Each open would raise if the dead process's claim on the file had
        outlived it: the kernel releases an ``flock`` when the process dies.
        """
        chain = EscrowChain(self.chain)
        governor = BudgetManager.open_sqlite(str(self.ledger))
        log_key = HmacKey(self.log_key)
        witness = FileWitness(
            self.witness_file,
            HmacKey(self.witness_key),
            witness_id=WITNESS_ID,
            logs={LOG_ID: log_key},
        )
        log = ReceiptLog(LOG_ID, log_key, path=self.receipts, witnesses=[witness])
        engine = EscrowEngine(
            PostgresSubstrate(
                dsn or self.pg.agent, tables=specs(*OBSERVED), acknowledge_cascades=ACKNOWLEDGED
            ),
            checkers=checkers(),
            chain=chain,
            anchor=LedgerAnchor(governed=governor),
            settle_cost="0.25",
            receipts=ReceiptIssuer(log, row_secret=self.row_secret),
        )
        return Restarted(chain, governor, log, witness, engine)

    def cleanup(self) -> None:
        for child in self.children:
            if child.process.poll() is None:
                child.kill()


@pytest.fixture
def crash(pg: Pg, tmp_path: Path) -> Iterator[Crash]:
    env = Crash(pg, tmp_path)
    try:
        yield env
    finally:
        env.cleanup()
        eventually(lambda: sessions(pg) == 0, "every child session to end before teardown")


# --------------------------------------------------------------------------
# what every recovered history must satisfy
# --------------------------------------------------------------------------


def stage_records(records: Sequence[EscrowRecord], plan_id: str) -> list[RecordType]:
    return [r.record_type for r in records if r.plan_id == plan_id]


def check_history(env: Crash, opened: Restarted, plans: Iterable[Refund]) -> set[str]:
    """Check the whole recovered history against the database, and return
    the plans that committed.

    - the chain verifies, its anchors never regress, and no intent is open;
    - no plan committed twice, and no refused plan committed;
    - the database holds exactly the committed plans' rows, once each, and a
      commit marker for exactly the stages the chain records as committed;
    - reconcile-effects finds nothing;
    - the ledger verifies, and every reverse anchor names a chain record;
    - every receipt verifies, with its checkpoint and the witness's
      cosignature, and names the chain record that names it back.
    """
    by_id = {p.plan_id: p for p in plans}
    records = opened.chain.records()
    opened.chain.verify()
    opened.chain.verify_anchors()
    assert opened.chain.unresolved_intents() == ()

    commits = Counter(r.plan_id for r in records if r.record_type is CO)
    assert all(n == 1 for n in commits.values()), f"a plan committed twice: {commits}"
    committed = {str(plan) for plan in commits}
    assert not {p for p in committed if by_id[p].globex}, "a refused plan committed"
    markers = {str(r.stage_id) for r in records if r.record_type is CO}
    assert Books.read(env.pg) == Books.after([by_id[p] for p in committed], markers)
    assert reconcile(env.pg, records).clean

    opened.governor.verify_integrity()
    heads = {r.record_hash[:16] for r in records}
    for entry in opened.governor.audit_trail():
        if entry.memo.startswith("interlock:"):
            assert entry.memo.removeprefix("interlock:") in heads, entry
    for hold in opened.governor.ledger.open_holds():
        assert hold.memo.removeprefix("interlock:") in heads, hold

    check_receipts(env, opened, records)
    return committed


def check_receipts(env: Crash, opened: Restarted, records: Sequence[EscrowRecord]) -> None:
    log = opened.log
    receipts = log.receipts()
    if not receipts:
        return
    # Checkpoint the log as it stands and have the witness cosign it: the
    # witness refuses anything that does not extend what it saw before.
    checkpoint = log.publish()
    published = load_cosignatures(env.witness_file)
    key = HmacKey(env.log_key)
    for index, receipt in enumerate(receipts):
        report = verify_bundle(
            log.bundle(index, checkpoint),
            issuer_key=key,
            cosignatures=published,
            witness_key=HmacKey(env.witness_key),
            ledger=opened.governor,
        )
        assert report.passed, (index, report.to_json())
        check_link(records, receipt)


def check_link(records: Sequence[EscrowRecord], receipt: ActionReceipt) -> None:
    """The receipt names its plan's terminal record, which names it back."""
    anchor = receipt.anchors.escrow
    assert anchor is not None
    record = records[anchor.seq - 1]
    assert record.record_hash == anchor.head
    assert record.record_type in (CO, AB)
    assert record.note.endswith(f"receipt {receipt.receipt_id}")
    assert (receipt.outcome.status is OutcomeStatus.COMMITTED) == (record.record_type is CO)


# --------------------------------------------------------------------------
# a kill at each point of the commit path
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    at: str
    committed: bool
    """What the database did with the plan."""
    chain: tuple[RecordType, ...]
    """The plan's records on the chain when the process died."""
    recovered: RecordType | None
    """What recovery appends for it."""
    effect: int = 0
    record: str = ""

    @property
    def open_transaction(self) -> bool:
        """Whether the stage's transaction was still open at the kill."""
        return not self.committed

    @property
    def id(self) -> str:
        return f"{self.at}-{self.record}" if self.record else self.at


CASES = [
    # Mid-stage: the transaction is open, two of three rows written.
    Case("apply", committed=False, chain=(PA, SO), recovered=None, effect=2),
    # The intent is on disk, the COMMIT never sent: the server rolls back.
    Case("intent", committed=False, chain=(*STAGED, CI), recovered=AB),
    # COMMIT returned; the process died before recording it.
    Case("committed", committed=True, chain=(*STAGED, CI), recovered=CO),
    # COMMITTED recorded; no reverse anchor and no receipt yet.
    Case("recorded", committed=True, chain=(*STAGED, CI, CO), recovered=None),
    # The reverse anchor settled; no receipt yet.
    Case("anchored", committed=True, chain=(*STAGED, CI, CO), recovered=None),
    # The intent torn mid-write: it never existed, so the COMMIT never ran.
    Case("torn", committed=False, chain=STAGED, recovered=None, record="commit_intent"),
    # COMMITTED torn mid-write: the resumed chain cuts it, recovery redoes it.
    Case("torn", committed=True, chain=(*STAGED, CI), recovered=CO, record="committed"),
]


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_a_kill_at_each_point_of_the_commit_path_is_recovered_exactly(
    crash: Crash, case: Case, caplog: pytest.LogCaptureFixture
) -> None:
    before = snapshot(crash.pg)
    first, second = refund(0), refund(1, "4.50")
    child = crash.start(
        [first],
        kill={"at": case.at, "effect": case.effect, "record": case.record},
    )
    stop = child.wait_for("stopped")
    assert stop.at == case.at

    if case.open_transaction:
        # Staged, not committed: invisible to everyone else, and locked.
        assert Books.read(crash.pg) == Books.after([], [])
        assert row_locked(crash.pg)
    with pytest.raises(ChainInUseError, match=f"held by pid {child.pid}"):
        EscrowChain(crash.chain)

    child.kill()
    crash.settle()
    assert not row_locked(crash.pg)
    assert one(crash.pg.admin, "SELECT count(*) FROM pg_prepared_xacts") == 0

    # What the crash left, before anything resumes a file.
    data = crash.chain.read_bytes()
    left = EscrowChain.load(crash.chain).records()
    assert stage_records(left, first.plan_id) == list(case.chain)
    if case.id.startswith("torn"):
        assert not data.endswith(b"\n")
        assert len(data) - (data.rfind(b"\n") + 1) == int(stop.raw["written"])
    intents = [r for r in left if r.record_type is CI]
    books = Books.read(crash.pg)
    stage = next(r.stage_id for r in left if r.record_type is SO)
    assert (str(stage) in books.markers) is case.committed
    if case.committed:
        assert books == Books.after([first], books.markers)
    else:
        assert snapshot(crash.pg) == before
    findings = reconcile(crash.pg, left).stages
    if case.committed and CO not in case.chain:
        assert findings == (StageFinding(str(stage), first.plan_id, "unresolved"),)
    else:
        assert findings == ()

    caplog.clear()
    opened = crash.restart()
    try:
        if case.id.startswith("torn"):
            assert crash.chain.read_bytes() == data[: data.rfind(b"\n") + 1]
            assert "torn record" in caplog.text
        recovered = opened.engine.recover()
        if case.recovered is None:
            assert recovered == ()
        else:
            (record,) = recovered
            (intent,) = intents
            assert record.record_type is case.recovered
            assert (record.stage_id, record.payload_hash) == (intent.stage_id, intent.payload_hash)
            note = COMMITTED_NOTE if case.recovered is CO else ABORTED_NOTE
            assert record.note == note.format(intent.sequence)
            assert record.anchored
        assert opened.engine.recover() == ()

        # Nothing the dead process started issued a receipt; the terminal
        # record written before the kill names the one it meant to issue.
        assert len(opened.log) == 0
        terminal = [r for r in opened.chain.records() if r.plan_id == first.plan_id][-1]
        if CO in case.chain:
            receipt_id = terminal.note.rsplit("receipt ", 1)[1]
            assert opened.log.index_of(receipt_id) is None
        anchors = [
            e
            for e in opened.governor.audit_trail()
            if e.memo.startswith("interlock:") and e.entry_type in REVERSE_ANCHORS
        ]
        if case.at == "anchored":
            (anchor,) = anchors
            assert anchor.entry_type is EntryType.SPEND and anchor.amount == Decimal("0.25")
            assert anchor.memo == f"interlock:{terminal.record_hash[:16]}"
        else:
            assert anchors == []

        # The restarted process carries on: the next plan commits against
        # the same rows, the chain continues, and the whole history holds.
        result = opened.engine.execute(second.plan())
        assert result.committed and result.receipt is not None
        committed = check_history(crash, opened, [first, second])
        assert committed == ({first.plan_id} if case.committed else set()) | {second.plan_id}
    finally:
        opened.close()


# --------------------------------------------------------------------------
# a kill while the server is still committing
# --------------------------------------------------------------------------


def install_gate(env: Pg) -> None:
    """A deferred trigger on ``accounts`` that makes COMMIT wait for a lock
    the test holds. PostgreSQL runs deferred triggers inside COMMIT, after it
    has stopped the statement timeout, so only the stage's ``lock_timeout``,
    or the server noticing the client is gone, ends the wait."""
    with psycopg.connect(env.admin, autocommit=True) as conn:
        conn.execute(
            "CREATE FUNCTION crash_gate() RETURNS trigger LANGUAGE plpgsql AS "
            f"$$ BEGIN PERFORM pg_advisory_xact_lock({GATE}); RETURN NULL; END $$"
        )
        conn.execute(
            "CREATE CONSTRAINT TRIGGER crash_gate AFTER INSERT OR UPDATE ON accounts "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION crash_gate()"
        )


@pytest.mark.parametrize(
    ("server", "outcome"),
    [
        ("finishes the commit", RecordType.COMMITTED),
        ("times out the commit's lock wait", RecordType.ABORTED),
        ("notices the client is gone", RecordType.ABORTED),
    ],
)
def test_a_kill_during_commit_is_resolved_as_the_server_decided(
    crash: Crash, server: str, outcome: RecordType, caplog: pytest.LogCaptureFixture
) -> None:
    """The process dies with its COMMIT in flight. Whatever the server then
    does, recovery follows it: nothing while the server has not decided, then
    exactly what it decided."""
    caplog.set_level(logging.WARNING)
    before = snapshot(crash.pg)
    first = refund(0)
    install_gate(crash.pg)
    gate = psycopg.connect(crash.pg.admin, autocommit=True)
    try:
        gate.execute("SELECT pg_advisory_lock(%s)", (GATE,))
        dsn = crash.pg.agent
        lock_seconds = 20.0
        if server == "times out the commit's lock wait":
            lock_seconds = 1.0
        if server == "notices the client is gone":
            dsn = make_conninfo(dsn, options="-c client_connection_check_interval=100")
        child = crash.start(
            [first], kill={"at": "commit"}, dsn=dsn, stage_seconds=20.0, lock_seconds=lock_seconds
        )
        sent = child.wait_for("committing")
        eventually(lambda: waiting_on_gate(crash.pg, sent.backend_pid), "COMMIT to reach the gate")
        child.kill()

        opened = crash.restart()
        try:
            if server == "finishes the commit":
                # The client is dead and the server is still committing. The
                # marker is not visible yet, and "absent" is not "rolled back".
                assert status(crash.pg, sent.txid) == "in progress"
                assert opened.engine.recover() == ()
                (intent,) = opened.chain.unresolved_intents()
                assert intent.stage_id == sent.stage_id
                assert "still running on the server" in caplog.text
                assert "is not settled yet; recovery will ask again" in caplog.text
                assert reconcile(crash.pg, opened.chain.records()).clean
                gate.execute("SELECT pg_advisory_unlock(%s)", (GATE,))
            eventually(lambda: status(crash.pg, sent.txid) != "in progress", "the server")
            decided = status(crash.pg, sent.txid)
            assert decided == ("committed" if outcome is CO else "aborted")
            crash.settle()

            (record,) = opened.engine.recover()
            assert record.record_type is outcome
            assert record.stage_id == sent.stage_id
            books = Books.read(crash.pg)
            if outcome is CO:
                assert books == Books.after([first], [str(sent.stage_id)])
            else:
                assert snapshot(crash.pg) == before
            gate.execute("SELECT pg_advisory_unlock_all()")
            assert opened.engine.execute(refund(1).plan()).committed
            check_history(crash, opened, [first, refund(1)])
        finally:
            opened.close()
    finally:
        gate.close()


# --------------------------------------------------------------------------
# a client that hangs instead of dying
# --------------------------------------------------------------------------


def test_a_hung_client_holds_its_stage_only_until_the_stage_bound(crash: Crash) -> None:
    """A client that stops responding (a hung process, a lost network) keeps
    its session, its transaction and its row locks on the server. Recovery
    must not read the missing marker as a rollback while the server still
    holds the transaction, and the stage's bound must end it."""
    before = snapshot(crash.pg)
    first = refund(0)
    child = crash.start([first], kill={"at": "intent"}, stage_seconds=4.0)
    stop = child.wait_for("stopped")
    intent = EscrowChain.load(crash.chain).unresolved_intents()[0]
    txid = intent.note.split("; txid ")[1].split(";")[0]

    # The client is alive but silent: its transaction is still running.
    assert status(crash.pg, txid) == "in progress"
    sub = PostgresSubstrate(crash.pg.agent, tables=specs(*OBSERVED))
    assert sub.resolve_intent(stop.stage_id, txid=txid) is None
    assert row_locked(crash.pg)
    with pytest.raises(ChainInUseError, match=f"held by pid {child.pid}"):
        EscrowChain(crash.chain)

    # The server ends it at the stage bound, idle_in_transaction_session_timeout.
    eventually(lambda: status(crash.pg, txid) == "aborted", "the stage bound")
    crash.settle()
    assert not row_locked(crash.pg)
    assert sub.resolve_intent(stop.stage_id, txid=txid) is False
    assert snapshot(crash.pg) == before
    # The file claim is the process's, not the server's: still held.
    with pytest.raises(ChainInUseError):
        EscrowChain(crash.chain)

    child.kill()
    opened = crash.restart()
    try:
        (record,) = opened.engine.recover()
        assert record.record_type is AB
        assert record.note == ABORTED_NOTE.format(intent.sequence)
        check_history(crash, opened, [first])
    finally:
        opened.close()


# --------------------------------------------------------------------------
# a kill during recovery itself
# --------------------------------------------------------------------------


def test_recovery_killed_halfway_resolves_the_rest_exactly_once(crash: Crash) -> None:
    """Two crashes leave two intents open, one committed on the server and
    one not. A third process starts recovering and is killed after resolving
    the first. The next recovery resolves only the second."""
    first, second = refund(0), refund(1, "2.25")
    child = crash.start([first], kill={"at": "committed"})
    child.wait_for("stopped")
    child.kill()
    crash.settle()
    # A process that does not recover at startup, and crashes in its turn.
    child = crash.start([second], kill={"at": "intent"}, recover=False)
    child.wait_for("stopped")
    child.kill()
    crash.settle()
    first_intent, second_intent = EscrowChain.load(crash.chain).unresolved_intents()

    child = crash.start([], kill={"at": "recovered"})
    stop = child.wait_for("stopped")
    assert stop.raw["note"] == COMMITTED_NOTE.format(first_intent.sequence)
    child.kill()

    opened = crash.restart()
    try:
        (record,) = opened.engine.recover()
        assert record.stage_id == second_intent.stage_id
        assert record.note == ABORTED_NOTE.format(second_intent.sequence)
        terminal = Counter(r.stage_id for r in opened.chain.records() if r.record_type in (CO, AB))
        assert terminal == {first_intent.stage_id: 1, second_intent.stage_id: 1}
        assert check_history(crash, opened, [first, second]) == {first.plan_id}
    finally:
        opened.close()


# --------------------------------------------------------------------------
# a connection lost with COMMIT in flight
# --------------------------------------------------------------------------


def _hang_up(sock: socket.socket, *, reset: bool = False) -> None:
    """Drop one end of a proxied connection, as a failing network does.

    ``shutdown`` first: another thread may be blocked reading this socket,
    and ``close`` alone neither wakes it nor ends the connection while that
    read holds it. ``reset`` sends a TCP reset rather than an orderly close.
    """
    with contextlib.suppress(OSError):
        if reset:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):
        sock.close()


class LossyLink:
    """A TCP hop between the engine and PostgreSQL that loses one COMMIT.

    Bytes pass untouched until a client sends a message carrying ``COMMIT``.
    Then, by ``mode``:

    - ``reply``: the COMMIT reaches the server, which commits; its answer is
      dropped and the client's connection reset. The server committed and the
      client never hears so.
    - ``request``: the COMMIT is dropped and the server's end closed. Once the
      server has ended the session (``settled``), the client's connection is
      reset. The server rolled back, and the client cannot tell which
      happened.
    - ``inflight``: the COMMIT reaches the server and both ends are closed at
      once, while the server is still committing.

    Only the first COMMIT is lost; every later connection passes through.
    """

    def __init__(
        self, target: tuple[str, int], mode: str, settled: Callable[[], bool] = lambda: True
    ) -> None:
        self._target = target
        self._mode = mode
        self._settled = settled
        self._armed = True
        self._guard = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = int(self._listener.getsockname()[1])
        self.lost = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def dsn(self, base: str) -> str:
        return make_conninfo(base, host="127.0.0.1", port=str(self.port), sslmode="disable")

    def close(self) -> None:
        _hang_up(self._listener)
        for sock in self._sockets:
            _hang_up(sock)

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            server = socket.create_connection(self._target)
            self._sockets += [client, server]
            hop = _Hop(client, server)
            threading.Thread(target=self._up, args=(hop,), daemon=True).start()
            threading.Thread(target=self._down, args=(hop,), daemon=True).start()

    def _claim(self) -> bool:
        with self._guard:
            armed, self._armed = self._armed, False
            return armed

    def _lose(self, hop: _Hop, *, settle: bool = False) -> None:
        """End both sides of one hop: the server's first, the client's with a
        reset, and only once the server has ended the session if ``settle``."""
        _hang_up(hop.server)
        if settle:
            eventually(self._settled, "the server to end the session")
        self.lost.set()
        _hang_up(hop.client, reset=True)

    def _up(self, hop: _Hop) -> None:
        """Client to server."""
        with contextlib.suppress(OSError):
            while data := hop.client.recv(65536):
                if b"COMMIT\x00" in data and self._claim():
                    if self._mode == "request":
                        hop.taken.set()
                        self._lose(hop, settle=True)
                        return
                    hop.committing.set()
                    hop.server.sendall(data)
                    if self._mode == "inflight":
                        hop.taken.set()
                        self._lose(hop)
                        return
                    continue
                hop.server.sendall(data)
        if not hop.taken.is_set():
            _hang_up(hop.server)

    def _down(self, hop: _Hop) -> None:
        """Server to client."""
        with contextlib.suppress(OSError):
            while data := hop.server.recv(65536):
                if hop.committing.is_set():
                    # The server's answer to COMMIT: it committed. Lose it.
                    hop.taken.set()
                    self._lose(hop)
                    return
                hop.client.sendall(data)
        if not hop.taken.is_set():
            _hang_up(hop.client)


@dataclass
class _Hop:
    """One proxied connection. Whichever pump loses the COMMIT takes the hop,
    and the other then leaves both ends to it."""

    client: socket.socket
    server: socket.socket
    committing: threading.Event = field(default_factory=threading.Event)
    taken: threading.Event = field(default_factory=threading.Event)


@pytest.fixture
def lossy(crash: Crash) -> Iterator[Callable[[str], LossyLink]]:
    info = conninfo_to_dict(crash.pg.agent)
    target = (str(info.get("host") or "127.0.0.1"), int(str(info.get("port") or 5432)))
    links: list[LossyLink] = []

    def make(mode: str) -> LossyLink:
        link = LossyLink(target, mode, settled=lambda: sessions(crash.pg) == 0)
        links.append(link)
        return link

    try:
        yield make
    finally:
        for link in links:
            link.close()


def test_a_commit_whose_reply_is_lost_is_recorded_as_committed(
    crash: Crash, lossy: Callable[[str], LossyLink]
) -> None:
    """The server committed and the client never heard. The stage's commit
    marker answers for it: the plan committed, and is reported so. Reporting
    it failed would invite a retry, which would apply it twice."""
    first = refund(0)
    link = lossy("reply")
    opened = crash.restart(dsn=link.dsn(crash.pg.agent))
    try:
        result = opened.engine.execute(first.plan())
        assert link.lost.is_set()
        assert result.committed and result.state is StageState.COMMITTED
        assert result.receipt is not None
        records = opened.chain.records()
        assert stage_records(records, first.plan_id) == [*STAGED, CI, CO]
        assert "the commit's reply was lost; its commit marker is present" in records[-1].note
        assert check_history(crash, opened, [first]) == {first.plan_id}
    finally:
        opened.close()


def test_a_commit_lost_before_the_server_saw_it_is_recorded_as_aborted(
    crash: Crash, lossy: Callable[[str], LossyLink]
) -> None:
    """The COMMIT never arrived, and the server rolled back. The marker is
    absent and the server has ended the transaction: aborted, exactly."""
    before = snapshot(crash.pg)
    first = refund(0)
    link = lossy("request")
    opened = crash.restart(dsn=link.dsn(crash.pg.agent))
    try:
        with pytest.raises(StageError) as raised:
            opened.engine.execute(first.plan())
        assert not isinstance(raised.value, CommitUnsettledError)
        assert link.lost.is_set()
        records = opened.chain.records()
        assert stage_records(records, first.plan_id) == [*STAGED, CI, AB]
        assert snapshot(crash.pg) == before
        assert check_history(crash, opened, [first]) == set()
    finally:
        opened.close()


def test_a_commit_lost_in_flight_stays_open_until_the_server_decides(
    crash: Crash, lossy: Callable[[str], LossyLink]
) -> None:
    """The connection died while the server was still committing. Nobody can
    say yet: the engine raises without a terminal record, tells the agent not
    to retry, and recovery follows the server once it decides."""
    first = refund(0)
    install_gate(crash.pg)
    gate = psycopg.connect(crash.pg.admin, autocommit=True)
    link = lossy("inflight")
    opened = crash.restart(dsn=link.dsn(crash.pg.agent))
    try:
        gate.execute("SELECT pg_advisory_lock(%s)", (GATE,))
        with pytest.raises(CommitUnsettledError) as raised:
            opened.engine.execute(first.plan())
        feedback = raised.value.feedback
        assert isinstance(feedback, AgentFeedback) and not feedback.retryable
        (intent,) = opened.chain.unresolved_intents()
        assert stage_records(opened.chain.records(), first.plan_id) == [*STAGED, CI]
        txid = intent.note.split("; txid ")[1].split(";")[0]
        assert status(crash.pg, txid) == "in progress"

        gate.execute("SELECT pg_advisory_unlock(%s)", (GATE,))
        eventually(lambda: status(crash.pg, txid) == "committed", "the server to commit")
        (record,) = opened.engine.recover()
        assert record.note == COMMITTED_NOTE.format(intent.sequence)
        assert check_history(crash, opened, [first]) == {first.plan_id}
    finally:
        opened.close()
        gate.close()


# --------------------------------------------------------------------------
# kills at random instants
# --------------------------------------------------------------------------

SEED = int(os.environ.get("INTERLOCK_CRASH_SEED", "20260926"))
ROUNDS = int(os.environ.get("INTERLOCK_CRASH_ROUNDS", "6"))


def test_kills_at_random_instants_never_break_the_history(crash: Crash) -> None:
    """Run a stream of refunds, some refused, and kill the process wherever
    it happens to be. Repeat. After every kill the recovered history must hold
    exactly: the database is the fold of the plans the chain says committed,
    each once, and every receipt, anchor and marker agrees.

    ``INTERLOCK_CRASH_SEED`` and ``INTERLOCK_CRASH_ROUNDS`` rerun a failure or
    run longer."""
    rng = random.Random(SEED)  # noqa: S311 - kill instants, not secrets
    plans: list[Refund] = []
    committed: set[str] = set()
    for round_ in range(ROUNDS):
        batch = [
            refund(
                round_ * 100 + i, f"{rng.randint(1, 9)}.{rng.randint(0, 99):02d}", globex=i % 5 == 4
            )
            for i in range(40)
        ]
        plans += batch
        child = crash.start(batch)
        child.wait_for("started")
        time.sleep(rng.uniform(0.05, 1.5))
        child.kill()
        crash.settle()
        opened = crash.restart()
        try:
            opened.engine.recover()
            now = check_history(crash, opened, plans)
        finally:
            opened.close()
        assert committed <= now, f"seed {SEED} round {round_}: a committed plan vanished"
        committed = now
    assert committed, f"seed {SEED}: no plan ever committed; the kills came too early"
