"""Crash consistency on SQLite: SIGKILL an engine at every step of a commit
that carries an outbound request (``docs/EPIC3_DESIGN.md`` §7).

Each test starts a child process (``tests/sqlite_stage_child.py``) that stages
refunds in a SQLite back office with the outbox installed: three tables and
the customer's email per plan, a durable escrow chain, an AgentGov ledger
taking each plan's reverse anchor and settling its cost. The child stops at a
named point on the commit path; the parent looks at the file from outside
while the child holds it, then kills it with ``SIGKILL``. A fresh engine
resumes the chain and runs ``recover()``, and the test checks:

- the chain verifies, no intent is left open, no plan committed twice, and
  none the checkers refused committed;
- the database is exactly the fold of the plans the chain says committed: the
  rows, the commit markers, and **the outbox, which holds a request exactly
  when its stage's commit marker is there**;
- ``reconcile-effects`` finds every write accounted for;
- the ledger verifies, and every reverse anchor names a chain record;
- while the child held a stage open, nothing it wrote was visible, and a relay
  could not take the write lock to lease anything (OB-7, across processes);
- a relay then delivers every committed plan's email once, and nothing else.

A random-instant soak then runs an engine and a relay as two processes
contending for the one file, kills both wherever they happen to be, over and
over, and checks the same rule over the whole history.
"""

from __future__ import annotations

import os
import random
import sqlite3
import sys
import time
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager

from interlock import EscrowChain, EscrowEngine, LedgerAnchor, SqliteSubstrate
from interlock.adapters import HttpAdapter
from interlock.chain import EscrowRecord, RecordType
from interlock.deliveries import OUTCOMES, verify_delivery_log
from interlock.exceptions import SubstrateUnavailableError
from interlock.outbound import SinkRegistry
from interlock.reconcile import install_sqlite_journal, reconcile_sqlite
from interlock.relay import NoBreaker, Relay
from interlock.sqlite_outbox import SqliteOutboxStore, install_sqlite_outbox
from interlock.types import EffectId, outbound_key
from tests.children import Child
from tests.conftest import OBSERVED, build_sqlite_back_office
from tests.crash_child import ACKNOWLEDGED, SCOPE, Refund, checkers, windows
from tests.fakesink import DROP, OK, FakeSink, hang, status
from tests.outbox_env import RELAY_SEED, ROUTES, relay_signer
from tests.schemas import TEST_SINKS, specs

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")

CO, AB, CI = RecordType.COMMITTED, RecordType.ABORTED, RecordType.COMMIT_INTENT
SEED = int(os.environ.get("INTERLOCK_CRASH_SEED", "20261003"))
ROUNDS = int(os.environ.get("INTERLOCK_CRASH_ROUNDS", "6"))
MAX_ROUNDS = 40
PLANS = 500
"""Per round: more than an engine finishes before the latest kill (a plan
takes a few milliseconds), so every kill lands mid-stream."""


def refund(n: int, amount: str = "3.00", *, globex: bool = False) -> Refund:
    return Refund(f"refund-{n:04d}", 9100 + n, Decimal(amount), globex=globex)


def key(plan_id: str) -> str:
    return outbound_key(plan_id, EffectId("notify"))


# --------------------------------------------------------------------------
# the database, read from outside
# --------------------------------------------------------------------------


def read(path: str) -> sqlite3.Connection:
    """A reader, as any other process opens the file: in WAL mode it never
    waits for the writer, and sees only what has committed."""
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def cents(value: object) -> Decimal:
    """A NUMERIC column read back: SQLite keeps it as REAL, so a running
    balance drifts in the last binary digits. Money is compared in cents."""
    return Decimal(str(value)).quantize(Decimal("0.01"))


@dataclass(frozen=True)
class Books:
    """What the database says the refunds did."""

    balance: Decimal
    qty: int
    globex: Decimal
    refunds: dict[int, Decimal]
    markers: frozenset[str]
    outbox: frozenset[str]
    """The plans with a request in the outbox."""
    windowed: dict[str, Decimal]
    """What each plan added to the refunds window, by its stage's plan."""

    @classmethod
    def read(cls, path: str) -> Books:
        with closing(read(path)) as conn:

            def value(statement: str) -> Any:
                row = conn.execute(statement).fetchone()
                assert row is not None
                return row[0]

            requests = Counter(
                str(r[0])
                for r in conn.execute(
                    # Each request's stage committed its marker (the foreign
                    # key), and is the stage of the same plan.
                    "SELECT o.plan_id FROM _interlock_outbox o "
                    "JOIN _interlock_commits c USING (stage_id) WHERE o.plan_id = c.plan_id"
                )
            )
            assert all(n == 1 for n in requests.values()), f"a request twice: {requests}"
            total = value("SELECT count(*) FROM _interlock_outbox")
            assert total == sum(requests.values()), "a request without its stage's marker"
            windowed: dict[str, Decimal] = {}
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = '_interlock_windows'"
            ).fetchone():
                rows = conn.execute(
                    "SELECT c.plan_id, w.amount, w.window_name FROM _interlock_windows w "
                    "JOIN _interlock_commits c USING (stage_id)"
                ).fetchall()
                bound = value("SELECT count(*) FROM _interlock_windows")
                assert bound == len(rows), "window history without its stage's marker"
                windowed = {
                    str(r[0]): Decimal(str(r[1])) for r in rows if r[2] == "refunds_per_agent"
                }
            return cls(
                balance=cents(value("SELECT balance FROM accounts WHERE id = 100")),
                qty=int(value("SELECT qty FROM order_items WHERE id = 5000")),
                globex=cents(value("SELECT balance FROM accounts WHERE id = 200")),
                refunds={
                    int(r[0]): cents(r[1])
                    for r in conn.execute("SELECT id, amount FROM refunds WHERE id >= 9100")
                },
                markers=frozenset(
                    str(r[0]) for r in conn.execute("SELECT stage_id FROM _interlock_commits")
                ),
                outbox=frozenset(requests),
                windowed=windowed,
            )

    @classmethod
    def after(cls, committed: Iterable[Refund], markers: Iterable[str]) -> Books:
        """The books if exactly ``committed`` committed, each exactly once,
        and each committed plan's email is in the outbox exactly once."""
        done = list(committed)
        return cls(
            balance=Decimal("500.00") + sum((r.amount for r in done), Decimal(0)),
            qty=2 + len(done),
            globex=Decimal("900.00"),
            refunds={r.refund_id: r.amount for r in done},
            markers=frozenset(markers),
            outbox=frozenset(r.plan_id for r in done),
            windowed={r.plan_id: r.amount for r in done},
        )


# --------------------------------------------------------------------------
# the environment
# --------------------------------------------------------------------------


@dataclass
class Restarted:
    chain: EscrowChain
    governor: BudgetManager
    engine: EscrowEngine

    def close(self) -> None:
        self.chain.close()
        self.governor.close()


@dataclass
class Crash:
    workdir: Path
    children: list[Child] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.database = build_sqlite_back_office(self.workdir / "back_office.db")
        install_sqlite_journal(self.database, specs(*OBSERVED))
        install_sqlite_outbox(self.database, TEST_SINKS)
        with BudgetManager.open_sqlite(str(self.ledger)) as governor:
            governor.open_root(SCOPE, "1000")

    @property
    def chain(self) -> Path:
        return self.workdir / "escrow.jsonl"

    @property
    def ledger(self) -> Path:
        return self.workdir / "governor.db"

    def start(self, plans: Sequence[Refund], *, kill: dict[str, object] | None = None) -> Child:
        scenario = {
            "database": self.database,
            "chain": str(self.chain),
            "ledger": str(self.ledger),
            "recover": True,
            "plans": [p.to_json() for p in plans],
            "kill": kill or {},
        }
        child = Child(scenario, self.workdir, len(self.children), module="tests.sqlite_stage_child")
        self.children.append(child)
        return child

    def start_relay(self, sink: FakeSink, number: int) -> Child:
        scenario = {
            "store": "sqlite",
            "dsn": self.database,
            "ledger": str(self.ledger),
            "sinks": {"mail": sink.url},
            "relay_id": f"relay-{number}",
            "key": RELAY_SEED.hex(),
            "lease": 1.5,
            "timeout": 0.5,
            "batch": 2,
            "kill_at": "",
            "message": "",
            "idle_rounds": 10_000,
        }
        child = Child(scenario, self.workdir, len(self.children), module="tests.relay_child")
        self.children.append(child)
        return child

    def restart(self) -> Restarted:
        """Open what a restarted process opens. Each open would fail if the
        dead process's lock on its file had outlived it."""
        chain = EscrowChain(self.chain)
        governor = BudgetManager.open_sqlite(str(self.ledger))
        engine = EscrowEngine(
            SqliteSubstrate(
                self.database, tables=specs(*OBSERVED), acknowledge_cascades=ACKNOWLEDGED
            ),
            checkers=checkers(),
            chain=chain,
            anchor=LedgerAnchor(governed=governor, same_transaction=False),
            settle_cost="0.25",
            sinks=SinkRegistry(TEST_SINKS),
            windows=windows(),
        )
        return Restarted(chain, governor, engine)

    def deliver(self, sink: FakeSink) -> None:
        """A relay that outlived them all: run until nothing is left to send."""
        relay = Relay(
            SqliteOutboxStore(self.database),
            adapters={"mail": HttpAdapter(sink.url, routes=ROUTES["mail"])},
            breaker=NoBreaker(),
            relay_id="survivor",
            lease=timedelta(seconds=5),
            timeout=timedelta(seconds=2),
            signer=relay_signer(),
        )
        try:
            for _ in range(500):
                if relay.run_once(limit=50).claimed == 0 and not self.unsettled():
                    return
                time.sleep(0.02)
            raise AssertionError("the outbox did not settle")
        finally:
            relay.close()

    def unsettled(self) -> int:
        with closing(read(self.database)) as conn:
            row = conn.execute(
                "SELECT count(*) FROM _interlock_outbox_state "
                "WHERE state IN ('pending', 'leased', 'held')"
            ).fetchone()
            return int(row[0])

    def states(self) -> dict[str, int]:
        with closing(read(self.database)) as conn:
            return dict(
                conn.execute(
                    "SELECT state, count(*) FROM _interlock_outbox_state GROUP BY state"
                ).fetchall()
            )

    def cleanup(self) -> None:
        for child in self.children:
            if child.process.poll() is None:
                child.kill()


@pytest.fixture
def crash(tmp_path: Path) -> Iterator[Crash]:
    env = Crash(tmp_path)
    try:
        yield env
    finally:
        env.cleanup()


# --------------------------------------------------------------------------
# what every recovered history must satisfy
# --------------------------------------------------------------------------


def check_history(env: Crash, opened: Restarted, plans: Iterable[Refund]) -> set[str]:
    """Check the recovered history against the file, and return the plans
    that committed."""
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
    assert Books.read(env.database) == Books.after([by_id[p] for p in committed], markers)
    assert reconcile_sqlite(env.database, specs(*OBSERVED), records).clean

    opened.governor.verify_integrity()
    heads = {r.record_hash[:16] for r in records}
    for entry in opened.governor.audit_trail():
        if entry.memo.startswith("interlock:"):
            assert entry.memo.removeprefix("interlock:") in heads, entry

    store = SqliteOutboxStore(env.database)
    try:
        assert verify_delivery_log(store) == ()
    finally:
        store.close()
    return committed


def interruptions(records: Sequence[EscrowRecord]) -> int:
    """How many stages a kill interrupted: opened and never ended, or ended
    only by recovery."""
    opened = {r.stage_id for r in records if r.record_type is RecordType.STAGE_OPENED}
    ended = {r.stage_id for r in records if r.record_type in (CO, AB)}
    recovered = sum(1 for r in records if r.note.startswith("recovered:"))
    return len(opened - ended) + recovered


def stage_records(records: Sequence[EscrowRecord], plan_id: str) -> list[RecordType]:
    return [r.record_type for r in records if r.plan_id == plan_id]


# --------------------------------------------------------------------------
# a kill at each point of the commit path
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Point:
    at: str
    effect: int = 0
    committed: bool = False
    """The stage's transaction committed before the kill."""
    holds_lock: bool = True
    """The child holds the stage's write lock at the kill point."""

    @property
    def id(self) -> str:
        return f"{self.at}-{self.effect}" if self.effect else self.at


POINTS = (
    Point("apply", effect=1),
    Point("apply", effect=4),
    Point("intent"),
    Point("marked"),
    Point("committed", committed=True, holds_lock=False),
    Point("recorded", committed=True, holds_lock=False),
)


@pytest.mark.parametrize("point", POINTS, ids=lambda p: p.id)
def test_a_kill_at_each_point_of_the_commit_path_is_recovered_exactly(
    crash: Crash, point: Point
) -> None:
    first, second = refund(1), refund(2, "4.50")
    child = crash.start(
        [first, second],
        kill={"at": point.at, "plan": second.plan_id, "effect": point.effect},
    )
    stopped = child.wait_for("stopped")
    assert stopped.at == point.at

    # The child is alive, at its point. From outside: the first plan is
    # there, whole; the second is there exactly when its COMMIT returned.
    seen = Books.read(crash.database)
    assert seen.outbox == ({first.plan_id, second.plan_id} if point.committed else {first.plan_id})
    assert (second.refund_id in seen.refunds) is point.committed
    if point.holds_lock:
        # A relay can lease nothing while a stage holds the file's write lock.
        impatient = SqliteOutboxStore(crash.database, busy_seconds=0.2)
        try:
            with pytest.raises(SubstrateUnavailableError, match="locked"):
                impatient.claim("impatient", timedelta(seconds=5), 10, ["mail"], 0.0)
        finally:
            impatient.close()
    child.kill()

    opened = crash.restart()
    try:
        recovered = opened.engine.recover()
        committed = check_history(crash, opened, [first, second])
        records = opened.chain.records()
    finally:
        opened.close()
    assert committed == ({first.plan_id, second.plan_id} if point.committed else {first.plan_id})
    history = stage_records(records, second.plan_id)
    if point.at in ("intent", "marked", "committed"):
        # The commit intent was on disk: recovery put it to the marker.
        (resolution,) = recovered
        assert resolution.record_type is (CO if point.committed else AB)
        assert "recovered:" in resolution.note
        assert history[-2:] == [CI, resolution.record_type]
    else:
        assert recovered == ()
        assert history[-1:] == ([CO] if point.committed else [history[-1]])
        assert (CI in history) is point.committed

    sink = FakeSink()
    try:
        crash.deliver(sink)
        assert crash.states() == {"delivered": len(committed)}
        assert set(sink.effects) == {key(p) for p in committed}
        assert all(n == 1 for n in sink.effects.values())
    finally:
        sink.close()


def test_a_kill_while_sqlite_commits_is_resolved_as_the_file_decided(crash: Crash) -> None:
    """The parent kills the child the moment it says COMMIT is running.
    Whether the commit frame reached the WAL is the file's to say; the chain
    must agree with it, and the outbox with the marker."""
    plans = [refund(n) for n in range(1, 4)]
    child = crash.start(plans, kill={"at": "commit", "plan": plans[1].plan_id})
    child.wait_for("committing")
    child.kill()
    opened = crash.restart()
    try:
        opened.engine.recover()
        committed = check_history(crash, opened, plans)
    finally:
        opened.close()
    assert plans[0].plan_id in committed and plans[2].plan_id not in committed


# --------------------------------------------------------------------------
# kills at random instants, an engine and a relay contending for the file
# --------------------------------------------------------------------------


def test_an_engine_and_a_relay_killed_at_random_instants_never_break_the_history(
    crash: Crash,
) -> None:
    """Two processes write the one file: an engine committing refunds and
    their emails, and a relay delivering them through a sink that fails,
    drops connections and hangs at random. Both are killed wherever they
    happen to be, again and again. After every round the recovered history
    must hold exactly, and the sink must have acted only on committed plans'
    emails; in the end every committed email is delivered, once.

    Most of a plan's time is spent outside its stage (the chain, the ledger),
    so a random kill lands inside one only now and then. The soak runs at
    least ``INTERLOCK_CRASH_ROUNDS`` rounds, and on until kills have cut
    stages and calls in flight, so that it always proves what it claims.
    ``INTERLOCK_CRASH_SEED`` reruns a failure."""
    rng = random.Random(SEED)  # noqa: S311 - kill instants, not secrets
    sink = FakeSink()

    def chaos() -> tuple[Any, ...]:
        return rng.choices([OK, status(503), DROP, hang(0.6)], weights=[60, 15, 10, 15])[0]

    sink.chaos = chaos
    plans: list[Refund] = []
    committed: set[str] = set()
    interrupted = cut = round_ = 0
    try:
        while round_ < ROUNDS or ((interrupted < 2 or cut < 1) and round_ < MAX_ROUNDS):
            batch = [
                refund(
                    round_ * 1000 + i,
                    f"{rng.randint(1, 9)}.{rng.randint(0, 99):02d}",
                    globex=i % 5 == 4,
                )
                for i in range(PLANS)
            ]
            plans += batch
            engine = crash.start(batch)
            relay = crash.start_relay(sink, round_)
            engine.wait_for("started")
            relay.wait_for("started")
            time.sleep(rng.uniform(0.1, 1.2))
            for child in (engine, relay):
                child.kill()
            opened = crash.restart()
            try:
                opened.engine.recover()
                now = check_history(crash, opened, plans)
                interrupted = interruptions(opened.chain.records())
            finally:
                opened.close()
            assert committed <= now, f"seed {SEED} round {round_}: a committed plan vanished"
            committed = now
            acted = set(sink.effects)
            assert acted <= {key(p) for p in committed}, (
                f"seed {SEED} round {round_}: the sink acted on an uncommitted plan's email"
            )
            cut = calls_cut(crash.database)
            round_ += 1
        assert committed, f"seed {SEED}: no plan ever committed; the kills came too early"
        assert interrupted >= 2, f"seed {SEED}: {round_} rounds, {interrupted} stages cut"
        assert cut >= 1, f"seed {SEED}: {round_} rounds, and no kill landed mid-call"

        sink.chaos = None
        time.sleep(1.8)  # the dead relays' leases run out
        crash.deliver(sink)
        assert crash.states() == {"delivered": len(committed)}
        assert set(sink.effects) == {key(p) for p in committed}
        assert all(n == 1 for n in sink.effects.values()), "mail honours its keys: one effect"
        store = SqliteOutboxStore(crash.database)
        try:
            assert verify_delivery_log(store) == ()
        finally:
            store.close()
    finally:
        sink.close()


def calls_cut(path: str) -> int:
    """Calls a kill cut off in flight: started, and with no outcome, or
    declared lost by the relay that took the message over."""
    with closing(read(path)) as conn:
        rows = conn.execute(
            "SELECT message_id, attempt, event FROM _interlock_outbox_attempts "
            "WHERE attempt IS NOT NULL"
        ).fetchall()
    started = {(m, a) for m, a, e in rows if e == "sending"}
    ended = {(m, a) for m, a, e in rows if e in OUTCOMES}
    lost = {(m, a) for m, a, e in rows if e == "lost"}
    return len((started - ended) | lost)
