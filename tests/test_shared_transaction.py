"""Same-transaction mode: claim and settle.

The governor is an AgentGov ledger shared through PostgreSQL, in the same
database as the back office. With ``LedgerAnchor(same_transaction=True)`` a
plan's hold is placed before its stage opens; at commit the governor joins
the stage's transaction, checks the breaker under the ledger's writer lock
taken inside it, and records a settlement claim there, which commits with the
effects and the commit marker, or not at all; after the commit the claim is
redeemed into the chain. ``test_crash_consistency.py`` kills processes at
every step of that; this file pins the behaviour of a process that lives:

- a committed plan's settlement names its commit intent, and its claim rode
  its COMMIT;
- a ledger commit by another governor during the stage conflicts with
  nothing: the claim reads nothing of the chain, so the plan commits;
- a halt refuses the commit; a cost the scope cannot pay refuses the plan
  before it stages, and the trip is recorded durably;
- nothing an agent's statement can do writes the ledger or claims anything,
  although the stage's role may execute the claim function;
- engines racing each other and a governor metering the ledger continuously
  all commit, and never leave effects without their settlement, or a
  settlement without its effects.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable, Iterator
from decimal import Decimal
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")
from agentgov import BudgetManager  # noqa: E402
from agentgov.core import EntryType, LedgerEntry  # noqa: E402
from agentgov.postgres import PostgresStore  # noqa: E402

from interlock import (  # noqa: E402
    EscrowChain,
    EscrowEngine,
    LedgerAnchor,
    PlanBuilder,
    PostgresSubstrate,
    SqliteSubstrate,
    StageState,
    TableSpec,
)
from interlock.chain import RecordType  # noqa: E402
from interlock.exceptions import (  # noqa: E402
    ForbiddenStatementError,
    InterlockError,
    ScopeHaltedError,
    StageConflictError,
)
from interlock.types import EffectDiff, EffectPlan, StageHandle  # noqa: E402
from tests.conftest import OBSERVED, Pg  # noqa: E402
from tests.crash_child import ACKNOWLEDGED, SCOPE, Refund, checkers  # noqa: E402
from tests.schemas import specs  # noqa: E402

SETTLE = Decimal("0.25")


def refund(n: int, amount: str = "3.00", *, globex: bool = False) -> Refund:
    return Refund(f"refund-{n:04d}", 9100 + n, Decimal(amount), globex=globex)


@pytest.fixture
def ledger(pg: Pg) -> Iterator[BudgetManager]:
    """A shared ledger in the back office's own database, its root funded, and
    the stage role granted joined writes (and nothing else on the ledger)."""
    gov = BudgetManager.open_postgres(pg.admin)
    try:
        gov.open_root(SCOPE, "100.00")
        store = gov.store
        assert isinstance(store, PostgresStore)
        store.grant_join(pg.role)
        yield gov
    finally:
        gov.close()


class Hooked(PostgresSubstrate):
    """A substrate that runs ``during`` once the stage's snapshot is taken:
    what another process does while this plan is staged."""

    __slots__ = ("during",)

    def __init__(self, dsn: str, during: Callable[[], None] | None = None) -> None:
        super().__init__(dsn, tables=specs(*OBSERVED), acknowledge_cascades=ACKNOWLEDGED)
        self.during = during

    def diff(self, handle: StageHandle) -> EffectDiff:
        if self.during is not None:
            during, self.during = self.during, None
            during()
        return super().diff(handle)


def engine(pg: Pg, gov: BudgetManager, *, during: Callable[[], None] | None = None) -> EscrowEngine:
    return EscrowEngine(
        Hooked(pg.agent, during),
        checkers=checkers(),
        chain=EscrowChain(),
        anchor=LedgerAnchor(governed=gov, same_transaction=True),
        settle_cost=SETTLE,
    )


def elsewhere(pg: Pg, act: Callable[[BudgetManager], Any]) -> Callable[[], None]:
    """``act`` on the shared ledger through another governor, as another
    process would."""

    def run() -> None:
        with BudgetManager.open_postgres(pg.admin) as other:
            act(other)

    return run


def settled(gov: BudgetManager) -> list[LedgerEntry]:
    gov.refresh()
    return [e for e in gov.audit_trail(SCOPE) if e.entry_type is EntryType.SPEND]


def books(pg: Pg) -> tuple[Decimal, frozenset[int], int]:
    """Account 100's balance, the refund rows, and the stage markers."""
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        balance = conn.execute("SELECT balance FROM accounts WHERE id = 100").fetchone()
        refunds = conn.execute("SELECT id FROM refunds WHERE id >= 9100").fetchall()
        markers = conn.execute("SELECT count(*) FROM interlock.stages").fetchone()
    assert balance is not None and markers is not None
    return Decimal(balance[0]), frozenset(int(r[0]) for r in refunds), int(markers[0])


# --------------------------------------------------------------------------
# One commit, one settlement
# --------------------------------------------------------------------------


def test_a_committed_plan_claims_in_its_commit_and_settles_after_it(
    pg: Pg, ledger: BudgetManager
) -> None:
    eng = engine(pg, ledger)
    result = eng.execute(refund(0).plan())
    assert result.committed and result.state is StageState.COMMITTED

    records = eng.chain.records()
    (intent,) = [r for r in records if r.record_type is RecordType.COMMIT_INTENT]
    assert "; settlement claimed" in intent.note
    assert intent.note.endswith("; commit marker armed")
    (spend,) = settled(ledger)
    assert spend.amount == SETTLE
    assert spend.memo == f"interlock:{intent.record_hash[:16]}", "names the intent it rode in"
    assert spend.ref is not None, "settled against the hold placed before the stage"
    assert result.anchored_to == spend.entry_hash
    assert ledger.pending_claims() == (), "redeemed right after the commit"
    assert ledger.stale_authorizations(0) == (), "the hold was released by the settlement"
    assert books(pg) == (Decimal("503.00"), frozenset({9100}), 1)
    ledger.verify_integrity()
    eng.chain.verify()


def test_a_refused_plan_is_charged_against_its_hold(pg: Pg, ledger: BudgetManager) -> None:
    """What a plan cost to produce was spent whether or not it committed. A
    refused plan has no claim; its hold is captured after its stage, naming
    its terminal record."""
    eng = engine(pg, ledger)
    result = eng.execute(refund(0, globex=True).plan())
    assert not result.committed
    (spend,) = settled(ledger)
    assert spend.memo == f"interlock:{eng.chain.records()[-1].record_hash[:16]}"
    assert spend.ref is not None
    assert ledger.stale_authorizations(0) == ()
    assert books(pg) == (Decimal("500.00"), frozenset(), 0)


# --------------------------------------------------------------------------
# The ledger moves during the stage: no conflict
# --------------------------------------------------------------------------


def test_a_ledger_commit_during_the_stage_conflicts_with_nothing(
    pg: Pg, ledger: BudgetManager
) -> None:
    """The stage's REPEATABLE READ snapshot predates another governor's
    commit. The claim reads nothing of the chain, so the plan commits, on its
    first attempt, and is settled on the head as it now stands."""
    eng = engine(pg, ledger, during=elsewhere(pg, lambda other: other.spend(SCOPE, "1.00")))
    result = eng.execute(refund(0).plan())
    assert result.committed
    assert [s.amount for s in settled(ledger)] == [Decimal("1.00"), SETTLE]
    assert books(pg) == (Decimal("503.00"), frozenset({9100}), 1)
    ledger.verify_integrity()


def test_a_halt_committed_during_the_stage_refuses_the_commit(
    pg: Pg, ledger: BudgetManager
) -> None:
    """The breaker is read after catching up, under the lock the stage holds
    until it commits: a trip anywhere in the fleet before that point stops it,
    and none can land after it. The plan's reservation, made while the scope
    was live, is captured as any refused plan's is."""
    eng = engine(pg, ledger, during=elsewhere(pg, lambda other: other.trip(SCOPE, "ops halt")))
    result = eng.execute(refund(0).plan())
    assert not result.committed and result.state is StageState.ABORTED
    assert "scope halted" in eng.chain.records()[-1].note
    assert books(pg) == (Decimal("500.00"), frozenset(), 0)
    assert [s.amount for s in settled(ledger)] == [SETTLE]
    assert ledger.pending_claims() == ()


def test_a_scope_that_cannot_pay_is_refused_before_staging_and_trips(
    pg: Pg, ledger: BudgetManager
) -> None:
    """The reservation overdraws the scope: the governor trips, durably, and
    the plan never stages. The chain says it ended before staging."""
    ledger.spend(SCOPE, "99.90")  # 0.10 left; the plan costs 0.25
    eng = engine(pg, ledger)
    with pytest.raises(ScopeHaltedError, match="cannot reserve"):
        eng.execute(refund(0).plan())
    assert [r.record_type for r in eng.chain.records()] == [
        RecordType.PLAN_ADMITTED,
        RecordType.ABORTED,
    ]
    assert "refused before staging" in eng.chain.records()[-1].note
    assert books(pg) == (Decimal("500.00"), frozenset(), 0)
    ledger.refresh()
    trips = [e for e in ledger.audit_trail(SCOPE) if e.entry_type is EntryType.CIRCUIT_TRIPPED]
    assert len(trips) == 1 and "overdraft" in trips[0].memo
    assert ledger.is_halted(SCOPE)
    assert [s.amount for s in settled(ledger)] == [Decimal("99.90")]
    ledger.verify_integrity()


def test_a_stage_that_fails_releases_its_hold(pg: Pg, ledger: BudgetManager) -> None:
    eng = engine(pg, ledger)
    plan = PlanBuilder(SCOPE).update(table="orders", statement="SELECT 1 / 0").build()
    with pytest.raises(InterlockError):
        eng.execute(plan)
    assert ledger.stale_authorizations(0) == ()
    assert settled(ledger) == []


# --------------------------------------------------------------------------
# The agent's statements run as the stage's role, and cannot touch the ledger
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO agentgov.nodes (scope_id, depth, allocated, created_at) "
        "VALUES ('rogue', 0, '1000000', 'now')",
        "INSERT INTO agentgov.claims (claim_id, scope_id, amount, memo) "
        "VALUES (gen_random_uuid(), 'support-agent', '1000', 'forged')",
        "SELECT k FROM agentgov.join_key",
        "SELECT agentgov.claim('\\x00'::bytea, gen_random_uuid(), NULL, 'support-agent', "
        "'1000', 'forged')",
    ],
    ids=["write-a-table", "forge-a-claim-row", "read-the-key", "claim-without-a-token"],
)
def test_no_statement_in_a_plan_can_touch_the_ledger(
    pg: Pg, ledger: BudgetManager, statement: str
) -> None:
    eng = engine(pg, ledger)
    ledger.refresh()
    before = ledger.ledger.head_hash
    plan = PlanBuilder(SCOPE).update(table="orders", statement=statement).build()
    with pytest.raises(ForbiddenStatementError, match="refused by the database"):
        eng.execute(plan)
    assert ledger.pending_claims() == ()
    ledger.refresh()
    assert ledger.stale_authorizations(0) == (), "the failed plan's hold was released"
    assert settled(ledger) == []
    assert before != ledger.ledger.head_hash, "only the hold and its release were written"
    assert books(pg) == (Decimal("500.00"), frozenset(), 0)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_same_transaction_needs_a_ledger_that_can_join(tmp_path: Any) -> None:
    with (
        BudgetManager.open_sqlite(str(tmp_path / "gov.db")) as gov,
        pytest.raises(ValueError, match="open_postgres"),
    ):
        LedgerAnchor(governed=gov, same_transaction=True)
    with pytest.raises(ValueError, match="open_postgres"):
        LedgerAnchor(same_transaction=True)


def test_same_transaction_needs_a_substrate_with_a_transaction_to_join(
    ledger: BudgetManager, tmp_path: Any
) -> None:
    sqlite = SqliteSubstrate(str(tmp_path / "db.sqlite"), tables=[TableSpec("t", columns=["id"])])
    with pytest.raises(ValueError, match="has none to join"):
        EscrowEngine(
            sqlite, checkers=[], anchor=LedgerAnchor(governed=ledger, same_transaction=True)
        )


# --------------------------------------------------------------------------
# Engines racing each other, and a governor metering beside them
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "meter_every", [0.01, 0.0], ids=["metering-100-per-s", "metering-back-to-back"]
)
def test_racing_engines_all_commit_under_a_busy_ledger(
    pg: Pg, ledger: BudgetManager, meter_every: float
) -> None:
    """Four engines, each its own process in all but name (its own governor
    and connections), commit refunds against the same account while a fifth
    governor writes the ledger continuously: a hundred commits a second, then
    back to back. Every plan commits. Conflicts still come from the account's
    row, which the engines race for under REPEATABLE READ, and are retried;
    none comes from the ledger. Whatever interleaves, every stage marker has
    exactly one settlement naming its intent, and no settlement exists
    without one."""
    ledger.open_root("metering", "100.00")
    plans: list[EffectPlan] = [refund(n, "1.00").plan() for n in range(24)]
    work = iter(enumerate(plans))
    lock = threading.Lock()
    outcomes: Counter[str] = Counter()
    stop = threading.Event()

    def next_plan() -> tuple[int, EffectPlan] | None:
        with lock:
            return next(work, None)

    def run_engine() -> None:
        with BudgetManager.open_postgres(pg.admin) as gov:
            eng = engine(pg, gov)
            while (item := next_plan()) is not None:
                _, plan = item
                for attempt in range(200):
                    try:
                        result = eng.execute(plan)
                    except StageConflictError:
                        with lock:
                            outcomes["conflict"] += 1
                        stop.wait(0.001 * (attempt % 8))  # a little jitter, as a caller would
                        continue
                    with lock:
                        outcomes["committed" if result.committed else "refused"] += 1
                    break
                else:  # pragma: no cover - the failure being tested for
                    raise AssertionError(f"{plan.plan_id} never committed")

    def meter() -> None:
        with BudgetManager.open_postgres(pg.admin) as gov:
            while not stop.wait(meter_every):
                gov.spend("metering", "0.01")
                with lock:
                    outcomes["metered"] += 1

    metering = threading.Thread(target=meter)
    metering.start()
    engines = [threading.Thread(target=run_engine) for _ in range(4)]
    for thread in engines:
        thread.start()
    for thread in engines:
        thread.join()
    stop.set()
    metering.join()

    assert outcomes["committed"] == len(plans), outcomes
    balance, refunds, markers = books(pg)
    assert refunds == {9100 + n for n in range(len(plans))}
    assert balance == Decimal("500.00") + len(plans)
    assert markers == len(plans)
    spends = settled(ledger)
    assert len(spends) == markers, "one settlement per committed stage, none without one"
    assert len({s.memo for s in spends}) == len(spends)
    assert sum((s.amount for s in spends), Decimal(0)) == SETTLE * len(plans)
    ledger.verify_integrity()
