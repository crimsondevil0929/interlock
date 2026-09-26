"""Tests for the escrow lifecycle.

The claims under test, in order of how much they matter:

1. A blocked plan leaves the database byte-identical. If this is wrong the
   product is worse than useless, because it advertises safety it lacks.
2. The diff is *measured*, not predicted. A trigger cascade the plan never
   mentioned must appear in the diff.
3. A legitimate plan commits. A gate that blocks everything is not a gate.
4. The chain detects tampering.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from interlock import (
    AdmissionError,
    AgentFeedback,
    BlastRadius,
    ChainIntegrityError,
    ColumnValueGuard,
    CyclicPlanError,
    Effect,
    EffectId,
    EffectKind,
    EffectPlan,
    EscrowChain,
    EscrowEngine,
    PlanError,
    PlanId,
    Severity,
    SqliteSubstrate,
    StageState,
    TableSpec,
    TenantIsolation,
    TruncationGuard,
    default_checkers,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    StageError,
    SubstrateUnavailableError,
)
from interlock.substrate import FORBIDDEN_VERBS, leading_verb
from interlock.types import CommitReceipt, InvariantViolation, StageHandle

SCHEMA = """
CREATE TABLE orders(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, customer INTEGER, total REAL NOT NULL
);
CREATE TABLE order_audit(id INTEGER PRIMARY KEY, order_id INTEGER, note TEXT);
-- A production trigger. No agent plan will ever mention it.
CREATE TRIGGER orders_audit AFTER UPDATE ON orders BEGIN
    INSERT INTO order_audit(order_id, note) VALUES (NEW.id, 'total changed');
END;
"""

TABLES = [
    TableSpec("orders", columns=["id", "tenant", "customer", "total"], tenant_column="tenant"),
    TableSpec("order_audit", columns=["id", "order_id", "note"]),
]


@pytest.fixture
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "prod.db")
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    rows = [
        (1, "acme", 42, 100.0),
        (2, "acme", 42, 200.0),
        (3, "acme", 77, 300.0),
        (4, "globex", 91, 400.0),
        (5, "initech", 12, 500.0),
    ]
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return path


def columns_of(path: str, table: str) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
    finally:
        conn.close()


def totals(path: str) -> list[tuple[int, float]]:
    conn = sqlite3.connect(path)
    try:
        return [(int(r[0]), float(r[1])) for r in conn.execute("SELECT id,total FROM orders")]
    finally:
        conn.close()


def make_plan(*effects: Effect, intent: str = "", scope: str = "agent") -> EffectPlan:
    return EffectPlan(
        plan_id=PlanId(f"plan-{uuid.uuid4().hex[:8]}"),
        scope_id=scope,
        trajectory_id="t1",
        created_at=datetime.now(UTC),
        effects=effects,
        intent=intent,
    )


def engine_for(path: str, **kwargs: object) -> EscrowEngine:
    substrate = SqliteSubstrate(path, tables=TABLES)
    checkers = kwargs.pop(
        "checkers",
        default_checkers(row_limit=5, allowed_tables=["orders", "order_audit"]),
    )
    return EscrowEngine(substrate, checkers=checkers)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# 1. A blocked plan changes nothing
# --------------------------------------------------------------------------


def test_blocked_plan_leaves_the_database_untouched(db: str) -> None:
    before = totals(db)
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 0",
            stated_rows=1,
        ),
        intent="zero every order",
    )
    result = engine_for(db).execute(plan)

    assert not result.committed
    assert result.state is StageState.ABORTED
    # 5 orders zeroed, plus 5 audit rows the schema trigger cascaded: 10 measured.
    assert set(result.blocked_by) == {"blast_radius", "tenant_isolation"}
    assert result.diff is not None and result.diff.blast_radius == 10
    assert totals(db) == before, "rollback failed; the product's central claim is broken"


def test_cross_tenant_plan_is_refused(db: str) -> None:
    before = totals(db)
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = total * 0.9 WHERE id IN (1,4)",
        )
    )
    engine = EscrowEngine(
        SqliteSubstrate(db, tables=TABLES),
        checkers=[TenantIsolation(max_tenants=1)],
    )
    result = engine.execute(plan)
    assert not result.committed
    assert result.blocked_by == ("tenant_isolation",)
    assert result.diff is not None
    assert result.diff.tenant_ids == frozenset({"acme", "globex"})
    assert totals(db) == before


def test_value_guard_catches_an_aggregate_that_every_row_passes(db: str) -> None:
    """Each row stays a valid float. The total collapses. Only the sum sees it."""
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 0 WHERE tenant = 'acme'",
        )
    )
    engine = EscrowEngine(
        SqliteSubstrate(db, tables=TABLES),
        checkers=[ColumnValueGuard("orders", "total", max_drop_fraction=0.25)],
    )
    result = engine.execute(plan)
    assert not result.committed
    assert result.blocked_by == ("column_value_guard:orders.total",)
    assert totals(db) == [(1, 100.0), (2, 200.0), (3, 300.0), (4, 400.0), (5, 500.0)]


# --------------------------------------------------------------------------
# 2. The diff is measured, not predicted
# --------------------------------------------------------------------------


def test_diff_includes_trigger_cascade_the_plan_never_mentioned(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = total * 0.9 WHERE tenant = 'acme'",
            stated_rows=3,
        )
    )
    engine = EscrowEngine(SqliteSubstrate(db, tables=TABLES), checkers=[])
    result = engine.execute(plan)

    assert result.diff is not None
    # Three order rows, plus three audit rows the schema's own trigger wrote.
    assert result.diff.rows_updated == 3
    assert result.diff.rows_inserted == 3
    assert result.diff.blast_radius == 6
    assert result.diff.tables_touched == frozenset({"orders", "order_audit"})
    # The statement reported three. The substrate measured six.
    assert result.outcomes[0].rows_affected == 3


def test_stated_footprint_reports_the_gap(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = total - 1 WHERE tenant = 'acme'",
            stated_rows=1,
        )
    )
    engine = engine_for(db)
    result = engine.execute(plan)
    assert result.verdict is not None
    gaps = [v for v in result.verdict.violations if v.invariant == "stated_footprint"]
    assert len(gaps) == 1
    assert gaps[0].severity is Severity.ADVISORY
    assert gaps[0].evidence["stated"] == "1"
    assert gaps[0].evidence["measured"] == "6"


def test_before_and_after_images_are_captured(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 111.0 WHERE id = 1",
        )
    )
    engine = EscrowEngine(SqliteSubstrate(db, tables=TABLES), checkers=[])
    result = engine.execute(plan)
    assert result.diff is not None
    order_row = next(d for d in result.diff.deltas if d.table == "orders")
    assert order_row.before is not None and order_row.after is not None
    assert order_row.before["total"] == 100.0
    assert order_row.after["total"] == 111.0
    assert order_row.changed_columns() == ("total",)
    assert order_row.tenant_id == "acme"


# --------------------------------------------------------------------------
# 3. Legitimate work still lands
# --------------------------------------------------------------------------


def test_legitimate_plan_commits(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = total * 0.9 WHERE id = :oid",
            parameters={"oid": 1},
            stated_rows=1,
        ),
        intent="apply a 10% loyalty discount to order 1",
    )
    result = engine_for(db).execute(plan)
    assert result.committed
    assert result.state is StageState.COMMITTED
    assert dict(totals(db))[1] == pytest.approx(90.0)


def test_parameters_are_bound_not_interpolated(db: str) -> None:
    """A parameter carrying SQL is data, not code."""
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET tenant = :t WHERE id = 1",
            parameters={"t": "'; DROP TABLE orders; --"},
        )
    )
    engine = EscrowEngine(SqliteSubstrate(db, tables=TABLES), checkers=[])
    result = engine.execute(plan)
    assert result.committed
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM orders").fetchone()[0] == 5
        assert conn.execute("SELECT tenant FROM orders WHERE id=1").fetchone()[0] == (
            "'; DROP TABLE orders; --"
        )
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 4. Admission and fail-closed behaviour
# --------------------------------------------------------------------------


def test_unobserved_table_is_refused_at_admission(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:secrets",
            statement="UPDATE secrets SET v = 1",
        )
    )
    with pytest.raises(PlanError, match="unobserved"):
        engine_for(db).execute(plan)


def test_dependency_cycle_is_refused(db: str) -> None:
    a = Effect(
        effect_id=EffectId("a"),
        kind=EffectKind.UPDATE,
        target="sqlite:orders",
        statement="UPDATE orders SET total = 1 WHERE id = 1",
        depends_on=(EffectId("b"),),
    )
    b = Effect(
        effect_id=EffectId("b"),
        kind=EffectKind.UPDATE,
        target="sqlite:orders",
        statement="UPDATE orders SET total = 2 WHERE id = 2",
        depends_on=(EffectId("a"),),
    )
    with pytest.raises(CyclicPlanError):
        engine_for(db).execute(make_plan(a, b))


def test_a_checker_that_raises_blocks_rather_than_approves(db: str) -> None:
    class Broken:
        @property
        def name(self) -> str:
            return "broken"

        def check(self, plan: object, diff: object) -> tuple[InvariantViolation, ...]:
            raise RuntimeError("boom")

    before = totals(db)
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 1 WHERE id = 1",
        )
    )
    engine = EscrowEngine(SqliteSubstrate(db, tables=TABLES), checkers=[Broken()])
    result = engine.execute(plan)
    assert not result.committed
    assert result.blocked_by == ("broken",)
    assert totals(db) == before


def test_truncated_diff_is_refused(db: str) -> None:
    substrate = SqliteSubstrate(db, tables=TABLES, max_diff_rows=2)
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = total - 1",
        )
    )
    engine = EscrowEngine(substrate, checkers=[TruncationGuard()])
    result = engine.execute(plan)
    assert result.diff is not None and result.diff.truncated
    assert result.blocked_by == ("truncation_guard",)


def test_execute_or_raise_surfaces_the_refusal(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 0",
        )
    )
    with pytest.raises(AdmissionError) as caught:
        engine_for(db).execute_or_raise(plan)
    assert "blast_radius" in str(caught.value) or "limit" in str(caught.value)


def test_every_checker_runs_so_a_refusal_lists_every_reason(db: str) -> None:
    plan = make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 0",
        )
    )
    engine = EscrowEngine(
        SqliteSubstrate(db, tables=TABLES),
        checkers=[
            BlastRadius(2),
            TenantIsolation(1),
            ColumnValueGuard("orders", "total", max_drop_fraction=0.1),
        ],
    )
    result = engine.execute(plan)
    assert set(result.blocked_by) == {
        "blast_radius",
        "tenant_isolation",
        "column_value_guard:orders.total",
    }


# --------------------------------------------------------------------------
# 5. The chain
# --------------------------------------------------------------------------


def test_chain_records_the_whole_lifecycle(db: str) -> None:
    engine = engine_for(db)
    engine.execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total = total - 1 WHERE id = 1",
            )
        )
    )
    kinds = [r.record_type for r in engine.chain.records()]
    assert kinds == [
        RecordType.PLAN_ADMITTED,
        RecordType.STAGE_OPENED,
        RecordType.DIFF_COMPUTED,
        RecordType.VERDICT,
        RecordType.COMMIT_INTENT,
        RecordType.COMMITTED,
    ]
    assert engine.chain.unresolved_intents() == (), "the intent was resolved"
    engine.chain.verify()


def test_chain_detects_an_edited_record() -> None:
    chain = EscrowChain()
    chain.append(RecordType.PLAN_ADMITTED, plan_id=PlanId("p1"), payload_hash="a" * 64)
    chain.append(RecordType.VERDICT, plan_id=PlanId("p1"), payload_hash="b" * 64)
    chain.verify()

    # Records are frozen, so tampering means substituting a rebuilt one. That
    # is exactly what an attacker with file access would do.
    records = list(chain.records())
    tampered = replace(records[0], note="after the fact")
    chain._records[0] = tampered
    with pytest.raises(ChainIntegrityError, match="contents were edited"):
        chain.verify()


def test_chain_round_trips_through_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "chain.jsonl"
    chain = EscrowChain(path)
    for index in range(3):
        chain.append(RecordType.VERDICT, plan_id=PlanId(f"p{index}"), payload_hash=f"{index:064d}")
    reloaded = EscrowChain.load(path)
    assert len(reloaded) == 3
    assert reloaded.head_hash == chain.head_hash
    reloaded.verify()


def test_anchor_monotonicity_rejects_a_regression() -> None:
    chain = EscrowChain()
    chain.append(
        RecordType.VERDICT,
        plan_id=PlanId("p1"),
        payload_hash="a" * 64,
        anchored=True,
        agentgov_sequence=10,
    )
    chain.append(
        RecordType.VERDICT,
        plan_id=PlanId("p2"),
        payload_hash="b" * 64,
        anchored=True,
        agentgov_sequence=4,
    )
    chain.verify()  # the links are fine
    with pytest.raises(ChainIntegrityError, match="regressed"):
        chain.verify_anchors()


# --------------------------------------------------------------------------
# 5. Configuration that would silently disable a check
# --------------------------------------------------------------------------


def test_tenant_column_missing_from_columns_is_refused_at_construction() -> None:
    """A tenant column absent from the captured image makes TenantIsolation inert.

    The label is read back out of the before/after JSON, so if it was never
    captured every RowDelta.tenant_id is None, tenant_count is 0, and
    TenantIsolation(1) passes a plan spanning any number of tenants. Fail at
    construction rather than adjudicate against a measurement that cannot see
    the axis it is checking.
    """
    with pytest.raises(ValueError, match="must also be listed in columns"):
        TableSpec("orders", columns=["id", "total"], tenant_column="tenant")


def test_tenant_column_present_is_accepted() -> None:
    spec = TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")
    assert spec.tenant_column == "tenant"


def test_non_ascii_identifiers_are_refused() -> None:
    """str.isalnum accepts non-ASCII letters; the trigger DDL should not."""
    with pytest.raises(ValueError, match="unsafe SQL identifier"):
        TableSpec("ordérs", columns=["id"])
    with pytest.raises(ValueError, match="unsafe SQL identifier"):
        TableSpec("orders", columns=["id", "tötal"])


# --------------------------------------------------------------------------
# 6. Gaps that are documented rather than closed
#
# These pin current behaviour so that closing any of them is a deliberate
# change with a failing test, not a silent one. Each is listed under "What
# this is not yet a boundary against" in README.md.
# --------------------------------------------------------------------------


def test_statement_writing_an_unobserved_table_is_denied(db: str) -> None:
    """The statement is gated, not the label the agent wrote on it.

    ``admit()`` reads ``Effect.target``, which the agent supplies. The
    statement below labels itself ``orders`` and writes somewhere else. The
    substrate's authorizer denies the write inside SQLite at prepare time, so
    it never executes and never reaches the diff as an empty measurement that
    every checker would pass.
    """
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE unobserved(id INTEGER PRIMARY KEY, v TEXT);")
    conn.execute("INSERT INTO unobserved VALUES (1,'before')")
    conn.commit()
    conn.close()

    with pytest.raises(ForbiddenStatementError) as caught:
        engine_for(db).execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",  # the label says orders
                    statement="UPDATE unobserved SET v='after'",  # the statement does not
                )
            )
        )
    assert "unobserved" in str(caught.value)

    conn = sqlite3.connect(db)
    written = conn.execute("SELECT v FROM unobserved WHERE id=1").fetchone()[0]
    conn.close()
    assert written == "before", "the denied write must not have landed"


def test_unobserved_write_still_commits_when_enforcement_is_off(db: str) -> None:
    """The escape hatch restores v0.1.0 behaviour, and it is genuinely unsafe.

    Kept as a test because ``enforce_table_access=False`` is a documented
    migration path: this pins exactly what a caller gives up by taking it.
    """
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE unobserved(id INTEGER PRIMARY KEY, v TEXT);")
    conn.execute("INSERT INTO unobserved VALUES (1,'before')")
    conn.commit()
    conn.close()

    substrate = SqliteSubstrate(db, tables=TABLES, enforce_table_access=False)
    engine = EscrowEngine(
        substrate,
        checkers=default_checkers(row_limit=5, allowed_tables=["orders", "order_audit"]),
    )
    result = engine.execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE unobserved SET v='after'",
            )
        )
    )

    assert result.committed
    assert result.diff is not None
    assert result.diff.blast_radius == 0
    assert result.diff.tables_touched == frozenset()

    conn = sqlite3.connect(db)
    written = conn.execute("SELECT v FROM unobserved WHERE id=1").fetchone()[0]
    conn.close()
    assert written == "after", "the write landed and the diff did not see it"


def test_ddl_declared_as_dml_is_refused_at_admission(db: str) -> None:
    """The statement is checked, not the kind the agent declared.

    NoSchemaChange reads Effect.kind. DDL fires no row triggers, so the diff
    is empty and every diff-reading checker passes on nothing. Before the
    substrate vetted the statement text this committed and changed the schema.
    """
    before = columns_of(db, "orders")

    with pytest.raises(ForbiddenStatementError, match="ALTER is not stageable"):
        engine_for(db).execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,  # not DDL, as far as the checker knows
                    target="sqlite:orders",
                    statement="ALTER TABLE orders ADD COLUMN injected TEXT",
                )
            )
        )

    assert columns_of(db, "orders") == before, "the schema is untouched"


def test_blast_radius_counts_mutations_not_distinct_rows(db: str) -> None:
    """One row updated twice in a plan contributes 2, so the limit is conservative."""
    result = engine_for(db, checkers=[BlastRadius(50)]).execute(
        make_plan(
            Effect(
                effect_id=EffectId("a"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total=1 WHERE id=1",
            ),
            Effect(
                effect_id=EffectId("b"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total=2 WHERE id=1",
                depends_on=(EffectId("a"),),
            ),
        )
    )

    assert result.diff is not None
    orders = [d for d in result.diff.deltas if d.table == "orders"]
    assert len(orders) == 2
    assert len({(d.table, d.primary_key) for d in orders}) == 1


def test_column_value_guard_does_not_bound_inflation(db: str) -> None:
    """ColumnValueGuard fires on a fall in the total. A rise passes."""
    result = engine_for(
        db, checkers=[ColumnValueGuard("orders", "total", max_drop_fraction=0.30)]
    ).execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total=total*1000",
            )
        )
    )

    assert result.committed
    assert result.diff is not None
    before, after = result.diff.column_total("orders", "total")
    assert after > before * 900


def test_committed_record_is_not_write_ahead(db: str, tmp_path: Path) -> None:
    """A crash between substrate.commit() and the chain append loses the record.

    Pins the ordering documented in engine.py: the effect is durable before
    the COMMITTED record exists. Closing this needs an intent record written
    before the commit plus a startup scan.
    """

    class CrashAfterCommit(SqliteSubstrate):
        def commit(self, handle: StageHandle) -> CommitReceipt:
            super().commit(handle)
            raise KeyboardInterrupt("killed after COMMIT")

    chain_path = tmp_path / "chain.jsonl"
    engine = EscrowEngine(
        CrashAfterCommit(db, tables=TABLES),
        checkers=[BlastRadius(50)],
        chain=EscrowChain(chain_path),
    )
    with pytest.raises(KeyboardInterrupt):
        engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total=777 WHERE id=1",
                )
            )
        )

    assert (1, 777.0) in totals(db), "the effect is durable"
    kinds = [r.record_type for r in EscrowChain.load(chain_path).records()]
    assert RecordType.COMMITTED not in kinds, "and there is no record that it committed"


def test_effect_labelled_for_another_substrate_is_refused(db: str) -> None:
    """Effect.target carries a substrate id that was parsed and never checked.

    apply() only ever uses the substrate the engine was built with, so an
    effect labelled ``stripe:orders`` was being executed against SQLite.
    """
    with pytest.raises(PlanError, match="but this engine holds"):
        engine_for(db).execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="stripe:orders",
                    statement="UPDATE orders SET total=0",
                )
            )
        )


def test_unprefixed_target_still_admits(db: str) -> None:
    """A bare table name carries no substrate id and is not treated as foreign."""
    result = engine_for(db, checkers=[BlastRadius(50)]).execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="orders",
                statement="UPDATE orders SET total=1 WHERE id=1",
            )
        )
    )
    assert result.committed


# --------------------------------------------------------------------------
# 7. Reverse anchoring runs after commit, so it must not throw from there
# --------------------------------------------------------------------------


def test_default_settle_cost_writes_a_free_reverse_anchor(db: str, tmp_path: Path) -> None:
    """EscrowEngine's default settle_cost is "0", which now anchors for free.

    Before AgentGov 0.1.2 a reverse anchor could only ride on a real
    authorize/capture pair, so the default meant forward anchoring only. Now a
    zero cost writes a zero-value ANCHOR entry and no money moves.
    """
    from agentgov import BudgetManager, money
    from agentgov.core import EntryType

    from interlock import LedgerAnchor

    gov = BudgetManager.open_sqlite(str(tmp_path / "gov.db"))
    try:
        gov.open_root("agent", money("5.00"))
        anchor = LedgerAnchor(governed=gov)
        engine = EscrowEngine(
            SqliteSubstrate(db, tables=TABLES),
            checkers=[BlastRadius(50)],
            anchor=anchor,
        )
        result = engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total=42 WHERE id=1",
                ),
                scope="agent",
            )
        )
        assert result.committed
        assert (1, 42.0) in totals(db)
        (entry,) = anchor.find_reverse_anchors()
        assert entry.entry_type is EntryType.ANCHOR
        assert result.anchored_to == entry.entry_hash
        assert entry.memo == f"interlock:{result.chain_head[:16]}"
        assert gov.available("agent") == money("5.00"), "the anchor cost nothing"
        gov.verify_integrity()
    finally:
        gov.close()


def test_a_negative_settle_cost_is_refused_before_anything_is_staged(db: str) -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        EscrowEngine(SqliteSubstrate(db, tables=TABLES), checkers=[], settle_cost="-0.01")

    engine = engine_for(db, checkers=[BlastRadius(50)])
    with pytest.raises(PlanError, match="cannot be negative"):
        engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total=42 WHERE id=1",
                )
            ),
            settle_cost="-1",
        )
    assert len(engine.chain) == 0 and (1, 42.0) not in totals(db)


def test_a_positive_settle_cost_writes_the_reverse_anchor(db: str, tmp_path: Path) -> None:
    from agentgov import BudgetManager, money

    from interlock import LedgerAnchor

    gov = BudgetManager.open_sqlite(str(tmp_path / "gov.db"))
    try:
        gov.open_root("agent", money("5.00"))
        anchor = LedgerAnchor(governed=gov)
        engine = EscrowEngine(
            SqliteSubstrate(db, tables=TABLES),
            checkers=[BlastRadius(50)],
            anchor=anchor,
            settle_cost="0.01",
        )
        result = engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total=42 WHERE id=1",
                ),
                scope="agent",
            )
        )
        assert result.committed
        assert result.anchored_to != ""

        anchors = anchor.find_reverse_anchors()
        assert len(anchors) == 1
        assert anchors[0].memo == f"interlock:{result.chain_head[:16]}"
        gov.verify_integrity()
    finally:
        gov.close()


# --------------------------------------------------------------------------
# 8. The statement is vetted, not the kind the agent declared
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE orders ADD COLUMN injected TEXT",
        "DROP TABLE orders",
        "CREATE TABLE smuggled (id INTEGER)",
        "CREATE INDEX idx_orders_total ON orders(total)",
        "VACUUM",
        "PRAGMA foreign_keys=OFF",
        "ATTACH DATABASE '/tmp/elsewhere.db' AS side",
        "REINDEX orders",
    ],
)
def test_forbidden_statements_are_refused_whatever_kind_is_declared(
    db: str, statement: str
) -> None:
    """Every one of these is declared kind=UPDATE, which is a lie the agent
    is free to tell. The refusal reads the SQL."""
    with pytest.raises(ForbiddenStatementError):
        engine_for(db).execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement=statement,
                )
            )
        )


def test_a_forbidden_statement_never_opens_a_stage(db: str) -> None:
    """Refused at admission, so no connection is bound and no write lock taken."""
    engine = engine_for(db)
    with pytest.raises(ForbiddenStatementError):
        engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="DROP TABLE orders",
                )
            )
        )

    kinds = [r.record_type for r in engine.chain.records()]
    assert RecordType.STAGE_OPENED not in kinds

    conn = sqlite3.connect(db, timeout=2.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("ROLLBACK")
    finally:
        conn.close()


def test_a_forbidden_statement_is_refused_by_the_substrate_directly(db: str) -> None:
    """A caller that skips the engine must not get a second answer."""
    substrate = SqliteSubstrate(db, tables=TABLES)
    effect = Effect(
        effect_id=EffectId("e1"),
        kind=EffectKind.UPDATE,
        target="sqlite:orders",
        statement="DROP TABLE orders",
    )
    assert substrate.reject_reason(effect) is not None

    plan = make_plan(effect)
    handle = substrate.open(plan)
    try:
        with pytest.raises(ForbiddenStatementError):
            substrate.apply(handle, effect)
    finally:
        substrate.close(handle)

    assert columns_of(db, "orders") == ["id", "tenant", "customer", "total"]


def test_comments_do_not_hide_the_verb(db: str) -> None:
    """`/* x */ DROP ...` and `-- x\\nDROP ...` are valid SQL.

    A prefix check that does not strip comments reads them as having no verb.
    """
    for statement in (
        "/* routine maintenance */ DROP TABLE orders",
        "-- approved in ticket 4471\nDROP TABLE orders",
        "   \n\t DROP TABLE orders",
    ):
        assert leading_verb(statement) == "drop"
        with pytest.raises(ForbiddenStatementError):
            engine_for(db).execute(
                make_plan(
                    Effect(
                        effect_id=EffectId("e1"),
                        kind=EffectKind.UPDATE,
                        target="sqlite:orders",
                        statement=statement,
                    )
                )
            )


def test_ordinary_dml_is_still_admitted(db: str) -> None:
    """The veto must not be so broad that nothing stages."""
    for verb, statement in (
        ("update", "UPDATE orders SET total = total - 1 WHERE id = 1"),
        ("insert", "INSERT INTO orders (id, tenant, customer, total) VALUES (99,'acme',1,5.0)"),
        ("delete", "DELETE FROM orders WHERE id = 5"),
        ("with", "WITH x AS (SELECT 1) UPDATE orders SET total = 1 WHERE id = 2"),
    ):
        assert leading_verb(statement) == verb
        assert verb not in FORBIDDEN_VERBS


def test_multi_statement_smuggling_is_refused_by_the_driver(db: str) -> None:
    """sqlite3 executes one statement per call, so a trailing DROP cannot ride along."""
    result_error: Exception | None = None
    try:
        engine_for(db).execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total = 1 WHERE id = 1; DROP TABLE orders",
                )
            )
        )
    except Exception as exc:
        result_error = exc

    assert result_error is not None
    assert columns_of(db, "orders"), "the table is still there"


# --------------------------------------------------------------------------
# 9. Write-ahead commit records
# --------------------------------------------------------------------------


def test_a_crash_between_commit_and_the_record_leaves_a_resolvable_intent(
    db: str, tmp_path: Path
) -> None:
    """The window is narrowed from silent to discoverable.

    COMMIT_INTENT lands before the substrate is told to commit, so a crash in
    the window leaves an intent with no terminal record after it. It does not
    say the commit succeeded, only that one was attempted for this plan and
    stage, which is the question recovery has to put to the substrate.
    """

    class CrashAfterCommit(SqliteSubstrate):
        def commit(self, handle: StageHandle) -> CommitReceipt:
            super().commit(handle)
            raise KeyboardInterrupt("killed after COMMIT")

    chain_path = tmp_path / "chain.jsonl"
    engine = EscrowEngine(
        CrashAfterCommit(db, tables=TABLES),
        checkers=[BlastRadius(50)],
        chain=EscrowChain(chain_path),
    )
    with pytest.raises(KeyboardInterrupt):
        engine.execute(
            make_plan(
                Effect(
                    effect_id=EffectId("e1"),
                    kind=EffectKind.UPDATE,
                    target="sqlite:orders",
                    statement="UPDATE orders SET total=777 WHERE id=1",
                ),
                intent="write-ahead probe",
            )
        )

    assert (1, 777.0) in totals(db), "the effect is durable"

    reloaded = EscrowChain.load(chain_path)
    kinds = [r.record_type for r in reloaded.records()]
    assert RecordType.COMMIT_INTENT in kinds
    assert RecordType.COMMITTED not in kinds

    unresolved = reloaded.unresolved_intents()
    assert len(unresolved) == 1
    assert unresolved[0].record_type is RecordType.COMMIT_INTENT
    reloaded.verify()


def test_a_clean_run_leaves_no_unresolved_intent(db: str) -> None:
    engine = engine_for(db, checkers=[BlastRadius(50)])
    engine.execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total = 2 WHERE id = 1",
            )
        )
    )
    assert engine.chain.unresolved_intents() == ()


def test_a_refused_plan_writes_no_commit_intent(db: str) -> None:
    """The intent means 'about to commit'. A rejected plan never gets there."""
    engine = engine_for(db, checkers=[BlastRadius(0)])
    engine.execute(
        make_plan(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="sqlite:orders",
                statement="UPDATE orders SET total = 3 WHERE id = 1",
            )
        )
    )
    kinds = [r.record_type for r in engine.chain.records()]
    assert RecordType.COMMIT_INTENT not in kinds
    assert RecordType.ABORTED in kinds
    assert engine.chain.unresolved_intents() == ()


def _probe_plan() -> EffectPlan:
    return make_plan(
        Effect(
            effect_id=EffectId("e1"),
            kind=EffectKind.UPDATE,
            target="sqlite:orders",
            statement="UPDATE orders SET total = 777 WHERE id = 1",
        ),
        intent="lost commit probe",
    )


class LosesTheAnswer(SqliteSubstrate):
    """Commits, or rolls back, and then reports the answer lost, as a
    connection dropped with COMMIT in flight does."""

    landed = True
    marker: bool | None = None
    """What ``resolve_intent`` says; ``None`` defers to the real marker."""

    def commit(self, handle: StageHandle) -> CommitReceipt:
        if self.landed:
            super().commit(handle)
        else:
            self.abort(handle)
        raise CommitUnsettledError("the connection was lost with COMMIT sent")

    def resolve_intent(self, stage_id: uuid.UUID) -> bool | None:
        if type(self).marker is False:
            raise SubstrateUnavailableError("the database cannot be reached")
        return super().resolve_intent(stage_id) if type(self).marker is None else None


@pytest.mark.parametrize("landed", [True, False])
def test_a_commit_whose_answer_was_lost_is_settled_by_its_marker(db: str, landed: bool) -> None:
    """No answer is not a failure. The marker says whether the stage landed,
    and the engine reports exactly that: committed, or rolled back."""
    substrate = type("Probe", (LosesTheAnswer,), {"landed": landed})(db, tables=TABLES)
    engine = EscrowEngine(substrate, checkers=[BlastRadius(50)])
    if landed:
        result = engine.execute(_probe_plan())
        assert result.committed
        assert "the commit's reply was lost; its commit marker is present" in (
            engine.chain.records()[-1].note
        )
        assert (1, 777.0) in totals(db)
    else:
        with pytest.raises(StageError, match="left no commit marker") as raised:
            engine.execute(_probe_plan())
        assert not isinstance(raised.value, CommitUnsettledError)
        assert engine.chain.records()[-1].record_type is RecordType.ABORTED
        assert (1, 777.0) not in totals(db)
    assert engine.chain.unresolved_intents() == ()


@pytest.mark.parametrize("marker", ["unanswered", "unreachable", "unarmed"])
def test_a_lost_commit_nobody_can_settle_stays_open_for_recovery(
    db: str, marker: str, caplog: pytest.LogCaptureFixture
) -> None:
    """When the marker cannot answer, the engine writes no terminal record at
    all, and tells the agent not to retry: the stage may yet have landed."""
    answers = {"unanswered": True, "unreachable": False, "unarmed": None}
    substrate = type("Probe", (LosesTheAnswer,), {"marker": answers[marker]})(
        db, tables=TABLES, commit_markers=marker != "unarmed"
    )
    engine = EscrowEngine(substrate, checkers=[BlastRadius(50)])
    with pytest.raises(CommitUnsettledError) as raised:
        engine.execute(_probe_plan())
    feedback = raised.value.feedback
    assert isinstance(feedback, AgentFeedback) and not feedback.retryable
    (intent,) = engine.chain.unresolved_intents()
    assert engine.chain.records()[-1] == intent

    caplog.clear()
    if marker == "unarmed":
        assert engine.recover() == ()
        assert "no commit marker was armed" in caplog.text
        return
    type(substrate).marker = True  # the server has still not decided
    assert engine.recover() == ()
    assert "is not settled yet; recovery will ask again" in caplog.text
    assert "no commit marker was armed" not in caplog.text
    type(substrate).marker = None  # it has now: the real marker answers
    (record,) = engine.recover()
    assert record.record_type is RecordType.COMMITTED
    assert record.stage_id == intent.stage_id
