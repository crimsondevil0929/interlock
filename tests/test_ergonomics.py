"""The high-level surface: PlanBuilder, EscrowRuntime, and the exception barrier.

These cover what a caller touches on day one. The primitives they sit on are
covered in ``test_engine.py``; what is asserted here is that the sugar does not
quietly change the guarantees underneath it.
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from pathlib import Path

import pytest
from agentgov import BudgetManager, money

from interlock import (
    BlastRadius,
    EffectKind,
    EscrowRuntime,
    InterlockError,
    PlanBuilder,
    TableSpec,
    TenantDrawdownGuard,
    TenantIsolation,
)
from interlock.exceptions import AnchorError, ForbiddenStatementError, PlanError

SCHEMA = """
CREATE TABLE orders(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, total REAL NOT NULL
);
CREATE TABLE secrets(id INTEGER PRIMARY KEY, v TEXT);
"""

TABLES = [TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")]


@pytest.fixture
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "prod.db")
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO orders VALUES (?,?,?)",
        [(1, "acme", 500.0), (2, "acme", 300.0), (3, "globex", 900.0)],
    )
    conn.execute("INSERT INTO secrets VALUES (1,'before')")
    conn.commit()
    conn.close()
    return path


def runtime_for(path: str, **kwargs: object) -> EscrowRuntime:
    kwargs.setdefault("checkers", [TenantIsolation(1), BlastRadius(8)])
    return EscrowRuntime(path, tables=TABLES, scope_id="agent", **kwargs)  # type: ignore[arg-type]


def total(path: str) -> float:
    conn = sqlite3.connect(path)
    try:
        value: float = conn.execute("SELECT SUM(total) FROM orders").fetchone()[0]
        return value
    finally:
        conn.close()


# -- PlanBuilder ------------------------------------------------------------


def test_builder_mints_ids_and_a_utc_clock() -> None:
    plan = (
        PlanBuilder(scope_id="agent")
        .update(
            table="orders",
            statement="UPDATE orders SET total = :t WHERE id = :i",
            parameters={"t": 1.0, "i": 1},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )
    assert plan.plan_id.startswith("plan-")
    assert plan.trajectory_id.startswith("traj-")
    assert plan.effects[0].effect_id.startswith("eff-")
    assert plan.created_at.tzinfo is not None


def test_builder_chains_effects_sequentially_by_default() -> None:
    builder = PlanBuilder(scope_id="agent")
    builder.update(table="orders", statement="UPDATE orders SET total = 1 WHERE id = 1")
    first = builder.last_effect_id
    builder.update(table="orders", statement="UPDATE orders SET total = 2 WHERE id = 2")
    plan = builder.build()

    assert plan.effects[0].depends_on == ()
    assert plan.effects[1].depends_on == (first,)
    assert [e.effect_id for e in plan.topological_order()] == [
        plan.effects[0].effect_id,
        plan.effects[1].effect_id,
    ]


def test_builder_independent_effects_carry_no_dependency() -> None:
    plan = (
        PlanBuilder(scope_id="agent")
        .update(table="orders", statement="UPDATE orders SET total = 1 WHERE id = 1")
        .update(
            table="orders",
            statement="UPDATE orders SET total = 2 WHERE id = 2",
            independent=True,
        )
        .build()
    )
    assert all(e.depends_on == () for e in plan.effects)


def test_builder_after_names_an_earlier_effect() -> None:
    builder = PlanBuilder(scope_id="agent")
    builder.insert(table="orders", statement="INSERT INTO orders VALUES (9,'acme',1.0)")
    root = builder.last_effect_id
    assert root is not None
    builder.delete(table="orders", statement="DELETE FROM orders WHERE id = 9", after=[root])
    assert builder.build().effects[1].depends_on == (root,)


def test_builder_rejects_unknown_dependency() -> None:
    from interlock import EffectId

    builder = PlanBuilder(scope_id="agent")
    with pytest.raises(PlanError, match="has not added"):
        builder.update(
            table="orders",
            statement="UPDATE orders SET total = 1 WHERE id = 1",
            after=[EffectId("nope")],
        )


def test_builder_rejects_after_and_independent_together() -> None:
    with pytest.raises(PlanError, match="not both"):
        PlanBuilder(scope_id="agent").update(
            table="orders",
            statement="UPDATE orders SET total = 1 WHERE id = 1",
            after=[],
            independent=True,
        )


def test_builder_refuses_a_positional_placeholder() -> None:
    """The failure a Mapping-typed parameters field otherwise defers to stage time."""
    with pytest.raises(PlanError, match="positional placeholder"):
        PlanBuilder(scope_id="agent").update(
            table="orders",
            statement="UPDATE orders SET total = ? WHERE id = ?",
            parameters={"t": 1.0},
        ).build()


def test_builder_allows_a_question_mark_inside_a_string_literal() -> None:
    plan = (
        PlanBuilder(scope_id="agent")
        .update(
            table="orders",
            statement="UPDATE orders SET tenant = 'who?' WHERE id = :i",
            parameters={"i": 1},
        )
        .build()
    )
    assert plan.effects[0].parameters == {"i": 1}


def test_builder_refuses_an_empty_plan() -> None:
    with pytest.raises(PlanError, match="at least one effect"):
        PlanBuilder(scope_id="agent").build()


def test_builder_refuses_a_naive_timestamp() -> None:
    from datetime import datetime

    with pytest.raises(PlanError, match="timezone-aware"):
        PlanBuilder(scope_id="agent", created_at=datetime(2026, 1, 1))


def test_builder_build_is_repeatable_with_fresh_ids() -> None:
    builder = PlanBuilder(scope_id="agent")
    builder.update(table="orders", statement="UPDATE orders SET total = 1 WHERE id = 1")
    assert len(builder) == 1
    assert builder.build().plan_id != builder.build().plan_id


# -- EscrowRuntime ----------------------------------------------------------


def test_execute_sql_commits_a_bounded_change(db: str) -> None:
    runtime = runtime_for(db)
    result = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i",
        {"t": 480.0, "i": 1},
        tenant_id="acme",
        stated_rows=1,
    )
    assert result.committed
    assert result.diff is not None
    assert result.diff.blast_radius == 1
    assert total(db) == pytest.approx(1680.0)


def test_execute_sql_rolls_back_a_refused_change(db: str) -> None:
    runtime = runtime_for(db, checkers=[TenantIsolation(1)])
    before = total(db)
    result = runtime.execute_sql(
        "UPDATE orders SET total = :t",  # every tenant
        {"t": 1.0},
        tenant_id="acme",
        stated_rows=1,
    )
    assert not result.committed
    assert "tenant_isolation" in result.blocked_by
    assert total(db) == before


def test_execute_sql_infers_the_table_when_there_is_only_one(db: str) -> None:
    result = runtime_for(db).execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i", {"t": 450.0, "i": 1}, tenant_id="acme"
    )
    assert result.committed


def test_execute_sql_requires_a_table_when_several_are_observed(tmp_path: Path) -> None:
    path = str(tmp_path / "two.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE a(id INTEGER PRIMARY KEY); CREATE TABLE b(id INTEGER PRIMARY KEY);"
    )
    conn.commit()
    conn.close()
    runtime = EscrowRuntime(
        path,
        tables=[TableSpec("a", columns=["id"]), TableSpec("b", columns=["id"])],
        scope_id="agent",
        checkers=[],
    )
    with pytest.raises(PlanError, match="table= is required"):
        runtime.execute_sql("UPDATE a SET id = 1", {})


def test_runtime_exposes_the_primitives(db: str) -> None:
    runtime = runtime_for(db)
    assert runtime.engine is not None
    assert runtime.chain is not None
    assert runtime.substrate.observed_tables == frozenset({"orders"})
    assert runtime.plan(intent="x").build is not None


def test_runtime_is_a_context_manager(db: str) -> None:
    with runtime_for(db) as runtime:
        assert runtime.execute_sql(
            "UPDATE orders SET total = :t WHERE id = :i", {"t": 450.0, "i": 1}, tenant_id="acme"
        ).committed


def test_runtime_defaults_to_the_placeholder_checkers(db: str) -> None:
    runtime = EscrowRuntime(db, tables=TABLES, scope_id="agent")
    assert runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i", {"t": 450.0, "i": 1}, tenant_id="acme"
    ).committed


def test_runtime_verify_passes_over_its_own_chain(db: str, tmp_path: Path) -> None:
    runtime = runtime_for(db, chain_path=str(tmp_path / "chain.jsonl"))
    runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i", {"t": 450.0, "i": 1}, tenant_id="acme"
    )
    runtime.verify()
    runtime.close()


# -- the authorizer ---------------------------------------------------------


def test_write_to_an_unobserved_table_is_denied(db: str) -> None:
    runtime = runtime_for(db)
    with pytest.raises(ForbiddenStatementError, match="secrets"):
        runtime.execute_sql(
            "UPDATE secrets SET v = :v WHERE id = 1",
            {"v": "after"},
            table="orders",  # the label lies
            tenant_id="acme",
        )
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT v FROM secrets WHERE id=1").fetchone()[0] == "before"
    finally:
        conn.close()


def test_a_denied_write_is_an_interlock_error(db: str) -> None:
    """One except clause has to be enough for the whole write path."""
    runtime = runtime_for(db)
    with pytest.raises(InterlockError):
        runtime.execute_sql(
            "UPDATE secrets SET v = 'x' WHERE id = 1", {}, table="orders", tenant_id="acme"
        )


# -- TenantDrawdownGuard ----------------------------------------------------


def test_tenant_drawdown_catches_a_wipe_a_table_guard_nets_out(db: str) -> None:
    """The case ``ColumnValueGuard`` cannot see.

    ``column_total`` sums the rows in the diff. A plan that zeroes acme and
    inflates globex by the same amount leaves that sum unchanged, so a
    table-scoped guard sees a 0% fall and passes — while acme has been wiped.
    """
    from interlock import ColumnValueGuard

    runtime = runtime_for(
        db,
        checkers=[
            ColumnValueGuard("orders", "total", max_drop_fraction=0.30),
            TenantDrawdownGuard("orders", "total", max_drop_fraction=0.30),
        ],
    )
    before = total(db)
    plan = (
        runtime.plan(intent="move value between tenants")
        .update(
            table="orders",
            statement="UPDATE orders SET total = 0 WHERE tenant = :ten",
            parameters={"ten": "acme"},
            tenant_id="acme",
            stated_rows=2,
        )
        .update(
            table="orders",
            statement="UPDATE orders SET total = :t WHERE tenant = :ten",
            parameters={"t": 1700.0, "ten": "globex"},
            tenant_id="globex",
            stated_rows=1,
        )
        .build()
    )
    result = runtime.execute(plan)

    assert result.diff is not None
    diff_before, diff_after = result.diff.column_total("orders", "total")
    assert diff_before == diff_after, "the table-wide total does not move"

    assert not result.committed
    assert result.verdict is not None
    fired = {v.invariant for v in result.verdict.blocking}
    assert "tenant_drawdown_guard:orders.total" in fired
    assert "column_value_guard:orders.total" not in fired
    assert total(db) == before


def test_tenant_drawdown_allows_a_bounded_change(db: str) -> None:
    runtime = runtime_for(
        db, checkers=[TenantDrawdownGuard("orders", "total", max_drop_fraction=0.30)]
    )
    result = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i",
        {"t": 400.0, "i": 1},
        tenant_id="acme",
        stated_rows=1,
    )
    assert result.committed


def test_column_totals_are_exact_decimals(db: str) -> None:
    runtime = runtime_for(db)
    result = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i",
        {"t": 0.1, "i": 1},
        tenant_id="acme",
        stated_rows=1,
    )
    assert result.diff is not None
    before, after = result.diff.column_total("orders", "total")
    assert isinstance(before, Decimal)
    assert isinstance(after, Decimal)
    assert after == Decimal("0.1")  # not 0.1000000000000000055511151231257827
    assert result.diff.tenant_column_totals("orders", "total")["acme"] == (
        Decimal("500.0"),
        Decimal("0.1"),
    )


# -- per-plan settle cost and the AgentGov barrier --------------------------


def test_settle_cost_can_be_overridden_per_plan(db: str, tmp_path: Path) -> None:
    governor = BudgetManager()
    governor.open_root("agent", money("1.00"))
    runtime = runtime_for(db, governed=governor, settle_cost="0.01")

    cheap = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i",
        {"t": 450.0, "i": 1},
        tenant_id="acme",
        settle_cost="0.0001",
    )
    assert cheap.committed
    assert cheap.anchored_to
    assert governor.available("agent") == Decimal("0.99990000")

    default = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i", {"t": 440.0, "i": 1}, tenant_id="acme"
    )
    assert default.committed
    assert governor.available("agent") == Decimal("0.98990000")


def test_an_unknown_scope_is_refused_at_admission_not_after_commit(db: str) -> None:
    """The scope is bogus, so nothing may be staged and nothing may commit."""
    governor = BudgetManager()
    governor.open_root("someone-else", money("1.00"))
    runtime = runtime_for(db, governed=governor, settle_cost="0.01")
    before = total(db)

    with pytest.raises(AnchorError, match="not a scope AgentGov knows about"):
        runtime.execute_sql(
            "UPDATE orders SET total = :t WHERE id = :i", {"t": 1.0, "i": 1}, tenant_id="acme"
        )
    assert total(db) == before, "an unknown scope must not commit effects"


def test_agentgov_errors_never_escape_as_agentgov_errors(db: str) -> None:
    """``except InterlockError`` is sufficient around the whole write path."""
    from agentgov.exceptions import AgentGovError

    governor = BudgetManager()
    governor.open_root("someone-else", money("1.00"))
    runtime = runtime_for(db, governed=governor, settle_cost="0.01")

    try:
        runtime.execute_sql(
            "UPDATE orders SET total = :t WHERE id = :i", {"t": 1.0, "i": 1}, tenant_id="acme"
        )
    except InterlockError as exc:
        assert not isinstance(exc, AgentGovError)
    else:  # pragma: no cover - the call above always raises
        pytest.fail("expected an InterlockError")


def test_a_halted_scope_stops_the_commit(db: str) -> None:
    governor = BudgetManager()
    governor.open_root("agent", money("1.00"))
    runtime = runtime_for(db, governed=governor, settle_cost="0.01")
    governor.trip("agent", "operator halt")
    before = total(db)

    result = runtime.execute_sql(
        "UPDATE orders SET total = :t WHERE id = :i", {"t": 1.0, "i": 1}, tenant_id="acme"
    )
    assert not result.committed
    assert total(db) == before


def test_builder_kinds_map_to_effect_kinds() -> None:
    builder = PlanBuilder(scope_id="agent")
    builder.insert(table="orders", statement="INSERT INTO orders VALUES (9,'acme',1.0)")
    builder.update(table="orders", statement="UPDATE orders SET total = 1 WHERE id = 9")
    builder.delete(table="orders", statement="DELETE FROM orders WHERE id = 9")
    assert [e.kind for e in builder.build().effects] == [
        EffectKind.INSERT,
        EffectKind.UPDATE,
        EffectKind.DELETE,
    ]
