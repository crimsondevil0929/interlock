"""Two-audience refusals (M1): the agent's feedback cannot carry what it did not know.

A refusal used to hand the agent the guard's own message: tenant names it had
never been told, exact before-and-after totals, the count of tenants it
reached. That is a side channel an injected agent reads aggregates through.
Feedback now names only the plan's own tables and declared tenants, shows row
counts as buckets, and carries no aggregate at all.

The unit tests pin each checker's feedback. The property tests are the
guarantee: over arbitrary multi-tenant diffs and checker configurations,
including checkers written to leak, the feedback is unchanged when anything
the agent did not name is renamed, and unchanged when every amount is scaled,
so nothing about either can be in it. The integration tests run the same plans
through the engine on SQLite and PostgreSQL.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from interlock import (
    BlastRadius,
    ColumnValueGuard,
    EffectKind,
    EscrowEngine,
    NoDelete,
    NoSchemaChange,
    PlanBuilder,
    Severity,
    SqliteSubstrate,
    StatedFootprint,
    TableAllowlist,
    TenantDrawdownGuard,
    TenantIsolation,
    TruncationGuard,
)
from interlock.adjudication import adjudicate
from interlock.exceptions import (
    CyclicPlanError,
    ForbiddenStatementError,
    ScopeHaltedError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.feedback import (
    BUCKETS,
    AgentFeedback,
    FeedbackHint,
    Guidance,
    bucket,
    feedback_for_error,
)
from interlock.invariants import InvariantChecker
from interlock.types import EffectDiff, EffectPlan, InvariantViolation, RowDelta
from tests.conftest import OBSERVED, Pg
from tests.schemas import specs

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def plan_of(
    *effects: tuple[str, str | None],
    stated: int | None = None,
    kind: EffectKind = EffectKind.UPDATE,
) -> EffectPlan:
    builder = PlanBuilder("agent")
    for table, tenant in effects:
        builder.add(
            kind,
            table=table,
            statement=f"UPDATE {table} SET amount = amount",
            tenant_id=tenant,
            stated_rows=stated,
        )
    return builder.build()


def row(
    table: str,
    key: int,
    tenant: str | None,
    before: Decimal | None,
    after: Decimal | None,
) -> RowDelta:
    def image(amount: Decimal | None) -> Mapping[str, Any] | None:
        if amount is None:
            return None
        return {"id": key, "tenant": tenant, "amount": amount}

    return RowDelta(
        table=table,
        primary_key=str(key),
        before=image(before),
        after=image(after),
        tenant_id=tenant,
    )


def diff_of(plan: EffectPlan, rows: Sequence[RowDelta], *, truncated: bool = False) -> EffectDiff:
    return EffectDiff(
        plan_id=plan.plan_id,
        stage_id=uuid.UUID(int=0),
        substrate_id="sqlite",
        computed_at=datetime(2026, 9, 26, tzinfo=UTC),
        deltas=tuple(rows),
        truncated=truncated,
    )


def feedback(
    plan: EffectPlan, rows: Sequence[RowDelta], checkers: Sequence[Any], **kw: Any
) -> AgentFeedback:
    judged = adjudicate(plan, diff_of(plan, rows, **kw), checkers, stage_id=uuid.UUID(int=0))
    return judged.feedback(committed=judged.admitted)


def text_of(fb: AgentFeedback) -> str:
    return fb.render() + "\n" + json.dumps(fb.to_json(), sort_keys=True)


D = Decimal
ONE = Decimal(1)

# --------------------------------------------------------------------------
# the vocabulary
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "label"),
    [
        (-3, "0"),
        (0, "0"),
        (1, "1"),
        (2, "2-9"),
        (9, "2-9"),
        (10, "10-99"),
        (99, "10-99"),
        (100, "100-999"),
        (999, "100-999"),
        (1000, "1000+"),
        (10**9, "1000+"),
    ],
)
def test_row_counts_are_bucketed(count: int, label: str) -> None:
    assert bucket(count) == label
    assert label in BUCKETS


def test_every_kind_renders_from_a_template() -> None:
    from interlock.feedback import sanitize

    plan = plan_of(("orders", "acme"))
    for kind in Guidance:
        constraint = sanitize(FeedbackHint(kind=kind), plan, blocking=True, trusted=True)
        assert constraint.render().startswith(f"{constraint.constraint}: ")
        assert constraint.render().endswith(".")


# --------------------------------------------------------------------------
# each built-in checker
# --------------------------------------------------------------------------


def test_blast_radius_names_only_the_plans_tables_and_buckets_counts() -> None:
    plan = plan_of(("orders", "acme"))
    rows = [row("orders", i, "acme", D("10.00"), D("0.00")) for i in range(40)]
    rows += [row("order_audit", 100 + i, "acme", None, D("1.00")) for i in range(189)]
    fb = feedback(plan, rows, [BlastRadius(8)])
    (c,) = fb.constraints
    assert c.to_json() | {"text": ""} == {
        "constraint": "blast_radius",
        "guidance": "row_limit",
        "blocking": True,
        "tables": ["orders"],
        "tenants": [],
        "columns": [],
        "measured": "100-999",
        "limit": "2-9",
        "percent": None,
        "withheld_tables": True,
        "withheld_tenants": False,
        "text": "",
    }
    assert "order_audit" not in text_of(fb)
    assert "229" not in text_of(fb)
    assert fb.outcome == "refused"


def test_tenant_isolation_never_names_or_counts_other_tenants() -> None:
    plan = plan_of(("orders", "acme"))
    rows = [
        row("orders", 1, "acme", D("5"), D("6")),
        row("orders", 2, "globex", D("5"), D("6")),
        row("orders", 3, "initech", D("5"), D("6")),
    ]
    fb = feedback(plan, rows, [TenantIsolation(1)])
    rendered = text_of(fb)
    assert "acme" in rendered
    assert "globex" not in rendered and "initech" not in rendered
    assert not re.search(r"\b3\b", rendered)
    (c,) = fb.constraints
    assert (c.tenants, c.withheld_tenants, c.limit) == (("acme",), True, "1")


def test_a_plan_that_declares_no_tenant_is_told_none() -> None:
    plan = plan_of(("orders", None))
    rows = [row("orders", 1, "acme", D("1"), D("2")), row("orders", 2, "globex", D("1"), D("2"))]
    fb = feedback(plan, rows, [TenantIsolation(1)])
    assert "declared tenants are none" in fb.render()
    assert "acme" not in text_of(fb) and "globex" not in text_of(fb)


def test_value_guards_show_the_policy_limit_and_no_total() -> None:
    plan = plan_of(("accounts", "acme"))
    rows = [
        row("accounts", 100, "acme", D("500.00"), D("0.00")),
        row("accounts", 101, "acme", D("250.00"), D("0.00")),
        row("accounts", 200, "globex", D("900.00"), D("100.00")),
    ]
    guards = [
        ColumnValueGuard("accounts", "amount", max_drop_fraction=0.3),
        TenantDrawdownGuard("accounts", "amount", max_drop_fraction=0.3),
    ]
    fb = feedback(plan, rows, guards)
    rendered = text_of(fb)
    for total in ("750", "1650", "100", "900", "500", "250", "93.9", "88.8", "0.9393"):
        assert total not in rendered, total
    assert [c.render() for c in fb.constraints] == [
        "column_value_guard: the plan lowers accounts.amount by more than the 30% allowed.",
        "tenant_drawdown_guard: the plan lowers accounts.amount by more than the 30% allowed "
        "for a tenant outside the plan's declared tenants.",
        "tenant_drawdown_guard: the plan lowers accounts.amount by more than the 30% allowed "
        "for tenant acme.",
    ]
    assert "globex" not in rendered


def test_a_guard_on_a_table_the_plan_never_named_names_no_table() -> None:
    """ColumnValueGuard's own name is ``column_value_guard:ledger.amount``.
    A plan that only names orders learns neither the table nor the column."""
    plan = plan_of(("orders", "acme"))
    rows = [row("ledger", 1, "acme", D("100.00"), D("1.00"))]
    fb = feedback(plan, rows, [ColumnValueGuard("ledger", "amount", max_drop_fraction=0.1)])
    rendered = text_of(fb)
    assert "ledger" not in rendered and "amount" not in rendered
    assert "a guarded column" in rendered


def test_untenanted_drawdown_reads_as_a_table_level_fall() -> None:
    plan = plan_of(("accounts", None))
    rows = [row("accounts", 1, None, D("100.00"), D("0.00"))]
    fb = feedback(plan, rows, [TenantDrawdownGuard("accounts", "amount", max_drop_fraction=0.5)])
    (c,) = fb.constraints
    assert c.guidance is Guidance.VALUE_DROP
    assert "untenanted" not in text_of(fb)


def test_table_allowlist_no_delete_truncation_and_ddl() -> None:
    plan = plan_of(("orders", "acme"))
    rows = [
        row("orders", 1, "acme", D("1"), None),
        row("secret_table", 2, "acme", D("1"), None),
    ]
    fb = feedback(
        plan,
        rows,
        [TableAllowlist(["orders"]), NoDelete(), TruncationGuard(), NoSchemaChange()],
        truncated=True,
    )
    rendered = [c.render() for c in fb.constraints]
    assert rendered == [
        "table_allowlist: the plan changed rows in a table the plan does not name, which it "
        "may not write.",
        "no_delete: the plan deletes rows from orders and a table the plan does not name, "
        "where deletes are not allowed.",
        "truncation_guard: the plan changed more rows than can be measured (2-9). Split the work.",
    ]
    assert "secret_table" not in text_of(fb)
    ddl = plan_of(("orders", "acme"), kind=EffectKind.DDL)
    (c,) = feedback(ddl, [], [NoSchemaChange()]).constraints
    assert c.guidance is Guidance.SCHEMA_CHANGE


def test_an_advisory_rides_on_a_committed_plan() -> None:
    plan = plan_of(("orders", "acme"), stated=1)
    rows = [row("orders", i, "acme", D("1"), D("2")) for i in range(12)]
    fb = feedback(plan, rows, [StatedFootprint(tolerance=2.0)])
    assert fb.outcome == "committed"
    (c,) = fb.constraints
    assert not c.blocking
    assert c.render() == "stated_footprint: the plan stated 1 rows; the database measured 10-99."


def test_constraints_are_ordered_canonically_and_duplicates_collapse() -> None:
    plan = plan_of(("orders", "acme"), stated=1)
    rows = [row("orders", i, "t" + str(i), D("9"), D("1")) for i in range(5)]
    fb = feedback(
        plan,
        rows,
        [
            StatedFootprint(),
            TenantDrawdownGuard("orders", "amount", max_drop_fraction=0.1),
            BlastRadius(2),
        ],
    )
    kinds = [c.guidance for c in fb.constraints]
    assert kinds == [Guidance.ROW_LIMIT, Guidance.TENANT_DRAWDOWN, Guidance.STATED_FOOTPRINT]
    assert fb.blocking == fb.constraints[:2]


# --------------------------------------------------------------------------
# checkers that are not built in
# --------------------------------------------------------------------------


@dataclass
class Leaky:
    """A custom checker written to leak everything it can."""

    tenants: Sequence[str]
    tables: Sequence[str]
    label: str = "leaky_guard_globex"

    @property
    def name(self) -> str:
        return self.label

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        before, after = diff.column_total(next(iter(self.tables)), "amount")
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=f"totals {before} -> {after} for {', '.join(self.tenants)}",
                evidence={"before": str(before), "tenants": ",".join(self.tenants)},
            ),
        )

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        before, _ = diff.column_total(next(iter(self.tables)), "amount")
        return FeedbackHint(
            kind=Guidance.ROW_LIMIT,
            tables=tuple(self.tables),
            tenants=tuple(self.tenants),
            columns=tuple(self.tenants),
            measured=int(before),
            limit=int(before) + 1,
            percent=37,
        )


class Silent:
    """A custom checker with no hint at all."""

    name = "no_weekend_writes_for_globex"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        return (InvariantViolation(self.name, Severity.BLOCKING, "globex is closed"),)


class Broken:
    name = "broken_globex"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        raise RuntimeError("globex total 123456.78")


class BadHint(Silent):
    name = "bad_hint"

    def hint(self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation) -> object:
        raise ValueError("globex 999")


class WrongHint(Silent):
    name = "wrong_hint"

    def hint(self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation) -> object:
        return "globex 999"


def test_a_custom_checker_cannot_leak_through_its_hint() -> None:
    plan = plan_of(("orders", "acme"))
    rows = [
        row("orders", 1, "acme", D("777.77"), D("1.00")),
        row("vault", 2, "globex", D("5"), None),
    ]
    leaky = Leaky(tenants=["acme", "globex"], tables=["orders", "vault"])
    fb = feedback(plan, rows, [leaky])
    (c,) = fb.constraints
    assert (c.tables, c.tenants, c.columns) == (("orders",), ("acme",), ())
    assert (c.measured, c.limit, c.percent) == (None, None, None)
    assert c.withheld_tables and c.withheld_tenants
    rendered = text_of(fb)
    for leak in ("globex", "vault", "777", "778", "37", "leaky_guard"):
        assert leak not in rendered, leak


@pytest.mark.parametrize("checker", [Silent(), Broken(), BadHint(), WrongHint()])
def test_a_custom_checker_without_a_usable_hint_is_an_operator_constraint(
    checker: InvariantChecker,
) -> None:
    plan = plan_of(("orders", "acme"))
    fb = feedback(plan, [row("orders", 1, "acme", D("1"), D("2"))], [checker])
    (c,) = fb.constraints
    assert c.render() == "operator_constraint: an operator-defined check refused the plan."
    assert "globex" not in text_of(fb) and "123456" not in text_of(fb)


def test_a_subclass_of_a_built_in_is_not_trusted_with_numbers() -> None:
    class Fancy(BlastRadius):
        __slots__ = ()

    plan = plan_of(("orders", "acme"))
    rows = [row("orders", i, "acme", D("1"), D("2")) for i in range(20)]
    (c,) = feedback(plan, rows, [Fancy(3)]).constraints
    assert (c.measured, c.limit) == (None, None)


# --------------------------------------------------------------------------
# errors that never reached a verdict
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "kind", "retryable"),
    [
        (
            ForbiddenStatementError(
                "DELETE on 'orders' reaches refunds: orders -> order_items -> refunds",
                reason="cascade",
                table="orders",
            ),
            Guidance.CASCADE,
            False,
        ),
        (
            ForbiddenStatementError(
                "writes 'customers'", reason="unobserved_table", table="customers"
            ),
            Guidance.UNOBSERVED_WRITE,
            False,
        ),
        (
            ForbiddenStatementError("COMMIT", reason="transaction_control"),
            Guidance.TRANSACTION_CONTROL,
            False,
        ),
        (ForbiddenStatementError("capture", reason="protected"), Guidance.PROTECTED, False),
        (ForbiddenStatementError("DROP", reason="statement_kind"), Guidance.STATEMENT_KIND, False),
        (CyclicPlanError("cycle among a, b"), Guidance.MALFORMED_PLAN, False),
        (ScopeHaltedError("scope agent halted by globex's breaker"), Guidance.SCOPE_HALTED, False),
        (StageConflictError("row 600 of globex is locked"), Guidance.CONFLICT, True),
        (StageExpiredError("expired"), Guidance.EXPIRED, False),
        (SubstrateUnavailableError("host db.internal down"), Guidance.UNAVAILABLE, True),
        (SubstrateConfigurationError("role can write payroll"), Guidance.UNAVAILABLE, False),
        (
            StageError("UNIQUE constraint failed: Key (email)=(ceo@globex.test) already exists"),
            Guidance.STATEMENT_FAILED,
            False,
        ),
        (
            sqlite3.OperationalError("no such table: globex_payroll"),
            Guidance.STATEMENT_FAILED,
            False,
        ),
        (RuntimeError("globex"), Guidance.UNAVAILABLE, False),
    ],
)
def test_error_feedback_reads_the_type_never_the_message(
    error: BaseException, kind: Guidance, retryable: bool
) -> None:
    plan = plan_of(("orders", "acme"))
    fb = feedback_for_error(plan, error)
    (c,) = fb.constraints
    assert (c.guidance, fb.retryable, fb.outcome) == (kind, retryable, "error")
    rendered = text_of(fb)
    for leak in (
        "refunds",
        "order_items",
        "customers",
        "globex",
        "600",
        "ceo@",
        "db.internal",
        "payroll",
    ):
        assert leak not in rendered, leak
    if kind is Guidance.CASCADE:
        assert "changing orders this way would cascade" in rendered


# --------------------------------------------------------------------------
# the property: nothing the agent did not name can move the feedback
# --------------------------------------------------------------------------

TENANT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=7, max_size=7).map(
    lambda s: "tn" + s
)
TABLE = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=6, max_size=6).map(
    lambda s: "tb" + s
)
AMOUNT = st.decimals(min_value=D("1.01"), max_value=D("99999.99"), places=2)
FRACTIONS = (0.05, 0.1, 0.25, 0.3, 0.5, 0.9)


@dataclass(frozen=True)
class CheckerSpec:
    """A checker as data, so a scenario can be rebuilt under a renaming."""

    kind: str
    table: str = ""
    tables: tuple[str, ...] = ()
    tenants: tuple[str, ...] = ()
    number: float = 0.0

    def build(self, rename: Mapping[str, str]) -> Any:
        t = rename.get(self.table, self.table)
        ts = [rename.get(x, x) for x in self.tables]
        if self.kind == "blast":
            return BlastRadius(int(self.number))
        if self.kind == "tenants":
            return TenantIsolation(int(self.number))
        if self.kind == "allow":
            return TableAllowlist(ts)
        if self.kind == "nodelete":
            return NoDelete(ts)
        if self.kind == "value":
            return ColumnValueGuard(t, "amount", max_drop_fraction=self.number)
        if self.kind == "drawdown":
            return TenantDrawdownGuard(t, "amount", max_drop_fraction=self.number)
        if self.kind == "truncation":
            return TruncationGuard()
        if self.kind == "stated":
            return StatedFootprint(tolerance=self.number, severity=Severity.BLOCKING)
        if self.kind == "ddl":
            return NoSchemaChange()
        assert self.kind == "leaky"
        return Leaky(
            tenants=[rename.get(x, x) for x in self.tenants], tables=[t, *ts], label="leaky"
        )


@dataclass(frozen=True)
class Scenario:
    tenants: tuple[str, ...]
    tables: tuple[str, ...]
    declared: tuple[str, ...]
    referenced: tuple[tuple[str, str | None], ...]
    stated: int | None
    rows: tuple[tuple[str, int, str, str, Decimal | None, Decimal | None], ...]
    truncated: bool
    checkers: tuple[CheckerSpec, ...]

    def plan(self) -> EffectPlan:
        return plan_of(*self.referenced, stated=self.stated)

    def run(
        self,
        plan: EffectPlan,
        *,
        rename: Mapping[str, str] | None = None,
        scale: Decimal = ONE,
        amounts: Mapping[int, tuple[Decimal | None, Decimal | None]] | None = None,
    ) -> tuple[AgentFeedback, list[tuple[str, str]]]:
        names = dict(rename or {})
        deltas = []
        for table, key, tenant, op, before, after in self.rows:
            if amounts and key in amounts:
                before, after = amounts[key]
            deltas.append(
                row(
                    names.get(table, table),
                    key,
                    names.get(tenant, tenant),
                    None if op == "insert" else (before or D(0)) * scale,
                    None if op == "delete" else (after or D(0)) * scale,
                )
            )
        checkers = [spec.build(names) for spec in self.checkers]
        judged = adjudicate(
            plan,
            diff_of(plan, deltas, truncated=self.truncated),
            checkers,
            stage_id=uuid.UUID(int=0),
        )
        declared = set(self.declared)
        # Which constraints fired, by full name (a guard's name carries its
        # table), with the tenant when the plan declared it. That is the
        # verdict itself; feedback may depend on it and on nothing else.
        fired = sorted(
            (
                v.invariant,
                v.evidence.get("tenant", "") if v.evidence.get("tenant") in declared else "*",
            )
            for v in judged.verdict.violations
        )
        return judged.feedback(committed=judged.admitted), fired


@st.composite
def scenarios(draw: st.DrawFn) -> Scenario:
    tenants = tuple(draw(st.lists(TENANT, min_size=2, max_size=5, unique=True)))
    tables = tuple(draw(st.lists(TABLE, min_size=2, max_size=4, unique=True)))
    declared = tuple(draw(st.lists(st.sampled_from(tenants[1:]), unique=True, max_size=2)))
    named = draw(st.lists(st.sampled_from(tables[1:]), unique=True, min_size=1, max_size=2))
    referenced = tuple((table, draw(st.sampled_from((None, *declared)))) for table in named)
    stated = draw(st.none() | st.integers(1, 30))
    count = draw(st.integers(1, 30))
    rows = []
    for key in range(count):
        op = draw(st.sampled_from(("insert", "update", "delete")))
        rows.append(
            (
                draw(st.sampled_from(tables)),
                key,
                draw(st.sampled_from(tenants)),
                op,
                draw(AMOUNT),
                draw(AMOUNT),
            )
        )
    specs_: list[CheckerSpec] = []
    for kind in draw(
        st.lists(
            st.sampled_from(
                (
                    "blast",
                    "tenants",
                    "allow",
                    "nodelete",
                    "value",
                    "drawdown",
                    "truncation",
                    "stated",
                    "ddl",
                    "leaky",
                )
            ),
            min_size=1,
            max_size=6,
        )
    ):
        table = draw(st.sampled_from(tables))
        subset = tuple(draw(st.lists(st.sampled_from(tables), unique=True, max_size=len(tables))))
        number = {
            "blast": float(draw(st.integers(1, 25))),
            "tenants": float(draw(st.integers(1, 3))),
            "value": draw(st.sampled_from(FRACTIONS)),
            "drawdown": draw(st.sampled_from(FRACTIONS)),
            "stated": draw(st.sampled_from((1.5, 2.0, 3.0))),
        }.get(kind, 0.0)
        specs_.append(
            CheckerSpec(kind=kind, table=table, tables=subset, tenants=tenants, number=number)
        )
    return Scenario(
        tenants=tenants,
        tables=tables,
        declared=declared,
        referenced=referenced,
        stated=stated,
        rows=tuple(rows),
        truncated=draw(st.booleans()),
        checkers=tuple(specs_),
    )


PROPERTY = settings(
    # INTERLOCK_PROPERTY_EXAMPLES=3000 for a thorough run; 300 keeps CI quick.
    max_examples=int(os.environ.get("INTERLOCK_PROPERTY_EXAMPLES", "300")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _numbers(fb: AgentFeedback) -> set[str]:
    return set(re.findall(r"\d+(?:\.\d+)?", fb.render()))


@PROPERTY
@given(scenarios())
def test_feedback_names_only_what_the_plan_names(case: Scenario) -> None:
    plan = case.plan()
    fb, _ = case.run(plan)
    named_tables = {t for t, _ in case.referenced}
    rendered = text_of(fb)
    for c in fb.constraints:
        assert set(c.tables) <= named_tables
        assert set(c.tenants) <= set(case.declared)
        assert c.measured in (None, *BUCKETS) and c.limit in (None, *BUCKETS)
        assert c.percent in (None, *(int(f * 100) for f in FRACTIONS))
    for tenant in set(case.tenants) - set(case.declared):
        assert tenant not in rendered
    for table in set(case.tables) - named_tables:
        assert table not in rendered
    allowed = {"0", "1", "2", "9", "10", "99", "100", "999", "1000"}
    allowed |= {str(int(f * 100)) for f in FRACTIONS}
    assert _numbers(fb) <= allowed


@PROPERTY
@given(scenarios(), st.data())
def test_renaming_what_the_plan_did_not_name_changes_nothing(
    case: Scenario, data: st.DataObject
) -> None:
    """Unreferenced tenants and tables, renamed consistently everywhere the
    agent could not see: the feedback is byte-identical."""
    plan = case.plan()
    hidden = [t for t in case.tenants if t not in case.declared]
    hidden += [t for t in case.tables if t not in {name for name, _ in case.referenced}]
    fresh = data.draw(
        st.lists(
            st.text(alphabet="qwxz", min_size=9, max_size=9),
            min_size=len(hidden),
            max_size=len(hidden),
            unique=True,
        )
    )
    rename = {old: "zz" + new for old, new in zip(hidden, fresh, strict=True)}
    original, _ = case.run(plan)
    renamed, _ = case.run(plan, rename=rename)
    assert renamed.to_json() == original.to_json()


@PROPERTY
@given(scenarios(), st.sampled_from((D(2), D(3), D("0.5"), D(7), D(1000), D("0.01"))))
def test_scaling_every_amount_changes_nothing(case: Scenario, factor: Decimal) -> None:
    """Every guard here decides on ratios, so scaling all money keeps every
    decision. Any total or fraction in the feedback would move with it."""
    plan = case.plan()
    original, fired = case.run(plan)
    scaled, fired_scaled = case.run(plan, scale=factor)
    assert fired_scaled == fired
    assert scaled.to_json() == original.to_json()


@PROPERTY
@given(scenarios(), st.data())
def test_other_tenants_amounts_move_feedback_only_through_what_fired(
    case: Scenario, data: st.DataObject
) -> None:
    plan = case.plan()
    hidden_rows = [r for r in case.rows if r[2] not in case.declared]
    amounts = {r[1]: (data.draw(AMOUNT), data.draw(AMOUNT)) for r in hidden_rows}
    original, fired = case.run(plan)
    perturbed, fired_after = case.run(plan, amounts=amounts)
    if fired_after == fired:
        assert perturbed.to_json() == original.to_json()


# --------------------------------------------------------------------------
# through the engine, on SQLite and PostgreSQL
# --------------------------------------------------------------------------

LEAKS = ("globex", "900", "250", "500", "750", "1650", "refunds", "order_items", "shipment_events")


def cross_tenant_plan(placeholder: str) -> EffectPlan:
    return (
        PlanBuilder("agent")
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = 0 WHERE tenant IN ({placeholder})",
            parameters={"a": "acme", "g": "globex"},
            tenant_id="acme",
        )
        .build()
    )


def assert_zero_leak(fb: AgentFeedback | None) -> str:
    assert fb is not None
    rendered = text_of(fb)
    for leak in LEAKS:
        assert leak not in rendered, leak
    return rendered


def checks() -> list[Any]:
    return [
        TenantIsolation(1),
        TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
        BlastRadius(2),
    ]


def test_sqlite_refusal_splits_by_audience(back_office: str) -> None:
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("accounts")), checkers=checks())
    result = engine.execute(cross_tenant_plan(":a, :g"))
    assert not result.committed
    refusal = result.refusal
    assert refusal is not None
    assert refusal.evidence.tenants_touched == ("acme", "globex")
    assert any("globex" in v.message for v in refusal.evidence.violations)
    rendered = assert_zero_leak(refusal.feedback)
    assert (
        "tenant_drawdown_guard: the plan lowers accounts.balance by more than the 30% "
        "allowed for tenant acme." in rendered
    )


def test_sqlite_cascade_refusal_does_not_name_unobserved_tables(back_office: str) -> None:
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("orders")), checkers=[])
    plan = (
        PlanBuilder("agent")
        .delete(table="orders", statement="DELETE FROM orders WHERE id = 500")
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as caught:
        engine.execute(plan)
    assert "refunds" in str(caught.value)  # the operator's message names the path
    fb = caught.value.feedback
    assert isinstance(fb, AgentFeedback)
    rendered = assert_zero_leak(fb)
    assert "cascade: changing orders this way would cascade" in rendered


def test_sqlite_unobserved_write_names_no_table_the_plan_did_not(back_office: str) -> None:
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("orders")), checkers=[])
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE customers SET email = 'x' WHERE id = 20")
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as caught:
        engine.execute(plan)
    fb = caught.value.feedback
    assert isinstance(fb, AgentFeedback)
    assert "customers" not in text_of(fb)
    assert "a statement writes a table the plan does not name" in fb.render()


def test_execute_or_raise_carries_feedback(back_office: str) -> None:
    from interlock import AdmissionError

    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("accounts")), checkers=checks())
    with pytest.raises(AdmissionError) as caught:
        engine.execute_or_raise(cross_tenant_plan(":a, :g"))
    assert "globex" in str(caught.value)
    assert_zero_leak(caught.value.feedback)  # type: ignore[arg-type]


def test_postgres_refusal_splits_by_audience(pg: Pg) -> None:
    from interlock import PostgresSubstrate

    engine = EscrowEngine(PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)), checkers=checks())
    plan = (
        PlanBuilder("agent")
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = 0 WHERE tenant IN (%(a)s, %(g)s)",
            parameters={"a": "acme", "g": "globex"},
            tenant_id="acme",
        )
        .build()
    )
    result = engine.execute(plan)
    assert not result.committed and result.refusal is not None
    assert "globex" in result.refusal.evidence.tenants_touched
    rendered = assert_zero_leak(result.feedback)
    assert "for tenant acme" in rendered


def test_postgres_cascade_refusal_does_not_name_unobserved_tables(pg: Pg) -> None:
    from interlock import PostgresSubstrate

    engine = EscrowEngine(PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)), checkers=[])
    plan = (
        PlanBuilder("agent")
        .delete(table="shipments", statement="DELETE FROM shipments WHERE id = 700")
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as caught:
        engine.execute(plan)
    assert "shipment_events" in str(caught.value)
    fb = caught.value.feedback
    assert isinstance(fb, AgentFeedback)
    assert_zero_leak(fb)
    assert "changing shipments this way would cascade" in fb.render()


def test_postgres_privilege_refusal_names_no_table(pg: Pg) -> None:
    from interlock import PostgresSubstrate

    engine = EscrowEngine(PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)), checkers=[])
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE payments SET amount = 0")
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as caught:
        engine.execute(plan)
    fb = caught.value.feedback
    assert isinstance(fb, AgentFeedback)
    assert "payments" not in text_of(fb)


def test_plan_ids_are_not_part_of_feedback() -> None:
    """Feedback is about the plan's content; it carries no identifier."""
    plan = plan_of(("orders", "acme"))
    fb = feedback(plan, [row("orders", 1, "acme", D("1"), D("2"))], [BlastRadius(0)])
    assert str(plan.plan_id) not in text_of(fb)
