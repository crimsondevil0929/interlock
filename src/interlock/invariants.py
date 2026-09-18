"""Deterministic predicates over a measured diff.

Every checker here is a pure function of ``(plan, diff)``. No I/O, no clock, no
RNG, no network, no model call. A checker that reads outside state cannot be
re-run on the recorded inputs to reproduce its verdict, which is the only thing
that makes the verdict checkable later.

Where a judgment needs a model, the model is a sensor: its output is passed
into the checker's constructor at configuration time and captured with the
configuration. It is not consulted from inside ``check``.

Most of these read the diff, so they see exactly what the substrate measured.
Two do not, and the difference matters: ``NoSchemaChange`` reads
``Effect.kind`` and ``StatedFootprint`` reads ``Effect.stated_rows``, both of
which the untrusted agent sets. Each says so in its own docstring.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from interlock.types import (
    EffectDiff,
    EffectKind,
    EffectPlan,
    InvariantViolation,
    Severity,
)

__all__ = [
    "BlastRadius",
    "ColumnValueGuard",
    "InvariantChecker",
    "NoDelete",
    "NoSchemaChange",
    "StatedFootprint",
    "TableAllowlist",
    "TenantIsolation",
    "TruncationGuard",
    "default_checkers",
]


@runtime_checkable
class InvariantChecker(Protocol):
    """A deterministic predicate over a staged diff."""

    @property
    def name(self) -> str:
        """Stable identifier, recorded on the verdict."""
        ...

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        """Evaluate. An empty tuple means satisfied."""
        ...


class BlastRadius:
    """Bound the mutations a single plan may make.

    The coarse radius check: an agent that meant to touch three rows and is
    about to touch four thousand is wrong regardless of why.

    Compares against ``diff.blast_radius``, which counts captured mutations
    rather than distinct rows, so a row mutated twice counts twice. The limit
    is therefore conservative.
    """

    __slots__ = ("_limit",)

    def __init__(self, limit: int) -> None:
        self._limit = limit

    @property
    def name(self) -> str:
        return "blast_radius"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        if diff.blast_radius <= self._limit:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=(f"plan would mutate {diff.blast_radius} rows, limit is {self._limit}"),
                evidence={
                    "measured_rows": str(diff.blast_radius),
                    "limit": str(self._limit),
                    "tables": ",".join(sorted(diff.tables_touched)),
                },
            ),
        )


class TenantIsolation:
    """Refuse a plan that reaches across tenants.

    Independent of row count: a one-row change spanning two tenants is a
    cross-tenant write, which is the expensive failure in a multi-tenant
    system whatever its size.

    Reads tenant labels out of the captured row images. Tables with no
    ``TableSpec.tenant_column`` contribute nothing to the count, so a plan
    confined to those tables passes this check by construction.
    """

    __slots__ = ("_max_tenants",)

    def __init__(self, max_tenants: int = 1) -> None:
        self._max_tenants = max_tenants

    @property
    def name(self) -> str:
        return "tenant_isolation"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        if diff.tenant_count <= self._max_tenants:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=(f"plan spans {diff.tenant_count} tenants, limit is {self._max_tenants}"),
                evidence={"tenants": ",".join(sorted(diff.tenant_ids))},
            ),
        )


class TableAllowlist:
    """Restrict the tables a plan may touch.

    Checked against the measured tables rather than the tables the statements
    name, so a cascade into another observed table is caught. A cascade into an
    unobserved table does not reach the diff and is not caught.
    """

    __slots__ = ("_allowed",)

    def __init__(self, allowed: Sequence[str]) -> None:
        self._allowed = frozenset(allowed)

    @property
    def name(self) -> str:
        return "table_allowlist"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        trespass = diff.tables_touched - self._allowed
        if not trespass:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=f"plan touched tables outside the allowlist: {', '.join(sorted(trespass))}",
                evidence={
                    "unexpected": ",".join(sorted(trespass)),
                    "allowed": ",".join(sorted(self._allowed)),
                },
            ),
        )


class NoDelete:
    """Refuse deletions unless the operator granted the table.

    A delete cannot be compensated without the row's pre-image, and the
    pre-image is gone unless something captured it first.

    Reads the measured deltas, so it catches a delete that arrived through a
    cascade into another *observed* table. A cascade into an unobserved table
    does not appear in the diff and is not caught.
    """

    __slots__ = ("_granted",)

    def __init__(self, granted_tables: Sequence[str] = ()) -> None:
        self._granted = frozenset(granted_tables)

    @property
    def name(self) -> str:
        return "no_delete"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        offenders = sorted(
            {d.table for d in diff.deltas if d.operation == "delete"} - self._granted
        )
        if not offenders:
            return ()
        count = sum(1 for d in diff.deltas if d.operation == "delete" and d.table in offenders)
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=(
                    f"plan deletes {count} row(s) from ungranted table(s): {', '.join(offenders)}"
                ),
                evidence={"tables": ",".join(offenders), "rows": str(count)},
            ),
        )


class ColumnValueGuard:
    """Bound how far a numeric column's total may fall in one plan.

    Catches the case where every row is individually valid and the aggregate is
    not: zeroing a thousand order totals passes any per-row type check.

    One-directional and it only fires on a decrease. An inflation is not
    checked, and neither is a diff whose pre-image total is zero or negative,
    which covers insert-only plans. Pair it with a second instance if the
    column needs a bound in both directions.

    :param max_drop_fraction: Largest permitted decrease as a fraction of the
        pre-image total. ``0.25`` allows a 25% reduction.
    """

    __slots__ = ("_column", "_max_drop", "_table")

    def __init__(self, table: str, column: str, *, max_drop_fraction: float) -> None:
        self._table = table
        self._column = column
        self._max_drop = max_drop_fraction

    @property
    def name(self) -> str:
        return f"column_value_guard:{self._table}.{self._column}"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        before, after = diff.column_total(self._table, self._column)
        if before <= 0:
            return ()
        drop = (before - after) / before
        if drop <= self._max_drop:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=(
                    f"{self._table}.{self._column} falls {drop * 100:.1f}% "
                    f"({before:,.2f} to {after:,.2f}), limit is {self._max_drop * 100:.0f}%"
                ),
                evidence={
                    "before_total": f"{before:.2f}",
                    "after_total": f"{after:.2f}",
                    "drop_fraction": f"{drop:.4f}",
                },
            ),
        )


class TruncationGuard:
    """Refuse a diff that hit the row cap.

    A truncated diff is a prefix of the real delta. Every other checker here
    reads it as if it were complete, so this one blocks first rather than
    letting them pass on a partial measurement.
    """

    @property
    def name(self) -> str:
        return "truncation_guard"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        if not diff.truncated:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=(
                    "diff exceeded the row cap and is incomplete; refusing to adjudicate a sample"
                ),
                evidence={"measured_rows": str(diff.blast_radius)},
            ),
        )


class StatedFootprint:
    """Compare what the agent claimed against what the substrate measured.

    Advisory by default. A large gap is not automatically wrong, because
    triggers and cascades do legitimately amplify a statement, but it is the
    clearest available signal that the agent did not model what it was doing.

    Reads ``Effect.stated_rows``, which the agent supplies and may omit. If any
    effect omits it, ``plan.stated_rows`` is ``None`` and this checker returns
    nothing. It is a diagnostic on cooperative plans, not a control.

    :param tolerance: Permitted ratio of measured to stated rows before the gap
        is reported.
    """

    __slots__ = ("_severity", "_tolerance")

    def __init__(self, *, tolerance: float = 2.0, severity: Severity = Severity.ADVISORY) -> None:
        self._tolerance = tolerance
        self._severity = severity

    @property
    def name(self) -> str:
        return "stated_footprint"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        stated = plan.stated_rows
        if stated is None or stated <= 0:
            return ()
        ratio = diff.blast_radius / stated
        if ratio <= self._tolerance:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=self._severity,
                message=(
                    f"agent stated {stated} row(s); substrate measured "
                    f"{diff.blast_radius} ({ratio:.1f}x)"
                ),
                evidence={
                    "stated": str(stated),
                    "measured": str(diff.blast_radius),
                    "ratio": f"{ratio:.2f}",
                },
            ),
        )


class NoSchemaChange:
    """Refuse effects declared as DDL.

    Reads ``Effect.kind``, which the agent sets, and does not inspect the
    statement. A DDL statement declared as ``kind=UPDATE`` passes this check,
    and because DDL fires no row triggers it is also measured as an empty diff,
    so every diff-reading checker passes with it. Enforcing this properly needs
    a statement-level gate at the substrate or a connection whose role cannot
    execute DDL. Use the latter.
    """

    @property
    def name(self) -> str:
        return "no_schema_change"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        offenders = [e.effect_id for e in plan.effects if e.kind is EffectKind.DDL]
        if not offenders:
            return ()
        return (
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=f"plan contains DDL: {', '.join(offenders)}",
                evidence={"effects": ",".join(offenders)},
            ),
        )


def default_checkers(
    *,
    row_limit: int,
    allowed_tables: Sequence[str],
    max_tenants: int = 1,
) -> tuple[InvariantChecker, ...]:
    """A starting set.

    Every threshold here is a placeholder and none of them is calibrated.
    Measure your own diffs and set the limits from the measurement.

    Does not include ``NoDelete`` or ``ColumnValueGuard``: both need arguments
    that depend on the schema, so they are opt-in.
    """
    return (
        TruncationGuard(),
        BlastRadius(row_limit),
        TenantIsolation(max_tenants),
        TableAllowlist(allowed_tables),
        NoSchemaChange(),
        StatedFootprint(),
    )
