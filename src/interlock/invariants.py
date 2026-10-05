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
from decimal import Decimal
from typing import Final, Protocol, runtime_checkable

from interlock.feedback import FeedbackHint, Guidance
from interlock.outbound_checks import (
    OutboundCount,
    OutboundTenantIsolation,
    PayloadAmountCap,
    RecipientAllowlist,
    SinkAllowlist,
)
from interlock.types import (
    EffectDiff,
    EffectKind,
    EffectPlan,
    InboundFact,
    InvariantViolation,
    OutboundDelta,
    RowDelta,
    Severity,
)
from interlock.types import exact_number as _number
from interlock.types import field_path as _path
from interlock.types import value_at as _at
from interlock.windows import RateWindowCheck

__all__ = [
    "BUILT_IN_CHECKERS",
    "BlastRadius",
    "ColumnValueGuard",
    "CrossEffectAgreement",
    "FactAgreement",
    "InvariantChecker",
    "NoDelete",
    "NoSchemaChange",
    "StatedFootprint",
    "TableAllowlist",
    "TenantDrawdownGuard",
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


# A checker may also implement ``hint(plan, diff, violation) -> FeedbackHint``:
# what the agent may be told about one of its violations. The hint is
# sanitized against the plan before the agent sees it (see
# :mod:`interlock.feedback`), and a custom checker's numbers are dropped. A
# checker without one is reported to the agent as an operator constraint,
# with nothing else.


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
    def limit(self) -> int:
        return self._limit

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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        return FeedbackHint(
            kind=Guidance.ROW_LIMIT,
            tables=tuple(sorted(diff.tables_touched)),
            measured=diff.blast_radius,
            limit=self._limit,
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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The tenants touched go in for the sanitizer to cut down to the ones
        # the plan declared; how many there were never leaves this method.
        return FeedbackHint(
            kind=Guidance.TENANT_SCOPE,
            tenants=tuple(sorted(diff.tenant_ids)),
            limit=self._max_tenants,
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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        return FeedbackHint(
            kind=Guidance.TABLE_SCOPE, tables=tuple(sorted(diff.tables_touched - self._allowed))
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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        offenders = {d.table for d in diff.deltas if d.operation == "delete"} - self._granted
        count = sum(1 for d in diff.deltas if d.operation == "delete" and d.table in offenders)
        return FeedbackHint(
            kind=Guidance.NO_DELETE, tables=tuple(sorted(offenders)), measured=count
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
        # Decimal, because ``drop`` is Decimal: mixing the two raises
        # TypeError, and a checker that raises is a blocking violation.
        self._max_drop = Decimal(str(max_drop_fraction))

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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The limit, which is policy. Never the totals or the fall, which are
        # the data: from its own change and the fall an agent could work out
        # the table's total.
        return FeedbackHint(
            kind=Guidance.VALUE_DROP,
            tables=(self._table,),
            columns=(self._column,),
            percent=_percent(self._max_drop),
        )


class TenantDrawdownGuard:
    """Bound how far any *single tenant's* column total may fall in one plan.

    ``ColumnValueGuard`` measures the fall against the whole table. On a
    multi-tenant substrate that is the wrong denominator: one tenant of forty
    is 2.5% of the platform total, so a table-scoped 30% guard will admit that
    tenant being zeroed without registering anything. This re-denominates the
    same question per tenant, which is the denominator a tenant cares about.

    Rows whose tenant could not be read group together under ``""`` and are
    checked as one bucket. That is deliberate: a table with no
    ``TableSpec.tenant_column`` degrades to exactly ``ColumnValueGuard``
    rather than silently passing.

    :param max_drop_fraction: Largest permitted decrease as a fraction of any
        one tenant's pre-image total. ``0.30`` allows a 30% reduction.
    """

    __slots__ = ("_column", "_max_drop", "_table")

    def __init__(self, table: str, column: str, *, max_drop_fraction: float) -> None:
        self._table = table
        self._column = column
        self._max_drop = Decimal(str(max_drop_fraction))

    @property
    def name(self) -> str:
        return f"tenant_drawdown_guard:{self._table}.{self._column}"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        violations: list[InvariantViolation] = []
        for tenant, (before, after) in sorted(
            diff.tenant_column_totals(self._table, self._column).items()
        ):
            if before <= 0 or after >= before:
                continue
            drop = (before - after) / before
            if drop <= self._max_drop:
                continue
            label = tenant or "<untenanted>"
            violations.append(
                InvariantViolation(
                    invariant=self.name,
                    severity=Severity.BLOCKING,
                    message=(
                        f"tenant {label!r} {self._table}.{self._column} falls "
                        f"{drop * 100:.1f}% ({before:,.2f} to {after:,.2f}), "
                        f"limit is {self._max_drop * 100:.0f}%"
                    ),
                    evidence={
                        "tenant": label,
                        "before_total": f"{before:.2f}",
                        "after_total": f"{after:.2f}",
                        "drop_fraction": f"{drop:.4f}",
                    },
                )
            )
        return tuple(violations)

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        tenant = violation.evidence.get("tenant", "")
        if tenant == "<untenanted>":
            # Rows with no tenant are one bucket: a table-level fall.
            return FeedbackHint(
                kind=Guidance.VALUE_DROP,
                tables=(self._table,),
                columns=(self._column,),
                percent=_percent(self._max_drop),
            )
        return FeedbackHint(
            kind=Guidance.TENANT_DRAWDOWN,
            tables=(self._table,),
            columns=(self._column,),
            tenants=(tenant,),
            percent=_percent(self._max_drop),
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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        return FeedbackHint(kind=Guidance.TRUNCATED, measured=diff.blast_radius)


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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # ``limit`` carries the plan's own stated count for this kind.
        return FeedbackHint(
            kind=Guidance.STATED_FOOTPRINT,
            measured=diff.blast_radius,
            limit=plan.stated_rows,
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

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        return FeedbackHint(kind=Guidance.SCHEMA_CHANGE)


_MEASURES: Final = ("inserted", "net", "value")


class CrossEffectAgreement:
    """Refuse a plan whose outbound request disagrees with the rows it rides with.

    The plan's two halves must say the same thing. A refund request for 5000.00
    beside the refund row the same plan inserted for 50.00 is a prompt-injected
    payload or a bug, and either way it is caught by arithmetic, not judgement
    (``docs/OUTBOX_DESIGN.md`` §5.2). Both halves are measured: the request is
    read back from the outbox, as the relay will send it, and the rows from the
    stage's capture. A pure function of ``(plan, diff)``, like every checker.

    :param sink: The requests this rule applies to: this sink's...
    :param operation: ...calls of this operation.
    :param field: The payload field, a dotted path: ``"amount"``,
        ``"refund.amount"``, ``"lines.0.amount"``.
    :param table: The rows the field must agree with: this table's...
    :param column: ...values of this column.
    :param measure: What of the rows the field must equal.

        - ``"inserted"`` (the default): the sum of ``column`` over the rows the
          plan inserted. A refund's amount against the refund rows.
        - ``"net"``: the net change of ``column`` over every row the plan
          wrote, after minus before, summed. A credit against the balance it
          moved.
        - ``"value"``: the one value of ``column`` every row the plan wrote
          holds, compared exactly. A currency, an order id, a recipient.
    :param key: Pairs requests with rows, as ``(payload_field, column)``: each
        request is held to the rows whose ``column`` equals its
        ``payload_field``, and every key on one side must be on the other.
        Without it, the requests' total is held to the rows' total (for
        ``"value"``, every request to the rows' one value).

    Strict both ways: a request with no rows to agree with is a disagreement,
    and so are rows with no request, since the rule says the two go together.
    A plan that has neither passes. Numbers compare exactly, as ``Decimal``: a
    numeric column against a payload integer or decimal string (money travels
    as decimal strings; no float reaches a payload). Anything else compares as
    itself, so ``"007"`` is not ``7``.

    :raises ValueError: On an unknown measure, or an empty name or key.
    """

    __slots__ = ("_column", "_field", "_key", "_measure", "_operation", "_path", "_sink", "_table")

    def __init__(
        self,
        sink: str,
        operation: str,
        *,
        field: str,
        table: str,
        column: str,
        measure: str = "inserted",
        key: tuple[str, str] | None = None,
    ) -> None:
        for label, value in (
            ("sink", sink),
            ("operation", operation),
            ("field", field),
            ("table", table),
            ("column", column),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"CrossEffectAgreement needs a {label}")
        if measure not in _MEASURES:
            raise ValueError(f"measure is one of {', '.join(_MEASURES)}, not {measure!r}")
        if key is not None and (
            len(key) != 2 or not all(isinstance(k, str) and k.strip() for k in key)
        ):
            raise ValueError("key is a (payload_field, column) pair")
        self._sink = sink
        self._operation = operation
        self._field = field
        self._path = _path(field)
        self._table = table
        self._column = column
        self._measure = measure
        self._key = key

    @property
    def name(self) -> str:
        return (
            f"cross_effect_agreement:{self._sink}.{self._operation}.{self._field}"
            f"={self._table}.{self._column}"
        )

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        requests = [
            o for o in diff.outbound if o.sink == self._sink and o.operation == self._operation
        ]
        table = self._table.lower()
        rows = [
            d
            for d in diff.deltas
            if d.table.lower() == table and (self._measure != "inserted" or d.operation == "insert")
        ]
        if not requests and not rows:
            return ()
        problems: list[tuple[str, dict[str, str]]] = []
        groups: dict[tuple[str, str] | None, tuple[list[OutboundDelta], list[RowDelta]]] = {}
        if self._key is None:
            groups[None] = (requests, rows)
        else:
            path, key_column = _path(self._key[0]), self._key[1]
            for request in requests:
                found, value = _at(request.payload, path)
                scalar = _scalar(value) if found else None
                if scalar is None:
                    problems.append(
                        (
                            f"a {self._sink}.{self._operation} request has no {self._key[0]} "
                            f"to pair it with {self._table} rows",
                            {"effect": request.effect_id},
                        )
                    )
                    continue
                groups.setdefault(scalar, ([], []))[0].append(request)
            for row in rows:
                image = row.after if row.after is not None else row.before
                scalar = _scalar(image.get(key_column)) if image is not None else None
                if scalar is None:
                    problems.append(
                        (
                            f"a {self._table} row has no {key_column} to pair it with a request",
                            {"row": row.primary_key},
                        )
                    )
                    continue
                groups.setdefault(scalar, ([], []))[1].append(row)
        for group_key, (grouped_requests, grouped_rows) in groups.items():
            problems += self._compare(group_key, grouped_requests, grouped_rows)
        return tuple(
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=message,
                evidence={
                    "sink": self._sink,
                    "operation": self._operation,
                    "field": self._field,
                    "rows": f"{self._table}.{self._column}",
                    "measure": self._measure,
                    **evidence,
                },
            )
            for message, evidence in problems
        )

    def _compare(
        self,
        group: tuple[str, str] | None,
        requests: list[OutboundDelta],
        rows: list[RowDelta],
    ) -> list[tuple[str, dict[str, str]]]:
        where = "" if group is None or self._key is None else f" for {self._key[0]} {group[1]}"
        evidence = {} if group is None else {"key": group[1]}
        if not requests:
            return [
                (
                    f"the plan wrote {self._table} rows{where} with no "
                    f"{self._sink}.{self._operation} request to match them",
                    evidence,
                )
            ]
        if not rows:
            return [
                (
                    f"a {self._sink}.{self._operation} request{where} has no {self._table} "
                    f"rows to agree with",
                    evidence,
                )
            ]
        if self._measure == "value":
            return self._compare_values(where, evidence, requests, rows)
        requested = Decimal(0)
        for request in requests:
            found, value = _at(request.payload, self._path)
            number = _number(value) if found else None
            if number is None:
                return [
                    (
                        f"a {self._sink}.{self._operation} request{where} carries no number "
                        f"at {self._field}",
                        {**evidence, "effect": request.effect_id},
                    )
                ]
            requested += number
        measured = Decimal(0)
        for row in rows:
            change = self._row_amount(row)
            if change is None:
                return [
                    (
                        f"a {self._table} row{where} holds no number in {self._column}",
                        {**evidence, "row": row.primary_key},
                    )
                ]
            measured += change
        if requested == measured:
            return []
        return [
            (
                f"{self._sink}.{self._operation} asks for {requested} at {self._field}{where}; "
                f"the plan's {self._table} rows record {measured} "
                f"({'inserted' if self._measure == 'inserted' else 'net change'})",
                {**evidence, "requested": str(requested), "measured": str(measured)},
            )
        ]

    def _row_amount(self, row: RowDelta) -> Decimal | None:
        if self._measure == "inserted":
            return _number(row.after.get(self._column)) if row.after is not None else None
        after = Decimal(0)
        before = Decimal(0)
        if row.after is not None:
            value = _number(row.after.get(self._column))
            if value is None:
                return None
            after = value
        if row.before is not None:
            value = _number(row.before.get(self._column))
            if value is None:
                return None
            before = value
        return after - before

    def _compare_values(
        self,
        where: str,
        evidence: dict[str, str],
        requests: list[OutboundDelta],
        rows: list[RowDelta],
    ) -> list[tuple[str, dict[str, str]]]:
        recorded: set[tuple[str, str]] = set()
        for row in rows:
            image = row.after if row.after is not None else row.before
            scalar = _scalar(image.get(self._column)) if image is not None else None
            if scalar is None:
                return [
                    (
                        f"a {self._table} row{where} holds no value in {self._column}",
                        {**evidence, "row": row.primary_key},
                    )
                ]
            recorded.add(scalar)
        if len(recorded) > 1:
            return [
                (
                    f"the plan's {self._table} rows{where} hold {len(recorded)} different "
                    f"{self._column} values, so no request can agree with them",
                    evidence,
                )
            ]
        (expected,) = recorded
        for request in requests:
            found, value = _at(request.payload, self._path)
            if not found or _scalar(value) != expected:
                # Values are not echoed: a recipient or an account is data.
                return [
                    (
                        f"a {self._sink}.{self._operation} request{where} carries a "
                        f"{self._field} other than the {self._column} its {self._table} rows "
                        f"hold",
                        {**evidence, "effect": request.effect_id},
                    )
                ]
        return []

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The rule, never the values: the requested and recorded amounts are
        # the agent's own, but a "value" rule's are data.
        return FeedbackHint(
            kind=Guidance.OUTBOUND_AGREEMENT, tables=(self._table,), columns=(self._column,)
        )


def _scalar(value: object) -> tuple[str, str] | None:
    """A value as it compares: numbers by value, everything else as itself."""
    number = _number(value)
    if number is not None:
        return ("number", format(number.normalize(), "f"))
    if isinstance(value, bool):
        return ("boolean", "true" if value else "false")
    if isinstance(value, str):
        return ("text", value)
    return None


class FactAgreement:
    """Refuse a plan that writes what no consumed inbound fact says.

    An agent's reaction must answer to the event behind it
    (``docs/EPIC5_DESIGN.md`` §2.7). Every row the plan writes to
    ``table.column`` must hold the value ``field`` has in a fact of ``kind``
    the plan consumed: a plan that marks a refund ``failed`` without the
    vendor's attested ``failed`` event is refused. A prompt-injected agent can
    neither claim an event it never received nor rewrite what one said, since
    the facts are read back from the database, attested, never from the plan.
    A pure function of ``(plan, diff)``, like every checker.

    :param kind: The facts that may justify a write: events of this type
        (``"charge.refund.updated"``), or of any of these types.
    :param field: The fact's projected field the row must agree with.
    :param table: The rows held to it: this table's...
    :param column: ...writes of this column. An insert writes it, and so does
        an update that changes it; a delete writes nothing.
    :param key: Pairs facts with rows, as ``(fact_field, key_column)``: a row
        is held only to the facts whose ``fact_field`` equals its
        ``key_column``, so the refund a fact names is the refund written.
        Without it, any consumed fact of ``kind`` saying the value will do.
    :param exempt: Values a row may be written with and no fact: an initial
        state, say ``"pending"``. Exempt nothing, and every write needs a fact.

    A fact and a row that each name a tenant must name the same one. Values
    compare exactly, numbers as ``Decimal``; anything else as itself. The agent
    is told the rule, never the values.

    :raises ValueError: On an empty name, kind or key.
    """

    __slots__ = ("_column", "_exempt", "_field", "_key", "_kinds", "_table")

    def __init__(
        self,
        kind: str | Sequence[str],
        *,
        field: str,
        table: str,
        column: str,
        key: tuple[str, str] | None = None,
        exempt: Sequence[object] = (),
    ) -> None:
        kinds = (kind,) if isinstance(kind, str) else tuple(kind)
        if not kinds or not all(isinstance(k, str) and k.strip() for k in kinds):
            raise ValueError("FactAgreement needs the kind of fact a write answers to")
        for label, value in (("field", field), ("table", table), ("column", column)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"FactAgreement needs a {label}")
        if key is not None and (
            len(key) != 2 or not all(isinstance(k, str) and k.strip() for k in key)
        ):
            raise ValueError("key is a (fact_field, column) pair")
        self._kinds = tuple(sorted(set(kinds)))
        self._field = field
        self._table = table
        self._column = column
        self._key = key
        self._exempt = frozenset(None if v is None else _scalar(v) for v in exempt)

    @property
    def name(self) -> str:
        return f"fact_agreement:{'|'.join(self._kinds)}.{self._field}={self._table}.{self._column}"

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        table = self._table.lower()
        facts = [f for f in diff.facts if f.kind in self._kinds]
        problems: list[tuple[str, str]] = []
        for row in diff.deltas:
            if row.table.lower() != table or row.after is None:
                continue
            if self._column not in row.after:
                continue
            value = row.after[self._column]
            written = None if value is None else _scalar(value)
            if row.before is not None and self._column in row.before:
                prior = row.before[self._column]
                if (None if prior is None else _scalar(prior)) == written:
                    continue
            if written in self._exempt:
                continue
            problem = self._unjustified(row, written, facts)
            if problem is not None:
                problems.append((problem, row.primary_key))
        return tuple(
            InvariantViolation(
                invariant=self.name,
                severity=Severity.BLOCKING,
                message=message,
                evidence={
                    "kind": "|".join(self._kinds),
                    "field": self._field,
                    "rows": f"{self._table}.{self._column}",
                    "row": key,
                },
            )
            for message, key in problems
        )

    def _unjustified(
        self, row: RowDelta, written: tuple[str, str] | None, facts: list[InboundFact]
    ) -> str | None:
        """Why no fact justifies the row's write, or ``None`` when one does.
        Values are not echoed: what a vendor said is data."""
        kinds = " or ".join(self._kinds)
        if written is None:
            # Empty, or not a value at all: no projected field is either.
            return f"the plan writes {self._table}.{self._column} with a value no fact can hold"
        if self._key is not None:
            fact_field, key_column = self._key
            assert row.after is not None
            paired = _scalar(row.after.get(key_column))
            if paired is None:
                return f"a {self._table} row has no {key_column} to pair it with a {kinds} fact"
            facts = [f for f in facts if _scalar(f.fields.get(fact_field)) == paired]
        if row.tenant_id is not None:
            facts = [f for f in facts if f.tenant_id in (None, row.tenant_id)]
        if not facts:
            return (
                f"the plan writes {self._table}.{self._column} without consuming a {kinds} "
                f"fact about that row"
            )
        if any(_scalar(f.fields.get(self._field)) == written for f in facts):
            return None
        return (
            f"the plan writes {self._table}.{self._column} other than the {self._field} its "
            f"{kinds} fact says"
        )

    def hint(
        self, plan: EffectPlan, diff: EffectDiff, violation: InvariantViolation
    ) -> FeedbackHint:
        # The rule, never the values: what the vendor said, and what the row
        # held, are data.
        return FeedbackHint(
            kind=Guidance.FACT_AGREEMENT, tables=(self._table,), columns=(self._column,)
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


def _percent(fraction: Decimal) -> int:
    """A configured fractional limit as a whole percentage, for feedback."""
    return int((fraction * 100).to_integral_value())


BUILT_IN_CHECKERS: frozenset[type] = frozenset(
    {
        CrossEffectAgreement,
        FactAgreement,
        SinkAllowlist,
        OutboundCount,
        PayloadAmountCap,
        RecipientAllowlist,
        OutboundTenantIsolation,
        RateWindowCheck,
        BlastRadius,
        TenantIsolation,
        TableAllowlist,
        NoDelete,
        ColumnValueGuard,
        TenantDrawdownGuard,
        TruncationGuard,
        StatedFootprint,
        NoSchemaChange,
    }
)
"""The checkers whose feedback hints are trusted with numbers. Exact types:
a subclass can override ``hint`` and is treated like any custom checker."""
