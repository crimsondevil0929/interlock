"""The vocabulary of a staged mutation.

Three kinds of object, kept separate because they have different levels of
trust.

*Plans* come from an untrusted agent. A plan holds no credentials and cannot
execute; it is a statement of intent, and nothing in it is believed.

*Diffs* come from the substrate. They are what the database measured, not what
the plan predicted. A statement reporting three affected rows can cascade
through triggers into six real mutations, and only the substrate sees that.

*Verdicts* come from a deterministic predicate over a diff. They are pure
functions of ``(plan, diff)``, so re-running one on the recorded inputs gives
the same answer.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final, NewType

__all__ = [
    "AUDIT_VERSION",
    "GENESIS_HASH",
    "CommitReceipt",
    "Compensation",
    "Effect",
    "EffectDiff",
    "EffectId",
    "EffectKind",
    "EffectOutcome",
    "EffectPlan",
    "InvariantViolation",
    "PlanId",
    "RowDelta",
    "Severity",
    "StageHandle",
    "StageState",
    "SubstrateCapabilities",
    "Verdict",
    "canonical_hash",
    "iso",
]

PlanId = NewType("PlanId", str)
EffectId = NewType("EffectId", str)

AUDIT_VERSION: Final = "ILOK1"
"""Chain version tag. Distinct from AgentGov's ``AGOV1`` so a record from one
chain can never be replayed as a record of the other."""

GENESIS_HASH: Final = "0" * 64


def iso(moment: datetime) -> str:
    """Render a timestamp as UTC ISO-8601 with an explicit offset."""
    return moment.isoformat()


def canonical_hash(fields: Sequence[object]) -> str:
    """Hash a fixed-order field list.

    A JSON list rather than a delimiter-joined string, matching AgentGov. Table
    names, tenant ids and statements are all attacker-influenceable, and a
    delimiter-joined payload can be forged by embedding the delimiter.

    :param fields: Values in a fixed order. Order is part of the contract;
        reordering changes every downstream hash.
    :returns: Lowercase SHA-256 hex digest.
    """
    payload = json.dumps(
        [AUDIT_VERSION, *fields],
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Vocabularies
# --------------------------------------------------------------------------


class EffectKind(Enum):
    """The class of mutation an effect performs."""

    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    DDL = "ddl"
    ENQUEUE = "enqueue"
    """A post-commit obligation written to a transactional outbox, rather than
    a direct external call. An email has no shadow, so it becomes a row that
    does, and a separate relay delivers it after commit.

    Defined but not implemented as of v0.1.0: nothing reads this kind.
    """


class StageState(Enum):
    """Where a plan is in the escrow lifecycle."""

    PLANNED = "planned"
    STAGING = "staging"
    STAGED = "staged"
    VERIFIED = "verified"
    REJECTED = "rejected"
    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"


class Severity(Enum):
    ADVISORY = "advisory"
    """Recorded on the verdict; does not block the commit."""

    BLOCKING = "blocking"
    """Forces rejection. There is no in-process override. Overriding means
    submitting a new plan that carries an explicit waiver, which is then itself
    a recorded artifact."""


# --------------------------------------------------------------------------
# Plans: what the agent proposes
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Compensation:
    """A pre-computed undo, serialized before its effect is applied.

    The ordering is a hard requirement: if the undo cannot be written down, the
    effect is not admitted. See ``EscrowEngine.admit``.

    :ivar idempotency_key: Deterministic in ``(plan_id, effect_id)``, so a
        compensation replayed after a crash cannot apply twice.
    """

    statement: str
    parameters: Mapping[str, object] = field(default_factory=dict)
    idempotency_key: str = ""


@dataclass(frozen=True, slots=True)
class Effect:
    """One intended mutation.

    :ivar target: Substrate-qualified resource, ``"<substrate_id>:<table>"``.
    :ivar statement: A parameterised statement. Parameters are bound by the
        driver and are never interpolated into this string. The agent authors
        both fields and is untrusted.
    :ivar depends_on: Effects that must be applied first. Defines the DAG.
    :ivar reversible: Whether the substrate can roll this back natively.
    :ivar stated_rows: What the agent claims this will touch, recorded so the
        claim can be compared against the measurement. Never trusted, and
        optional: an agent that omits it disables ``StatedFootprint``.
    """

    effect_id: EffectId
    kind: EffectKind
    target: str
    statement: str
    parameters: Mapping[str, object] = field(default_factory=dict)
    depends_on: tuple[EffectId, ...] = ()
    tenant_id: str | None = None
    reversible: bool = True
    compensation: Compensation | None = None
    stated_rows: int | None = None

    @property
    def table(self) -> str:
        """The bare table name, with the substrate prefix stripped."""
        _, _, rest = self.target.partition(":")
        return rest or self.target

    @property
    def substrate_id(self) -> str:
        head, sep, _ = self.target.partition(":")
        return head if sep else ""

    def content_hash(self) -> str:
        return canonical_hash(
            [
                self.effect_id,
                self.kind.value,
                self.target,
                self.statement,
                sorted((k, str(v)) for k, v in self.parameters.items()),
                list(self.depends_on),
                self.tenant_id,
                self.reversible,
            ]
        )


@dataclass(frozen=True, slots=True)
class EffectPlan:
    """A complete unit of intended change.

    The plan is the atomic unit of staging, verification and commit. Its
    effects either all land or none do.

    :ivar scope_id: The AgentGov scope accountable for this plan. Used for the
        halted-scope check before commit.
    :ivar trajectory_id: The logical unit of work, matching AgentGov's
        trajectory notion, so an orchestrator retrying through fresh
        sub-agents is still one trajectory.
    """

    plan_id: PlanId
    scope_id: str
    trajectory_id: str
    created_at: datetime
    effects: tuple[Effect, ...]
    intent: str = ""
    """The agent's own description. Recorded for the audit trail; no checker
    reads it."""

    def topological_order(self) -> tuple[Effect, ...]:
        """Effects in a deterministic execution order.

        Ties break on ``effect_id`` ascending. A plan that stages in a
        different order on replay produces a different diff, which would
        destroy the replay guarantee, so the order is part of the contract.

        :raises ValueError: On a dependency cycle or an unknown dependency.
        """
        by_id = {effect.effect_id: effect for effect in self.effects}
        for effect in self.effects:
            for dependency in effect.depends_on:
                if dependency not in by_id:
                    raise ValueError(
                        f"effect {effect.effect_id!r} depends on unknown {dependency!r}"
                    )

        ordered: list[Effect] = []
        placed: set[EffectId] = set()
        remaining = sorted(self.effects, key=lambda e: e.effect_id)
        while remaining:
            ready = [e for e in remaining if all(d in placed for d in e.depends_on)]
            if not ready:
                stuck = ", ".join(sorted(e.effect_id for e in remaining))
                raise ValueError(f"dependency cycle among effects: {stuck}")
            for effect in ready:
                ordered.append(effect)
                placed.add(effect.effect_id)
            remaining = [e for e in remaining if e.effect_id not in placed]
        return tuple(ordered)

    @property
    def stated_rows(self) -> int | None:
        """The agent's own total claim, when every effect declared one."""
        claims = [e.stated_rows for e in self.effects]
        if any(c is None for c in claims):
            return None
        return sum(c for c in claims if c is not None)

    def content_hash(self) -> str:
        return canonical_hash(
            [
                self.plan_id,
                self.scope_id,
                self.trajectory_id,
                iso(self.created_at),
                [e.content_hash() for e in self.topological_order()],
            ]
        )


# --------------------------------------------------------------------------
# Diffs: what the substrate measured
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RowDelta:
    """One row's before and after image.

    ``before is None`` is an insert. ``after is None`` is a delete.
    """

    table: str
    primary_key: str
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    tenant_id: str | None = None

    @property
    def operation(self) -> str:
        if self.before is None:
            return "insert"
        if self.after is None:
            return "delete"
        return "update"

    def changed_columns(self) -> tuple[str, ...]:
        """Columns whose value actually moved. Empty for inserts and deletes."""
        if self.before is None or self.after is None:
            return ()
        return tuple(sorted(k for k in self.after if self.before.get(k) != self.after.get(k)))


@dataclass(frozen=True, slots=True)
class EffectDiff:
    """The delta a stage would commit, as measured by the substrate.

    :ivar truncated: Set when the row cap was reached. The diff is then a
        prefix of the real delta, and any predicate that needs completeness
        must fail closed against it. See ``invariants.TruncationGuard``.
    """

    plan_id: PlanId
    stage_id: uuid.UUID
    substrate_id: str
    computed_at: datetime
    deltas: tuple[RowDelta, ...]
    truncated: bool = False

    @property
    def rows_inserted(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "insert")

    @property
    def rows_updated(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "update")

    @property
    def rows_deleted(self) -> int:
        return sum(1 for d in self.deltas if d.operation == "delete")

    @property
    def blast_radius(self) -> int:
        """Captured mutations. NOT a distinct-row count: a row mutated twice
        inside one plan contributes 2, so this is an upper bound on rows
        touched. Use it as a bound, not as a row tally."""
        return len(self.deltas)

    @property
    def tables_touched(self) -> frozenset[str]:
        return frozenset(d.table for d in self.deltas)

    @property
    def tenant_ids(self) -> frozenset[str]:
        return frozenset(d.tenant_id for d in self.deltas if d.tenant_id is not None)

    @property
    def tenant_count(self) -> int:
        """Distinct tenants touched, as a radius axis independent of row count.

        Reads the tenant label out of the captured row image, so it is 0 for
        any table whose ``TableSpec.tenant_column`` is not also listed in
        ``TableSpec.columns``.
        """
        return len(self.tenant_ids)

    def column_total(self, table: str, column: str) -> tuple[Decimal, Decimal]:
        """Sum a numeric column across this diff, before and after.

        Exact, not approximate. Every value is routed through
        ``Decimal(str(value))`` rather than binary floating point, because this
        total is the input to a financial predicate: a guard that permits a
        30% drawdown must not admit a 30.000000000000004% one because two
        representations of the same cent did not compare equal. The cost is
        that a column of IEEE doubles is summed at the precision it was
        *printed* with, which is the precision it was meant to have.

        Rows absent from one side contribute zero to that side, which is the
        correct treatment for inserts and deletes.

        :returns: ``(before_total, after_total)`` as exact decimals.
        """
        before = after = Decimal(0)
        for delta in self.deltas:
            if delta.table != table:
                continue
            if delta.before is not None:
                before += _as_decimal(delta.before.get(column))
            if delta.after is not None:
                after += _as_decimal(delta.after.get(column))
        return before, after

    def tenant_column_totals(self, table: str, column: str) -> dict[str, tuple[Decimal, Decimal]]:
        """As :meth:`column_total`, but grouped by tenant.

        The whole-table total is the wrong denominator on a multi-tenant
        substrate: draining one tenant completely is a small fraction of a
        platform-wide sum, so a table-scoped guard admits a single-tenant
        wipe. Rows whose tenant could not be read group under ``""``.

        :returns: ``{tenant_id: (before_total, after_total)}``.
        """
        totals: dict[str, tuple[Decimal, Decimal]] = {}
        for delta in self.deltas:
            if delta.table != table:
                continue
            tenant = delta.tenant_id or ""
            before, after = totals.get(tenant, (Decimal(0), Decimal(0)))
            if delta.before is not None:
                before += _as_decimal(delta.before.get(column))
            if delta.after is not None:
                after += _as_decimal(delta.after.get(column))
            totals[tenant] = (before, after)
        return totals

    def content_hash(self) -> str:
        rows = [
            [d.table, d.primary_key, d.operation, d.before, d.after, d.tenant_id]
            for d in sorted(self.deltas, key=lambda d: (d.table, d.primary_key, d.operation))
        ]
        return canonical_hash([self.plan_id, self.substrate_id, self.truncated, rows])


def _as_decimal(value: object) -> Decimal:
    """Coerce a column value to an exact Decimal, non-numerics to zero.

    ``bool`` is excluded deliberately: it is an ``int`` subclass in Python, and
    summing a status flag into a money column is never what was meant.
    ``str`` is accepted because SQLite is dynamically typed and a NUMERIC
    column can hand back text; an unparseable string contributes zero rather
    than raising, since a checker that dies on one bad row approves nothing.
    """
    if isinstance(value, bool):
        return Decimal(0)
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float | str):
        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError):
            return Decimal(0)
    return Decimal(0)


# --------------------------------------------------------------------------
# Verdicts: what a deterministic predicate decided
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InvariantViolation:
    invariant: str
    severity: Severity
    message: str
    evidence: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Verdict:
    """The admission decision for one staged diff."""

    plan_id: PlanId
    stage_id: uuid.UUID
    diff_hash: str
    decided_at: datetime
    checkers_run: tuple[str, ...]
    violations: tuple[InvariantViolation, ...]

    @property
    def blocking(self) -> tuple[InvariantViolation, ...]:
        return tuple(v for v in self.violations if v.severity is Severity.BLOCKING)

    @property
    def admitted(self) -> bool:
        return not self.blocking

    def content_hash(self) -> str:
        return canonical_hash(
            [
                self.plan_id,
                self.diff_hash,
                self.admitted,
                list(self.checkers_run),
                [[v.invariant, v.severity.value, v.message] for v in self.violations],
            ]
        )


# --------------------------------------------------------------------------
# Substrate handles
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SubstrateCapabilities:
    """What a driver supports, declared rather than inferred.

    The engine reads these to decide whether a plan is stageable. A driver that
    overstates them turns an enforced property into an unchecked assumption, so
    a new driver's values are part of its review.
    """

    transactional: bool
    row_level_diff: bool
    snapshot_isolation: bool
    requires_compensation: bool
    max_stage_seconds: float = 10.0
    max_diff_rows: int = 50_000


@dataclass(frozen=True, slots=True)
class StageHandle:
    """Opaque token identifying one open stage.

    Binds a plan to a single physical connection. Do not serialize it across
    processes. The process that opened the stage owns it; an open transaction
    with no live owner holds write locks until something reaps it.
    """

    stage_id: uuid.UUID
    plan_id: PlanId
    substrate_id: str
    opened_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class EffectOutcome:
    """Result of applying one effect inside a stage."""

    effect_id: EffectId
    rows_affected: int
    applied_at: datetime


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    """Evidence that a stage was made durable."""

    stage_id: uuid.UUID
    plan_id: PlanId
    committed_at: datetime
    diff_hash: str
    verdict_hash: str
    substrate_txn_id: str | None = None
