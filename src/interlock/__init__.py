"""Interlock: a reference monitor for agent side effects.

An agent proposes a plan. It holds no credentials and cannot execute. Interlock
applies the plan against a real but uncommitted substrate, measures what
actually changed, evaluates deterministic predicates against that measurement,
and only then commits or rolls back.

The position exists because a prompt-injected agent is a fully authorized
agent. It is doing something it has permission to do, so an authorization check
passes, and the injected instruction arrived inside a tool result after every
provider-side filter had run, so a provider-side filter does not see it. What
is left is measuring the consequence before it becomes durable.

    from interlock import EscrowEngine, EscrowChain, SqliteSubstrate, TableSpec
    from interlock import default_checkers

    substrate = SqliteSubstrate("prod.db", tables=[TableSpec("orders", columns=[...])])
    engine = EscrowEngine(
        substrate,
        checkers=default_checkers(row_limit=50, allowed_tables=["orders"]),
        chain=EscrowChain("escrow.jsonl"),   # omit and the chain is in memory only
    )
    result = engine.execute(plan)

    if not result.committed:
        print(result.blocked_by, result.diff.blast_radius)

Every adjudication is written to a hash-linked chain, anchored to an AgentGov
ledger when one is attached. See :mod:`interlock.anchor` for the seam, which is
read-only by default.

v0.1.0 is one substrate (SQLite) and a measurement scoped to the tables that
substrate was configured to observe. ``docs/ESCROW_SPEC.md`` has a conformance
section listing what is implemented, partial and unimplemented; read it before
putting this in front of a production database.
"""

from __future__ import annotations

from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.engine import EscrowEngine, StageResult
from interlock.exceptions import (
    AdmissionError,
    AnchorError,
    ChainIntegrityError,
    CyclicPlanError,
    InterlockError,
    LedgerUnverifiedError,
    PlanError,
    ScopeHaltedError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateUnavailableError,
    UncompensatableEffectError,
)
from interlock.invariants import (
    BlastRadius,
    ColumnValueGuard,
    InvariantChecker,
    NoDelete,
    NoSchemaChange,
    StatedFootprint,
    TableAllowlist,
    TenantIsolation,
    TruncationGuard,
    default_checkers,
)
from interlock.substrate import ShadowSubstrate, SqliteSubstrate, TableSpec
from interlock.types import (
    Compensation,
    Effect,
    EffectDiff,
    EffectId,
    EffectKind,
    EffectPlan,
    InvariantViolation,
    PlanId,
    RowDelta,
    Severity,
    StageState,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "AdmissionError",
    "AnchorError",
    "AnchorPoint",
    "BlastRadius",
    "ChainIntegrityError",
    "ColumnValueGuard",
    "Compensation",
    "CyclicPlanError",
    "Effect",
    "EffectDiff",
    "EffectId",
    "EffectKind",
    "EffectPlan",
    "EscrowChain",
    "EscrowEngine",
    "EscrowRecord",
    "InterlockError",
    "InvariantChecker",
    "InvariantViolation",
    "LedgerAnchor",
    "LedgerUnverifiedError",
    "NoDelete",
    "NoSchemaChange",
    "PlanError",
    "PlanId",
    "RecordType",
    "RowDelta",
    "ScopeHaltedError",
    "Severity",
    "ShadowSubstrate",
    "SqliteSubstrate",
    "StageConflictError",
    "StageError",
    "StageExpiredError",
    "StageResult",
    "StageState",
    "StatedFootprint",
    "SubstrateUnavailableError",
    "TableAllowlist",
    "TableSpec",
    "TenantIsolation",
    "TruncationGuard",
    "UncompensatableEffectError",
    "Verdict",
    "__version__",
    "default_checkers",
]
