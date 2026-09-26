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

    from interlock import EscrowRuntime, TableSpec

    runtime = EscrowRuntime(
        "prod.db",
        tables=[TableSpec("orders", columns=["id", "tenant", "total"],
                          tenant_column="tenant")],
        scope_id="support-agent",
    )
    result = runtime.execute_sql(
        "UPDATE orders SET total = :total WHERE id = :id",
        {"total": 100.0, "id": 1},
        tenant_id="acme",
        stated_rows=1,
    )

    if not result.committed:
        print(result.blocked_by, result.diff.blast_radius)

``EscrowRuntime`` owns the substrate, chain, anchor and engine. Drop to
:class:`EscrowEngine` and :class:`PlanBuilder` when you need the primitives;
the runtime is sugar over them and hands both back.

Every adjudication is written to a hash-linked chain, anchored to an AgentGov
ledger when one is attached. See :mod:`interlock.anchor` for the seam, which is
read-only by default.

Two substrates, SQLite and PostgreSQL, and a measurement scoped to the tables
each was configured to observe. ``docs/ESCROW_SPEC.md`` has a conformance
section listing what is implemented, partial and unimplemented; read it before
putting this in front of a production database.
"""

from __future__ import annotations

from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.builder import PlanBuilder, new_effect_id, new_plan_id
from interlock.cascade import CascadeReport
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.engine import EscrowEngine, StageResult
from interlock.exceptions import (
    AdmissionError,
    AnchorError,
    ChainIntegrityError,
    ChainInUseError,
    CommitUnsettledError,
    CyclicPlanError,
    ExtensionError,
    ForbiddenStatementError,
    InterlockError,
    LedgerUnverifiedError,
    PlanError,
    RecordIntegrityError,
    RecoveryError,
    RecoveryExhaustedError,
    ScopeHaltedError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
    ToolRevokedError,
    UncompensatableEffectError,
)
from interlock.extension import (
    BudgetGuard,
    Estimate,
    ExtensionGrant,
    ExtensionRequest,
    Milestones,
    Progress,
    Spend,
)
from interlock.feedback import AgentFeedback, ConstraintFeedback, OperatorEvidence, Refusal
from interlock.invariants import (
    BlastRadius,
    ColumnValueGuard,
    InvariantChecker,
    NoDelete,
    NoSchemaChange,
    StatedFootprint,
    TableAllowlist,
    TenantDrawdownGuard,
    TenantIsolation,
    TruncationGuard,
    default_checkers,
)
from interlock.postgres import PostgresSubstrate
from interlock.receipts import ReceiptIssuer
from interlock.records import RecordKind, RecordLog, SignedRecord, check_anchors, verify_records
from interlock.recovery import (
    Channel,
    Directive,
    RecoveryPolicy,
    RecoveryRuntime,
    RecoveryStep,
    Rung,
    Trip,
    TripKind,
)
from interlock.repair import DroppedEffect, Repair, RepairFeedback
from interlock.runtime import EscrowRuntime
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

__version__ = "0.1.2"

__all__ = [
    "AdmissionError",
    "AgentFeedback",
    "AnchorError",
    "AnchorPoint",
    "BlastRadius",
    "BudgetGuard",
    "CascadeReport",
    "ChainInUseError",
    "ChainIntegrityError",
    "Channel",
    "ColumnValueGuard",
    "CommitUnsettledError",
    "Compensation",
    "ConstraintFeedback",
    "CyclicPlanError",
    "Directive",
    "DroppedEffect",
    "Effect",
    "EffectDiff",
    "EffectId",
    "EffectKind",
    "EffectPlan",
    "EscrowChain",
    "EscrowEngine",
    "EscrowRecord",
    "EscrowRuntime",
    "Estimate",
    "ExtensionError",
    "ExtensionGrant",
    "ExtensionRequest",
    "ForbiddenStatementError",
    "InterlockError",
    "InvariantChecker",
    "InvariantViolation",
    "LedgerAnchor",
    "LedgerUnverifiedError",
    "Milestones",
    "NoDelete",
    "NoSchemaChange",
    "OperatorEvidence",
    "PlanBuilder",
    "PlanError",
    "PlanId",
    "PostgresSubstrate",
    "Progress",
    "ReceiptIssuer",
    "RecordIntegrityError",
    "RecordKind",
    "RecordLog",
    "RecordType",
    "RecoveryError",
    "RecoveryExhaustedError",
    "RecoveryPolicy",
    "RecoveryRuntime",
    "RecoveryStep",
    "Refusal",
    "Repair",
    "RepairFeedback",
    "RowDelta",
    "Rung",
    "ScopeHaltedError",
    "Severity",
    "ShadowSubstrate",
    "SignedRecord",
    "Spend",
    "SqliteSubstrate",
    "StageConflictError",
    "StageError",
    "StageExpiredError",
    "StageResult",
    "StageState",
    "StatedFootprint",
    "SubstrateConfigurationError",
    "SubstrateUnavailableError",
    "TableAllowlist",
    "TableSpec",
    "TenantDrawdownGuard",
    "TenantIsolation",
    "ToolRevokedError",
    "Trip",
    "TripKind",
    "TruncationGuard",
    "UncompensatableEffectError",
    "Verdict",
    "__version__",
    "check_anchors",
    "default_checkers",
    "new_effect_id",
    "new_plan_id",
    "verify_records",
]
