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

from interlock.adapters import HttpAdapter
from interlock.anchor import AnchorPoint, LedgerAnchor
from interlock.builder import PlanBuilder, new_effect_id, new_plan_id
from interlock.cascade import CascadeReport
from interlock.chain import EscrowChain, EscrowRecord, RecordType
from interlock.deliveries import verify_delivery_log
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
    OutboundRequestError,
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
    CrossEffectAgreement,
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
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.outbound_checks import (
    OutboundCount,
    OutboundTenantIsolation,
    PayloadAmountCap,
    RecipientAllowlist,
    SinkAllowlist,
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
from interlock.relay import (
    Delivery,
    DeliveryResult,
    LedgerBreaker,
    NoBreaker,
    Relay,
    RelayReport,
    SinkAdapter,
    retry_delay,
)
from interlock.repair import DroppedEffect, Repair, RepairFeedback
from interlock.runtime import EscrowRuntime
from interlock.settlement import SettlementReport, Settler, verify_settlements
from interlock.substrate import ShadowSubstrate, SqliteSubstrate, TableSpec
from interlock.types import (
    Compensation,
    Effect,
    EffectDiff,
    EffectId,
    EffectKind,
    EffectPlan,
    InvariantViolation,
    OutboundRequest,
    PlanId,
    RowDelta,
    Severity,
    StageState,
    Verdict,
    WindowMeasure,
)
from interlock.windows import (
    Plans,
    RateWindow,
    RateWindowCheck,
    Requests,
    RequestSum,
    RowSum,
)

__version__ = "0.4.0"

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
    "CrossEffectAgreement",
    "CyclicPlanError",
    "Delivery",
    "DeliveryResult",
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
    "HttpAdapter",
    "InterlockError",
    "InvariantChecker",
    "InvariantViolation",
    "LedgerAnchor",
    "LedgerBreaker",
    "LedgerUnverifiedError",
    "Milestones",
    "NoBreaker",
    "NoDelete",
    "NoSchemaChange",
    "OperationSpec",
    "OperatorEvidence",
    "OutboundCount",
    "OutboundRequest",
    "OutboundRequestError",
    "OutboundTenantIsolation",
    "PayloadAmountCap",
    "PlanBuilder",
    "PlanError",
    "PlanId",
    "Plans",
    "PostgresSubstrate",
    "Progress",
    "RateWindow",
    "RateWindowCheck",
    "ReceiptIssuer",
    "RecipientAllowlist",
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
    "Relay",
    "RelayReport",
    "Repair",
    "RepairFeedback",
    "RequestSum",
    "Requests",
    "RowDelta",
    "RowSum",
    "Rung",
    "ScopeHaltedError",
    "SettlementReport",
    "Settler",
    "Severity",
    "ShadowSubstrate",
    "SignedRecord",
    "SinkAdapter",
    "SinkAllowlist",
    "SinkRegistry",
    "SinkSpec",
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
    "WindowMeasure",
    "__version__",
    "check_anchors",
    "default_checkers",
    "new_effect_id",
    "new_plan_id",
    "retry_delay",
    "verify_delivery_log",
    "verify_records",
    "verify_settlements",
]
