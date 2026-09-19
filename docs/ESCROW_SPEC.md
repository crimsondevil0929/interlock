# Effect escrow: specification and interface contract

**Status:** specification. `interlock` v0.1.0 implements a subset; see
[Conformance](#conformance-of-interlock-v010) at the end of this document for
what is implemented, what is partial, and what is unimplemented.
**Applies to:** `interlock` v0.1.0 against `agentgov` v0.1.0.
**Normative language:** MUST, MUST NOT, SHOULD, MAY per RFC 2119.

---

## Preamble: package boundary

`interlock` is a **separate sibling package and repository**. It is not a
subpackage of `agentgov`, not an optional extra of `agentgov`, and not a plugin
loaded by `agentgov`.

The dependency is one-way and read-only:

```
    interlock  ──── imports ───▶  agentgov      (permitted)
    agentgov   ──── imports ───▶  interlock     (FORBIDDEN)
```

`interlock` imports `agentgov` **purely as a read-only audit dependency**. It
opens the governor's SQLite ledger through
`BudgetManager.open_sqlite(path, read_only=True)`, reads the hash chain, and
anchors its own records to that chain. It does not write to the ledger, does not
subclass `Ledger` or `BudgetManager`, and does not depend on any private name.

`agentgov` v0.1.0 is frozen. Nothing in this document requires a change to
`src/agentgov/`. If a requirement here appears to need one, the requirement is
wrong and MUST be redesigned around the existing public surface.

The `agentgov` surface listed in section 3.1 is the compatibility promise.
Changing it is a breaking change for `interlock`.

### Why the boundary is drawn here

The escrow layer holds write credentials to production systems. The governor
holds the audit record. Fusing them puts a write-path component inside the trust
boundary of the record that has to survive an incident involving that component.
The two MUST fail independently: a crashed escrow leaves the ledger intact and
verifiable, and a corrupt ledger blocks the escrow from staging rather than
silently degrading it.

---

# 1. Core thesis and state machine

## 1.1 Thesis

Authorization is a predicate on permission, not on correctness. An agent may be
fully entitled to update inventory and still write ten thousand wrong rows.

The blocking problem for autonomous write access is not entitlement. It is that
side effects are **irreversible and unpreviewable**. The current mitigation is a
human approving a prose summary produced by the same model requesting approval.
That is not review. It also does not survive a five-hundred-step agent, because
the number of approval points scales with the autonomy horizon while human
attention does not.

Interlock separates **deciding** from **committing**. The agent proposes a
plan. The escrow executes it against a real but uncommitted substrate, computes
the measured consequence, evaluates deterministic invariants against that
consequence, and only then commits. The artifact presented for review is a
row-level diff, not a summary.

## 1.2 Lifecycle

```
                       ┌───────────┐
        plan admitted  │  PLANNED  │   no substrate touched
                       └─────┬─────┘
                             │ open(plan)            AgentGov: HOLD
                       ┌─────▼─────┐
                       │  STAGING  │   transaction open, effects applying
                       └─────┬─────┘
            apply(effect)xN  │
                       ┌─────▼─────┐
                       │  STAGED   │───── diff() ────▶  EffectDiff
                       └─────┬─────┘
                             │ check(plan, diff)
                     ┌───────┴────────┐
            admitted │                │ violated (severity=BLOCKING)
                ┌────▼─────┐     ┌────▼─────┐
                │ VERIFIED │     │ REJECTED │
                └────┬─────┘     └────┬─────┘
                     │ commit()       │ abort()
      AgentGov:      │                │      AgentGov: HOLD_VOID
      HOLD_VOID      │                │
      + SPEND   ┌────▼─────┐     ┌────▼─────┐
                │COMMITTED │     │ ABORTED  │  (terminal)
                └────┬─────┘     └──────────┘
                     │ compensate()
                     │                        AgentGov: REVERSAL
               ┌─────▼────────┐
               │ COMPENSATED  │  (terminal)
               └──────────────┘

  Orphan path, from STAGING or STAGED:

    process death  ─┐
    max_stage_secs ─┴──▶ ┌──────────┐ ──▶ ABORTED
                         │ ORPHANED │   reaper rolls back the substrate
                         └──────────┘   and voids the AgentGov hold
```

### 1.2.1 State definitions

| State | Substrate | Terminal | Meaning |
|---|---|---|---|
| `PLANNED` | untouched | no | Plan parsed, DAG validated, admission checks passed |
| `STAGING` | transaction open | no | Effects applying in topological order |
| `STAGED` | transaction open | no | All effects applied, diff computable |
| `VERIFIED` | transaction open | no | Invariants ran, no blocking violation |
| `REJECTED` | transaction open | no | At least one blocking violation |
| `COMMITTED` | committed | yes | Durable |
| `ABORTED` | rolled back | yes | No effect reached the substrate |
| `ORPHANED` | transaction open, owner gone | no | Stage exceeded its bound or its process died |
| `COMPENSATED` | compensating actions applied | yes | Post-commit undo completed |

### 1.2.2 Transition requirements

- **E1-1.** A plan MUST NOT touch a substrate before reaching `PLANNED`.
- **E1-2.** `diff()` MUST be callable only in `STAGED` or `VERIFIED`. Calling it
  in `STAGING` is an error, because the diff would be partial and a partial diff
  presented as complete is worse than no diff.
- **E1-3.** `commit()` MUST be reachable only from `VERIFIED`. There is no path
  from `STAGED` to `COMMITTED` that skips invariant evaluation.
- **E1-4.** `REJECTED` MUST transition to `ABORTED`. It MUST NOT be overridable
  in-process. An operator override MUST be expressed as a new plan carrying an
  explicit waiver, so the override is itself a first-class recorded artifact
  rather than a mutable flag.
- **E1-5.** Every non-terminal state MUST carry an expiry. A stage that reaches
  `expires_at` transitions to `ORPHANED` regardless of owner liveness.
- **E1-6.** `COMPENSATED` is reachable only from `COMMITTED`, and only for plans
  whose effects carried serialized compensations at admission time.

## 1.3 Mapping onto AgentGov primitives

The four escrow transitions are not analogous to AgentGov's entry types. They
are the same state machine with the unit of account generalized from currency to
staged mutation. AgentGov encumbers dollars; Interlock encumbers rows.

| AgentGov | Posted by | Interlock meaning |
|---|---|---|
| `HOLD` (DEBIT) | `authorize()` | **Staged mutation.** Resource encumbered, not visible to concurrent readers, not yet real. |
| `HOLD_VOID` + `SPEND` (one transaction) | `capture()` | **Committed effect.** The encumbrance is lifted and converted into a durable outflow. |
| `HOLD_VOID` (alone) | `void()` | **Aborted stage.** The encumbrance is released with nothing settled. |
| `REVERSAL` (CREDIT) | `refund()` | **Compensating transaction.** A previously committed effect is undone after the fact. |

Three properties come from this mapping for free, and MUST be relied on rather
than reimplemented:

- **E1-7.** Double-commit protection. `capture()` on an authorization that has
  already been captured raises `DoubleSpendError`. An escrow stage whose commit
  path is driven through `capture()` therefore inherits idempotency at the
  ledger boundary. Interlock MUST NOT implement a second, weaker guard.
- **E1-8.** Orphan detection. `stale_authorizations(older_than)` and
  `void_stale(older_than)` already enumerate and release holds abandoned between
  `authorize()` and `capture()`. The escrow reaper MUST use these for the
  AgentGov side of an `ORPHANED` stage rather than maintaining a parallel index.
- **E1-9.** Conservation. `verify_conservation()` proves that
  `Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded`.
  The escrow's analogous invariant is that every stage is eventually
  `COMMITTED`, `ABORTED`, or `COMPENSATED`, with no stage both committed and
  aborted. This MUST be checkable offline from the escrow chain alone, by the
  same argument.

### 1.3.1 Cost governance is orthogonal and optional

An escrow plan MAY be cost-governed, in which case the `HOLD` it opens is a real
AgentGov authorization sized by the plan's expected model and tool cost. A plan
MAY also be cost-free, in which case no AgentGov entry is posted and the escrow
chain stands alone.

Both modes MUST anchor to the ledger per section 3. Anchoring is about evidence
ordering and is independent of whether money moved.

---

# 2. Interface contract

Conventions follow `agentgov`: `Protocol` for pluggable behaviour, frozen
`slots` dataclasses for data, `Enum` for closed vocabularies, no inheritance
from concrete classes. Every type is exported from `interlock.types` unless
noted.

## 2.1 Identifiers and vocabularies

```python
from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final, NewType, Protocol, runtime_checkable

PlanId = NewType("PlanId", str)
EffectId = NewType("EffectId", str)

ESCROW_AUDIT_VERSION: Final = "AESC1"
GENESIS_HASH: Final = "0" * 64


class EffectKind(Enum):
    """The class of mutation an effect performs."""

    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    UPSERT = "upsert"
    DDL = "ddl"
    ENQUEUE = "enqueue"
    """A post-commit obligation written to a transactional outbox. Never a
    direct external call: see section 4.4."""


class StageState(Enum):
    PLANNED = "planned"
    STAGING = "staging"
    STAGED = "staged"
    VERIFIED = "verified"
    REJECTED = "rejected"
    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"
    COMPENSATED = "compensated"


class Severity(Enum):
    ADVISORY = "advisory"
    """Recorded on the verdict, does not block the commit."""

    BLOCKING = "blocking"
    """Forces REJECTED. Not overridable in-process (E1-4)."""
```

## 2.2 `EffectPlan`

The typed DAG the agent emits. The agent produces this structure and nothing
else. It MUST NOT hold substrate credentials and MUST NOT be able to execute.

```python
@dataclass(frozen=True, slots=True)
class Compensation:
    """A pre-computed undo for one effect.

    Serialized at plan admission, before the effect is staged. If the
    compensation cannot be constructed, the plan is rejected: an effect whose
    undo cannot be written down MUST NOT be committed against a substrate that
    cannot roll it back.

    :ivar statement: Parameterised statement or serialized request.
    :ivar idempotency_key: Deterministic in ``(plan_id, effect_id)``, so a
        replayed compensation after a crash cannot double-apply.
    :ivar expires_at: After this instant the compensation is presumed
        ineffective and the stage is escalated rather than auto-undone.
    """

    statement: str
    parameters: Mapping[str, object]
    idempotency_key: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Effect:
    """One intended mutation.

    :ivar target: Substrate-qualified resource, ``"<substrate_id>:<locator>"``,
        e.g. ``"pg-main:public.orders"``. Parsed by the substrate, opaque here.
    :ivar statement: Parameterised statement. Parameters are never interpolated
        into this string; see E2-3.
    :ivar depends_on: Effects that MUST be applied first. Defines the DAG.
    :ivar tenant_id: Tenancy label, used by blast-radius invariants. ``None``
        means the effect is not tenant-scoped, which is itself a policy signal.
    :ivar reversible: Whether the substrate can roll this back natively.
    :ivar compensation: Required when ``reversible`` is ``False``.
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


@dataclass(frozen=True, slots=True)
class EffectPlan:
    """A complete unit of intended change.

    A plan is the atomic unit of staging, verification and commit. Effects
    within a plan either all commit or none do, for substrates that support it.

    :ivar scope_id: The AgentGov scope accountable for this plan. Used for the
        halted-scope check (E3-6) and for cost governance when enabled.
    :ivar trajectory_id: The logical unit of work, matching the cognitive
        breaker's trajectory notion. Distinct from ``scope_id`` when an
        orchestrator retries via fresh sub-agents.
    """

    plan_id: PlanId
    scope_id: str
    trajectory_id: str
    created_at: datetime
    effects: tuple[Effect, ...]

    def topological_order(self) -> tuple[Effect, ...]:
        """Effects in a valid execution order.

        :raises CyclicPlanError: If ``depends_on`` contains a cycle.
        :raises UnknownEffectError: If a dependency names an absent effect.
        """
        ...

    def content_hash(self) -> str:
        """SHA-256 over the canonical serialization (section 3.3)."""
        ...
```

Requirements:

- **E2-1.** `topological_order()` MUST be deterministic. Where the DAG admits
  several valid orders, ties MUST break on `effect_id` ascending. A plan that
  stages in a different order on replay produces a different diff, which
  destroys the replay guarantee.
- **E2-2.** A plan MUST be rejected at admission if any effect has
  `reversible=False` and `compensation=None`, or if the target substrate reports
  `requires_compensation=True` for that effect kind. Fail closed at admission,
  not at commit.
- **E2-3.** `statement` MUST be a parameterised template. Substrate drivers MUST
  bind `parameters` through the driver's own parameter binding. A driver that
  string-formats parameters into `statement` is non-conforming. The agent
  authors both fields and is untrusted.
- **E2-4.** `EffectPlan` MUST be immutable after admission. Amendment is a new
  plan with a new `plan_id`.

## 2.3 `ShadowSubstrate`

The pluggable driver. One instance per configured backend.

```python
@dataclass(frozen=True, slots=True)
class SubstrateCapabilities:
    """What this driver can honestly do.

    Declared rather than assumed. The escrow reads these to decide whether a
    plan is stageable at all, so a driver that overstates them converts a
    safety property into a silent lie.

    :ivar transactional: Native atomic commit and rollback.
    :ivar row_level_diff: Can enumerate affected rows with before/after images,
        not merely counts.
    :ivar snapshot_isolation: Reads within a stage are stable, so the diff does
        not shift under concurrent writers.
    :ivar requires_compensation: Effects cannot be rolled back natively and
        therefore require a serialized undo.
    :ivar max_stage_seconds: Upper bound on how long a stage may hold its
        transaction and locks before the reaper orphans it.
    :ivar max_diff_rows: Row cap beyond which the diff is truncated and
        ``EffectDiff.truncated`` is set.
    """

    transactional: bool
    row_level_diff: bool
    snapshot_isolation: bool
    requires_compensation: bool
    max_stage_seconds: float
    max_diff_rows: int


@dataclass(frozen=True, slots=True)
class StageHandle:
    """Opaque token identifying one open stage.

    Binds a plan to a single physical connection. The handle MUST NOT be
    serialized across processes: a stage is owned by the process that opened it,
    and an unowned open transaction is an orphan by definition.
    """

    stage_id: uuid.UUID
    plan_id: PlanId
    substrate_id: str
    opened_at: datetime
    expires_at: datetime
    authorization_id: uuid.UUID | None
    """The AgentGov ``Authorization`` backing this stage, when cost-governed."""


@dataclass(frozen=True, slots=True)
class EffectOutcome:
    """Result of applying one effect inside a stage."""

    effect_id: EffectId
    rows_affected: int
    applied_at: datetime


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    """Evidence that a stage was committed.

    :ivar substrate_txn_id: Backend transaction identifier where one exists
        (e.g. Postgres ``txid_current()``). ``None`` where the backend exposes
        none.
    """

    stage_id: uuid.UUID
    committed_at: datetime
    substrate_txn_id: str | None
    diff_hash: str
    verdict_hash: str
    agentgov_head_hash: str


@runtime_checkable
class ShadowSubstrate(Protocol):
    """Executes a plan against a real but uncommitted backend."""

    @property
    def substrate_id(self) -> str:
        """Stable identifier, matching the prefix in ``Effect.target``."""
        ...

    @property
    def capabilities(self) -> SubstrateCapabilities:
        """What this driver supports. MUST be constant for the driver's life."""
        ...

    def open(self, plan: EffectPlan, *, expires_at: datetime) -> StageHandle:
        """Acquire a connection and begin an uncommitted unit of work.

        :raises SubstrateUnavailableError: Backend unreachable.
        :raises StageConflictError: A conflicting stage already holds the
            resources this plan needs.
        """
        ...

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Apply one effect inside the open stage.

        MUST NOT commit. MUST raise rather than partially apply.
        """
        ...

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Compute the measured delta of everything applied so far.

        MUST be read from the substrate, never reconstructed from the plan.
        The difference between intended and measured change is the product.
        """
        ...

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Make the staged work durable. MUST be atomic where
        ``capabilities.transactional`` is ``True``."""
        ...

    def abort(self, handle: StageHandle) -> None:
        """Roll back. MUST be idempotent and MUST NOT raise on an already
        aborted stage: it is called from error paths."""
        ...

    def close(self, handle: StageHandle) -> None:
        """Release the connection. MUST abort first if still open."""
        ...
```

Requirements:

- **E2-5.** `open()` MUST bind exactly one connection for the stage's lifetime.
  The connection MUST NOT be returned to a pool until `close()`.
- **E2-6.** `diff()` MUST be pure with respect to the substrate: it MUST NOT
  mutate state, and calling it twice on an unchanged stage MUST produce an
  identical `content_hash()`.
- **E2-7.** A driver with `transactional=False` MUST NOT be used for effects
  with `reversible=True`. Reversibility is a property of the substrate, and a
  plan claiming otherwise is rejected.
- **E2-8.** `abort()` MUST be safe to call in any state, including after
  `commit()`, where it is a no-op.

## 2.4 `EffectDiff`

The measured consequence. This is the artifact a human reviews and an invariant
evaluates, and it is the thing that gets hashed into the chain.

```python
@dataclass(frozen=True, slots=True)
class RowDelta:
    """One row's before and after image.

    ``before is None`` is an insert. ``after is None`` is a delete.
    """

    schema: str
    table: str
    primary_key: Mapping[str, object]
    before: Mapping[str, object] | None
    after: Mapping[str, object] | None
    tenant_id: str | None


@dataclass(frozen=True, slots=True)
class EffectDiff:
    """The delta a stage would commit.

    :ivar truncated: ``True`` when the row cap was hit. A truncated diff MUST
        NOT be presented as complete, and invariants that require completeness
        MUST fail closed against it (E2-11).
    """

    plan_id: PlanId
    stage_id: uuid.UUID
    substrate_id: str
    computed_at: datetime
    rows_inserted: int
    rows_updated: int
    rows_deleted: int
    tables_touched: frozenset[str]
    schemas_touched: frozenset[str]
    tenant_ids: frozenset[str]
    deltas: tuple[RowDelta, ...]
    truncated: bool

    @property
    def blast_radius(self) -> int:
        """Total rows mutated. The primary scalar for policy tiering."""
        return self.rows_inserted + self.rows_updated + self.rows_deleted

    @property
    def tenant_count(self) -> int:
        """Distinct tenants touched. A second, independent radius axis: a
        one-row change spanning two tenants is not a small change."""
        return len(self.tenant_ids)

    def content_hash(self) -> str:
        """SHA-256 over the canonical serialization (section 3.3)."""
        ...
```

- **E2-9.** Counts MUST be measured from the substrate, not summed from
  `EffectOutcome.rows_affected`. Triggers, cascades and rules mutate rows the
  statement never named, and those mutations are exactly the ones worth seeing.
- **E2-10.** `deltas` MUST be ordered deterministically: `(schema, table,
  primary_key)` ascending. Hash stability depends on it.
- **E2-11.** When `truncated` is `True`, any invariant whose correctness
  requires the full row set MUST emit a `BLOCKING` violation. Silently
  evaluating a completeness-dependent predicate against a sample is the failure
  mode this whole design exists to prevent.

## 2.5 `InvariantChecker`

Deterministic predicates over `(plan, diff)`. This is the trusted decider, and
its trustworthiness rests entirely on it being a pure function.

```python
@dataclass(frozen=True, slots=True)
class InvariantViolation:
    invariant: str
    severity: Severity
    message: str
    evidence: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Verdict:
    """The admission decision. Hashed and anchored (section 3.4)."""

    plan_id: PlanId
    stage_id: uuid.UUID
    diff_hash: str
    decided_at: datetime
    admitted: bool
    checkers_run: tuple[str, ...]
    violations: tuple[InvariantViolation, ...]

    def content_hash(self) -> str: ...


@runtime_checkable
class InvariantChecker(Protocol):
    """A deterministic predicate over a staged diff."""

    @property
    def name(self) -> str:
        """Stable identifier, recorded in ``Verdict.checkers_run``."""
        ...

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        """Evaluate. Empty tuple means satisfied.

        MUST be a pure function of its arguments. No I/O, no clock, no RNG, no
        network, no model call. A checker that reads the world cannot be
        replayed, and a verdict that cannot be replayed is not evidence.
        """
        ...
```

Requirements:

- **E2-12.** `check()` MUST be pure. A predicate needing external facts MUST
  have them supplied as constructor arguments at configuration time, so they are
  captured in the checker's configuration hash and replay is exact.
- **E2-13.** A model MAY act as a **sensor** feeding a checker, never as the
  checker. Model-derived facts MUST enter as constructor-time inputs with
  recorded provenance, and MUST NOT be fetched inside `check()`.
- **E2-14.** Checkers MUST be order-independent. The escrow runs all of them and
  unions the violations; it MUST NOT short-circuit on the first blocking result,
  so a rejected plan reports every reason at once.
- **E2-15.** A checker that raises MUST be treated as a `BLOCKING` violation,
  not as a pass. Fail closed.

### 2.5.1 Baseline checkers shipped in v1

| Name | Severity | Predicate |
|---|---|---|
| `blast_radius` | BLOCKING | `diff.blast_radius <= limit` |
| `tenant_isolation` | BLOCKING | `diff.tenant_count <= 1` unless the plan carries a cross-tenant grant |
| `schema_allowlist` | BLOCKING | `diff.schemas_touched ⊆ allowed` |
| `no_ddl` | BLOCKING | No effect has `kind == DDL` |
| `truncation_guard` | BLOCKING | `not diff.truncated` |
| `distribution_shift` | ADVISORY | `blast_radius` within *k* MAD of the historical median for this `(scope_id, table)` pair |

`distribution_shift` is advisory in v1 because its threshold is uncalibrated.
Promoting it to blocking requires the same empirical treatment the cognitive
breaker's threshold received: a measured corpus, both error classes counted, and
a swept decision rule. See `ARCHITECTURE.md` Part A. Shipping it as blocking on
an assumed constant would repeat a mistake this project has already made once
and documented.

---

# 3. AgentGov integration seam

## 3.1 The consumed surface

This is the entire public surface `interlock` depends on. Nothing else.

```python
from agentgov.core import (
    BudgetManager,  # open_sqlite(path, read_only=True)
    LedgerEntry,  # sequence, entry_hash, prev_hash, entry_type, scope_id,
    # transaction_id, timestamp, amount, memo
    EntryType,  # HOLD / HOLD_VOID / SPEND / REVERSAL
    ControlEvent,  # event_type, scope_id, reason, ledger_head_hash
    GENESIS_HASH,
)
from agentgov.exceptions import (
    AgentGovError,
    LedgerIntegrityError,
    ReadOnlyLedgerError,
    StorageError,
)
```

Methods called:

| Call | Purpose |
|---|---|
| `BudgetManager.open_sqlite(path, read_only=True)` | Attach. Read-only mode takes no advisory file lock, so it is safe against a live governing process. |
| `manager.verify_integrity()` | Admissibility gate (E3-2). |
| `manager.ledger.head_hash` | The anchor value. Commits to the entire history. |
| `manager.ledger.entries()` | Chain read for anchor resolution. |
| `manager.audit_trail(scope_id)` | Correlate committed plans to settled spend. |
| `manager.control_events` | Halted-scope check (E3-6). |
| `manager.node(scope_id)`, `.ancestry()` | Scope hierarchy for radius policy. |

Requirements:

- **E3-1.** The handle MUST be opened with `read_only=True`. Any write attempt
  raises `ReadOnlyLedgerError`, which the escrow MUST treat as a defect in
  itself, not as a recoverable condition.
- **E3-2.** `verify_integrity()` MUST pass before any stage is opened. On
  `LedgerIntegrityError` the escrow MUST refuse to stage. Anchoring to a chain
  that does not verify produces evidence that proves nothing, and proceeding
  would be worse than not anchoring, because it manufactures false assurance.
- **E3-3.** The escrow MUST tolerate the ledger being absent. A deployment with
  no governor runs unanchored, and every escrow record MUST then carry
  `agentgov_head_hash = GENESIS_HASH` with `anchored = False`, so unanchored
  records are distinguishable rather than indistinguishable.

## 3.2 The escrow's own chain

`interlock` maintains an independent append-only hash chain using the same
discipline as `agentgov`: a JSON payload with fixed field order, compact
separators, `ensure_ascii=True`, SHA-256, `prev_hash` linking each record to its
predecessor. The version tag is `AESC1`, distinct from `AGOV1`, so a record from
one chain can never be replayed as a record of the other.

```python
class RecordType(Enum):
    PLAN_ADMITTED = "plan_admitted"
    STAGE_OPENED = "stage_opened"
    DIFF_COMPUTED = "diff_computed"
    VERDICT = "verdict"
    COMMITTED = "committed"
    ABORTED = "aborted"
    ORPHANED = "orphaned"
    COMPENSATED = "compensated"


@dataclass(frozen=True, slots=True)
class EscrowRecord:
    """One tamper-evident escrow event, anchored to the AgentGov chain.

    :ivar payload_hash: Content hash of the artifact this record attests
        (plan, diff, verdict or receipt). The artifact itself is stored
        alongside; the chain carries only the digest, so the chain stays small
        and carries no row data.
    :ivar agentgov_head_hash: ``Ledger.head_hash`` observed at record creation.
    :ivar agentgov_sequence: Sequence of the entry that head hash belongs to,
        or ``-1`` for the genesis/unanchored case. Enables the monotonicity
        check in E3-5.
    """

    sequence: int
    record_id: uuid.UUID
    timestamp: datetime
    record_type: RecordType
    plan_id: PlanId
    stage_id: uuid.UUID | None
    payload_hash: str
    anchored: bool
    agentgov_head_hash: str
    agentgov_sequence: int
    prev_hash: str
    record_hash: str
```

- **E3-4.** Row data MUST NOT enter the chain. Only digests. The chain is an
  audit artifact and MUST NOT become a copy of the production database. This
  mirrors `agentgov`'s posture, where `retain_arguments=False` is the default.

## 3.3 Canonical serialization

Every `content_hash()` in this document MUST be computed as:

```
sha256(
    json.dumps(
        [ESCROW_AUDIT_VERSION, <ordered field list>],
        separators=(",", ":"),
        ensure_ascii=True,
        sort_keys=False,
    ).encode("utf-8")
).hexdigest()
```

Fixed field order, never `sort_keys` over a dict. Decimals serialize via `str()`,
datetimes via UTC ISO-8601 with explicit offset, `frozenset` fields as sorted
lists. This matches `agentgov._hash_entry`, which uses a JSON list rather than a
delimiter-joined string specifically so that a scope id or memo containing the
delimiter cannot forge a payload boundary. The same reasoning applies to table
names and tenant ids here, which are attacker-influenceable.

## 3.4 What anchoring proves

Each escrow record names the AgentGov head hash observed when it was written.

**It proves a lower bound on time.** A record naming head `H_n` cannot have been
created before AgentGov produced entry `n`, because `H_n` did not exist until
then. Combined with the escrow chain's own append-only linkage, the ordering of
escrow records relative to ledger entries is fixed.

**It does not prove an upper bound.** A record could name a *stale* head, making
itself appear older than it is. One-way anchoring cannot detect that in
isolation.

Three mitigations, in increasing strength:

- **E3-5. Monotonicity (mandatory, v1).** `agentgov_sequence` MUST be
  non-decreasing across the escrow chain. A verifier walking the escrow chain in
  order MUST reject any record whose anchor regresses. This makes backdating
  detectable in all cases except a contiguous suffix rewrite of the escrow chain
  itself, which the escrow chain's own hash linkage already covers. The
  remaining gap is the escrow's genesis, which is unavoidable for any
  self-hosted log.
- **E3-6. Reverse anchoring (optional, co-resident deployments).** Where the
  escrow also drives the governed model call, it holds a write-capable
  `BudgetManager` for the metering path. It MAY then write its own chain head
  into the `memo` of the entry that call posts:

  ```
  memo = f"aesc:{record_hash[:16]}"
  ```

  `memo` is part of `_hash_entry`'s payload, so the reverse anchor is itself
  tamper-evident inside the AgentGov chain. This yields a bidirectional
  interlock and therefore an upper time bound. It uses only the public
  `authorize(..., memo=)` / `capture(..., memo=)` surface and requires no change
  to `agentgov`. It is optional because it needs a write handle, which the
  read-only audit posture in the preamble deliberately does not assume.
- **E3-7. External transparency log (out of scope for v1).** Publishing escrow
  chain heads to a third-party append-only log removes the self-hosted genesis
  gap entirely. Named here so its absence is a stated limitation rather than an
  oversight.

## 3.5 Cross-system rules

- **E3-8. A halted scope MUST NOT commit.** Before `commit()`, the escrow MUST
  re-read `manager.control_events` and refuse if the plan's `scope_id`, or any
  ancestor of it, has an unreset trip. AgentGov's breaker is latching, so this
  is a stable read. A financial or cognitive halt that does not also stop
  in-flight side effects is a halt in name only.
- **E3-9.** The check in E3-8 MUST occur after `VERIFIED` and immediately before
  `commit()`, not at admission. The window between staging and commit is exactly
  where a breaker trip is most likely and most important.
- **E3-10.** `COMMITTED` and `COMPENSATED` records MUST record the
  `transaction_id` of the corresponding AgentGov entry where the plan is
  cost-governed, giving a join key in both directions.

---

# 4. V1 reference target

## 4.1 Scope

V1 ships exactly one substrate family: **transactional SQL** over SQLite and
PostgreSQL. Everything else is out of scope.

This is a deliberate narrowing. The value of the product is bounded by connector
depth, and connector depth is a grind. One connector done to the row-level-diff
standard is worth more than five that report only row counts, because a row
count is a summary and summaries are what this design exists to replace.

| Backend | `transactional` | `row_level_diff` | `snapshot_isolation` |
|---|---|---|---|
| PostgreSQL ≥ 14 | yes | yes, via `RETURNING` + pre-image capture | yes, `REPEATABLE READ` |
| SQLite ≥ 3.37 | yes | yes, via pre/post image `SELECT` | yes, single-writer |

## 4.2 Stage protocol

```
  open(plan)
    ├── acquire dedicated connection (never pooled for the stage's life)
    ├── SET statement_timeout / lock_timeout      (Postgres)
    ├── BEGIN ISOLATION LEVEL REPEATABLE READ     (Postgres)
    │   BEGIN IMMEDIATE                           (SQLite)
    ├── create stage-local pre-image table (TEMP / temp schema)
    └── register expires_at with the reaper

  apply(effect)  xN, in topological order
    ├── SELECT the target primary-key set into the pre-image table
    │     (Postgres: FOR UPDATE, to pin the rows for the stage)
    ├── execute the parameterised statement
    │     Postgres: rewritten to carry RETURNING <pk>, <columns>
    │     SQLite:   followed by a post-image SELECT on the pinned pk set
    └── record EffectOutcome(rows_affected=cursor.rowcount)

  diff()
    ├── join pre-image against post-image on primary key
    ├── classify each row: insert / update / delete
    ├── attribute tenant_id per row
    ├── stop at capabilities.max_diff_rows, set truncated=True
    └── return EffectDiff, ordered per E2-10

  check(plan, diff)  → Verdict

  commit()  → COMMIT    │    abort()  → ROLLBACK
```

## 4.3 Operational hazards, stated

- **H-1. Lock footprint.** A stage holds write locks for its entire duration,
  including invariant evaluation and any human review. On a hot table this
  blocks other writers. `max_stage_seconds` MUST be set low (single-digit
  seconds by default), and `lock_timeout` MUST be set so a blocked stage fails
  fast instead of queueing. **Human-in-the-loop review MUST NOT happen inside an
  open stage.** Where review is required, the stage aborts and the diff is
  presented from the recorded artifact; approval produces a new plan that is
  re-staged and re-verified. Re-verification is mandatory because the substrate
  may have moved.
- **H-2. Latency.** Staging roughly doubles write-path round trips. Plans below
  a configured blast-radius threshold SHOULD bypass escrow entirely. Escrowing
  every write makes the system unusable and the threshold is a policy input, not
  a constant.
- **H-3. Diff cost.** Pre-image capture is a second read of the affected set. On
  a large `UPDATE` this can dominate. `max_diff_rows` bounds it; beyond the
  bound the plan is rejected by `truncation_guard` rather than committed
  half-seen.
- **H-4. Trigger and cascade amplification.** Measured diffs will routinely
  exceed the statement's nominal footprint. This is correct behaviour and the
  main source of genuine findings. It will also generate false alarms against
  radius limits calibrated on nominal counts, so limits MUST be set from
  measured diffs.
- **H-5. Connection exhaustion.** Each open stage pins a connection. Concurrent
  stages are bounded by the pool. The reaper is the only thing preventing a
  crashed process from permanently consuming one.

## 4.4 Non-transactional sinks

Sending an email cannot be staged. There is no shadow for it, and no atomic
protocol spans a Postgres transaction and an SMTP server.

V1 does not pretend otherwise. **Non-transactional effects MUST NOT participate
in the staged diff.** They are expressed as `EffectKind.ENQUEUE`: an intent row
written to a transactional outbox table *inside the same stage*. The row is part
of the diff, reviewable and revocable, like any other row.

```
   stage ──▶ outbox row written inside the transaction ──▶ COMMIT
                                                             │
                                          relay (separate process)
                                                             │
                                            at-least-once delivery,
                                          idempotency_key deduplicated
                                                             │
                                              external side effect
```

- **E4-1.** The relay MUST be a separate process reading committed outbox rows.
  It MUST NOT be invoked inside a stage.
- **E4-2.** Delivery is at-least-once. Every enqueued effect MUST carry an
  `idempotency_key` derived deterministically from `(plan_id, effect_id)`, so a
  redelivery after a crash is absorbed by the receiver.
- **E4-3.** Compensations for enqueued effects MUST be serialized and written to
  the escrow chain **before** the outbox row is committed. The ordering matters:
  if the undo cannot be written down, the do MUST NOT happen.
- **E4-4.** Compensations apply in **reverse topological order** of the plan's
  DAG.
- **E4-5.** A compensation past its `expires_at` MUST NOT be auto-applied. It
  escalates to an operator. An hour-old unsend is not an unsend, and applying a
  stale compensation can cause a second incident rather than resolving the
  first.

This is the outbox pattern, and choosing it is a scope decision as much as a
technical one. It means v1 gives a hard guarantee on transactional SQL and an
explicitly weaker, at-least-once, compensation-backed guarantee everywhere else,
rather than a uniform guarantee that is quietly false at the edges.

---

## Open questions

Unresolved, and listed because they are unresolved rather than minor.

- **Diff cost on wide updates.** Pre-image capture may be the dominant cost for
  large `UPDATE`s. Whether logical decoding is cheaper than explicit pre-image
  capture at realistic sizes is unmeasured, and the answer decides whether H-3
  is a tuning parameter or a design flaw.
- **Radius limits are uncalibrated.** Every threshold in section 2.5.1 is a
  placeholder. They need the treatment `result_similarity_threshold` received:
  measured corpus, both error classes counted, decision rule swept. Shipping
  assumed constants is the specific mistake this project already made once.
- **Cross-substrate plans.** A plan spanning two transactional backends needs
  real 2PC or a saga. V1 rejects such plans at admission. Whether sagas across
  two SQL substrates are worth the complexity is unanswered.
- **Replay fidelity.** Deterministic replay requires pinning every
  nondeterministic input, including substrate-assigned identities such as
  sequences, `now()` and `random()`. Plans using them are replayable only if the
  driver captures and re-injects those values, which is unspecified here.
- **How many substrates in a real stack are shadowable at all.** Unknown. The
  answer bounds what fraction of an agent's effects this can cover, and it
  should be counted on three real stacks rather than assumed.

---

# Conformance of `interlock` v0.1.0

What the shipped package actually does against this document. Verified by
reading `src/interlock/` and by running adversarial plans against it, not by
reading the test suite.

## Implemented

| Requirement | Where |
|---|---|
| One-way `interlock -> agentgov` dependency, read-only by default | `anchor.LedgerAnchor`, opens with `read_only=True` |
| Ledger verified at attach; refuses to stage against a chain that fails | `anchor.LedgerAnchor.__init__` |
| Reverse anchor into AgentGov `memo` when co-resident | `anchor.LedgerAnchor.reverse_anchor` |
| Breaker re-read immediately before commit, not at admission | `engine.EscrowEngine.execute` |
| `E1-3`: no path from `STAGED` to `COMMITTED` that skips adjudication | `engine.EscrowEngine.execute` |
| `E1-4`: `REJECTED` not overridable in-process | no override surface exists |
| Row-level diff measured from the substrate via `AFTER` triggers | `substrate.SqliteSubstrate` |
| Truncation is explicit and blocking | `types.EffectDiff.truncated`, `invariants.TruncationGuard` |
| Checkers are pure `(plan, diff)`; a raising checker becomes BLOCKING | `engine.EscrowEngine._adjudicate` |
| Hash-linked chain with sequence, link and digest verification | `chain.EscrowChain.verify` |
| Anchor monotonicity check | `chain.EscrowChain.verify_anchors` |

## Partial

- **Diff completeness is scoped to `TableSpec`, and admission does not enforce
  that scope.** `admit()` rejects a plan whose `Effect.target` names an
  unobserved table, but `target` is an agent-supplied label and is never
  compared against the statement. A statement that writes a table outside
  `TableSpec` executes, commits, and produces `blast_radius == 0` with an empty
  `tables_touched`, so every measured checker passes on an empty measurement.
  The same gap covers FK cascades into unobserved tables: the cascade executes
  and does not appear in the diff.
- **`no_ddl` is enforced on the statement, not on `Effect.kind`.** The
  checker still reads the agent-supplied kind, but `SqliteSubstrate` vets the
  statement's leading verb through `reject_reason()`, which `admit()` calls
  before a connection is opened and `apply()` re-checks for callers that skip
  the engine. A verb allowlist is not a SQL parser: it says nothing about which
  table a permitted statement reaches.
- **`blast_radius` counts capture rows, not distinct rows.** A row mutated twice
  inside one plan contributes 2. The bound is therefore conservative for row
  count and is not a count of affected rows.
- **Chain durability is opt-in.** `EscrowEngine` defaults to an in-memory
  `EscrowChain`, which does not survive the process. The commit record is now
  write-ahead — `COMMIT_INTENT` before `substrate.commit()`, `COMMITTED` after
  — and `EscrowChain.unresolved_intents()` reads back intents with no terminal
  record. An intent attests an attempt, not an outcome: resolving one means
  asking the substrate whether that transaction landed, and nothing here
  automates that.
- **`tenant_isolation` depends on `tenant_column` being present in
  `TableSpec.columns`.** It is not validated as of v0.1.0 in the spec's sense of
  a declared capability: if the column is absent from the captured image, every
  `tenant_id` reads as `None`, `tenant_count` is 0, and the check passes
  regardless of how many tenants the plan spans.

## Unimplemented

- **PostgreSQL substrate.** `pyproject.toml` declares a `postgres` extra; there
  is no driver. Section 4.2's `statement_timeout` / `lock_timeout` / logical
  decoding requirements are unexercised.
- **`E1-5`: expiry to `ORPHANED`.** `StageState.ORPHANED` and
  `RecordType.ORPHANED` exist and are never assigned. Expiry raises
  `StageExpiredError` from `apply()` and `commit()`; there is no reaper, and
  `diff()` does not check expiry at all.
- **`COMPENSATED` and the compensation path.** `Compensation` is validated at
  admission and never executed. `RecordType.COMPENSATED` is never appended.
- **`schema_allowlist`.** `TableAllowlist` operates on table names;
  `diff.schemas_touched` does not exist.
- **Cross-substrate plans (2PC / saga).** `admit()` now refuses a plan whose
  effects name a substrate other than the engine's, so such a plan is rejected
  rather than misrouted, but nothing coordinates two substrates.
- **`distribution_shift`.** No historical store, no MAD computation.
- **Transactional outbox and relay** (section 4.4). `EffectKind.ENQUEUE` is
  defined and carries no behaviour.
- **Deterministic replay.** Nothing captures or re-injects substrate-assigned
  values (`now()`, sequences, `random()`), so a recorded verdict cannot be
  re-derived by re-running the plan.
