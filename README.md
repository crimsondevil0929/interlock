# Interlock

**A reference monitor for agent side effects.** An agent proposes a plan. It holds no
credentials and cannot execute. Interlock applies the plan against a real but uncommitted
substrate, measures what actually changed, evaluates deterministic predicates against that
measurement, and only then commits or rolls back.

```bash
uv run python demo.py
```

```
  ACT 2  The identical plan, through Interlock.
    MEASURED by the database, not predicted from the plan:
      rows updated    63   inserted    63   deleted   103
      blast radius   229 rows across 4 tenants
      orders.total $21,350.25 -> $425.25

    ADJUDICATED by 7 deterministic checks:
      BLOCK   blast_radius          plan would mutate 229 rows, limit is 8
      BLOCK   tenant_isolation      plan spans 4 tenants, limit is 1
      BLOCK   no_delete             plan deletes 103 row(s) from ungranted table(s): order_audit
      BLOCK   column_value_guard    orders.total falls 98.0% (21,350.25 to 425.25), limit is 30%
      advise  stated_footprint      agent stated 6 row(s); substrate measured 229 (38.2x)

    OUTCOME  ROLLED BACK
      Byte-identical to before the plan ran. Nothing reached disk.
```

## Why authorization does not catch this

A prompt-injected agent is a fully authorized agent. It is doing something it has
permission to do, so an authorization check passes. The injected instruction arrived from
the customer's own database, inside a tool result, after every provider-side filter had
already run, so a provider-side filter does not see it either. The only remaining place to
catch it is between the effect being computed and the effect becoming durable.

That position requires write-path credentials to the database the effects land in, which is
why this runs inside the deployment rather than at the model provider.

The demo is also a control for model quality: the agent loops zero times, costs $0.0012,
and emits valid SQL on the first attempt. The damage is not a model-quality failure.

## What it measures

The diff is read **from the substrate**, never reconstructed from the plan. The two are
routinely different:

| | |
|---|---|
| Agent stated | 1 row |
| SQL `rowcount` | 1 row |
| **Measured** | **2 rows across 2 tables** |

A compliance trigger nobody remembered doubled the footprint. No plan inspection, SQL
parser or policy engine reading the statement could know that. The database knew, because
it had just done it.

## Lifecycle

```
PLANNED -> STAGING -> STAGED -> VERIFIED  -> COMMITTED
                             \-> REJECTED -> ABORTED
```

Three properties hold by construction:

1. No path from `STAGED` to `COMMITTED` skips adjudication.
2. `REJECTED` is not overridable in-process. Overriding means submitting a new plan that
   carries an explicit waiver, which is then itself a recorded artifact.
3. A committed effect is discoverable from the chain. `COMMIT_INTENT` is written before
   the substrate is told to commit and `COMMITTED` after it returns, so a crash in that
   window leaves an intent with no terminal record after it.

What the third does **not** give: an intent says a commit was *attempted*, not that it
succeeded. `EscrowChain.unresolved_intents()` returns the open ones and narrows the
question to a specific plan and stage; answering it means asking the substrate whether
that transaction landed. An append-only chain cannot honestly backfill the answer.

## Quickstart

`EscrowRuntime` owns the substrate, the record chain, the AgentGov anchor and
the engine. Five lines to a governed write:

```python
from interlock import EscrowRuntime, TableSpec

runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
)
result = runtime.execute_sql(
    "UPDATE orders SET total = :total WHERE id = :id",
    {"total": 480.0, "id": 1},
    tenant_id="acme",
    stated_rows=1,
)
print(result.committed, result.blocked_by)
```

That stages the statement in a real transaction, measures what the database
actually did, adjudicates the measurement, and commits or rolls back.

**Placeholders must be named.** `Effect.parameters` is a `Mapping`, so the
driver binds by name: write `:id`, never `?`. A positional placeholder is
refused when the plan is built, before any lock is taken.

### Building a plan

For anything past one statement, `PlanBuilder` mints the identifiers and the
UTC timestamp and wires the dependency DAG:

```python
from interlock import PlanBuilder

plan = (
    PlanBuilder(scope_id="support-agent")
    .update(
        table="orders",
        statement="UPDATE orders SET total = :total WHERE id = :id",
        parameters={"total": 100.0, "id": 1},
        tenant_id="acme",
        stated_rows=1,
    )
    .build()
)
```

Effects are sequential by default: each depends on the one added before it.
Pass `independent=True` for no ordering constraint, or `after=[effect_id]` to
fan out. `builder.last_effect_id` hands back the id to depend on.

### Under the runtime

The primitives are unchanged and the runtime hands them back
(`runtime.engine`, `runtime.chain`, `runtime.anchor`). Wire them yourself when
you need to:

```python
from interlock import (
    BlastRadius,
    EscrowChain,
    EscrowEngine,
    PlanBuilder,
    SqliteSubstrate,
    TableSpec,
    TenantIsolation,
)

substrate = SqliteSubstrate(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
)
engine = EscrowEngine(
    substrate,
    checkers=[BlastRadius(50), TenantIsolation(1)],
    chain=EscrowChain("escrow.jsonl"),  # omit this and the chain is in memory only
)

plan = (
    PlanBuilder(scope_id="support-agent", intent="refund order 1")
    .update(
        table="orders",
        statement="UPDATE orders SET total = :total WHERE id = :id",
        parameters={"total": 480.0, "id": 1},
        tenant_id="acme",
        stated_rows=1,
    )
    .build()
)

result = engine.execute(plan)
if not result.committed:
    print(result.blocked_by, result.diff.blast_radius)
```

`execute()` takes a per-plan `settle_cost=` that overrides the engine's
default, because what a plan cost to produce is a property of the plan.

### Typing

`PlanId` and `EffectId` are `NewType`s over `str`. `PlanBuilder` mints both,
so most code never names them. Under `mypy --strict`, constructing an
`EffectPlan` or `Effect` by hand means importing them:

```python
from datetime import UTC, datetime

from interlock import Effect, EffectId, EffectKind, EffectPlan, PlanId

plan = EffectPlan(
    plan_id=PlanId("plan-0001"),
    scope_id="support-agent",
    trajectory_id="traj-0001",
    created_at=datetime.now(UTC),
    effects=(
        Effect(
            effect_id=EffectId("eff-0001"),
            kind=EffectKind.UPDATE,
            target="orders",
            statement="UPDATE orders SET total = :total WHERE id = :id",
            parameters={"total": 480.0, "id": 1},
            tenant_id="acme",
            stated_rows=1,
        ),
    ),
)
```

### Invariants

Checkers are pure functions of `(plan, diff)`. No I/O, no clock, no RNG, no
model call. A checker that reads the world cannot be replayed, and a verdict
that cannot be replayed is not evidence. Where a judgment genuinely needs a
model, the model is a **sensor** whose output is passed in at configuration
time, never consulted from inside `check`. A checker that raises becomes a
blocking violation: fail closed.

| Checker | Bounds |
|---|---|
| `BlastRadius` | captured mutations in one plan |
| `TenantIsolation` | distinct tenants one plan may span |
| `ColumnValueGuard` | fall in a column total, table-wide |
| `TenantDrawdownGuard` | fall in a column total, **per tenant** |
| `NoDelete` | deletions outside granted tables |
| `NoSchemaChange` | effects declared as DDL |
| `TruncationGuard` | a diff that hit the row cap |
| `StatedFootprint` | the agent's claim against the measurement |

`TenantDrawdownGuard` exists because `ColumnValueGuard` sums the column across
the whole diff, and a sum is the wrong denominator on a multi-tenant
substrate. A plan that zeroes one tenant while inflating another by the same
amount moves that sum by 0%, so a table-scoped guard passes it — with a tenant
wiped. Grouping by tenant first is the only way to see it.
Column totals are `Decimal`, computed through `Decimal(str(value))`, so a
guard permitting a 30% drawdown does not admit 30.000000000000004%.

Every threshold in `default_checkers` is an uncalibrated placeholder. Measure
your own diffs and set the limits from the measurement.

### Errors

Every failure on the write path is an `InterlockError`. The AgentGov seam is
an implementation detail of the anchor, and its exceptions are translated at
the boundary, so this is sufficient:

```python
from interlock import EscrowRuntime, InterlockError, TableSpec

runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
)

try:
    runtime.execute_sql(
        "UPDATE order_audit SET note = :note WHERE id = :id",
        {"note": "x", "id": 1},
        table="orders",  # the label lies; the statement writes elsewhere
        tenant_id="acme",
        stated_rows=1,
    )
except InterlockError as exc:
    print(type(exc).__name__, exc)
```

That example is the case worth knowing about: `table=` is a label the agent
writes, and the statement goes somewhere else entirely. The substrate denies
the write inside SQLite before it executes, and it surfaces as a
`ForbiddenStatementError` like everything else on this path.

## AgentGov integration

Interlock imports [`agentgov`](https://github.com/crimsondevil0929/agentgov) as a
**read-only audit dependency**. The dependency runs one way (`interlock -> agentgov`) and
requires no change to AgentGov.

Every adjudication is written to a hash-linked chain whose records carry the AgentGov head
hash observed at the time. That proves a *lower* bound on a record's time. It does not
prove an upper bound on its own, because a record could name a stale head, so
`verify_anchors()` additionally requires the observed AgentGov sequence to be
non-decreasing across an append-only chain.

Where Interlock is co-resident with a write-capable governor it also writes its own chain
head into the `memo` of the ledger entries a plan causes. `memo` is inside AgentGov's hash
payload, so the reverse anchor cannot be altered without breaking AgentGov's own
verification. The two chains then interlock in both directions.

**Reverse anchoring costs something.** AgentGov has no zero-value entry that can carry a
memo, so the chain head rides on a real `authorize`/`capture` pair. `EscrowEngine`'s
`settle_cost` defaults to `"0"`, which means forward anchoring only and leaves
`StageResult.anchored_to` empty. Pass the plan's real cost to get the bidirectional
anchor:

```python
from agentgov import BudgetManager, money

from interlock import EscrowRuntime, TableSpec, TenantIsolation

governor = BudgetManager()
governor.open_root("support-agent", money("8.00"))

runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
    checkers=[TenantIsolation(1)],
    governed=governor,  # enables reverse anchoring
    settle_cost="0.0002",  # what this plan cost to produce
)

result = runtime.execute_sql(
    "UPDATE orders SET total = :total WHERE id = :id",
    {"total": 480.0, "id": 1},
    tenant_id="acme",
    stated_rows=1,
)
print(result.committed, bool(result.anchored_to))
```

`scope_id` must name a scope AgentGov knows about. That is checked at
admission, not at commit, because the reverse anchor is written *after* the
substrate commits and a failure there would arrive on top of durable effects.

Every failure on this seam is an `InterlockError`. `agentgov` exceptions are
translated at the anchor boundary, so a caller never has to import
`agentgov.exceptions` to catch a write-path error.

AgentGov's latching breaker is re-read immediately before commit, not at admission. The
staging window is where a trip has to be observed, because a halt that does not stop
in-flight side effects does not stop the effects.

## Scope

**v0.1.0 ships one substrate: SQLite.** PostgreSQL is declared as an extra and has no
driver. One connector at the row-level-diff standard is worth more than several reporting
only row counts, because a row count is the summary this design exists to replace.

### What this is not yet a boundary against

Read this before pointing it at a production database. Each item below was reproduced
against the shipped code, not inferred.

- **Writes outside `TableSpec` are denied, by SQLite, at prepare time.**
  `Effect.target` is a label the agent writes and is never compared against the statement,
  so it cannot be the boundary. `SqliteSubstrate` installs a
  `sqlite3.Connection.set_authorizer` callback that denies `INSERT`/`UPDATE`/`DELETE` on
  any table not in `TableSpec`, plus `ATTACH`/`DETACH`. A statement whose label claims an
  observed table while writing elsewhere never executes; it raises
  `ForbiddenStatementError` naming the table it reached for. Pass
  `enforce_table_access=False` to restore the v0.1.0 behaviour for a migration.

  **What this still does not cover.** The authorizer fires when SQLite *prepares a
  statement*. Foreign-key cascades are executed internally and are not prepared, so a
  cascade into an unobserved table is neither denied here nor visible in the diff — see
  the next bullet. Grant the connection exactly the observed tables anyway; a
  database-enforced grant is a boundary, and this is a second one in front of it.

  DDL specifically is refused twice over: `SqliteSubstrate.reject_reason()` reads the
  statement's leading verb at admission, so `ALTER`/`DROP`/`CREATE`/`TRUNCATE`/`VACUUM`
  /`ATTACH`/`PRAGMA` and friends are rejected whatever `Effect.kind` claims.
- **Cascades reach outside the measurement.** A granted `DELETE` on an observed table whose
  foreign key cascades into an unobserved table destroys those rows and they do not appear
  in the diff.
- **One engine stages one substrate.** A plan whose effects name another
  substrate is refused at admission; nothing coordinates two substrates, so a
  plan spanning SQL and a non-transactional sink needs the outbox pattern below.
- **`blast_radius` counts captured mutations, not distinct rows.** A row mutated twice in
  one plan contributes 2, so the limit is conservative and is not a row tally.
- **`ColumnValueGuard` and `TenantDrawdownGuard` are one-directional.** Both fire on a
  fall in the column total. An inflation passes, and so does any diff whose pre-image total
  is zero, which includes every insert-only plan. `TenantDrawdownGuard` re-denominates
  per tenant; it does not make the guard symmetric.
- **`StatedFootprint` is a cooperative diagnostic.** It reads `Effect.stated_rows`. An agent
  that omits the field on any effect turns the checker into a no-op.
- **Chain durability is opt-in and the commit record is not write-ahead.** See
  [Lifecycle](#lifecycle).
- **Lock footprint.** A stage holds write locks for its whole life. `max_stage_seconds`
  bounds it. Human review must not happen inside an open stage; abort, present the recorded
  diff, and re-stage on approval, because the substrate may have moved.
- **Latency.** Staging roughly doubles write-path round trips. Plans below a blast-radius
  threshold should bypass escrow entirely.
- **Non-transactional sinks cannot be staged.** An email has no shadow. Those belong in a
  transactional outbox written inside the stage and delivered by a separate relay, with the
  compensation serialized before the outbox row commits. `EffectKind.ENQUEUE` is defined
  and carries no behaviour.
- **Every threshold in `default_checkers` is a placeholder.** They are uncalibrated.
  Measure your own diffs and set them from the measurement.

[`docs/ESCROW_SPEC.md`](docs/ESCROW_SPEC.md) is the interface contract, with a conformance
section listing implemented, partial and unimplemented requirements.

## Install

`agentgov` resolves from git, so a clone needs no sibling checkout:

```bash
git clone https://github.com/crimsondevil0929/interlock
cd interlock && uv sync
```

Or install the package directly:

```bash
uv pip install git+https://github.com/crimsondevil0929/interlock
```

The `agentgov` dependency is a PEP 508 direct reference, which is what makes the second
form work. Two consequences worth knowing before you depend on this:

- **Interlock cannot be published to PyPI as-is.** PyPI rejects direct-URL dependencies.
  Publishing means putting `agentgov` on PyPI and pinning a version range instead.
- **`@main` is a moving target, and a resolver cache is keyed on name and version.** If
  `agentgov`'s version does not change when its behaviour does, a cached wheel built from
  an older commit satisfies `agentgov==0.1.0` forever and you get stale code with no
  warning. Pin a tag or a commit for anything reproducible, and use
  `uv sync --refresh-package agentgov` when you suspect a stale build.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run mypy --strict tests/ demo.py
```

Apache-2.0.
