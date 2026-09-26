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

These properties hold by construction:

1. No path from `STAGED` to `COMMITTED` skips adjudication.
2. `REJECTED` is not overridable in-process. Overriding means submitting a new plan that
   carries an explicit waiver, which is then itself a recorded artifact.
3. A committed effect is discoverable from the chain. `COMMIT_INTENT` is written, and
   forced to stable storage, before the substrate is told to commit, and `COMMITTED`
   after it returns, so a crash in that window leaves an intent with no terminal record
   after it.
4. That crash is resolved exactly, not guessed. An intent says only that a commit was
   *attempted*, so the substrate also writes a marker row, in `_interlock_commits`,
   inside the stage's own transaction: it exists if and only if the effects do. On
   restart, `EscrowEngine.recover()` reads the marker for every intent a crashed process
   left open and appends `COMMITTED` or `ABORTED`, noted as recovered. `EscrowRuntime`
   runs it at startup whenever it has a `chain_path`. An intent written before v0.1.2,
   or by a substrate without markers, is left open and logged for an operator: its
   marker's absence proves nothing. So is one the server has not decided yet (a client
   that died mid-`COMMIT` leaves PostgreSQL still committing); a later `recover()`
   resolves it.
5. A commit whose answer is lost is resolved the same way, while the process lives. If
   the connection drops with `COMMIT` in flight, the engine reads the marker at once:
   the plan is reported committed if it landed, and rolled back only once the server has
   ended the transaction without it. Until the server decides, `execute()` raises
   `CommitUnsettledError` and writes no terminal record. Do not retry the plan then: the
   intent stays open, and `recover()` settles it.

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

**The chain file.** `EscrowChain(path)` resumes an existing file: every record is read
and verified before the first append, so a restarted process continues the chain rather
than starting a second one at sequence 1. One file has one writer. The chain claims
`<path>.lock` for as long as it is open, and a second writer, in this process or
another, gets `ChainInUseError`: two writers would fork the chain, and recovery would
resolve one writer's in-flight commits as if it had died. `EscrowChain.load(path)`
reads and verifies a live chain without claiming it, and cannot append. A final line
left torn by a crash mid-append is cut off by the next writer, because that append
never returned. Intents and outcomes are fsynced before `append` returns; pass
`fsync=False` to give that up for speed.

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

### Refusals: two audiences

A refusal has two readers, and they must not get the same record. The operator
needs everything: which tenants the plan reached, the exact totals, the checker's
own message. The agent must get none of it. A guard's message is data about other
tenants, and an injected agent reading refusals is reading a side channel.

So every result carries both. `StageResult.refusal.evidence` is the operator's
record. `StageResult.feedback` (and `exc.feedback` on any error `execute` raises)
is what the agent may be told:

```python
from interlock import EscrowRuntime, TableSpec, TenantIsolation

runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
    checkers=[TenantIsolation(1)],
)
result = runtime.execute_sql("UPDATE orders SET total = 0", table="orders", tenant_id="acme")

assert not result.committed
print(result.feedback.render())  # for the agent
# The plan was refused and rolled back; nothing changed.
# - tenant_isolation: the plan changed rows of more tenants than one plan may
#   (at most 1); its declared tenants are acme. Confine every statement to its
#   declared tenants.
assert "globex" in result.refusal.evidence.tenants_touched  # for the operator
```

Feedback is built so that it cannot carry more than the agent already knew:

- it names only tables the plan's effects name, and tenants they declare. Anything
  else is "a table the plan does not name", never named or counted;
- row counts are buckets (`0`, `1`, `2-9`, `10-99`, `100-999`, `1000+`);
- it carries no aggregate at all: no column total, no fraction of one. The only other
  number is a built-in checker's configured limit, as a whole percentage;
- its text comes from fixed templates, and its constraints come in a canonical order,
  never the order the violations came in.

A checker contributes a typed hint per violation, and the hint is sanitized against the
plan field by field. A custom checker's hint can name the plan's own tables and tenants
and pick a kind of guidance. Its numbers and columns are dropped, because nothing can
tell a row count from a total. Errors are mapped by type, never by message, since a
database error can quote another tenant's row. Property tests check, over arbitrary
multi-tenant diffs and adversarial checkers, that renaming anything the plan did not
name, scaling every amount, or changing other tenants' values leaves the feedback
byte-identical (see `tests/test_feedback.py`).

### Repair: the part that would pass

A refused plan is often one step away from an acceptable one: nine corrections to one
tenant's orders and a tenth that reaches another tenant. Refusing all ten is right;
telling the agent which nine would pass turns a halt into finished work. `repair()`
finds the largest part of a plan that would be admitted, by experiment. It stages the
plan once and, inside that one stage, tries candidate sub-plans in savepoints: each is
run, measured and adjudicated by the same checkers, then rolled back.

```python
from interlock import EscrowRuntime, TableSpec, TenantIsolation

runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
    checkers=[TenantIsolation(1)],
)
plan = (
    runtime.plan(intent="apply ticket 9001 corrections")
    .update(
        table="orders",
        statement="UPDATE orders SET total = 450 WHERE id = 1",
        tenant_id="acme",
        effect_id="reprice_1",
        independent=True,
    )
    .update(
        table="orders",
        statement="UPDATE orders SET total = 250 WHERE id = 2",
        tenant_id="acme",
        effect_id="reprice_2",
        independent=True,
    )
    .update(
        table="orders",
        statement="UPDATE orders SET total = 0 WHERE id = 3",  # globex's order
        tenant_id="acme",
        effect_id="reprice_3",
        independent=True,
    )
    .build()
)
assert not runtime.execute(plan).committed

repair = runtime.repair(plan)  # advisory: nothing is committed here
print(repair.feedback.render())  # for the agent
# Resubmit the largest part of the plan that would be admitted: keep reprice_1,
# reprice_2; drop reprice_3.
# - reprice_3: tenant_isolation: the plan changed rows of more tenants than one plan
#   may (at most 1); its declared tenants are acme. Confine every statement to its
#   declared tenants.
assert runtime.execute(repair.proposal).committed
```

- **Advisory, and re-adjudicated.** The repair stage is always rolled back. The
  proposal is a new plan whose `repair_of` names the refused one, and it commits only
  through `execute()`, staged and adjudicated again from scratch, because the database
  may have moved in between.
- **Exactly as proposed, and once.** A plan naming itself a repair is admitted only if
  this engine's chain holds a `REPAIR_PROPOSED` record with its exact content hash, and
  only until it has committed. A widened or forged "repair" is refused.
- **No monotonicity assumed.** A debit alone fails a drawdown guard that the debit and
  its balancing credit pass together. A search that dropped whatever fails on its own
  would keep a lone credit; this one keeps both and drops only the step that is wrong.
- **Runnable candidates, largest first.** A step is kept only with everything it
  depends on. The whole plan is tried, then every such sub-plan one step smaller, and
  so on, later steps dropped first within a size; the first admitted one is a largest,
  and `repair.exhaustive` says so. `max_trials` (default 32) bounds the search; when it
  runs out, a greedy pass keeps each step whose addition is admitted, which is sound but
  may not be largest. The stage's time bound ends the search too.
- **Explained without leaking.** Each dropped step says why, from its own trial: the
  constraints that refused it, sanitized like every other feedback, a dropped
  dependency, or a statement the substrate refuses outright.

Both substrates have savepoints. A repair's trials all run inside one stage, so the
stage's locks are held for the whole search.

## AgentGov integration

Interlock imports [`agentgov`](https://github.com/crimsondevil0929/agentgov) as a
**read-only audit dependency**. The dependency runs one way (`interlock -> agentgov`) and
requires no change to AgentGov.

Every adjudication is written to a hash-linked chain whose records carry the AgentGov head
hash observed at the time. That proves a *lower* bound on a record's time. It does not
prove an upper bound on its own, because a record could name a stale head, so
`verify_anchors()` additionally requires the observed AgentGov sequence to be
non-decreasing across an append-only chain.

**The breaker is read as it is now, immediately before commit.** Attached read-only
(`audit_path=`, the separate-process deployment), Interlock refreshes its view of the
governor before every record and before the pre-commit breaker check, verifying
everything the governor wrote since, so a halt written after Interlock attached stops
the commit. A view that fails verification refuses to operate. With a governed manager
in the same process, the governor's own lock is held from that check through the
substrate's commit, so a trip lands strictly before it (and the commit is refused) or
strictly after it. Across processes no lock spans both databases: a trip the governor
commits between the check and the commit cannot be excluded, and when one happens the
`COMMITTED` record says so.

Where Interlock is co-resident with a write-capable governor it also writes its own chain
head into AgentGov's chain: into a zero-value `ANCHOR` entry, or, when the plan carries a
cost, into the memo of the spend that settles it. `memo` is inside AgentGov's hash
payload, so the reverse anchor cannot be altered without breaking AgentGov's own
verification. The two chains then interlock in both directions.

**Reverse anchoring is free.** `settle_cost` defaults to `"0"`, which writes a zero-value
`ANCHOR` entry and charges nothing. Pass the plan's real cost and the anchor rides on the
spend that settles it instead:

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

## Receipts

With a `ReceiptIssuer`, every plan the engine adjudicates, committed or refused, gets a
signed ARC1 receipt in an agentgov `ReceiptLog` (the format is agentgov's
`docs/RECEIPTS.md`). Anyone holding the issuer's key can then check offline what the
agent was allowed to do, what it said it would do, what it measurably did, what was
decided and what it cost:

```python
from agentgov.receipts import HmacKey, ReceiptLog, verify_bundle

from interlock import EscrowRuntime, ReceiptIssuer, TableSpec, TenantIsolation

key = HmacKey.generate()
log = ReceiptLog("support-receipts", key, path="receipts.jsonl")
runtime = EscrowRuntime(
    "prod.db",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    scope_id="support-agent",
    checkers=[TenantIsolation(1)],
    receipts=ReceiptIssuer(log),
)
result = runtime.execute_sql(
    "UPDATE orders SET total = 480 WHERE id = 1", table="orders", tenant_id="acme"
)
receipt = result.receipt
print(receipt.outcome.status.value, receipt.effect.row_count)  # committed 1

bundle = log.bundle(log.index_of(receipt.receipt_id), log.checkpoint())
assert verify_bundle(bundle, issuer_key=key).passed
```

What goes into one:

- **Authority:** the AgentGov scope path when an anchor is attached, the trajectory, and
  a capability naming the observed tables and the tightest `BlastRadius` limit.
- **Intent and effect:** the plan's content hash and stated footprint; the diff hash the
  chain's `DIFF_COMPUTED` record carries; a salted commitment over every measured row
  change, from which one row can be disclosed later without the rest; and a hash of the
  observed schema, foreign keys included.
- **Coverage:** the observed tables, and every gap in words: an acknowledged cascade, a
  substrate that did not read the foreign keys or does not refuse unobserved tables.
- **Decision:** the verdict hash, each checker with a digest of its configuration, the
  issuer's policy epoch, and, for a repair, the refused plan's receipt as `repair_of`.
- **Cost:** the AgentGov transaction that settled the plan. The receipt is issued last,
  after the reverse anchor, so agentgov's verifier can check the cost against the ledger.

The receipt and the escrow chain name each other: the stage's terminal record carries
the receipt id, and the receipt's `anchors.escrow` names that record by sequence and
hash. A receipt that cannot be issued after a commit is logged, not raised; the effects
stand, and the terminal record names the receipt that should exist. An HMAC receipt
verifies only for a holder of the key: for third parties, sign with agentgov's
`Ed25519Signer` (`agentgov[sign]`) and publish the public key.

## Recovery

A halt is correct, and it used to be the end of the task. `RecoveryRuntime` gives a halted
task a bounded way to finish instead: a few more model calls, each under tighter constraints
than the one before, paid from a reserve set aside for it, and each recorded and signed
before it is made.

```python
from decimal import Decimal

from agentgov import BudgetManager
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.exceptions import AgentThrashingError
from agentgov.receipts import HmacKey

from interlock import Directive, RecordLog, RecoveryPolicy, RecoveryRuntime, Trip, TripKind

governor = BudgetManager()
governor.open_root("org", "10.00")
governor.delegate("org", "support-agent", "5.00")
policy = RecoveryPolicy(
    reserve=Decimal("0.50"),  # carved out of support-agent's envelope
    step_estimate=Decimal("0.05"),  # held for each recovery call
    directives=(
        Directive(
            "no-repeat",
            "Do not repeat a tool call that has already returned; use the results you have.",
            frozenset({TripKind.THRASHING}),
        ),
    ),
)
records = RecordLog(HmacKey.generate(), log_id="support")
runtime = RecoveryRuntime(
    governor, "support-agent", policy, records, tools=["lookup", "apply_plan"]
)

transcript = [
    {"role": "user", "content": "What is the total of order 1?"},
    {
        "role": "assistant",
        "content": [{"type": "tool_use", "id": "toolu_02", "name": "lookup", "input": {"id": 1}}],
    },
]
breaker = CognitiveBreaker(
    policy=CognitivePolicy(max_identical_repeats=2), observer=None, manager=governor
)
try:
    for _ in range(2):  # the same lookup, twice: halted before the second runs
        breaker.observe_call("support-agent", "lookup", kwargs={"id": 1})
except AgentThrashingError as exc:
    trip = Trip.of(exc, tool="lookup")

step = runtime.recover(trip, transcript, max_tokens=4096)
print(step.rung, step.tools)  # revoke_tool ('apply_plan',)
# Send step.messages (with step.betas) and step.max_tokens, the system prompt and
# the tools as before; settle what the call cost; refuse revoked tools where they run.
runtime.settle(step, "0.03")
runtime.check_tool("apply_plan")
runtime.close()
records.verify()
print(governor.is_halted("support-agent"), len(records))  # True 4
```

**The ladder** is fixed and deterministic, one rung per step: revoke the tool the halt
names, then an operator directive from the policy's allowlist, then a lower token ceiling,
then guidance in fixed words. Constraints come before conversation. Each step takes the
first rung that can still do something for this kind of halt, and tightening only
accumulates: a revoked tool stays revoked and the ceiling stays down. When no rung is left,
or `max_steps` is reached, `recover()` raises `RecoveryExhaustedError` and the halt stands.
The same halts always take the same steps. A refused plan is left to guidance by default,
so the agent can correct it; its guidance is the refusal's sanitized feedback, or a repair's
(see [Repair](#repair-the-part-that-would-pass)).

**History is never edited.** A step returns the transcript it was given, as the same
objects, with messages appended: error results for tool calls the halt stopped, then the
rung's notice. The system prompt and the tool definitions are never touched. On Claude
Opus 5, Opus 5.5, Opus 4.8, Fable and Mythos, a directive goes in an appended
`{"role": "system"}` message and a revocation in a `tool_removal` block (beta
`mid-conversation-tool-changes-2026-07-01`, in `step.betas`), the operator channel a user
turn cannot forge; `Channel.USER` uses user-turn notices for every other model. Either way,
`check_tool()` refuses a revoked tool where the harness runs it. Each step checks that the
transcript it is handed extends the one the last step returned, so an edit in between is
refused, and its record pins the transcript before and after by a running hash
(`transcript_head`).

**The reserve sits beside the scope, not under it.** A trip halts the tripped scope's
whole subtree, and recovery exists for a tripped scope, so `{scope}/recovery` is carved out
of the scope's own envelope (released to its parent and delegated from there). The halted
scope stays halted; every call made during recovery is billed to the reserve, a step's
through `recover()` and `settle()`, the task's own through `hold()` and `capture()`. A root
scope's reserve is a new root funded from the treasury, or `RecoveryPolicy(funding=...)`
names a scope to delegate it from. `close()` returns what is left to the parent.

**Every act is signed first.** Opening, each step, each settlement and the close are
`RecordLog` entries: ILOK1, agentgov's canonical JSON under an `ILOK1/record/v1` signing
prefix, hash-linked, and anchored into the AgentGov ledger as `ANCHOR` entries, so
`check_anchors()` catches a log truncated or rewritten after the fact. A step's record names
the halt (and a refused plan's ARC1 receipt), the rung and exactly what it did, the hold
that pays for it, the policy's digest, and the transcript before and after, and is written
before the step is returned. Persist the log (`RecordLog(..., path=...)`): a runtime
restarted over it adopts the recovery scope and replays what was revoked and lowered, so a
restart never loosens a constraint.

## Extension quotes

AgentGov's backstop is blunt on purpose: an authorization that would overdraw a scope
trips its breaker, and so does a capture that spends it to zero. For a runaway loop that is
the answer. For a task that is only more expensive than its envelope, it throws away the
work done. `BudgetGuard.authorize()` asks first: when a call will not fit, it returns a
signed `ExtensionRequest` instead of placing a hold that would trip the breaker.

```python
from agentgov import BudgetManager
from agentgov.receipts import HmacKey

from interlock import BudgetGuard, ExtensionRequest, Milestones, RecordLog

governor = BudgetManager()
governor.open_root("org", "10.00")
governor.delegate("org", "support-agent", "5.00")
guard = BudgetGuard(governor, RecordLog(HmacKey.generate(), log_id="support"))

held = guard.authorize("support-agent", "4.60")  # fits: an ordinary hold
governor.capture(held, "4.60")

done = Milestones(done=3, total=5, unit="tickets")
quote = guard.authorize("support-agent", "0.50", milestones=done)
assert isinstance(quote, ExtensionRequest)  # did not fit: quoted, and nothing tripped
print(quote.requested, governor.is_halted("support-agent"))  # 3.44 False
print(quote.render())
# Extension requested for support-agent: 3.44000000.
# Spent 4.60000000 (support-agent 4.60000000); held 0.00000000; 0.40000000 left; ...
# Proof of work: 0 plan(s) committed (0 rows); declared 3 of 5 tickets done.
# Estimate: 1.53333333 per unit x 2 remaining = 3.06666667, plus 25% margin = 3.84000000 ...

grant = guard.grant(quote, approved_by="ops@example.com")
print(grant.scope_id, governor.available(grant.scope_id))  # support-agent/ext-1 3.84000000
```

A quote has three parts, and is a signed `extension.quoted` record anchored in the ledger:

- **Spend to date**, from the ledger: what the task's scopes (the scope, its recovery
  scope, its extensions) settled net of refunds, what they hold, and what is left.
- **Proof of work**: with `BudgetGuard(receipts=...)`, the ARC1 receipts of the plans the
  task committed and the rows they measurably changed, with a checkpoint the receipt log
  signed for the quote, so each receipt is provable by inclusion
  (`log.bundle(log.index_of(id), checkpoint)`); the recovery steps it took; and any
  milestones the harness declares, which are carried as declared, not proven.
- **An estimated completion cost**, by a named method: cost per declared milestone times
  those remaining, or with none declared, the call that did not fit; plus a margin,
  rounded up to the cent. `requested` is that, less what the scope has left.

A quote is answered once, before it expires, by the guard that issued it: `grant()` or
`decline()`, each a signed record naming the quote. A root scope is topped up in place, and
if the money running out is what tripped it, its breaker is reset. A delegated scope cannot
be topped up, so the grant delegates `{scope}/ext-N` beside it, carries along what the old
scope had left, and the task bills there from then on. A grant the parent cannot make
changes nothing. A scope halted for any other reason is not quoted: `authorize()` raises
AgentGov's `CircuitOpenError`, because more money is not the answer to a safety halt.

A `RecoveryRuntime` given the guard quotes for its own reserve the same way: when a step
will not fit, `RecoveryExhaustedError.quote` carries the request, and `extend()` takes up
the grant. Quotes are operator evidence; nothing in them is sent to the agent. Granting is
the operator's act: the guard records `approved_by` but cannot authenticate it, so put
`grant()` behind the approval you already trust, and never within the agent's reach as a
tool.

## PostgreSQL

`PostgresSubstrate` stages each plan in a `REPEATABLE READ` transaction and measures it with
row triggers installed once, so no stage ever alters a busy table. Install as the tables'
owner, then stage as a separate role granted DML on the observed tables and nothing else:

```bash
uv pip install 'interlock[postgres]'
interlock install --config interlock.toml --database postgresql://owner@db/app
interlock check   --config interlock.toml --database postgresql://interlock_agent@db/app
```

```toml
substrate = "postgres"
schema = "public"
stage_roles = ["interlock_agent"]   # granted the interlock schema's stage functions
acknowledge_cascades = []

[[tables]]
name = "orders"
columns = ["id", "tenant", "total"]
tenant_column = "tenant"
```

<!-- readme-test: skip reason="needs a live PostgreSQL server" -->
```python
from interlock import EscrowEngine, PlanBuilder, PostgresSubstrate, TableSpec, default_checkers

substrate = PostgresSubstrate(
    "postgresql://interlock_agent@db/app",
    tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
)
engine = EscrowEngine(substrate, checkers=default_checkers(row_limit=8))
plan = (
    PlanBuilder("support-agent")
    .update(
        table="orders",
        statement="UPDATE orders SET total = %(total)s WHERE id = %(id)s",
        parameters={"total": 100, "id": 1},
    )
    .build()
)
result = engine.execute(plan)
```

What `interlock install` puts in the database: an `interlock` schema holding the stage
table and four functions, and on each observed table one `AFTER` row trigger plus one
`TRUNCATE` trigger, both `ENABLE ALWAYS` so `session_replication_role` does not switch them
off. For a transaction that opened no stage, the trigger logs the write to
`interlock.unmediated` (see [Unrecorded writes](#unrecorded-writes)). For one that did, it
writes before and after images into a temporary table that exists only in that session for
that transaction. Rows are keyed to the stage by `pg_current_xact_id()`, read from a row
only the stage-opening function can write, not from the `interlock.stage_id` setting,
which any statement could change; the setting is still set, and the trigger refuses to go
on when the two disagree.

Every stage checks, before its first effect and with the observed tables locked
`ROW EXCLUSIVE` so none of it can change underneath:

- each observed table carries Interlock's triggers, enabled always, capturing exactly
  its `TableSpec`'s columns, and has no inheritance children or partitions (a statement
  on the parent writes their rows too, through no trigger, and PostgreSQL checks
  privileges on the parent alone);
- the stage's role is not a superuser, owns no observed table (an owner can disable a
  trigger), and can write no other table, directly, through a column grant, or through
  any role it belongs to. PostgreSQL has no statement authorizer, so the grant is the table
  boundary; the substrate checks it rather than trusting it. `enforce_table_access=False`
  trusts it;
- the cascade check, read from `pg_constraint`.

What differs from SQLite:

- **Placeholders are psycopg's:** `%(name)s`, and `%%` for a literal percent sign.
- **Only row statements stage:** `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`,
  `WITH`, `VALUES`, `TABLE`. Each is sent as a prepared statement, which the server will
  not split, so `UPDATE ...; COMMIT` fails instead of committing before adjudication.
- **A cascade gate fires per row.** A delete of a gated row, or an update that changes a
  gated key, is refused inside the statement and PostgreSQL rolls the statement back,
  cascade included. SQLite refuses when it prepares the statement.
- **`NUMERIC` is read as `Decimal`**, exactly.
- **Bounds are the server's:** `statement_timeout`, `lock_timeout` and
  `idle_in_transaction_session_timeout` are set for the stage and re-set before every
  effect, so a statement cannot lift them, and a stage whose client died cannot hold locks
  past `max_stage_seconds`.
- **Crash recovery reads the transaction.** The stage's row is its commit marker, and
  `pg_current_xact_id()` is written into the commit intent, so recovery can tell a
  transaction the server still has open (a crashed client's, until its session times out,
  or one still committing when its client died) from one that rolled back, and leaves the
  first open. A connection lost with `COMMIT` in flight is answered from the same marker.
  PostgreSQL stops `statement_timeout` before running a commit's deferred triggers, so
  work there is bounded by the stage's `lock_timeout` and not by its statement bound.

What grants cannot see, so the substrate cannot either: a `SECURITY DEFINER` function the
role may call that writes elsewhere, an extension such as `dblink` that opens another
connection, and large objects. Do not grant them to the stage role. Requires PostgreSQL 14
or later; CI runs 16.

## Unrecorded writes

The monitor only sees what goes through it. A cron job, a migration, a DBA at a prompt, or
the agent's own credentials used directly all write observed tables and leave nothing in
the escrow chain. `interlock reconcile-effects` is the check that closes the loop: nothing
changes an observed table without a record.

```bash
interlock install           --config interlock.toml   # once; SQLite needs it for this too
interlock reconcile-effects --config interlock.toml --chain escrow.jsonl [--after N]
```

It fails (exit 1) on:

- **an unmediated write:** a row change no stage made. On PostgreSQL the installed trigger
  logs each one to `interlock.unmediated` inside the writer's own transaction, with the
  session user, `application_name` and transaction id; a `TRUNCATE` is logged too. On
  SQLite, `interlock install` adds permanent journal triggers that record every row change
  in `_interlock_journal`, and each committed stage records the range of journal rows it
  produced, which is exact because `BEGIN IMMEDIATE` admits one writer at a time. A
  cascade from a table nobody observes is found row by row;
- **an unrecorded stage:** one the database committed that no chain records, such as one
  opened by hand with the stage role's credentials, or by an engine on the default
  in-memory chain;
- **a contradicted stage:** recorded as aborted, or under another plan;
- **an unresolved stage:** committed with only its commit intent in the chain, after a
  crash in the commit window. Recovery resolves it; `EscrowRuntime` runs recovery at
  startup;
- on SQLite, an observed table whose journal trigger is missing.

Each run prints `last entry: N`; pass it back as `--after N` to check only what is new.
Exit code 5 means a chain failed verification and proves nothing. On PostgreSQL, run it as
a role named in `audit_roles` at install, which may read Interlock's logs and write
nothing.

What it cannot see: anyone who can disable the triggers or edit the logs. On PostgreSQL
that is the tables' owner or a superuser, which logical decoding would close; on SQLite it
is anyone who can write the file.

## Scope

**Two substrates: SQLite and PostgreSQL.** One connector at the row-level-diff standard is
worth more than several reporting only row counts, because a row count is the summary this
design exists to replace.

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
  `enforce_table_access=False` to lift the unobserved-table rule for a migration; the rules
  below stay on.

  The same callback refuses a statement that writes the capture table (which would erase
  the measurement), the commit-marker table, or transaction control: a `COMMIT` inside a
  stage used to make every effect before it durable before any checker ran. Grant the
  connection exactly the observed tables anyway; a database-enforced grant is a boundary,
  and this is a second one in front of it.

  DDL and transaction control are refused twice over: `SqliteSubstrate.reject_reason()`
  reads the statement's leading verb at admission, so `ALTER`/`DROP`/`CREATE`/`TRUNCATE`
  /`VACUUM`/`ATTACH`/`PRAGMA`/`COMMIT`/`SAVEPOINT` and friends are rejected whatever
  `Effect.kind` claims.
- **A foreign-key cascade into an unobserved table is refused unless you acknowledge it.**
  A `DELETE` on `orders` that cascades into an unobserved `order_notes` used to destroy
  those notes unmeasured. Every stage now reads the foreign-key graph under its write lock
  and refuses, before a row changes, a delete or a referenced-key update whose `CASCADE`,
  `SET NULL` or `SET DEFAULT` actions reach an unobserved table, naming the path. The
  analysis follows chains of actions to any depth and is column-precise: updating
  `orders.status` is never refused because of a key on `orders.id`. `EscrowRuntime` runs
  the same check at startup and logs every gated operation. To let a cascade run
  unmeasured, name the table in `acknowledge_cascades=[...]`; every stage that runs with
  that gap says so in its `STAGE_OPENED` record. The refusal is enforced three ways, so no
  single layer is load-bearing: the authorizer refuses the parent operation, the
  authorizer refuses any foreign-key action SQLite compiles into the table (which is what
  catches `INSERT OR REPLACE`), and temporary triggers on the table abort any row change
  there while the stage is open.
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
- **Chain durability is opt-in.** With no `chain_path` the chain lives in memory and
  dies with the process. With one, the intent is write-ahead and a crashed commit is
  resolved exactly on restart; see [Lifecycle](#lifecycle). The `_interlock_commits`
  table gains one row per committed stage and is not pruned.
- **The chain is keyless.** Anyone who can write the chain file can recompute a SHA-256
  chain from start to finish and it will verify. A reverse anchor in a governed AgentGov
  is one copy of the head outside the file. With [receipts](#receipts) on, each
  adjudicated plan also gets a signed receipt naming its terminal record, under a key the
  chain file does not hold; the chain itself stays unsigned.
- **Lock footprint.** A stage holds write locks for its whole life, a repair search's
  included. `max_stage_seconds` bounds it. Human review must not happen inside an open stage; abort, present the recorded
  diff, and re-stage on approval, because the substrate may have moved.
- **Recovery trusts the harness to route its calls.** The runtime holds and records its
  own steps, refuses a revoked tool when asked, and catches an edited transcript at the
  next step. It cannot see a harness that bills a recovery call to another scope, runs a
  tool without calling `check_tool()`, or sends the model something other than
  `step.messages`.
- **An extension estimate is arithmetic on what the harness declares.** Cost per declared
  milestone times those remaining assumes the rest of the work costs what the done work
  did; with none declared it prices only the call that did not fit. The receipts in a
  quote's proof of work are verifiable; its milestones are the harness's claim.
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
- **The pin is an agentgov release tag, never a branch.** A resolver cache is keyed on
  name and version, and `@main` is a moving target: interlock 0.1.1 locked an agentgov
  commit that reported itself as 0.1.0 and lacked APIs this README relied on. Interlock
  0.1.2 pins the agentgov tag `v0.1.2`; this line pins `v0.2.0`, the first release with
  `agentgov.receipts`. That tag's package metadata still reports version 0.1.2, so tell
  the two apart by the commit, `6d3cac2`, which `uv.lock` records. Pin a tag or a commit
  for anything reproducible, and use `uv sync --refresh-package agentgov` when you
  suspect a stale build.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run mypy --strict tests/ demo.py
```

The PostgreSQL tests run against a live server: set `INTERLOCK_TEST_POSTGRES_DSN` to a
role that may create databases and roles, and `INTERLOCK_REQUIRE_POSTGRES=1` to fail
rather than skip without one. Two suites are release gates.
`tests/test_crash_consistency.py` kills a real process with `SIGKILL` at every step of a
PostgreSQL commit, and at random instants, then checks exactly what recovery makes of it.
`tests/test_tamper_evidence.py` alters every part of the audit trail and checks that
verification fails exactly there. `INTERLOCK_CRASH_SEED` and `INTERLOCK_CRASH_ROUNDS`
replay or lengthen the random-instant run.

Apache-2.0.
