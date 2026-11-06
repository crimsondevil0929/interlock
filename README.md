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
      orders.total $20,925.00 -> $0.00

    ADJUDICATED by 7 deterministic checks:
      BLOCK   blast_radius          plan would mutate 229 rows, limit is 8
      BLOCK   tenant_isolation      plan spans 4 tenants, limit is 1
      BLOCK   no_delete             plan deletes 103 row(s) from ungranted table(s): order_audit
      BLOCK   column_value_guard    orders.total falls 100.0% (20,925.00 to 0.00), limit is 30%
      advise  stated_footprint      agent stated 6 row(s); substrate measured 229 (38.2x)

    OUTCOME  ROLLED BACK
      Byte-identical to before the plan ran. Nothing reached disk.
```

## The stack: consequence control, under the gateway

A gateway decides whether an agent may make a call. This stack decides whether what the
call changed may be kept, and produces evidence for someone who trusts neither the agent
nor the operator. It runs behind an MCP or policy gateway and doesn't replace it.

| Layer | Package | The question it answers |
|---|---|---|
| [AgentGov](https://github.com/crimsondevil0929/agentgov) | [`interlock-agentgov`](https://pypi.org/project/interlock-agentgov/) | May this scope spend this amount, counted across its whole delegation tree and every session, with in-flight calls held? |
| [Interlock](https://github.com/crimsondevil0929/interlock) | [`interlock-escrow`](https://pypi.org/project/interlock-escrow/) | Does what this transaction actually changed, read back from the database, satisfy policy? Commit it or roll it back, and deliver its outbound API calls exactly once. |
| [Fiduciary](https://github.com/crimsondevil0929/fiduciary) | [`interlock-fiduciary`](https://pypi.org/project/interlock-fiduciary/) | Who set those limits, and who approved each exception? Signed mandates, quorum warrants, and an audit bundle anyone verifies offline. |

## Why authorization does not catch this

A prompt-injected agent is a fully authorized agent. It is doing something it has
permission to do, so an authorization check passes. The injected instruction arrived from
the customer's own database, inside a tool result, after every provider-side filter had
already run, so a provider-side filter does not see it either. The only remaining place to
catch it is between the effect being computed and the effect becoming durable.

That position requires write-path credentials to the database the effects land in, which is
why this runs inside the deployment rather than at the model provider.

The demo also rules out model quality as the cause. The agent doesn't loop, costs $0.0012
and writes valid SQL on its first try. The damage isn't a model failure.

**`demo.py` uses a scripted agent, not a live model.** `injected_plan` and the rest of
Act 2's input are fixed `EffectPlan`s defined in `demo.py`. No model is called. That keeps
two questions apart: does Interlock stop this plan, and would a real model produce it? The
demo answers only the first. Current Claude models decline the injected instruction
shown above in several realistic phrasings. For runs against a real model, see
[`scripts/live_gauntlet.py`](scripts/live_gauntlet.py): eight scenarios with a real
`anthropic.Anthropic` client and governed spend. Its results are not reproducible, because
model behavior varies.

## What it measures

The diff is read **from the substrate**, never reconstructed from the plan. The two are
routinely different:

| | |
|---|---|
| Agent stated | 1 row |
| SQL `rowcount` | 1 row |
| **Measured** | **2 rows across 2 tables** |

An audit trigger that the plan doesn't mention doubled the footprint. Inspecting the plan
or parsing the SQL can't show that. Reading the change back from the database does.

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
4. That crash is resolved exactly, without guessing. An intent only says a commit was
   *attempted*, so the substrate also writes a marker row in `_interlock_commits`, inside
   the stage's own transaction. The marker exists if and only if the effects do. On
   restart, `EscrowEngine.recover()` reads the marker for every intent a crashed process
   left open and appends `COMMITTED` or `ABORTED`, noted as recovered. `EscrowRuntime`
   runs it at startup whenever it has a `chain_path`. An intent written before v0.1.2, or
   by a substrate without markers, is left open and logged for an operator, because a
   missing marker proves nothing there. So is one the server hasn't decided yet: a client
   that died mid-`COMMIT` leaves PostgreSQL still committing. A later `recover()` resolves
   it.
5. A commit whose answer is lost is resolved the same way while the process is alive. If
   the connection drops with `COMMIT` in flight, the engine reads the marker at once. The
   plan is reported committed if it landed, and rolled back only once the server has ended
   the transaction without it. Until the server decides, `execute()` raises
   `CommitUnsettledError` and writes no terminal record. Don't retry the plan then. The
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

The runtime takes every option the engine does: `substrate=` in place of the
path (any substrate, PostgreSQL included), `windows=`, `inbox=`, `sinks=`, and
`anchor=` for claim and settle. `EscrowRuntime.from_config(config, scope_id=...)`
builds the one `interlock.toml` describes.

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

**The chain file.** `EscrowChain(path)` resumes an existing file. Every record is read and
verified before the first append, so a restarted process continues the chain instead of
starting a second one at sequence 1. One file has one writer. The chain claims
`<path>.lock` for as long as it's open, and a second writer, in this process or another,
gets `ChainInUseError`. Two writers would fork the chain, and recovery would treat one
writer's in-flight commits as if it had died. `EscrowChain.load(path)` reads and verifies a
live chain without claiming it, and can't append. If a crash tears the last line
mid-append, the next writer cuts it off, because that append never returned. Intents and
outcomes are fsynced before `append` returns. Pass `fsync=False` to trade that for speed.

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

Checkers are pure functions of `(plan, diff)`: no I/O, no clock, no RNG, no model call. A
checker that reads the outside world can't be replayed, and an auditor can't check a
verdict that can't be replayed. When a judgment really needs a model, the model is a
**sensor**: its output is passed in when the deployment is configured, and never consulted
from inside `check`. A checker that raises counts as a blocking violation, so failures fail
closed.

| Checker | Bounds |
|---|---|
| `BlastRadius` | captured mutations in one plan |
| `TenantIsolation` | distinct tenants one plan may span; with `declared=True`, the tenants its effects declare; with `dimension=`, any other partition (a patient, an account) |
| `ColumnValueGuard` | fall, or rise, in a column total, table-wide |
| `TenantDrawdownGuard` | fall, or rise, in a column total, **per tenant**, or per any other partition |
| `NoDelete` | deletions outside granted tables |
| `NoSchemaChange` | effects declared as DDL |
| `TruncationGuard` | a diff that hit the row cap |
| `StatedFootprint` | the agent's claim against the measurement |
| `CrossEffectAgreement` | an outbound request against the rows it rides with ([outbox](#outbound-requests-the-transactional-outbox)) |
| `SinkAllowlist` | the sinks and operations a plan may call |
| `OutboundCount` | the requests one plan may enqueue, in all or per sink |
| `PayloadAmountCap` | a payload amount, per request, per tenant or per plan, per currency or any unit |
| `RecipientAllowlist` | where a request may send: email domains and addresses, https hosts, per tenant |
| `OutboundTenantIsolation` | the tenants one plan's requests may span |
| `FactAgreement` | a write against the inbound fact it must follow ([inbox](#inbound-facts-the-zero-trust-inbox)) |

`TenantIsolation(1)` counts tenants. A plan declared for `acme` that changes one row of
`globex` and none of its own spans one tenant, so it passes. When an agent acts for one
tenant and the operator stamps every effect with it (`tenant_id=`, never the model's
choice), pass `declared=True`. Then any row of a tenant the plan's effects don't declare
is refused, one row as much as many. The agent is told its own tenants and nothing about
the other one.

`TenantDrawdownGuard` exists because `ColumnValueGuard` sums the column across
the whole diff, and a sum is the wrong denominator on a multi-tenant
substrate. A plan that zeroes one tenant while inflating another by the same
amount moves that sum by 0%, so a table-scoped guard passes it — with a tenant
wiped. Grouping by tenant first is the only way to see it.
Column totals are `Decimal`, computed through `Decimal(str(value))`, so a
guard permitting a 30% drawdown does not admit 30.000000000000004%.

### Partitions beyond the tenant, and guards that watch a rise

A hospital partitions by facility *and* by patient, and a cloud by account and
environment. A table can name more dimensions than its tenant, each a column read back
from the captured row, and a plan can be held to one label of each at once:

```python
from interlock import ColumnValueGuard, TableSpec, TenantDrawdownGuard, TenantIsolation

orders = TableSpec(
    "med_orders",
    columns=["id", "facility_id", "patient_id", "drug", "mme_per_day", "status"],
    partitions={"tenant": "facility_id", "patient": "patient_id"},
)
checkers = [
    TenantIsolation(1, declared=True),  # one facility
    TenantIsolation(1, declared=True, dimension="patient"),  # and one patient's chart
    ColumnValueGuard("med_orders", "mme_per_day", max_rise_fraction=0),
    TenantDrawdownGuard("med_orders", "mme_per_day", max_rise_fraction=0.5, dimension="patient"),
]
```

An effect declares its labels (`PlanBuilder.update(..., tenant_id="f-1",
partitions={"patient": "p-1182"})`), and the agent is told only the ones it declared. Outside
finance, the dangerous direction is often up: a dose, a replica count, a role grant. A guard
can bound a rise as well as a fall. One with a rise bound reports totals at their own
precision, `0.125` rather than `0.13`. A guard configured the old way reports and decides
exactly as before. A rate window can also keep a history per patient, with
`per="partition:patient"`.

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

A refusal has two readers, and they can't get the same record. The operator needs
everything: which tenants the plan reached, the exact totals, the checker's own message.
The agent must get none of that. A guard's message contains data about other tenants, so
an injected agent could use refusals as a side channel.

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
# - tenant_isolation: the plan changed rows of more tenants than allowed (at most
#   1); its declared tenants are acme. Confine every statement to its declared
#   tenants.
assert "globex" in result.refusal.evidence.tenants_touched  # for the operator
```

Feedback is built so that it cannot carry more than the agent already knew:

- it names only tables the plan's effects name, and tenants they declare. Anything
  else is "a table the plan does not name", never named or counted;
- row counts are buckets (`0`, `1`, `2-9`, `10-99`, `100-999`, `1000+`);
- it carries no aggregate at all, neither a column total nor a fraction of one. The only
  other number is a built-in checker's configured limit, as a whole percentage;
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

A refused plan is often one step away from an acceptable one, for example nine corrections
to one tenant's orders and a tenth that reaches another tenant. Refusing all ten is right.
Telling the agent which nine would pass lets it finish the work. `repair()` finds the
largest part of a plan that would be admitted, by trying it. It stages the plan once, and
inside that stage it tries candidate sub-plans in savepoints. Each one is run, measured
and adjudicated by the same checkers, then rolled back.

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
# - reprice_3: tenant_isolation: the plan changed rows of more tenants than allowed
#   (at most 1); its declared tenants are acme. Confine every statement to its
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
- **No monotonicity assumed.** A debit alone fails a drawdown guard that the debit and its
  balancing credit pass together. A search that dropped whatever fails on its own would
  keep a lone credit. This one keeps both, and drops only the step that's wrong.
- **Runnable candidates, largest first.** A step is kept only with everything it depends
  on. The whole plan is tried first, then every such sub-plan one step smaller, and so on,
  dropping later steps first within each size. The first one admitted is a largest, and
  `repair.exhaustive` says so. `max_trials` (default 32) bounds the search. When it runs
  out, a greedy pass keeps each of the plan's independent parts (the connected components
  of its dependency graph), then each step, as long as adding it is admitted. That result
  is sound but may not be the largest. Parts go first because steps a rule admits only
  together, such as a row and the request that goes with it, are each refused alone. The
  stage's time bound also ends the search.
- **Explained without leaking.** Each dropped step says why, from its own trial with the
  dropped steps that depend on it added back. The reason is the constraints that refused
  it (sanitized like all other feedback), a dropped dependency, or a statement the
  substrate refuses outright.

Both substrates have savepoints. A repair's trials all run inside one stage, so the
stage's locks are held for the whole search.

## Rate windows

A checker sees one plan. An agent that keeps every plan under every per-plan limit, a
refund of 50 a hundred times over, passes every one. A rate window measures a plan with
what came before it (`docs/EPIC4_DESIGN.md` §3):

```python
from datetime import timedelta

from interlock import (
    BlastRadius,
    EscrowEngine,
    OperationSpec,
    RateWindow,
    Requests,
    RequestSum,
    SinkRegistry,
    SinkSpec,
    SqliteSubstrate,
    TableSpec,
)

engine = EscrowEngine(
    SqliteSubstrate(
        "prod.db",
        tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    ),
    checkers=[BlastRadius(100)],
    sinks=SinkRegistry(
        [
            SinkSpec("mail", (OperationSpec("send"),)),
            SinkSpec("payments", (OperationSpec("refunds.create"),)),
        ]
    ),
    windows=[
        RateWindow("mail_per_tenant_hour", timedelta(hours=1), 10, Requests("mail"), per="tenant"),
        RateWindow("mail_per_agent_hour", timedelta(hours=1), 50, Requests("mail")),
        RateWindow(
            "refunds_per_agent_day",
            timedelta(days=1),
            "10000",
            RequestSum("payments", "refunds.create", "amount"),
        ),
    ],
)
```

A window counts requests (`Requests`), sums a payload amount (`RequestSum`) or a column
over the plan's rows (`RowSum`, inserted or net), or counts plans (`Plans`). It can be kept
per scope, per tenant or globally, and it slides: what a plan added stops counting one span
after the plan committed. Pair a per-tenant window with a per-scope one, because the plan
itself declares a request's tenant.

Each plan is measured with the history of every window key it adds to, read while the key
is locked. On PostgreSQL that's a transaction-scoped advisory lock held until `COMMIT`, with
the history read on a second `READ COMMITTED` connection. On SQLite it's the stage's own
write lock. Plans racing into one window commit exactly up to its limit. The history and
what the plan adds are part of the diff, so the verdict can be replayed from it. What the
plan adds is written beside its commit marker, or not at all. A plan's statements can't
read or write window history. The agent is told which window refused it, but never what
the window holds:

```text
- rate_window: the plan would take rate window mail_per_agent_hour past its limit. The
  window slides: what earlier plans added stops counting as it ages.
```

`[[windows]]` in `interlock.toml` configures them, checked against `[[sinks]]` and
`[[tables]]`, for `EscrowEngine(windows=config.windows)`.

### Meters: conserving a unit across plans

A window bounds what plans add up to over a span of time. A meter conserves a quantity the
way AgentGov conserves money. A dose in morphine milligram equivalents, capacity in vCPUs
or a count of seats is held in an AgentGov ledger of that unit, whose envelopes are
delegated down a tree of scopes. Five agents working from one envelope can't each spend
what's left of it:

<!-- readme-test: skip reason="continues the partitions example, with a clinical database" -->
```python
from agentgov import BudgetManager, Unit
from interlock import EscrowEngine, Meter, RowSum, SqliteSubstrate

mme = BudgetManager.open_sqlite("mme.db", unit=Unit("mme"))
engine = EscrowEngine(
    SqliteSubstrate("ward.db", tables=[orders]),
    checkers=checkers,
    meters=[Meter(mme, RowSum("med_orders", "mme_per_day"), per_plan="90")],
)
```

Each plan holds `per_plan` on its scope before it stages. If the envelope has less, the
plan is refused right there, with nothing staged. The plan is checked against `per_plan`,
and when it commits it settles what its diff measured, and the rest of the hold is
returned. A refused plan's hold is released. Recovery settles a committed plan's whole
hold, so it never under-counts. The receipt names what the plan consumed and the
transaction that settled it.

## AgentGov integration

Interlock imports [`agentgov`](https://github.com/crimsondevil0929/agentgov) as a
**read-only audit dependency**. The dependency runs one way (`interlock -> agentgov`) and
requires no change to AgentGov.

Every adjudication is written to a hash-linked chain whose records carry the AgentGov head
hash observed at the time. That proves a *lower* bound on a record's time. It does not
prove an upper bound on its own, because a record could name a stale head, so
`verify_anchors()` additionally requires the observed AgentGov sequence to be
non-decreasing across an append-only chain.

**The breaker is read as it is right before commit.** When attached read-only
(`audit_path=`, the separate-process deployment), Interlock refreshes its view of the
governor before every record and before the pre-commit breaker check. It verifies
everything the governor wrote since, so a halt written after Interlock attached still
stops the commit. A view that fails verification refuses to operate. With a governed
manager in the same process, the governor's own lock is held from that check through the
substrate's commit, so a trip lands strictly before the commit (which is then refused) or
strictly after it. Across processes no lock spans both databases. A trip the governor
commits between the check and the commit can't be ruled out, and when one happens the
`COMMITTED` record says so.

When Interlock runs in the same process as a write-capable governor, it also writes its own
chain head into AgentGov's chain. It goes into a zero-value `ANCHOR` entry, or, when the
plan has a cost, into the memo of the spend that settles it. `memo` is part of AgentGov's
hash payload, so this reverse anchor can't be altered without breaking AgentGov's own
verification. Each chain then vouches for the other.

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

### Settling with the commit: claim and settle (PostgreSQL)

Across processes, the governed mode above leaves two gaps. Another process can commit a
trip between the breaker check and the commit, and a crash between the commit and the
reverse anchor leaves effects with no settlement. Both gaps close when the ledger lives in
the same PostgreSQL database as the observed tables (`BudgetManager.open_postgres`,
agentgov v0.3):

<!-- readme-test: skip reason="needs a live PostgreSQL server" -->
```python
from agentgov import BudgetManager

from interlock import EscrowEngine, LedgerAnchor, PostgresSubstrate, TableSpec, default_checkers

governor = BudgetManager.open_postgres("postgresql://owner@db/app")  # the tables' owner
governor.store.grant_join("interlock_agent")  # once: the stage role may claim, and no more
engine = EscrowEngine(
    PostgresSubstrate(
        "postgresql://interlock_agent@db/app",
        tables=[TableSpec("orders", columns=["id", "tenant", "total"], tenant_column="tenant")],
    ),
    checkers=default_checkers(row_limit=8),
    anchor=LedgerAnchor(governed=governor, same_transaction=True),
    settle_cost="0.25",
)
```

Each plan is settled in three steps:

1. **Reserve.** Before the stage opens, the governor places a hold for the plan's cost, in
   its own transaction. A scope that is halted or cannot pay refuses the plan here, before
   anything is staged, and an overdraft trips its breaker.
2. **Claim.** At commit the stage takes the ledger's writer lock inside its own
   transaction, the governor catches up with every other governor and checks the breaker,
   and a settlement claim keyed to the hold is written into the stage. The claim commits in
   the stage's `COMMIT`, with the effects and the commit marker, or not at all, and no trip
   in any process can land between the check and the commit.
3. **Settle.** After the commit the claim is redeemed into AgentGov's chain: the hold's
   release and the spend, which names the plan's `COMMIT_INTENT` record.

The claim doesn't read the chain, so the stage's `REPEATABLE READ` snapshot never
conflicts, however many ledger commits old it is. A busy ledger never stops a plan from
committing. In a test with four engines racing for one account while a governor wrote the
ledger back to back, every plan committed. Every retry came from the engines' own race for
the account's row, and there were as many as with no ledger traffic at all.

No crash can leave effects without their claim, or a claim without its effects. A process
that dies after its commit leaves the claim pending, and `recover()` books it. Any governor
may book any pending claim, since one only exists for a stage that committed. A plan that
didn't commit leaves at most its hold, which `recover()` releases once the chain shows the
plan can no longer commit. `tests/test_crash_consistency.py` runs every kill point against
this mode, including after the hold, mid-claim, and after the commit but before the claim
is booked.

- **The stage's role cannot write the ledger or claim anything.** It gets no privilege on
  the ledger's tables, only `EXECUTE` on one `SECURITY DEFINER` function that records a
  claim, and only with a token derived from a secret the role cannot read and from the
  transaction's own id. A statement in an agent's plan runs as that role, and can neither
  write the ledger, forge a claim, nor reuse a governor's token.
- **A booked settlement is kept, whatever happened since.** A claim whose hold an operator
  voided is booked as a spend on its own. One that overdraws the scope is booked and trips
  the breaker. Its effects have already happened.
- **A refused plan is charged against its hold**, after its stage, as before, naming its
  terminal record. A plan whose stage fails releases its hold.
- **A stage stuck in `COMMIT` holds the ledger** until the server decides. No governor can
  write in the meantime, for at most the stage's `lock_timeout`.

## Fiduciary, the layer above

[Fiduciary](https://github.com/crimsondevil0929/fiduciary)
([`interlock-fiduciary`](https://pypi.org/project/interlock-fiduciary/)) says who set the
limits Interlock and AgentGov enforce, and who approved an exception. A principal's signed
mandate compiles into Interlock's checkers and AgentGov's policies. Whatever it doesn't
allow goes to the principals as a ticket, and a quorum's warrant is executed once, through
Interlock's operators and AgentGov's ledger. A lineage exports as an audit bundle that
anyone can verify offline. Fiduciary uses only Interlock's public API, as Interlock uses
only AgentGov's.

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
- **Intent and effect:** the plan's content hash and stated footprint, the diff hash in
  the chain's `DIFF_COMPUTED` record, a salted commitment over every measured row change
  (one row can be disclosed later without the rest), and a hash of the observed schema,
  foreign keys included.
- **Coverage:** the observed tables, and every gap spelled out, such as an acknowledged
  cascade, or a substrate that didn't read the foreign keys or doesn't refuse unobserved
  tables. It also says how strongly the effect was measured when that was short of a
  transaction. For a plan whose only effect is the requests it commits, it says only the
  request was measured.
- **Decision:** the verdict hash, each checker with a digest of its configuration, the
  issuer's policy epoch, and, for a repair, the refused plan's receipt as `repair_of`.
- **Cost:** the AgentGov transaction that settled the plan. The receipt is issued last,
  after the reverse anchor, so agentgov's verifier can check the cost against the ledger.

A product that serves many tenants from one store can hand each tenant its own receipts:
`ReceiptIssuer(log, tenants="declared")` names only the tenants a plan declares, and
counts any others its diff reached, so a refused plan still says how far it went without
saying into whose rows.

The receipt and the escrow chain point at each other. The stage's terminal record carries
the receipt id, and the receipt's `anchors.escrow` names that record by sequence and hash.
If a receipt can't be issued after a commit, the failure is logged rather than raised. The
effects are kept, and the terminal record names the receipt that should exist. Only a
holder of the key can verify an HMAC receipt. For third parties, sign with agentgov's
`Ed25519Signer` (`agentgov[sign]`) and publish the public key.

## Recovery

A halt is the right call, but it used to end the task. `RecoveryRuntime` gives a halted task
a bounded way to finish: a few more model calls, each under tighter constraints than the
one before, paid from a reserve set aside for it, and each recorded and signed before it's
made.

```python
from decimal import Decimal

from agentgov import BudgetManager
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.exceptions import AgentThrashingError
from agentgov.receipts import HmacKey

from interlock import (
    Directive,
    RecordLog,
    RecoveryPolicy,
    RecoveryRuntime,
    ToolRevokedError,
    Trip,
    TripKind,
)

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
print(step.rung, step.granted_tools, step.revoked_tool)  # revoke_tool ('apply_plan',) lookup
# Send step.messages (through the beta endpoint with step.betas when non-empty,
# the plain one otherwise) and step.max_tokens, the system prompt and the tools
# as before; settle what the call cost; refuse a revoked tool where you run it:
runtime.settle(step, "0.03")
try:
    runtime.check_tool("lookup")  # the tool the halt named, and this step revoked
except ToolRevokedError:
    pass  # refuse the call here instead of running it
runtime.close()
records.verify()
print(governor.is_halted("support-agent"), len(records))  # True 4
```

**The ladder** is fixed and deterministic, one rung per step: revoke the tool the halt
names, then an operator directive from the policy's allowlist, then a lower token ceiling,
then guidance in fixed words. Constraints come before any conversation. Each step takes the
first rung that can still help with this kind of halt, and tightening only accumulates: a
revoked tool stays revoked and the ceiling stays down. When no rung is left, or
`max_steps` is reached, `recover()` raises `RecoveryExhaustedError` and the halt remains in
force. The same halts always take the same steps. A refused plan goes straight to guidance
by default, so the agent can correct it. The guidance is the refusal's sanitized feedback,
or a repair's (see [Repair](#repair-the-part-that-would-pass)).

**History is never edited.** A step returns the transcript it was given, as the same
objects, with messages appended: first error results for the tool calls the halt stopped,
then the rung's notice. The system prompt and the tool definitions are never touched. On Claude
Opus 5, Opus 5.5, Opus 4.8, Fable and Mythos, a directive goes in an appended
`{"role": "system"}` message and a revocation in a `tool_removal` block (beta
`inline-tools-2026-09-15`, in `step.betas`). That's the operator channel, which a user turn
can't forge. `Channel.USER` uses user-turn notices for every other model. Either way,
`check_tool()` refuses a revoked tool where the harness runs it. Each step checks that the
transcript it's handed extends the one the last step returned, so an edit in between is
refused. The step's record pins the transcript before and after it with a running hash
(`transcript_head`).

**A non-empty `step.betas` has to go through the beta endpoint.** With the `anthropic`
Python SDK that's `client.beta.messages.create(..., betas=step.betas)`. Never call
`client.messages.create(betas=...)`, which raises a plain `TypeError` because that method
takes no `betas` keyword. `step.betas` is empty under `Channel.USER`, so a harness that only
runs on `Channel.USER` models never needs the beta endpoint. `TOOL_CHANGES_BETA`
(`interlock.recovery`) is the exact string this release sends. Treat it as a snapshot of
Anthropic's API as it is today. An audit against live traffic has already caught it
changing once (see the docstring), and nothing here detects the next rename automatically.

**The reserve sits beside the scope, not under it.** A trip halts the tripped scope's whole
subtree, and recovery exists for tripped scopes, so `{scope}/recovery` is carved out of the
scope's own envelope: released to its parent and delegated from there. The halted scope
stays halted. Every call made during recovery is billed to the reserve, a step's through
`recover()` and `settle()`, and the task's own through `hold()` and `capture()`. A root
scope's reserve is a new root funded from the treasury, or `RecoveryPolicy(funding=...)`
names a scope to delegate it from. `close()` returns whatever is left to the parent.

**Everything is signed before it happens.** The opening, each step, each settlement and the
close are `RecordLog` entries. They use ILOK1, agentgov's canonical JSON under an
`ILOK1/record/v1` signing prefix (or `ILOK1/record/v2` over its SHA-512, for a key service
that limits what it signs, as ARC1 1.2's version 2 does). They're hash-linked and anchored
into the AgentGov ledger as `ANCHOR` entries, so `check_anchors()` catches a log that was
truncated or rewritten afterwards. A step's record names the halt (and a refused plan's
ARC1 receipt), the rung and exactly what it did, the hold that pays for it, the policy's
digest, and the transcript before and after. It's written before the step is returned.
Persist the log (`RecordLog(..., path=...)`). A runtime restarted over it adopts the
recovery scope and replays what was revoked and lowered, so a restart never loosens a
constraint. A closed recovery opens again only with `RecoveryRuntime(..., reopen=True)`,
for a scope that runs task after task. That gives a fresh reserve, funded like the first,
on `{scope}/recovery/ext-N` (a delegated scope is funded once), starts the ladder again,
and writes an opening record that names the close it follows.

## Extension quotes

AgentGov's backstop is blunt on purpose. An authorization that would overdraw a scope
trips its breaker, and so does a capture that spends it to zero. That's the right answer
for a runaway loop. For a task that just costs more than its envelope, it throws away the
work done so far. `BudgetGuard.authorize()` asks first. When a call won't fit, it returns a
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
  task committed and the rows they measurably changed, plus a checkpoint the receipt log
  signed for the quote, so each receipt is provable by inclusion
  (`log.bundle(log.index_of(id), checkpoint)`). It also lists the recovery steps the task
  took, and any milestones the harness declares, which are carried as declared and not
  proven.
- **An estimated completion cost**, by a named method: the cost per declared milestone
  times the milestones remaining, or, with none declared, the cost of the call that didn't
  fit. A margin is added, and the total rounded up to the cent. `requested` is that amount
  minus what the scope has left.

A quote is answered once, before it expires, by the guard that issued it, with `grant()`
or `decline()`. Each answer is a signed record that names the quote. The quote is a signed
record too, so a guard opened over a persisted log adopts any unexpired quotes that no
record has answered yet. A restart loses none, and whichever guard on the log answers a
quote, it's answered once (`BudgetGuard(..., adopt=False)` adopts none). A root scope is
topped up in place, and if running out of money is what tripped it, its breaker is reset.
A delegated scope can't be topped up, so the grant delegates `{scope}/ext-N` beside it,
carries over what the old scope had left, and the task bills there from then on. A grant
the parent can't make changes nothing. A scope halted for any other reason isn't quoted.
`authorize()` raises AgentGov's `CircuitOpenError`, because more money doesn't fix a safety
halt.

A `RecoveryRuntime` given the guard asks for quotes on its own reserve the same way. When a
step won't fit, `RecoveryExhaustedError.quote` carries the request, and `extend()` takes up
the grant. Quotes are operator evidence, and nothing in them is sent to the agent. Granting
is the operator's decision. The guard records `approved_by` but can't authenticate it, so
put `grant()` behind an approval process you already trust, and never give the agent a
tool that reaches it.

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
that only the stage-opening function can write. They aren't keyed by the
`interlock.stage_id` setting, which any statement could change. The setting is still set,
and the trigger refuses to continue when the two disagree.

Every stage checks, before its first effect and with the observed tables locked
`ROW EXCLUSIVE` so none of it can change underneath:

- each observed table carries Interlock's triggers, enabled always, capturing exactly
  its `TableSpec`'s columns, and has no inheritance children or partitions (a statement
  on the parent writes their rows too, through no trigger, and PostgreSQL checks
  privileges on the parent alone);
- the stage's role isn't a superuser, owns no observed table (an owner can disable a
  trigger), and can't write any other table, whether directly, through a column grant, or
  through a role it belongs to. PostgreSQL has no statement authorizer, so grants are the
  table boundary, and the substrate checks them instead of trusting them.
  `enforce_table_access=False` trusts them;
- the cascade check, read from `pg_constraint`.

What differs from SQLite:

- **Placeholders are psycopg's:** `%(name)s`, and `%%` for a literal percent sign.
- **Only row statements stage:** `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`,
  `WITH`, `VALUES`, `TABLE`. Each is sent by the extended query protocol, as one unnamed
  statement, which the server will not split, so `UPDATE ...; COMMIT` fails instead of
  committing before adjudication. Nothing is prepared on the server.
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

**Behind a connection pooler.** A stage holds its connection for its whole life, and reads
the rate windows on a second connection in `READ COMMITTED`, because its own snapshot can't
see what other plans committed after it began. With PgBouncer in transaction mode, give the
stage role's pool at least one connection more than `[engine] workers`. Then a window read
waits only for other window reads, never for a commit. A pool no larger is slow but never
stuck. The second connection has to be obtained within `[engine] pool_timeout_seconds` (the
lock timeout by default). When it can't be, the stage is aborted with `PoolExhaustedError`
(a `StageConflictError`), its locks and connection are released, and the daemon's engine
pool stages the plan again. The read is one transaction that sets nothing beyond itself,
and nothing is prepared, so PgBouncer needs no `max_prepared_statements` and no client
inherits another's session.

Some things grants can't see, so the substrate can't either: a `SECURITY DEFINER` function
the role may call that writes elsewhere, an extension such as `dblink` that opens another
connection, and large objects. Don't grant them to the stage role. PostgreSQL 14 or later
is required, and CI runs 16.

## Git: the same guarantee on a branch

`GitSubstrate` stages a plan on a Git branch with the same guarantee the SQL substrates
give: what commits is exactly what was measured, or nothing commits. It needs only the
`git` command.

- **Stage.** Each plan gets a worktree of its own at the branch's head, its *base*.
- **Apply.** Effects edit files there. The repository's hooks run after each effect, the way
  triggers run after a statement: a code generator, a formatter, a lockfile refresh.
- **Measure.** Git diffs everything in the worktree against the base. A file a hook wrote is
  measured exactly like a file the plan wrote.
- **Commit.** The commit is `git update-ref <branch> <new> <base>`, a compare-and-swap. If
  anything moved the branch while the plan was staged (a push, a merge, another stage), the
  branch stays where it is and nothing commits.

<!-- readme-test: skip reason="needs a bare Git repository; tests/test_git_substrate.py makes the same calls on one" -->
```python
from interlock import BlastRadius, EscrowEngine, NoDelete, PlanBuilder, TableAllowlist
from interlock.git_substrate import GitHook, GitSubstrate

repo = GitSubstrate(
    "/srv/git/billing-service.git",
    branch="main",
    hooks=[
        GitHook(
            "codegen",
            ("python", "tools/codegen.py"),
            when=("src/billing/api/schema.json",),
            sources=("tools/codegen.py",),
        )
    ],
)
engine = EscrowEngine(
    repo,
    checkers=[
        BlastRadius(12),
        TableAllowlist(["src", "tests", "docs"]),
        NoDelete(),
    ],
)
plan = (
    PlanBuilder("repo-agent")
    .update(
        table="src",
        statement="replace :path :old :new",
        stated_rows=1,
        parameters={"path": "src/billing/invoice.py", "old": "x * 1", "new": "round(x, 2)"},
    )
    .build()
)
engine.execute(plan)
```

Or configure it in `interlock.toml`, as SQLite and PostgreSQL are. `database` then names
the control database, a SQLite file for the outbox, the inbox and window history (see
below). `interlock install` sets it up, `interlock check` reads the branch's head through
the substrate, and `EscrowRuntime.from_config`, the daemon and Fiduciary's service all stage
on the repository:

```toml
substrate = "git"
database = "control.db"

[git]
repository = "billing-service.git"   # relative to this file
branch = "main"
workspace = "billing-service"

[[git.hooks]]
name = "codegen"
argv = ["python", "tools/codegen.py"]
when = ["src/billing/api/schema.json"]
sources = ["tools/codegen.py"]
```

The tables are the path classes, so a Git configuration lists no `[[tables]]`. A
`[[windows]]` `row_sum` names a class and a column, such as `src` and `lines_added`. Give
`[[git.classes]]` to replace the default classes. `interlock reconcile-effects --since
<commit>` reconciles the branch.

**What the checkers see.** Each changed path is one measured row:

- the *table* is the path's class: `workflows` (`.github/workflows/**`), `governance`
  (`CODEOWNERS`, `SECURITY.md`, `LICENSE`), `infra`, `deps` (`pyproject.toml`, `uv.lock`,
  `package-lock.json` and their kin), `tests`, `src`, `docs`, and `other` for any path no
  rule names. The globs are configurable (`PathClass`).
- the *primary key* is the path;
- the *partition* is the repository, or the owner a rule names for the path.

Each row records `path`, `blob_sha`, `mode`, `lines_added`, `lines_deleted`, `net_lines`
and `secret_markers`. The last is how many credential-shaped strings the change adds: cloud
and package-registry tokens, private keys, a CI workflow reading a secret, and long
high-entropy strings. Only the count is kept, never the text.

So every built-in checker works unchanged:

- `TableAllowlist` keeps a plan out of workflow files;
- `NoDelete` refuses a deleted test;
- `BlastRadius` and `StatedFootprint` catch the 35 files a code generator rewrote after a
  one-line edit;
- `FactAgreement` holds a dependency change to CI's signed result for exactly the bytes
  being written.

**Statements.** A statement is one operation, with `:parameters` or `'quoted'` literals.
That means a tool binding can pin it the way it pins SQL:

| Statement | Does |
|---|---|
| `write :path :text` | creates or replaces a file |
| `replace :path :old :new` | replaces the one occurrence of `old` (it fails on none, or on more than one) |
| `delete :path` | removes a file |
| `mode :path :mode` | sets `100644` or `100755` |
| `patch :diff` | applies a unified diff (no renames, links or submodules) |
| `expect-head :commit` | refuses unless the branch is at that commit |

`expect-head` pins a plan to the commit its approvers reviewed. A warrant over such a plan
commits onto that exact commit or not at all.

A path is refused if it is absolute, has a `..` component, reaches into `.git`, or passes
through a symbolic link. A plan may not write a file a hook runs (`GitHook.sources`).

**Recovery and reconciliation.**

- Each commit carries the trailer `Interlock-Stage: <stage id>`. `resolve_intent` reads the
  branch's history for it, so a crash between the commit intent and its record is settled
  exactly.
- Savepoints are trees, so `EscrowEngine.repair` searches sub-plans on Git as it does on
  SQL.
- `reconcile_git(substrate, records, since=...)` names every commit on the branch that no
  stage made, and a force-push that rewrote the branch.

**The control database.** Rate windows, the outbox and the inbox need a transactional home
that Git does not have. Pass `control=` a SQLite file that `interlock install` set up. A
stage then writes its requests, the facts it consumes and its window history there, and
the branch moves inside that transaction, just before it commits. A redo record is written
to disk before the branch moves. If the process dies between the two commits, the next
stage or `EscrowEngine.recover()` finishes the database's half, exactly when the branch
holds the commit.

**Limits.**

- A hook is operator code. It runs in the stage's worktree, with a timeout and a scrubbed
  environment (no variable of the process reaches it but `PATH`), and it can reach anything
  the process can.
- Point the substrate at a bare repository, or at a branch no worktree has checked out.
  Moving a checked-out branch would leave that worktree behind, so the substrate refuses.
- A commit that a force-push later removes from the branch reads as not committed to
  recovery, unless a control database recorded it. Reconciliation names the rewrite.

## Kubernetes and Terraform: plan-bound

A cluster and a Terraform configuration cannot be staged in a transaction and rolled back.
They can be measured exactly, though, and the change applied on the condition that nothing
moved. Interlock calls that *plan-bound*: what was measured is the plan that is applied, on
the state it was measured on, and a partial failure is put back from an undo written down
before the first write. Every receipt of such a plan says `coverage.measurement =
"plan-bound"`, never `transactional`.

`KubernetesSubstrate` measures with the API server's own dry run:

- **Stage.** Each effect reads its object live, with its `resourceVersion`, and changes it as
  its statement says: `scale`, `set` (one field), `merge-patch`, `apply` (a whole manifest),
  `delete`, or `expect-version` (pin the version approvers saw).
- **Measure.** The changed object goes to the API server with `?dryRun=All`. Defaults, every
  mutating admission webhook and every validating one run as on a real write, and what comes
  back is the after image. A webhook that turns 6 replicas into 60 is measured as 60. A
  webhook declaring side effects makes the API server refuse the dry run, so a change whose
  admission cannot be measured never stages.
- **Forced replacements.** A change to an immutable field is refused, or, on a kind marked
  `replace_on_immutable` (a GitOps sync with `Replace=true`), measured as the deletion and
  creation the sync would do. `NoDelete` sees the deletion.
- **Commit.** Each object is written on the version measured, with the annotation
  `interlock.io/stage-id`. If anything wrote it since, the API server answers
  `409 Conflict` and nothing is applied. An object that lands other than measured, or a
  write that fails part way, is put back from the undo, and the stage is `COMPENSATED`.

<!-- readme-test: skip reason="needs a cluster; tests/test_kubernetes.py makes the same calls on interlock.sim.kubernetes" -->
```python
from interlock import BlastRadius, EscrowEngine, KubeKind, KubernetesSubstrate, NoDelete

cluster = KubernetesSubstrate(
    "https://10.0.0.1:6443",
    token=open("/var/run/secrets/remediator/token").read().strip(),
    ca_file="/var/run/secrets/remediator/ca.crt",
    namespaces=["prod-east"],
    journal="/var/lib/interlock/undo",
    kinds=[
        KubeKind(
            "deployments",
            "deployments",
            "Deployment",
            group="apps",
            columns={
                "replicas": "spec.replicas",
                "vcpu": "spec.replicas * spec.template.spec.containers.0.resources.requests.cpu",
            },
        ),
        KubeKind(
            "statefulsets",
            "statefulsets",
            "StatefulSet",
            group="apps",
            columns={"storage": "spec.volumeClaimTemplates.0.spec.resources.requests.storage"},
            replace_on_immutable=True,
        ),
    ],
)
engine = EscrowEngine(cluster, checkers=[BlastRadius(20), NoDelete(())])
```

`TerraformSubstrate` (Terraform or OpenTofu) measures with a saved plan. Effects `set` input
variables, and the stage runs `plan -out` and reads `show -json`. Each entry of
`resource_changes` is a row of its resource type's table (`TfResource`). A replacement is a
deletion plus an insertion, and a resource whose type no table names is measured in
`resources`. An observed attribute that the provider only knows after the apply is an
`UnknownValue`, which `TruncationGuard` refuses unless that column is acknowledged
(`TruncationGuard(acknowledged_unknown={"db_instances.endpoint"})`). The commit checks the
state's `serial` and `lineage` and applies exactly the saved plan. The stage's id reaches
the state as the `interlock_stage_id` output, which the configuration has to declare.

Both are configured in `interlock.toml` (`substrate = "kubernetes"` with `[kubernetes]` and
`[[kubernetes.kinds]]`, `substrate = "terraform"` with `[terraform]` and
`[[terraform.resources]]`). `interlock.sim` has a loopback API server, with webhooks called
over HTTP and an audit log, and a stand-in `terraform` command: CI stages class P with no
cloud credentials.

## FHIR servers: predicted and verified

A FHIR server (an EHR's API) can't hold a transaction open or dry-run a write. It does keep
a version on every resource, and it supports conditional writes. Interlock builds a
guarantee from those that it calls *predicted and verified*. The checks judge a
prediction of the change. The write is conditional on the version that was read, and a
read-back afterwards confirms the result matches the prediction. Every receipt for such a
plan says `coverage.measurement = "predicted"`.

`FhirSubstrate`:

- **Stage.** Each effect reads the resources it touches live, with their `meta.versionId`.
  The first time a stage reaches a patient, it reads that patient's whole chart (every
  observed type, `[type]?patient=<id>`). `create` builds a resource from a template whose
  `":name"` values are the effect's parameters. Each conditional reference
  (`Encounter?location=:bed&status=in-progress`) is resolved by a search that must find
  exactly one match. `patch` applies a JSON merge patch, and `expect-version` pins a
  version.
- **Judge.** The predicted change is the diff that every checker, partition and window
  judges. That happens before anything is written, so an order that resolves to the wrong
  patient is refused before the server sees it.
- **Undo first.** Each effect declares its undo (`void <table>` for a create, `restore
  <table>` for a patch). The undo journal gets every before image, and the charts as read,
  before the first write. A created record is undone by marking it `entered-in-error`, never
  by deleting it.
- **Write.** The charts are read again. If anything changed since the stage read it, such
  as a clinician's edit while the plan waited for a warrant, the commit is refused and
  nothing is written. Each update carries `If-Match`, so a change in the last instant gets
  `412 Precondition Failed`. Every write carries the stage's id, in `meta.tag` and in
  `X-Request-Id`, which the server's `AuditEvent` log records.
- **Read back.** The charts are read once more and compared with the prediction. Any
  difference, such as a server rule that stopped the encounter's other orders or a dose it
  rewrote, means everything the write changed is put back and the discrepancies are named.
  The stage is recorded as `COMPENSATED`, with receipt outcome `compensated` (ARC1 1.4), so
  `agentgov reconcile-actions --format fhir-auditevent` ties both the write and its undo to
  that receipt.

<!-- readme-test: skip reason="needs a FHIR server; tests/test_fhir.py makes the same calls on interlock.sim.fhir" -->
```python
from interlock import BlastRadius, EscrowEngine, FhirSubstrate, FhirType, TenantIsolation

ehr = FhirSubstrate(
    "https://ehr.example.org/fhir",
    token=open("/var/run/secrets/med-rec/token").read().strip(),
    journal="/var/lib/interlock/undo",
    control="/var/lib/interlock/control.db",
    types=[
        FhirType(
            "medicationrequests",
            "MedicationRequest",
            columns={
                "status": "status",
                "dose_mg": "dosageInstruction.0.doseAndRate.0.doseQuantity.value",
            },
            partitions={"facility": "dispenseRequest.performer.reference"},
        ),
        FhirType("tasks", "Task", columns={"status": "status"}, tenant="for.reference"),
    ],
)
engine = EscrowEngine(ehr, checkers=[BlastRadius(12), TenantIsolation(declared=True)])
```

It's configured in `interlock.toml` as `substrate = "fhir"` with `[fhir]` and
`[[fhir.types]]`. `interlock.sim.fhir` is a loopback FHIR R4 server (versions, `If-Match`,
search with `_has`, rules that write as the server, and an `AuditEvent` log), so CI stages
class V without an EHR. Class V can't see a server rule before the write. The rule's effect
is caught by the read-back and undone, not refused in advance, and the receipt's class says
so. The server has to allow client-assigned ids, so that a create can be predicted exactly.

### Sensor facts: an analyzer's word on the exact diff

A checker is a pure function of the plan and the diff, so it cannot call a policy engine, a
scanner or a test suite. A *sensor* can. The engine shows each measured diff to its sensors
(`EscrowEngine(sensors=...)`), and each signs a `SensorFact` with its own key: its verdict,
its findings, the digest of its report, and the hash of the diff it read. The pure
`SensorAttestation` checker then requires a clean fact from a key the policy pins. A fact
about a different diff, or one signed by a different key, doesn't count.

<!-- readme-test: skip reason="needs an analyzer command; tests/test_sensors.py runs one" -->
```python
from interlock import CommandSensor, EscrowEngine, SensorAttestation

policy = CommandSensor("policy-check", ["policy-check", "--key", "/etc/policy-check/key"])
engine = EscrowEngine(
    cluster,
    checkers=[SensorAttestation("policy-check", ["ed25519:3b6a27bc..."])],
    sensors=[policy],
)
```

### Pinned checker packs

A domain whose invariant can't be built from the built-in checkers ships a pack: a module
that names `PACK_VERSION` and `CHECKERS`. `load_pack(PackPin(module, version, digest))`
loads it only if the installed code is exactly the pinned code (the digest covers every file
in the package). Otherwise it says why: not installed, a different version, or tampered.

### Tested against the real systems

The loopback stand-ins in `interlock.sim` make the unit tests fast and let them inject
faults. CI also runs each substrate against the real system:

- the OpenTofu CLI (1.13.2), with plans of its built-in `terraform_data`, so no provider is
  downloaded;
- a Kubernetes 1.37 cluster (kind), where a `MutatingAdmissionPolicy` multiplies replicas
  by ten and a `ValidatingAdmissionPolicy` sets a ceiling;
- HAPI FHIR (8.12), the reference open-source FHIR server.

Run them locally by naming each system:

```
INTERLOCK_TEST_TOFU=$(command -v tofu) uv run pytest tests/test_real_tofu.py
kind create cluster --name interlock && eval "$(scripts/kind-setup.sh kind-interlock)"
uv run pytest tests/test_real_kubernetes.py
docker run -d -p 8091:8080 hapiproject/hapi:v8.12.0-2
INTERLOCK_TEST_FHIR_URL=http://localhost:8091/fhir uv run pytest tests/test_real_fhir.py
```

The first run against them found three bugs that the stand-ins could not show. All are
fixed in 1.4.1:

- A Kubernetes dry-run delete was real when the request had a body.
- A controller's status writes on a healthy cluster were taken for conflicts.
- A refused FHIR write was put back over the edit that refused it.

## Outbound requests: the transactional outbox

Plans often need to call something besides their database: send an email, issue a refund
through a payment API, post a webhook. None of those calls can be staged, measured or
rolled back. An agent that makes the call itself has made it before anything could check
it, and that's how an instruction injected through a tool result gets out.

So Interlock doesn't let the plan make the call. It uses the **transactional outbox**
pattern. The plan *enqueues a request* for the call alongside its SQL effects, and the
request is handled like a row, on PostgreSQL and SQLite alike. (The design and the proofs are in
[`docs/OUTBOX_DESIGN.md`](docs/OUTBOX_DESIGN.md) and
[`docs/EPIC3_DESIGN.md`](docs/EPIC3_DESIGN.md)).

1. **Enqueue.** `PlanBuilder.enqueue()` adds the request to the plan. Admission holds it to
   the operator's `SinkRegistry`: a registered sink and operation, a payload that matches
   the operation's JSON Schema and fits the sink's size bound, no field named like a
   credential, and the compensation the operation registers, if any.
2. **Stage.** The stage writes the request to `interlock.outbox` in its own transaction,
   through a function gated by a token only the substrate holds. The checkers read it back
   from there, beside the measured rows. It commits with the rows and the stage marker, or
   not at all, so a refused or failed plan leaves no request behind.
3. **Pay.** The plan pays at commit, in the settlement that commits with it: its settle
   cost plus each request's `cost_per_call`. The hold placed before staging covers both. A
   refused plan pays only its settle cost, since its requests never commit.
4. **Deliver.** `interlock relay`, a separate process under its own database role and the
   only holder of the sinks' credentials, reads committed requests and makes the calls, at
   least once.

### Configuring a sink

Sinks are declared in `interlock.toml` beside the tables. `interlock install` mirrors them
into the database, which then refuses a request for any sink or operation it doesn't hold.
A sink has no URL or credential here. Those belong to the relay.

```toml
substrate = "postgres"
stage_roles = ["interlock_agent"]
relay_roles = ["interlock_relay"]     # granted read access and the relay functions, nothing else

[[sinks]]
name = "payments"
cost_per_call = "0.0005"              # a decimal string, charged at commit
idempotency = "header"                # the sink deduplicates on Idempotency-Key; "none" if not
unknown_outcome = "redeliver"         # or "dead-letter": a call that may have acted is not repeated
not_after_seconds = 900               # delivered within this, or not at all
max_attempts = 10
backoff_base_seconds = 1              # doubling, with jitter, up to the cap
backoff_cap_seconds = 600

[[sinks.operations]]
name = "refund"
schema = "schemas/payments-refund.json"   # a JSON Schema subset, relative to this file
compensation = "none-possible"            # or the operation that undoes this one
```

```bash
interlock install --config interlock.toml --database postgresql://owner@db/app
```

### Enqueueing a request, and checking it against its rows

<!-- readme-test: skip reason="needs a live PostgreSQL server" -->
```python
from interlock import (
    BlastRadius,
    CrossEffectAgreement,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
)
from interlock.config import load_config

config = load_config("interlock.toml")
engine = EscrowEngine(
    PostgresSubstrate("postgresql://interlock_agent@db/app", tables=config.tables),
    checkers=[
        BlastRadius(10),
        # The refund the payment API is asked for is the refund the plan recorded.
        CrossEffectAgreement(
            "payments",
            "refund",
            field="amount",
            table="refunds",
            column="amount",
            key=("order_item", "order_item_id"),
        ),
    ],
    sinks=config.sink_registry(),
)
plan = (
    PlanBuilder("support-agent")
    .insert(
        table="refunds",
        statement=(
            "INSERT INTO refunds (id, order_item_id, amount) VALUES (%(id)s, %(item)s, %(a)s)"
        ),
        parameters={"id": 9100, "item": 5000, "a": "50.00"},
    )
    .enqueue(sink="payments", operation="refund", payload={"order_item": 5000, "amount": "50.00"})
    .build()
)
result = engine.execute(plan)
```

A row diff alone has a blind spot. Every row can be valid and every request well-formed,
and the two can still contradict each other. `CrossEffectAgreement` closes that gap. If a
tool result talks the agent into asking the payment API for 5000.00 while the refund row it
inserts says 50.00, the plan is refused before it commits, so there's no row, no request
and nothing for the relay to send. Both halves are measured: the request is read back from
the outbox and the rows from the stage's capture. The check judges exactly what would be
sent and what would be committed. `measure="net"` holds a request to the change in a
balance it moves, and `measure="value"` holds it to one exact value, such as a currency.
The rule is strict both ways, so a refund call with no refund row, or a refund row with no
call, is refused too. The agent is told which rule it broke, but never the amounts.

### Running the relay

```toml
[relay]
key = "relay.key"                                  # this relay's Ed25519 key; or INTERLOCK_RELAY_KEY
database = "postgresql://interlock_relay@db/app"   # a relay role; or INTERLOCK_RELAY_DATABASE
ledger = "postgresql://interlock_relay@db/app"     # AgentGov, read-only, for the breaker
lease_seconds = 60                                 # at least twice timeout_seconds
timeout_seconds = 10
workers = 4

[[relay.endpoints]]
sink = "payments"
url = "https://api.payments.example"
routes = { refund = "POST /v1/refunds" }                    # every operation the sink registers
header_env = { Authorization = "PAYMENTS_AUTHORIZATION" }   # the value is read from the environment
```

```bash
export PAYMENTS_AUTHORIZATION="Bearer ..."     # in the relay's environment, nowhere else
interlock relay --config interlock.toml        # runs until SIGTERM; --once drains and exits

# As the installer: inspect, verify, and act on what the relay could not deliver.
interlock outbox status  --config interlock.toml --database postgresql://owner@db/app
interlock outbox list    --state dead --config interlock.toml --database postgresql://owner@db/app
interlock outbox verify  --config interlock.toml --database postgresql://owner@db/app
interlock outbox release --scope support-agent --key ~/.interlock/alice.key --config interlock.toml ...
```

Run as many relays as throughput needs, on as many hosts as you like. They share the work
through `FOR UPDATE SKIP LOCKED` and never wait on each other. On SIGTERM a relay finishes
the call in hand, records it, and exits. `interlock outbox show <message>` prints a
message's delivery log. `requeue` sends a dead message back with a fresh budget of
attempts, and `cancel` drops one.

A relay reads AgentGov's ledger and never writes it. For a ledger shared through
PostgreSQL, grant its role `USAGE` on the `agentgov` schema and `SELECT` on its tables, and
nothing more. For a SQLite ledger, name the file, and it's opened read-only. Without
AgentGov at all, set `breaker = "none"` explicitly. A relay never runs without a breaker
by default.

What the relay guarantees, each with a test that fails without it:

- **Nothing is sent before its plan commits, and nothing but what was adjudicated.** The
  relay reads committed rows only, and hashes the stored payload again before every call.
  A payload that no longer matches is refused, not sent.
- **Every call is recorded before it is made, and its outcome after**, in the message's
  delivery log, `interlock.outbox_attempts`. The database links each row to the one before
  it by hash, and `interlock outbox verify` recomputes every link and checks each message's
  state against its log.
- **A tripped breaker holds messages.** AgentGov's breaker for the message's scope is read
  right before every call. If it's tripped, the message is held instead of sent, until an
  operator releases it. Each call records the ledger position its breaker check read.
- **Relays never share a message.** Leases are claimed with `FOR UPDATE SKIP LOCKED`, and a
  fence on each lease stops a relay whose lease ran out from acting on the message again.
- **Delivery is at least once, and a duplicate is never silent.** Every call carries the
  same idempotency key. If a relay dies after its call reached the sink but before it
  recorded the outcome, the call is recorded as lost and made again. A sink that honours
  the key acts once. One that doesn't acts twice, and the log shows which lost call the
  second effect came from. `unknown_outcome = "dead-letter"` makes such a sink at most once
  instead. `tests/test_relay_crash.py` kills relays at every point of this path.
- **Failure is bounded.** Retries back off exponentially with deterministic jitter, honour
  `Retry-After`, and stop at `max_attempts` or the request's deadline. When a request dies,
  the requests waiting on it die with it, and `interlock outbox requeue` brings them back.

### Stripe and SendGrid

Two sinks are typed. They bring their own operations, strict payload schemas, and an
adapter that speaks the vendor's API. Configuration names which operations to allow, but
doesn't write their schemas.

```toml
[[sinks]]
name = "payments"
type = "stripe"                       # payment_intents.create, charges.create, refunds.create
cost_per_call = "0.30"

[[sinks.operations]]
name = "payment_intents.create"       # takes money, so carries its refund...

[[sinks.operations]]
name = "refunds.create"               # ...which is registered too

[[sinks]]
name = "email"
type = "sendgrid"                     # mail.send; at most once unless unknown_outcome = "redeliver"
cost_per_call = "0.001"

[[sinks.operations]]
name = "mail.send"

[[relay.endpoints]]
sink = "payments"
secret_env = "STRIPE_SECRET_KEY"      # the adapter knows the routes and the headers

[[relay.endpoints]]
sink = "email"
secret_env = "SENDGRID_API_KEY"
```

- **A Stripe charge carries the refund that undoes exactly it.** The refund names the charge
  by the placeholder `{"$bind": "delivered.id"}`, never a literal id, so a plan can't point
  its undo at another customer's payment. It refunds no more than was charged, and names no
  currency. The rule is checked at admission and again by the database when the request is
  written, so an engine configured with a looser registry can't stage the charge either.
- **The adapter** sends Stripe's form encoding with the request's idempotency key and a
  pinned `Stripe-Version`, and records the id of the payment intent it created in the
  delivery log. Stripe answers a redelivered call with an idempotent replay, so there's one
  charge whatever the relay went through.
- **SendGrid has no idempotency keys**, so its sinks are at most once by default. A call
  whose outcome is unknown isn't made again, and the message goes dead for an operator to
  resolve. Every email carries its message id and idempotency key in `custom_args`, which
  SendGrid's Event Webhook echoes, so `agentgov reconcile-actions --format sendgrid-events`
  can match each sent message to its delivery receipt.
- `tests/test_relay_crash.py` drives both through the relay's kill matrix, on both stores:
  a charge is made once and an email is never sent twice.

### MCP tools, and holding an operation for a warrant

An MCP tool that writes, behind a sink of type `mcp`, is governed like any request. The
plan is measured and judged, the call is committed to the outbox, and the relay makes it
as one `tools/call`. MCP has no idempotency key, so an `mcp` sink is always at most once. A
call whose outcome is unknown is never made again, and goes to an operator. Some
operations should never run on an agent's word alone. Mark them `hold = true`, on any
sink, and every request for them enters the outbox held, even with the breaker closed,
until an operator or a warrant releases it:

```toml
[[sinks]]
name = "crm"
type = "mcp"

[[sinks.operations]]
name = "close_ticket"
schema = "schemas/close_ticket.json"  # the input schema you pin, not the server's of the day
hold = true

[[relay.endpoints]]
sink = "crm"
command = ["crm-mcp-server", "--stdio"]
```

The receipt of a plan whose only effect is such a request says so. It records that only
the request was measured, and names the sink that carries the effect.

### Sinks and sources of your own

A FHIR server, ServiceNow or a cloud's API can be a typed sink of its own, configured from
`interlock.toml` like Stripe. A package registers its kind with `register_sink_kind`, or
under the `interlock.sinks` entry point, and follows the same contract as `interlock.stripe`
and `interlock.mcp`: its operations (or none), its idempotency, its payload rules and its
relay adapter. A vendor that signs its webhooks its own way is an inbox source kind,
registered with `register_source_kind` or under `interlock.sources`.

### On SQLite

The outbox, the relay and every operator command work on a SQLite file the same way they do
on PostgreSQL. `interlock install` switches the file to WAL and installs the outbox, and
the relay is `interlock relay` with the same configuration. SQLite admits one writer at a
time, and Interlock relies on that. Every write is a short `BEGIN IMMEDIATE` transaction, so
claims queue where PostgreSQL's would skip, and a relay never holds the lock while it calls
a sink. WAL means every process that opens the file has to run on one host. SQLite has no
roles. The file's permissions are the boundary, and verification is how an edit made around
Interlock gets found.

### Operators: every action signed

Releasing a held request, cancelling one, requeueing a dead one, and compensating a
delivered one are a person's decisions about money and messages that leave the system.
Each is signed with the operator's own Ed25519 key, in two phases. First, before the
database is touched, a signed intent names the targets and the delivery-log head of each.
The database acts under the intent's hash, only at those heads, and refuses any operator
row that carries no such authority. Then a signed outcome names the rows it wrote. If a
command is killed between the phases, the next one resolves it.

```bash
interlock operator keygen --out ~/.interlock/alice.key --name alice   # prints the line below
```

```toml
[operators]
log = "operators.ilok1"               # the signed operator log, beside this file
ledger = "governor.db"                # optional: every record anchored into AgentGov

[operators.keys]                      # public halves only
alice = "ed25519:5f0c..."
```

```bash
export INTERLOCK_OPERATOR_KEY=~/.interlock/alice.key
interlock outbox release   <message> --reason "the breaker tripped on a false alarm" --config ...
interlock outbox compensate <message> --config ...       # the undo the plan carried, bound
interlock outbox compensate --plan <plan> --late --config ...   # a whole plan, in reverse order
interlock outbox verify    --config ...
```

`interlock outbox verify` checks every delivery log against the operator log, using public
keys alone, and names each edit made around it. That includes an operator row with no
authority, an authority that no signed intent holds or one replayed on another message, a
row written at a head other than the one signed for, an operator log that was edited or cut
short (its signatures or its AgentGov anchors), and a sink re-enabled or widened since the
last signed `interlock install`. A database's owner can still edit their own database, but
not without it being noticed.

### Relays sign every outcome

A sink's answer is recorded only with the signature of the relay that heard it: an ARC1
1.1 attestation, made with the relay's own Ed25519 key, over the request as the outbox
committed it and the outcome as the row records it. The database refuses an outcome
without one, and a relay starts only with a key registered for verification:

```bash
interlock keygen --role relay --out ~/.interlock/east-1.key --name east-1   # prints the line below
```

```toml
[relays.keys]
east-1 = "ed25519:9a1b..."
```

`interlock outbox verify` rebuilds each outcome's attestation from the outbox row and the
log row, and names every outcome that no registered relay signed. A delivery written around
Interlock is named even if it's linked and hashed perfectly, and so is a genuine row that
was rewritten after it was signed. Outcomes recorded before schema version 4 carry no
attestation. The install that brought version 4 recorded them once as a legacy set, and
the signed `interlock install` vouches for that set. A row forged into an old log later
isn't in it, however early it's dated.

### Keys held by a signing service

A relay, the inbox, the vacuum and the receipt log can sign with a key held by a KMS, an
HSM or Vault's transit engine. The process keeps the key's name, the version it pinned, the
public half and a credential, and never the private key (`docs/EPIC8_DESIGN.md` §1).

```toml
[signers.relay]
type = "http"                       # interlock.signers.HttpRemoteSigner's protocol
url = "https://kms.internal:8200"
key = "interlock-relay"             # the key's name at the service
token_env = "INTERLOCK_KMS_TOKEN"   # its bearer token, read from the environment
timeout_seconds = 5
# version = 3                       # pinned; the service's latest when left out

[relay]
signer = "relay"                    # in place of key = "relay.key"
```

Every signature the service hands back is verified under the pinned key before it's used.
If the service signs with another key or version, or answers with anything but a
signature, the call fails and nothing is attested. `sign_async` signs off the event loop.
Operator commands take `--signer NAME` in place of `--key PATH`. An adapter for another
service implements `RemoteSigner._remote_key` and `_remote_sign`.

### Registering, revoking and rotating keys

The operator log is the key registry and its revocation list (`docs/EPIC8_DESIGN.md` §2).
An operator registers a key beside the configuration's, and it's trusted from the next
record on. Revoking one is a two-phase operator action, like every other. For a relay's or
an inbox's key, the database records the revocation in the transaction of the signed
intent, and *seals* every row the key attested by recording each one's reference and hash.
The applied record signs the seal's count and digest and is anchored in AgentGov. From then
on, the database refuses every row the key would attest. What the key attested before still
verifies, exactly as sealed. `interlock outbox verify` names any row written around the
refusal and any sealed row that was rewritten.

```bash
interlock keys list --config interlock.toml
interlock keys register --config interlock.toml --key ops.key --role relay --name east-2 \
    --public-of relay                 # the version [signers.relay]'s service serves now
interlock keys revoke --config interlock.toml --key ops.key --role relay 03dd37a92a71a9ba \
    --reason "rotated"
```

For a planned rotation, create a new version at the key service and register it. Reload
the daemon (`kill -HUP`, or `await supervisor.reload()`): each part finishes its step and
opens again with the key it's given now. Then revoke the old one. Nothing is refused along
the way. After a compromise, revoke first. A relay finds its key revoked before its next
claim, and the inbox at its next matching pass, and each opens again with the key its
service serves at that point. An operator's key is revoked by another operator, never by
itself, and the last operator key can't be revoked.

### Settlement: delivery receipts, and credits for compensations

The process that holds the receipt log and the ledger (the engine's) settles each
delivered request once (`docs/EPIC4_DESIGN.md` §4):

<!-- readme-test: skip reason="needs a settler role, and the engine's receipt log and ledger" -->
```python
import psycopg

from interlock import Settler

settler = Settler(
    psycopg.connect(SETTLER_DSN, autocommit=True),  # a role in settler_roles
    receipts=issuer,  # the engine's ReceiptIssuer
    chain=engine.chain,
    relays=config.relay_keyring(),
    ledger=governor,  # the engine's AgentGov ledger
    operator_log="operators.ilok1",
    operators=config.operators.keyring(),
    sinks=registry,  # the engine's SinkRegistry, which priced every request
)
report = settler.settle()  # as often as you like
```

- **A delivery receipt** for each delivered request. It's an ARC1 `DeliveryReceipt` signed
  by the receipt log, carrying the relay's attestation. It's bound by leaf hash to the
  action receipt of the plan that committed the request, meaning the plan the attested
  idempotency key was derived from, not just the one the row names. agentgov's verifier
  checks it with `agentgov verify-receipt delivery.json --relay-key ... --action action.json`,
  and `agentgov reconcile-actions` matches a vendor's own log against it by the idempotency
  key and the vendor's id.
- **A credit** for a delivered compensation. It's an AgentGov `refund()` of the
  `cost_per_call` that the engine's sink registry prices the request at, which is what its
  plan was charged for it, to the scope the ledger charged. It never refunds the money the
  request moved. It's posted only when all of these hold: a registered relay attested the
  compensation's delivery, the original's `compensated` row carries the authority of a
  signed operator intent that names exactly this compensation and is recorded as applied,
  and the outbox row agrees with the registry's price and the compensation's signed key. No
  column the database's owner can rewrite sets the amount or the scope. The plan's charge
  caps the credits, and nothing is credited when the row and the registry disagree.
- **Exactly once.** Each step first finds what a crashed run left of it. If a run is
  killed after the receipt, the credit or the settlement row, the next run still settles
  every request once: no duplicate receipt, no orphaned receipt, no second credit.

### Inbound facts: the zero-trust inbox

Vendors answer later. Stripe sends `charge.refund.updated` days after the refund, and
SendGrid reports a bounce an hour after the send. An agent has to react, and a webhook is
an obvious way in for a prompt injection: a forged request, or a genuine one whose
description field says "refund everything". The inbox turns a webhook into a fact the
agent may act on, and nothing more (`docs/EPIC5_DESIGN.md` §2):

```toml
inbox_roles = ["interlock_inbox"]     # PostgreSQL: the inbox's own role

[inbox]
key = "inbox.key"                     # interlock keygen --role inbox
database = "postgresql://interlock_inbox@db/app"
listen = "127.0.0.1:8787"             # plain HTTP: put TLS in front of it

[[inbox.sources]]                     # POST /inbox/stripe
name = "stripe"
kind = "stripe"                       # or "sendgrid", or "http" (Standard Webhooks)
secret_env = "STRIPE_WEBHOOK_SECRET"  # the secret lives in the inbox's environment only

[inbox.keys]                          # what engines verify facts under
main = "ed25519:7d2e..."
```

```bash
interlock keygen --role inbox --out ~/.interlock/inbox.key --name main   # prints [inbox.keys]
STRIPE_WEBHOOK_SECRET=whsec_... interlock inbox serve --config interlock.toml
interlock inbox verify --config interlock.toml
```

- **Verified, or not recorded.** The vendor's signature (Stripe's HMAC, Standard Webhooks'
  HMAC, SendGrid's ECDSA) is checked over the raw bytes, within a timestamp tolerance, before
  the body is parsed. A forged, replayed or stale webhook gets `401` and writes nothing. A
  retry of a genuine one doesn't record anything twice.
- **Bound to what Interlock sent.** An event names what it's about, such as a refund's id.
  It's bound to the delivered request whose relay-attested `remote_ref` is that id. It's
  never bound to a delivery no registered relay attested, or to two messages' deliveries at
  once. The binding gives the fact its scope and plan.
- **Attested, and chained.** Each source's events form a hash-linked log, and the inbox
  signs every event and every fact with its own Ed25519 key. A fact written, copied or
  moved around the inbox does not verify, and `interlock inbox verify` names it.
- **Typed.** A fact carries a projection: ids, codes, integers, decimals, currencies,
  booleans, instants. No type admits free text, so a vendor's description, metadata or
  error message never reaches the agent. A value that doesn't fit is withheld, and named.

An engine consumes facts, never webhooks:

<!-- readme-test: skip reason="needs an inbox's facts" -->
```python
from interlock import EscrowEngine, FactAgreement, PlanBuilder

engine = EscrowEngine(
    substrate,
    checkers=[
        # A refund is marked failed only on the vendor's word that it failed.
        FactAgreement(
            "charge.refund.updated",
            field="status",
            table="refunds",
            column="status",
            exempt=["pending"],
        ),
    ],
    inbox=config.inbox_keyring(),
)
(fact,) = engine.facts("support-agent")  # pending, attested, this scope's
plan = (
    PlanBuilder("support-agent")
    .consume(fact)
    .update(
        table="refunds",
        statement="UPDATE refunds SET status = %(status)s WHERE id = 9000",
        parameters={"status": fact.fields["status"]},
    )
    .build()
)
engine.execute(plan)
```

A fact is consumed once, in the plan's own stage, exactly when the plan commits. A second
plan that names it is refused, and a refused plan consumes nothing. The stage reads the
fact back for the diff, where it's verified again, and the receipt commits to it. No
statement in a plan can read the inbox. `FactAgreement` ties the agent's reaction to the
fact: a plan that writes a status no consumed fact supports is refused, and the agent is
told the rule but never the values.

### Compaction: the vacuum

The outbox, window history and the inbox only grow. `interlock vacuum` prunes what no check
will read again, and keeps it provable (`docs/EPIC5_DESIGN.md` §1):

```toml
[vacuum]
retain_days = 30                      # a delivered request can be compensated this long
margin_seconds = 3600                 # window history stays this long past the longest span
archive = "archive"                   # optional: the pruned rows, written first, provable
```

```bash
interlock vacuum --config interlock.toml --key ~/.interlock/alice.key --dry-run
interlock vacuum --config interlock.toml --key ~/.interlock/alice.key --reason monthly
interlock vacuum --config interlock.toml --verify-archive archive/checkpoint-1.jsonl
```

It verifies everything first: delivery logs, relay attestations, operator records, earlier
checkpoints, and the inbox under `[inbox.keys]`. Anything that doesn't verify is kept and
named. Three kinds of history can go: stages past the retention period whose every request
was delivered and settled, or cancelled; window history older than the longest span; and,
for each inbound source, the events past the retention period whose facts were all
consumed. A *checkpoint* commits to all of it: each pruned message's log head and
settlement, folds over everything pruned, and where each inbound log was cut. It's signed
in an operator intent and anchored into AgentGov before any row is deleted. One database
transaction then records it, recomputes every fold from what the database holds, and
deletes. The database refuses any other delete. Afterwards every verifier passes, counting
pruned history through its tombstones and cuts, and a window that would reach back past
pruned history fails closed.

## The daemon: every part in one process

`interlock daemon` runs the engines that execute your agents' plans alongside the relays,
the inbox, the settler and the vacuum. It's one process with one asyncio event loop, and
each part makes its database calls on a thread of its own (`docs/EPIC6_DESIGN.md`). Each
part connects as its own role, from the sections `interlock.toml` already has, plus these:

```toml
[engine]                              # the engines executing agents' plans
workers = 4                           # plans staged at once (SQLite: one)
database = "postgresql://interlock_agent@db/app"   # the stage role
chain = "escrow.chain"                # worker n writes escrow-<n>.chain
settle_cost = "0.01"
ledger = "postgresql://owner@db/app"  # AgentGov in the same database...
same_transaction = true               # ...settles each plan with its commit
conflict_retries = 16                 # a plan that lost a race is staged again

[receipts]                            # one receipt log, the engines' and the settler's
log = "receipts.jsonl"
key = "receipts.key"

[settler]
database = "postgresql://interlock_settle@db/app"
every_seconds = 5

[vacuum]                              # the daemon's own vacuums
every_seconds = 300
key = "vacuum.key"                    # an operator's key, in [operators.keys]
database = "postgresql://owner@db/app"

[daemon]
drain_timeout_seconds = 30            # each shutdown step's bound

[metrics]                             # Prometheus, on a listener of its own
listen = "127.0.0.1:9464"             # GET /metrics and /healthz: a private address
every_seconds = 15                    # how often the database is sampled
database = "postgresql://interlock_audit@db/app"   # an audit_roles role
```

Your agents and their policy come in as an application: a function that takes the
configuration and returns an `Application` of checkers and agents. An agent is a coroutine
taking an `AgentContext`, or a plain function, run on a thread of its own:

```python
from interlock import AgentContext, Application, BlastRadius, TenantIsolation


async def support(ctx: AgentContext) -> None:
    while not ctx.stopping:
        for fact in await ctx.facts("support-agent"):
            plan = ctx.plan("support-agent", intent=f"react to {fact.kind}")
            ...  # .consume(fact), then the writes it justifies
            await ctx.execute(plan.build())
        await ctx.sleep(1.0)


def build(config: object) -> Application:
    return Application(checkers=[BlastRadius(50), TenantIsolation()], agents=[support])
```

```bash
interlock daemon --config interlock.toml --app myapp.agents:build
```

A plan that loses a race for a row or a window key is staged again, with jittered backoff.
A part that fails is reopened after a backoff that doubles each time. `SIGHUP` reloads the
daemon. The relays and the inbox finish their step and open again, signing with whichever
key their configuration points at by then, and the inbox's listener never closes. The
vacuum opens its key at each run anyway, and engines and agents keep running. `GET
/healthz` on the inbox's port answers `200` while every part runs and `503` otherwise, with
each part's counters. `SIGTERM` stops the parts in order, each step bounded in time: the
agents; the engines (queued plans run until the deadline, and a running stage always
finishes); the inbox, followed by one last match; the relays; the settler, with one last
pass; and any vacuum in progress. A second signal skips the drains and gives the parts one
second to close, and the next start recovers as it would after a crash. Without `--app`,
the daemon runs the relays, the inbox and the vacuum.

In a process of your own, `build_supervisor(config, application)` returns the same
`InterlockSupervisor`, to run on your event loop.

### Several daemons: a cluster

Run three to five daemons over one database and one AgentGov ledger, each in a pod of its
own, and any of them can die at any moment (`docs/EPIC9_DESIGN.md`). Each is a node:

```toml
[cluster]                             # PostgreSQL only
node = "interlock-0"                  # or INTERLOCK_NODE, or interlock daemon --node
database = "postgresql://interlock_cluster@db/app"   # direct, or a session-mode pool
heartbeat_seconds = 1
session_timeout_seconds = 10          # a node silent this long holds nothing more
```

A node's name is at most 40 characters (letters, digits, `.`, `_`, `-`). `database` is the
database Interlock is installed in. A node's lock lives in that database, where the relays
look for it, and a node refuses to join a database without Interlock's storage. Its role
needs no privilege for the locks. To fence other nodes (below), it needs
`pg_signal_backend`, and the parts' roles must not be superusers, because only a superuser
can end a superuser's sessions:

```sql
CREATE ROLE interlock_cluster LOGIN PASSWORD '...';
GRANT pg_signal_backend TO interlock_cluster;
```

A node holds its lock in PostgreSQL, as a session-level advisory lock, for as long as its
process lives. So the database alone decides when a node is gone: when it ends the node's
session. That's immediate for a killed process, and takes `session_timeout_seconds` for one
that froze or lost the network. Every node runs the engines, the relays, the inbox and the
metrics endpoint. The vacuum, and the inbox's matching of webhooks that arrived before
their delivery was recorded, run on one node at a time: the node leading that role, which
holds another advisory lock on the same session. Another node takes the role the next time
it asks after the leader is gone. Each node settles the deliveries of the plans its own
engines committed, into its own receipt log, because a delivery receipt goes into the log
that holds its plan's action receipt. No two nodes ever settle the same message.

A relay's lease names its node (storage version 8: `interlock install` upgrades version 7
in place, and a relay of version 7 left running keeps claiming). When a node is gone, the
next claim of any relay takes its leases over, its calls in flight made again under the same
idempotency key, without waiting for the leases to run out. In a cluster every session that
holds what others wait for, the relays', the inbox's and every AgentGov governor's, is
bounded by `session_timeout_seconds`, and every connection a node opens says whose it is in
`pg_stat_activity`: `interlock-<part>@<node>`.

A node that's gone is fenced. At each heartbeat, a node ends every session belonging to a
node whose lock no session holds, found by its connections' names. A frozen node, or one
cut off from the network, holds nothing past its session timeout plus a heartbeat. That
covers its transactions and any lock it was waiting for, which it would otherwise take and
sit on for its own bound, wait after wait. A node that isn't allowed to end those sessions
says so once in its log, and they end at their own bounds.
`interlock_cluster_fenced_total` counts the sessions a node ended.

On Kubernetes, run it as a StatefulSet:

- `INTERLOCK_NODE` set from the pod's name;
- a volume per pod for its escrow chains and receipt log, with a unique `[receipts] log_id`
  per pod;
- the operator log on a `ReadWriteMany` volume that every pod mounts, with working file
  locks;
- `/healthz` for readiness and liveness (a node on standby for a role counts as healthy);
- the node's session reaching PostgreSQL directly, or through a pool in session mode,
  never transaction mode.

`interlock daemon` exits 3 when its node is already running, or when another process took
its name while it ran.

### Metrics

With `[metrics] listen` set, or `interlock daemon --metrics HOST:PORT`, the daemon serves
Prometheus's text format on a port of its own (never the inbox's, which faces vendors):
`GET /metrics` and `GET /healthz`. Each part measures its own work:

- the engines: every plan by outcome and duration, races lost (to a row's lock or to the
  pool), waits for window-key locks and for the windows' connection, and the longest of
  each in the last minute;
- the relays: every call by sink and outcome;
- the settler: each delivery receipt's lag behind its delivery;
- the inbox: every webhook by answer and by the trace context it carried;
- the vacuum: its runs and what they pruned;
- every part: its state, steps and failures.

What only the database knows is sampled every `every_seconds`, in one read-only snapshot,
as the `database` role: the outbox's depth by state and its oldest due message,
settlement's backlog, facts no plan has consumed, and each rate window's fullest key
against its limit (`interlock_window_saturation`). A scrape reads memory, never the
database. No label is a tenant, a scope, a plan or a key, so the configuration sets the
number of series and traffic doesn't. `interlock.telemetry.CATALOG` lists every metric, and
`docs/EPIC7_DESIGN.md` §2 says what each one measures. The registry adds under two
microseconds to a plan (`scripts/metrics_overhead.py`).

The endpoint isn't authenticated, so bind it to an address only your scraper can reach. It
shows how the system is behaving, never its data.

### Trace context

A plan can carry a W3C `traceparent`, and Interlock carries it wherever the plan's effects
go: beside each request in the outbox, out as the `traceparent` header of every call the
relay makes (`HttpAdapter`, and Stripe's and SendGrid's adapters), retries included, and
onto the refund an operator issues to compensate a charge. When a webhook's signature
verifies, the context it carried is kept beside its event. The fact the inbox binds to a
delivery continues the delivery's trace. It uses the webhook's context when the vendor
continued ours, and the delivery's own when the vendor sent its own trace, a malformed one,
or none. A plan that consumes the fact continues the trace too, so agent, outbox, relay,
vendor, webhook and agent again form one trace:

```python
from interlock import PlanBuilder, child_traceparent, new_traceparent, parse_traceparent

checkout = new_traceparent()  # or your tracing library's current context
plan = (
    PlanBuilder("support-agent", intent="charge order 7", traceparent=checkout)
    .update(
        table="orders",
        statement="UPDATE orders SET status = :status WHERE id = :id",
        parameters={"status": "charging", "id": 7},
    )
    .build()
)
assert plan.traceparent == checkout

# What arrives over HTTP is read as W3C asks a receiver to: malformed is None.
assert parse_traceparent("not a traceparent") is None

# A plan consuming a fact bound to the charge: a span of its own, in the same trace.
follow_up = child_traceparent(checkout)
assert follow_up.split("-")[1] == checkout.split("-")[1] and follow_up != checkout
```

In the daemon, `ctx.plan(scope, traceparent=...)` does the same, and each fact from
`ctx.facts(scope)` has its `traceparent`. Trace context is outside every hash. A plan, a
request, a delivery log, a relay's attestation, a receipt, an event and a fact all hash the
same with or without it, and no decision Interlock makes reads it. It's kept in tables of
its own, which the vacuum prunes along with the rows they describe. Interlock propagates
and records trace context, but exports no spans of its own.

### The soak

`scripts/live_stress_test.py` runs a cluster of daemons for minutes against a live
PostgreSQL, in a container it starts or on a server you name:

```bash
uv run python scripts/live_stress_test.py --docker --minutes 5
uv run python scripts/live_stress_test.py --dsn postgresql://admin:pw@localhost:5432/postgres
```

It runs `--nodes` daemons (three by default), each an `interlock daemon --node` in its own
process, over one database and one ledger. On every node, agents keep plans in flight:
checkouts that insert an order and charge for it, carrying the refund that undoes it;
reconciliations of what the payment API's webhooks say; notes on rows that every node
contends for; and now and then a plan that has to be refused.

A fake payment API answers in Stripe's shape, honours idempotency keys, and fails on
purpose: 500s after acting, 429s, replies slower than the relay waits. Its webhooks come
back signed, duplicated, early, about objects nobody created, and forged. An operator
refunds paid orders, signing every action. Webhooks reach the nodes through a balancer
that takes a node out when it stops answering.

At 45% of the load, the node leading the vacuum is killed with `SIGKILL` while its relays
have a call in flight. At 70%, the node leading it then is frozen with `SIGSTOP`, with a
call in flight and a stage open, its connections left open the way a host cut off from
the network leaves them. It's killed once the server and the other nodes have ended
everything it held. Each node comes back, as a rescheduled pod would, and recovers.

A quarter of the way through, the operator rotates the relays' key, which the relays, the
inbox and the vacuum sign with through a key service in the soak's process. A new version
is registered, every node is reloaded with `SIGHUP`, and the old key is revoked while a
stale relay that still holds it has a call in flight. The database refuses that relay's
outcome, another relay delivers the message once under the new key, and everything the old
key attested before still verifies under its seal.

Then the soak checks, from the database, the ledger, the logs and each node's journal of
what its agents did:

- no deadlock, lock waits within their bounds, and every lost race retried to an outcome;
- every rate window within its limit at every instant of its history;
- the ledger balanced to the cent, each plan charged once and each refund credited once;
- one charge per order and one receipt per delivery, except for a plan whose node died
  before issuing its action receipt;
- no forgery accepted, and the vacuum keeping the outbox bounded as it runs;
- every verifier passing afterwards, a graceful stop, and a second daemon finding nothing
  to recover;
- every checkout's trace context carried to the payment API, onto its refund, back on the
  facts its webhooks became and on to the plans that consumed them, whatever the vendor
  sent;
- the metrics, scraped every second, agreeing with what the run counted itself;
- keys rotating under load, every node sharing the work, and one node leading each role at
  a time;
- the killed node's lock gone with it, its leases taken over within a second, and its call
  in flight made again and acted on once;
- the frozen node's leases taken only once it was gone, every session it held fenced a
  heartbeat later, and no survivor waiting on any of them longer.

`tests/test_soak.py` runs it for a minute and a half in the test suite.

### The security audit

`scripts/security_audit.py` checks whether any sensitive value reaches a hash Interlock
commits to (`docs/EPIC8_DESIGN.md` §4). On each store it runs one scenario through the
daemon, with canaries planted in a plan's trace context, the relay's API key, a webhook's
body and headers, and its signing secret. It records the input of every SHA-256 and every
signature Interlock and AgentGov compute. None of them may contain a sensitive value or its
digest, except the body's SHA-256, which the inbound event commits to, and only columns
made for a sensitive value may hold one. It prints, column by column, what holds a
sensitive value and which hash reads it:

```bash
uv run python scripts/security_audit.py --docker
```

### The customer acceptance matrix

`demo/customer_acceptance_suite.py` puts a live Claude model in front of four unrelated
business domains on SQLite: accounts-payable disbursements on a double-entry ledger, cluster
operations, a multi-tenant SaaS admin console, and fulfilment in dependent stages for a
third-party warehouse. Each has its own schema, triggers, constraints and simulated outside
APIs, and one function builds each domain's policy from the same checkers. Only table and
column names and limits differ. The model gets each domain's everyday request, requests
that conflict with its rules (another tenant's rows, a cap, a table outside its remit, an
append-only log), and conflicting figures. Everything it proposes goes through
`PlanBuilder` and `EscrowEngine.execute`. Independent checks, which don't ask Interlock,
verify every outcome: other tenants' rows byte for byte, each committed request against its
rows, the domain's own invariants, delivery order and count, and that nothing shown to the
model names another tenant's data. Reference proposals, one per policy dimension in every domain, run
the same tool with no model, in CI (`tests/test_acceptance_suite.py`). The last live run is
recorded in [`docs/CUSTOMER_ACCEPTANCE_MATRIX.md`](docs/CUSTOMER_ACCEPTANCE_MATRIX.md), with
every tool call the first model named made, exactly as it made it.

```bash
uv run python demo/customer_acceptance_suite.py --offline    # the references; no model
BENCHMARK_API_KEY=sk-ant-... uv run python demo/customer_acceptance_suite.py \
    --matrix docs/CUSTOMER_ACCEPTANCE_MATRIX.md
```

## Unrecorded writes

The monitor only sees what goes through it. A cron job, a migration, a DBA at a prompt, or
the agent's own credentials used directly can all write observed tables without leaving
anything in the escrow chain. `interlock reconcile-effects` closes that gap by checking
that nothing changed an observed table without a record.

```bash
interlock install           --config interlock.toml   # once; SQLite needs it for this too
interlock reconcile-effects --config interlock.toml --chain escrow.jsonl [--after N]
```

It fails (exit 1) on:

- **an unmediated write**, a row change no stage made. On PostgreSQL, the installed
  trigger logs each one to `interlock.unmediated` inside the writer's own transaction, with
  the session user, `application_name` and transaction id. A `TRUNCATE` is logged too. On
  SQLite, `interlock install` adds permanent journal triggers that record every row change
  in `_interlock_journal`, and each committed stage records the range of journal rows it
  produced. That range is exact because `BEGIN IMMEDIATE` admits one writer at a time. A
  cascade from a table nobody observes is found row by row;
- **an unrecorded stage:** one the database committed that no chain records, such as one
  opened by hand with the stage role's credentials, or by an engine on the default
  in-memory chain;
- **a contradicted stage:** recorded as aborted, or under another plan;
- **an unresolved stage**, one that committed with only its commit intent in the chain,
  after a crash in the commit window. Recovery resolves it, and `EscrowRuntime` runs
  recovery at startup;
- on SQLite, an observed table whose journal trigger is missing.

Each run prints `last entry: N`; pass it back as `--after N` to check only what is new.
Exit code 5 means a chain failed verification and proves nothing. On PostgreSQL, run it as
a role named in `audit_roles` at install, which may read Interlock's logs and write
nothing.

It can't see anyone who can disable the triggers or edit the logs. On PostgreSQL that's
the tables' owner or a superuser (logical decoding would close that gap). On SQLite it's
anyone who can write the file.

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
  observed table while writing elsewhere never executes. It raises
  `ForbiddenStatementError`, naming the table it reached for. Pass
  `enforce_table_access=False` to lift the unobserved-table rule for a migration. The rules
  below stay on.

  The same callback refuses a statement that writes the capture table (which would erase
  the measurement), the commit-marker table, or transaction control. A `COMMIT` inside a
  stage used to make every effect before it durable before any checker ran. Grant the
  connection exactly the observed tables anyway. A grant the database enforces is a
  boundary, and the callback is a second one in front of it.

  DDL and transaction control are refused twice over: `SqliteSubstrate.reject_reason()`
  reads the statement's leading verb at admission, so `ALTER`/`DROP`/`CREATE`/`TRUNCATE`
  /`VACUUM`/`ATTACH`/`PRAGMA`/`COMMIT`/`SAVEPOINT` and friends are rejected whatever
  `Effect.kind` claims.
- **A foreign-key cascade into an unobserved table is refused unless you acknowledge it.**
  A `DELETE` on `orders` that cascades into an unobserved `order_notes` used to destroy
  those notes unmeasured. Every stage now reads the foreign-key graph under its write lock
  and refuses, before a row changes, a delete or a referenced-key update whose `CASCADE`,
  `SET NULL` or `SET DEFAULT` actions reach an unobserved table, naming the path. The
  analysis follows chains of actions to any depth and is precise to the column, so updating
  `orders.status` is never refused because of a key on `orders.id`. `EscrowRuntime` runs
  the same check at startup and logs every gated operation. To let a cascade run
  unmeasured, name the table in `acknowledge_cascades=[...]`. Every stage that runs with
  that gap says so in its `STAGE_OPENED` record. The refusal is enforced three ways, so no
  single layer carries it alone. The authorizer refuses the parent operation. It also
  refuses any foreign-key action SQLite compiles into the table, which is what catches
  `INSERT OR REPLACE`. And temporary triggers on the table abort any row change there while
  the stage is open.
- **One engine stages one substrate.** A plan whose effects name another substrate is
  refused at admission. Nothing coordinates two substrates, so a plan that spans SQL and a
  non-transactional sink needs the outbox pattern below.
- **`blast_radius` counts captured mutations, not distinct rows.** A row mutated twice in
  one plan contributes 2, so the limit is conservative and is not a row tally.
- **`ColumnValueGuard` and `TenantDrawdownGuard` are one-directional.** Both fire on a
  fall in the column total, which counts each row once: its value before the plan and its
  value after, however many times the plan or a trigger wrote it. An inflation passes, and
  so does any diff whose pre-image total is zero, which includes every insert-only plan.
  `TenantDrawdownGuard` works per tenant, but that doesn't make it symmetric. Use a rise
  bound (`max_rise`) to catch an increase.
- **`StatedFootprint` is a cooperative diagnostic.** It reads `Effect.stated_rows`. An agent
  that omits the field on any effect turns the checker into a no-op.
- **Chain durability is opt-in.** With no `chain_path` the chain lives in memory and
  dies with the process. With one, the intent is written ahead and a crashed commit is
  resolved exactly on restart (see [Lifecycle](#lifecycle)). The `_interlock_commits`
  table gains one row per committed stage and isn't pruned, not even by the
  [vacuum](#compaction-the-vacuum), because recovery and `reconcile-effects` read it.
- **The chain is keyless.** Anyone who can write the chain file can recompute a SHA-256
  chain from start to finish and it will verify. A reverse anchor in a governed AgentGov
  is one copy of the head outside the file. With [receipts](#receipts) on, each
  adjudicated plan also gets a signed receipt naming its terminal record, under a key the
  chain file doesn't hold. The chain itself stays unsigned.
- **Lock footprint.** A stage holds write locks for its whole life, a repair search's
  included. `max_stage_seconds` bounds it. Human review must not happen inside an open
  stage. Abort, present the recorded diff, and stage again on approval, because the
  substrate may have moved in the meantime.
- **Recovery trusts the harness to route its calls.** The runtime holds and records its
  own steps, refuses a revoked tool when asked, and catches an edited transcript at the
  next step. It cannot see a harness that bills a recovery call to another scope, runs a
  tool without calling `check_tool()`, or sends the model something other than
  `step.messages`.
- **An extension estimate is arithmetic on what the harness declares.** Cost per declared
  milestone times the milestones remaining assumes the rest of the work costs what the
  finished work did. With none declared, it prices only the call that didn't fit. The
  receipts in a quote's proof of work are verifiable, but its milestones are only the
  harness's claim.
- **Latency.** Staging roughly doubles write-path round trips. Plans below a blast-radius
  threshold should bypass escrow entirely.
- **External effects get a weaker guarantee than rows, by design.** The **request** is
  measured, adjudicated and made durable exactly when the rest of the plan is. Its
  **delivery** is at least once, recorded, and bounded. What the external system then does
  isn't measured at all. What it reports back arrives as an
  [inbound fact](#inbound-facts-the-zero-trust-inbox), which is the vendor's signed word,
  bound to the request, and never a measurement. To check what the vendor actually did,
  reconcile its own log against the delivery receipts with `agentgov reconcile-actions`.
  See [Outbound requests](#outbound-requests-the-transactional-outbox). On SQLite,
  `interlock install` installs the outbox, as it does on PostgreSQL.
- **Every threshold in `default_checkers` is a placeholder.** They are uncalibrated.
  Measure your own diffs and set them from the measurement.
- **A node's deliveries wait for it.** In a cluster, each node settles its own plans'
  deliveries, from its own chains and receipt log. If a node never comes back, its
  deliveries stay unsettled until another process takes over its volume as that node. In
  the meantime, the rest of the cluster still makes its payments, records its webhooks and
  consumes its facts.

[`docs/ESCROW_SPEC.md`](docs/ESCROW_SPEC.md) is the interface contract, the architecture
built on it (§5: components, data flows, roles, evidence, concurrency), and a conformance
section listing implemented, partial and unimplemented requirements.

## Install

`agentgov` comes from PyPI (`interlock-agentgov>=1.3.0`, ARC1 1.4), so a clone needs
nothing beside it:

```bash
git clone https://github.com/crimsondevil0929/interlock
cd interlock && uv sync
```

Or install the package directly:

```bash
uv pip install git+https://github.com/crimsondevil0929/interlock
```

Signing (a relay's attestations, an operator's records) needs the `sign` extra
(`cryptography`). Verifying never does. `kms-aws` adds `boto3` for `AwsKmsSigner`, a key
held by AWS KMS, and `otel` adds agentgov's OpenTelemetry metrics. Both pass through to
agentgov's extras of the same names.

**Developing on both repos at once.** `uv sync` resolves agentgov from PyPI, and a sibling
`../agentgov` checkout is not consulted on its own. To point `uv` at one, add to
interlock's `pyproject.toml`:

```toml
[tool.uv.sources]
interlock-agentgov = { path = "../agentgov", editable = true }
```

then `uv lock && uv sync`. It is workspace configuration, not written into the built
wheel. Drop it, and rerun `uv lock`, before merging: CI resolves a clean clone from the
lockfile, with no sibling checkout, and fails on a path source.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run mypy --strict tests/ demo.py
```

The PostgreSQL tests run against a live server. Set `INTERLOCK_TEST_POSTGRES_DSN` to a
role that may create databases and roles, and `INTERLOCK_REQUIRE_POSTGRES=1` to fail
rather than skip when there isn't one. Two suites are release gates.
`tests/test_crash_consistency.py` kills a real process with `SIGKILL` at every step of a
PostgreSQL commit, and at random instants, then checks exactly what recovery makes of it.
`tests/test_tamper_evidence.py` alters every part of the audit trail and checks that
verification fails exactly there. `INTERLOCK_CRASH_SEED` and `INTERLOCK_CRASH_ROUNDS`
replay or lengthen the random-instant run.

## License

Apache-2.0: see [LICENSE](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).
