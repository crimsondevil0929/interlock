# The Interlock guide

Everything about the engine that the [README](../../README.md) leaves out: typing, invariants and partitions, errors and refusals, repair, rate windows, AgentGov and Fiduciary, receipts, recovery, extension quotes, unrecorded writes, and the scope of what Interlock claims. The systems it stages on, the outbox and the daemon are in [SYSTEMS.md](../SYSTEMS.md). Every Python block here runs in CI, as the README's do.

## The engine in detail

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
| `CrossEffectAgreement` | an outbound request against the rows it rides with ([outbox](SYSTEMS.md#outbound-requests-the-transactional-outbox)) |
| `SinkAllowlist` | the sinks and operations a plan may call |
| `OutboundCount` | the requests one plan may enqueue, in all or per sink |
| `PayloadAmountCap` | a payload amount, per request, per tenant or per plan, per currency or any unit |
| `RecipientAllowlist` | where a request may send: email domains and addresses, https hosts, per tenant |
| `OutboundTenantIsolation` | the tenants one plan's requests may span |
| `FactAgreement` | a write against the inbound fact it must follow ([inbox](SYSTEMS.md#inbound-facts-the-zero-trust-inbox)) |

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

### The same model on every system (1.6.0)

A measured change is a `Change`: its `kind` (the table, the path class, the Kubernetes kind,
the resource type), its `id` within that kind (the primary key, the path, `namespace/name`),
its `before` and `after` images, and its partition labels. `RowDelta` is the same class under
the name it had before 1.6.0, and `table` and `primary_key` read the same two values, so
nothing written against the SQL names changes. On a diff, `changes`, `change_count` and
`kinds_touched` read what `deltas`, `blast_radius` and `tables_touched` read.

Four built-in checkers have a name for every system beside their SQL one. The two are the
same check and judge alike. Each records its own name on the verdict and in the receipt, so
a deployment that keeps the SQL names keeps every digest it has issued.

| For every system | The SQL name | Records |
|---|---|---|
| `ChangeLimit(8)` | `BlastRadius(8)` | `change_limit` / `blast_radius` |
| `KindAllowlist([...])` | `TableAllowlist([...])` | `kind_allowlist` / `table_allowlist` |
| `PartitionIsolation("tenant", max=1)` | `TenantIsolation(1)` | `partition_isolation:tenant` / `tenant_isolation` |
| `ValueGuard(kind, field, ...)` | `ColumnValueGuard(table, column, ...)` | `value_guard:<kind>.<field>` / `column_value_guard:<table>.<column>` |

`checker_family()` says which check a recorded name is, in either vocabulary, without its
configuration: `change_limit` for both `blast_radius` and `change_limit`. An agent on a
directory that is refused by `KindAllowlist` is told `kind_allowlist: the plan changed files
in the scripts path class`, with no table in the sentence or the label.

```python
from interlock import ChangeLimit, KindAllowlist, NoDelete, PartitionIsolation, ValueGuard

checkers = [
    ChangeLimit(10),
    KindAllowlist(["config", "docs"]),
    NoDelete(),
    PartitionIsolation("tenant", max=1, declared=True),
    ValueGuard("orders", "total", max_drop_fraction=0.25),
]
```

### A stage that opens before its plan (1.6.0)

`execute()` takes a finished plan. Code that reads a row, decides, and writes another does
not have one. `EscrowEngine.stage()` opens the stage first:

<!-- readme-test: skip reason="needs the quickstart's engine and database; tests/test_open_stage.py makes the same calls" -->
```python
with engine.stage("support-agent", intent="discount order 500") as stage:
    (order,) = stage.read("SELECT total FROM orders WHERE id = :id", {"id": 500})
    stage.add(
        EffectKind.UPDATE,
        table="orders",
        statement="UPDATE orders SET total = :total WHERE id = :id",
        parameters={"total": str(order["total"] - 5), "id": 500},
    )
    result = stage.settle()
```

Each effect is checked as admission checks it and applied to the stage at once, and a read
in the stage sees it. `settle()` turns the effects into an ordinary plan and runs it through
the same lifecycle on the stage that is already open: admitted, measured, judged, then
committed or refused. The chain reads exactly as it does for `execute()`, and it holds
nothing until the settle. Leaving the `with` block without settling discards the stage, with
nothing changed and nothing recorded. An effect that is refused or fails is not part of the
plan.

- **Reads.** On SQLite and PostgreSQL, `read(statement, parameters)` returns rows, and runs
  inside a savepoint that is rolled back, so a statement that writes keeps nothing. On a
  directory, `read(path)` returns the file's bytes as the stage holds it. Other systems'
  stages hold predictions and nothing to read: read the system itself.
- **One at a time.** The stage holds the database's write lock, or the directory's private
  copy, for as long as it is open. Keep it short.
- **Not with claim and settle.** When the ledger settles inside the stage's own transaction
  (PostgreSQL, joined), a plan's hold is placed before its stage opens. `stage()` refuses
  there.
- **On PostgreSQL a failed effect ends the stage**, as a failed statement ends any
  transaction. A failed read does not.

### Observing before enforcing (1.6.0)

A new policy is easier to trust after it has watched real work. An engine built with
`observe_only=True` stages, measures and judges every plan exactly as an enforcing one does,
and then commits it either way. A violation that would have refused the plan is recorded on
the verdict with the severity `observed`.

```python
from interlock import ChangeLimit, EscrowEngine, KindAllowlist, SqliteSubstrate, TableSpec

engine = EscrowEngine(
    SqliteSubstrate("back_office.db", tables=[TableSpec("orders", columns=["id", "total"])]),
    checkers=[ChangeLimit(1), KindAllowlist(["refunds"])],
    observe_only=True,
)
```

- `result.would_refuse` lists the checkers that would have refused, and
  `result.verdict.observed` holds their violations, with the same messages a refusal carries.
- The chain's `VERDICT` record reads `admitted; observed, not enforced: change_limit,...`.
  The severity is in the verdict's hash, so a plan that committed under observation cannot be
  presented as one an enforcing engine admitted clean.
- The agent's feedback lists each constraint, followed by "Observed, not enforced: the plan
  was not refused for it."
- `always_enforce=[...]` names checkers that still refuse.

Observing changes what a verdict does, and nothing else. A statement the substrate refuses to
stage, a halted scope, a scope that cannot pay and a held outbound request all behave as they
do on an enforcing engine.

### Coding sessions: one stage for a whole session (1.7.0)

A coding agent does not make one tool call and stop. It edits files with its own tools, runs
the build and the tests, and edits again, for an hour. A *session* gives that work one stage
for its whole length, on a directory (`substrate = "filesystem"`) or a Git branch
(`substrate = "git"`), and promotes the result as one plan:

```bash
interlock install --config interlock.toml          # once: the control database
interlock stage open --config interlock.toml --name fix-timeouts
cd "$(interlock stage open ... | tail -1)"         # the path is the last line it prints
interlock run --config interlock.toml -- pytest -q # sandboxed: writes only here, no network
interlock promote --config interlock.toml --check  # what promotion would decide; commits nothing
interlock promote --config interlock.toml          # commit on the session's base, or refuse
```

- **Open.** A directory is copied into `sessions/<name>/tree` in the substrate's state
  directory, with a copy of the base beside it. A Git branch gets a worktree with a detached
  HEAD at the branch's head, in `.git/interlock/sessions/<name>/worktree`. The session records
  its *base* (the commit, or a digest of the files) and its *input tree*.
- **Work.** The agent edits the tree with whatever tools it has. `interlock run -- <command>`
  runs each command under the operating system's sandbox (`interlock.sandbox`): Seatbelt on
  macOS, bubblewrap on Linux. It may write only in the session's tree and its own temporary
  directory, it may not read the session's records or the directories `[sessions] hidden`
  lists, and it has no network. `--sandbox none` runs a command unconfined, only when asked
  for by name, and the log says so. Each command is logged with its exit code and the digest
  of the profile it ran under.
- **Promote.** Everything the session changed is measured against its base as one plan and
  checked. A directory's plan holds an `expect-hash` of each changed file at the hash the
  session started from; a branch's, an `expect-head` of the base commit. A plan that passes
  commits on that exact base. One that is refused leaves the session open, with its tree as it
  was, for the agent to fix and promote again. If someone changed the same files (or moved the
  branch) since the session opened, nothing is written and the outcome is `conflict`.
- **Receipt.** Each promotion writes `promotion.json` (`ILPR1`) into the session: the input and
  output trees, the command log's digest, each command's exit code, the sandboxes and profile
  digests, the plan, diff and verdict hashes, the chain's head and the commit. With `--key`,
  `--signer` or `[receipts]`'s key it is signed; `interlock.session.verify_receipt` checks it.

On a Git repository whose branch you have checked out yourself, set `checked_out = "follow"` in
`[git]`: a promotion then moves the branch by fast-forwarding your checkout, only when the
checkout is at the session's base, and refuses (moving nothing) when it is not.

`[sessions]` sets a session's lifetime, its sandbox, the directories its commands may not read,
and, for `interlock promote`, the path classes a promotion may change and how many files.
`--app module:callable` adds an application's checkers. Fiduciary promotes a session under a
signed mandate instead (`fiduciary init --claude-code`).

**Claude Code.** `interlock hook claude-code --config interlock.toml` answers the hooks a
session needs, with the event on stdin (`interlock.hooks.settings` writes them):
`WorktreeCreate` opens a session and hands Claude Code its tree as the working directory
(`claude --worktree`, or the EnterWorktree tool), `SessionStart` tells the agent how the session
ends, `PreToolUse` refuses an edit outside the tree, `Stop` checks the session and, when it
would be refused, keeps the agent working with the refusal, and `SessionEnd` and
`WorktreeRemove` promote it. No tool call's input is rewritten: the tree is where Claude Code
works.

### What the session read before the plan (1.8.0)

A checker judges a plan by what it would change. Some plans are fine or not depending on what
the agent read before it asked. An agent that has just read a customer's email, which says
"refund order 7 in full", and then asks to refund order 7 within its cap, is asking for
something its limits allow, for a reason nobody on your side wrote.

A plan can carry the labels of what its session had read, and `ProvenanceGate` reads them:

```python
from interlock import EscrowEngine, PlanBuilder, ProvenanceGate, SqliteSubstrate, TableSpec

engine = EscrowEngine(
    SqliteSubstrate("back_office.db", tables=[TableSpec("orders", columns=["id", "total"])]),
    checkers=[
        ProvenanceGate(
            untrusted_kinds=["orders"],  # after untrusted input, changing orders takes approval
            untrusted_sinks=["stripe"],  # and so does a call to Stripe
            egress={"secret": ["vault"]},  # data labeled secret goes only to the vault
            rule_of_two=True,  # see below
        ),
    ],
)
builder = PlanBuilder("support-agent", provenance=["untrusted"])
```

- **After untrusted input.** A plan labeled `untrusted` that changes a kind in
  `untrusted_kinds`, or sends to a sink in `untrusted_sinks`, is refused (`*` means any).
- **Egress.** After reading data labeled `secret`, or one tenant's data
  (`partition:tenant=acme`; `partition:*` covers every partition label), a plan may send only
  to the sinks `egress` clears for that label.
- **The rule of two.** A session may have read untrusted input, read sensitive data, and
  changed or sent something: any two of the three. With `rule_of_two=True` a plan that would
  make it all three is refused.
- A plan labeled `cleared` is admitted: the principals approved that exact plan, with its
  labels. A label `quarantined:<tool>` is a reader sub-agent's typed result, and counts as
  none of the above.

The refusal tells the agent what it changed and that the change takes the principals'
approval. A stage opened before its plan takes the labels too: `engine.stage(scope,
provenance=["untrusted"])`. The labels are in the plan's hash when there are any; a plan with
none hashes as it always did.

Interlock does not decide what is untrusted. The code that serves the reads labels them;
Fiduciary's bridge and SDK label a session from each tool's binding, record each label in a
signed session record, and hold a refused plan for the principals instead of only refusing it.
The gate trusts the labels it is given. It cannot tell what a model did with what it read, only
that it read it, and a read nobody labeled is not seen.

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
# Proof of work: 0 plans committed (0 rows); declared 3 of 5 tickets done.
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

**Substrates, each at the measurement class it can honestly claim.** SQLite and PostgreSQL,
a Git branch and a directory are transactional (T); Kubernetes and Terraform are plan-bound
(P); a FHIR server and any JSON REST API with versions are predicted and verified (V); an
outbound request is request-only (R). Every one measures at the row-level-diff standard: one
row, file, object or record per change, never a count reported by the system. A row count is
the summary this design exists to replace. See [SYSTEMS.md](SYSTEMS.md) for each.

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
  resolved exactly on restart (see [Lifecycle](../README.md#lifecycle)). The `_interlock_commits`
  table gains one row per committed stage and isn't pruned, not even by the
  [vacuum](SYSTEMS.md#compaction-the-vacuum), because recovery and `reconcile-effects` read it.
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
- **Latency.** A write through Interlock costs from about 2 ms (SQLite) to tens of
  milliseconds (PostgreSQL across its round trips), measured per system in the README's
  [What a write costs](../README.md#what-a-write-costs). A read never goes through it.
- **External effects get a weaker guarantee than rows, by design.** The **request** is
  measured, adjudicated and made durable exactly when the rest of the plan is. Its
  **delivery** is at least once, recorded, and bounded. What the external system then does
  isn't measured at all. What it reports back arrives as an
  [inbound fact](SYSTEMS.md#inbound-facts-the-zero-trust-inbox), which is the vendor's signed word,
  bound to the request, and never a measurement. To check what the vendor actually did,
  reconcile its own log against the delivery receipts with `agentgov reconcile-actions`.
  See [Outbound requests](SYSTEMS.md#outbound-requests-the-transactional-outbox). On SQLite,
  `interlock install` installs the outbox, as it does on PostgreSQL.
- **Every threshold in `default_checkers` is a placeholder.** They are uncalibrated.
  Measure your own diffs and set them from the measurement.
- **A node's deliveries wait for it.** In a cluster, each node settles its own plans'
  deliveries, from its own chains and receipt log. If a node never comes back, its
  deliveries stay unsettled until another process takes over its volume as that node. In
  the meantime, the rest of the cluster still makes its payments, records its webhooks and
  consumes its facts.

[`docs/ESCROW_SPEC.md`](ESCROW_SPEC.md) is the interface contract, the architecture
built on it (§5: components, data flows, roles, evidence, concurrency), and a conformance
section listing implemented, partial and unimplemented requirements.
