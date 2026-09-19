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

## Usage

```python
from interlock import (
    BlastRadius,
    EscrowChain,
    EscrowEngine,
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

result = engine.execute(plan)
if not result.committed:
    print(result.blocked_by, result.diff.blast_radius)
```

Checkers are pure functions of `(plan, diff)`. No I/O, no clock, no RNG, no model call. A
checker that reads the world cannot be replayed, and a verdict that cannot be replayed is
not evidence. Where a judgment genuinely needs a model, the model is a **sensor** whose
output is passed in at configuration time, never consulted from inside `check`. A checker
that raises becomes a blocking violation: fail closed.

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
engine = EscrowEngine(substrate, checkers=[...], anchor=anchor, settle_cost="0.01")
```

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

- **The measurement is scoped to `TableSpec`, and admission does not enforce that scope.**
  `admit()` rejects a plan whose `Effect.target` names an unobserved table, but `target` is
  a label the agent writes and is never compared against the statement. A statement that
  writes a table outside `TableSpec` executes, commits, and is measured as
  `blast_radius == 0` with an empty `tables_touched`, so every diff-reading checker passes
  on an empty measurement. **Restrict what the substrate's connection can reach.** Grant
  the role exactly the observed tables; do not rely on this layer for containment.

  DDL specifically is refused: `SqliteSubstrate.reject_reason()` reads the statement's
  leading verb and the engine calls it at admission, so `ALTER`/`DROP`/`CREATE`/`TRUNCATE`
  /`VACUUM`/`ATTACH`/`PRAGMA` and friends are rejected whatever `Effect.kind` claims. That
  closes the specific hole, not the general one: the check is a verb allowlist, not a
  parser, and it says nothing about which table a permitted statement reaches.
- **Cascades reach outside the measurement.** A granted `DELETE` on an observed table whose
  foreign key cascades into an unobserved table destroys those rows and they do not appear
  in the diff.
- **One engine stages one substrate.** A plan whose effects name another
  substrate is refused at admission; nothing coordinates two substrates, so a
  plan spanning SQL and a non-transactional sink needs the outbox pattern below.
- **`blast_radius` counts captured mutations, not distinct rows.** A row mutated twice in
  one plan contributes 2, so the limit is conservative and is not a row tally.
- **`ColumnValueGuard` is one-directional.** It fires on a fall in the column total. An
  inflation passes, and so does any diff whose pre-image total is zero, which includes every
  insert-only plan.
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
form work. It also means interlock cannot be published to PyPI as-is: PyPI rejects
direct-URL dependencies. Publishing means putting `agentgov` on PyPI and pinning a version
range instead.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run mypy --strict tests/ demo.py
```

Apache-2.0.
