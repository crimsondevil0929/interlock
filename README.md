# Interlock

**A reference monitor for agent side effects.** An agent proposes a plan. It holds no
credentials and cannot execute. Interlock applies the plan against a real but uncommitted
substrate, measures what actually changed, evaluates deterministic predicates against that
measurement, and only then commits or rolls back.

> **Start here:** [the live console](https://crimsondevil0929.github.io/fiduciary/) ·
> [how AgentGov, Interlock and Fiduciary fit together](#start-here) ·
> [put it in front of your agent in 30 minutes](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/QUICKSTART.md)

```bash
uv run python demo.py
```

```
  SCENARIO 2  The identical plan, through Interlock.
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

## Start here

**See the whole stack working:** <https://crimsondevil0929.github.io/fiduciary/>. Six
industries run on one engine, a real model's recorded turns are replayed on the current
release, and 16 audit bundles can be verified in your browser.

A gateway decides whether an agent may call a tool. This stack decides whether what the call
changed may be kept, and produces evidence for someone who trusts neither the agent nor the
operator. It is three packages:

| Package | On PyPI | What it answers |
|---|---|---|
| [Fiduciary](https://github.com/crimsondevil0929/fiduciary) | [`interlock-fiduciary`](https://pypi.org/project/interlock-fiduciary/) | Who may do what, and who approved each exception. Signed mandates, 2-of-3 quorum warrants, the approvals console, governed MCP tools, and audit bundles anyone can verify offline. **Start here** to put the stack in front of an agent: it installs the other two. |
| **Interlock** (this repository) | [`interlock-escrow`](https://pypi.org/project/interlock-escrow/) | Does what this write actually changed satisfy policy? It stages the write, measures it, commits it once or puts it back, and delivers outbound calls exactly once. Each change is measured in one of four ways: **T** inside a transaction, **P** as the system's own plan, **V** predicted then read back, **R** the request only. |
| [AgentGov](https://github.com/crimsondevil0929/agentgov) | [`interlock-agentgov`](https://pypi.org/project/interlock-agentgov/) | May this scope spend this amount? Spend and rate ledgers across a delegation tree, circuit breakers, ARC1 receipts, and reconciliation of a system's own log against them. |

New here? [Put it in front of your agent in 30 minutes](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/QUICKSTART.md),
and read [what it does and does not protect against](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/THREAT_MODEL.md).

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
scenario 2's input are fixed `EffectPlan`s defined in `demo.py`. No model is called. That keeps
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

How a change can be read back depends on the system, and each receipt says which of four
ways it was:

| Class | Measured | Where | What it rests on |
|---|---|---|---|
| **T**, transactional | inside the transaction, before it commits | SQLite, PostgreSQL | the database's own capture of every row the plan touched |
| **P**, plan-bound | the system's own plan of the change, applied only if nothing moved | Git (the diff), Kubernetes (the API server's dry run), Terraform (the plan) | the plan applied is the one measured: a compare-and-swap on the head, version or plan file |
| **V**, predicted and verified | a prediction, written conditionally, then read back | FHIR servers | the read-back: anything that differs from the prediction is put back and receipted `compensated` |
| **R**, request-only | the request itself | outbound API calls through the outbox | the vendor's word: delivery is receipted, and its own log is reconciled against the receipts |

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

## What a write costs

Each system timed two ways, in alternating rounds on one machine: the write made directly,
and the same change through Interlock. Through Interlock is the whole path: staged,
measured, judged by three checkers, committed, recorded in the escrow chain, and receipted
with an Ed25519 signature. Measured with [`scripts/overhead.py`](scripts/overhead.py)
on an Apple M2 Pro (macOS, Python 3.11), PostgreSQL 16 in Docker on the same machine, and
Kubernetes and FHIR on Interlock's loopback servers.

| System | Measured as | Direct, median ms | Through Interlock, median ms | Through Interlock, p95 ms | Added, ms | Ratio | Counted per write (direct / through Interlock) |
|---|---|---|---|---|---|---|---|
| SQLite | T, in the transaction | 0.20 | 2.17 | 2.93 | +1.97 | 10.6x | file |
| PostgreSQL 16 | T, in the transaction | 0.96 | 31.93 | 38.56 | +30.98 | 33.4x | connections: 0 / 1 (7.7 ms each here); statements: 1 / 40 |
| Git | P, the branch's own diff | 122.19 | 382.55 | 464.59 | +260.36 | 3.1x | git processes: 3 / 16 |
| Kubernetes (loopback API server) | P, the server's dry run | 1.15 | 5.85 | 6.83 | +4.70 | 5.1x | HTTP requests: 1 / 3 |
| FHIR R4 (loopback server) | V, predicted, then read back | 2.36 | 9.11 | 10.41 | +6.75 | 3.9x | HTTP requests: 2 / 5 |
| Outbound request (outbox and relay) | R, the request only | 1.08 | 4.42 | 5.11 | +3.34 | 4.1x | HTTP requests: 1 / 1, sent after the commit |

200 writes per path (Git: 50); interlock 1.4.3.

How to read it:

- **SQLite: about 2 ms a write.** The stage, the checks, the chain record and the signed
  receipt, with no network.
- **PostgreSQL: about 31 ms here, and most of it is round trips.** A stage opens its own
  connection (7.7 ms through Docker's port forwarding) and runs 40 statements, where the
  direct write is one UPDATE on a connection already open. Each statement is a round trip,
  so on a database across a network, multiply 40 by that network's round trip. Stages do
  not reuse connections yet.
- **Git: git's own processes.** 16 of them against 3 for a commit and push.
- **Kubernetes and FHIR: two and three more requests.** The dry run and the read-back on
  Kubernetes; the read, the conditional write and the read-back on FHIR. Against a real
  server, each costs that network's round trip.
- **Outbound: the relay's delivery after the commit,** about 3 ms on top of the POST itself.

An agent's tool call already waits hundreds of milliseconds to seconds on its model, so on
most systems this is a small part of each step. A read never goes through Interlock at all.
Run `uv run python scripts/overhead.py --postgres "$DSN" --markdown` for your own numbers.

## Install

```bash
pip install interlock-escrow          # or, with the stack above it: pip install interlock-fiduciary
```

To work on it, clone it. `agentgov` comes from PyPI (`interlock-agentgov>=1.3.0`, ARC1
1.4), so a clone needs nothing beside it:

```bash
git clone https://github.com/crimsondevil0929/interlock
cd interlock && uv sync
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

## Documentation

- [docs/GUIDE.md](docs/GUIDE.md): the engine in full. Typing, invariants and partitions,
  refusals and repair, rate windows, AgentGov and Fiduciary, receipts, recovery, extension
  quotes, and [what Interlock does and does not claim](docs/GUIDE.md#scope).
- [docs/SYSTEMS.md](docs/SYSTEMS.md): each system it stages on (PostgreSQL, Git, Kubernetes
  and Terraform, FHIR), outbound requests through the outbox, and the daemon.
- [docs/ESCROW_SPEC.md](docs/ESCROW_SPEC.md): the specification, with every requirement
  traced to its tests. [docs/OUTBOX_DESIGN.md](docs/OUTBOX_DESIGN.md) and the `EPIC*_DESIGN`
  documents record how each part was designed.
- [scripts/overhead.py](scripts/overhead.py): the overhead table above, reproducible.
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md).
