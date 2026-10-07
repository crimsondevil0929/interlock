# Epic 6: the runtime daemon, and the system under load

**Status: building**, step by step on `feat/epic6-v1-orchestrator`; §8 will record where
the build settles what this design leaves open. Builds on
[`OUTBOX_DESIGN.md`](OUTBOX_DESIGN.md) and the designs of Epics 3 to 5. Four parts:

1. **One runtime** (§1). `EscrowRuntime` grows from a SQLite convenience into the
   configured whole: any substrate, rate windows, inbound facts, the claim-and-settle
   anchor, and construction from `interlock.toml`.
2. **The supervisor** (§2). `InterlockSupervisor` runs every part of Interlock in one
   process, on one event loop: the engines that execute agents' plans, the relays, the
   inbox's receiver and matcher, the settler and the vacuum. It restarts a part that
   fails, reports each part's health, and shuts down without cutting anything in half.
3. **The soak** (§3). `scripts/live_stress_test.py` runs the whole daemon for minutes
   against a live PostgreSQL. A fake payment API answers with injected faults, signed
   webhooks come back, duplicated, early and forged, and agents push hundreds of concurrent
   plans through it. The soak then proves the system's invariants from the database, the
   ledger and the logs.
4. **The specification** (§4). `docs/ESCROW_SPEC.md`'s architecture and conformance sections,
   rewritten for what version 0.5.0 actually is.

Decided before any code:

- **What must have one writer lives in one process.** An escrow chain, the receipt log and
  the operator log each refuse a second writer. The engines and the settler share the
  receipt log (the settler issues delivery receipts into the log that holds the action
  receipts), so they run in one process: the supervisor's. Each engine worker writes a
  chain of its own (§2.2). The vacuum opens the operator log only for its run, so an
  operator's command can use it in between.
- **Blocking work stays blocking, on threads; the event loop orchestrates.** Every database
  call in Interlock and AgentGov is synchronous. The supervisor schedules them, bounds them
  and stops them from one asyncio loop, and runs each on a thread pool of its own service.
  None of the primitives changes to suit the loop.
- **Every part connects as its own role.** Engines connect as the stage role, the governor
  as the ledger's owner, relays as a relay role, the inbox as an inbox role, the settler as
  a settler role, and the vacuum as the installer. The daemon is least privilege by
  construction.
- **Shutdown cuts nothing in half.** A stage, a delivery, a webhook being recorded and a
  vacuum each finish or never start. A `kill -9` is a crash, and every part already
  survives a crash: the crash matrices of Epics 2 to 5 stand behind the daemon unchanged.
- **Conflicts are expected; deadlocks are bugs.** Under concurrency, stages lose races for
  rows and window keys and are retried. A deadlock is a lock-ordering defect, and the soak
  fails on one.

---

## 1. One runtime

### 1.1 `EscrowRuntime`, configured whole

Today `EscrowRuntime(db_path, tables=..., scope_id=...)` builds a `SqliteSubstrate`, and
passes neither rate windows nor `inbox=` to its engine. It becomes:

```python
EscrowRuntime(
    "app.db",                      # a SQLite path, as before
    tables=..., scope_id=...,
    windows=[...],                 # passed to the engine
    inbox=keyring,                 # passed to the engine; facts() exposed
    sinks=registry,
    anchor=LedgerAnchor(...),      # or governed=/audit_path=, as before
)
EscrowRuntime(substrate=PostgresSubstrate(...), scope_id=..., ...)   # any substrate
EscrowRuntime.from_config(config, scope_id=..., checkers=[...])      # interlock.toml
```

- `db_path` stays the first positional argument. `substrate=` takes any built substrate in
  its place. Passing both, or neither, is an error.
- `windows=`, `inbox=` and `anchor=` reach the engine unchanged. `facts(scope)` and
  `plan(...).consume(fact)` work through the runtime as through the engine.
- `from_config` builds the substrate the file names (SQLite or PostgreSQL, the observed
  tables, the acknowledged cascades), the sink registry, the windows and the inbox keys.
  Checkers stay in code: they are policy, and policy is reviewed as code.

### 1.2 One engine per worker

An engine stages one plan at a time on its substrate. The runtime stays one engine; the
supervisor (§2) is how many plans run at once.

---

## 2. The supervisor

### 2.1 Process model

```
                          one process, one asyncio event loop
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ agents ──execute(plan)──▶ engine pool: N workers, each its own engine,       │
 │   (coroutines or          substrate (stage role), governor (ledger owner),   │
 │    threads)               escrow chain file; one shared receipt log          │
 │                                                                              │
 │ relay pool: M workers, each its own Relay (relay role) ───▶ sinks (HTTP)     │
 │ inbox: HTTP receiver (inbox role) + matcher every few seconds ◀── vendors    │
 │ settler: every few seconds (settler role, shares the receipt log)            │
 │ vacuum: every few minutes (installer; operator log opened per run)           │
 └──────────────────────────────────────────────────────────────────────────────┘
          every blocking call on its service's own thread pool
```

Each part is a **service**. The supervisor starts, supervises and stops each one, and it
owns the event loop.

### 2.2 The services

| Service | What runs | Owns |
|---|---|---|
| **engines** | a pool of `N` workers. A plan submitted is queued, and the next free worker executes it. A `StageConflictError` is retried with jittered backoff, up to a bound. | per worker: an `EscrowEngine`, its substrate, its governor, its escrow chain (`<chain>-<n>`); one `ReceiptIssuer` for all |
| **relays** | `M` workers, each calling `Relay.run_once` in a loop, and resting `poll` seconds when nothing is due | per worker: a `Relay` and its store |
| **inbox** | the HTTP receiver (`POST /inbox/<source>`, `GET /healthz`), and `match_pending` every `match_every` seconds | the `Inbox`, its store, the server |
| **settler** | `Settler.settle` every `settle_every` seconds | the settler's connection and governor |
| **vacuum** | `Vacuum.run` every `vacuum_every` seconds, opening the operator log for the run and closing it after | nothing between runs |
| **agents** | each agent the application registers: a coroutine `async def agent(ctx)`, or a function run on a thread of its own | its `AgentContext` |

**Escrow chains per worker.** `EscrowChain.verify_anchors` requires the AgentGov sequence
each record observed to be non-decreasing along the chain. Engines appending to one chain
would interleave observations made by different governors at different moments, and break
it. So each worker writes its own chain, and its governor's observations only move forward.
The settler reads every worker's chain (`Settler(chain=[...])`).

**Recovery.** At startup each worker's engine runs `recover()` on its own chain, before
that worker takes a plan. Recovery only ever runs on a chain no live engine is writing.

**The `AgentContext`** gives an agent `execute(plan)`, `facts(scope)`, a `PlanBuilder` for
its scope, and `stopping`, which is set when the supervisor begins to shut down. A
synchronous agent calls the same methods, and they block on the loop's futures.

### 2.3 Scheduling on the loop

Each service runs a control loop on the event loop. The loop awaits the service's blocking
step on that service's own executor, then awaits either its interval or the stop event.
Dedicated executors keep one service from starving another: a slow vacuum never delays a
delivery. The engines' executor has exactly `N` threads, so a worker's engine is only ever
used by one thread at a time.

### 2.4 Failure and restart

A service step that raises is logged and counted, and the service is restarted after an
exponential backoff (from `restart_min` doubling to `restart_max`). Its resources are
closed and opened again. A plan's failure is not a service's failure: it is returned to the
agent that submitted it. A database that goes away is a failure of every service that
needs it; each backs off and reconnects, and nothing is lost, because every piece of state
is durable before it is acted on.

### 2.5 Graceful shutdown

`stop()`, or `SIGTERM`/`SIGINT` when the supervisor runs in the main thread, begins this
sequence. Every step has a deadline (`drain_timeout`):

1. **Agents.** `ctx.stopping` is set. Async agents are given the drain timeout to return,
   then cancelled; threaded agents are given the same time and then left to finish.
2. **Engines.** New submissions are refused (`SupervisorStoppedError`). Queued plans
   are executed until the deadline, then cancelled: a cancelled plan was never staged.
   Running plans always finish. A stage is never cut.
3. **Inbox.** The server stops accepting, the requests in flight finish, and a vendor
   retries what was not answered. Then one last match.
4. **Relays.** Each worker finishes the batch it holds and stops. A message never claimed
   stays pending for the next start. One that was claimed is recorded, or its lease runs
   out and another relay takes it over.
5. **Settler.** A last pass settles what the relays just delivered.
6. **Vacuum.** A run in progress finishes, and no new one starts.
7. **Close.** Engines, chains, governors, stores and the receipt log, in that order.

A second signal skips the remaining drains and closes at once: the next start recovers
from whatever was left, exactly as after a crash.

### 2.6 Health

`supervisor.status()` reports, for each service, its state (`starting`, `running`,
`backing-off`, `stopping`, `stopped`), the steps run, the failures, the last error, and
the service's own counters (plans committed, refused and retried; messages delivered;
webhooks recorded and matched; receipts issued and credits made; checkpoints written).
`GET /healthz` on the inbox's port answers with it as JSON: `200` while every service is
running, and `503` otherwise.

### 2.7 Configuration

New sections of `interlock.toml`, each optional:

```toml
[engine]                              # the engines that execute agents' plans
workers = 4
database = "postgresql://interlock_agent@db/app"   # the stage role (default: database)
chain = "escrow.chain"                # worker n writes escrow-<n>.chain
settle_cost = "0.01"
ledger = "postgresql://owner@db/app"  # AgentGov: claim and settle on PostgreSQL, or a SQLite file
same_transaction = true               # PostgreSQL: settle with the commit
conflict_retries = 16
max_stage_seconds = 10

[receipts]
log = "receipts.jsonl"
log_id = "interlock-receipts"
key = "receipts.key"                  # the receipt log's Ed25519 key

[settler]
database = "postgresql://interlock_settle@db/app"  # a settler role
every_seconds = 5

[daemon]
relay_workers = 2
match_every_seconds = 2
vacuum_every_seconds = 300            # 0: no vacuum
drain_timeout_seconds = 30
```

`[vacuum]` gains `database` (the installer) and `key` (the operator key the daemon signs
its vacuums with, registered in `[operators.keys]` like any operator's).

### 2.8 `interlock daemon`

```bash
interlock daemon --config interlock.toml                  # relays, inbox, settler, vacuum
interlock daemon --config interlock.toml --app app:build  # and the application's agents
```

`--app module:callable` names a function taking the configuration and returning an
`Application`: the checkers the engines adjudicate with, and the agents. Without it the
daemon runs the services that need no engine: the relays, the inbox and the vacuum, and the
settler when `[receipts]` is configured.

---

## 3. The soak

`scripts/live_stress_test.py` (the earlier live-model gauntlet moves to
`scripts/live_gauntlet.py` unchanged):

```bash
uv run python scripts/live_stress_test.py --docker --minutes 5
uv run python scripts/live_stress_test.py --dsn postgresql://admin@localhost:5432/postgres
```

### 3.1 Topology

- **PostgreSQL**: a `postgres:16` container started for the run (`--docker`), or a fresh
  database created on a server given by DSN (`--dsn`). Interlock is installed with a
  stage, relay, inbox, settler and audit role. AgentGov's ledger lives in the same
  database: claim and settle.
- **The daemon**: one `InterlockSupervisor` with every service. Its window spans,
  retention and vacuum interval are scaled down to seconds, so the vacuum works through
  history many times in one run.
- **A fake payment API**: HTTP, speaking Stripe's shape. `POST /v1/payment_intents` and
  `POST /v1/refunds` honour `Idempotency-Key`, and replay the same object on a retry.
- **Vendor webhooks**: a thread sends each object's events, signed as Stripe signs them, to
  the daemon's inbox.

### 3.2 The workload

- **Agents** (`A` of them, each its own AgentGov scope, each `C` plans in flight), for the
  whole run:
  - *checkout*: insert an order and enqueue a `payment_intents.create` for its amount,
    carrying the refund that undoes it. `CrossEffectAgreement` holds the amount to the row;
    a rate window holds each agent's charged amount within a span, and another each
    tenant's plans.
  - *reconcile*: consume a pending fact, and write what it says to the order:
    `succeeded` or `requires_payment_method`, or the refund's status. `FactAgreement`
    holds each write to the fact.
  - *misbehave*, occasionally: a payload amount other than the row's, a tenant other than
    the plan's, a write no fact says. Each must be refused.
- **An operator**, every few seconds, compensates a recent paid order, as a signed operator
  action. Its refund is delivered, the webhook comes back, the agent records it, and the
  settler credits the charge back.
- **Faults in the payment API**: 500s (an unknown outcome, redelivered under the same key),
  429s, latency spikes past the relay's timeout, and duplicate calls.
- **Faults in the webhooks**: duplicates (a vendor's retry), webhooks sent before the
  relay has recorded the delivery, webhooks sent after the matching window, noise about
  objects Interlock never created, and forgeries (another secret, a stale timestamp,
  a rewritten body).

### 3.3 What is proven, and how

| Claim | Measured by |
|---|---|
| No deadlock occurs | `pg_stat_database.deadlocks` does not move, and no error anywhere says `deadlock detected` |
| Lock waits resolve | every conflict was retried to an outcome; no session waits on a lock past its stage's `lock_timeout` (sampled from `pg_stat_activity` throughout); the run ends on time, every submitted plan answered |
| Rate windows hold exactly | for every key of every window, at the commit instant of every row of its history, the history within one span sums to no more than the limit. Window history is sampled before each vacuum and again at the end, so rows the vacuum prunes are checked too |
| The ledger balances | AgentGov's `verify_integrity()` (the hash chain, and conservation: balances, holds, spend and reversals sum to funding). Per scope, spend equals what the escrow chains say was charged (settle costs, and request costs of committed plans). Credits equal the settled compensations. No hold is left open |
| Exactly once | every idempotency key the fake API saw created one object; every delivered request has one receipt; every committed stage one settlement; every fact was consumed at most once |
| No forgery is accepted | every forged webhook was answered `401` or `400`, and no recorded event carries its id |
| The vacuum compacts as it goes | checkpoints are written throughout the run; messages, window rows and inbox events are pruned; the live outbox stays bounded while the total committed grows |
| Everything verifies after | `verify_delivery_log`, `verify_attestations`, `verify_operators` (with AgentGov's anchors), `verify_settlements`, `verify_inbox`, every escrow chain's `verify()`, and the receipt log |
| Shutdown is graceful | the daemon stops on `SIGTERM`-equivalent `stop()` within the drain timeout, with no plan half-staged, and a second daemon resumes with nothing to recover |

The script prints a report and exits non-zero on any failed claim. `--minutes`, `--agents`,
`--concurrency` and `--seed` scale and reproduce it.

---

## 4. The specification

`docs/ESCROW_SPEC.md` keeps its contract (the state machine, the effect model, the
requirements by number) and gets two new sections:

- **Architecture**: the components as built (the engine and substrates, the transactional
  outbox and relays, the operator log, settlement, rate windows, the inbox, compaction, the
  supervisor), their data flows, their trust boundaries, and their roles.
- **Conformance**: a table of every requirement, what implements it and how it is proven,
  with what is partial or unimplemented, stated plainly.

---

## 5. Proofs

- `tests/test_runtime.py`: the runtime over both substrates, with windows, facts and the
  claim-and-settle anchor, and `from_config`.
- `tests/test_supervisor.py`, on both stores: plans executed concurrently; conflicts
  retried; every service running and reporting; a failing service restarted with backoff;
  shutdown ordered, every step bounded, nothing cut in half; signals; `/healthz`.
- `tests/test_daemon_cli.py`: `interlock daemon`, with and without `--app`.
- `tests/test_soak.py`: the soak itself, scaled down to seconds, in the PostgreSQL suite.
- The soak, run for minutes against a live PostgreSQL, with its report recorded in §8.
- A mutation pass over the supervisor's mechanisms.

## 6. Sequence

1. This document.
2. The runtime (§1).
3. The supervisor, its configuration and `interlock daemon` (§2).
4. The soak (§3), run until it passes.
5. The specification (§4).
6. Documentation, the mutation pass, final verification.

## 7. Limits

- **One process.** The daemon is one process. Run several for throughput or availability:
  relays, the inbox and the vacuum already share work safely across processes. Engines in
  several processes each need their own chain files and receipt log.
- **Agents in-process.** Agents run inside the daemon, as code the application supplies.
  There is no network API for submitting plans: an API would need authentication that
  Interlock does not have a design for yet.
- **A blocking call cannot be interrupted.** A stage stuck in the database is bounded by
  its `statement_timeout`, a delivery by the relay's timeout, a vacuum by nothing but its
  own size. Shutdown waits for them, up to the drain timeout, then closes anyway.

## 8. As built

Where the implementation settles what the design left open; filled in step by step.
