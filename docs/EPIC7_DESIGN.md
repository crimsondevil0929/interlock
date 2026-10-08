# Epic 7: observability, trace context and metrics

**Status: built** on `feat/epic7-observability`. §9 records where the build departs from
this design, what it measured, and what the soak proved. Builds on
[`EPIC6_DESIGN.md`](EPIC6_DESIGN.md): the daemon runs every part of Interlock in one
process, and this epic makes what it does visible from outside it. Four parts:

1. **Trace context** (§1). A W3C `traceparent` rides with a plan into the outbox, out
   through the relay's HTTP request, and back through the webhook the vendor sends, onto
   the fact the agent then consumes, so one trace spans the agent, the outbox, the vendor
   and the asynchronous reply.
2. **Metrics** (§2). The supervisor exports Prometheus metrics on a listener of its own:
   the outbox's depth by state, each rate window's saturation, settlement lag, the
   engines' saturation and the waits for locks and connections.
3. **The pool** (§3). The second connection a stage opens to read the rate windows fails
   fast, with a retryable error, when a connection pool such as PgBouncer has none to give,
   instead of waiting while the stage holds its locks. A stage's sessions leave nothing
   behind in a pooled server connection.
4. **CI** (§4). The test matrix runs the Python each job is named for.

Decided before any code:

- **Trace context is outside every hash.** A plan's hash, a request's, the outbox's
  genesis and delivery-log links, a relay's ARC1 attestation, an action or delivery
  receipt, an inbound event's statement and a fact's: none covers trace context, whether
  it is there or not. The same plan, traced or not, has the same hash, and every hash
  written before this epic verifies unchanged. Trace context is kept in tables of its own,
  beside the rows it describes, never in them.
- **Trace context is advisory.** It is not signed, and nothing Interlock decides reads it:
  no checker, no verifier, no settlement. A forged or missing one misleads a trace view,
  and nothing else. That is what allows it outside the hashes.
- **Interlock propagates; it does not export spans.** It carries the context the agent
  gives it and records what a vendor sends back. An agent instrumented with OpenTelemetry
  (or anything W3C) sees its plan, the vendor's work and the reply in one trace. Exporting
  Interlock's own spans would need an exporter and a collector to send to; §8 leaves it
  for later.
- **No new dependency.** The Prometheus text format is small and fixed; Interlock writes
  it. The package keeps `interlock-agentgov` as its only requirement.
- **Measure in the parts, publish in the supervisor.** The engines, relay, inbox, settler
  and vacuum report what they measured, through an optional observer that does nothing by
  default; the supervisor owns the registry and the endpoint. Nothing Interlock does
  depends on whether anyone scrapes it.

## 1. Trace context

### 1.1 What carries it

- **`EffectPlan.traceparent`**: `str | None`, a W3C `traceparent` of version `00`:
  `00-<trace-id: 32 hex>-<parent-id: 16 hex>-<flags: 2 hex>`, lowercase, neither id all
  zeros. `PlanBuilder(..., traceparent=...)` and `AgentContext.plan(..., traceparent=...)`
  set it; the builder and the engine's admission refuse a malformed one (`PlanError`),
  so a bad value fails where it was written, never in a header.
- **`InboundFact.traceparent`**: the context a fact continues (§1.4), for the plan that
  consumes it.
- **`interlock.trace`**: `parse_traceparent` (lenient, for what arrives over HTTP),
  `require_traceparent` (strict, for what an agent writes), `new_traceparent()` and
  `child_traceparent(parent)` (same trace, a fresh random span id), and
  `trace_id(traceparent)`. Enough for an agent with no tracing library to start and
  continue traces; an agent with one passes its own context.
- **A repair proposal** carries the plan's context: it is the same work, tried again.

### 1.2 Outside every hash

`EffectPlan.content_hash()` lists the fields it covers; `traceparent` is not one of them,
and neither is it in `OutboundRequest.content_hash()`, the outbox's genesis hash, the
delivery log's event hash, `attested_outcome` (the relay's ARC1 statement), the receipts
(which carry the plan's hash), the inbound event statement or the fact statement. The
proofs (§6) pin each with a golden vector computed before this epic: the hash of a fixed
plan, request, delivery-log row, attestation, event and fact, with and without trace
context, is the one it always was.

### 1.3 The outbound path

1. **The stage.** A substrate learns the plan's context when it opens the stage, and as it
   commits writes one row per outbound request the stage enqueued, into
   `outbox_traces (message_id, traceparent)`, in the stage's transaction: the rows commit
   with the stage, or not at all. On PostgreSQL through `interlock.outbox_trace(token,
   traceparent)`, gated by the stage's token like `enqueue`; on SQLite in the same
   transaction. A plan with no context, or no requests, writes nothing.
2. **The relay.** After each claim it reads the context of the messages it leased, one
   query per batch; `Lease.traceparent` and then `Delivery.traceparent` carry it. Every
   adapter that makes an HTTP call (`HttpAdapter`, Stripe's, SendGrid's) sends it as the
   `traceparent` header. The value is the plan's, unchanged: the call is a child of the
   agent's span, which is in the agent's trace, where a span of the relay's own would be
   missing (§8). Retries carry the same value; `X-Interlock-Attempt` tells them apart.
3. **Compensations.** An operator's compensation is a new request for the same work: it
   inherits the context of the message it compensates, so a refund is in the charge's
   trace.

### 1.4 The inbound path

1. **The webhook.** The inbox reads `traceparent` from the request's headers, after the
   signature verifies. W3C's rules for a receiver apply: surrounding whitespace is
   trimmed, a version above `00` is read for its `00` fields, and anything malformed is
   ignored, never refused. A valid one is stored beside the event,
   `inbox_traces (source, seq, traceparent)`, in the transaction that records it; a
   duplicate delivery of the event keeps the first.
2. **The fact.** A fact binds an event to the delivered request it names, so it has two
   candidate contexts: the delivery's (its plan's) and the webhook's. It continues the
   delivery's trace: the webhook's context is taken when it has the same trace id (the
   vendor propagated ours, and its span is the more precise parent), and otherwise the
   delivery's. With no delivery context, the webhook's, if any. A vendor's unrelated trace
   never detaches the reply from the agent's.
3. **The agent.** `ctx.facts()` returns facts with `traceparent` set; a plan built to
   consume one passes `child_traceparent(fact.traceparent)`, or its tracing library's
   context, and the loop closes in one trace.

### 1.5 Storage, upgrade and pruning

| | SQLite | PostgreSQL |
|---|---|---|
| Outbound | `_interlock_outbox_traces` | `interlock.outbox_traces` |
| Inbound | `_interlock_inbox_traces` | `interlock.inbox_traces` |
| Written by | the stage; an operator's compensation | `interlock.outbox_trace` (stage), `interlock.outbox_compensate`, `interlock.inbox_trace` (inbox) |
| Read by | the relay, the agent's facts | relay, settler, inbox and audit roles (`SELECT`); stage roles through `interlock.inbox_pending_traces` |

Each row references its parent (the outbox row, the inbox event) `ON DELETE CASCADE`:
the vacuum prunes trace context with what it describes, and nothing else changes in
compaction. A `CHECK` holds every stored value to the format. The SQLite outbox becomes
version 6 and PostgreSQL's installation version 6; both upgrade in place with
`interlock install`, by adding tables and functions. No existing table, column, function
signature or trigger changes, except `outbox_compensate`'s body. The agent's SQL can no
more write these tables than the outbox's.

### 1.6 Validation

The header a relay sends is built from a stored value that matched
`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$` twice, at admission and by the column's
`CHECK`: it cannot carry a line break or anything else into a request. What a webhook
sends is parsed, never echoed. `tracestate` is not propagated (§8).

## 2. Metrics

### 2.1 The registry

`interlock.telemetry.Metrics`: counters, gauges and histograms, each with a fixed set of
label names, declared once in a catalog (§2.3), so a typo fails a test, not a dashboard.
Thread-safe under one lock per metric; an increment or an observation is a dictionary
update under a lock, a few hundred nanoseconds. `render()` writes the Prometheus text
format, version 0.0.4: `# HELP`, `# TYPE`, samples, histograms as cumulative `_bucket`,
`_sum` and `_count`. `NullMetrics` accepts everything and keeps nothing: the default
for every part run outside the supervisor.

### 2.2 The endpoint

`MetricsService`: an HTTP listener of its own, `GET /metrics` and `GET /healthz`, bound to
`[metrics] listen` (`127.0.0.1:9464` in the examples; off unless configured, or
`interlock daemon --metrics HOST:PORT`). Not the inbox's port: that one faces vendors on
the internet, and the metrics describe the system to whoever can read them. The service
also samples the database every `[metrics] every_seconds` (default 15), §2.4. A scrape
reads the registry and touches no database, so scraping often costs nothing.

### 2.3 What is measured

| Metric | Type | Labels | From |
|---|---|---|---|
| `interlock_build_info` | gauge | `version` | the supervisor |
| `interlock_service_up` | gauge | `service` | each part: 1 while running |
| `interlock_service_steps_total`, `_failures_total` | counter | `service` | each part's loop |
| `interlock_service_step_seconds` | histogram | `service` | each step's duration |
| `interlock_service_busy` | gauge | `service` | 1 while a step runs |
| `interlock_engine_workers`, `_workers_busy` | gauge | | the engine pool |
| `interlock_engine_queue_depth` | gauge | | plans waiting for a worker |
| `interlock_engine_queue_wait_seconds` | histogram | | submission to a worker |
| `interlock_plans_total` | counter | `outcome` | committed, refused, failed, unsettled, cancelled |
| `interlock_plan_seconds` | histogram | `outcome` | a plan's staging, retries included |
| `interlock_plan_conflicts_total` | counter | `cause` | races lost and retried: `lock`, `pool` |
| `interlock_window_lock_wait_seconds` | histogram | | PostgreSQL: the wait for window keys' locks |
| `interlock_pool_wait_seconds` | histogram | | PostgreSQL: acquiring the windows' connection |
| `interlock_pool_exhausted_total` | counter | | PostgreSQL: acquisitions that ran out of time |
| `interlock_wait_max_seconds` | gauge | `wait` | the longest `window_lock` or `pool` wait in the last minute |
| `interlock_deliveries_total` | counter | `sink`, `outcome` | the relay: delivered, retryable, permanent, unknown, held, deferred, refused |
| `interlock_delivery_seconds` | histogram | `sink` | the relay's HTTP call |
| `interlock_outbox_messages` | gauge | `state` | sampled: pending, leased, held, delivered, dead, cancelled |
| `interlock_outbox_oldest_due_seconds` | gauge | | sampled: the oldest message still due, since enqueued |
| `interlock_window_value`, `_limit`, `_saturation` | gauge | `window` | sampled: the fullest key's total, the limit, their ratio |
| `interlock_window_keys` | gauge | `window` | sampled: keys with anything in the span |
| `interlock_window_refusals_total` | counter | `window` | plans a window refused |
| `interlock_settlement_lag_seconds` | histogram | | delivery to its delivery receipt |
| `interlock_settlement_backlog`, `_oldest_seconds` | gauge | | sampled: delivered and not settled |
| `interlock_receipts_issued_total`, `interlock_credits_total` | counter | | the settler |
| `interlock_webhooks_total` | counter | `source`, `status` | the inbox's answers |
| `interlock_webhook_traceparent_total` | counter | `source`, `result` | valid, invalid, absent |
| `interlock_inbox_facts_pending`, `_events_unmatched` | gauge | | sampled |
| `interlock_vacuum_runs_total` | counter | `outcome` | applied, nothing, refused, rejected, abandoned, busy |
| `interlock_vacuum_pruned_total` | counter | `kind` | messages, window rows, inbound events |
| `interlock_metrics_sampled_at_seconds` | gauge | | the last good sample, epoch seconds: staleness |
| `interlock_metrics_sample_errors_total` | counter | | samples that failed |

Every label is drawn from configuration or a closed set: service, sink, window and source
names, states and outcomes. No tenant, scope, plan or key is ever a label, so the number
of series is fixed by the configuration, not by the traffic.

### 2.4 Sampled from the database

What only the database knows is read by `MetricsService` on a connection of its own,
read-only, in one `REPEATABLE READ READ ONLY` transaction per sample: the outbox's states,
the oldest due message, settlement's backlog, the inbox's pending facts and unmatched
events, and, for each configured window, the fullest key's total within its span. On
PostgreSQL this needs a role that may read the window ledger and the outbox's and inbox's
tables: an `audit_roles` role, `[metrics] database` or `INTERLOCK_METRICS_DATABASE`.
Without one, the sampled gauges are absent and everything measured in the process is
still exported. On SQLite the file, opened read-only. A sample that fails is counted and
retried at the next interval; the gauges keep their last values, and
`interlock_metrics_sampled_at_seconds` says how old those are.

### 2.5 Overhead

On the hot paths a plan costs the engine pool two clock readings and three observations;
a delivery, one clock reading pair and two. The database is read only by the sampler, on
its own connection, every 15 seconds. The proof (§6) measures plans per second through an
engine pool with the registry and with `NullMetrics`, interleaved, and the soak runs with
metrics on throughout.

## 3. The pool

### 3.1 The deadlock

A stage on PostgreSQL holds one connection, in `REPEATABLE READ`, for its whole life; its
snapshot cannot see what other plans committed to a rate window after it began, so
`measure_windows` reads the window ledger on a second connection, in `READ COMMITTED`. In
front of PgBouncer in transaction mode, every open stage holds a server connection and asks
for a second. When the pool has as many server connections as there are open stages, every
stage waits for a connection that only another stage's commit would free: nothing moves
until PgBouncer's `query_wait_timeout` (120 seconds by default) fails them all, the
stages' row locks held meanwhile.

### 3.2 Bounded acquisition

The windows' connection must be had within `pool_timeout_seconds` (`[engine]`, default
the lock timeout, 2 seconds), connecting and the first statement included: the first
statement is where a transaction-mode pooler queues a client. A watchdog bounds it: when
the time runs out it cancels the statement (`PQcancel`, which a pooler answers for a
queued client), and if the statement is still blocked a second later, shuts the socket
down, so the wait ends whatever the pooler does. Running out of time, or a refusal for want
of connections (`53300`, a pooler's `no more connections allowed`), raises
`PoolExhaustedError`, a `StageConflictError`: the stage is aborted, its locks and its
connection released, and the engine pool stages the plan again after a jittered backoff,
as it does a lost race. The error names the pool, not the plan. Facts read for an agent
take the same bounded path.

### 3.3 Pooler-safe sessions

The windows' read becomes one transaction, `BEGIN ISOLATION LEVEL READ COMMITTED READ
ONLY` with `SET LOCAL` timeouts, where it was autocommit statements after `SET SESSION`.
In transaction mode those statements could run on different server connections, the
`SET`s on one and the read on another, and a session setting stayed behind in a server
connection for the next client to inherit. The substrate's connections no longer prepare
statements on the server (`prepare_threshold=None`): a transaction-mode pooler without
prepared-statement support answers a reused prepared statement with an error.

### 3.4 How it is proven

A fake server that accepts a connection and never answers a query, standing in for a
pooler's queue, shows the bound holds, whichever of cancel or shutdown ends the wait. A
role's `CONNECTION LIMIT` makes PostgreSQL refuse the windows' connection, which must raise
`PoolExhaustedError` and leave nothing held. And a real PgBouncer in transaction mode, with
one server connection, shows the old deadlock (a windowed stage waits on itself) is now a
`PoolExhaustedError` within the bound, and, with two server connections and plans
from several workers, that every plan still commits.

## 4. CI

`.python-version` pins 3.11, and `uv run` follows it, so every job named py3.12 tested 3.11.
Each job now sets `UV_PYTHON` to its matrix version, which `uv sync` and `uv run` both
follow, and the suite is run on 3.12 here first.

## 5. The soak

`scripts/live_stress_test.py` grows a tenth claim, **trace context survives**, and runs
with metrics on:

- Every checkout plan carries a fresh trace; the fake payment API records the
  `traceparent` of every call; the fake vendor echoes it on some of its webhooks, as a
  propagating vendor would, and not on the rest, as Stripe does not.
- The claim holds when every call the payment API saw carried its plan's trace id, every
  refund its charge's, every fact the agents read the trace id of the plan whose delivery
  it is bound to (the webhook's context when that propagated ours), and every reconcile
  plan built from a fact the trace id of the checkout it reconciles: agent, outbox, relay,
  vendor, webhook, fact and agent again, one trace each.
- The existing claim that everything verifies after stands over traced data: no hash
  moved.
- The soak scrapes `/metrics` throughout, and checks what it scraped against what it
  knows: the plans counted, the outbox's depth when the load stops, window saturation never
  above 1, and one settlement-lag observation per delivery receipt.

## 6. Proofs

- Golden vectors (§1.2): each hash family, traced and not, equal to its pre-epic value.
- Trace context through both stores: stage, relay header (every adapter), compensation,
  webhook, fact resolution (all four cases), vacuum pruning, an upgrade from version 5.
- Validation: malformed contexts refused at admission, ignored on webhooks, counted.
- The registry's text format against Prometheus's grammar; every catalogued metric
  exported by the daemon; cardinality bounded.
- Overhead (§2.5); the pool (§3.4); CI on 3.12 (§4); the soak (§5).
- The mutation pass: each mechanism removed in turn, and a test must fail.

## 7. Sequence

1. This design.
2. CI: the matrix's Python.
3. Trace context: plans, both stores, the relay, the inbox, facts; the upgrade.
4. The pool: bounded acquisition, pooler-safe sessions.
5. Metrics: the registry, the endpoint, instrumentation, sampling, configuration.
6. The soak: trace context and metrics under load.
7. The documents, the mutation pass and the whole suite.

## 8. Limits

- **No span export.** Interlock propagates context and records it; it sends no spans to a
  collector, so the relay's call and the inbox's receipt are not spans of their own. An
  OTLP exporter can follow; the context it needs is already everywhere.
- **No `tracestate`**, which W3C asks a propagator to carry beside `traceparent`. Its
  grammar is larger, and nothing here reads vendor state.
- **No exemplars**, which link a metric to a trace: they need the OpenMetrics format.
- **The endpoint is not authenticated.** Bind it to a private address; anything that can
  reach it can read the system's shape, never its data.
- **Sampled gauges need a role** on PostgreSQL that may read the window ledger (§2.4).
- **Other parts' connections** (relays', inbox's, settler's) keep their defaults: they
  hold no locks while they wait, so a pool's queue only delays them.

## 9. As built

Where the build departs from the design above, or measured what it could only predict.

### 9.1 Trace context (§1)

- **Pinned, traced or not.** `tests/test_trace.py` holds golden vectors computed on the
  code before this epic: a plan's hash, a request's, the outbox genesis, a delivery-log
  event, a relay's ARC1 attestation, an inbound event, its statement and a fact's. Each is
  recomputed with no context and with two different ones, and none moves.
- **An outbox not yet upgraded.** PostgreSQL's substrate refuses to stage on an
  installation older than version 6, as it has at every version: `interlock install`
  first. SQLite's commits a traced plan with its context dropped, and logs a warning:
  nothing the plan does depends on its trace.
- **The relay reads context once per claim**, for the batch it leased; a relay of
  version 5 on an upgraded database reads none and sends none, and is otherwise unchanged.

### 9.2 The pool (§3), corrected

- **The deadlock ended sooner, and worse, than §3.1 says.** Measured against PgBouncer 1.26
  in transaction mode, on the code before step 4: a stage left no connection held its
  locks for 10.1 seconds and failed with `SubstrateUnavailableError`, which nothing
  retries. Its own `idle_in_transaction_session_timeout` (`max_stage_seconds`, 10 by
  default) had PostgreSQL end its transaction while it waited; with a `max_stage_seconds`
  above `query_wait_timeout`, the pooler's timeout ends the wait first, with the same
  error. The same scenario after: `PoolExhaustedError` in 2.3 seconds, and the plan
  staged again.
- **The session leak was real.** The old windows' read ran `SET statement_timeout` as an
  autocommit statement: behind the same PgBouncer it stayed on a pooled server
  connection, `10s`, for whichever client was served next. After: every server connection
  as the pool found it.
- **PgBouncer does not answer the cancel (§3.2).** It accepts a cancel request for a
  client it is queueing and leaves the client queued; only the socket's shutdown ends the
  wait. The grace between the two is a quarter second, not a second, so an acquisition
  waits at most the pool timeout and a quarter second. The fake pooler in
  `tests/fakepg.py` is tested both ways, answering the cancel and ignoring it.
- **Facts are read unbounded.** §3.2 says facts read for an agent take the bounded path.
  They hold no locks while they wait, so a full pool only delays them; bounding them
  would only turn a delay into an error for the agent to retry. They wait their turn.
- **Statements go unnamed.** With `prepare_threshold=None` nothing is prepared on the
  server, but psycopg then sends a statement without parameters by the simple protocol,
  which runs `UPDATE ...; COMMIT` whole. An agent's statement is sent with `binary=True`,
  which keeps it on the extended protocol (an unnamed statement), and the server still
  refuses a string of two.
- **Sizing.** With the stage role's pool at least one larger than `[engine] workers`, a
  windows' read waits at most for other windows' reads, each a few milliseconds, never for
  a commit: one worker on two server connections staged every plan without a retry. A
  pool no larger than the workers is slow, never stuck: two workers on two connections
  lost races to the pool, were staged again, and committed every plan. CI runs these
  tests behind a PgBouncer pinned by digest.

### 9.3 Metrics (§2)

- **Overhead (§2.5).** `scripts/metrics_overhead.py`: the registry's calls for one plan
  cost 1.8 µs, and PostgreSQL's two waits 2.8 µs more, timed alone; 0.17% and 0.25% of a
  plan on this machine. Through the supervisor, a real SQLite stage per plan, 15
  alternating rounds of 1,000 plans each way: −0.9% in the median of the paired rounds,
  where one round differs from the next by ±25%. Within the noise.
- **The peak is kept to the second.** `interlock_wait_max_seconds` keeps the largest wait
  of each second, at most 61 per series, where the first build kept every observation for
  a minute: 60,000 of them per series at 1,000 plans a second.
- **Trace context is counted for webhooks taken.** `interlock_webhook_traceparent_total`
  counts the webhooks the inbox answered 200, by what they carried; an unverified
  request's headers are anyone's, and would let anyone move the count.
- **An unknown source is `_unknown`.** The path names the source, and the path is the
  sender's: a label taken from it would let a sender add series.

### 9.4 The soak (§5)

The vendor sends, on each object's webhooks, the context of the call that made the
object, continued (`echo`, 45%); a trace of its own (`foreign`, 15%); a malformed one
(`invalid`, 5%); or none, as Stripe does (35%). The claim **trace context survives**
checks every call the payment API saw, every refund against its charge, every fact the
agents consumed against the four cases, every consuming plan, and the trace rows still in
the database; **metrics agree** checks every scrape as Prometheus would read it and the
settled daemon's figures against the run's own counts.

Run for five minutes in a `postgres:16` container (`--docker`: 4 agents with 6 plans in
flight each, 8 engines, 3 relays), on a machine busy with other work, every claim held:

- 3,286 plans; 1,120 calls to the payment API, each carrying one context, its plan's: 994
  charges their checkout's, 126 refunds their charge's.
- 1,120 facts consumed, each continuing its delivery's trace: 519 under the vendor's
  continuation of ours, 152 against a trace of the vendor's own, 45 after a malformed one,
  404 after none; each consuming plan a new span of the same trace.
- 1,120 messages and 1,168 events seen in the database before the vacuum pruned them, each
  beside the right context: 671 of the events kept one, exactly the webhooks that carried
  a valid one.
- 309 scrapes, every one well formed, all 39 families exported with data, no counter ever
  falling, no window above its limit (both reached it), all 8 engines busy at the peak; the
  settled daemon's figures what the run counted: 2,925 plans committed, 348 refused, 13
  failed (fact replays refused at admission); 1,339 webhooks taken, 76 forgeries refused;
  1,120 delivering calls, 1,120 receipts, 1,120 settlement lags; the database sampled as
  the audit role every second without an error.

`tests/test_soak.py` runs the same for half a minute in CI's PostgreSQL job.

### 9.5 The mutation pass

Each of 56 mechanisms was removed in turn (trace context 24, the pool 8, the metrics 24),
and a test had to fail. Every target passed on the unmutated code first, and a mutation
counted as killed only when a test failed or hung, never when pytest could not run: the
pass's first run counted an interpreter outside the virtual environment, where nothing
imports, as 56 kills.

- **Found before the pass, from its plan:** nothing fed `parse_traceparent` an all-zero
  trace or span id, and nothing called `interlock.outbox_trace` with a forged token from
  an agent's statement. Both tests added.
- **Found by the pass:** a repair proposal the engine's own search builds dropped nothing,
  but nothing checked it kept the plan's context; only `subplan` was tested. Test
  extended, mutation killed.
- **Equivalent:** `SET` for `SET LOCAL` in the windows' read changes nothing, since the
  read's transaction is never committed and closing the connection rolls a `SET` back
  with it. The mutation that matters drops the transaction, as the code before step 4
  did, and the test behind PgBouncer kills it: the `SET` commits on its own and stays on
  the server connection.

56 of 56 killed.
