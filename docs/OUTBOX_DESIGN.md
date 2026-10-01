# Transactional outbox: design (Epic 2)

**Status: design. No implementation.** This document turns the outbox sketch in
[`ESCROW_SPEC.md` §4.4](ESCROW_SPEC.md#44-non-transactional-sinks) (requirements
E4-1 to E4-5) into an architecture, a schema and an implementation plan. Where
the two disagree, this document is newer; §4.4 should be updated to point here
when Phase 1 lands.

---

## 0. Summary

An agent that can only change rows is half an agent. The other half calls
things: Stripe to refund, SendGrid to email, a ticketing API to close a case.
None of those can be staged, measured and rolled back the way a row can. An
email has no shadow.

So Interlock does not try to escrow the call. It escrows the **obligation to
make the call**:

1. The agent proposes an external request as an `ENQUEUE` effect in its plan,
   beside its SQL effects. It holds no API credentials and cannot make the call
   itself.
2. The engine writes the request into an **outbox row inside the stage's own
   transaction**, where it is measured (read back from the database, not trusted
   from the plan) and handed to the checkers with the row diff.
3. The checkers adjudicate the payload as they adjudicate rows: which sink, which
   operation, how much, to whom, for which tenant, whether it agrees with the rows
   it accompanies, and whether it fits the rate and budget limits.
4. The outbox row **commits in the same `COMMIT`** as the effects, the commit
   marker and the settlement claim, or not at all.
5. A separate **relay** process, which alone holds the credentials, delivers
   committed requests at least once, with an idempotency key fixed at plan time,
   and records every attempt.

The guarantee for SQL effects is unchanged: measured, adjudicated, atomic. The
guarantee for external effects is deliberately weaker, and stated as such: the
**request** is measured, adjudicated and made durable exactly when the rest of
the plan is; its **delivery** is at-least-once, recorded, and bounded; what the
external system then does is not measured at all.

### A correction to the brief

The brief says to stage the payload "inside our existing Postgres
`_interlock_commits` transaction". `_interlock_commits` is the **SQLite**
substrate's commit-marker table. On PostgreSQL the marker is the stage's own
`interlock.stages` row, written by `interlock.begin_stage()` in the stage's
transaction. The outbox therefore lives in the `interlock` schema and each row
references `interlock.stages(stage_id)`: an outbox row exists if and only if its
stage committed, for the same reason the marker does. The SQLite design (Phase 6)
uses `_interlock_commits` as the brief says.

---

## 1. Guarantees and non-goals

### What this design guarantees

| ID | Guarantee | Mechanism |
|---|---|---|
| **OB-1** | An outbound request is durable **iff** the plan's database effects are. | Outbox row written in the stage's transaction, FK to the stage marker (§4). |
| **OB-2** | No request is delivered unless it was adjudicated, **as delivered**. | The checkers read the outbox rows back from the stage (§5). The relay sends the stored payload, and checks its hash against the one adjudicated (§7). |
| **OB-3** | The agent never holds sink credentials, and cannot write the outbox except through an admitted plan. | Credentials live only in the relay. The stage role has no privilege on outbox tables. Writes go through a `SECURITY DEFINER` function gated by a per-stage token (§4.3). |
| **OB-4** | Delivery is at-least-once, with one idempotency key per request for every attempt. | Key derived from `(plan_id, effect_id)` at plan time (E4-2). Leases with expiry (§7). |
| **OB-5** | Every delivery attempt is recorded and tamper-evident. | Append-only `outbox_attempts` hash-linked per message (§4.2). Optional ARC1 delivery receipts (§9). |
| **OB-6** | Failure is bounded and escalates to an operator. It is never silently retried forever, and never auto-compensated late. | Max attempts, `not_after` expiry, dead letters, compensation past expiry needs an operator (E4-5, §8). |
| **OB-7** | Nothing is sent before its stage commits. | A row is invisible to the relay until its transaction commits (§7.1). Needs no state flag and has no race. |

### What it does not guarantee

- **Exactly-once external effects.** Impossible in general. A relay can make the
  call and die before recording it. For sinks that honour an idempotency key
  (Stripe does), the duplicate is absorbed there. For sinks that do not (SMTP,
  SendGrid's mail send), a crash in that window can send twice. §7.4 lists the
  windows and §7.5 what each sink supports.
- **Measurement of the external effect.** Interlock measures the request it
  stores. It does not observe what Stripe or SendGrid did with it. The receipt says
  so in `coverage.known_gaps` (§6.2).
- **Rollback of a delivered call.** Only compensation, which is another request,
  adjudicated in its own right (§8).
- **Cross-substrate atomicity.** The outbox lives in the substrate's database. A
  plan still stages one substrate (§2.3 of the spec is unchanged).

---

## 2. Architecture

```
  agent (no credentials)
    │  plan: SQL effects + ENQUEUE effects (sink, operation, payload)
    ▼
  EscrowEngine.admit ── sink registered? operation allowed? payload schema, size,
    │                    compensation present when irreversible (E4-3)?
    ▼
  reserve (claim & settle): hold for settle_cost + Σ sink cost_per_call
    ▼
  ┌────────────────────── stage transaction (REPEATABLE READ) ──────────────────────┐
  │ begin_stage(…, enqueue_token_hash)                                              │
  │ SQL effects ──► capture triggers ──► interlock_capture (row diff)               │
  │ ENQUEUE effects ──► interlock.enqueue(token, …) ──► interlock.outbox rows        │
  │ diff() ──► rows + outbound (read back from interlock.outbox)                    │
  │        ──► outbound_window counts (per-sink lock, counted read-committed)       │
  │ checkers(plan, diff) ──► verdict                                                │
  │ COMMIT_INTENT (chain) ──► settlement claim ──► COMMIT                           │
  └─────────────────────────────────────────────────────────────────────────────────┘
    │  effects + marker + claim + outbox rows: one COMMIT, or none
    ▼
  interlock relay (separate process, own role, holds credentials)
    claim ready rows (FOR UPDATE SKIP LOCKED, lease) ──► breaker / expiry / deps check
    ──► sink adapter (Idempotency-Key) ──► attempt row (append-only, hash-linked)
    ──► delivered │ retry with backoff │ dead letter ──► operator (retry, cancel, compensate)
```

Three processes' worth of roles, and three database roles:

| Role | Who | Privileges on the outbox |
|---|---|---|
| installer / owner | `interlock install` | Owns the tables and functions. |
| stage role | every stage, and therefore every agent statement | `EXECUTE` on `interlock.enqueue` and `interlock.stage_outbox` only. The token gates `enqueue`. |
| relay role (new) | `interlock relay` | `SELECT` on `outbox`; `SELECT, UPDATE` on `outbox_state`; `INSERT` on `outbox_attempts`. No other table. Holds sink credentials outside the database. |

---

## 3. The plan surface: intercepting the request

### 3.1 How the request is "intercepted"

There is no network sniffing. Interception is **structural**: the agent's
process holds no credentials for any sink, so it cannot make the call. The only
path to Stripe is to propose an `ENQUEUE` effect. The agent's tool surface (a
function tool today, the Epic 2 gateway's MCP tool later) turns "refund charge
X" into an `ENQUEUE` effect instead of an HTTP call. Pairing this with an egress
proxy that blocks the agent's host from the sinks' domains is recommended, and
out of scope.

### 3.2 `OutboundRequest`

A new frozen value type in `interlock.types`:

| Field | Type | Meaning |
|---|---|---|
| `sink` | `str` | Operator-registered name (`"stripe"`, `"sendgrid"`), never a URL (§10). |
| `operation` | `str` | A named operation the sink allows (`"refunds.create"`, `"mail.send"`). |
| `payload` | `Mapping[str, JSON]` | The request body, in ARC1's canonical domain: no floats, integers within ±(2^53−1), no NUL. Money as decimal strings (the checkers need exact money, §5). Frozen at construction. |
| `not_after` | `timedelta \| None` | How long after staging the request may still be delivered, at most seven days. `None` takes the sink's default. |
| `compensation` | `OutboundRequest \| None` | The request that undoes this one, when the operation registers an undo (§3.3). |

The tenant the request acts for is the effect's own `Effect.tenant_id`, as for a
statement, not a field of the request; it is checked against rows and payload
(§5.2).

`Effect` gains `request: OutboundRequest | None`. An `ENQUEUE` effect carries a
`request` and an empty `statement`; every other kind carries a statement and no
request. `Effect.__post_init__` enforces this. `PlanBuilder.enqueue(sink=,
operation=, payload=, tenant_id=, compensation=, after=)` builds one.

**The idempotency key** is `outbound_key(plan_id, effect_id)`:
`canonical_hash(["outbound", plan_id, effect_id])`, a canonical-JSON array, so
no two `(plan_id, effect_id)` pairs share a key by concatenation (E4-2). A
retried *plan* (after `StageConflictError`) keeps the same key; the outbox's
`UNIQUE (idempotency_key)` means a plan's request commits at most once, and
executing a committed plan again is refused (`OutboundRequestError`, reason
`duplicate`). A *repair* proposal gets a new `plan_id`, and so a new key,
deliberately, since it is a different request.

**Canonical form.** The payload is hashed with agentgov's ARC1 canonical JSON
(`agentgov.receipts.canonical`), and `payload_hash` enters
`EffectPlan.content_hash()`. The hash the checkers adjudicate, the hash stored
in the row, and the hash the relay verifies before sending are the same value.

### 3.3 Admission (in `EscrowEngine.admit`, before anything is staged)

- The sink is registered, and the operation is in its allowlist.
- The payload validates against the operation's JSON Schema (a registered subset:
  types, required, enums, string patterns, max lengths), and is under the sink's
  `max_payload_bytes`.
- No field is named like a credential (`api_key`, `authorization`, `secret`,
  `password`, `token`): credentials come from the relay, and a payload that
  carries one is an agent trying to choose its own (§10).
- Every operation either names the operation that undoes it, in which case the
  request must carry that compensation, itself an `OutboundRequest` validated
  the same way, or is declared `"none-possible"` by the operator, in which case
  it may not carry one (E4-3).
- `depends_on` may name SQL effects and other `ENQUEUE` effects. The relay
  honours the order between requests (§7.3).

### 3.4 The sink registry

Operator configuration, in the same TOML `interlock install` already reads:

```toml
[[sinks]]
name = "stripe"
cost_per_call = "0.0005"          # settled through AgentGov with the plan (§5.4)
default_not_after = "15m"
max_payload_bytes = 16384
idempotency = "header"            # "header" | "none" (§7.5)
rate_limits = [{ window = "60s", max = 100, per = "tenant" }]

  [[sinks.operations]]
  name = "refunds.create"
  reversible = false
  schema = "schemas/stripe.refunds.create.json"
  compensation = "none-possible"  # or the name of the operation that undoes it
```

`interlock install` mirrors the registry's non-secret parts into
`interlock.sinks` (§4.1), so the database can refuse an unregistered sink by
foreign key, and the relay and `reconcile-effects` read the same definition.
**Endpoints and credentials are relay configuration only**, never in this file
or the database.

---

## 4. Schema (PostgreSQL)

All new objects live in the `interlock` schema, are owned by the installer, and
are created by `interlock install` (bumping `INSTALL_VERSION` to `"2"`).
`_verify_installation` checks them at every stage, as it checks the capture
triggers today.

### 4.1 Tables

```sql
-- The registry, mirrored from configuration. Non-secret.
CREATE TABLE interlock.sinks (
    name            text PRIMARY KEY,
    operations      text[] NOT NULL,
    cost_per_call   text NOT NULL,             -- decimal string, as AgentGov stores money
    idempotency     text NOT NULL CHECK (idempotency IN ('header', 'none')),
    config_hash     text NOT NULL              -- sha256 of the canonical sink config
);

-- The obligation. Immutable once written: the request the checkers adjudicated.
CREATE TABLE interlock.outbox (
    message_id      uuid PRIMARY KEY,
    stage_id        uuid NOT NULL REFERENCES interlock.stages (stage_id),
    plan_id         text NOT NULL,
    effect_id       text NOT NULL,
    seq             integer NOT NULL,          -- topological position in the plan
    depends_on      text[] NOT NULL DEFAULT '{}',  -- effect_ids, in this stage, delivered first
    sink            text NOT NULL REFERENCES interlock.sinks (name),
    operation       text NOT NULL,
    tenant_id       text,
    payload         jsonb NOT NULL,
    payload_hash    text NOT NULL,             -- canonical-JSON sha256, as in the plan
    idempotency_key text NOT NULL UNIQUE,
    compensation    jsonb,                     -- the serialized undo (E4-3), if any
    not_after       timestamptz NOT NULL,
    enqueued_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (stage_id, effect_id)
);

-- Delivery state. The only mutable table, written by the relay alone.
CREATE TABLE interlock.outbox_state (
    message_id      uuid PRIMARY KEY REFERENCES interlock.outbox (message_id),
    state           text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'leased', 'held', 'delivered', 'dead', 'cancelled')),
    attempts        integer NOT NULL DEFAULT 0,
    lease_owner     text,
    lease_expires   timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason          text                       -- why held / dead / cancelled
);
CREATE INDEX outbox_ready ON interlock.outbox_state (next_attempt_at)
    WHERE state IN ('pending', 'leased');

-- Every attempt, append-only, hash-linked per message (OB-5).
CREATE TABLE interlock.outbox_attempts (
    message_id      uuid NOT NULL REFERENCES interlock.outbox (message_id),
    attempt         integer NOT NULL,
    relay_id        text NOT NULL,
    started_at      timestamptz NOT NULL,
    finished_at     timestamptz,
    outcome         text NOT NULL
                    CHECK (outcome IN ('delivered', 'retryable', 'permanent', 'unknown', 'expired', 'held')),
    status_code     integer,
    response_digest text,                      -- sha256 of the response body; the body is not kept
    error           text,                      -- bounded, redacted
    prev_hash       text NOT NULL,             -- attempt 1 links to payload_hash
    attempt_hash    text NOT NULL,             -- sha256(prev_hash || canonical(this row))
    PRIMARY KEY (message_id, attempt)
);
```

**Why three tables.** The request must never change after it was adjudicated,
so `outbox` is append-only, enforced by the same `BEFORE UPDATE OR DELETE OR
TRUNCATE` trigger pattern agentgov's `entries` uses, enabled `ALWAYS`. Delivery
state must change, so it lives apart, in the one table the relay may update. The
attempt log is append-only and hash-linked, so a rewritten delivery history is
detectable (`interlock reconcile-effects` verifies the links, §8.3).

`outbox_state` rows are inserted by `interlock.enqueue` in the stage's
transaction, beside the `outbox` row, so they exist exactly when it does.

### 4.2 Functions

```sql
-- begin_stage gains one argument: the sha256 of a random per-stage token the
-- engine generates and never sends anywhere else. Stored on the stage row.
interlock.begin_stage(p_stage uuid, p_plan text, p_gates jsonb, p_enqueue_hash bytea)

-- Writes one outbox row and its state row, in the stage's transaction.
-- SECURITY DEFINER. Refuses unless:
--   * this transaction opened a stage (interlock.stages keyed by pg_current_xact_id()),
--   * sha256(p_token) equals that stage's enqueue hash,
--   * the sink is registered and the operation in its allowlist,
--   * sha256(p_payload) = p_payload_hash, recomputed server-side over the
--     canonical text exactly as sent (stored as p_payload::jsonb),
--   * the payload is under the sink's size bound.
interlock.enqueue(p_token bytea, p_message uuid, p_effect text, p_seq integer,
                  p_depends text[], p_sink text, p_operation text, p_tenant text,
                  p_payload text, p_payload_hash text, p_idempotency_key text,
                  p_compensation text, p_not_after_seconds integer) RETURNS void
-- Also refused, with SQLSTATE IL004 and a JSON DETAIL naming the reason: a
-- disabled sink. A wrong or absent token is IL002. not_after is measured from
-- the same instant as enqueued_at.

-- This stage's outbox rows, for diff(). SECURITY DEFINER, like stage_capture.
interlock.stage_outbox(p_limit bigint) RETURNS TABLE (...)
```

**Why a token, when `enqueue` checks that a stage is open.** Every agent
statement runs inside the stage, as the stage role. Without the token, an agent
statement `SELECT interlock.enqueue(...)` would write a row the plan never
declared. It would still be measured and adjudicated (the checkers read what is
*in* the outbox), so this is defence in depth, not the only line. The token is
the same construction agentgov's settlement claim uses: the agent never sees
it, and it is bound to one stage.

Server-side canonicalisation of `jsonb` must match agentgov's canonical JSON
byte for byte. `jsonb` normalises key order and whitespace, but not number
formatting, so **payload numbers are decimal strings** (§3.2) and the server
hashes the canonical text the engine sends (`p_payload text`), not the parsed
`jsonb`. The relay re-canonicalises the stored `jsonb` before sending and must
reach the same bytes, which is why numbers are strings. This is Phase 1's main
correctness risk, and it gets a vector test.

### 4.3 What the substrate adds

- `PostgresSubstrate.apply()` for `ENQUEUE` calls `interlock.enqueue` with the
  stage token, instead of executing a statement. It is refused if the stage is
  not the engine's.
- `PostgresSubstrate.diff()` also reads `interlock.stage_outbox()` into
  `EffectDiff.outbound: tuple[OutboundDelta, ...]` (sink, operation, tenant,
  payload, payload_hash, idempotency key, depends_on). Truncation follows
  `max_diff_rows`, as for rows.
- `EffectDiff.content_hash()` covers `outbound`, so `DIFF_COMPUTED` and the
  receipt's `diff_hash` commit to the requests.
- Rate windows (§5.3) are measured here and recorded in the diff.

---

## 5. Adjudication

Checkers stay **pure functions of `(plan, diff)`**: no I/O, no clock, no model.
Everything a rule needs about the world is a measurement the substrate put into
the diff, recorded in the chain, and replayable.

### 5.1 What the checkers see

`diff.outbound` is read back from the database, not copied from the plan. The
difference matters in the same way it does for rows: a future payload field bound
to a staged row (§11, "bound fields") is only known after the stage runs, and the
row the relay will send is the row checked.

### 5.2 Built-in checkers

| Checker | Blocks when |
|---|---|
| `SinkAllowlist(sinks, operations)` | A request names a sink or operation outside the allowlist. Registry admission catches this first; the checker makes the policy per plan scope. |
| `OutboundCount(max_per_plan, per_sink=)` | The plan enqueues more requests than allowed. It is the blast radius for calls. |
| `PayloadAmountCap(sink, operation, path, max, per_tenant=)` | A money field (JSON path, decimal string) exceeds a cap. `Decimal`, never float, as `ColumnValueGuard` is. |
| `RecipientAllowlist(sink, operation, path, domains=)` | An email or webhook recipient falls outside the allowed domains or a tenant's own contacts. |
| `OutboundTenantIsolation()` | A request's `tenant_id`, or a tenant field in its payload, differs from the plan's declared tenants, or from the tenants of the rows it accompanies. |
| `CrossEffectAgreement(sink, operation, path, table, column)` | The request disagrees with the rows it rides with: the Stripe refund amount is not the `refunds.amount` the same plan inserted, or the email quotes a total the `orders` row does not hold. **The flagship.** An injected "refund $5,000" beside a row that says $50 is caught by arithmetic, not judgement. |
| `OutboundRateLimit(sink, window, max, per="tenant")` | Committed requests in the window, plus this plan's, would exceed the limit (§5.3). |

Every checker offers a typed `FeedbackHint`, sanitised as today: feedback names
the plan's own effects and sinks, and never echoes payload values or other
tenants' counts (`interlock.feedback` rules apply unchanged).

### 5.3 Rate limits: a measurement, not a clock

A rate limit needs history, and a pure checker cannot read history. So the
substrate **measures** it and records it: `diff.outbound_window` maps
`(sink, tenant)` to the number of committed requests in each configured window,
counted when the diff is taken.

The count has to be exact under concurrency, and a `REPEATABLE READ` stage
cannot count what committed after its snapshot. That is the same trap Epic 1
hit. So the count is taken the way the governor catches up:

1. Inside the stage transaction, take `pg_advisory_xact_lock` on
   `(outbox, sink, tenant)` for each pair the plan enqueues to, in sorted
   order, so two stages cannot deadlock. Held until the stage commits or rolls
   back.
2. Count on a **separate `READ COMMITTED` connection**, which sees every commit.
   None can land for that pair while the lock is held, so the count is exact.
3. Record the counts in the diff, under `DIFF_COMPUTED`.

The cost: stages enqueuing to the same `(sink, tenant)` serialize from `diff()`
to `COMMIT`, which is milliseconds. Stages that don't use rate-limited sinks
take no lock. Replay reads the recorded counts, so determinism holds.

Delivery-side rate limiting (the sink's own 429s) is a relay concern (§7.2),
not policy.

### 5.4 Budget

Each request's `cost_per_call` joins the plan's settle cost. Claim and settle
already reserves before staging and claims in the commit, so a plan whose scope
cannot pay for its calls is refused before it stages anything, and the claim
that commits with the outbox rows is what pays for them. Cost is charged at
commit, when the obligation is incurred, not at delivery. A dead-lettered
request is refunded by the operator action that cancels it (§8), as an AgentGov
`refund()`, so the ledger shows both.

---

## 6. Commit and evidence

### 6.1 The commit protocol is unchanged

`COMMIT_INTENT` (its note gains `; outbound N`), then the settlement claim, then
`COMMIT`. The outbox rows, their state rows, the effects, the stage marker and
the claim become durable together or not at all. `recover()` needs no change
for the outbox: the rows exist exactly when the marker does, and the relay finds
them without being told.

### 6.2 Receipts

- `effect.row_root` also commits to the outbox rows, as rows of table
  `interlock.outbox`, so one request can be disclosed later with its proof, like
  any row.
- `effect.summary.tables` includes `interlock.outbox`.
- `coverage.known_gaps` gains, when a plan enqueues:
  *"N outbound request(s): delivered at least once by the relay after commit;
  their external effects are not measured."*
- `decision.checkers` lists the outbound checkers with their config hashes, as
  today.

ARC1 needs no format change for this; §9 adds an optional delivery receipt.

---

## 7. The relay

`interlock relay --config interlock.toml` is a separate long-running process
(E4-1). It never runs inside a stage and never opens one. Run as many as you
like: they share work through row locks.

### 7.1 Claiming work

```sql
WITH ready AS (
    SELECT s.message_id
      FROM interlock.outbox_state s
      JOIN interlock.outbox o USING (message_id)
     WHERE s.next_attempt_at <= clock_timestamp()
       AND (s.state = 'pending'
            OR (s.state = 'leased' AND s.lease_expires < clock_timestamp()))
       AND NOT EXISTS (                       -- dependencies delivered first (§7.3)
             SELECT 1 FROM interlock.outbox dep
               JOIN interlock.outbox_state d USING (message_id)
              WHERE dep.stage_id = o.stage_id AND dep.effect_id = ANY (o.depends_on)
                AND d.state <> 'delivered')
     ORDER BY o.enqueued_at, o.seq
     LIMIT $batch
       FOR UPDATE OF s SKIP LOCKED
)
UPDATE interlock.outbox_state s
   SET state = 'leased', lease_owner = $relay_id,
       lease_expires = clock_timestamp() + $lease, attempts = s.attempts + 1
  FROM ready WHERE s.message_id = ready.message_id
RETURNING s.message_id, s.attempts;
```

Run at `READ COMMITTED`, in its own short transaction. `SKIP LOCKED` lets many
relays work without contention. A row of a stage that has not committed is
invisible here (OB-7): the relay cannot send early, by construction. The lease
is committed **before** the call, so a relay that dies mid-call releases the
message by expiry, not by anyone's cleanup.

### 7.2 Delivering one message

1. **Re-check before sending.** Read the `outbox` row and verify
   `sha256(canonical(payload)) = payload_hash` (OB-2: what is sent is what was
   adjudicated). Check `now() <= not_after`, or record `expired` and dead-letter.
   Check AgentGov's breaker for the plan's scope (read-only view, refreshed), or
   record `held` and park (§7.6).
2. **Call** the sink adapter with the stored payload, the relay's credentials for
   the sink, `Idempotency-Key: <idempotency_key>` where supported, and a timeout.
3. **Classify** the outcome:

   | Result | Outcome | Next |
   |---|---|---|
   | 2xx | `delivered` | state `delivered` |
   | 409 with the same idempotency key | `delivered` | the sink already has it |
   | 429, 5xx, timeout before the request was sent | `retryable` | backoff |
   | Connection lost after the request was sent | `unknown` | retry **with the same key** (at-least-once) |
   | Other 4xx | `permanent` | dead letter |

4. **Record** the attempt row, hash-linked, then update `outbox_state`, in one
   transaction. Backoff is exponential with full jitter, capped, honouring
   `Retry-After`. After `max_attempts` the message is dead.

Sink adapters are small classes behind one protocol (`SinkAdapter.send(request,
credentials, idempotency_key) -> SinkResponse`): a generic JSON-over-HTTPS
adapter, then Stripe and SendGrid. Adapters never see the database.

### 7.3 Ordering

Within a plan, requests are delivered in the plan's topological order.
`outbox.depends_on` holds the effect ids of the requests in the same stage that
must deliver first: those the effect depends on directly, and those reached
through the SQL effects between them (a request after an `UPDATE` after a
request waits for the first request). A message is claimable only when all its
dependencies are `delivered`. If a dependency goes
dead, its dependants are dead-lettered with reason `dependency failed`. Across
plans there is no ordering, as with commits today.

### 7.4 Crash windows

| The relay dies… | Left behind | What happens |
|---|---|---|
| before leasing | `pending` | another relay claims it |
| after leasing, before calling | `leased`, lease running | claimable again when the lease expires; no call was made |
| after the call, before recording | `leased`, the sink acted | redelivered after expiry **with the same key**: the sink deduplicates if it supports keys, otherwise a duplicate (§7.5) |
| after recording, before updating state | attempt row, state `leased` | the next claim sees an attempt `delivered` for this message and closes it without calling (a claim checks the last attempt first) |

These windows get the same treatment as the escrow's commit path: a child
process killed at each one, and a random-instant soak (Phase 4).

### 7.5 Sinks and duplicates

| Sink | Idempotency | Duplicate on relay crash |
|---|---|---|
| Stripe | `Idempotency-Key` header, 24h | absorbed |
| SendGrid mail send | none | possible; mitigated with a `custom_args` message id and a suppression window, not prevented |
| SMTP | none | possible |
| Generic webhook | `Idempotency-Key` if the receiver honours it | depends on the receiver |

`interlock.sinks.idempotency` records which. `interlock check` warns when a sink
without idempotency is registered for an irreversible operation.

### 7.6 A halt after commit

The obligation committed while the scope was live. Should a trip after commit
stop delivery? **Default: yes, hold.** The relay parks the message in state
`held` and does not call. `interlock outbox release` delivers it after an
operator's decision, and `cancel` drops it. A halt usually means something is
wrong, and holding costs latency, not correctness. It is configurable per sink
(`deliver_when_halted = true` for, say, a customer receipt that must go out).

---

## 8. Failure, compensation, operators

### 8.1 Dead letters

`dead` rows are the operator's queue, via `interlock outbox dead` and
`interlock outbox show <message>`. Actions, each recorded as an escrow chain
record naming the message:

- `retry`: back to `pending`, new attempts, same key.
- `cancel`: `cancelled`. Refunds the request's cost through AgentGov.
- `compensate`: enqueue the stored compensation (§8.2).

### 8.2 Compensation (E4-3, E4-4, E4-5)

- **Serialized before the do (E4-3).** An irreversible operation's compensation
  is part of the plan (covered by the `PLAN_ADMITTED` hash) and stored in the
  outbox row in the same transaction. If it cannot be written, the request is not
  enqueued.
- **Compensation is a plan, not a side door.** It runs as a new plan whose
  `compensates` field names the original, through the same admission, staging,
  checkers and relay. A compensation that would refund a different amount than
  the original charged is refused by `CrossEffectAgreement` like anything else.
- **Reverse topological order (E4-4)** across the plan's *delivered* requests.
  Undelivered ones are cancelled instead.
- **Never auto-applied past `expires_at` (E4-5).** Past it, compensation needs an
  operator's `compensate --confirm`. A stale unsend can be a second incident.
- The escrow chain records `COMPENSATED` (the record type exists and is unused
  today) naming the original stage and the compensating plan.

### 8.3 Reconciliation

`interlock reconcile-effects` extends to the outbox, and fails on:

- an `outbox` row whose stage the chain does not record as committed. It should be
  impossible: the rows are privilege-gated and FK-bound.
- a message `delivered` with no `delivered` attempt, or an attempt chain whose
  hashes do not link;
- a message `leased` far past its lease with no relay alive (a stuck lease);
- an attempt whose request payload hash differs from the row's. The relay
  records the hash it sent.

---

## 9. Delivery receipts (optional, Phase 5)

An ARC1 extension: a `delivery` document signed by the relay, naming the
original action receipt (`receipt_id`), the message id, the attempt, the
outcome, the status code and the response digest, appended to the same receipt
log and cosigned by its witness. It closes the audit loop: the action receipt
proves what was *authorized and committed*; the delivery receipt proves what was
*sent* and what the sink answered. It needs an ARC1 v1.1 schema bump and test
vectors in agentgov.

---

## 10. Security

- **No credentials anywhere but the relay.** Not in the plan, the database, the
  sink registry, or the agent's process. Admission refuses payload fields named
  like credentials.
- **No URLs from the agent (SSRF).** A request names a registered sink. The
  endpoint comes from relay configuration. An agent cannot aim the relay at an
  internal address.
- **The stage role cannot write the outbox** except through `enqueue`, and not
  without the stage token. It cannot read other stages' rows: `stage_outbox`
  returns only the current stage's.
- **The relay role cannot change a request.** It has no `UPDATE` on `outbox`.
  The append-only trigger holds even for the owner, unless lifted.
- **PII.** Payloads hold personal data, like emails and addresses.
  `outbox.payload` is purged to `NULL` after delivery plus a retention period;
  `payload_hash` stays, so receipts and disclosures still verify. Response
  bodies are never stored, only their digest.
- **Prompt injection shaping payloads** is the threat this whole pipeline answers:
  the payload is data the checkers read, and `CrossEffectAgreement`,
  `PayloadAmountCap` and `RecipientAllowlist` are the rules that catch an
  instruction that arrived through a tool result.

---

## 11. Open questions

- **Bound fields.** Let a payload field reference a staged row
  (`{"$row": "refunds.amount", "key": 9100}`), filled in by `enqueue` from the
  stage's own writes, so the request is *derived from* the rows rather than
  merely checked against them. Stronger than `CrossEffectAgreement`, and more
  machinery. Proposed for after Phase 3.
- **Hold versus deliver on a halt.** Default hold (§7.6). Needs a product call
  for customer-facing sends.
- **Charging at commit versus delivery.** Commit, for simplicity and because the
  obligation is real (§5.4). Delivery-time charging needs a second claim.
- **Response-driven follow-ups** (webhooks back from Stripe) are inbound, and out
  of scope. They would arrive as a new plan.
- **Exactly-once for non-idempotent sinks** is not solvable here, only narrowed.

---

## 12. Implementation plan

Each phase ships on its own, behind `interlock.toml` configuration: a deployment
without `[[sinks]]` sees no behaviour change. Estimates are engineer-weeks,
including tests.

### Phase 0: types and admission (0.5–1 wk)

- `OutboundRequest`; `Effect.request` and the invariant that `ENQUEUE` carries a
  request and no statement; `PlanBuilder.enqueue`.
- Idempotency key derivation. Canonical payload hash via
  `agentgov.receipts.canonical`, included in `EffectPlan.content_hash()`.
- Sink registry in `config.py` (TOML), JSON Schema subset validator, credential
  field refusal, compensation required for irreversible operations.
- `EscrowEngine.admit` checks. `SqliteSubstrate` and `PostgresSubstrate` refuse
  `ENQUEUE` with a clear error until their phase lands.
- **Tests:** admission refusals, one per rule; key stable across retries,
  different across repairs; plan hash changes with any payload byte.

### Phase 1: PostgreSQL staging (1–1.5 wk)

- `install()`: the four tables, the append-only trigger on `outbox` and
  `outbox_attempts`, `enqueue`, `stage_outbox`, the `begin_stage` token
  argument, grants for the relay role (`relay_roles` in `interlock.toml`, as
  `stage_roles` and `audit_roles` are).
  `INSTALL_VERSION = "2"`, with an upgrade path from `"1"`.
- `_verify_installation` checks them. `_verify_grants` keeps refusing a stage
  role that can write anything; the outbox tables must not appear.
- `apply()` for `ENQUEUE`, `diff()` reading `stage_outbox`,
  `EffectDiff.outbound` in the content hash, receipts coverage (§6.2).
- **Tests:** a request is durable iff the stage commits (commit, refusal, abort,
  crash at every existing kill point); an agent statement calling `enqueue`, or
  inserting into `outbox`, is refused; the canonical-hash vector test (Python
  bytes equal server bytes); the extended `test_crash_consistency.py` invariant
  *outbox rows ⟺ marker*.

### Phase 2: checkers and windows (1 wk)

- The seven checkers of §5.2, with feedback hints and property tests that their
  feedback leaks no payload value or other tenant's count.
- Window measurement (§5.3): sorted per-pair xact locks in the stage, count on
  the engine's own read-committed connection, recorded in `DIFF_COMPUTED`.
- Outbound cost into the settle cost (claim and settle).
- **Tests:** `CrossEffectAgreement` catches the injected-amount case end to end;
  rate limits exact under 16 concurrent stages to one sink (no overshoot, by
  replaying the chain); a replayed verdict equals the recorded one.

### Phase 3: the relay (1.5–2 wk)

- `interlock relay` command, claim loop (§7.1), re-check before sending (§7.2),
  outcome classification, backoff, dead letters, dependency ordering, halted
  scopes held, lease expiry.
- Adapters: generic HTTPS JSON, Stripe, SendGrid. A recording fake sink for
  tests that can fail on demand: 5xx, 429, timeout, drop after send.
- **Tests:** OB-7 (a long-running stage's rows are never claimed); ordering; halt
  holds; `not_after` expires; 16 relays racing deliver each message once, to a
  sink that honours keys.

### Phase 4: relay crash consistency (1 wk)

- A relay child process killed at `leased`, `called`, `recorded`, and at random
  instants, in the style of `test_crash_consistency.py`. Checked after each
  kill: no message lost, none delivered without an attempt row, attempt chains
  verify, and duplicates occur only where §7.4 says they can, and only for sinks
  without keys.

### Phase 5: operators, compensation, receipts (1–1.5 wk)

- `interlock outbox dead|show|retry|cancel|release|compensate`; compensation as a
  `compensates` plan; `COMPENSATED` records; AgentGov refund on cancel.
- `reconcile-effects` over the outbox (§8.3).
- Optional: ARC1 delivery receipts (agentgov schema v1.1, vectors).

### Phase 6: SQLite parity (0.5–1 wk)

- `_interlock_outbox`, `_interlock_outbox_state` and `_interlock_outbox_attempts`
  in the SQLite file, written in the `BEGIN IMMEDIATE` stage, keyed to the
  `_interlock_commits` marker; the same relay over a file (one relay per file).

**Total:** about 6.5–9 engineer-weeks. Phases 0–3 (4–5.5 weeks) are the minimum
that delivers a request safely; Phase 4 is what lets us claim it.

### Exit criteria for Epic 2

- The invariants of §1 each have a test that fails when the mechanism behind it
  is removed. This is the mutation discipline Epic 1 used.
- The crash suites pass on PostgreSQL 14 and 16, in CI, required.
- The README's "What this is not yet a boundary against" loses the line
  *"Non-transactional sinks cannot be staged"* and gains the at-least-once
  statement of §1, verbatim.
