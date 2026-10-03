# Epic 3: ecosystem adapters, signed operator logs, SQLite parity

**Status: design, approved; built step by step on `feat/epic3-adapters-audit`.**
Builds on the transactional outbox of [`OUTBOX_DESIGN.md`](OUTBOX_DESIGN.md)
(Epic 2). Five decisions were settled before any code:

1. Operator actions are recorded in a **dedicated signed ILOK1 log**
   (`interlock.records`), cross-referenced from the delivery log, not in the
   escrow chain: the chain is keyless, and a running engine holds its file.
2. **`interlock outbox compensate`** executes the compensations plans serialize
   (E4-3), so a required refund can actually run.
3. **SendGrid defaults to at most once**: an unknown outcome is dead-lettered.
4. **Schema version 3**, upgraded in place from 2; every hash written under 2
   stays valid.
5. **`interlock install` switches a SQLite database to WAL.**

---

## 1. The outbox store

The relay's state machine (claim, record a call, record its outcome, hold,
defer, refuse) and the operator's actions are reached through one interface,
`OutboxStore`, with two implementations:

| | PostgreSQL | SQLite |
|---|---|---|
| state machine | the `relay_*` and `outbox_*` SQL functions (Epic 2) | the same transitions, in Python, inside `BEGIN IMMEDIATE` |
| claims never collide by | `FOR UPDATE SKIP LOCKED` | the database's one write lock (§2) |
| who may write | roles and grants | the file's permissions, narrowed by an authorizer |
| delivery-log linking | a trigger assigns position and hashes | a trigger checks them, through a function only Interlock registers |

The two are held to one behaviour by one conformance suite: every relay test and
every crash matrix runs against both.

## 2. SQLite: concurrency without `SKIP LOCKED`

SQLite admits one writer at a time. That is the whole mechanism:

- **Every outbox write is a short `BEGIN IMMEDIATE` transaction**, which takes
  the write lock when it begins. A claim selects due messages and leases them
  under that lock: no other claim, call record, outcome or stage can write until
  it commits, and the next claim reads the leases and passes them by. What
  `SKIP LOCKED` does by skipping, SQLite does by queueing. Claims serialize;
  each takes milliseconds.
- **No transaction ever starts as a read and becomes a write.** In WAL mode a
  read transaction that tries to write after another writer committed fails
  (`SQLITE_BUSY_SNAPSHOT`); every transaction that may write begins
  `IMMEDIATE`, so none is ever in that position.
- **WAL** (set by `interlock install`, persistent in the file) lets readers run
  beside the writer: the relay's and the operator's reads never wait. WAL needs
  every process on one host, which a SQLite deployment is; leases use that
  host's clock. `synchronous=FULL` on every Interlock connection: a committed
  outbox row survives power loss, not only a crash.
- **A stage holds the write lock for its life** (`BEGIN IMMEDIATE` at open,
  bounded by `max_stage_seconds`). A relay's writes queue behind it, so the
  relay's busy timeout is longer than a stage may live. A relay never holds the
  lock while it calls a sink: claim, call record and outcome are three separate
  transactions, and the call happens between them.
- **Nothing is sent before its stage commits** (OB-7), as on PostgreSQL: a
  stage's writes are invisible to every other connection until its `COMMIT`.
- **The gate is the authorizer.** On PostgreSQL a token keeps agent statements
  from calling `enqueue`. On SQLite the agent's statements run under an
  authorizer that refuses them, at prepare time, any write to `_interlock_*`
  tables; the substrate writes the outbox with the authorizer lifted
  (`_substrate_statements`), as it writes the commit marker. The relay's
  connection carries its own authorizer, admitting writes to delivery state and
  the delivery log only.
- **The delivery log is linked by the database.** Triggers make the log and the
  outbox append-only, and a `BEFORE INSERT` trigger requires each row to sit at
  the head of its message's log, link to it, and hash to what it holds: the hash
  is recomputed by `interlock_event_hash`, an application function that only
  Interlock's connections register. A plain `sqlite3` shell cannot append to the
  log at all.
- **The outbox rows are bound to the commit marker** by a deferred foreign key
  to `_interlock_commits`, written in the same transaction just before `COMMIT`.
  An outbox row exists if and only if its stage committed. Outbound requests
  therefore need commit markers on.

**Weaker than PostgreSQL, said plainly:** SQLite has no roles. A process that
can open the file for writing can write any table in it; the relay's authorizer
bounds the relay's own code, not a hostile process. The file's permissions are
the boundary, and the signed operator log (§6) and the delivery log's
verification are how an edit made around Interlock is found.

## 3. Schema version 3 (PostgreSQL)

Installed in place over version 2, in one transaction:

- `outbox_attempts` gains `remote_ref` (the id of what a delivered call created:
  a Stripe `pi_...`) and `authority` (the signed operator record behind an
  operator's event). `outbox` gains `compensates` (the message a compensation
  undoes). `sinks` gains `kind` (`http`, `stripe`, `sendgrid`).
- **Every hash written under version 2 is unchanged.** A log row with neither
  `remote_ref` nor `authority` hashes as before (`interlock-outbox-event-v1`); a
  row with either hashes under `interlock-outbox-event-v2`, which frames both.
- `relay_outcome` takes the `remote_ref`. The operator functions take an
  `authority` and the log head the operator saw, and refuse without the first
  or when the second is stale. `outbox_compensate` is new. `enqueue` checks the
  compensation contract of a typed sink (§4) a second time.

## 4. Sink kinds and adapters

A sink has a kind. `http` is Epic 2's generic sink; `stripe` and `sendgrid`
bring their own operations, with strict built-in payload schemas, and their own
relay adapters. Configuration names a typed sink's operations; it does not
write their schemas.

### 4.1 Stripe

Operations: `payment_intents.create`, `charges.create`, `refunds.create`.

- **The compensation contract**, checked at admission and again in `enqueue`.
  A charge (`payment_intents.create`, `charges.create`) must carry a
  compensation, and it must be a `refunds.create` that:
  - names the charge it refunds by the placeholder `{"$bind": "delivered.id"}`
    (in `payment_intent` for a payment intent, `charge` for a charge): never a
    literal id, so a plan cannot point its undo at another customer's payment;
  - refunds at most the charge's `amount`, or omits `amount` (all of it);
  - names no currency: a refund is in the charge's.
- **The placeholder** is resolved by `compensate` (§5) from the delivery log:
  the `remote_ref` the `delivered` row recorded, the id Stripe returned. It is
  never resolved by the relay, which only ever sends concrete payloads.
- **The adapter** sends form-encoded bodies (Stripe's bracket notation,
  computed deterministically from the canonical payload), the request's
  idempotency key in `Idempotency-Key`, a pinned `Stripe-Version`, and the secret
  key from the relay's environment. It returns the created object's `id` as the
  `remote_ref`. Classification: 2xx delivered (an `Idempotent-Replayed` reply
  too); `Stripe-Should-Retry` decides when present; 409 and 429 retryable; 5xx
  unknown (Stripe's own guidance: the request may have been executed); an
  `idempotency_error` (a key reused with other parameters) permanent, and
  reported as tampering; other 4xx permanent.

### 4.2 SendGrid

Operation: `mail.send`, with a strict payload (`to`, `cc`, `bcc`, `from`,
`reply_to`, `subject`, `text`, `html`, `categories`) that the adapter maps to
SendGrid's v3 body, adding `custom_args` with the message id and idempotency key
so a duplicate can be traced downstream. 202 delivered (the `X-Message-Id`
header is the `remote_ref`); 429 retryable, no sooner than `X-RateLimit-Reset`;
5xx unknown; other 4xx permanent. No idempotency keys exist, so the sink kind
defaults to `idempotency = "none"` and `unknown_outcome = "dead-letter"`: at
most once. A sandbox switch sets SendGrid's `sandbox_mode`, for live tests.

## 5. Compensation

`interlock outbox compensate <message>` (or `--plan <plan>`) enqueues the
compensation a delivered request carried, as a new outbox message:

- the placeholder is replaced with the original's recorded `remote_ref`; a
  compensation whose placeholder has nothing to bind to is refused;
- its idempotency key derives from the original's, so compensating twice is
  refused by the outbox's uniqueness, never sent twice;
- across a plan, compensations run in reverse topological order of the
  plan's delivered requests (E4-4): each waits for the compensation of every
  request that waited for its original;
- past the original's deadline it needs `--late` (E4-5): a stale undo is a
  decision, not a default;
- the original's log records a `compensated` row naming the new message, and
  the new message's outbox row names the original (`compensates`).

## 6. The signed operator log

Every human intervention, `release`, `cancel`, `requeue`, `compensate`, and an
`install` that changes the sink registry, is a signed record in an ILOK1 log of
its own (`[operators] log`), anchored into AgentGov when a ledger is configured.

- **Keys.** Each operator signs with an Ed25519 key of their own (`--key` or
  `INTERLOCK_OPERATOR_KEY`); `[operators.keys]` maps names to public keys.
  Verifying needs only the public halves.
- **Two phases, like a commit.**
  1. An `operator.intent` record is signed and written: the action, its target
     messages, the reason, and each message's delivery-log head as the operator
     saw it.
  2. The database action runs with the intent's hash as its `authority` and the
     heads as preconditions: an authority is required, and a head that moved is
     a refusal, so an authorization cannot be replayed on a later state.
  3. An `operator.applied` (or `operator.refused`) record names the intent and
     the delivery-log rows the action wrote.

  A process killed between phases leaves an intent with no outcome; the next
  operator command resolves it from the database (`applied` if a row carries its
  authority, `operator.abandoned` if none does). Nothing is ever applied without
  an intent signed first.
- **What `interlock outbox verify` finds** (the "ghost edits"):
  - an operator row in a delivery log with no authority, or one that is not a
    signed intent for that message and action, or whose head precondition is
    not the row before it;
  - a state that the message's log does not lead to (a direct `UPDATE`);
  - a delivery log that does not link (a row rewritten or removed);
  - an operator record whose signature does not verify under a registered key,
    an intent left unresolved, an `applied` naming rows that do not exist, and
    records missing from the AgentGov ledger they were anchored into.

A database's owner can still edit their own database; no design prevents
that. What this design ensures is that every edit not made through a signed
intent is named by verification, from evidence outside the owner's reach:
records signed with keys the database does not hold, anchored in a ledger it
does not control.

## 7. Proofs

- A SQLite engine is killed at each point of its commit path: a request is in
  the outbox exactly when the stage's commit marker is.
- The relay's kill matrix (Epic 2, §7.4) and its random-instant soak run
  against both stores; several relay processes contend for one SQLite file.
- The operator command is killed after its intent, after the database action,
  and after its outcome record: no action exists without a signed intent, and
  every intent resolves exactly.
- Stripe and SendGrid are driven through the kill matrix against fakes that
  keep their protocols (Stripe's idempotent replays, SendGrid's lack of them):
  a charge is made once; an email is never sent twice.
- Each ghost edit of §6 is made, and verification names it.
- Every mechanism above has a test that fails when it is removed.
