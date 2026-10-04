# Epic 5: the zero-trust inbox, cryptographic compaction, the last checkers

**Status: building**, step by step on `feat/epic5-inbox-compaction`; §8 will
record where the build settled what the design leaves open. Builds on
[`OUTBOX_DESIGN.md`](OUTBOX_DESIGN.md) (Epic 2), [`EPIC3_DESIGN.md`](EPIC3_DESIGN.md) and
[`EPIC4_DESIGN.md`](EPIC4_DESIGN.md). Three parts:

1. **Cryptographic compaction** (§1). Rate-window history and the outbox's tables grow
   without bound (`EPIC4_DESIGN.md` §7, "left open"). A vacuum prunes what no check will
   read again. It first verifies the history it prunes, then signs a *checkpoint* that
   commits to it, anchors that checkpoint into AgentGov, and only then deletes the rows,
   in the same database transaction that records the checkpoint. Every verifier still
   passes afterwards, and every pruned row stays provable against the checkpoint from an
   archive.
2. **The zero-trust inbox** (§2). Vendors answer later: Stripe sends `charge.refund.updated`
   days after the refund. An inbox process, which alone holds the webhook secrets, verifies
   each webhook's vendor signature. It binds the event to the outbound delivery whose
   relay-attested `remote_ref` it names, attests the result with its own Ed25519 key, and
   stages it as a typed, read-only fact. An agent's next plan may consume the fact, exactly
   once. No vendor-controlled free text ever reaches the agent.
3. **The last outbound checkers** (§3): the five of `OUTBOX_DESIGN.md` §5.2 not built yet,
   and strict numbers in every payload rule.

Decided before any code:

- **A compaction is an operator action.** Signed in two phases like every outbox action
  (`EPIC3_DESIGN.md` §6): the intent carries the checkpoint, and the deletion runs under the
  intent's authority. A vacuum without an AgentGov ledger to anchor into does not run.
- **Nothing unverified is pruned.** History that fails verification is evidence of
  tampering. The vacuum refuses it, reports it, and leaves it in place.
- **Inbound facts are attested, like outcomes.** The inbox process signs what it verified,
  as relays sign what sinks answered. The database cannot forge a fact, and the engine
  consumes only facts whose attestation verifies under `[inbox.keys]`.
- **Schema version 5** on both stores, upgraded in place from 4 (and from 2 and 3 through
  it). It is tested against version 4's frozen code, as Epic 4 tested 2 and 3.

---

## 1. Cryptographic compaction

### 1.1 What grows, and what may go

| What | Grows by | Read by | May go when |
|---|---|---|---|
| `window_ledger` / `_interlock_windows` | a row per plan per window key | the window checks, for rows `at > now - span` | older than the longest span plus a margin |
| `outbox`, `outbox_state`, `outbox_attempts`, `outbox_settlements` | a message, its state, its delivery log, its settlement | the relay, operators, settlement, verification | the message's whole stage is final and settled (§1.2) |
| `inbox_events`, `inbox_facts`, `inbox_consumed` (§2) | an event, its facts, their consumption | the engine, verification | consumed or expired, older than retention, as a prefix of its source's log |

The vacuum leaves everything else alone. Commit markers are one small row per committed plan,
and both recovery and `reconcile-effects` read them. The legacy set is sealed, and so are the
messages it names. The escrow chain, the operator log, the receipt log and the ledger are
files and ledgers with their own lifecycles.

### 1.2 Eligibility

- **Windows.** A row with `at ≤ horizon`, where `horizon = now − (longest configured span +
  margin)`. The margin (default one hour) exceeds any stage's lifetime, so no stage still
  open can commit a row that old.
- **Outbox, by stage.** A plan's requests go together: compensations and the order between
  requests are per plan, so a plan is never half pruned. A stage is eligible when every one
  of its messages:
  - is `delivered` and settled, or `cancelled`. A `dead` message may still be requeued, and
    a `pending`, `leased` or `held` one is still live;
  - holds no lease, and its last log row is older than `retain` (default 30 days). Past
    retention a delivered request can no longer be compensated: retention is that window;
  - is in no row of the legacy set;
  - verifies: its log recomputes from its genesis, every outcome carries a registered
    relay's valid attestation, every operator row carries the authority of an applied
    signed intent, and no unresolved intent names it.
- **Inbox, by source.** A prefix of the source's log: every event up to some position whose
  facts are all consumed, or that matched nothing within its match window, older than
  `retain`.

### 1.3 The checkpoint

A checkpoint is a canonical JSON body:

```
{"v": "interlock-checkpoint-v1",
 "seq": N, "prev": <digest of checkpoint N-1, or 64 zeros>,
 "horizon": {"windows": <instant or null>, "outbox": <instant>, "inbox": <instant>},
 "outbox":  {"messages": m, "rows": r, "root": <tombstone fold>},
 "windows": {"rows": w, "root": <window-row fold>},
 "inbox":   {"sources": [{"source": s, "through": k, "head": <event hash at k>,
                          "events": e, "facts": f, "consumed": c}], "root": <fact fold>},
 "agentgov": {"sequence": q, "head": <ledger head hash>},
 "archive": <SHA-256 of the archive file, or null>}
```

Its digest is SHA-256 over its canonical bytes. Checkpoints form a chain of their own through
`seq` and `prev`, so the database's sequence of compactions is tamper-evident too.

**Tombstones** keep a pruned message verifiable. One row per message, in the checkpoint's
transaction:

```
(message_id, checkpoint, stage_id, plan_id, state, log_seq, log_head,
 receipt_id, credit, cost, compensates)
```

`log_head` is the tip of the message's hash-linked delivery log. Through every row, and the
genesis that binds the request (message, stage, plan, scope, effect, sink, operation,
idempotency key, payload hash), it commits to the whole pruned history of the message.
`receipt_id` and `credit` are the settlement's, so the receipt log and the ledger still have
something to be held to.

**The folds.** A fold commits to a list in a fixed order with the outbox's own framing
(`interlock.outbox_digest`, SHA-256 over length-prefixed fields; `OUTBOX_DESIGN.md` §4.1),
the same in Python and in SQL:

```
leaf(tombstone) = digest("interlock-tombstone-v1", message_id, stage_id, plan_id, state,
                         log_seq, log_head, receipt_id, credit, cost, compensates)
leaf(window row) = digest("interlock-window-row-v1", stage_id, window, key,
                          amount (normalized decimal), at (UTC microseconds))
fold(tag, leaves) = r_n, where r_0 = digest(tag, "0"), r_i = digest(tag, r_{i-1}, leaf_i)
```

Tombstones are ordered by message id, window rows by (window, key, stage, at). A fold is a
hash chain over sorted leaves: as binding as a Merkle root for recomputing the whole set,
which is all verification does, and computable in a PL/pgSQL loop. An inbox source's pruned
prefix needs no fold. Its log is a hash chain already, and the checkpoint names the position
and hash it was cut at, where the remaining log continues (§2.3).

### 1.4 Two phases, anchored first

1. **Verify** (§1.2). Anything that fails is reported and kept.
2. **Intent.** An `operator.intent`, action `compact`, carries the checkpoint body, signed
   with the operator's key. It is then anchored as an AgentGov `ANCHOR` entry
   (`ILOK1 interlock-operators <seq> <hash>`, as every operator record is). If the anchor
   cannot be written, nothing is deleted, and the intent is recorded abandoned.
3. **Act.** One database transaction, under the intent's hash (its *authority*):
   - Write the checkpoint row: its `seq` is the next, and its `prev` is the last one's
     digest. A racing vacuum fails on the key.
   - Check that every message's log head is the one verified and signed for. A moved log
     refuses the whole transaction.
   - Write the tombstones, then recompute both folds from what the database holds and
     compare them with the signed roots.
   - Delete the rows, and cut the inbox prefixes.
   All of it commits, or none.
4. **Outcome.** `operator.applied` names the checkpoint (`seq`, digest). `operator.refused`
   says why the transaction refused.

A process killed after the intent leaves no checkpoint row under it, and the next operator
command records it abandoned. One killed after the commit leaves the row, and the next
command records it applied. Rows are never deleted without a checkpoint signed and anchored
before them.

### 1.5 The database's part

Version 5 adds, on both stores:

- `checkpoints` (`seq`, `authority`, `body`, `digest`, `windows_horizon`, `at`), append-only.
- `outbox_compacted`, the tombstones, append-only.
- **Guards that admit one deletion.** The outbox's append-only triggers, a new delete guard
  on `outbox_state`, and a new append-only guard on window history refuse every `UPDATE`,
  `DELETE` and `TRUNCATE`, with one exception: a `DELETE` of a message tombstoned by a
  checkpoint written *in the same transaction*, or of a window row at or before that
  checkpoint's window horizon.
  - On PostgreSQL, "the same transaction" is `checkpoints.xid = pg_current_xact_id()`.
  - On SQLite, it is a checkpoint whose `open` flag is set. The transaction sets it first
    and clears it last, so no other connection ever sees it set. A trigger refuses any other
    change to the table.

The database cannot check a signature. It can check that no row disappears except beside a
checkpoint row naming an authority, and verification holds that authority to the signed
operator log (§1.6). On PostgreSQL the act is `interlock.outbox_compact(authority,
checkpoint, expected_heads)`, `SECURITY DEFINER`, granted to no role: the installer runs it,
as every operator function. On SQLite it is the same steps in one `BEGIN IMMEDIATE`, through a
store opened with a compactor's write set.

### 1.6 Verification after compaction

| Verifier | A compacted message is accounted for by |
|---|---|
| `verify_delivery_log` | nothing: it reads the live rows, and pruned messages have none |
| `verify_operators` | an applied record naming a row of a compacted message: its tombstone, with `log_seq` at or past the row |
| `verify_attestations` | nothing: legacy messages are never compacted |
| `verify_settlements` | a delivery receipt naming a compacted message: the tombstone's `receipt_id`; a credit for a compacted compensation: the tombstone's `credit` |
| the inbox's chain check | the source's log starts at the latest checkpoint's `(through, head)` instead of its genesis |

`verify_operators` also holds every checkpoint to the operator log:

- a checkpoint row whose authority is no applied `compact` intent;
- an applied `compact` intent whose checkpoint row is missing;
- a checkpoint whose body is not the one the intent signed;
- a chain of checkpoints with a gap or a fork;
- tombstones or window folds that no longer recompute to the signed roots;
- a compacted message that is live again.

| A database owner... | is named because |
|---|---|
| deletes a live message and calls it compacted | no tombstone covers it: the receipts and applied records naming it are findings, as before |
| adds a tombstone to cover a deletion | the checkpoint's tombstones no longer fold to its signed root |
| writes a whole checkpoint, tombstones and all | its authority is no signed `compact` intent |
| deletes a checkpoint row | an applied `compact` intent names a checkpoint the database lacks |
| restores pruned rows, or forged ones | a message is both tombstoned and live |
| deletes window history to reopen a window | the guard refuses it. Done around the guard, it is undetectable from the database alone (§7) |

### 1.7 The archive

With `--archive DIR`, the vacuum first writes everything it will prune to
`checkpoint-<seq>.jsonl`. The first line is the checkpoint body, and each following line is
one pruned row, table by table, as the database held it. The file's SHA-256 enters the
checkpoint (`"archive": <digest>`) before the intent is signed. `interlock vacuum
verify-archive FILE` then proves the pruned history from the checkpoint alone:

- every archived message's log recomputes from its genesis to its tombstone's head;
- every outcome's relay attestation verifies;
- the tombstones fold to the signed root, and the window rows to theirs.

Without an archive, the checkpoint proves that the history verified when it was pruned, and
commits to it exactly. With one, it proves the history itself.

### 1.8 The window watermark

The latest checkpoint's window horizon is a watermark. A window whose span reaches back
before it cannot be measured honestly, since part of its history is gone. So the history
read refuses it and the plan fails closed: `IL009` in `interlock.window_totals` on
PostgreSQL, a `StageError` in `measure_windows` on SQLite. A vacuum configured with spans
shorter than an engine's turns into refusals, never into undercounts.

---

## 2. The zero-trust inbox

### 2.1 Shape

```
vendor ── POST /inbox/<source> ──►  interlock inbox  (own process, own database role;
                                                       holds the webhook secrets and an
                                                       Ed25519 key)
  1. route, size bound, content type
  2. the vendor's signature, its timestamp within tolerance            (§2.2)
  3. each event: id, type, references, typed projection               (§2.5)
  4. record the event: the source's hash-linked log, attested         (§2.3)
     (idempotent on (source, event id))
  5. match: the delivered request whose relay-attested remote_ref     (§2.4)
     the event names → a fact, attested
  6. 2xx
engine:
  facts(scope) → pending facts that verify under [inbox.keys]
  PlanBuilder.consume(fact) → admission checks it; the stage marks it consumed in its
  own transaction; the diff carries it; checkers judge the plan against it  (§2.6, §2.7)
```

The inbox never opens a stage and never writes the outbox, and the engine never holds a
webhook secret.

### 2.2 Vendor signatures

Each `[[inbox.sources]]` names a kind, which fixes the scheme. The secret comes from the
inbox's environment, never the database or the configuration file. Every comparison is
constant-time. A request that fails any check is answered `401` and writes nothing.

- **Stripe** (`kind = "stripe"`). The `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]`
  header carries one or more `v1` signatures. One of them must be HMAC-SHA256 over
  `"<t>." + raw body` under the endpoint's signing secret (`whsec_...`); several appear
  while a secret rotates. `|now − t|` must be within the tolerance (default 300 s), so
  replays and future-dated signatures are refused. Only the raw bytes are signed: the body
  is parsed only after the signature verifies.
- **Standard Webhooks** (`kind = "http"`, the Svix-compatible standard), using the
  `webhook-id`, `webhook-timestamp` and `webhook-signature: v1,<base64> [v1,<base64>...]`
  headers. The signature is HMAC-SHA256 over `"<id>.<timestamp>." + raw body`, under the
  key that `whsec_<base64>` encodes. The timestamp tolerance is the same, and the event id
  is the header's.
- **SendGrid** (`kind = "sendgrid"`, the Signed Event Webhook). The
  `X-Twilio-Email-Event-Webhook-Signature` header carries a base64 DER ECDSA P-256/SHA-256
  signature over `timestamp + raw body`. It must verify under the account's verification
  key (base64 SubjectPublicKeyInfo, which is public and lives in the configuration file),
  and `X-Twilio-Email-Event-Webhook-Timestamp` is held to the tolerance. Verification uses
  `cryptography`, which the inbox has anyway in order to sign. One request carries a batch
  of events.

Also refused, and recording nothing:

| Answer | Why |
|---|---|
| `404` | an unknown source |
| `413` | a body over the bound (default 256 KiB) |
| `415` | anything but JSON |
| `400` | a missing header, or JSON that does not parse after a valid signature |

### 2.3 The inbox log

Each source's events form a hash-linked log, built like a message's delivery log (`OUTBOX_DESIGN.md`
§4.1):

```
genesis(source) = digest("interlock-inbox-genesis-v1", source)
event_hash      = digest("interlock-inbox-event-v1", prev_hash, source, seq, event_id,
                         type, vendor_at, received_at, body_hash, attestation)
```

A trigger assigns `seq`, `prev_hash` and `event_hash`, and advances the source's head in
`inbox_sources`, so no writer appends a row that does not link. The inbox process's
**event attestation** is an Ed25519 signature, under the domain `ILOK1/inbound/v1\n`, over the
canonical `{source, event_id, type, vendor_at, received_at, body_hash, kid}`. It is made
before the row is written, and the row's hash covers it. The raw body is kept, so anyone
holding the secret can re-check the vendor's signature, but no stage role can read it.

Rewriting or deleting an event in the middle of a log breaks the chain, and
`interlock inbox verify` recomputes every chain. A pruned prefix leaves the chain to start
at a checkpoint's `(through, head)` (§1.3). Truncating the tail of a log is the one edit a
chain held in the database cannot show (§7).

### 2.4 Matching: the binding to the delivery receipt

An event names the object it is about by its references, tried in order:

| Kind | References |
|---|---|
| Stripe | `data.object.id`, `data.object.payment_intent`, `data.object.charge` (a refund event names its refund, its charge and its payment intent) |
| SendGrid | `sg_message_id` up to its first `.`, which is the `X-Message-Id` the relay recorded |
| `http` | the paths the source configures |

The event is bound to the delivered request whose `remote_ref` is the first reference that
matches. A match must hold all of these:

- every `delivered` row carrying that `remote_ref` belongs to one message. Two different
  messages make the event ambiguous, and it is bound to neither;
- the row's relay attestation verifies under `[relays.keys]`. The relay signed the
  `remote_ref`, so the database's word is not enough;
- the message's attested idempotency key derives from its plan and effect, as settlement
  checks (`EPIC4_DESIGN.md` §7), which binds the plan.

The **fact** records the binding as `(message_id, delivery_seq, delivery_hash, remote_ref,
scope, plan, tenant)`, with the event's position and hash, its kind (the event type) and its
projected fields. The inbox's **fact attestation** signs all of it.

`delivery_seq` and `delivery_hash` are the row the delivery receipt names as `delivery.log_seq`
and `delivery.log_hash`. So one chain of signatures runs from the vendor to the plan:

- the vendor's MAC or ECDSA signature;
- the inbox's Ed25519 attestations;
- the relay's attestation, which covers `remote_ref`;
- the receipt log's delivery receipt;
- the plan's action receipt.

A webhook can arrive before the relay records the delivery (Stripe sends
`payment_intent.succeeded` as the API call returns). An event that matches nothing is still
recorded, attested, and matched again by the inbox's matcher until its match window ends
(default one hour). After that it is unattributed: kept for operators, and never a fact.

### 2.5 Facts are typed: nothing injectable reaches the agent

A fact's fields are a projection: named fields, each of a type from a closed set.

| Type | Value |
|---|---|
| `id` | `^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,254}$` |
| `code` | `^[a-z][a-z0-9_.]{0,63}$` |
| `integer` | within ±(2^53 − 1) |
| `decimal` | a numeral as payloads carry money |
| `currency` | `^[a-z]{3}$` |
| `boolean` | |
| `instant` | integer seconds since the epoch |

No type admits free text. A value that does not fit is *withheld*: the fact records the
field's name among the withheld, never the value. The projections are fixed per kind:

- **Stripe**, from `data.object`: `object`, `id`, `status`, `amount`, `amount_refunded`,
  `currency`, `payment_intent`, `charge`, `reason`, `failure_code`, `failure_reason`,
  `created`; and the event's `livemode`.
- **SendGrid**: `event`, `type`, `status`, `timestamp`.
- **`http`**: the source's own configuration declares the projection, `name = {path, type}`.

Descriptions, metadata, names, email addresses and error messages never project: they are
the vendor-controlled text a prompt injection would ride in. The agent sees a fact as data in
a typed record, and feedback never quotes a fact's values.

### 2.6 Read-only, exactly once

- **Read-only.** The inbox tables are written only through the inbox role's functions, and
  are append-only. No stage role may read or write them on PostgreSQL (no grant). On SQLite,
  the substrate's authorizer refuses a plan's statements any read or write of them, as it
  refuses window history.
- **Pending facts.** `engine.facts(scope)` reads a scope's facts outside any stage:
  `interlock.inbox_pending(scope)` refuses inside one (`IL009`, as `window_totals` does), so
  no agent statement reads them. It returns only facts whose attestation verifies under
  `[inbox.keys]`.
- **Consumption.** `PlanBuilder.consume(fact)` puts the fact's id in the plan, and the plan's
  hash covers it. Admission refuses a fact that:
  - is unknown, or consumed already;
  - belongs to another scope;
  - does not verify under `[inbox.keys]`.
  The stage then writes `inbox_consumed(fact_id, stage_id)` in its own transaction: with its
  token on PostgreSQL (`interlock.inbox_consume`, as `enqueue`), directly on SQLite. The row
  exists exactly when the plan commits, and of two plans racing for one fact, one commits
  and the other is refused.
- **Measured.** The diff carries the consumed facts (`EffectDiff.facts`), read back from the
  database in the stage as outbound requests are. Its hash covers them, and the action
  receipt's row commitment includes them as rows of `interlock.inbox`.

### 2.7 `FactAgreement`

`FactAgreement(kind, field, table, column, key=(fact_field, key_column))` makes an agent's
reaction answer to the fact behind it. Every row the plan writes to `table.column` must
equal `field` of a consumed fact of `kind` keyed to that row. A plan that marks a refund
`failed` without consuming the vendor's attested `failed` event is refused. An injected agent
cannot claim an event it never received, or rewrite what the event said. Values compare
exactly, numbers as `Decimal`, and the agent is told the rule, never the values.

### 2.8 Roles

| | PostgreSQL | SQLite |
|---|---|---|
| inbox process | `inbox_roles`: may read the outbox and the inbox, and call `inbox_record`, `inbox_match` | a store with the inbox's write set |
| engine (stage role) | `inbox_pending` (refused in a stage), `inbox_consume` (token), `stage_facts` | its own connection outside the stage; the stage's own transaction |
| agent statements | no privilege on any inbox table | refused by the authorizer, reads included |
| operators (installer) | everything, through functions, signed | the file |

---

## 3. The outbound checkers (`OUTBOX_DESIGN.md` §5.2)

Each is a pure function of `(plan, diff)` over the requests read back from the outbox, and
each fails closed: a value it cannot read refuses the plan, never passes it. Every hint names
the rule, never a payload value. A payload number counts only as a strict decimal numeral,
`-?(0|[1-9][0-9]*)(\.[0-9]+)?`, or an integer. `1_000`, `" 5"`, `1e3`, `+5` and non-ASCII
digits (`١٢٣`) are not numbers, because a sink may read them differently than the check did.
This holds for every rule, including the schema subset's `minimum` and `maximum`, which today
accept them.

| Checker | Refuses a plan when |
|---|---|
| `SinkAllowlist(allowed)` | a request names a sink, or an operation of it, outside `allowed` (`{"stripe": ["refunds.create"], "mail": "*"}`). The registry admits per engine; this narrows per plan scope. |
| `OutboundCount(max_per_plan, per_sink={})` | the plan enqueues more requests than allowed, in all or to one sink: the blast radius for calls. |
| `PayloadAmountCap(sink, operation, field, maximum, per="request", currency_field=None)` | an amount exceeds its cap. `per` is `"request"` (each), `"tenant"` (the plan's sum per tenant) or `"plan"` (its sum). `maximum` is a number, or a map by currency, read at `currency_field`; a currency the map lacks refuses. A missing, malformed or negative amount refuses: no negative entry nets a sum under the cap. |
| `RecipientAllowlist(sink, operation, fields, domains=(), addresses=(), tenant_domains={}, subdomains=False, kind="email")` | a recipient at any of `fields` (paths with `*` over lists: `to.*.email`) falls outside the allowed domains or addresses. Parsed strictly: one `local@domain`, ASCII only, no display name, no second address, no `%` or `!` routing, no quoted local part, the domain a hostname compared case-folded without a trailing dot. `kind="url"` checks an `https` URL's host the same way, with no userinfo and no IP literal. Anything that does not parse refuses. A request's tenant may also use `tenant_domains[tenant]`. |
| `OutboundTenantIsolation(fields={}, max_tenants=1, require_tenant=False)` | the requests and rows of a plan span more tenants than allowed; a request goes to a tenant none of the plan's rows involve, when they involve any; a payload's tenant field (configured per sink and operation) differs from the request's tenant, or is missing; or, with `require_tenant`, a request carries no tenant. |

Property tests extend the feedback guarantee (`interlock.feedback`) to all five: over generated
plans and payloads, the agent is told no payload value, no tenant the plan did not declare,
and no number but bucketed counts and configured limits.

---

## 4. Schema version 5

| | PostgreSQL (`interlock.`) | SQLite (`_interlock_`) |
|---|---|---|
| checkpoints | `checkpoints` (+ `xid`) | `checkpoints` (+ `open`) |
| tombstones | `outbox_compacted` | `outbox_compacted` |
| inbox | `inbox_sources`, `inbox_events`, `inbox_facts`, `inbox_consumed` | the same |
| guards | compaction-aware append-only triggers on the outbox tables; delete guard on `outbox_state`; append-only guard on `window_ledger` | the same, as `BEFORE` triggers |
| functions | `outbox_compact`; `inbox_record`, `inbox_match` (inbox roles); `inbox_pending`, `inbox_consume`, `stage_facts` (stage roles); `window_totals` gains the watermark | the same steps in Python, under `BEGIN IMMEDIATE` |
| index | `outbox_attempts (remote_ref)` for delivered rows | the same |

Upgraded in place from version 4. No relay needs a restart: no relay function changes.

---

## 5. Proofs

- **The vacuum's crash matrix, on both stores.** A vacuum in a process of its own is
  SIGKILLed after its intent, inside its transaction, after its commit, and after its
  outcome. After each:
  - the database is wholly compacted or untouched;
  - the next operator command resolves the intent exactly (abandoned or applied);
  - every verifier passes: logs, attestations, operators, settlements;
  - a second vacuum prunes the rest once, with no message tombstoned twice.
- **No forged webhook is accepted.** Each case is answered and writes nothing, on both
  stores and for every kind:
  - a wrong secret, or a signature from another source;
  - a tampered body, or a tampered timestamp;
  - a replay outside the tolerance, or a future timestamp;
  - a missing header, or a truncated signature;
  - a valid signature over another body;
  - a duplicate event, which is idempotent.
- **The inbox's crash matrix.** An inbox process is SIGKILLed after verifying, after
  recording the event, after recording the fact, and before answering. The vendor's retry
  then yields exactly one event and one fact, every chain verifies, and every attestation
  holds.
- **Forged facts are refused.** A fact written around the inbox, a genuine attestation
  copied to another fact, or a fact moved to another scope is refused at admission and named
  by `interlock inbox verify`.
- **Consumption is atomic.** A stage killed at each crash point consumes its facts exactly
  when its commit marker exists. Two plans racing for one fact: one commits.
- **Mutations.** Each mechanism of this epic is removed in turn, and a test fails for each.

## 6. Sequence

1. This document.
2. The outbound checkers and strict numbers (§3).
3. Schema version 5's compaction, and the vacuum (§1): checkpoints, tombstones, guards, the
   watermark, verification after compaction, the archive, `interlock vacuum`.
4. The inbox (§2): the log, vendor signatures, matching, facts, consumption,
   `FactAgreement`, `interlock inbox serve | match | list | verify`,
   `interlock keygen --role inbox`; the inbox's prefixes in the vacuum.
5. Crash matrices and the forgery matrix.
6. Documentation, the mutation pass, final verification.

## 7. Limits

- **A log's tail.** A chain held in the database proves every row against the rows before it,
  never that no row came after. The outbox's delivery logs are held further by delivery
  receipts and operator records. An inbox source's latest events, or window history deleted
  around its guard, are held by nothing outside the database: an owner who deletes them
  denies service, and cannot pass off a forgery.
- **Which scope a request belongs to** is the outbox's word, as before
  (`EPIC4_DESIGN.md` §7). A fact goes to the scope of the message it matched. Its plan is
  bound by the relay's attestation, its scope is not.
- **Pruning ends compensation.** A delivered request pruned at retention can no longer be
  compensated, since its row is gone. Retention is that window, and the operator chooses it.

## 8. As built

Where the implementation settled what the design left open, or refined it.

### Step 2: the outbound checkers

- **`interlock.outbound_checks`** holds the five, exported from `interlock`, and listed among
  the built-in checkers whose hints are trusted with bucketed counts. A hint names sinks only
  as the plan's own requests name them (`FeedbackHint.sinks`, filtered like tables), and the
  five kinds have templates of their own (`sink_allowlist`, `outbound_count`,
  `payload_amount_cap`, `recipient_allowlist`, `outbound_tenant_isolation`).
- **A cap is never told**, nor an amount: a cap told is a target. `outbound_count` tells the
  plan's own count and its limit, bucketed.
- **Paths with `*`** (`interlock.types.values_at`) reach every item of a list, or every value
  of an object: `to.*.email`.
- **Two more payload rules made strict**, found while writing these. The schema subset's
  `enum` and `const` compared with Python's equality, under which `true` is `1`; they now
  compare as JSON does. And a field named like a credential is folded through NFKC before
  it is compared, so `ＡＰＩ_ＫＥＹ` is `api_key`.
