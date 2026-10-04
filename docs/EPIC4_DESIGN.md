# Epic 4: delivery receipts, rate windows, ledger-integrated compensations

**Status: built**, step by step on `feat/epic4-zero-trust`; §7 records where the build
settled what the design left open. Builds on
[`OUTBOX_DESIGN.md`](OUTBOX_DESIGN.md) (Epic 2) and [`EPIC3_DESIGN.md`](EPIC3_DESIGN.md),
and closes the outbox specification's last open items: delivery receipts (§9 there) and
rate windows (§5.3 there), with the ledger policy for compensations. Decided before any
code:

1. **ARC1 v1.1**, in agentgov 0.4.0: a delivery receipt is a document type of its own in
   the same receipt log, not an action receipt bent to fit. agentgov is branched and
   released separately; Interlock depends on the branch's commit until 0.4.0 is on PyPI.
2. **Relays sign, always.** Every outcome a relay records carries its Ed25519 attestation;
   a relay without a registered key does not start.
3. **A compensation that delivers credits the agent back the `cost_per_call` the ledger
   charged for the request it undid**, never a customer amount: AgentGov budgets compute
   and API spend, not the money a sink moves.

---

## 1. Delivery receipts (ARC1 v1.1)

An action receipt proves what was *authorized and committed*. A delivery receipt proves
what was *sent*, and what the sink answered. Two parties see those two things, so the
delivery receipt carries two signatures.

### 1.1 The attestation: the relay's, at the instant of the answer

When a sink answers, the relay signs what it saw with its own Ed25519 key, before
recording the outcome:

```
ARC1/attestation/v1\n || canonical({
  "v": "ARC1-attestation",
  "request":  {message_id, effect_id, sink, operation, payload_hash, idempotency_key},
  "outcome":  {attempt, result, status_code, response_digest, remote_ref},
  "sig":      {alg, key_id}
})
```

`result` is `delivered`, `retryable`, `permanent` or `unknown`. The signature, with its key
id, is stored in the delivery-log row the outcome writes (schema version 4, §2), so the
statement is durable the moment it is made and part of the message's hash-linked log. The
relay never holds the receipt log or its key: a receipt log has one writer, the engine's
process, and relays run elsewhere, many at a time.

### 1.2 The delivery receipt: the log's, asynchronously

The process that holds the receipt log (the engine's) later wraps each delivered outcome
in an `ARC1-delivery` document, signs it with the log's key, and appends it to the same
log, where the witness cosigns it with everything else (Step 5):

| Field | |
|---|---|
| `v` | `"ARC1-delivery"` |
| `receipt_id`, `issued_at`, `issuer` | as an action receipt's |
| `action` | `{receipt_id, log_id, leaf_index, leaf_hash}`: the action receipt of the plan that committed the request |
| `request` | `{message_id, effect_id, sink, operation, payload_hash, idempotency_key}` |
| `delivery` | `{attempt, status_code, response_digest, remote_ref, delivered_at, log_seq, log_hash}` |
| `attestation` | `{alg, key_id, signature}`: the relay's signature of §1.1, over `request` and the outcome fields of `delivery` |
| `anchors` | `{log: {log_id, leaf_index}}`, signed, as in an action receipt |
| `sig` | the log's |

### 1.3 The binding

- **To the action receipt:** `action.leaf_hash` is `SHA-256(0x00 || canonical(receipt))`,
  the action receipt's own Merkle leaf hash: it binds its exact signed bytes. With both in
  one log, one checkpoint and two audit paths prove the action receipt is at
  `action.leaf_index`, unaltered, and that the delivery came after it.
- **To the request adjudicated:** `request.effect_id` and `request.payload_hash` are the
  outbox row the action receipt's `row_root` commits to; disclosing that row proves the
  payload delivered is the payload the checkers judged.
- **To the delivery log:** `delivery.log_seq` and `log_hash` name the hash-linked row that
  recorded the outcome, and carries the same attestation.
- **To the relay:** the attestation verifies under a registered relay key, over fields the
  log could not change without breaking it.

Re-pointing a delivery receipt at another plan, another payload, another log row or
another answer breaks a signature or a hash.

### 1.4 In agentgov

- `Attestation` and `DeliveryReceipt` documents, strict like every ARC1 document, under
  domains `ARC1/attestation/v1\n` and `ARC1/delivery/v1\n`.
- `ReceiptLog` holds both kinds. A leaf is a document's own canonical bytes, so every
  existing leaf, root and checkpoint is unchanged; a v1.0 verifier simply refuses a
  `ARC1-delivery` leaf it does not understand.
- `verify_bundle` verifies a delivery bundle: schema, the log's signature, the relay's
  attestation (`relay_keys`), inclusion, witness, and, given the action receipt's bundle,
  the binding of §1.3.
- `RECEIPTS.md` §13, and test vectors for every case above.

## 2. Schema version 4: attested outcomes, and ghost deliveries

- `outbox_attempts.attestation`: the relay's signature, `{alg, key_id, signature}` as
  canonical JSON. A row with an attestation hashes under `interlock-outbox-event-v3`,
  which frames it; rows without one hash as before, so every log written under 3 still
  verifies.
- `relay_outcome` takes the attestation; the link trigger refuses an outcome row
  (`delivered`, `retryable`, `permanent`, `unknown`) without one.
- `outbox_epochs` gains version 4: outcome rows older than it are version 3's, unsigned,
  counted as legacy.
- `[relays.keys]` names each relay's public key; `[relay] key` is a relay's own key file.
  A relay refuses to start without a key registered there.
- **Ghost deliveries are named.** Epic 3 left one forgery open: a `delivered` row written
  around Interlock, hash-linked perfectly, is indistinguishable from a real one. From
  version 4, `interlock outbox verify` reconstructs each outcome's attestation from the
  outbox row and the log row, and names every outcome without a valid signature under a
  registered relay key: a delivery no relay reported.
- Upgraded in place from 3, tested against version 3's frozen SQL.

## 3. Rate windows

A checker sees one plan. A sub-threshold attacker sends hundreds, each under every
per-plan limit. A window measures a plan *with its history*: "at most 10 emails per tenant
per hour", "at most $10,000 of refunds per agent per day".

### 3.1 What a window is

`RateWindow(name, span, limit, measure, per)`:

- `measure`: `Requests(sink, operation)` counts requests; `RequestSum(sink, operation,
  field)` sums a payload amount; `RowSum(table, column, measure="inserted"|"net")` sums
  rows, measured as `CrossEffectAgreement` measures them; `Plans()` counts plans.
- `per`: `"scope"` (the plan's agent), `"tenant"` (each request's or row's tenant), or
  `"global"`. Windows compose: per tenant *and* globally, so spreading across tenants buys
  nothing.

### 3.2 History beside the commit marker

Each committed plan's contribution to each window is written in the stage's own
transaction, beside the commit marker and bound to it (PostgreSQL: a foreign key to
`interlock.stages`, through a function gated by the stage's token, as `enqueue` is;
SQLite: a deferred foreign key to `_interlock_commits`). History exists exactly when the
commit does, for every engine process alike. The escrow chains are not used: they are
per-process files of hashes, not amounts. Agent statements can neither write window
history nor read it (it would show other tenants' activity).

### 3.3 Exact under concurrency

A `REPEATABLE READ` stage cannot see what committed after its snapshot, so a count taken
inside it, or before it, races: two plans each see 9 emails, and both commit the 10th.

- **PostgreSQL.** After the stage is measured, it takes a transaction-scoped advisory lock
  for each `(window, key)` it contributes to, in sorted order (no deadlock), held to
  `COMMIT`. It then reads history through a token-gated function on a separate `READ
  COMMITTED` connection, which sees every commit. No other stage can commit to those keys
  while the lock is held, so the count is exact. Stages contending for one key serialize
  from measurement to commit, milliseconds; others take no lock.
- **SQLite.** The stage holds the database's write lock from `BEGIN IMMEDIATE`, and its
  snapshot is the latest: the count is exact as is.

### 3.4 Adjudication and replay

The measured history and the plan's contribution are part of the diff, so
`DIFF_COMPUTED` covers them and replay reads them back. A built-in checker refuses a plan
that would take a window past its limit; the agent is told which window, never the counts.

## 4. Compensations credit the agent (Step 5)

The process that holds the ledger (the engine's, beside the receipt log) settles each
delivered message: issues its delivery receipt and, for a compensation, posts an AgentGov
`refund()` crediting the original's scope with the `cost_per_call` the ledger charged for
the original request. Relays stay read-only on the ledger. A credit is posted only when the
compensation's delivery is attested by a registered relay and the original's `compensated`
row carries a signed operator intent naming that compensation. Receipt, then credit, then a
settlement row: a crash between any two is resumed without a second receipt or credit.

## 5. Proofs

- Delivery receipts verify through agentgov's own verifier; every tampering of §1.3 fails it.
- The relay's kill matrix holds with attestations; each forged outcome is named.
- Plans racing into one window from many connections commit exactly up to its limit, on
  both stores; without the lock they would not (a mutation shows it).
- A sub-threshold attacker is stopped at the window, whatever per-plan limits it passes.
- The settlement step, killed between receipt, credit and record, settles each message once.
- Every mechanism has a test that fails without it.

## 6. Sequence

1. This document.
2. ARC1 v1.1 in agentgov, branch `feat/arc1-v1.1-delivery`, version 0.4.0; Interlock
   depends on that commit until the release.
3. Schema version 4, relay attestations, ghost-delivery verification.
4. Rate windows.
5. *(after agentgov 0.4.0 is published)* Settlement: delivery receipts and credits.
6. Documentation, mutation pass, final verification.

## 7. As built

Where the implementation settled what the design left open, or refined it.

### Step 3: attested outcomes

- **The relay attests as it records.** `Relay(signer=...)` is required and must be
  Ed25519 (an HMAC key verifies only for whoever holds it, so anyone who could check an
  attestation could make one). The relay signs inside its outcome step, from the lease and
  the result, so no path records an outcome without one.
- **`interlock relay` starts only with a registered key**: `--key`, else
  `INTERLOCK_RELAY_KEY`, else `[relay] key`; one missing, unreadable, or absent from
  `[relays.keys]` is refused with exit 2 before anything is claimed. `interlock keygen
  --role relay|operator` writes a key and prints the line that registers it
  (`interlock operator keygen` remains).
- **The database checks the shape.** An outcome row's attestation must be exactly
  `{"alg":"ed25519","key_id":<16 hex>,"signature":<128 hex>}`, canonical: PostgreSQL's
  link trigger raises `IL008`; SQLite's `_interlock_log_attested` aborts. Verification
  checks the signature.
- **A relay of an older version left running cannot record an outcome.** On PostgreSQL
  the ten-argument `relay_outcome` is gone, so it records a call and never its outcome;
  the next relay finds the call lost and makes it again. On SQLite it records nothing:
  the link trigger hashes the attestation through a function only version 4 registers.
- **Legacy, pinned.** Outcomes recorded before version 4 carry no attestation. As first
  built, they were told from forgeries by timestamps, which left one gap: an outcome forged
  into a log version 4 never wrote to, dated early, passed for version 3's. The gap is
  closed by the legacy set (below): an unattested outcome is legacy only if the install
  that brought version 4 recorded it, and a signed install vouches for that record.
- **A copied attestation is caught twice.** On another call its signature fails; on the
  same call it is a second outcome, which `verify_delivery_log` names.
- `outbox show` names the relay that attested each outcome; `outbox verify` counts the
  attested outcomes, or says attestations went unchecked when `[relays.keys]` is absent.
- Upgrades from versions 2 and 3 are tested against each version's frozen code:
  PostgreSQL's SQL (`tests/outbox_v2.py`, `tests/outbox_v3.py`) and SQLite's module
  (`tests/sqlite_outbox_v3.py`).

### Step 4: rate windows

- **The API.** `RateWindow(name, span, limit, measure, per)`, with the measures
  `Requests(sink, operation=None)`, `RequestSum(sink, operation, field)`,
  `RowSum(table, column, rows="inserted"|"net")` (`rows`, so as not to read as the
  window's own `measure`) and `Plans()`. A limit is an integer, a `Decimal` or a decimal
  string, never a float. A name is a lowercase identifier: it is what the refused agent is
  told. `EscrowEngine(windows=...)` adds one built-in `RateWindowCheck` per window, refuses
  two windows of one name, and refuses windows on a substrate that keeps no history. The
  configuration file takes them as `[[windows]]`, checked against its `[[sinks]]` and
  `[[tables]]`.
- **What a plan adds is positive, or refuses it.** Per key, only what is above zero is
  added. A request with no number at the field, or a negative one; a row with no number in
  the column; an inserted row with a negative one: each refuses the plan rather than be
  guessed at. Net is taken per window key, so moving money between rows of one key adds
  nothing; a net decrease adds nothing and takes nothing back. SQLite hands a `NUMERIC`
  column back as a float, read at the precision SQLite printed it with.
- **A request's tenant is the plan's to declare,** so a per-tenant window alone can be
  spread across invented tenants. Beside a per-scope or global window it buys nothing: the
  tests show the spread refused by the second.
- **A plan that adds to no window locks nothing and reads nothing.** The repair search
  measures each candidate as `execute` would, so a proposal fits the window.
- **The diff carries the measures** (`EffectDiff.windows`, each a `WindowMeasure`: window,
  key, history, amount), hashed only when present, so every diff measured before windows
  keeps its hash. The check fails closed on a diff with no measure for a key the plan adds
  to, or with another amount than the plan adds.
- **PostgreSQL**, in schema version 4 (folded in rather than a version 5: neither is
  released): `interlock.window_ledger` (a foreign key to `interlock.stages`, amounts above
  zero); `window_lock(bigint[])`, taking each distinct lock in ascending order;
  `window_totals(...)`, which refuses a stage's transaction and anything but `READ
  COMMITTED` (`IL009`, a protected statement to the agent); `window_add(token, ...)`, gated
  by the stage's token as `enqueue` is. A key's lock is 64 bits of SHA-256 over the window
  and the key. The second connection is opened before the locks are taken, so connecting
  is not part of anyone's wait, and closed once it has read, so by its commit a stage holds
  one session again (the crash tests' lost-COMMIT cases count on that). A lock wait obeys
  the stage's lock timeout: contention past it is a `StageConflictError`, which the agent
  is told may succeed if resubmitted. Auditors read the ledger; stage and relay roles
  cannot.
- **SQLite**: `_interlock_windows`, created with the commit-marker table, its rows bound
  to the marker by a deferred foreign key; read inside the stage, written by `commit()`
  just before the marker. The authorizer refuses a plan's statements any read or write of
  it, with `enforce_table_access=False` too: the one table a plan may not read.
- **The agent is told** `rate_window`, the window's name (only from the built-in check,
  only as an identifier), and a tenant only if the plan declared it; never what the window
  holds or its limit.
- **Proofs.** Eight plans racing into a window of four commit exactly four, on both
  stores; on PostgreSQL, with the lock removed, more than four commit. Both crash harnesses
  run every plan through two windows and check, at every kill point, that window history
  exists for exactly the plans that committed, and is bound to their markers.
- **Left open:** history is never pruned. Rows older than the longest span are read by no
  check, but they are a record of what each plan added; removing them is the operator's
  call.

### The legacy set: what came before, vouched for

- **Recorded once.** The install that first brings version 4 records, in its own
  transaction and with the delivery log held still, every row written before the proof
  its kind now carries: outcomes without a relay's attestation, operators' rows without an
  authority (version 2's). `interlock.outbox_legacy` on PostgreSQL,
  `_interlock_outbox_legacy` on SQLite: each row's message, position and event hash, which
  binds everything the row says. The capture runs only while version 4's epoch does not
  exist yet; once it does, the table is sealed against inserts, updates and deletes, so a
  later install never sweeps a forgery into it.
- **Vouched for.** `interlock install` under `[operators]` signs the set's digest and size
  into its `operator.installed` record, from the set its own transaction read; one edited
  in between is not signed. The first record that carries a legacy set pins it: a later
  install signs it again only unchanged, and `verify_operators` names a record that
  vouches for another.
- **Held to it.** An unattested outcome, or an unsigned operator row, is legacy only if it
  is in the set exactly as recorded, and the set is the one vouched for. Any other is
  named, however it is dated. A set edited since its vouch, or naming a row its log no
  longer holds as recorded, is named. Without any vouch, legacy rows rest on the
  database's word, and verification says so, once, as a finding.
- **What remains** is what any upgrade has: the set vouches for the database as it stood
  when version 4 was installed. A forgery made before that is in it; nothing can be added
  after.
- A fresh install records an empty set, so on a database that never ran an older version,
  every outcome must be attested and every operator row signed.

### Step 5: settlement

- **`Settler`**, in `interlock.settlement`, runs in the process that holds the receipt log
  and the ledger (the engine's: the receipt log admits one writer, a SQLite ledger one
  governor). It reads the outbox as a settler role (`install(settler_roles=...)`, which
  may read the outbox and call `interlock.outbox_settle`, nothing else) or a SQLite store
  opened with `writes=SETTLER`.
- **The delivery receipt** binds to the action receipt the plan that committed the request
  was issued, found through the escrow chain (its `COMMITTED` record names the receipt) and
  read from the log. A compensation binds to its original's plan: the plan carried and the
  checkers judged the compensation; an operator's signed intent only set it off. A plan
  with no action receipt (receipts off, or a commit recovered after a crash, which issues
  none) is settled without one, and the settlement says so.
- **The credit** is AgentGov `refund()` to the original's scope of the original's
  `cost_per_call`, the amount its plan was charged for it, under a memo naming the
  compensation and the charge it reverses. The charge is the plan's reverse-anchor spend,
  whose memo names its commit record; the credits for one plan never exceed it. The
  authority is checked in full: the original's `compensated` row carries the hash of a
  signed intent, under a registered operator key, of action `compensate`, naming this
  compensation's message, sink, operation, payload hash and idempotency key, and recorded
  applied with that row.
- **Decided, or deferred.** A credit is refused for good, and the request settled without
  one and saying why, when there is no ledger, the original cost nothing, the plan was
  never charged, or the authority does not hold. It is deferred, the request left
  unsettled and reported, while the decision may still change: the intent behind the
  compensation has no outcome yet (the next operator command resolves it), or no operator
  log is configured. A delivery no registered relay attested is never settled.
- **Exactly once.** Each step looks for what a crashed run left of it: the log's delivery
  receipt for the message, the ledger's credit for the compensation; the settlement row
  is written once, for a delivered request only, never changed. Killed after the receipt,
  after the credit, or after the row, on either store, the next run settles every message
  once: `tests/test_settlement_crash.py`.
- `verify_settlements` holds the three to each other: every settlement's receipt in the
  log, for its message, attested and bound; every delivery receipt named by a settlement;
  every credit named by one, once, of its original's cost.

### Step 6: the mutation pass

Every mechanism of this epic was removed in turn, and a test failed for each: 36 of 36.
The relays' attestations (the database's refusal on both stores, what the relay signs, the
verifier's signature check, the command's key check); the rate windows (the read and the
write closed to plans, history written with the commit, the token and the read's gate on
PostgreSQL, the advisory lock, the limit, the fail-closed check, the diff's hash, the
feedback's name, the repair's measure); the legacy set (recorded once and sealed on both
stores, the install's two refusals, the records' agreement, the vouch, membership, a row
rewritten); and settlement (the receipt and the credit a crashed run left, reused; the
credit's amount, its wait for an intent's outcome, the relay's signature, the charge; only
a delivered request settled, on both stores; a double credit named). One mutation first
survived, a settler that skipped the signature check, since the test's forger used an
unregistered key; a test with a registered relay's signature copied from another delivery
now kills it.
