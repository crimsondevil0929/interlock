# Epic 4: delivery receipts, rate windows, ledger-integrated compensations

**Status: design, approved; built step by step on `feat/epic4-zero-trust`.** Builds on
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
