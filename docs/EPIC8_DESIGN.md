# Epic 8: key management, rotation and the security audit

**Status: design** on `feat/epic8-kms-rotation`. Builds on
[`EPIC7_DESIGN.md`](EPIC7_DESIGN.md). Every relay, inbox and operator signs with an Ed25519
key whose seed sits in a file the process reads. This epic lets the key live elsewhere,
lets an operator retire one without undoing what it signed, and audits that nothing
sensitive reaches a hash. Four parts:

1. **Remote signers** (§1). A `RemoteSigner` signs through an external service, a cloud KMS
   or an HSM, and never holds the private key. `HttpRemoteSigner` is the reference
   adapter; the daemon boots with remote signers for its relays, inbox, vacuum and
   receipt log.
2. **Registration, revocation and rotation** (§2). The operator log becomes the key
   registry and its revocation list. A revocation seals what the key had signed, so its
   history verifies forever, and from then on the database refuses anything new it
   signs.
3. **Rotation in a running daemon** (§3): parts resolve their signers when they open, and
   the supervisor reopens them on a reload.
4. **The security audit** (§4): `scripts/security_audit.py` crawls both stores' schemas
   and proves no sensitive value (webhook bodies and headers, trace context, secrets)
   reaches a plan's hash or an ARC1 statement.

Decided before any code:

- **One protocol, every signer.** Relays, the inbox, the operator log, the vacuum and
  agentgov's receipt log all sign through agentgov's `Signer` protocol: `alg`, `key_id`,
  `sign(message)`, `verify(message, signature)`. A `RemoteSigner` is one more
  implementation; nothing that signs changes.
- **The private key never enters the process.** A remote signer holds the key's name at
  the service, its version, its public half and a credential read from the environment.
  It verifies every signature it is given back under the pinned public key before
  returning it: a service that signs with another key, or answers with garbage, fails the
  call; it never yields an attestation that does not verify.
- **The operator log is the registry and the revocation list.** The configuration's
  keyrings (`[relays.keys]`, `[inbox.keys]`, `[operators.keys]`) are the roots of trust.
  Signed, anchored operator records add keys to them and revoke keys from them. Nothing
  the database holds can add a key.
- **History stays valid by construction, not by clock.** A revocation seals, inside the
  database transaction that installs it, the exact set of rows the key had attested, and
  the seal's digest is signed into the operator log and anchored into AgentGov. An
  attestation by a revoked key verifies if and only if its row is in the seal. No
  timestamp decides it: not the inbox's clock, which stamps events, and not the
  database's, which an owner can write.
- **The database enforces; the log decides.** The database refuses a new row attested by
  a revoked key (a relay's outcome, an inbound event, a fact) under a lock that orders
  every attested write against the revocation. The verifiers hold the database's
  revocations and seals to the signed log.
- **No new dependency.** The HTTP signer speaks JSON over `urllib`; the fake key service
  the tests and the soak run is `http.server`.

## 1. Remote signers

### 1.1 The abstraction

`interlock.signers.RemoteSigner` implements agentgov's `Signer` protocol for an Ed25519
key held elsewhere:

| | |
|---|---|
| `alg` | `ed25519` |
| `key_id` | derived from the public key, as ARC1 derives it: the same key, local or remote, has one id |
| `public_key()` | the pinned public half, an `Ed25519PublicKey` |
| `sign(message)` | `_remote_sign(message)`, then verified under the public key; `SignerUnavailableError` when the service fails or answers with a signature that does not verify |
| `verify(message, signature)` | under the public key, locally |
| `sign_async(message)` | `sign` on a worker thread, for a coroutine: the event loop never waits on the service |

A subclass implements two methods: `_remote_key()` (the version and public key to pin) and
`_remote_sign(message)`. An adapter for AWS KMS, Google Cloud KMS or Vault's transit engine
is one subclass each; the epic ships the HTTP one.

**Version pinning.** A remote key may have versions (a KMS rotates by adding one). A signer
pins one version when it is built and signs with that version only: every record and
attestation names `key_id` before it is signed, so the key behind an id cannot change
between the two. Rotation builds a new signer (§3).

### 1.2 `HttpRemoteSigner`

A minimal signing protocol, shaped like Vault's transit engine:

```
GET  {url}/v1/keys/{name}              -> {"alg": "ed25519", "version": 3,
                                           "public_key": "<hex>"}
POST {url}/v1/keys/{name}/sign          <- {"version": 3, "message": "<base64>"}
                                         -> {"version": 3, "signature": "<hex>"}
```

`Authorization: Bearer <token>` when a token is configured, read from an environment
variable and never from the configuration file. A non-2xx answer, a timeout, a malformed
body, a version other than the pinned one, or a signature that does not verify raises
`SignerUnavailableError`, and the part fails its step, as when a database is away: the
supervisor reopens it after a backoff.

### 1.3 Configuration

```toml
[signers.relay-kms]
type = "http"
url = "https://kms.internal:8443"
key = "interlock-relay"           # the key's name at the service
token_env = "INTERLOCK_KMS_TOKEN" # its credential: from the environment only
timeout_seconds = 5

[relay]
signer = "relay-kms"              # instead of key = "relay.key"
```

`[relay]`, `[inbox]`, `[vacuum]` and `[receipts]` take `signer` (a `[signers.<name>]`) or
`key` (a file), not both. The operator commands take `--signer NAME` beside `--key PATH`. A
remote signer's key must be registered for its role exactly as a file's is (§2.1), and the
part refuses to start otherwise.

### 1.4 Asynchronous by construction

The daemon never signs on its event loop. Each part steps on a thread of its own
(`docs/EPIC6_DESIGN.md`), so a signature's round trip delays the part that asked for it
and nothing else. `sign_async` serves a caller on the loop. The proofs: concurrent
`sign_async` calls against a key service that takes 200 ms finish in about one round trip,
with the loop ticking throughout; and the daemon, with every part signing remotely, passes
its tests and the soak.

## 2. Registration, revocation and rotation

### 2.1 The registry

A key's role is `relay`, `inbox` or `operator`. The keys of a role are:

- **roots**: the configuration's keyring for the role;
- **registered**: every `key.registered` operator record for the role, `{role, name, key}`,
  signed and anchored like every operator record.

A key is *trusted* for a role when it is a root or registered, and trusted keys verify the
role's attestations, subject to revocation (§2.3). Registration needs no database: it adds a
public key, and a database can only ever refuse.

A running part resolves an unknown key id by reading the operator log again (verified under
`[operators.keys]`), so a key registered while it runs is trusted at its first use.

### 2.2 Revocation, in two phases

A revocation is an operator action like any other (`docs/EPIC3_DESIGN.md` §6):

1. `operator.intent`, action `revoke-key`: the role, the key id, the reason.
2. The database, under the intent's hash: `interlock.key_revoke` (PostgreSQL), or the same
   in the SQLite store. In one transaction, holding the keys lock exclusively (§2.4), it
   records the revocation and seals the key's rows (§2.3).
3. `operator.applied`, with the seal: `{count, digest}`.

A process killed between the phases is resolved like any operator action: the revocation
row that carries the intent's hash says it was applied.

An operator key is revoked in the log alone (§2.5): it signs nothing the database holds.

### 2.3 The seal

Let *K* be a relay or inbox key, and *A(K)* the rows in the database whose attestation names
*K*:

| role | rows | reference | row hash |
|---|---|---|---|
| relay | outcome rows of the delivery logs | `message_id, seq` | the row's `event_hash` |
| inbox | inbound events | `source, seq` | the event's `event_hash` |
| inbox | facts | `source, event_seq` (an event has one fact at most) | SHA-256 of the fact's attestation |

At the revocation, at the instant *t_R* of its transaction, the seal is
*S(K) = A(K) at t_R*: the references and row hashes of every row *K* had attested that is
still in the database. It is stored beside the revocation, row by row, and its digest

> *D(K)* = SHA-256( frame( *k₁*, *r₁*, *h₁*, *k₂*, *r₂*, *h₂*, … ) )

over the members `(kind, reference, row hash)` in byte order, where `frame` is the
length-prefixed framing every Interlock hash uses (`interlock.deliveries.frame`: no field can
run into the next), is signed into the applied record with its count, and anchored. The
database computes it (`interlock.key_revoke` sorts with `COLLATE "C"`, byte order) and
`interlock.keys.seal_digest` recomputes it.

**The write side.** Every write of an attested row takes the keys lock shared and, holding
it, refuses an attestation by a revoked key. The revocation takes it exclusively. So every
row attested by *K* either committed before *t_R*, and is in *A(K)* at *t_R*, unless a
vacuum pruned it earlier; or tried after, and was refused. The lock is a transaction-scoped
advisory lock on PostgreSQL, the file's write lock on SQLite.

**The verification.** An attestation *a* of a row, by key *K*, holds when:

> σ(*a*) verifies under *K* ∧ *K* is trusted for the role ∧ (*K* is not revoked ∨ ref(*a*) ∈ *S(K)* with the same row hash)

and the seal holds when the stored *S(K)* hashes to the signed *D(K)*, and every member
whose row the database no longer holds was pruned under a checkpoint: its message has a
tombstone, or its event was pruned under one. A row attested by *K* outside the seal was
written around the database's refusal; a seal that does not hash to its signed digest was
edited; a member gone without a tombstone was deleted around a vacuum.

**Why not a clock.** An inbound event's time is the inbox's own; an outcome row's is the
database's, which an owner can write. A seal is a commitment made, signed and anchored at
the revocation: no row can be dated into it afterwards, and none taken out.

**Pruning.** A row the vacuum pruned before *t_R* was verified when it was pruned, while
*K* was trusted, and the checkpoint that pruned it is anchored. A sealed row pruned after
*t_R* leaves a tombstone. Neither needs the key again.

**Size.** *S(K)* holds only what the database still holds at *t_R*: with a vacuum running,
the live outbox's rows and the inbox's recent events, not the key's whole history.

### 2.4 Enforcement points

| where | PostgreSQL | SQLite |
|---|---|---|
| a relay's outcome | `interlock.relay_outcome` | `SqliteOutboxStore.outcome` |
| an inbound event | `interlock.inbox_record` | the store's `record_event` |
| a fact | `interlock.inbox_match` | the store's `record_fact` |
| a revocation | `interlock.key_revoke` (exclusive) | the store's `revoke_key` |

A relay also checks its own key before each claim, so a revoked relay stops before it calls
a sink rather than after. An outcome refused after the call (the revocation landed between)
is not lost: the lease runs out, the next relay calls again, and the sink's idempotency key
answers with what it already did.

### 2.5 Operator keys

The operator log orders itself. A record signed by operator key *K* holds when *K* is a root,
or a `key.registered` record before it registered *K*, and no `operator.intent` to revoke
*K* precedes it. Another operator revokes *K*: an operator does not revoke their own key,
so every revocation is signed by a key that still signs, and the last operator key is never
revoked, so someone always can. A log written on by a revoked key is named record by record.
`OperatorLog` refuses to open with a revoked or unregistered key.

### 2.6 Rotation

A planned rotation, with no refusal at any point:

1. a new key *K'* (a version at the key service, or a file);
2. `key.registered` for *K'*: both keys are trusted;
3. a reload: each part reopens and signs with *K'* (§3);
4. the revocation of *K*: its rows sealed, its new ones refused.

After a compromise, revoke first: a part still holding *K* fails its next claim or write,
the supervisor reopens it, and it opens with whatever key the service serves now.

### 2.7 Storage version 7

| | SQLite | PostgreSQL |
|---|---|---|
| revocations | `_interlock_key_revocations` | `interlock.key_revocations` |
| seals | `_interlock_key_seals` | `interlock.key_seals` |

`key_revocations (key_id, role, revoked_at, authority, count, digest)`;
`key_seals (key_id, kind, ref, row_hash)`. Both append-only: a trigger refuses an update or
a delete, as for the legacy set. Readable by relay, inbox, settler and audit roles, written
only through `interlock.key_revoke` by the installer. Version 6 upgrades in place with
`interlock install`.

### 2.8 Verification

`verify_attestations`, `verify_inbox`, the settler, the vacuum and the inbox's binding take
keyrings that carry revocations and seals. `verify_keys` holds the database to the log:
every revocation row carries an applied `revoke-key` intent's hash, and the seal hashes to
the digest that record signed; every applied revocation is in the database; every
registration record is signed by an operator trusted at its position.

## 3. Rotation in a running daemon

- **Signers resolved at open.** The daemon opens and checks every key when it is built, so a
  key that cannot be used stops it before it starts. After that a relay and the inbox open
  their key again each time they open, and the vacuum at each run: a part reopened signs
  with the key its configuration points at then (a new version at the key service, or a new
  file). A key is refused at open when the operator log does not trust it for the role:
  never registered, or revoked (`interlock.wiring.operator_signer` for the vacuum's).
- **Reload.** `InterlockSupervisor.reload()`, and `SIGHUP` to `interlock daemon`: each
  service finishes its step and opens again (`Service.reopen`); its next step stays where
  its pace put it, so a reload never runs an hourly vacuum early. The inbox opens its new
  self behind its listener, which never closes: a webhook already taken is answered by the
  inbox that took it, every later one by the new. A service backing off is opened at once.
  One that cannot open again fails as at any reopen, backs off and retries, and the reload
  says why. Engines and agents are untouched.
- **Fresh keyrings.** A running part's keyrings resolve a key id they do not hold among
  the keys the operator log registers (`interlock.wiring.live_keyring`), reading the log
  again only when it changed: a key registered while the part runs is trusted at its first
  use, an engine's included. The revoked keys are read once a pass, one short query, and
  each seal once, when its key is first seen revoked: a seal never changes
  (`interlock.keys.Seals`).
- **A key revoked under a running part.** A relay asks before it claims, the inbox at each
  matching pass; each finds its key revoked, fails, and opens again with the key it is
  given then, which is how a compromise needs no reload (§2.6). Until it does, the database
  refuses what the old key would write, and the inbox answers webhooks 503, which vendors
  send again. `interlock relay` and `interlock inbox serve`, which hold one key for their
  life, stop with exit status 3.

## 4. The security audit

`scripts/security_audit.py` answers one question about both stores: does any sensitive value
reach the input of a plan's hash, a request's, a delivery log's, an ARC1 statement, an
inbound statement or a fact's?

1. **Crawl.** Install both stores fresh and list every table and column
   (`sqlite_master` and `pragma table_info`; `information_schema.columns` and
   `pg_catalog` for the `interlock` schema).
2. **Canaries.** Run one scenario through each store, the daemon's parts as they run in
   production: plans traced with canary trace ids, requests delivered, webhooks sent with
   canary bodies, canary headers and canary trace context, signed with a canary secret.
3. **Taint.** Record the exact input of every hash and signature the run makes, through the
   functions that compute them.
4. **Assert.** No canary, and no SHA-256 of one, appears in any recorded input of an
   `EffectPlan`, `Effect`, `OutboundRequest`, delivery-log, ARC1 or fact hash. Each canary
   lands only in the columns made to hold it (the event body, the trace tables), which the
   crawl locates; no other column holds one. The inbound event statement commits to the
   body's hash and not the body; the audit lists that commitment as the one digest of a
   sensitive value a statement may hold.

It exits 0 when clean and prints, column by column, what holds a canary and which hash
reads it.

## 5. The soak

The soak's relays, inbox and vacuum sign through `HttpRemoteSigner` against a fake key
service in the soak's process. Mid-load, the operator rotates the relay key: the service
adds a version, the desk registers it, the daemon reloads, and the desk revokes the old one.
A stale relay that kept the old key then tries to record an outcome, and is refused. A new
claim, **keys rotate**, holds when every attestation by the old key is sealed or was
refused, every outcome after the revocation is attested by the new key, the seal hashes to
its signed digest, and the claims of Epic 6 and 7 still hold across the rotation.

## 6. Proofs

- Remote signers: signatures interchangeable with a local key's; a service that signs with
  another key, answers with garbage, times out or refuses is a `SignerUnavailableError`,
  never an attestation; concurrency off the event loop; the daemon booted with remote
  signers for every part.
- The registry: a registered key trusted from its record; one registered by no trusted
  operator not; operator-key revocation positional.
- Revocation on both stores: the seal exactly what the key signed; the refusal of every new
  attested write; the race of a write against a revocation; history verifying; a row
  forged after the revocation named; a seal edited, a member deleted, named; crash between
  the phases resolved; upgrade from version 6.
- The audit, on both stores, and its own canaries proven to reach their columns.
- The soak (§5); the mutation pass.

## 7. Sequence

1. This design.
2. Remote signers: the abstraction, the HTTP adapter, configuration, the parts.
3. The registry and revocation: storage version 7, both stores, verification.
4. Rotation in the daemon: signers at open, reload, fresh keyrings.
5. The security audit.
6. The soak: remote signers and a rotation under load.
7. The documents, the mutation pass and the whole suite.

## 8. Limits

- **No expiry date.** A key is valid until revoked; a `not_after` would be a revocation the
  database applies on its own clock, which the seal argument does not cover.
- **One operator decides.** A registration or a revocation takes one operator's signature.
  An operator key in the wrong hands can register a relay key or revoke the honest ones;
  quorum signing is future work.
- **Signing is as available as the key service.** A part whose signer cannot be reached
  fails its step and retries; it does not fall back to a local key.
- **The receipt log's key** can be remote, but rotating it starts a new receipt log: ARC1's
  log is signed by one key.
