# Changelog

All notable changes to Interlock are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
from 1.0.0 onward. Before 1.0.0, minor versions may include breaking changes.
Releases before 0.1.2 are described by their tags and commit history.

## [Unreleased]

### Added (Epic 6: the runtime daemon, and the system under load; `docs/EPIC6_DESIGN.md`)

- **`EscrowRuntime`, configured whole.** `substrate=` takes any substrate in place of the
  SQLite path, and `windows=`, `inbox=` (with `runtime.facts(scope)`), `sinks=`,
  `receipts=` and `anchor=` reach the engine unchanged. `EscrowRuntime.from_config(config,
  scope_id=...)` builds the runtime `interlock.toml` describes: its substrate, tables,
  acknowledged cascades, sinks, windows, inbox keys, ledger (claim and settle with
  `[engine] same_transaction`), chain and receipt log.
- **`InterlockSupervisor`** (`interlock.supervisor`): every part of Interlock in one
  process, on one asyncio event loop. An `EnginePool` of workers, each with its own
  engine, substrate, governor and escrow chain, retrying a plan that lost a race with
  jittered backoff; `RelayService`, `InboxService` (the HTTP receiver and the matcher),
  `SettlerService` and `VacuumService`, each stepping on a thread pool of its own and
  reopened after a doubling backoff when it fails. Agents are coroutines or threads
  given an `AgentContext` (`execute`, `facts`, `plan`, `sleep`, `stopping`). Shutdown runs
  in order with every step bounded, and never cuts a stage, a delivery, a webhook or a
  vacuum in half; a second signal skips the drains, and gives the parts a second to
  close. `status()` and `GET /healthz` report every part.
- **`interlock daemon`** (`--app module:callable`, `--listen`, `--relay-key`,
  `--inbox-key`), and `build_supervisor(config, application)`: the supervisor
  `interlock.toml` describes, each part connecting as its own role. New sections:
  `[engine]` (workers, the stage role's database, the chain, the settle cost, the ledger,
  `same_transaction`, `conflict_retries`, stage and lock timeouts), `[receipts]`,
  `[settler]` and `[daemon]`; `[vacuum]` gains `every_seconds`, `retain_seconds`,
  `database` and `key`.
- `InboxServer`: the inbox's HTTP server, which `interlock inbox serve` and the daemon
  share, with `GET /healthz`. `Settler(chain=[...])` reads several engines' chains.
- `deliveries.consistent(source)`: every read inside sees one state of the database (a
  `REPEATABLE READ` snapshot on PostgreSQL, a read transaction on SQLite). The vacuum's
  survey and every verifier read through it.
- **The soak**, `scripts/live_stress_test.py`: the whole daemon for minutes against a live
  PostgreSQL (`--docker` or `--dsn`), under a faulty Stripe-shaped API, duplicated, early,
  noisy and forged webhooks, contending agents and a refunding operator. It proves nine
  claims from the database, the ledger and the logs, and exits non-zero on any that fails.
  `tests/test_soak.py` runs it scaled down; `tests/test_daemon.py` runs every part from
  `interlock.toml` on SQLite, and `interlock daemon` until `SIGTERM`.
- `docs/ESCROW_SPEC.md`: §5, the architecture as built, and its conformance section,
  rewritten for 0.5.0, requirement by requirement.

### Fixed (Epic 6: found by the soak and by CI, each with a test that fails without its fix)

- **The vacuum refused nearly every run under live webhooks.** Its survey read the
  inbox's events, heads, facts and the outbox in separate statements; a fact recorded in
  between was read without its event, and the survey took it for tampering. It now
  reads one snapshot, as do `verify_inbox`, `verify_settlements`, `verify_operators` and
  `verify_attestations`, and the SQLite store's `snapshot()`.
- **Compensations settled for good without their credit.** The settler read its own
  governor's view of a shared PostgreSQL ledger, as of when it opened, and found no
  charge for plans other governors had charged since. It refreshes before every pass,
  and a charge committed as a claim and not yet booked holds the compensation until it
  is, instead of counting as no charge.
- **Deliveries settled for good without their receipt.** In one process a relay can
  deliver, and the settler run, between a plan's commit and its action receipt. A
  receipt the commit names and the log does not hold yet now holds the delivery until it
  is issued.
- `OperatorLog` anchored records a second time from a stale view of a shared ledger. It
  refreshes first; a ledger it cannot read leaves the records to the next open.
- `[operators] ledger` took a keyword connection string for a file path.
- The supervisor waited out its drain bound for queued plans no worker was left to take.
- **The inbox's server could take half a minute to start.** `http.server` resolves the
  address it binds to a name, which nothing reads; where the resolver times out (GitHub's
  macOS runners: 35 seconds, in every new process), `interlock daemon` and `interlock
  inbox serve` waited that long before taking a request. The server binds without the
  lookup.

### Changed (Epic 6)

- The live-model gauntlet moved from `scripts/live_stress_test.py` to
  `scripts/live_gauntlet.py`, unchanged; the soak took its name.
- `EscrowRuntime.substrate` is typed `ShadowSubstrate`, since the runtime takes any.
- The daemon's vacuum keeps one governor between runs, caught up at the start of each,
  instead of reading the whole ledger every run; a run that finds the operator log in use
  tries again after a second.

### Added (Epic 5: the zero-trust inbox, cryptographic compaction, the last checkers; `docs/EPIC5_DESIGN.md`)

- **The vacuum** (`interlock.vacuum.Vacuum`, `interlock vacuum`; schema version 5). Prunes
  what no check will read again: stages whose every message is delivered and settled, or
  cancelled, past `[vacuum] retain_days`; rate-window history past the longest
  `[[windows]]` span plus a margin; and each inbound source's prefix of events past the
  retention whose facts were all consumed. Everything is verified first (delivery logs,
  relay attestations, operator records, earlier checkpoints, the inbox under
  `[inbox.keys]`), and what does not verify is kept and reported. A *checkpoint* commits
  to what goes: tombstones (each message's log head, settlement and price), folds over
  the tombstones, the window rows and the inbox's facts, each source's cut, and the
  AgentGov ledger's head. It is signed in an operator intent, anchored into AgentGov, and
  only then is the act run: one database transaction recording the checkpoint,
  recomputing every fold from what the database holds, and deleting. The guards admit no
  other delete. Checkpoints chain by `seq` and `prev`; `verify_operators` holds each to
  its signed intent; verifiers account for pruned history by its tombstones and cuts; a
  window reaching back past pruned history fails closed. `--archive` writes the pruned
  rows first and `--verify-archive FILE` proves them against the checkpoint.
- **The zero-trust inbox** (`interlock.inbox`, `interlock inbox serve | match | list |
  verify`, `interlock keygen --role inbox`). Verifies each vendor's webhook signature
  (Stripe's `Stripe-Signature`, Standard Webhooks, SendGrid's ECDSA Signed Event Webhook)
  within a timestamp tolerance, with secrets only in the inbox's environment; records each
  event once in its source's hash-linked log, attested with the inbox's Ed25519 key; binds
  it to the delivered request whose relay-attested `remote_ref` it names (never to two
  messages' deliveries, never to a delivery no registered relay attested); and attests the
  binding as a fact. A fact's fields are a typed projection (ids, codes, integers,
  decimals, currencies, booleans, instants): no vendor free text reaches the agent.
  `EscrowEngine(inbox=keys)`, `engine.facts(scope)`, `PlanBuilder.consume(fact)`: a plan
  consumes its scope's attested facts in its stage's own transaction, exactly once and
  exactly when it commits; the diff carries them (`EffectDiff.facts`), verified again as
  measured; receipts commit to them. `[inbox]`, `[[inbox.sources]]`, `[inbox.keys]`,
  `inbox_roles`. Crash-proven: `tests/test_inbox_crash.py`.
- **`FactAgreement`**: a write of a guarded column must hold what a consumed fact of the
  named kind says, keyed to the row when configured; exempt values need no fact.
- **The last outbound checkers** (`interlock.outbound_checks`): `SinkAllowlist`,
  `OutboundCount`, `PayloadAmountCap` (per request, tenant or plan; per currency),
  `RecipientAllowlist` (email domains and addresses, https hosts, per tenant), and
  `OutboundTenantIsolation`. Each tells the agent the rule, never a cap or a value.
- `interlock.types.values_at` reaches list items and object values through `*`.

### Changed (Epic 5)

- **Breaking:** schema version 5. Run `interlock install`; versions 2 to 4 upgrade in place.
  No relay function changed, so running relays carry on.
- Payload numbers are strict everywhere: ASCII digits only, no exponents, no leading `+`,
  no underscores. The schema subset's `enum` and `const` compare as JSON does, so `true` is
  not `1`; a field named like a credential is folded through NFKC before it is compared.
- `IL009` names both the rate windows' history and the inbox: neither is a stage's to read.
  A window past pruned history raises `IL011`, surfaced as `SubstrateConfigurationError`.

### Added (Epic 4: delivery receipts, rate windows, ledger-integrated compensations; `docs/EPIC4_DESIGN.md`)

- **Relays sign every outcome** (schema version 4). Each `delivered`, `retryable`,
  `permanent` or `unknown` row carries the relay's Ed25519 attestation, an ARC1 1.1
  `Attestation` over the request as committed and the outcome as recorded, hashed into the
  delivery log under a new framing; the database refuses an outcome without one.
  `Relay(signer=...)` is required, Ed25519 only; `interlock relay` starts only with a key
  registered in `[relays.keys]` (`[relay] key`, `--key`, `INTERLOCK_RELAY_KEY`);
  `interlock keygen --role relay|operator` makes one; `outbox show` names who attested.
- **Ghost deliveries are named.** `interlock.attestations.verify_attestations` (run by
  `interlock outbox verify` with `[relays.keys]`) rebuilds each outcome's attestation and
  names one with none, one by an unregistered key, one copied from another call, and a row
  rewritten after it was signed.
- **The legacy set.** The install that first brings version 4 records, once, the rows
  written before the proof their kind now carries (unattested outcomes, version 2's
  unsigned operator rows), then seals it; `interlock install` under `[operators]` signs its
  digest into the install record, and the first such record pins it. Unattested outcomes
  and unsigned operator rows are legacy only if they are in it, as recorded, and it is the
  set vouched for; anything else is named, however it is dated.
- **Rate windows** (`interlock.windows`; `EscrowEngine(windows=...)`, `[[windows]]`).
  `RateWindow(name, span, limit, measure, per)` with `Requests`, `RequestSum`, `RowSum`
  (inserted or net) and `Plans`, per scope, tenant or globally, sliding. Each plan is
  measured with its windows' history read with the keys locked (PostgreSQL: sorted
  transaction-scoped advisory locks and a `READ COMMITTED` read; SQLite: the stage's write
  lock), so racing plans commit exactly up to a limit. The measures are part of the diff
  (`EffectDiff.windows`, `WindowMeasure`) and its hash; the built-in `RateWindowCheck`
  refuses a plan past a limit; what a plan adds is written beside its commit marker. The
  agent is told the window (`rate_window` guidance), never what it holds. Agent statements
  can neither read nor write window history.
- **Settlement** (`interlock.settlement.Settler`). Each delivered request gets an ARC1
  delivery receipt, signed by the receipt log, carrying the relay's attestation, bound to
  the action receipt of the plan its relay-attested idempotency key was derived from;
  each delivered compensation credits, through AgentGov `refund()`, the `cost_per_call`
  the engine's sink registry (`Settler(sinks=...)`) prices the original at, which is what
  its plan was charged for it, to the scope the ledger charged, only under a signed
  operator intent naming it, and only when the outbox row agrees with the registry and
  the compensation's signed key. No outbox column sets the amount or the scope. Exactly
  once across crashes: `tests/test_settlement_crash.py` kills a settler after the
  receipt, the credit and the settlement row, on both stores. `settler_roles` at
  install; `verify_settlements`; `ReceiptIssuer.issue_delivery`.

### Changed (Epic 4)

- **Breaking:** schema version 4. Stop the relays, run `interlock install`, start them
  again: an older relay cannot record an outcome in version 4. Versions 2 and 3 upgrade in
  place, every log still verifying.
- **Breaking:** `Relay` requires `signer=`, and `interlock relay` a registered key.
- **Breaking:** `OutboxStore.outcome` takes the attestation.
- An unsigned operator row from before version 3 is held to the legacy set, not to when
  version 3 was installed.
- `install()` and `install_sqlite_outbox()` return the legacy set their transaction read.
- `interlock-agentgov>=0.4.0`, from PyPI.

### Added (Epic 3: adapters, signed operator logs, SQLite parity; `docs/EPIC3_DESIGN.md`)

- **The outbox on SQLite.** `interlock install` switches a SQLite file to WAL and installs
  the outbox; stages enqueue in their own `BEGIN IMMEDIATE` transaction, a request bound to
  its stage's commit marker by a deferred foreign key; `SqliteOutboxStore` runs the relay's
  state machine under SQLite's one write lock. The delivery log is append-only and linked
  by triggers through a function only Interlock's connections register. `interlock relay`
  and `interlock outbox` work on a SQLite file. Every relay test, the relay's kill matrix
  and its soak run on both stores; `tests/test_sqlite_stage_crash.py` kills a SQLite engine
  at each point of its commit path, and an engine and a relay at random instants.
- **Typed sinks: Stripe and SendGrid** (`interlock.stripe`, `interlock.sendgrid`;
  `[[sinks]] type = ...`). Their own operations and strict schemas; a Stripe charge must
  carry the refund that undoes exactly it, named by `{"$bind": "delivered.id"}`, checked at
  admission and again by the database. `StripeAdapter` (form encoding, idempotency key,
  pinned version, the created object's id recorded as `remote_ref`) and `SendGridAdapter`
  (the v3 body, `custom_args`, sandbox mode; at most once by default). Both driven through
  the relay's kill matrix against fakes keeping their protocols; live tests gated on
  test-mode keys.
- **Signed operator actions** (`interlock.operators`). Every `release`, `cancel`,
  `requeue` and the new `compensate` is an intent signed with the operator's Ed25519 key
  before the database is touched, applied under the intent's hash and only at the
  delivery-log heads it names, and recorded applied or refused; a command killed mid-way is
  resolved by the next. `interlock operator keygen`, `interlock outbox resolve`,
  `[operators]` in `interlock.toml`, records anchored into AgentGov.
- **`interlock outbox compensate`** enqueues the compensation a delivered request carried,
  bound to what its delivery created, in reverse topological order across a plan, once,
  and past its deadline only with `--late`.
- **Ghost edits are named.** `interlock outbox verify` holds the delivery logs to the
  operator log and the operator log to its keys and anchors: unsigned operator rows,
  authorities no intent holds or replayed elsewhere, a log cut short, a sink registry
  changed since the last signed install.
- **Schema version 3**, installed in place over version 2: `remote_ref`, `authority`,
  `compensates`, sink `kind`, `outbox_epochs`. Every delivery log written under version 2
  still verifies; `tests/test_pg_upgrade.py` upgrades a database installed from version
  2's own SQL.
- `records.Keyring`: one ILOK1 log written by several signers, each record verified under
  the key it names.

### Changed (Epic 3)

- **Breaking:** `deliveries.release`, `cancel` and `requeue` take the `authority` of a signed
  intent and the `expected_head`; `deliveries.release_scope` is removed (release a scope
  through `Operator.release_scope`). The database refuses an operator's row without an
  authority. `interlock outbox release/cancel/requeue` need `[operators]` and a key;
  `--actor` is gone: the key names the operator.
- **Breaking:** `OutboundRequest.not_after` and `SinkSpec.not_after` are whole seconds.
- A relay of version 2 cannot record outcomes in version 3: stop the relays, run
  `interlock install`, start them again. A stage or relay against a version 2 database is
  refused with that instruction.
- `interlock outbox verify` reads both stores' logs in one consistent snapshot.

### Added

- **Outbound requests, staged in a transactional outbox (Epic 2, phases 0 and 1; see
  `docs/OUTBOX_DESIGN.md`).** `PlanBuilder.enqueue(sink=, operation=, payload=, ...)` adds
  an `EffectKind.ENQUEUE` effect carrying an `OutboundRequest`, whose payload is frozen and
  hashed over its ARC1 canonical bytes. `EscrowEngine(sinks=SinkRegistry(...))` admits a
  request only for a registered sink and operation, under the sink's size bound, with no
  credential-like field, matching the operation's JSON Schema (a strict subset; anything
  else is refused at registration), and carrying the compensation the operation registers,
  or none when the operator declares it `"none-possible"` (E4-3). On PostgreSQL the request
  is written to `interlock.outbox` inside the stage through `interlock.enqueue`, a function
  gated by a per-stage token only the substrate holds; the database re-checks the sink, the
  operation, the size and the payload hash over the bytes sent. It is measured into
  `EffectDiff.outbound`, committed with the plan's rows and marker or not at all, recorded
  in the receipt's row commitment (`interlock.receipts.receipt_rows`) and noted on
  `COMMIT_INTENT` (`; outbound N`). Its idempotency key is `outbound_key(plan_id,
  effect_id)`, unique in the outbox, so a plan's request commits at most once. SQLite
  refuses the effect.
- **`[[sinks]]` and `relay_roles` in `interlock.toml`,** which `interlock install` mirrors
  into `interlock.sinks` (a sink no longer listed is disabled, not deleted, and the relay
  holds its messages) and grants.
- **Crash consistency with an outbox.** Every refund in `tests/test_crash_consistency.py`
  also enqueues its email; at every kill point, in both ledger modes, a request is in the
  outbox exactly when its plan's stage marker is.
- **Requests are paid for at commit (Epic 2, phase 2).** A plan's hold covers its settle
  cost and each request's `cost_per_call`, so a scope that cannot pay for the plan and its
  requests is refused before staging; the settlement that commits with the outbox rows (or
  the reverse anchor written after the commit) charges the sum. A refused plan pays only
  its settle cost. The database prices each request from its own copy of the registry and
  stores the price with it (`interlock.outbox.cost`, `OutboundDelta.cost`); the engine
  requires the outbox to hold exactly the plan's requests, as declared, at the engine's
  price, and refuses the plan otherwise, so nothing is sent unpaid or paid for unsent.
- **`interlock relay` delivers committed requests (Epic 2, phase 3).** `Relay` claims
  leases with `FOR UPDATE SKIP LOCKED`, each under a fence that stops a relay whose lease ran
  out from acting again; re-hashes the stored payload before every call; reads AgentGov's
  breaker (`LedgerBreaker`, read-only, over a SQLite or PostgreSQL ledger) immediately
  before every call and holds the message, not sends it, when the scope is halted, or
  unknown to AgentGov; records the call before making it and the outcome after; retries
  with exponential backoff and deterministic jitter (`retry_delay`), honouring
  `Retry-After`, up to the sink's `max_attempts` and the request's deadline; delivers in
  plan order; and dead-letters a request, with everything that waits for it, on a
  permanent failure. `HttpAdapter` is the generic JSON-over-HTTP sink adapter: credentials
  from the relay's environment only, redirects never followed. Every change of a message's
  state is a row of its delivery log (`interlock.outbox_attempts`), hash-linked by the
  database from a genesis bound to the request; `verify_delivery_log` recomputes it.
  `interlock outbox status|list|show|verify|release|cancel|requeue` for operators. Sinks
  gain `max_attempts`, `backoff_base_seconds`, `backoff_cap_seconds` and
  `unknown_outcome` (`"redeliver"`, at least once; `"dead-letter"`, at most once); the
  configuration gains `[relay]`.
- **`CrossEffectAgreement`: a request must say what its rows say.** A pure checker that
  holds a field of an outbound request, read back from the outbox, to the rows the same plan
  wrote, as measured: the sum of a column over inserted rows (`measure="inserted"`), its net
  change over every row written (`"net"`), or one exact value every row holds (`"value"`),
  optionally pairing each request with its own rows (`key=`). Strict both ways: a request
  with no rows, or rows with no request, is refused. A refund request for 5000.00 beside the
  refund row the plan inserted for 50.00 is refused before commit, and nothing is written or
  sent; the agent is told the rule (`cross_effect_agreement`), never the amounts.
- **Relay crash consistency (Epic 2, phase 4).** `tests/test_relay_crash.py` kills a relay
  process with SIGKILL at each point of the delivery path, for a sink that honours keys, one
  that does not, and one that dead-letters, and checks the exact outcome; a duplicate
  effect occurs only for a keyless redelivering sink whose relay died between the sink
  acting and the outcome committing, and the delivery log records the lost call it came
  from. A random-instant soak kills racing relays over failing sinks and checks that
  nothing is lost and every call and duplicate is accounted for.

### Changed

- **`INSTALL_VERSION` is `"2"`.** `interlock install` over version 1 upgrades in place, in
  one transaction: `interlock.stages` gains `enqueue_hash`, `begin_stage` its token
  argument, and the outbox tables their append-only triggers (enabled `ALWAYS`). A stage
  refuses to open over a version-1 installation, over an outbox whose append-only triggers
  are missing or disabled, and for a stage role that can write any `interlock` table.
- **`EffectPlan.stated_rows` ignores `ENQUEUE` effects,** which write no observed row, so a
  plan with a request still gets `StatedFootprint`'s check.
- **The relay role reads the outbox and writes nothing directly:** every change goes
  through the `relay_*` functions, which check its lease. `interlock install` revokes
  `EXECUTE` from `PUBLIC` on every function in the `interlock` schema, and grants back only
  what each role needs. The delivery log of the phase 0–1 commit is replaced; installing
  over an outbox from that pre-release build is refused with what to do (`IL005`).

Every plan, effect and diff hash computed before outbound requests is unchanged: the new
fields enter a hash only when present (pinned in `tests/test_outbound.py`).

### Fixed

- **`interlock.__version__` reads `0.3.0`,** the version published to PyPI; it still read
  `0.2.1`. A test now holds it to `pyproject.toml`.

## [0.3.0] - 2026-09-27

Requires agentgov 0.3.0 (`interlock-agentgov` on PyPI), whose PostgreSQL fleet ledger
the same-transaction mode joins. Published to PyPI as `interlock-escrow`.

### Added

- **Settlement with the commit: claim and settle
  (`LedgerAnchor(same_transaction=True)`).** With the AgentGov ledger shared through
  PostgreSQL in the same database as the observed tables, a plan's hold is placed before
  its stage opens; at commit the governor joins the stage's transaction, checks the breaker
  under the ledger's writer lock taken inside it, and writes a settlement claim keyed to
  the hold into the stage, so effects, commit marker and claim commit in one `COMMIT` or
  not at all; after the commit the claim is redeemed into AgentGov's chain, the spend
  naming the plan's `COMMIT_INTENT` record, whose note says `settlement claimed`. The claim
  reads nothing of the chain, so a stage conflicts with no ledger traffic, however busy.
  A scope that cannot pay, or is halted, refuses the plan before it stages. A refused plan
  is charged against its hold; a failed stage releases it. `EscrowEngine.recover()` books
  every pending claim and releases the holds of its plans that can no longer commit.
  `PostgresSubstrate.connection()` exposes the stage's connection to the anchor;
  `EscrowEngine` refuses a same-transaction anchor over a substrate without one.
- **Crash consistency for the shared ledger.** Every test in
  `tests/test_crash_consistency.py` now runs against a SQLite ledger and a shared
  PostgreSQL one. New kill points stop after the hold is placed (`reserved`), after the
  claim is written into the stage and before `COMMIT` is sent (`claimed`), and after the
  claim is booked (`redeemed`). At every kill a claim exists exactly when the effects do,
  and a plan that did not commit leaves only its hold; after recovery nothing is left
  owed or reserved, and a stage's settled spend exists exactly when its effects do.

### Changed

- **A governed anchor over a shared ledger follows the other governors** before it reads
  the ledger's head or a scope, as an audit view always has.

## [0.2.1] - 2026-09-26

Four fixes found by an adversarial DX audit that drove real Claude traffic through
`RecoveryRuntime`, the repair/resubmit loop, and the substrate error path. Requires
agentgov v0.2.1 (fixes `AgentThrashingError`'s exception hierarchy and a witness
file's torn-line handling; see agentgov's changelog).

### Fixed

- **`RecoveryStep.tools` reads, at a glance, exactly backwards.** It has always meant
  "the tools still granted after this step," but the README's own quickstart prints it
  right next to a rung called `revoke_tool` (`step.rung, step.tools  # revoke_tool
  ('apply_plan',)`), and the obvious reading -- build an enforcement check around
  whatever's in `step.tools` -- checks the tool that is still allowed and misses the one
  that was actually revoked. Added `RecoveryStep.granted_tools` and `.revoked_tool` as
  clearly-named aliases for `.tools` and `.tool`, documented the trap directly on the
  class, and fixed the README's own quickstart, which had exactly this bug baked into
  its `check_tool()` call.
- **The default recovery channel's beta flag was stale against the live API.**
  `TOOL_CHANGES_BETA` was `mid-conversation-tool-changes-2026-07-01`; sending a real
  `Channel.SYSTEM` step against the current Anthropic API gets a 400 asking for
  `inline-tools-2026-09-15` instead. Updated the constant and documented that it is a
  snapshot of the API surface, not a permanent value, since nothing here detects the
  next rename automatically.
- **The README didn't say `step.betas` needs the beta SDK endpoint.** "Send
  `step.messages` (with `step.betas`)" reads like `client.messages.create(betas=...)`,
  which raises a plain `TypeError` in the `anthropic` SDK; it has to be
  `client.beta.messages.create(...)`. Documented in the Recovery section.
- **An empty (or whitespace-only) `Effect.statement` staged, measured nothing, and
  committed as a silent no-op.** Nothing downstream rejects it: there is no leading
  verb for `reject_reason()` to refuse, and SQLite executes `''` without complaint.
  Most often the sign of a template that produced an empty string rather than a
  genuinely empty step. `Effect.__post_init__` now raises `PlanError` on construction,
  which also catches it through `PlanBuilder`.

### Clarified

- **`demo.py`'s agent is scripted, not live.** No model is called anywhere in it; the
  injected plan it "detects" is a hardcoded `EffectPlan`. That was always the intent
  (a controlled comparison, not a live demo) but wasn't said plainly, and an audit
  found that a real, current Claude model declines the exact injection shown, across
  several framings. The README now says so and points to
  [`scripts/live_stress_test.py`](scripts/live_stress_test.py) -- a real model against
  a real substrate, previously unmentioned in the README -- for that question instead.
- **`InterlockError.feedback` already covers `StageError`/`ForbiddenStatementError`,
  not only checker refusals**, via `feedback_for_error()`, reading the exception's type
  and structured fields rather than its message. This was not obvious from the
  docstrings and the audit's own harness initially missed it, comparing `str(exc)`
  (which does leak driver detail, by design -- it's the operator's record) against
  nothing rather than against `exc.feedback.render()` (which doesn't). Strengthened the
  docstrings on `InterlockError`, `StageError` and `ForbiddenStatementError` instead of
  adding a second, redundant sanitization mechanism.

## [0.2.0] - 2026-09-26

PostgreSQL, signed receipts and recovery, with release gates behind them. A
PostgreSQL substrate with installed capture triggers, a cascade check and
reconciliation of unrecorded writes; a signed ARC1 receipt for every adjudicated
plan; refusals split by audience, checked repair, budgeted recovery from a halt,
and extension quotes. Crash consistency is tested by killing a real process at
every step of a commit, and tamper evidence by altering every part of the audit
trail. Requires agentgov v0.2.0.

### Added

- **Two-audience refusals (3.1).** Every `StageResult` carries `feedback`, what
  the agent may be told, and a refused one carries `refusal`, split into the
  operator's `evidence` and that feedback; every error `execute()` raises carries
  `exc.feedback`. Feedback names only the plan's own tables and declared tenants,
  buckets row counts, and carries no aggregate: no column total, no fraction of
  one, no count of other tenants. Its text comes from fixed templates, and its
  constraints come in a canonical order. Checkers offer a typed `FeedbackHint`
  per violation, sanitized against the plan; a custom checker's numbers and
  columns are dropped. `ForbiddenStatementError` gains structured `reason` and
  `table`, so errors map to feedback by type, never by message. New modules
  `interlock.feedback` and `interlock.adjudication`. Property tests (hypothesis)
  check that renaming what the plan did not name, scaling every amount, or
  changing other tenants' values never changes the feedback.
- **Checked repair (3.2).** `EscrowEngine.repair()` (and `EscrowRuntime.repair()`)
  finds the largest part of a refused plan that would be admitted, by experiment. It
  stages the plan once and tries candidate sub-plans, the down-sets of its dependency
  graph, largest first, in savepoints: each is measured and adjudicated by the same
  checkers and rolled back. Nothing assumes monotonicity, so a debit is kept with the
  credit that balances it under a drawdown guard. `max_trials` bounds the search, with
  a greedy fallback whose result was still admitted. Advisory: the stage always rolls
  back, and the proposal is a new plan whose `repair_of` names the refused one;
  `execute()` admits it only exactly as a `REPAIR_PROPOSED` record on the chain says,
  once, and adjudicates it again from scratch. Each dropped step is explained through
  the sanitized feedback (`Repair.feedback`). Both substrates gain `savepoint`,
  `rollback_to` and `release_savepoint`. New module `interlock.repair`.
- **ARC1 receipts.** With `receipts=ReceiptIssuer(log)`, the engine issues a signed
  agentgov ARC1 receipt for every plan it adjudicates, committed or refused
  (`StageResult.receipt`), covering authority, intent, the measured effect (with a
  salted row commitment and a schema hash), coverage and its gaps, the decision, cost
  and outcome. A repair's receipt names the refusal's as `decision.repair_of`. The
  receipt and the stage's terminal record name each other, and the receipt is issued
  after the reverse anchor, so agentgov's verifier can check it against the ledger. A
  receipt that fails to issue after a commit is logged, not raised. New module
  `interlock.receipts`.
- **Budgeted recovery (3.3).** `RecoveryRuntime` gives a halted task a bounded way to
  finish: a deterministic ladder, fixed in order (revoke the tool the halt names, an
  operator directive from the policy's allowlist, a lower token ceiling, then guidance in
  fixed words), one rung per step, tightening only ever accumulating. Each step appends to
  the transcript and never edits it, answering tool calls the halt stopped; directives and
  revocations go in appended `role: "system"` messages and `tool_removal` blocks on the
  models that take them, or user-turn notices otherwise, and `check_tool()` refuses a
  revoked tool either way. Recovery is billed to `{scope}/recovery`, a reserve carved out of
  the scope's envelope and delegated beside it, since a trip halts the tripped scope's
  subtree. `Trip.of()` reads AgentGov's and Interlock's halts by type, never by message; a
  halt's own words are recorded and never sent to the agent (property-tested). New modules
  `interlock.recovery` and `interlock.records`.
- **ILOK1 signed records.** `RecordLog` is an append-only, hash-linked, signed log for the
  runtime's own acts, built on agentgov's canonical JSON and signers under an
  `ILOK1/record/v1` prefix, fsynced, resumed and verified from its file, one writer per
  file. The runtime anchors every record into the AgentGov ledger, and `check_anchors()`
  finds a log truncated or rewritten after the fact.
- **Extension quotes (3.4).** `BudgetGuard.authorize()` checks a scope's balance under the
  ledger's lock before AgentGov has to refuse, and when a call will not fit returns a signed
  `ExtensionRequest` instead of tripping the breaker: spend to date from the ledger over the
  task's scopes; proof of work from the ARC1 receipts of the task's committed plans, with a
  checkpoint each is provable against, its recovery steps, and declared `Milestones`; and an
  estimated completion cost by a named method, rounded up to the cent. `grant()` tops up a
  root (resetting a breaker the money running out tripped) or delegates `{scope}/ext-N`
  beside a delegated scope, carrying its leftover along; `decline()` records the refusal.
  Each quote is answered once, before it expires. A scope halted for safety is never
  quoted. A `RecoveryRuntime` with a guard quotes for its reserve
  (`RecoveryExhaustedError.quote`) and takes a grant up with `extend()`. New module
  `interlock.extension`.
- `RecoveryError`, `RecoveryExhaustedError`, `ToolRevokedError`, `RecordIntegrityError`,
  `ExtensionError`.
- `EffectPlan.repair_of`, hashed only when set, so earlier plans keep their hashes;
  `RecordType.REPAIR_PROPOSED`; `LedgerAnchor.scope_path()`; `BlastRadius.limit`;
  `table_specs` and `enforces_table_access` on both substrates.
- **The cascade check (2.1).** New `interlock.cascade` reads the foreign-key
  graph (`PRAGMA foreign_key_list` on SQLite, `pg_constraint` on PostgreSQL)
  and works out every table a `DELETE` or `UPDATE` on an observed table can
  reach through `CASCADE`, `SET NULL` or `SET DEFAULT`, to any depth, with the
  shortest path. It is column-precise for updates, and `RESTRICT` and
  `NO ACTION` reach nothing. `SqliteSubstrate` runs it when every stage opens,
  under the write lock, cached on `schema_version`, and refuses an operation
  whose actions reach an unobserved table, before a row changes, naming the
  path. `acknowledge_cascades=[...]` lets a named table be cascaded into
  unmeasured, and the gap is written into that stage's `STAGE_OPENED` record.
  `EscrowRuntime` runs the check at startup (`cascade_report`), logs every
  gated operation, and now requires the database to exist.

- **`PostgresSubstrate` (2.2).** Stages run in `REPEATABLE READ` on a
  dedicated connection with the observed tables locked `ROW EXCLUSIVE`, and
  `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout`
  set from `max_stage_seconds` and re-set before every effect. Changes are
  captured by row triggers installed once with `interlock install` (or
  `interlock.postgres.install`), `ENABLE ALWAYS`, which write to a temporary
  table only for a transaction that opened a stage; the stage is identified by
  `pg_current_xact_id()` in `interlock.stages`, and the `interlock.stage_id`
  setting must agree. The capture table, the stage row and the gates belong to
  the installing role and are written only through `SECURITY DEFINER`
  functions, so no statement of the agent's can reach them. Each stage verifies
  the installed triggers against its `TableSpec`s, that no observed table has
  inheritance children or partitions, and that its role is not a superuser,
  owns no observed table, and can write no other table
  (`SubstrateConfigurationError` otherwise). Only row statements are accepted,
  each sent as a prepared statement. `NUMERIC` is read as `Decimal`. The
  stage's row is its commit marker and `pg_current_xact_id()` is written into
  the commit intent, so `resolve_intent` tells a transaction still open on the
  server from one that rolled back.
- **Unrecorded writes (2.3).** `interlock reconcile-effects` fails (exit 1) on
  any write to an observed table that no chain records: a row change no stage
  made, a committed stage no chain records, one recorded as aborted or under
  another plan, or one left with only its commit intent. On PostgreSQL the
  installed trigger logs every write made outside a stage to
  `interlock.unmediated`, in the writer's transaction, with its session user,
  `application_name` and transaction id; `install(audit_roles=)` grants a role
  read access to the logs and nothing else. On SQLite `interlock install` adds
  permanent journal triggers writing `_interlock_journal`, and each committed
  stage records the exact range of journal rows it produced; the authorizer
  keeps statements away from both tables. `--after` takes the previous run's
  `last entry`; exit 5 means a chain failed verification.
- **The `interlock` command**, with `install`, `check` and `reconcile-effects`,
  reading a TOML configuration file (`interlock.config`).
- `SubstrateConfigurationError`; `CascadeReport` and `PostgresSubstrate` at the
  top level. A substrate may expose `transaction_id(handle)`; the engine writes
  it into `COMMIT_INTENT` and passes it back to `resolve_intent(..., txid=)`.
- `EffectDiff.column_total` and the value guards read `Decimal` values exactly.
- **Release gates: crash consistency and tamper evidence.**
  `tests/test_crash_consistency.py` starts a real process (`tests/crash_child.py`)
  with the whole production stack on PostgreSQL (a durable escrow chain, a governed
  ledger, a witnessed ARC1 receipt log) and kills it with `SIGKILL` at each step of a
  commit: mid-stage, with the intent on disk, with `COMMIT` in flight on the server,
  after it returned, after `COMMITTED`, after the reverse anchor, halfway through
  writing a record, and halfway through recovery itself. It checks exactly what
  recovery makes of each. The same rule holds for a hung client (bounded by the stage's
  idle timeout), for a connection that loses the `COMMIT` or its reply, and for a soak
  that kills at random instants and checks the whole history. That rule: the chain says
  `COMMITTED` exactly when the database committed, `ABORTED` exactly when it rolled back,
  and nothing while the server has not decided.
  `tests/test_tamper_evidence.py` alters every part of the audit trail and checks that
  verification fails at exactly that check, receipt, row or line: disclosed rows, a
  receipt's row commitment (against forgers holding one key more at each step), a
  committed row in the database, deleted checkpoints and receipts, forged receipt,
  checkpoint and witness signatures, inclusion proofs, a settled cost, and the keyless
  escrow chain against the signed receipts and ledger anchors that name it.
- `CommitUnsettledError` (a `StageError`): the connection was lost with `COMMIT` in
  flight and the server has not decided. The intent stays open, and the plan must not be
  retried.

### Changed

- **agentgov is pinned to its `v0.2.0` tag** (commit `6d3cac2`), the first agentgov
  release with `agentgov.receipts`, which receipts, recovery records and extension quotes
  need. The tag's package metadata still reports version 0.1.2; `uv.lock` records the
  commit.

### Fixed

- **A commit whose reply was lost was recorded as aborted.** When the connection dropped
  with `COMMIT` in flight after PostgreSQL had committed, `execute()` appended `ABORTED`
  ("stage failed") over the commit intent and raised `StageError`. The chain then said
  the plan never happened while its rows and commit marker were in the database.
  `reconcile-effects` flagged the stage as "committed in the database, recorded as
  aborted", recovery could not repair it (the intent was closed), and a caller that
  retried applied the plan twice. `PostgresSubstrate.commit` now tells a lost
  connection (`CommitUnsettledError`) from an error the server sent (`StageError`, which
  still means rolled back). The engine then reads the stage's commit marker at once:
  committed, rolled back, or, while the server has not decided, left open with no
  terminal record. Found by the new crash tests.
- **Recovery blamed an undecided commit on a missing marker.** When the server was still
  running a dead client's transaction, `recover()` logged that "no commit marker was
  armed" and asked for a hand resolution, which could contradict what the server did
  next. It now says the intent is not settled yet and will be asked again.
- **Refusals leaked other tenants' data to the agent.** The reference stress
  harness returned each blocking violation's message to the model, which for
  `TenantDrawdownGuard` named other tenants and their exact totals; it also
  returned the count of tenants touched and the measured tables. It now returns
  the agent feedback, and the operator's record stays in its attempt log.
- **A statement could erase the measurement.** The authorizer allowed any write
  to `_interlock_capture`, so an effect `DELETE FROM _interlock_capture` emptied
  the diff, and a plan that zeroed every order committed past `BlastRadius(1)`.
  Only the capture triggers may write it now, with or without
  `enforce_table_access`.
- **A statement could commit the stage before adjudication.** `COMMIT` was not
  a forbidden verb and SQLite's transaction actions were authorized, so an
  effect `COMMIT` made every earlier effect durable before any checker ran, and
  every later one autocommitted. `BEGIN`, `COMMIT`, `END`, `ROLLBACK`,
  `SAVEPOINT` and `RELEASE` are refused at admission and by the authorizer.
- **The authorizer was off with `enforce_table_access=False`.** It now always
  runs; the flag lifts only the unobserved-table rule.
- The README said a foreign-key cascade is not seen by SQLite's authorizer. On
  current SQLite it is, and it was refused with a message about an unobserved
  write; the cascade check now refuses it first and says why.

## [0.1.2] - 2026-09-25

Makes two of v0.1.1's guarantees true. Each fix is tested against a
reproduction of the break in
[`tests/test_core_guarantees.py`](tests/test_core_guarantees.py).

### Fixed

- **A plan committed on a scope the governor had halted (R4).** Attached
  read-only, the anchor's view of AgentGov was loaded once, at attach time, and
  never refreshed. The "re-read the breaker immediately before commit" step read
  that snapshot, so when the governor halted the scope afterwards, which is the
  documented separate-process deployment, the plan committed anyway. Now:
  - The view is refreshed, and everything new in it verified, before every
    record and before the pre-commit breaker check. A halt on the scope or any
    ancestor written after attach stops the commit, and so does one that lands
    while the plan is staged.
  - A refresh that fails verification, such as a ledger rewritten under the
    view, fails the stage closed with `LedgerUnverifiedError`. The stage rolls
    back and the `ABORTED` record is written unanchored rather than not at all.
  - With a governed manager, `LedgerAnchor.guard_commit()` holds the governor's
    own lock from the check through the substrate's commit, so a trip in this
    process lands strictly before the check or strictly after the commit.
  - Across processes no lock spans both databases, so a trip committed between
    the check and the commit cannot be excluded. When one is seen immediately
    after the commit, the `COMMITTED` record says so.
  - Records anchor to the governor's current head. They used to anchor to the
    head at attach time.
- **A second process lifetime forked the chain (R5).** `EscrowChain(path)`
  appended to an existing file without reading it, so a restarted runtime began
  a second chain at sequence 1: `load()` then raised, and
  `unresolved_intents()` came back empty. Now:
  - An existing file is resumed. Every record is read and verified before the
    first append, and a final line torn by a crash mid-append is cut off,
    because that append never returned.
  - One file has one writer. The chain claims `<path>.lock` while it is open,
    and a second writer, in this process or another, gets `ChainInUseError`.
    The kernel drops the claim when a process dies, `SIGKILL` included.
  - `COMMIT_INTENT` and every terminal record are fsynced before `append()`
    returns (`fsync=False` gives that up). A write that fails leaves neither a
    torn line nor a record.
- **A crashed commit is resolved exactly.** An intent says only that a commit
  was attempted. `SqliteSubstrate` now writes a marker row into
  `_interlock_commits` inside the stage's own transaction, just before
  `COMMIT`, so the marker exists if and only if the effects do. New
  `EscrowEngine.recover()` resolves every intent a crashed process left open
  from its marker, appending `COMMITTED` or `ABORTED` noted as recovered, and
  `EscrowRuntime` runs it at startup when it has a `chain_path`. Intents without
  an armed marker (written before 0.1.2, or by a substrate without markers) stay
  open and are logged, because a missing marker proves nothing for them. The
  SQLite authorizer refuses a statement that tries to write the marker table
  itself.
- **Effects that committed were never recorded as aborted.** An exception after
  a durable commit, such as the `COMMITTED` record failing to write, used to
  fall through to the path that appends `ABORTED`. It now propagates with the
  intent left open, and `recover()` resolves it from the marker.

### Added

- `EscrowEngine.recover()`, `EscrowRuntime.recovered`.
- `SqliteSubstrate.resolve_intent()` and `SqliteSubstrate(commit_markers=True)`.
- `LedgerAnchor.guard_commit()` and `LedgerAnchor.halted_after_commit()`.
- `EscrowChain(path, fsync=True)`, `EscrowChain.close()`, `.path`, `.read_only`,
  and use as a context manager. `ChainInUseError`.

### Changed

- **Reverse anchoring is free and on by default with a governed manager.** A
  `settle_cost` of `"0"`, the default, now writes a zero-value `ANCHOR` entry
  (AgentGov 0.1.2) instead of meaning forward anchoring only.
  `StageResult.anchored_to` is therefore set on every result a governed engine
  returns, refused plans included. A positive cost still settles through
  `authorize`/`capture`; a negative one is refused before anything is staged,
  with `ValueError` from the constructor and `PlanError` from `execute()`.
- **`EscrowChain.load()` returns a read-only snapshot.** It claims nothing, so
  it can read a chain a live writer holds, and its `append()` raises. Resume
  appending with `EscrowChain(path)`. An engine refuses a read-only chain.
- **Halt messages name the reason** the governor recorded for the trip.
- **agentgov is pinned to its `v0.1.2` release tag**, not `@main`, and
  `uv.lock` records the exact commit. Interlock 0.1.1's lock resolved an
  agentgov commit that reported itself as 0.1.0 and lacked
  `verify_conservation()`, so the two 0.1.1 releases had never run together.
- `docs/ESCROW_SPEC.md`'s conformance section describes 0.1.2, including two
  items it had not caught up with: writes outside `TableSpec` are denied by the
  authorizer, and `tenant_column` is validated.

### Known limitations

- The `_interlock_commits` table gains one row per committed stage and is not
  pruned.
- The escrow chain is keyless. Anyone who can write the file can recompute it
  from start to finish; a reverse anchor in a governed AgentGov is the only copy
  of its head outside the file.
