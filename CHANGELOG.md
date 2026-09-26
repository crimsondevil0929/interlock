# Changelog

All notable changes to Interlock are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
from 1.0.0 onward. Before 1.0.0, minor versions may include breaking changes.
Releases before 0.1.2 are described by their tags and commit history.

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
