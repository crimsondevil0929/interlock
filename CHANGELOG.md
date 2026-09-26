# Changelog

All notable changes to Interlock are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
from 1.0.0 onward. Before 1.0.0, minor versions may include breaking changes.
Releases before 0.1.2 are described by their tags and commit history.

## [Unreleased]

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

### Fixed

- **Refusals leaked other tenants' data to the agent.** The reference stress
  harness returned each blocking violation's message to the model, which for
  `TenantDrawdownGuard` named other tenants and their exact totals; it also
  returned the count of tenants touched and the measured tables. It now returns
  the agent feedback, and the operator's record stays in its attempt log.

### Added

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

### Fixed

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
