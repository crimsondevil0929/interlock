"""Shadow substrates: execute for real, commit only on instruction.

The contract that matters is :meth:`ShadowSubstrate.diff`. A diff is measured
from the substrate and never reconstructed from the plan, because the two
routinely disagree:

- A trigger, cascade or rule mutates rows the statement never named.
- A ``WHERE`` clause matches more than the agent believed.
- A foreign-key cascade deletes into a table the plan does not mention.

Neither the agent nor a static analysis of the SQL sees any of that. The
database does, because it has already executed it.

Scope limit worth knowing before wiring this up: the measurement covers exactly
the tables in ``tables``. A statement that writes any other table is refused,
and so is an operation whose foreign-key actions would carry it into one,
unless the operator acknowledged that table (see :mod:`interlock.cascade`).
See ``EscrowEngine.admit`` for what is and is not gated.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from collections.abc import Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

from interlock.cascade import (
    CascadeReport,
    analyze_cascades,
    log_report,
    read_sqlite_foreign_keys,
)
from interlock.exceptions import (
    ForbiddenStatementError,
    InboundFactError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.inbox_sql import (
    SQLITE_CONSUMED,
    SQLITE_FACTS,
    SQLITE_INBOX_TABLES,
)
from interlock.inbox_store import sqlite_facts, sqlite_has
from interlock.outbound import EnqueueOrder
from interlock.sqlite_outbox import (
    CHECKPOINTS,
    OUTBOX_TABLES,
    WINDOWS_TABLE,
    enqueue,
    now_us,
    outbox_installed,
    stage_requests,
)
from interlock.sqlite_outbox import WINDOWS_DDL as _WINDOWS_DDL
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectKind,
    EffectOutcome,
    EffectPlan,
    InboundFact,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
    WindowMeasure,
    outbound_key,
)
from interlock.windows import WindowCharge

__all__ = [
    "FORBIDDEN_VERBS",
    "ShadowSubstrate",
    "SqliteSubstrate",
    "TableSpec",
    "leading_verb",
]

logger = logging.getLogger("interlock.substrate")

_CAPTURE_TABLE = "_interlock_capture"

_MARKER_TABLE = "_interlock_commits"

JOURNAL_TABLE = "_interlock_journal"
"""Written by the permanent journal triggers ``interlock install`` puts on
each observed table: one row per row change, staged or not. See
:mod:`interlock.reconcile`."""

STAGE_JOURNAL_TABLE = "_interlock_stage_journal"
"""The range of journal rows each committed stage produced, written by the
substrate inside the stage's own transaction."""
_MARKER_DDL = (
    f"CREATE TABLE IF NOT EXISTS main.{_MARKER_TABLE} "
    f"(stage_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, committed_at TEXT NOT NULL)"
)

FORBIDDEN_VERBS: frozenset[str] = frozenset(
    {
        # Schema changes. They fire no row triggers, so the diff is empty and
        # every checker that reads the diff passes on nothing.
        "alter",
        "create",
        "drop",
        "truncate",
        "rename",
        # Reach outside the observed database, or change how it behaves while
        # a stage is open. ATTACH in particular puts any file the process can
        # write inside the transaction, where no capture trigger exists.
        "attach",
        "detach",
        "pragma",
        # Not row mutations, and not transactional in the way a stage assumes.
        "vacuum",
        "reindex",
        "analyze",
        # Transaction control. The stage's transaction belongs to the
        # substrate: a COMMIT here makes the effects so far durable before
        # they are measured or adjudicated, and every later effect then runs
        # in autocommit, outside anything a verdict can roll back.
        "begin",
        "commit",
        "end",
        "rollback",
        "savepoint",
        "release",
    }
)
"""Statement verbs a stage refuses outright.

Enforced on the statement text, never on ``Effect.kind``, which the agent
supplies and which nothing else checks against the SQL.
"""

_WRITE_ACTIONS: dict[int, str] = {
    sqlite3.SQLITE_INSERT: "INSERT",
    sqlite3.SQLITE_UPDATE: "UPDATE",
    sqlite3.SQLITE_DELETE: "DELETE",
}
"""Row-mutating actions the authorizer gates on the observed-table set."""

_REACH_ACTIONS: dict[int, str] = {
    sqlite3.SQLITE_ATTACH: "ATTACH",
    sqlite3.SQLITE_DETACH: "DETACH",
}
"""Actions that would move the stage outside the database being measured.
Also caught by ``FORBIDDEN_VERBS``; denied here too because that check reads a
leading verb and this one reads what SQLite is about to do."""

_CONTROL_ACTIONS: frozenset[int] = frozenset({sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT})
"""Transaction control. Only the substrate issues it; see ``FORBIDDEN_VERBS``."""

_SENTINEL = "interlock: a write reached"
"""Prefix of the message a sentinel trigger aborts with."""

_ROWID_ALIASES: frozenset[str] = frozenset({"rowid", "_rowid_", "oid"})
"""Names SQLite accepts for a table's rowid. Updating one updates an
``INTEGER PRIMARY KEY`` column, which a foreign key may reference."""

_LEADING_COMMENT = re.compile(r"\A(?:\s|--[^\n]*\n|/\*.*?\*/)+", re.S)
_LEADING_WORD = re.compile(r"\A[A-Za-z_]+")


def leading_verb(statement: str) -> str:
    """The first SQL keyword, with leading comments and whitespace removed.

    Comments are stripped first because ``/* x */ DROP TABLE t`` and
    ``-- x\nDROP TABLE t`` are both valid SQL that a naive prefix check reads
    as having no verb at all.

    :param statement: A single SQL statement.
    :returns: The lowercased leading keyword, or ``""`` when there is none.
    """
    stripped = _LEADING_COMMENT.sub("", statement.lstrip("(").strip())
    found = _LEADING_WORD.match(stripped.lstrip("("))
    return found.group(0).lower() if found else ""


_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


@runtime_checkable
class ShadowSubstrate(Protocol):
    """A backend that can apply effects without committing them."""

    @property
    def substrate_id(self) -> str:
        """Stable identifier, matching the prefix in ``Effect.target``."""
        ...

    @property
    def capabilities(self) -> SubstrateCapabilities:
        """What this driver supports. Constant for the driver's life."""
        ...

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, or ``None`` if it can.

        Called from ``EscrowEngine.admit`` before anything is opened, so a
        plan this substrate would refuse never takes a write lock. Optional:
        the engine skips the check on a driver that does not implement it.
        """
        ...

    def open(self, plan: EffectPlan) -> StageHandle: ...

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome: ...

    def diff(self, handle: StageHandle) -> EffectDiff: ...

    def commit(self, handle: StageHandle) -> CommitReceipt: ...

    def abort(self, handle: StageHandle) -> None: ...

    def close(self, handle: StageHandle) -> None: ...


# A driver may also implement ``savepoint(handle, name)``,
# ``rollback_to(handle, name)`` and ``release_savepoint(handle, name)``, which
# ``EscrowEngine.repair`` needs to try candidate sub-plans inside one stage.
#
# A driver may also implement ``resolve_intent(stage_id) -> bool | None``: did
# that stage's transaction commit? ``EscrowEngine.recover`` asks it about every
# commit intent a crashed process left open, and leaves the intent open when
# the driver cannot say. It is not part of the protocol, so a driver without it
# still satisfies ``isinstance(driver, ShadowSubstrate)``. A driver that also
# implements ``transaction_id(handle) -> str | None`` has that id written into
# the commit intent, and gets it back as ``resolve_intent(stage_id, txid=...)``.


class TableSpec:
    """A table Interlock is allowed to observe and mutate.

    :param name: Table name in the main schema.
    :param primary_key: Column uniquely identifying a row.
    :param columns: Columns to capture in the before and after images.
    :param tenant_column: Column carrying the tenancy label, when the table has
        one. It MUST also appear in ``columns``, because the tenant label is
        read back out of the captured image; the constructor enforces that. A
        table with no tenant column contributes nothing to tenant radius.
    :raises ValueError: On an identifier that is not a plain SQL identifier, or
        a ``tenant_column`` missing from ``columns``.
    """

    __slots__ = ("columns", "name", "primary_key", "tenant_column")

    def __init__(
        self,
        name: str,
        *,
        primary_key: str = "id",
        columns: Sequence[str],
        tenant_column: str | None = None,
    ) -> None:
        tenant = [tenant_column] if tenant_column else []
        for identifier in (name, primary_key, *columns, *tenant):
            _assert_identifier(identifier)
        if tenant_column is not None and tenant_column not in columns:
            # Without this, the tenant label is absent from every captured row
            # image, every RowDelta.tenant_id reads None, tenant_count is 0,
            # and TenantIsolation passes on a plan spanning any number of
            # tenants. Fail at construction instead.
            raise ValueError(
                f"tenant_column {tenant_column!r} must also be listed in columns "
                f"for table {name!r}, or tenant isolation cannot be measured"
            )
        self.name = name
        self.primary_key = primary_key
        self.columns = tuple(columns)
        self.tenant_column = tenant_column

    def json_object(self, alias: str) -> str:
        """A ``json_object(...)`` expression over ``OLD`` or ``NEW``."""
        pairs = ", ".join(f"'{column}', {alias}.{column}" for column in self.columns)
        return f"json_object({pairs})"


def _assert_identifier(name: str) -> None:
    """Reject anything that is not an ASCII ``[A-Za-z][A-Za-z0-9_]*``.

    Table and column names come from operator configuration, not from the
    agent, but they are interpolated into the capture-trigger DDL, so they are
    validated rather than trusted. ASCII-only: ``str.isalnum`` accepts
    non-ASCII letters and digits, which SQLite would take and a reviewer
    reading the trigger source would not expect.
    """
    if not _IDENTIFIER.fullmatch(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")


class SqliteSubstrate:
    """Transactional staging over SQLite.

    The stage is a real ``BEGIN IMMEDIATE`` transaction on a dedicated
    connection. Effects execute against live tables and are measured by
    temporary ``AFTER`` triggers that record before and after images into a
    session-local capture table. ``COMMIT`` makes the work durable;
    ``ROLLBACK`` erases it, capture rows included.

    Temporary triggers are used because they fire on what actually happened,
    including mutations produced by the schema's own triggers and by
    foreign-key cascades. Parsing the agent's SQL to predict the footprint sees
    none of that.

    :param path: SQLite database file.
    :param tables: Tables to observe. A mutation to any other table does not
        appear in the diff. ``EscrowEngine.admit`` rejects a plan whose
        ``Effect.target`` names an unobserved table, but ``target`` is an
        agent-supplied label and is not checked against the statement, so this
        is not a containment boundary. Grant the connection only what these
        tables need.
    :param max_stage_seconds: Bound on stage lifetime. A stage holds write
        locks for its whole life, so this is an operational limit.
    :param commit_markers: Write a row into ``_interlock_commits`` inside
        every stage's own transaction, just before it commits. The row exists
        exactly when the stage's effects do, so after a crash between a
        commit intent and its record, :meth:`resolve_intent` answers whether
        that commit landed. The table is created in the database on first use
        and gains one row per committed stage. Rate windows' history
        (``_interlock_windows``) is bound to it, so windows need it on.
    :param acknowledge_cascades: Unobserved tables a foreign-key action may
        write, unmeasured. By default an operation whose referential actions
        reach an unobserved table is refused (see :meth:`check_cascades`);
        naming the table here lets it run and records the gap on every stage.
        Not lifted by ``enforce_table_access=False``.
    :raises ValueError: If an acknowledged table is also observed.

    The cascade check runs when a stage opens, inside its write lock, against
    the live schema, so a foreign key added since setup is enforced from the
    next stage on. It is cached on SQLite's ``schema_version``. It is enforced
    three times over, because each layer sees a path the others might not:

    - The authorizer refuses a statement that deletes from, or updates a
      referenced column of, an observed table whose action is gated.
    - The authorizer refuses a foreign-key action SQLite compiles into an
      unobserved, unacknowledged table. It catches ``INSERT OR REPLACE`` and
      ``ON CONFLICT REPLACE``, which delete through an ``INSERT``.
    - Temporary ``BEFORE`` triggers on each gated unobserved table abort any
      row change there while the stage is open.
    """

    __slots__ = (
        "_acknowledged",
        "_by_name",
        "_capture_triggers",
        "_charges",
        "_conn",
        "_denied",
        "_enforce",
        "_facts",
        "_folded",
        "_handle",
        "_internal",
        "_journal_start",
        "_journal_triggers",
        "_markers",
        "_max_rows",
        "_order",
        "_outbox",
        "_path",
        "_report",
        "_report_version",
        "_scope",
        "_stage_seconds",
        "_tables",
        "_target",
    )

    def __init__(
        self,
        path: str,
        *,
        tables: Sequence[TableSpec],
        max_stage_seconds: float = 10.0,
        max_diff_rows: int = 50_000,
        enforce_table_access: bool = True,
        commit_markers: bool = True,
        acknowledge_cascades: Collection[str] = (),
    ) -> None:
        self._path = path
        self._tables = tuple(tables)
        self._by_name = {t.name: t for t in tables}
        self._folded = frozenset(t.name.lower() for t in tables)
        self._capture_triggers = frozenset(
            f"ilok_{t.name}_{op}" for t in tables for op in ("i", "u", "d")
        )
        self._journal_triggers = frozenset(
            f"ilok_journal_{t.name}_{op}" for t in tables for op in ("i", "u", "d")
        )
        self._journal_start: int | None = None
        acknowledged = frozenset(a.lower() for a in acknowledge_cascades)
        clash = sorted(acknowledged & self._folded)
        if clash:
            raise ValueError(
                f"acknowledge_cascades names observed table(s) {', '.join(clash)}; a "
                f"cascade into an observed table is measured, so there is no gap to accept"
            )
        self._acknowledged = acknowledged
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._enforce = enforce_table_access
        self._markers = commit_markers
        self._internal = False
        self._target: str | None = None
        self._denied: tuple[str, str, str | None] | None = None
        self._report: CascadeReport | None = None
        self._report_version: int | None = None
        self._conn: sqlite3.Connection | None = None
        self._handle: StageHandle | None = None
        self._order = EnqueueOrder()
        self._scope: str | None = None
        self._outbox = False
        self._charges: tuple[WindowCharge, ...] = ()
        self._facts: tuple[uuid.UUID, ...] = ()

    @property
    def substrate_id(self) -> str:
        return "sqlite"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=True,
            row_level_diff=True,
            snapshot_isolation=True,
            requires_compensation=False,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            outbound=self._markers and self._has_outbox(),
        )

    def _has_outbox(self) -> bool:
        """Whether ``interlock install`` put the outbox in this file. Learned
        once found; looked for again until then, since it may be installed
        while this substrate lives."""
        if self._outbox:
            return True
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
        except sqlite3.Error:
            return False
        try:
            self._outbox = outbox_installed(conn)
        except sqlite3.Error:
            return False
        finally:
            conn.close()
        return self._outbox

    @property
    def observed_tables(self) -> frozenset[str]:
        return frozenset(self._by_name)

    @property
    def commit_markers(self) -> bool:
        """Whether each commit writes the marker :meth:`resolve_intent` reads."""
        return self._markers

    @property
    def cascade_report(self) -> CascadeReport | None:
        """The last cascade check, or ``None`` before the first one."""
        return self._report

    @property
    def table_specs(self) -> tuple[TableSpec, ...]:
        """The tables observed, as configured."""
        return self._tables

    @property
    def enforces_table_access(self) -> bool:
        """Whether a write outside the observed tables is refused."""
        return self._enforce

    def check_cascades(self) -> CascadeReport:
        """Read the foreign-key graph and report every reach out of ``tables``.

        The setup-time form of the check a stage runs when it opens: call it
        (``EscrowRuntime`` does) to learn at startup which operations will be
        refused and which gaps were acknowledged. Each gated reach and each
        acknowledged gap is logged as a warning when the schema changes.

        :raises SubstrateUnavailableError: If the database cannot be read.
        """
        try:
            conn = sqlite3.connect(
                f"file:{self._path}?mode=rw", uri=True, timeout=self._stage_seconds
            )
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open {self._path}: {exc}") from exc
        try:
            return self._cascades(conn)
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(
                f"cannot read the foreign-key graph of {self._path}: {exc}"
            ) from exc
        finally:
            conn.close()

    # -- lifecycle ----------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Bind a connection, install capture triggers, and begin.

        The connection is dedicated for the stage's life and is not returned to
        a pool mid-stage.
        """
        if self._handle is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage {self._handle.stage_id} open"
            )
        try:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=self._stage_seconds)
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open {self._path}: {exc}") from exc

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        # Cascades and the schema's own triggers have to fire through to the
        # capture triggers, or the measurement misses the effects the agent
        # could not have predicted. Note this only captures cascades into
        # tables in self._tables; a cascade into any other table executes and
        # is not measured.
        conn.execute("PRAGMA recursive_triggers=ON")
        if self._markers:
            # Created before any stage can commit, so a missing table later
            # means someone removed it, not that nothing ever committed.
            try:
                conn.execute(_MARKER_DDL)
                for statement in _WINDOWS_DDL:
                    conn.execute(statement)
            except sqlite3.Error as exc:
                conn.close()
                raise StageConflictError(
                    f"could not create the commit-marker table {_MARKER_TABLE}: {exc}"
                ) from exc
        self._install_capture(conn)

        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=uuid.uuid4(),
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        try:
            # A commit is on disk when COMMIT returns. In WAL mode, NORMAL
            # would let a power loss take back the last commits, outbox rows
            # included. (It reads the schema, so it waits for the lock too.)
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            conn.close()
            raise StageConflictError(f"could not acquire a write transaction: {exc}") from exc
        # The graph is read under the write lock, so no schema change can land
        # between the check and the statements it governs.
        try:
            report = self._cascades(conn)
            self._install_sentinels(conn, report)
            self._journal_start = _journal_position(conn)
        except sqlite3.Error as exc:
            conn.close()
            raise SubstrateUnavailableError(
                f"cannot read the foreign-key graph of {self._path}: {exc}"
            ) from exc
        # Installed last, after every statement the substrate issues to set
        # the stage up, so the first statement it covers is the first effect.
        # Always installed: enforce_table_access governs only the
        # unobserved-table rule, never the capture table, the commit marker,
        # transaction control or the cascade gates.
        conn.set_authorizer(self._authorize)
        self._conn = conn
        self._handle = handle
        self._order = EnqueueOrder()
        self._scope = plan.scope_id
        self._charges = ()
        self._facts = ()
        return handle

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from the statement.

        Checks the SQL, not ``Effect.kind``. The kind is authored by the agent
        and nothing compares it against the statement, so a ``DROP TABLE``
        declared as ``kind=UPDATE`` otherwise reaches the substrate, executes,
        fires no row triggers, and measures as an empty diff that every
        diff-reading checker passes.

        This is not a containment boundary on its own. A statement can still
        reach a table outside ``tables``, where the mutation executes and does
        not appear in the diff. Scope the connection's grants.

        :param effect: The effect to vet.
        :returns: A refusal reason, or ``None`` when the effect may be staged.
        """
        verb = leading_verb(effect.statement)
        if verb in FORBIDDEN_VERBS:
            return (
                f"{verb.upper()} is not stageable: it fires no row triggers, so the "
                f"diff would be empty and every measured invariant would pass on "
                f"nothing. Grant the connection no DDL rather than relying on this"
            )
        return None

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Execute one effect inside the open stage. Never commits.

        Re-checks :meth:`reject_reason`. Not redundant with admission: a caller
        driving a substrate directly never passes through the engine.

        :raises ForbiddenStatementError: On a statement this substrate refuses.
        """
        conn = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            outcome = self._enqueue(conn, handle, effect)
            self._order.applied(effect.effect_id, effect.depends_on, request=True)
            return outcome
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(
                f"effect {effect.effect_id!r} refused: {refusal}", reason=_verb_reason(effect)
            )
        self._denied = None
        self._target = None
        try:
            cursor = conn.execute(effect.statement, dict(effect.parameters))
        except sqlite3.Error as exc:
            denied = self._denied
            self._denied = None
            if denied is not None:
                text, reason, table = denied
                raise ForbiddenStatementError(
                    f"effect {effect.effect_id!r} refused: {text}", reason=reason, table=table
                ) from exc
            if _SENTINEL in str(exc):
                raise ForbiddenStatementError(
                    f"effect {effect.effect_id!r} refused: {exc}. A foreign-key action "
                    f"reached a table the cascade check gates; the statement was "
                    f"aborted before the row changed",
                    reason="cascade",
                    table=self._target,
                ) from exc
            if "no name" in str(exc) and effect.parameters:
                raise StageError(
                    f"effect {effect.effect_id!r} failed: {exc}. Effect.parameters is "
                    f"a Mapping, so statements must use named placeholders "
                    f"(:name), not positional ones (?)"
                ) from exc
            raise StageError(f"effect {effect.effect_id!r} failed: {exc}") from exc
        self._order.applied(effect.effect_id, effect.depends_on, request=False)
        return EffectOutcome(
            effect_id=effect.effect_id,
            rows_affected=max(cursor.rowcount, 0),
            applied_at=datetime.now(UTC),
        )

    def _enqueue(
        self, conn: sqlite3.Connection, handle: StageHandle, effect: Effect
    ) -> EffectOutcome:
        """Write one outbound request to the outbox, in the stage's transaction.

        With the authorizer lifted, as for the commit marker: the agent's own
        statements are refused every write to the outbox, at prepare time.
        The row is bound to the commit marker by a deferred foreign key, so it
        commits with the stage, or not at all.
        """
        sink = effect.request.sink if effect.request is not None else None
        if not self._markers or not self._has_outbox():
            raise OutboundRequestError(
                f"effect {effect.effect_id!r} is an outbound request, and this SQLite "
                f"database has no outbox"
                + ("" if self._markers else " (commit markers are off)")
                + ": run `interlock install` with [[sinks]] configured",
                reason="substrate",
                sink=sink,
            )
        if not self._scope:
            raise StageError(f"effect {effect.effect_id!r} needs the scope that pays for it")
        with self._substrate_statements():
            try:
                enqueue(
                    conn,
                    stage_id=handle.stage_id,
                    plan_id=handle.plan_id,
                    scope_id=self._scope,
                    effect=effect,
                    seq=self._order.next_seq(),
                    waits_for=self._order.waits_for(effect.depends_on),
                    idempotency_key=outbound_key(handle.plan_id, effect.effect_id),
                )
            except sqlite3.Error as exc:
                raise StageError(
                    f"effect {effect.effect_id!r} could not be written to the outbox: {exc}"
                ) from exc
        return EffectOutcome(
            effect_id=effect.effect_id, rows_affected=1, applied_at=datetime.now(UTC)
        )

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Read the measured delta out of the capture table.

        Capture rows live inside the same transaction, so call this while the
        stage is open. After a rollback there is nothing left to read.

        One capture row per mutation, not per row: a row mutated twice in one
        plan yields two deltas. See ``EffectDiff.blast_radius``.
        """
        conn = self._require(handle)
        with self._substrate_statements():
            rows = conn.execute(
                f"SELECT tbl, pk, before, after FROM {_CAPTURE_TABLE} "
                f"ORDER BY tbl, pk, rowid LIMIT ?",
                (self._max_rows + 1,),
            ).fetchall()
            requests = (
                stage_requests(conn, handle.stage_id, self._max_rows + 1) if self._outbox else []
            )
            consumed = (
                sqlite_facts(
                    conn,
                    f"f.fact_id IN (SELECT fact_id FROM {SQLITE_CONSUMED} WHERE stage_id = ?)",
                    str(handle.stage_id),
                )
                if self._facts
                else []
            )

        truncated = len(rows) > self._max_rows or len(requests) > self._max_rows
        deltas: list[RowDelta] = []
        for row in rows[: self._max_rows]:
            table = str(row["tbl"])
            spec = self._by_name.get(table)
            before = _load(row["before"])
            after = _load(row["after"])
            tenant: str | None = None
            if spec is not None and spec.tenant_column is not None:
                source = after if after is not None else before
                if source is not None:
                    raw = source.get(spec.tenant_column)
                    tenant = None if raw is None else str(raw)
            deltas.append(
                RowDelta(
                    table=table,
                    primary_key=str(row["pk"]),
                    before=before,
                    after=after,
                    tenant_id=tenant,
                )
            )
        return EffectDiff(
            plan_id=handle.plan_id,
            stage_id=handle.stage_id,
            substrate_id=self.substrate_id,
            computed_at=datetime.now(UTC),
            deltas=tuple(deltas),
            truncated=truncated,
            outbound=tuple(requests[: self._max_rows]),
            facts=tuple(consumed),
        )

    # -- inbound facts (docs/EPIC5_DESIGN.md §2) --------------------------------

    def pending_facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        """The facts pending for ``scope_id``, read outside any stage, on a
        connection of their own that reads and writes nothing else."""
        try:
            conn = sqlite3.connect(
                f"file:{self._path}?mode=rw", uri=True, timeout=self._stage_seconds
            )
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open {self._path}: {exc}") from exc
        try:
            if not outbox_installed(conn) or not sqlite_has(conn, SQLITE_FACTS):
                raise SubstrateConfigurationError(
                    f"{self._path} has no inbox: run `interlock install` with this version"
                )
            return tuple(
                sqlite_facts(
                    conn,
                    f"f.scope_id = ? AND NOT EXISTS (SELECT 1 FROM {SQLITE_CONSUMED} AS c "
                    f"WHERE c.fact_id = f.fact_id)",
                    scope_id,
                )
            )
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(
                f"cannot read the inbox from {self._path}: {exc}"
            ) from exc
        finally:
            conn.close()

    def consume_facts(
        self, handle: StageHandle, fact_ids: Sequence[uuid.UUID], scope_id: str
    ) -> None:
        """Consume the plan's facts in its stage: each its scope's, and not
        consumed already. The rows commit with the stage's marker, or not at
        all.

        :raises InboundFactError: If a fact is unknown, another scope's, or
            consumed already.
        :raises StageError: If commit markers are off: consumption is bound to
            them.
        """
        conn = self._require(handle)
        self._assert_live(handle)
        if not self._markers:
            raise StageError(
                "facts are consumed beside the commit marker; this substrate has "
                "commit_markers=False"
            )
        try:
            with self._substrate_statements():
                for fact_id in fact_ids:
                    row = conn.execute(
                        f"SELECT scope_id FROM {SQLITE_FACTS} WHERE fact_id = ?", (str(fact_id),)
                    ).fetchone()
                    if row is None or row[0] != scope_id:
                        raise InboundFactError(f"no fact {fact_id} for scope {scope_id!r}")
                    conn.execute(
                        f"INSERT INTO {SQLITE_CONSUMED} (fact_id, stage_id, at) VALUES (?, ?, ?)",
                        (str(fact_id), str(handle.stage_id), now_us()),
                    )
        except sqlite3.IntegrityError as exc:
            raise InboundFactError(f"a fact the plan consumes was consumed already: {exc}") from exc
        except sqlite3.Error as exc:
            raise StageError(f"could not consume the plan's facts: {exc}") from exc
        self._facts = tuple(fact_ids)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        """What each window holds for each key the plan adds to.

        Read in the stage, which is exact: the stage has held the database's
        write lock since ``BEGIN IMMEDIATE``, so no other stage has committed
        since its snapshot or can until it ends. What the plan adds is
        written with its commit marker, if it commits.

        :raises StageError: If commit markers are off: window history is
            bound to them.
        """
        conn = self._require(handle)
        self._assert_live(handle)
        if not self._markers:
            raise StageError(
                "rate windows keep their history beside the commit marker; this "
                "substrate has commit_markers=False"
            )
        now = now_us()
        measures: list[WindowMeasure] = []
        try:
            with self._substrate_statements():
                # A window reaching back before the latest checkpoint's window
                # horizon would be read short: what it held there was pruned
                # (docs/EPIC5_DESIGN.md §1.8). Fail closed.
                pruned = _windows_watermark(conn)
                if pruned is not None and any(
                    now - _microseconds(c.span) < pruned for c in charges
                ):
                    raise SubstrateConfigurationError(
                        "a rate window reaches back past the history a checkpoint pruned: the "
                        "vacuum was run with windows shorter than this engine's. It cannot be "
                        "measured until it no longer does"
                    )
                for charge in charges:
                    rows = conn.execute(
                        f"SELECT amount FROM main.{WINDOWS_TABLE} "
                        f"WHERE window_name = ? AND key = ? AND at > ?",
                        (charge.window, charge.key, now - _microseconds(charge.span)),
                    ).fetchall()
                    history = sum((Decimal(str(r[0])) for r in rows), Decimal(0))
                    measures.append(
                        WindowMeasure(charge.window, charge.key, history, charge.amount)
                    )
        except sqlite3.Error as exc:
            raise StageError(f"could not read the rate windows' history: {exc}") from exc
        self._charges = tuple(charges)
        return tuple(measures)

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Make the staged work durable.

        With commit markers on, the stage's marker row is written inside the
        same transaction immediately before ``COMMIT``, so it becomes durable
        with the effects or not at all; and with it, what the plan adds to
        each rate window it was measured against.
        """
        conn = self._require(handle)
        self._assert_live(handle)
        committed_at = datetime.now(UTC)
        try:
            with self._substrate_statements():
                if self._charges:
                    at = now_us()
                    conn.executemany(
                        f"INSERT INTO main.{WINDOWS_TABLE} "
                        f"(stage_id, window_name, key, amount, at) VALUES (?, ?, ?, ?, ?)",
                        [
                            (
                                str(handle.stage_id),
                                c.window,
                                c.key,
                                format(c.amount.normalize(), "f"),
                                at,
                            )
                            for c in self._charges
                        ],
                    )
                if self._journal_start is not None:
                    # Exact: BEGIN IMMEDIATE admits one writer, so every
                    # journal row numbered after the stage opened is its own.
                    conn.execute(
                        f"INSERT INTO main.{STAGE_JOURNAL_TABLE} (stage_id, first_seq, last_seq) "
                        f"VALUES (?, ?, ?)",
                        (str(handle.stage_id), self._journal_start + 1, _journal_position(conn)),
                    )
                if self._markers:
                    conn.execute(
                        f"INSERT INTO main.{_MARKER_TABLE} (stage_id, plan_id, committed_at) "
                        f"VALUES (?, ?, ?)",
                        (str(handle.stage_id), handle.plan_id, committed_at.isoformat()),
                    )
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise StageError(f"commit failed: {exc}") from exc
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=committed_at,
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=None,
        )

    def resolve_intent(self, stage_id: uuid.UUID) -> bool | None:
        """Whether a stage's transaction committed, read from its commit marker.

        Exact, not a guess: the marker was written inside the stage's own
        transaction, so it is present if and only if the effects are. Reads
        through a fresh connection, which also rolls back any transaction a
        crashed process left half-written.

        :returns: ``True`` if the stage committed, ``False`` if it did not, or
            ``None`` if this database has no marker table, so cannot say.
        :raises SubstrateUnavailableError: If the database cannot be read.
        """
        try:
            conn = sqlite3.connect(
                f"file:{self._path}?mode=rw", uri=True, timeout=self._stage_seconds
            )
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open {self._path}: {exc}") from exc
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (_MARKER_TABLE,),
            ).fetchone()
            if exists is None:
                return None
            found = conn.execute(
                f"SELECT 1 FROM main.{_MARKER_TABLE} WHERE stage_id = ?", (str(stage_id),)
            ).fetchone()
            return found is not None
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(
                f"cannot read commit markers from {self._path}: {exc}"
            ) from exc
        finally:
            conn.close()

    def savepoint(self, handle: StageHandle, name: str) -> None:
        """Mark the stage's state now, to return to with :meth:`rollback_to`.

        The capture table is rolled back with everything else, so after a
        return :meth:`diff` measures only what ran since the mark.

        :raises ValueError: If ``name`` is not a plain identifier.
        """
        self._savepoint_statement(handle, "SAVEPOINT", name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        """Undo everything since :meth:`savepoint` ``name``; the mark stays."""
        self._savepoint_statement(handle, "ROLLBACK TO", name)

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        """Forget a mark, keeping what ran since it."""
        self._savepoint_statement(handle, "RELEASE", name)

    def _savepoint_statement(self, handle: StageHandle, verb: str, name: str) -> None:
        conn = self._require(handle)
        _assert_identifier(name)
        try:
            with self._substrate_statements():
                conn.execute(f"{verb} {name}")
        except sqlite3.Error as exc:
            raise StageError(f"{verb} {name} failed: {exc}") from exc

    def abort(self, handle: StageHandle) -> None:
        """Roll back. Safe in any state, including after a commit."""
        conn = self._conn
        if conn is None or self._handle is None or self._handle.stage_id != handle.stage_id:
            return
        try:
            with self._substrate_statements():
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            # Already resolved. abort() runs on error paths, where raising
            # would replace the original exception with this one.
            pass

    def close(self, handle: StageHandle) -> None:
        """Release the connection, rolling back first if still open."""
        if self._handle is None or self._handle.stage_id != handle.stage_id:
            return
        self.abort(handle)
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._handle = None

    # -- internals ----------------------------------------------------------

    def _require(self, handle: StageHandle) -> sqlite3.Connection:
        if self._conn is None or self._handle is None or self._handle.stage_id != handle.stage_id:
            raise StageError(f"stage {handle.stage_id} is not open on this substrate")
        return self._conn

    def _assert_live(self, handle: StageHandle) -> None:
        if datetime.now(UTC) > handle.expires_at:
            raise StageExpiredError(
                f"stage {handle.stage_id} exceeded its {self._stage_seconds}s bound "
                f"while holding write locks"
            )

    @contextmanager
    def _substrate_statements(self) -> Iterator[None]:
        """Statements the substrate itself issues: the authorizer lets them by.

        The commit marker, ``COMMIT``, ``ROLLBACK`` and the capture read. Each
        is authored here, never by the agent, so none needs the checks that
        exist to bound what the agent's statements reach.
        """
        self._internal = True
        try:
            yield
        finally:
            self._internal = False

    def _cascades(self, conn: sqlite3.Connection) -> CascadeReport:
        """The cascade report for the schema ``conn`` sees, cached on its version."""
        version = int(conn.execute("PRAGMA main.schema_version").fetchone()[0])
        if self._report is not None and self._report_version == version:
            return self._report
        report = analyze_cascades(read_sqlite_foreign_keys(conn), self._folded, self._acknowledged)
        previous = self._report
        self._report = report
        self._report_version = version
        log_report(logger, previous, report)
        return report

    def _install_sentinels(self, conn: sqlite3.Connection, report: CascadeReport) -> None:
        """Abort any row change in a gated unobserved table while the stage is open.

        The authorizer refuses the operations that would reach these tables.
        This is the layer that does not depend on it: whatever path a write
        takes into the table, SQLite fires these triggers first. Temporary, so
        they exist on this connection only and die with it.
        """
        for index, table in enumerate(sorted(report.unmonitored_tables())):
            quoted = '"' + table.replace('"', '""') + '"'
            message = f"{_SENTINEL} unobserved table {table} during a stage"
            literal = "'" + message.replace("'", "''") + "'"
            for op, suffix in (("DELETE", "d"), ("UPDATE", "u")):
                conn.execute(
                    f"CREATE TEMP TRIGGER ilok_guard_{index}_{suffix} BEFORE {op} "
                    f"ON main.{quoted} BEGIN SELECT RAISE(ABORT, {literal}); END"
                )

    def _authorize(
        self,
        action: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        trigger_name: str | None,
    ) -> int:
        """SQLite authorizer: bound what a stage's statements can write.

        Runs inside SQLite at statement-prepare time, so a denied statement
        never executes at all — this is enforcement in the engine, not a
        predicate over a diff that was never captured. It closes the cases
        ``reject_reason`` cannot see, because it reads what SQLite is about to
        do rather than the statement's leading word:

        - A write to a table outside ``tables``, whatever ``Effect.target``
          claims (unless ``enforce_table_access=False``).
        - A write to the capture table, which would rewrite the measurement,
          except by the capture triggers themselves.
        - A write to the commit marker, which would forge a recovery answer.
        - Transaction control, which would commit before adjudication.
        - A cascade-gated delete or key update (see :mod:`interlock.cascade`),
          and a foreign-key action SQLite compiles into an unobserved table.

        Reads are left alone, but for the tables that hold everyone's
        activity. A statement may legitimately join or subquery a table it
        does not write, and denying reads would break correct plans without
        bounding any effect. The exceptions are the rate windows' history,
        which records what every plan, of every agent and tenant, added to
        each window, and the inbox, which holds every scope's facts and the
        vendors' raw bodies: no statement of a plan reads either. A plan
        reads its scope's facts the one way the engine gives it, typed and
        attested (``EscrowEngine.facts``).

        :returns: ``SQLITE_OK`` or ``SQLITE_DENY``.
        """
        if self._internal:
            return sqlite3.SQLITE_OK
        if action in _CONTROL_ACTIONS:
            return self._deny(
                f"statement attempts transaction control ({arg1 or 'SAVEPOINT'}). The "
                f"stage's transaction belongs to the substrate: a COMMIT inside it makes "
                f"the effects durable before they are measured or adjudicated",
                "transaction_control",
            )
        if action in _REACH_ACTIONS:
            return self._deny(
                f"statement attempts {_REACH_ACTIONS[action]} on {arg1 or ''!r}, which "
                f"reaches outside the database being measured",
                "reach",
            )
        if action == sqlite3.SQLITE_READ and (arg1 or "").lower() == WINDOWS_TABLE:
            # The one table a stage may not read: what every plan, of every
            # agent and tenant, added to each rate window.
            return self._deny(
                f"statement reads {arg1!r}, the rate windows' history, which holds other "
                f"plans' activity",
                "protected",
            )
        if action == sqlite3.SQLITE_READ and (arg1 or "").lower() in SQLITE_INBOX_TABLES:
            # Nor the inbox: every scope's facts, and the vendors' raw bodies.
            return self._deny(
                f"statement reads {arg1!r}, the inbox, which holds every scope's facts",
                "protected",
            )
        if action not in _WRITE_ACTIONS:
            return sqlite3.SQLITE_OK
        verb = _WRITE_ACTIONS[action]
        table = arg1 or ""
        key = table.lower()
        if key == _CAPTURE_TABLE:
            # Written by the capture triggers and nothing else. A statement
            # that deleted from it would erase the measurement, and the diff
            # would read as empty to every checker.
            if trigger_name in self._capture_triggers:
                return sqlite3.SQLITE_OK
            return self._deny(
                f"statement attempts {verb} on the capture table {table!r}, which "
                f"holds the stage's measurement",
                "protected",
            )
        if key == JOURNAL_TABLE:
            # Written by the journal triggers alone, like the capture table:
            # a statement that deleted journal rows would hide an
            # out-of-band write from reconciliation.
            if trigger_name in self._journal_triggers:
                return sqlite3.SQLITE_OK
            return self._deny(
                f"statement attempts {verb} on the journal table {table!r}, which "
                f"only the journal triggers write",
                "protected",
            )
        if key == STAGE_JOURNAL_TABLE:
            return self._deny(
                f"statement attempts {verb} on {table!r}, which only the substrate writes",
                "protected",
            )
        if key in OUTBOX_TABLES:
            # Written by the substrate (a request, in its stage) and by relays
            # and operators, each through Interlock's own code. A statement
            # that wrote here would enqueue what was never adjudicated, or
            # mark a request delivered.
            return self._deny(
                f"statement attempts {verb} on {table!r}, which only the substrate, the "
                f"relay and operators write",
                "protected",
            )
        if key == WINDOWS_TABLE:
            # Written by commit() alone, with the marker. A statement that
            # deleted from it would reopen a window; one that wrote to it would
            # close another's.
            return self._deny(
                f"statement attempts {verb} on {table!r}, the rate windows' history, which "
                f"only the substrate writes",
                "protected",
            )
        if key == _MARKER_TABLE:
            # Written by commit() alone. A statement the agent authored that
            # forged one would make recovery report a crashed stage as
            # committed.
            return self._deny(
                f"statement attempts {verb} on the commit-marker table {table!r}, "
                f"which only the substrate writes",
                "protected",
            )
        # sqlite_* internal tables are touched by the engine itself, never by
        # a statement the agent authored; denying them breaks SQLite.
        if key.startswith("sqlite_"):
            return sqlite3.SQLITE_OK

        gate = self._report.gates().get(key) if self._report is not None else None
        if gate is not None and self._report is not None:
            if action == sqlite3.SQLITE_DELETE and gate.delete:
                return self._deny(self._report.refusal(table, "delete"), "cascade", table)
            if action == sqlite3.SQLITE_UPDATE:
                column = (arg2 or "").lower()
                if gate.blocks_update_of(column) or (
                    column in _ROWID_ALIASES and (gate.update_columns or gate.update_any)
                ):
                    return self._deny(
                        self._report.refusal(table, "update", arg2 or ""), "cascade", table
                    )

        if trigger_name is None:
            # SQLite has no multi-table DML: the first unnamed write in a
            # statement is the statement's own target. A later unnamed write to
            # another table is a foreign-key action SQLite compiled for it.
            if self._target is None:
                self._target = key
            elif key != self._target and key not in self._folded:
                if key in self._acknowledged:
                    return sqlite3.SQLITE_OK
                return self._deny(
                    f"statement's foreign-key action attempts {verb} on {table!r}, "
                    f"which this substrate does not observe; the rows it changed there "
                    f"would not appear in the diff. Observe the table, or accept the "
                    f"unmeasured write with acknowledge_cascades",
                    "cascade",
                    self._target,
                )

        if key in self._folded or not self._enforce:
            return sqlite3.SQLITE_OK
        return self._deny(
            f"statement attempts {verb} on {table!r}, which this substrate does not "
            f"observe. A write there would execute, commit, and measure as an empty "
            f"diff that every invariant passes. Observed tables: "
            f"{', '.join(sorted(self._by_name)) or '<none>'}",
            "unobserved_table",
            table,
        )

    def _deny(self, text: str, reason: str, table: str | None = None) -> int:
        # The first denial is the one that names the statement's real problem;
        # SQLite may call back again while unwinding the prepare.
        if self._denied is None:
            self._denied = (text, reason, table)
        return sqlite3.SQLITE_DENY

    def _install_capture(self, conn: sqlite3.Connection) -> None:
        """Create the session-local capture table and its triggers."""
        conn.execute(
            f"CREATE TEMP TABLE IF NOT EXISTS {_CAPTURE_TABLE} "
            f"(tbl TEXT NOT NULL, pk TEXT NOT NULL, before TEXT, after TEXT)"
        )
        conn.execute(f"DELETE FROM {_CAPTURE_TABLE}")
        for spec in self._tables:
            old = spec.json_object("OLD")
            new = spec.json_object("NEW")
            pk = spec.primary_key
            # Identifiers are interpolated because SQL has no parameter
            # binding for table or column names in DDL. All of them were
            # validated by _assert_identifier at TableSpec construction and
            # come from operator config, not from the agent.
            conn.executescript(
                f"""
                DROP TRIGGER IF EXISTS temp.ilok_{spec.name}_i;
                DROP TRIGGER IF EXISTS temp.ilok_{spec.name}_u;
                DROP TRIGGER IF EXISTS temp.ilok_{spec.name}_d;
                CREATE TEMP TRIGGER ilok_{spec.name}_i AFTER INSERT ON main.{spec.name}
                BEGIN
                  INSERT INTO {_CAPTURE_TABLE}(tbl, pk, before, after)
                  VALUES ('{spec.name}', CAST(NEW.{pk} AS TEXT), NULL, {new});
                END;
                CREATE TEMP TRIGGER ilok_{spec.name}_u AFTER UPDATE ON main.{spec.name}
                BEGIN
                  INSERT INTO {_CAPTURE_TABLE}(tbl, pk, before, after)
                  VALUES ('{spec.name}', CAST(NEW.{pk} AS TEXT), {old}, {new});
                END;
                CREATE TEMP TRIGGER ilok_{spec.name}_d AFTER DELETE ON main.{spec.name}
                BEGIN
                  INSERT INTO {_CAPTURE_TABLE}(tbl, pk, before, after)
                  VALUES ('{spec.name}', CAST(OLD.{pk} AS TEXT), {old}, NULL);
                END;
                """
            )


def _windows_watermark(conn: sqlite3.Connection) -> int | None:
    """The latest window horizon a checkpoint pruned history at, or ``None``."""
    if (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (CHECKPOINTS,)
        ).fetchone()
        is None
    ):
        return None
    row = conn.execute(f"SELECT max(windows_horizon) FROM main.{CHECKPOINTS}").fetchone()
    return None if row is None or row[0] is None else int(row[0])


def _microseconds(span: timedelta) -> int:
    return span // timedelta(microseconds=1)


def _load(raw: object) -> Mapping[str, Any] | None:
    if raw is None:
        return None
    parsed: Any = json.loads(str(raw))
    return parsed if isinstance(parsed, dict) else None


def _journal_position(conn: sqlite3.Connection) -> int | None:
    """The journal's high-water mark, or ``None`` when it is not installed.

    Read from ``sqlite_sequence``, which AUTOINCREMENT never moves backwards,
    so a deleted journal row cannot make two stages claim the same number.
    """
    installed = conn.execute(
        "SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?", (JOURNAL_TABLE,)
    ).fetchone()
    if installed is None:
        return None
    row = conn.execute(
        "SELECT seq FROM main.sqlite_sequence WHERE name = ?", (JOURNAL_TABLE,)
    ).fetchone()
    return int(row[0]) if row is not None else 0


_CONTROL_VERBS = frozenset({"begin", "commit", "end", "rollback", "savepoint", "release"})


def _verb_reason(effect: Effect) -> str:
    """The structured reason for a refusal read from a statement's leading verb."""
    return (
        "transaction_control"
        if leading_verb(effect.statement) in _CONTROL_VERBS
        else ("statement_kind")
    )
