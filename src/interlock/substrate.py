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
the tables in ``tables``. A mutation to anything else is invisible here and the
diff will not say so. See ``EscrowEngine.admit`` for what is and is not gated.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from interlock.exceptions import (
    ForbiddenStatementError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateUnavailableError,
)
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectOutcome,
    EffectPlan,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
)

__all__ = [
    "FORBIDDEN_VERBS",
    "ShadowSubstrate",
    "SqliteSubstrate",
    "TableSpec",
    "leading_verb",
]

_CAPTURE_TABLE = "_interlock_capture"

_MARKER_TABLE = "_interlock_commits"
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


# A driver may also implement ``resolve_intent(stage_id) -> bool | None``: did
# that stage's transaction commit? ``EscrowEngine.recover`` asks it about every
# commit intent a crashed process left open, and leaves the intent open when
# the driver cannot say. It is not part of the protocol, so a driver without it
# still satisfies ``isinstance(driver, ShadowSubstrate)``.


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
        and gains one row per committed stage.
    """

    __slots__ = (
        "_by_name",
        "_conn",
        "_denied",
        "_enforce",
        "_handle",
        "_markers",
        "_marking",
        "_max_rows",
        "_path",
        "_stage_seconds",
        "_tables",
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
    ) -> None:
        self._path = path
        self._tables = tuple(tables)
        self._by_name = {t.name: t for t in tables}
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._enforce = enforce_table_access
        self._markers = commit_markers
        self._marking = False
        self._denied: tuple[str, str] | None = None
        self._conn: sqlite3.Connection | None = None
        self._handle: StageHandle | None = None

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
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        return frozenset(self._by_name)

    @property
    def commit_markers(self) -> bool:
        """Whether each commit writes the marker :meth:`resolve_intent` reads."""
        return self._markers

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
            except sqlite3.Error as exc:
                conn.close()
                raise StageConflictError(
                    f"could not create the commit-marker table {_MARKER_TABLE}: {exc}"
                ) from exc
        self._install_capture(conn)
        # Installed *after* the capture DDL, which would otherwise be denied
        # by its own authorizer, and before BEGIN, so the first statement of
        # the stage is already covered.
        if self._enforce:
            conn.set_authorizer(self._authorize)

        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=uuid.uuid4(),
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            conn.close()
            raise StageConflictError(f"could not acquire a write transaction: {exc}") from exc
        self._conn = conn
        self._handle = handle
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
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(f"effect {effect.effect_id!r} refused: {refusal}")
        self._denied = None
        try:
            cursor = conn.execute(effect.statement, dict(effect.parameters))
        except sqlite3.Error as exc:
            denied = self._denied
            self._denied = None
            if denied is not None:
                verb, table = denied
                raise ForbiddenStatementError(
                    f"effect {effect.effect_id!r} refused: statement attempts "
                    f"{verb} on {table!r}, which this substrate does not observe. "
                    f"A write there would execute, commit, and measure as an empty "
                    f"diff that every invariant passes. Observed tables: "
                    f"{', '.join(sorted(self._by_name)) or '<none>'}"
                ) from exc
            if "no name" in str(exc) and effect.parameters:
                raise StageError(
                    f"effect {effect.effect_id!r} failed: {exc}. Effect.parameters is "
                    f"a Mapping, so statements must use named placeholders "
                    f"(:name), not positional ones (?)"
                ) from exc
            raise StageError(f"effect {effect.effect_id!r} failed: {exc}") from exc
        return EffectOutcome(
            effect_id=effect.effect_id,
            rows_affected=max(cursor.rowcount, 0),
            applied_at=datetime.now(UTC),
        )

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Read the measured delta out of the capture table.

        Capture rows live inside the same transaction, so call this while the
        stage is open. After a rollback there is nothing left to read.

        One capture row per mutation, not per row: a row mutated twice in one
        plan yields two deltas. See ``EffectDiff.blast_radius``.
        """
        conn = self._require(handle)
        rows = conn.execute(
            f"SELECT tbl, pk, before, after FROM {_CAPTURE_TABLE} ORDER BY tbl, pk, rowid LIMIT ?",
            (self._max_rows + 1,),
        ).fetchall()

        truncated = len(rows) > self._max_rows
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
        )

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Make the staged work durable.

        With commit markers on, the stage's marker row is written inside the
        same transaction immediately before ``COMMIT``, so it becomes durable
        with the effects or not at all.
        """
        conn = self._require(handle)
        self._assert_live(handle)
        committed_at = datetime.now(UTC)
        try:
            if self._markers:
                self._marking = True
                try:
                    conn.execute(
                        f"INSERT INTO main.{_MARKER_TABLE} (stage_id, plan_id, committed_at) "
                        f"VALUES (?, ?, ?)",
                        (str(handle.stage_id), handle.plan_id, committed_at.isoformat()),
                    )
                finally:
                    self._marking = False
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

    def abort(self, handle: StageHandle) -> None:
        """Roll back. Safe in any state, including after a commit."""
        conn = self._conn
        if conn is None or self._handle is None or self._handle.stage_id != handle.stage_id:
            return
        try:
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

    def _authorize(
        self,
        action: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        trigger_name: str | None,
    ) -> int:
        """SQLite authorizer: deny row mutations outside ``tables``.

        Runs inside SQLite at statement-prepare time, so a denied statement
        never executes at all — this is enforcement in the engine, not a
        predicate over a diff that was never captured. It closes the case
        ``reject_reason`` cannot see: an ``Effect.target`` label claiming an
        observed table while the statement writes somewhere else.

        Reads are left alone. A statement may legitimately join or subquery a
        table it does not write, and denying reads would break correct plans
        without bounding any effect.

        :returns: ``SQLITE_OK`` or ``SQLITE_DENY``.
        """
        if action in _WRITE_ACTIONS:
            table = arg1 or ""
            if table == _CAPTURE_TABLE or table in self._by_name:
                return sqlite3.SQLITE_OK
            # The commit marker is written by commit() alone. A statement the
            # agent authored that forged one would make recovery report a
            # crashed stage as committed.
            if table == _MARKER_TABLE and self._marking and db_name == "main":
                return sqlite3.SQLITE_OK
            # sqlite_* internal tables are touched by the engine itself, never
            # by a statement the agent authored; denying them breaks SQLite.
            if table.startswith("sqlite_"):
                return sqlite3.SQLITE_OK
            self._denied = (_WRITE_ACTIONS[action], table)
            return sqlite3.SQLITE_DENY
        if action in _REACH_ACTIONS:
            self._denied = (_REACH_ACTIONS[action], arg1 or "")
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

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


def _load(raw: object) -> Mapping[str, Any] | None:
    if raw is None:
        return None
    parsed: Any = json.loads(str(raw))
    return parsed if isinstance(parsed, dict) else None
