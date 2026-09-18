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

__all__ = ["ShadowSubstrate", "SqliteSubstrate", "TableSpec"]

_CAPTURE_TABLE = "_interlock_capture"
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

    def open(self, plan: EffectPlan) -> StageHandle: ...

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome: ...

    def diff(self, handle: StageHandle) -> EffectDiff: ...

    def commit(self, handle: StageHandle) -> CommitReceipt: ...

    def abort(self, handle: StageHandle) -> None: ...

    def close(self, handle: StageHandle) -> None: ...


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
    """

    __slots__ = ("_by_name", "_conn", "_handle", "_max_rows", "_path", "_stage_seconds", "_tables")

    def __init__(
        self,
        path: str,
        *,
        tables: Sequence[TableSpec],
        max_stage_seconds: float = 10.0,
        max_diff_rows: int = 50_000,
    ) -> None:
        self._path = path
        self._tables = tuple(tables)
        self._by_name = {t.name: t for t in tables}
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
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
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            conn.close()
            raise StageConflictError(f"could not acquire a write transaction: {exc}") from exc
        self._conn = conn
        self._handle = handle
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Execute one effect inside the open stage. Never commits."""
        conn = self._require(handle)
        self._assert_live(handle)
        try:
            cursor = conn.execute(effect.statement, dict(effect.parameters))
        except sqlite3.Error as exc:
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
        """Make the staged work durable."""
        conn = self._require(handle)
        self._assert_live(handle)
        try:
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise StageError(f"commit failed: {exc}") from exc
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=datetime.now(UTC),
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=None,
        )

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
