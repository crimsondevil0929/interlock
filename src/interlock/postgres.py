"""PostgreSQL: stage in ``REPEATABLE READ``, measure with triggers installed once.

``interlock install`` (or :func:`install`) puts a small ``interlock`` schema
into the database and one row trigger on each observed table. Nothing is
created or altered on those tables per stage, so staging never takes the
schema lock a busy table cannot spare.

For a transaction that opened no stage, the trigger logs the write to
``interlock.unmediated`` for ``interlock reconcile-effects``. For one that did,
it writes each row's before and after image into a temporary table that exists
only in that session and only for that transaction. Whether a
transaction opened a stage is read from ``interlock.stages``, keyed by
``pg_current_xact_id()``, and not from the ``interlock.stage_id`` setting
alone: a setting is a string any statement can change, and the stage's row is
one only :func:`interlock.begin_stage` can write. The setting is still set,
for anyone watching, and the trigger refuses to proceed when the two disagree.

What the agent's statements cannot touch, because the database says so:

- The capture table, the stage row and the gates are owned by the role that
  ran ``install`` and written only through ``SECURITY DEFINER`` functions. The
  stage's role has no privilege on any of them.
- The triggers are ``ENABLE ALWAYS``, so ``session_replication_role`` does
  not switch them off.
- A table outside ``tables``: at every stage the substrate checks that the
  stage's role, and every role it belongs to, can write no other table (the
  grant is the boundary here; PostgreSQL has no statement authorizer), and
  that it owns no observed table (an owner can disable a trigger).
- Transaction control and multiple statements: only row statements are
  accepted, and each is sent as a prepared statement, which the server
  refuses to split.

``pg_current_xact_id()`` is recorded when the stage opens and written into the
commit intent, so :meth:`PostgresSubstrate.resolve_intent` can tell a stage
whose transaction is still running on the server from one that rolled back.
The stage row itself is the commit marker: it commits with the effects or not
at all.

Statements use psycopg's placeholders: ``%(name)s``, and ``%%`` for a literal
percent sign.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Collection, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final

from interlock.cascade import (
    CascadeReport,
    analyze_cascades,
    log_report,
    read_postgres_foreign_keys,
)
from interlock.exceptions import (
    ForbiddenStatementError,
    InterlockError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.substrate import TableSpec, _verb_reason, leading_verb
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

if TYPE_CHECKING:
    import psycopg

__all__ = [
    "INSTALL_VERSION",
    "STAGEABLE_VERBS",
    "PostgresSubstrate",
    "install",
]

logger = logging.getLogger("interlock.postgres")

INSTALL_VERSION: Final = "1"
"""Bumped when the installed functions change in a way a stage depends on."""

STAGEABLE_VERBS: Final = frozenset(
    {"select", "insert", "update", "delete", "merge", "with", "values", "table"}
)
"""Leading words a PostgreSQL stage accepts. An allowlist, not a denylist:
PostgreSQL has far more statements than SQLite that change what a stage is
(``SET``, ``DO``, ``CALL``, ``COPY``, ``LOCK``, ``PREPARE``...), and no
authorizer behind the text check to catch one this list missed."""

_CAPTURE_TRIGGER: Final = "interlock_capture"
_TRUNCATE_TRIGGER: Final = "interlock_truncate"
_ROW_TRIGGER_TYPE: Final = 1 | 4 | 8 | 16
"""``pg_trigger.tgtype`` for ``AFTER INSERT OR UPDATE OR DELETE FOR EACH ROW``."""
_TRUNCATE_TRIGGER_TYPE: Final = 32
"""``pg_trigger.tgtype`` for ``AFTER TRUNCATE FOR EACH STATEMENT``."""

_GATED: Final = "IL001"
_TAMPERED: Final = "IL002"
_CONFLICTS: Final = frozenset({"40001", "40P01", "55P03"})
"""Serialization failure, deadlock, lock not available: another writer won."""
_CANCELLED: Final = "57014"
_PRIVILEGE: Final = "42501"
_NOT_INSTALLED: Final = frozenset({"42883", "42P01", "3F000"})
"""Undefined function, undefined table, undefined schema."""


_FUNCTIONS: Final = r"""
CREATE OR REPLACE FUNCTION interlock.begin_stage(p_stage uuid, p_plan text, p_gates jsonb)
RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    x xid8 := pg_catalog.pg_current_xact_id();
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'repeatable read' THEN
        RAISE EXCEPTION 'interlock: a stage runs in REPEATABLE READ, not %',
            pg_catalog.current_setting('transaction_isolation')
            USING ERRCODE = 'IL003';
    END IF;
    CREATE TEMP TABLE interlock_capture (
        seq bigint GENERATED ALWAYS AS IDENTITY,
        tbl text NOT NULL,
        pk text NOT NULL,
        before jsonb,
        after jsonb
    ) ON COMMIT DROP;
    INSERT INTO interlock.stages (stage_id, plan_id, xid, gates)
    VALUES (p_stage, p_plan, x, p_gates);
    PERFORM pg_catalog.set_config('interlock.stage_id', p_stage::text, true);
    RETURN x;
END
$fn$;

CREATE OR REPLACE FUNCTION interlock.capture()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    marker text := pg_catalog.current_setting('interlock.stage_id', true);
    stage uuid;
    gates jsonb;
    gate jsonb;
    old_row jsonb;
    new_row jsonb;
    keep text[];
    col text;
BEGIN
    SELECT s.stage_id, s.gates INTO stage, gates
      FROM interlock.stages s
     WHERE s.xid = pg_catalog.pg_current_xact_id();
    IF stage IS NULL THEN
        IF coalesce(marker, '') <> '' THEN
            RAISE EXCEPTION
                'interlock: interlock.stage_id is set, but this transaction opened no stage'
                USING ERRCODE = 'IL002';
        END IF;
        -- Not mediated: nothing measured this write and nothing adjudicated
        -- it. Logged for reconciliation, in the writer's own transaction, so
        -- the entry exists exactly when the write does.
        IF TG_LEVEL = 'STATEMENT' THEN
            INSERT INTO interlock.unmediated (xid, tbl, pk, op)
            VALUES (pg_catalog.pg_current_xact_id(), TG_TABLE_NAME, NULL, 'truncate');
        ELSE
            INSERT INTO interlock.unmediated (xid, tbl, pk, op)
            VALUES (
                pg_catalog.pg_current_xact_id(),
                TG_TABLE_NAME,
                coalesce(pg_catalog.to_jsonb(NEW), pg_catalog.to_jsonb(OLD)) ->> TG_ARGV[0],
                pg_catalog.lower(TG_OP)
            );
        END IF;
        RETURN NULL;
    END IF;
    IF marker IS DISTINCT FROM stage::text THEN
        RAISE EXCEPTION 'interlock: interlock.stage_id was changed inside stage %', stage
            USING ERRCODE = 'IL002';
    END IF;
    IF TG_LEVEL = 'STATEMENT' THEN
        RAISE EXCEPTION 'interlock: TRUNCATE on % inside a stage', TG_TABLE_NAME
            USING ERRCODE = 'IL001',
                  DETAIL = pg_catalog.json_build_object(
                      'table', TG_TABLE_NAME, 'operation', 'truncate')::text;
    END IF;
    IF TG_OP <> 'INSERT' THEN old_row := pg_catalog.to_jsonb(OLD); END IF;
    IF TG_OP <> 'DELETE' THEN new_row := pg_catalog.to_jsonb(NEW); END IF;

    gate := gates -> TG_TABLE_NAME;
    IF gate IS NOT NULL THEN
        IF TG_OP = 'DELETE' AND (gate ->> 'delete')::boolean THEN
            RAISE EXCEPTION 'interlock: DELETE on % is gated by the cascade check', TG_TABLE_NAME
                USING ERRCODE = 'IL001',
                      DETAIL = pg_catalog.json_build_object(
                          'table', TG_TABLE_NAME, 'operation', 'delete')::text;
        END IF;
        IF TG_OP = 'UPDATE' THEN
            IF (gate ->> 'update_any')::boolean AND old_row IS DISTINCT FROM new_row THEN
                RAISE EXCEPTION 'interlock: UPDATE on % is gated by the cascade check',
                    TG_TABLE_NAME
                    USING ERRCODE = 'IL001',
                          DETAIL = pg_catalog.json_build_object(
                              'table', TG_TABLE_NAME, 'operation', 'update')::text;
            END IF;
            FOR col IN SELECT pg_catalog.jsonb_array_elements_text(gate -> 'update_columns') LOOP
                IF (old_row -> col) IS DISTINCT FROM (new_row -> col) THEN
                    RAISE EXCEPTION 'interlock: UPDATE of %.% is gated by the cascade check',
                        TG_TABLE_NAME, col
                        USING ERRCODE = 'IL001',
                              DETAIL = pg_catalog.json_build_object(
                                  'table', TG_TABLE_NAME, 'operation', 'update',
                                  'column', col)::text;
                END IF;
            END LOOP;
        END IF;
    END IF;

    keep := TG_ARGV[1:TG_NARGS - 1];
    INSERT INTO pg_temp.interlock_capture (tbl, pk, before, after)
    VALUES (
        TG_TABLE_NAME,
        coalesce(new_row, old_row) ->> TG_ARGV[0],
        (SELECT pg_catalog.jsonb_object_agg(e.key, e.value)
           FROM pg_catalog.jsonb_each(old_row) AS e WHERE e.key = ANY (keep)),
        (SELECT pg_catalog.jsonb_object_agg(e.key, e.value)
           FROM pg_catalog.jsonb_each(new_row) AS e WHERE e.key = ANY (keep))
    );
    RETURN NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION interlock.stage_capture(p_limit bigint)
RETURNS TABLE (out_tbl text, out_pk text, out_before text, out_after text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    RETURN QUERY
        SELECT c.tbl, c.pk, c.before::text, c.after::text
          FROM pg_temp.interlock_capture AS c
         ORDER BY c.tbl COLLATE "C", c.pk COLLATE "C", c.seq
         LIMIT p_limit;
END
$fn$;

CREATE OR REPLACE FUNCTION interlock.resolve(p_stage uuid, p_xid xid8)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM interlock.stages s WHERE s.stage_id = p_stage) THEN
        RETURN 'marker';
    END IF;
    IF p_xid IS NULL THEN
        RETURN 'unknown';
    END IF;
    RETURN coalesce(pg_catalog.pg_xact_status(p_xid), 'forgotten');
END
$fn$;
"""

_SCHEMA: Final = """
CREATE SCHEMA IF NOT EXISTS interlock;
REVOKE ALL ON SCHEMA interlock FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.stages (
    stage_id uuid PRIMARY KEY,
    plan_id text NOT NULL,
    xid xid8 NOT NULL UNIQUE,
    gates jsonb NOT NULL DEFAULT '{}'::jsonb,
    stage_role name NOT NULL DEFAULT session_user,
    opened_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON interlock.stages FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.unmediated (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    xid xid8 NOT NULL,
    tbl text NOT NULL,
    pk text,
    op text NOT NULL,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    db_user name NOT NULL DEFAULT session_user,
    application text DEFAULT current_setting('application_name', true)
);
REVOKE ALL ON interlock.unmediated FROM PUBLIC;

CREATE TABLE IF NOT EXISTS interlock.installation (
    tbl text PRIMARY KEY,
    primary_key text NOT NULL,
    columns text[] NOT NULL,
    tenant_column text,
    version text NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON interlock.installation FROM PUBLIC;
"""

_PRIVATE_FUNCTIONS: Final = (
    "interlock.begin_stage(uuid, text, jsonb)",
    "interlock.capture()",
    "interlock.stage_capture(bigint)",
    "interlock.resolve(uuid, xid8)",
)
"""Every function defaults to ``EXECUTE`` for ``PUBLIC``. Revoked from all:
anyone who could call ``begin_stage`` could open a stage, so their writes would
be captured into their own session instead of treated as unmediated."""

_STAGE_FUNCTIONS: Final = (
    "interlock.begin_stage(uuid, text, jsonb)",
    "interlock.stage_capture(bigint)",
    "interlock.resolve(uuid, xid8)",
)


def install(
    conn: psycopg.Connection[Any],
    tables: Sequence[TableSpec],
    *,
    schema: str = "public",
    stage_roles: Iterable[str] = (),
    audit_roles: Iterable[str] = (),
) -> None:
    """Install Interlock's schema, functions and triggers. Idempotent.

    Run once, and again whenever ``tables`` change, as a role that owns the
    observed tables and is not the role stages run as. Everything happens in
    one transaction. A table the installation covered before and ``tables``
    no longer lists has its triggers removed.

    :param conn: A connection as the installing role, not in a transaction.
    :param tables: The tables to observe, in ``schema``.
    :param stage_roles: Roles stages will run as. Each is granted what a stage
        needs from the ``interlock`` schema and nothing else; grant it DML on
        the observed tables yourself.
    :param audit_roles: Roles that run ``interlock reconcile-effects``. Each
        may read ``interlock.stages``, ``interlock.unmediated`` and
        ``interlock.installation``, and write nothing.
    :raises ValueError: On a schema or role name that is not a plain
        identifier.
    """
    from psycopg import sql

    _identifier(schema)
    roles = list(stage_roles)
    auditors = list(audit_roles)
    for role in (*roles, *auditors):
        _identifier(role)
    wanted = {spec.name.lower(): spec for spec in tables}
    with conn.transaction():
        conn.execute(_SCHEMA)
        conn.execute(_FUNCTIONS)
        for signature in _PRIVATE_FUNCTIONS:
            conn.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        previous = [
            str(row[0]) for row in conn.execute("SELECT tbl FROM interlock.installation").fetchall()
        ]
        for stale in previous:
            if stale in wanted:
                continue
            target = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(stale))
            for trigger in (_CAPTURE_TRIGGER, _TRUNCATE_TRIGGER):
                conn.execute(
                    sql.SQL("DROP TRIGGER IF EXISTS {} ON {}").format(
                        sql.Identifier(trigger), target
                    )
                )
            conn.execute("DELETE FROM interlock.installation WHERE tbl = %s", (stale,))
        for spec in tables:
            qualified = f"{schema}.{spec.name}"
            arguments = ", ".join(f"'{a}'" for a in (spec.primary_key, *spec.columns))
            # Identifiers are interpolated unquoted, as SqliteSubstrate does, so
            # PostgreSQL folds them the way it folded the table's own name.
            # Every one was validated by TableSpec or _identifier above.
            conn.execute(
                f"DROP TRIGGER IF EXISTS {_CAPTURE_TRIGGER} ON {qualified};"
                f"CREATE TRIGGER {_CAPTURE_TRIGGER} AFTER INSERT OR UPDATE OR DELETE"
                f" ON {qualified} FOR EACH ROW EXECUTE FUNCTION interlock.capture({arguments});"
                f"ALTER TABLE {qualified} ENABLE ALWAYS TRIGGER {_CAPTURE_TRIGGER};"
                f"DROP TRIGGER IF EXISTS {_TRUNCATE_TRIGGER} ON {qualified};"
                f"CREATE TRIGGER {_TRUNCATE_TRIGGER} AFTER TRUNCATE ON {qualified}"
                f" FOR EACH STATEMENT EXECUTE FUNCTION interlock.capture();"
                f"ALTER TABLE {qualified} ENABLE ALWAYS TRIGGER {_TRUNCATE_TRIGGER}"
            )
            conn.execute(
                "INSERT INTO interlock.installation "
                "(tbl, primary_key, columns, tenant_column, version) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (tbl) DO UPDATE SET "
                "primary_key = EXCLUDED.primary_key, columns = EXCLUDED.columns, "
                "tenant_column = EXCLUDED.tenant_column, version = EXCLUDED.version, "
                "installed_at = now()",
                (
                    spec.name.lower(),
                    spec.primary_key,
                    list(spec.columns),
                    spec.tenant_column,
                    INSTALL_VERSION,
                ),
            )
        for role in roles:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {role}")
            conn.execute(f"GRANT SELECT ON interlock.installation TO {role}")
            for signature in _STAGE_FUNCTIONS:
                conn.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {role}")
        for role in auditors:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {role}")
            conn.execute(
                "GRANT SELECT ON interlock.stages, interlock.unmediated, "
                f"interlock.installation TO {role}"
            )


def _identifier(name: str) -> None:
    # TableSpec's validator, for the names install() takes directly.
    TableSpec(name, columns=[name])


class PostgresSubstrate:
    """Transactional staging over PostgreSQL.

    :param dsn: A libpq connection string for the role stages run as.
    :param tables: Tables to observe, in ``schema``. They must be installed
        with :func:`install` (or ``interlock install``) first.
    :param schema: The schema the observed tables live in.
    :param max_stage_seconds: Bound on stage lifetime, and the server's
        ``statement_timeout`` and ``idle_in_transaction_session_timeout`` for
        the stage, so a stage whose client died cannot hold locks past it.
    :param lock_timeout_seconds: How long any statement in the stage waits for
        a lock before the stage fails with :class:`StageConflictError`.
    :param enforce_table_access: Refuse to open a stage when the role can
        write a table outside ``tables``, or owns one inside it. On
        PostgreSQL the grant is the table boundary, so this checks it rather
        than trusting it. Off, the grant is trusted.
    :param acknowledge_cascades: As for :class:`SqliteSubstrate`.
    :raises ValueError: If an acknowledged table is also observed.
    """

    __slots__ = (
        "_acknowledged",
        "_by_name",
        "_conn",
        "_dsn",
        "_enforce",
        "_folded",
        "_handle",
        "_lock_seconds",
        "_max_rows",
        "_report",
        "_schema",
        "_stage_seconds",
        "_tables",
        "_xid",
    )

    def __init__(
        self,
        dsn: str,
        *,
        tables: Sequence[TableSpec],
        schema: str = "public",
        max_stage_seconds: float = 10.0,
        lock_timeout_seconds: float = 2.0,
        max_diff_rows: int = 50_000,
        enforce_table_access: bool = True,
        acknowledge_cascades: Collection[str] = (),
    ) -> None:
        _identifier(schema)
        self._dsn = dsn
        self._schema = schema
        self._tables = tuple(tables)
        self._by_name = {t.name.lower(): t for t in tables}
        self._folded = frozenset(self._by_name)
        acknowledged = frozenset(a.lower() for a in acknowledge_cascades)
        clash = sorted(acknowledged & self._folded)
        if clash:
            raise ValueError(
                f"acknowledge_cascades names observed table(s) {', '.join(clash)}; a "
                f"cascade into an observed table is measured, so there is no gap to accept"
            )
        self._acknowledged = acknowledged
        self._stage_seconds = max_stage_seconds
        self._lock_seconds = min(lock_timeout_seconds, max_stage_seconds)
        self._max_rows = max_diff_rows
        self._enforce = enforce_table_access
        self._report: CascadeReport | None = None
        self._conn: psycopg.Connection[Any] | None = None
        self._handle: StageHandle | None = None
        self._xid: str | None = None

    @property
    def substrate_id(self) -> str:
        return "postgres"

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
        return frozenset(t.name for t in self._tables)

    @property
    def commit_markers(self) -> bool:
        """Always: the stage's own ``interlock.stages`` row is the marker."""
        return True

    @property
    def cascade_report(self) -> CascadeReport | None:
        """The last cascade check, or ``None`` before the first one."""
        return self._report

    def transaction_id(self, handle: StageHandle) -> str | None:
        """The stage's ``pg_current_xact_id()``, for the commit intent."""
        if self._handle is None or self._handle.stage_id != handle.stage_id:
            return None
        return self._xid

    # -- setup ----------------------------------------------------------------

    def check_cascades(self) -> CascadeReport:
        """Check the installation, the role's grants and the foreign-key reach.

        The setup-time form of what every stage checks when it opens. Runs in
        a read-only transaction and changes nothing.

        :raises SubstrateConfigurationError: If Interlock is not installed for
            these tables, or the role can write outside them.
        :raises SubstrateUnavailableError: If the database cannot be reached.
        """
        import psycopg

        conn = self._connect()
        try:
            conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            self._verify_installation(conn)
            if self._enforce:
                self._verify_grants(conn)
            return self._cascades(conn)
        except psycopg.Error as exc:
            raise self._setup_error(exc) from exc
        finally:
            conn.close()

    # -- lifecycle ------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Refuse anything but a row statement, read from the statement.

        :param effect: The effect to vet.
        :returns: A refusal reason, or ``None`` when it may be staged.
        """
        verb = leading_verb(effect.statement)
        if verb in STAGEABLE_VERBS:
            return None
        shown = verb.upper() or "a statement with no leading keyword"
        return (
            f"{shown} is not stageable on PostgreSQL: a stage runs row statements "
            f"({', '.join(sorted(v.upper() for v in STAGEABLE_VERBS))}) only. Anything "
            f"else can change the schema, the session, or the transaction the "
            f"measurement depends on"
        )

    def open(self, plan: EffectPlan) -> StageHandle:
        """Begin a ``REPEATABLE READ`` stage on a dedicated connection.

        The observed tables are locked ``ROW EXCLUSIVE`` before the snapshot is
        taken. That lock does not block other writers, but it does block a
        trigger being disabled and a foreign key being added, so the checks
        that follow hold for the stage's whole life.
        """
        import psycopg

        if self._handle is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage {self._handle.stage_id} open"
            )
        conn = self._connect()
        stage_id = uuid.uuid4()
        try:
            conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            conn.execute(self._timeouts())
            targets = ", ".join(f"{self._schema}.{t.name}" for t in self._tables)
            if targets:
                conn.execute(f"LOCK TABLE {targets} IN ROW EXCLUSIVE MODE")
            self._verify_installation(conn)
            if self._enforce:
                self._verify_grants(conn)
            report = self._cascades(conn)
            row = conn.execute(
                "SELECT interlock.begin_stage(%s, %s, %s::jsonb)::text",
                (stage_id, plan.plan_id, json.dumps(_gates(report))),
            ).fetchone()
        except psycopg.Error as exc:
            conn.close()
            if exc.sqlstate in _CONFLICTS:
                raise StageConflictError(f"could not lock the observed tables: {exc}") from exc
            raise self._setup_error(exc) from exc
        except BaseException:
            conn.close()
            raise
        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=stage_id,
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        self._conn = conn
        self._handle = handle
        self._xid = str(row[0]) if row is not None else None
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Execute one effect inside the open stage. Never commits.

        :raises ForbiddenStatementError: On a statement this substrate refuses,
            or one the database refused on the stage's behalf: a cascade gate,
            a missing grant, or tampering with the stage marker.
        :raises StageConflictError: If another writer holds what it needs.
        """
        import psycopg

        conn = self._require(handle)
        self._assert_live(handle)
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(
                f"effect {effect.effect_id!r} refused: {refusal}", reason=_verb_reason(effect)
            )
        try:
            # Re-asserted every time: a SELECT can call set_config() and lift
            # them, and a stage bound that the agent can lift is not a bound.
            conn.execute(self._timeouts())
            # prepare=True sends the statement with the extended protocol,
            # which the server refuses to split: "UPDATE ...; COMMIT" fails
            # instead of committing the stage before adjudication.
            cursor = conn.execute(effect.statement, dict(effect.parameters), prepare=True)
        except psycopg.Error as exc:
            raise self._statement_error(effect, exc) from exc
        return EffectOutcome(
            effect_id=effect.effect_id,
            rows_affected=max(cursor.rowcount, 0),
            applied_at=datetime.now(UTC),
        )

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Read the measured delta out of the stage's capture table.

        Numbers are read exactly: ``NUMERIC`` becomes ``Decimal``, never a
        float, because this is the input to financial predicates.
        """
        import psycopg

        conn = self._require(handle)
        try:
            rows = conn.execute(
                "SELECT out_tbl, out_pk, out_before, out_after FROM interlock.stage_capture(%s)",
                (self._max_rows + 1,),
            ).fetchall()
        except psycopg.Error as exc:
            raise StageError(f"could not read the stage's capture: {exc}") from exc
        truncated = len(rows) > self._max_rows
        deltas: list[RowDelta] = []
        for table, key, raw_before, raw_after in rows[: self._max_rows]:
            spec = self._by_name.get(str(table).lower())
            before = _load(raw_before)
            after = _load(raw_after)
            tenant: str | None = None
            if spec is not None and spec.tenant_column is not None:
                source = after if after is not None else before
                if source is not None:
                    raw = source.get(spec.tenant_column)
                    tenant = None if raw is None else str(raw)
            deltas.append(
                RowDelta(
                    table=str(table),
                    primary_key=str(key),
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
        """Make the staged work durable, with its ``interlock.stages`` row.

        :raises StageError: If the transaction had already failed. PostgreSQL
            answers ``COMMIT`` on a failed transaction with a rollback, not an
            error, so the answer is checked.
        """
        import psycopg
        from psycopg.pq import TransactionStatus

        conn = self._require(handle)
        self._assert_live(handle)
        committed_at = datetime.now(UTC)
        if conn.info.transaction_status != TransactionStatus.INTRANS:
            raise StageError(
                f"stage {handle.stage_id} cannot commit: its transaction is "
                f"{conn.info.transaction_status.name}"
            )
        try:
            cursor = conn.execute("COMMIT")
        except psycopg.Error as exc:
            raise StageError(f"commit failed: {exc}") from exc
        if cursor.statusmessage != "COMMIT":
            raise StageError(f"commit was answered with {cursor.statusmessage!r}")
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=committed_at,
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=self._xid,
        )

    def resolve_intent(self, stage_id: uuid.UUID, *, txid: str | None = None) -> bool | None:
        """Whether a stage's transaction committed.

        Its ``interlock.stages`` row commits with it, so a present row means
        committed. An absent one means rolled back only once the transaction
        is no longer running: a client that crashed can leave its session, and
        its open transaction, on the server until
        ``idle_in_transaction_session_timeout`` ends it. ``pg_xact_status`` on
        the recorded ``txid`` says which.

        :param txid: The stage's ``pg_current_xact_id()``, from its intent.
        :returns: ``True``, ``False``, or ``None`` when that cannot yet be
            said: no ``txid``, the transaction still running, or a
            transaction the server says committed with no row, which means the
            row was deleted.
        :raises SubstrateUnavailableError: If the database cannot be read.
        """
        import psycopg

        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT interlock.resolve(%s, %s::xid8)", (stage_id, txid)
            ).fetchone()
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"cannot resolve stage {stage_id}: {exc}") from exc
        finally:
            conn.close()
        # "marker": the stage's row is there. Otherwise pg_xact_status's answer
        # for the transaction, or "forgotten" when it is too old to have one,
        # or "unknown" when no txid was recorded.
        status = str(row[0]) if row is not None else "unknown"
        if status == "marker":
            return True
        if status in ("aborted", "forgotten"):
            return False
        if status == "in progress" and txid is not None:
            logger.warning(
                "stage %s: transaction %s is still running on the server; its outcome "
                "is not settled yet",
                stage_id,
                txid,
            )
        elif txid is not None:
            logger.warning(
                "stage %s: transaction %s is %s but its interlock.stages row is gone",
                stage_id,
                txid,
                status,
            )
        return None

    def abort(self, handle: StageHandle) -> None:
        """Roll back. Safe in any state, including after a commit."""
        import psycopg

        conn = self._conn
        if conn is None or self._handle is None or self._handle.stage_id != handle.stage_id:
            return
        try:
            conn.execute("ROLLBACK")
        except psycopg.Error:
            # Already resolved, or the connection is gone and the server
            # rolled back for us. abort() runs on error paths.
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
        self._xid = None

    # -- internals ------------------------------------------------------------

    def _connect(self) -> psycopg.Connection[Any]:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - the extra is installed in tests
            raise SubstrateUnavailableError(
                "PostgresSubstrate needs psycopg: pip install 'interlock[postgres]'"
            ) from exc
        try:
            return psycopg.connect(
                self._dsn,
                autocommit=True,
                application_name="interlock",
                connect_timeout=max(1, int(self._stage_seconds)),
            )
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc

    def _timeouts(self) -> str:
        # Integers only, so the interpolation cannot carry anything else.
        stage = max(1, int(self._stage_seconds * 1000))
        lock = max(1, int(self._lock_seconds * 1000))
        return (
            f"SET LOCAL statement_timeout = {stage}; "
            f"SET LOCAL lock_timeout = {lock}; "
            f"SET LOCAL idle_in_transaction_session_timeout = {stage}"
        )

    def _require(self, handle: StageHandle) -> psycopg.Connection[Any]:
        if self._conn is None or self._handle is None or self._handle.stage_id != handle.stage_id:
            raise StageError(f"stage {handle.stage_id} is not open on this substrate")
        return self._conn

    def _assert_live(self, handle: StageHandle) -> None:
        if datetime.now(UTC) > handle.expires_at:
            raise StageExpiredError(
                f"stage {handle.stage_id} exceeded its {self._stage_seconds}s bound "
                f"while holding locks"
            )

    def _cascades(self, conn: psycopg.Connection[Any]) -> CascadeReport:
        report = analyze_cascades(
            read_postgres_foreign_keys(conn, self._schema), self._folded, self._acknowledged
        )
        previous, self._report = self._report, report
        log_report(logger, previous, report)
        return report

    def _verify_installation(self, conn: psycopg.Connection[Any]) -> None:
        """Every observed table has an enabled-always capture trigger that
        captures exactly its ``TableSpec``. Read from ``pg_trigger``, which is
        what fires, not from Interlock's own bookkeeping."""
        rows = conn.execute(
            """
            SELECT c.relname::text, t.tgname::text, t.tgenabled::text, t.tgtype::int,
                   t.tgargs, pn.nspname::text || '.' || p.proname::text
              FROM pg_catalog.pg_trigger t
              JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
              JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
             WHERE n.nspname = %s AND c.relname = ANY (%s)
               AND t.tgname = ANY (%s)
            """,
            (self._schema, sorted(self._folded), [_CAPTURE_TRIGGER, _TRUNCATE_TRIGGER]),
        ).fetchall()
        found = {(str(r[0]), str(r[1])): r for r in rows}
        problems: list[str] = []
        # A statement on a parent writes its inheritance children's and its
        # partitions' rows too. They carry no capture trigger, and PostgreSQL
        # checks privileges on the parent alone, so neither the measurement
        # nor the grant boundary would reach them.
        inherited = conn.execute(
            """
            SELECT DISTINCT parent.relname::text
              FROM pg_catalog.pg_inherits i
              JOIN pg_catalog.pg_class parent ON parent.oid = i.inhparent
              JOIN pg_catalog.pg_namespace n ON n.oid = parent.relnamespace
             WHERE n.nspname = %s AND parent.relname = ANY (%s)
             ORDER BY 1
            """,
            (self._schema, sorted(self._folded)),
        ).fetchall()
        for (table,) in inherited:
            problems.append(
                f"{table}: has inheritance children or partitions, whose rows a statement "
                f"on it writes unmeasured; not supported"
            )
        for key, spec in sorted(self._by_name.items()):
            capture = found.get((key, _CAPTURE_TRIGGER))
            truncate = found.get((key, _TRUNCATE_TRIGGER))
            expected = [spec.primary_key, *spec.columns]
            if capture is None:
                problems.append(f"{key}: no {_CAPTURE_TRIGGER} trigger")
            elif capture[2] != "A":
                problems.append(f"{key}: {_CAPTURE_TRIGGER} is not ENABLE ALWAYS ({capture[2]})")
            elif capture[3] != _ROW_TRIGGER_TYPE or capture[5] != "interlock.capture":
                problems.append(f"{key}: {_CAPTURE_TRIGGER} is not Interlock's row trigger")
            elif _trigger_arguments(capture[4]) != expected:
                problems.append(
                    f"{key}: capture trigger records {_trigger_arguments(capture[4])}, "
                    f"the TableSpec says {expected}"
                )
            if truncate is None or truncate[2] != "A" or truncate[3] != _TRUNCATE_TRIGGER_TYPE:
                problems.append(f"{key}: {_TRUNCATE_TRIGGER} is missing or not ENABLE ALWAYS")
        if problems:
            raise SubstrateConfigurationError(
                "Interlock's triggers do not match this substrate's tables, so a stage "
                "would not measure what it claims to: "
                + "; ".join(problems)
                + ". Run `interlock install` for these tables"
            )

    def _verify_grants(self, conn: psycopg.Connection[Any]) -> None:
        """The role, and every role it can act as, writes only observed tables."""
        members = """
            WITH RECURSIVE member_of(oid) AS (
                SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = session_user
              UNION
                SELECT m.roleid FROM pg_catalog.pg_auth_members m
                  JOIN member_of o ON m.member = o.oid
            )
        """
        row = conn.execute(
            members
            + """
            SELECT coalesce(bool_or(r.rolsuper), false),
                   array_agg(r.rolname::text ORDER BY r.rolname)
              FROM member_of JOIN pg_catalog.pg_roles r ON r.oid = member_of.oid
            """
        ).fetchone()
        roles = ", ".join(row[1]) if row is not None and row[1] else "?"
        if row is not None and row[0]:
            raise SubstrateConfigurationError(
                f"the stage's role ({roles}) is or can become a superuser, which bypasses "
                f"every grant the table boundary rests on. Stage as a role granted DML on "
                f"the observed tables only"
            )
        owned = conn.execute(
            members
            + """
            SELECT c.relname::text FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = %s AND c.relname = ANY (%s)
               AND c.relowner IN (SELECT oid FROM member_of)
             ORDER BY 1
            """,
            (self._schema, sorted(self._folded)),
        ).fetchall()
        if owned:
            raise SubstrateConfigurationError(
                f"the stage's role ({roles}) owns observed table(s) "
                f"{', '.join(str(r[0]) for r in owned)}; an owner can disable the capture "
                f"trigger. Stage as a role granted DML on them, not their owner"
            )
        writable = conn.execute(
            members
            + """
            SELECT DISTINCT n.nspname::text, c.relname::text
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              CROSS JOIN member_of m
             WHERE c.relkind IN ('r', 'p', 'v', 'f')
               AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'interlock')
               AND n.nspname !~ '^pg_(temp|toast)'
               AND NOT (n.nspname = %s AND c.relname = ANY (%s))
               AND (pg_catalog.has_table_privilege(
                        m.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
                    OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'INSERT, UPDATE'))
             ORDER BY 1, 2
             LIMIT 20
            """,
            (self._schema, sorted(self._folded)),
        ).fetchall()
        if writable:
            names = ", ".join(
                name if schema == self._schema else f"{schema}.{name}"
                for schema, name in ((str(r[0]), str(r[1])) for r in writable)
            )
            raise SubstrateConfigurationError(
                f"the stage's role ({roles}) can write table(s) outside the observed set: "
                f"{names}. On PostgreSQL the grant is the table boundary; a write there "
                f"would execute and measure as nothing. Revoke it, observe the table, or "
                f"pass enforce_table_access=False to trust the grants unchecked"
            )

    def _setup_error(self, exc: Exception) -> InterlockError:
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate in _NOT_INSTALLED:
            return SubstrateConfigurationError(
                f"Interlock is not installed in this database, or not for this role: {exc}. "
                f"Run `interlock install`"
            )
        if sqlstate == _PRIVILEGE:
            return SubstrateConfigurationError(
                f"the stage's role lacks a privilege a stage needs: {exc}. Grant it DML on "
                f"the observed tables, and pass it to `interlock install --stage-role`"
            )
        return SubstrateUnavailableError(f"cannot open a stage: {exc}")

    def _statement_error(self, effect: Effect, exc: Exception) -> InterlockError:
        sqlstate = getattr(exc, "sqlstate", None)
        diag = getattr(exc, "diag", None)
        who = f"effect {effect.effect_id!r}"
        if sqlstate == _GATED:
            detail = _json_detail(getattr(diag, "message_detail", None))
            table = str(detail.get("table", ""))
            operation = str(detail.get("operation", ""))
            column = detail.get("column")
            if operation in ("delete", "update") and self._report is not None:
                reason = self._report.refusal(
                    table,
                    "delete" if operation == "delete" else "update",
                    None if column is None else str(column),
                )
            else:
                reason = f"{operation.upper()} on {table!r} is not stageable"
            return ForbiddenStatementError(
                f"{who} refused: {reason}. PostgreSQL rolled the statement back, cascade included",
                reason="cascade" if operation in ("delete", "update") else "statement_kind",
                table=table or None,
            )
        if sqlstate == _TAMPERED:
            return ForbiddenStatementError(
                f"{who} refused: {exc}. The stage marker is set by the substrate alone",
                reason="protected",
            )
        if sqlstate == _PRIVILEGE:
            return ForbiddenStatementError(
                f"{who} refused by the database: {exc}. The stage role's grants are the "
                f"table boundary on PostgreSQL",
                reason="privilege",
            )
        if sqlstate in _CONFLICTS:
            return StageConflictError(f"{who} lost to a concurrent writer: {exc}")
        if sqlstate == _CANCELLED:
            return StageExpiredError(f"{who} ran past the stage's {self._stage_seconds}s bound")
        if "multiple commands" in str(exc):
            return ForbiddenStatementError(
                f"{who} refused: one effect is one statement, and this carries several",
                reason="multiple_statements",
            )
        return StageError(f"{who} failed: {exc}")


def _gates(report: CascadeReport) -> dict[str, dict[str, object]]:
    """The gates, keyed and listed as PostgreSQL spells them.

    Not :meth:`CascadeReport.gates`, which lowercases for SQLite: the trigger
    compares against ``TG_TABLE_NAME`` and ``to_jsonb(OLD)`` keys exactly, and
    a folded name that matched nothing would let the update through.
    """
    gates: dict[str, dict[str, object]] = {}
    for reach in report.gated:
        entry = gates.setdefault(
            reach.parent, {"delete": False, "update_columns": [], "update_any": False}
        )
        if reach.operation == "delete":
            entry["delete"] = True
        elif reach.columns:
            listed = entry["update_columns"]
            assert isinstance(listed, list)
            entry["update_columns"] = sorted({*listed, *reach.columns})
        else:
            entry["update_any"] = True
    return gates


def _trigger_arguments(raw: object) -> list[str]:
    """Decode ``pg_trigger.tgargs``: NUL-terminated strings, as bytes."""
    data = bytes(raw) if isinstance(raw, bytes | bytearray | memoryview) else b""
    return [part.decode() for part in data.split(b"\x00")[:-1]]


def _json_detail(raw: object) -> Mapping[str, object]:
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _load(raw: object) -> Mapping[str, Any] | None:
    if raw is None:
        return None
    parsed: Any = json.loads(str(raw), parse_float=Decimal)
    return parsed if isinstance(parsed, dict) else None
