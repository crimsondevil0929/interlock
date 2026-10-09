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

import contextlib
import hashlib
import json
import logging
import math
import os
import secrets
import socket
import threading
import time
import uuid
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final

from agentgov.receipts.canonical import canonical_bytes, loads_strict

from interlock.cascade import (
    CascadeReport,
    analyze_cascades,
    log_report,
    read_postgres_foreign_keys,
)
from interlock.deliveries import LegacySet, PostgresReader
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    InboundFactError,
    InterlockError,
    OutboundRequestError,
    PoolExhaustedError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.inbox_sql import INBOX_FUNCTIONS, INBOX_TABLES, INBOX_TRIGGERS
from interlock.inbox_store import fact_row
from interlock.outbound import EnqueueOrder, SinkSpec
from interlock.outbox_sql import (
    OUTBOX_FUNCTIONS,
    OUTBOX_GUARD,
    OUTBOX_TABLES,
    OUTBOX_TRIGGER_NAMES,
    OUTBOX_TRIGGERS,
)
from interlock.substrate import TableSpec, _verb_reason, leading_verb
from interlock.telemetry import Metrics, NullMetrics
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectId,
    EffectKind,
    EffectOutcome,
    EffectPlan,
    InboundFact,
    OutboundDelta,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
    WindowMeasure,
    _frozen,
    outbound_key,
)
from interlock.windows import WindowCharge, window_lock

if TYPE_CHECKING:
    import psycopg

    from interlock.inbox import InboundSource

__all__ = [
    "INSTALL_VERSION",
    "STAGEABLE_VERBS",
    "PostgresSubstrate",
    "install",
]

logger = logging.getLogger("interlock.postgres")

INSTALL_VERSION: Final = "7"
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

_GRACE: Final = 0.25
"""Seconds a bounded statement has, once cancelled, before its socket is shut.
A server answers a cancel at once; PgBouncer takes the cancel of a client it is
holding in its queue and leaves the client waiting, so only the shut ends it."""

_EXHAUSTED: Final = (
    "too many connections",
    "too many clients",
    "remaining connection slots",
    "no more connections allowed",
    "query_wait_timeout",
    "timeout expired",
)
"""How a refusal for want of connections reads: PostgreSQL's (``53300``),
and a pooler's, whose errors carry no SQLSTATE of their own."""


def _exhausted(exc: BaseException) -> bool:
    """Whether ``exc`` refused a connection, or a statement, for want of one."""
    if getattr(exc, "sqlstate", None) in ("53300", "53400"):
        return True
    text = str(exc).lower()
    return any(phrase in text for phrase in _EXHAUSTED)


class _Watch:
    """Bounds the statements run on a connection inside it (``docs/EPIC7_DESIGN.md``
    §3.2): when ``seconds`` run out, the one running is cancelled; if it is
    still blocked :data:`_GRACE` later, the socket is shut down, so the wait
    ends whatever answers the cancel. ``None`` bounds nothing."""

    def __init__(self, conn: psycopg.Connection[Any], seconds: float | None) -> None:
        self._conn = conn
        self._lock = threading.Lock()
        self._over = False
        self.fired = False
        """Whether the time ran out: then a cancel may be in flight, and
        nothing more should run on the connection."""
        self._timer = None if seconds is None else threading.Timer(seconds, self._cancel)

    def __enter__(self) -> _Watch:
        if self._timer is not None:
            self._timer.daemon = True
            self._timer.start()
        return self

    def __exit__(self, *exc: object) -> None:
        with self._lock:
            self._over = True
        if self._timer is not None:
            self._timer.cancel()

    def _cancel(self) -> None:
        with self._lock:
            if self._over:
                return
            self.fired = True
        with contextlib.suppress(Exception):
            self._conn.cancel_safe(timeout=_GRACE)
        shut = threading.Timer(_GRACE, self._shut)
        shut.daemon = True
        shut.start()

    def _shut(self) -> None:
        with self._lock:
            if self._over:
                return
            try:
                fd = os.dup(self._conn.pgconn.socket)
            except Exception:  # closed meanwhile: nothing left to end
                return
            with contextlib.suppress(OSError), socket.socket(fileno=fd) as sock:
                sock.shutdown(socket.SHUT_RDWR)


"""Serialization failure, deadlock, lock not available: another writer won."""
_OUTBOUND: Final = "IL004"
"""The outbox refused a request: an unregistered or disabled sink, an operation
it does not install, a payload over its bound or not matching its hash."""
_WINDOWS: Final = "IL009"
"""``interlock.window_totals`` or ``interlock.inbox_pending`` was called inside
a stage: the rate windows' history and the inbox are never a stage's to read."""
_PRUNED: Final = "IL011"
"""A rate window reaches back past the history a checkpoint pruned
(``docs/EPIC5_DESIGN.md`` §1.8): it cannot be measured honestly."""
_INBOUND: Final = "IL012"
"""The inbox refused: no such fact for the plan's scope, an event that does
not extend its log, a binding to nothing delivered (``docs/EPIC5_DESIGN.md``
§2)."""
_UNIQUE: Final = "23505"
_CANCELLED: Final = "57014"
_PRIVILEGE: Final = "42501"
_NOT_INSTALLED: Final = frozenset({"42883", "42P01", "3F000"})
"""Undefined function, undefined table, undefined schema."""


_FUNCTIONS: Final = r"""
-- Version 1 took three arguments. A function is identified by its argument
-- types, so the old one would survive CREATE OR REPLACE as an overload.
DROP FUNCTION IF EXISTS interlock.begin_stage(uuid, text, jsonb);

CREATE OR REPLACE FUNCTION interlock.begin_stage(
    p_stage uuid, p_plan text, p_gates jsonb, p_enqueue_hash bytea DEFAULT NULL
)
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
    -- p_enqueue_hash is the sha256 of a token only the substrate holds; it
    -- authorizes this stage's writes to the outbox (interlock.enqueue).
    INSERT INTO interlock.stages (stage_id, plan_id, xid, gates, enqueue_hash)
    VALUES (p_stage, p_plan, x, p_gates, p_enqueue_hash);
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

-- Rate windows (docs/EPIC4_DESIGN.md §3). A stage locks each window key it
-- adds to, in one order, until it ends; reads what the keys hold from outside
-- itself; and writes what it adds with its token, beside its stages row.
CREATE OR REPLACE FUNCTION interlock.window_lock(p_locks bigint[])
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    lock_id bigint;
BEGIN
    FOR lock_id IN SELECT DISTINCT l FROM pg_catalog.unnest(p_locks) AS l ORDER BY 1 LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(lock_id);
    END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION interlock.window_totals(
    p_windows text[], p_keys text[], p_spans_us bigint[]
)
RETURNS TABLE (out_window text, out_key text, out_total numeric)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    now_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
    -- Outside every stage, in READ COMMITTED: a stage's snapshot would miss
    -- what committed after it began, and an agent's statement, which runs
    -- only inside a stage, may not read what other plans added.
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed'
       OR coalesce(pg_catalog.current_setting('interlock.stage_id', true), '') <> ''
       OR EXISTS (SELECT 1 FROM interlock.stages s
                   WHERE s.xid = pg_catalog.pg_current_xact_id_if_assigned()) THEN
        RAISE EXCEPTION 'interlock: the rate windows'' history is read outside every stage'
            USING ERRCODE = 'IL009';
    END IF;
    -- A window reaching back before the latest checkpoint's window horizon
    -- would be read short: what it held there was pruned. Fail closed.
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.unnest(p_spans_us) AS w(span)
         WHERE now_at - w.span * interval '1 microsecond' < (
                   SELECT max(c.windows_horizon) FROM interlock.checkpoints AS c)) THEN
        RAISE EXCEPTION 'interlock: a rate window reaches back past the history a checkpoint '
            'pruned' USING ERRCODE = 'IL011';
    END IF;
    RETURN QUERY
        SELECT w.name, w.key,
               coalesce((SELECT sum(l.amount) FROM interlock.window_ledger l
                          WHERE l.window_name = w.name AND l.key = w.key
                            AND l.at > now_at - w.span * interval '1 microsecond'), 0)
          FROM ROWS FROM (pg_catalog.unnest(p_windows), pg_catalog.unnest(p_keys),
                          pg_catalog.unnest(p_spans_us)) AS w(name, key, span);
END
$fn$;

CREATE OR REPLACE FUNCTION interlock.window_add(
    p_token bytea, p_windows text[], p_keys text[], p_amounts numeric[]
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    stage uuid;
    expected bytea;
BEGIN
    SELECT s.stage_id, s.enqueue_hash INTO stage, expected
      FROM interlock.stages s
     WHERE s.xid = pg_catalog.pg_current_xact_id();
    IF stage IS NULL OR expected IS NULL
       OR pg_catalog.sha256(p_token) IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'interlock: this transaction''s stage did not add to a rate window'
            USING ERRCODE = 'IL002';
    END IF;
    INSERT INTO interlock.window_ledger (stage_id, window_name, key, amount)
    SELECT stage, w.name, w.key, w.amount
      FROM ROWS FROM (pg_catalog.unnest(p_windows), pg_catalog.unnest(p_keys),
                      pg_catalog.unnest(p_amounts)) AS w(name, key, amount);
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

-- Version 2: the transactional outbox (docs/OUTBOX_DESIGN.md); its own
-- objects are in interlock.outbox_sql.
ALTER TABLE interlock.stages ADD COLUMN IF NOT EXISTS enqueue_hash bytea;

-- Version 4: what each committed plan added to each rate window
-- (docs/EPIC4_DESIGN.md §3), written in its stage, so a row exists exactly
-- when its stages row does. No role writes it but through
-- interlock.window_add, and none but an auditor reads it.
CREATE TABLE IF NOT EXISTS interlock.window_ledger (
    stage_id uuid NOT NULL REFERENCES interlock.stages (stage_id),
    window_name text NOT NULL,
    key text NOT NULL,
    amount numeric NOT NULL CHECK (amount > 0),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (stage_id, window_name, key)
);
CREATE INDEX IF NOT EXISTS window_ledger_by_key
    ON interlock.window_ledger (window_name, key, at);
REVOKE ALL ON interlock.window_ledger FROM PUBLIC;
"""

_PRUNED_WINDOW: Final = (
    "a rate window reaches back past the history a checkpoint pruned: the vacuum was run "
    "with windows shorter than this engine's. It cannot be measured until it no longer does"
)

_ENQUEUE_CALL: Final = (
    "interlock.enqueue(%s, %s, %s, %s, %s::text[], %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_ENQUEUE: Final = (
    "interlock.enqueue(bytea, uuid, text, integer, text[], text, text, text, text, text, "
    "text, text, integer, text)"
)

_STAGE_FUNCTIONS: Final = (
    "interlock.begin_stage(uuid, text, jsonb, bytea)",
    "interlock.stage_capture(bigint)",
    "interlock.resolve(uuid, xid8)",
    _ENQUEUE,
    "interlock.stage_outbox(bigint)",
    "interlock.window_lock(bigint[])",
    "interlock.window_totals(text[], text[], bigint[])",
    "interlock.window_add(bytea, text[], text[], numeric[])",
    "interlock.inbox_pending(text)",
    "interlock.inbox_consume(bytea, uuid[], text)",
    "interlock.stage_facts(bigint)",
    "interlock.outbox_trace(bytea, text)",
    "interlock.inbox_pending_traces(text)",
)

_OUTBOX_TABLES: Final = (
    "interlock.sinks",
    "interlock.outbox",
    "interlock.outbox_state",
    "interlock.outbox_attempts",
    "interlock.outbox_epochs",
    "interlock.outbox_legacy",
    "interlock.outbox_settlements",
    "interlock.checkpoints",
    "interlock.outbox_compacted",
    "interlock.outbox_traces",
    "interlock.key_revocations",
    "interlock.key_seals",
)

_SETTLER_FUNCTIONS: Final = ("interlock.outbox_settle(uuid, text, text, text)",)

_INBOX_TABLES: Final = (
    "interlock.inbox_sources",
    "interlock.inbox_events",
    "interlock.inbox_facts",
    "interlock.inbox_consumed",
    "interlock.inbox_traces",
)

_INBOX_FUNCTIONS: Final = (
    "interlock.inbox_record(text, text, text, timestamptz, timestamptz, text, text, text, "
    "integer, text, text, text, text)",
    "interlock.inbox_match(uuid, text, integer, text, uuid, integer, text, text, text, text, "
    "text, text)",
    "interlock.inbox_trace(text, integer, text)",
)
"""What an inbox process may call: every event and fact it records goes
through one of these, and the trace context an event came with."""

_RELAY_FUNCTIONS: Final = (
    "interlock.relay_claim(text, double precision, integer, text[])",
    "interlock.relay_sending(uuid, text, bigint, text)",
    "interlock.relay_outcome(uuid, text, bigint, integer, text, integer, text, text, bigint, text, "
    "text)",
    "interlock.relay_hold(uuid, text, bigint, text)",
    "interlock.relay_defer(uuid, text, bigint, text, bigint)",
    "interlock.relay_refuse(uuid, text, bigint, text)",
)
"""What a relay may call: every change it makes goes through one of these."""


def install(
    conn: psycopg.Connection[Any],
    tables: Sequence[TableSpec],
    *,
    schema: str = "public",
    stage_roles: Iterable[str] = (),
    audit_roles: Iterable[str] = (),
    sinks: Iterable[SinkSpec] = (),
    relay_roles: Iterable[str] = (),
    settler_roles: Iterable[str] = (),
    sources: Iterable[InboundSource] = (),
    inbox_roles: Iterable[str] = (),
) -> LegacySet:
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
        may read ``interlock.stages``, ``interlock.unmediated``,
        ``interlock.installation`` and the outbox tables, and write nothing.
    :param sinks: The sinks outbound requests may name, mirrored into
        ``interlock.sinks`` without endpoints or credentials. A sink installed
        before and no longer listed is disabled, not deleted: requests already
        in the outbox name it.
    :param relay_roles: Roles the outbox relay runs as. Each may read the
        outbox tables, and change delivery state only through the relay
        functions, which check its lease and append to the delivery log. It
        may not change a request, or write anything else.
    :param settler_roles: Roles settlement runs as
        (:class:`~interlock.settlement.Settler`). Each may read the outbox
        tables and record a delivered request's settlement, through
        ``interlock.outbox_settle``, and nothing else.
    :param sources: The inbound sources webhooks arrive from
        (``docs/EPIC5_DESIGN.md`` §2), mirrored into ``interlock.inbox_sources``
        without their secrets. One installed before and no longer listed is
        disabled, not deleted: its log stays.
    :param inbox_roles: Roles the inbox process runs as. Each may read the
        outbox and the inbox, and record events and facts through
        ``interlock.inbox_record`` and ``interlock.inbox_match``, and nothing
        else.
    :raises ValueError: On a schema or role name that is not a plain
        identifier.

    Version 2 adds the transactional outbox (``docs/OUTBOX_DESIGN.md``).
    Installing it over version 1 upgrades in place, in the same transaction:
    ``interlock.stages`` gains ``enqueue_hash``, and ``begin_stage`` its fourth
    argument.

    Version 3 (``docs/EPIC3_DESIGN.md`` §3) adds sink kinds, the id of what a
    delivered call created, operator authority and compensations. Installing
    it over version 2 upgrades in place, in the same transaction, and every
    delivery log written under version 2 still verifies. Stop the relays
    first: a relay of version 2 cannot record an outcome in version 3.

    Version 4 (``docs/EPIC4_DESIGN.md`` §2) records each relay's attestation
    with every outcome, and refuses an outcome without one. It upgrades
    version 3 in place the same way; again, stop the relays first. The install
    that brings it records the legacy set
    (:class:`~interlock.deliveries.LegacySet`), which no later one adds to.

    :returns: The legacy set, as this install's transaction read it: what a
        signed install vouches for.
    """
    from psycopg import sql

    _identifier(schema)
    roles = list(stage_roles)
    auditors = list(audit_roles)
    relays = list(relay_roles)
    settlers = list(settler_roles)
    inboxes = list(inbox_roles)
    for role in (*roles, *auditors, *relays, *settlers, *inboxes):
        _identifier(role)
    wanted = {spec.name.lower(): spec for spec in tables}
    registry = list(sinks)
    with conn.transaction():
        conn.execute(OUTBOX_GUARD)
        conn.execute(_SCHEMA)
        conn.execute(OUTBOX_TABLES)
        conn.execute(INBOX_TABLES)
        conn.execute(_FUNCTIONS)
        conn.execute(OUTBOX_FUNCTIONS)
        conn.execute(INBOX_FUNCTIONS)
        conn.execute(OUTBOX_TRIGGERS)
        conn.execute(INBOX_TRIGGERS)
        # Every function defaults to EXECUTE for PUBLIC. Revoked from all:
        # anyone who could call begin_stage could open a stage, so their
        # writes would be captured into their own session instead of treated
        # as unmediated; anyone who could call a relay function could mark a
        # request delivered. Roles get back exactly what their part needs.
        conn.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA interlock FROM PUBLIC")
        _install_sinks(conn, registry)
        _install_sources(conn, list(sources))
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
                f"interlock.installation, interlock.window_ledger, "
                f"{', '.join((*_OUTBOX_TABLES, *_INBOX_TABLES))} TO {role}"
            )
        for role in relays:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {role}")
            # Reads only: every change goes through a relay function, which
            # checks the lease and appends to the delivery log.
            conn.execute(f"REVOKE ALL ON {', '.join(_OUTBOX_TABLES)} FROM {role}")
            conn.execute(f"GRANT SELECT ON {', '.join(_OUTBOX_TABLES)} TO {role}")
            for signature in _RELAY_FUNCTIONS:
                conn.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {role}")
        for role in settlers:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {role}")
            # Reads only, but for its one function.
            conn.execute(f"REVOKE ALL ON {', '.join(_OUTBOX_TABLES)} FROM {role}")
            conn.execute(f"GRANT SELECT ON {', '.join(_OUTBOX_TABLES)} TO {role}")
            for signature in _SETTLER_FUNCTIONS:
                conn.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {role}")
        for role in inboxes:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {role}")
            # Reads the outbox to match, the inbox to verify; writes only
            # through its two functions, which link and check.
            readable = ", ".join((*_OUTBOX_TABLES, *_INBOX_TABLES))
            conn.execute(f"REVOKE ALL ON {readable} FROM {role}")
            conn.execute(f"GRANT SELECT ON {readable} TO {role}")
            for signature in _INBOX_FUNCTIONS:
                conn.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {role}")
        legacy = PostgresReader(conn).legacy()
    return legacy or LegacySet({})


def _install_sinks(conn: psycopg.Connection[Any], sinks: Sequence[SinkSpec]) -> None:
    """Mirror the registry into ``interlock.sinks``: what ``enqueue`` checks."""
    for sink in sinks:
        conn.execute(
            "INSERT INTO interlock.sinks (name, kind, operations, cost_per_call, idempotency, "
            "max_payload_bytes, not_after_seconds, max_attempts, backoff_base_ms, "
            "backoff_cap_ms, unknown_outcome, config_hash, enabled) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true) "
            "ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind, "
            "operations = EXCLUDED.operations, cost_per_call = EXCLUDED.cost_per_call, "
            "idempotency = EXCLUDED.idempotency, "
            "max_payload_bytes = EXCLUDED.max_payload_bytes, "
            "not_after_seconds = EXCLUDED.not_after_seconds, "
            "max_attempts = EXCLUDED.max_attempts, "
            "backoff_base_ms = EXCLUDED.backoff_base_ms, "
            "backoff_cap_ms = EXCLUDED.backoff_cap_ms, "
            "unknown_outcome = EXCLUDED.unknown_outcome, "
            "config_hash = EXCLUDED.config_hash, enabled = true",
            (
                sink.name,
                sink.kind,
                [op.name for op in sink.operations],
                str(sink.cost_per_call),
                sink.idempotency,
                sink.max_payload_bytes,
                int(sink.not_after.total_seconds()),
                sink.max_attempts,
                _milliseconds(sink.backoff_base),
                _milliseconds(sink.backoff_cap),
                sink.unknown_outcome,
                sink.config_hash(),
            ),
        )
    conn.execute(
        "UPDATE interlock.sinks SET enabled = false WHERE NOT (name = ANY (%s))",
        ([sink.name for sink in sinks],),
    )


def _install_sources(conn: psycopg.Connection[Any], sources: Sequence[InboundSource]) -> None:
    """Mirror the inbound sources into ``interlock.inbox_sources``: no secret."""
    from interlock.inbox import inbox_genesis

    for source in sources:
        conn.execute(
            "INSERT INTO interlock.inbox_sources (name, kind, config_hash, enabled, log_seq, "
            "log_head) VALUES (%s, %s, %s, true, 0, %s) ON CONFLICT (name) DO UPDATE SET "
            "kind = EXCLUDED.kind, config_hash = EXCLUDED.config_hash, enabled = true",
            (source.name, source.kind, source.config_hash(), inbox_genesis(source.name)),
        )
    conn.execute(
        "UPDATE interlock.inbox_sources SET enabled = false WHERE NOT (name = ANY (%s))",
        ([source.name for source in sources],),
    )


def installed_version(conn: psycopg.Connection[Any]) -> int:
    """Which version installed the outbox in this database: 7 when it records
    revoked keys and their seals, 6 when it keeps trace context, 5 when
    vacuums compact it under checkpoints, 4 when its
    delivery log records relays' attestations and rate windows keep their
    history, 3 when the log records what calls created, 2 before; 0 when there
    is no outbox."""
    row = conn.execute(
        "SELECT pg_catalog.to_regclass('interlock.outbox_attempts') IS NOT NULL, "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_attribute "
        "        WHERE attrelid = pg_catalog.to_regclass('interlock.outbox_attempts') "
        "        AND attname = 'remote_ref' AND NOT attisdropped), "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_attribute "
        "        WHERE attrelid = pg_catalog.to_regclass('interlock.outbox_attempts') "
        "        AND attname = 'attestation' AND NOT attisdropped), "
        "pg_catalog.to_regclass('interlock.window_ledger') IS NOT NULL, "
        "pg_catalog.to_regclass('interlock.checkpoints') IS NOT NULL, "
        "pg_catalog.to_regclass('interlock.outbox_traces') IS NOT NULL, "
        "pg_catalog.to_regclass('interlock.key_revocations') IS NOT NULL"
    ).fetchone()
    if row is None or not row[0]:
        return 0
    if row[2] and row[3]:
        if not row[4]:
            return 4
        if not row[5]:
            return 5
        return 7 if row[6] else 6
    return 3 if row[1] else 2


def _milliseconds(span: timedelta) -> int:
    return int(span / timedelta(milliseconds=1))


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
    :param pool_timeout_seconds: How long the stage waits for its second
        connection, the one that reads the rate windows, while it holds its
        locks: connecting is bounded by libpq's ``connect_timeout`` (whole
        seconds, two at least), and its first statement, where a
        transaction-mode pooler queues a client, by this.
        :class:`~interlock.exceptions.PoolExhaustedError` when it runs out.
        Defaults to the lock timeout.
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
        "_charges",
        "_conn",
        "_dsn",
        "_enforce",
        "_enqueued",
        "_facts",
        "_folded",
        "_handle",
        "_lock_seconds",
        "_max_rows",
        "_metrics",
        "_order",
        "_pool_seconds",
        "_report",
        "_schema",
        "_scope",
        "_stage_seconds",
        "_tables",
        "_token",
        "_traceparent",
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
        pool_timeout_seconds: float | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        _identifier(schema)
        pool = lock_timeout_seconds if pool_timeout_seconds is None else pool_timeout_seconds
        if pool <= 0:
            raise ValueError("pool_timeout_seconds is positive")
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
        self._pool_seconds = min(pool, max_stage_seconds)
        self._metrics: Metrics = metrics if metrics is not None else NullMetrics()
        self._max_rows = max_diff_rows
        self._enforce = enforce_table_access
        self._report: CascadeReport | None = None
        self._conn: psycopg.Connection[Any] | None = None
        self._handle: StageHandle | None = None
        self._xid: str | None = None
        self._reset_outbound()

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
            outbound=True,
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

    @property
    def table_specs(self) -> tuple[TableSpec, ...]:
        """The tables observed, as configured."""
        return self._tables

    @property
    def enforces_table_access(self) -> bool:
        """Whether a write outside the observed tables is refused."""
        return self._enforce

    def connection(self, handle: StageHandle) -> psycopg.Connection[Any]:
        """The open stage's connection, for a governor to join its transaction.

        What runs on it runs inside the stage, as the stage's role, and commits
        or rolls back with the effects. Only the engine's commit path uses it,
        after every effect has been applied and adjudicated (see
        :meth:`interlock.anchor.LedgerAnchor.joined_commit`).

        :raises StageError: If ``handle`` is not the stage open here.
        """
        return self._require(handle)

    def _reset_outbound(self) -> None:
        self._token: bytes | None = None
        self._scope: str | None = None
        self._order = EnqueueOrder()
        self._charges: tuple[WindowCharge, ...] = ()
        self._facts: tuple[uuid.UUID, ...] = ()
        self._traceparent: str | None = None
        self._enqueued = 0

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

        An ``ENQUEUE`` effect carries a request, not a statement, and is
        vetted against the sink registry instead (and by ``interlock.enqueue``
        when it is written).

        :param effect: The effect to vet.
        :returns: A refusal reason, or ``None`` when it may be staged.
        """
        if effect.kind is EffectKind.ENQUEUE:
            return None
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
        # Authorizes this stage's writes to the outbox. Held here and sent only
        # as a bound parameter of the substrate's own enqueue calls; the stage
        # row keeps its hash, which the stage role cannot read.
        token = secrets.token_bytes(32)
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
                "SELECT interlock.begin_stage(%s, %s, %s::jsonb, %s)::text",
                (
                    stage_id,
                    plan.plan_id,
                    json.dumps(_gates(report)),
                    hashlib.sha256(token).digest(),
                ),
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
        self._reset_outbound()
        self._token = token
        self._scope = plan.scope_id
        self._traceparent = plan.traceparent
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
        if effect.kind is EffectKind.ENQUEUE:
            outcome = self._enqueue(conn, handle, effect)
        else:
            refusal = self.reject_reason(effect)
            if refusal is not None:
                raise ForbiddenStatementError(
                    f"effect {effect.effect_id!r} refused: {refusal}", reason=_verb_reason(effect)
                )
            try:
                # Re-asserted every time: a SELECT can call set_config() and
                # lift them, and a stage bound that the agent can lift is not a
                # bound.
                conn.execute(self._timeouts())
                # binary=True sends the statement with the extended protocol,
                # which the server refuses to split: "UPDATE ...; COMMIT" fails
                # instead of committing the stage before adjudication. Unnamed,
                # so nothing is prepared that a pooler would hand on.
                cursor = conn.execute(effect.statement, dict(effect.parameters), binary=True)
            except psycopg.Error as exc:
                raise self._statement_error(effect, exc) from exc
            outcome = EffectOutcome(
                effect_id=effect.effect_id,
                rows_affected=max(cursor.rowcount, 0),
                applied_at=datetime.now(UTC),
            )
        self._order.applied(
            effect.effect_id, effect.depends_on, request=effect.kind is EffectKind.ENQUEUE
        )
        return outcome

    def _enqueue(
        self, conn: psycopg.Connection[Any], handle: StageHandle, effect: Effect
    ) -> EffectOutcome:
        """Write one outbound request to the outbox, in the stage's transaction.

        Through ``interlock.enqueue``, with this stage's token. The function
        recomputes the payload's hash over the exact bytes sent, and refuses
        a sink or operation the database does not have enabled.
        """
        import psycopg

        request = effect.request
        if request is None or self._token is None or not self._scope:
            raise StageError(f"effect {effect.effect_id!r} cannot be enqueued outside a stage")
        compensation = (
            None
            if request.compensation is None
            else canonical_bytes(request.compensation.to_json()).decode("utf-8")
        )
        try:
            conn.execute(self._timeouts())
            conn.execute(
                f"SELECT {_ENQUEUE_CALL}",
                (
                    self._token,
                    uuid.uuid4(),
                    effect.effect_id,
                    self._order.next_seq(),
                    sorted(self._order.waits_for(effect.depends_on)),
                    request.sink,
                    request.operation,
                    effect.tenant_id,
                    request.canonical_payload.decode("utf-8"),
                    request.payload_hash,
                    outbound_key(handle.plan_id, effect.effect_id),
                    compensation,
                    None if request.not_after is None else int(request.not_after.total_seconds()),
                    self._scope,
                ),
            )
        except psycopg.Error as exc:
            raise self._enqueue_error(effect, exc) from exc
        self._enqueued += 1
        return EffectOutcome(
            effect_id=effect.effect_id, rows_affected=1, applied_at=datetime.now(UTC)
        )

    def _enqueue_error(self, effect: Effect, exc: Exception) -> InterlockError:
        sqlstate = getattr(exc, "sqlstate", None)
        sink = effect.request.sink if effect.request is not None else None
        if sqlstate == _OUTBOUND:
            detail = _json_detail(getattr(getattr(exc, "diag", None), "message_detail", None))
            return OutboundRequestError(
                f"effect {effect.effect_id!r} refused by the outbox: {exc}",
                reason=str(detail.get("reason", "unregistered_sink")),
                sink=sink,
            )
        if sqlstate == _UNIQUE:
            return OutboundRequestError(
                f"effect {effect.effect_id!r}: this plan's request is already in the outbox "
                f"(its idempotency key is taken); a request commits at most once",
                reason="duplicate",
                sink=sink,
            )
        return self._statement_error(effect, exc)

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
        try:
            requests = conn.execute(
                "SELECT out_message, out_effect, out_depends, out_sink, out_operation, "
                "out_tenant, out_payload, out_payload_hash, out_idempotency_key, out_cost "
                "FROM interlock.stage_outbox(%s)",
                (self._max_rows + 1,),
            ).fetchall()
        except psycopg.Error as exc:
            raise StageError(f"could not read the stage's outbox: {exc}") from exc
        consumed: list[Any] = []
        if self._facts:
            try:
                consumed = conn.execute(
                    "SELECT * FROM interlock.stage_facts(%s)", (self._max_rows + 1,)
                ).fetchall()
            except psycopg.Error as exc:
                raise StageError(f"could not read the facts the stage consumed: {exc}") from exc
        truncated = len(rows) > self._max_rows or len(requests) > self._max_rows
        outbound = tuple(
            OutboundDelta(
                message_id=message,
                effect_id=EffectId(str(effect_id)),
                sink=str(sink),
                operation=str(operation),
                tenant_id=None if tenant is None else str(tenant),
                payload=_frozen(loads_strict(str(payload))),
                payload_hash=str(payload_hash),
                idempotency_key=str(key),
                depends_on=tuple(EffectId(str(d)) for d in depends or ()),
                cost=Decimal(str(cost)),
            )
            for (
                message,
                effect_id,
                depends,
                sink,
                operation,
                tenant,
                payload,
                payload_hash,
                key,
                cost,
            ) in requests[: self._max_rows]
        )
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
            outbound=outbound,
            facts=tuple(fact_row(r) for r in consumed),
        )

    # -- inbound facts (docs/EPIC5_DESIGN.md §2) --------------------------------

    def pending_facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        """The facts pending for ``scope_id``, read on a connection of their
        own, outside every stage: ``interlock.inbox_pending`` refuses inside
        one, so no statement of a plan reads them.

        :raises SubstrateConfigurationError: If the inbox is not installed.
        """
        import psycopg

        with self._reader(bounded=False) as side:
            try:
                rows = side.execute(
                    "SELECT * FROM interlock.inbox_pending(%s)", (scope_id,)
                ).fetchall()
                traces = {
                    r[0]: (r[1], r[2])
                    for r in side.execute(
                        "SELECT * FROM interlock.inbox_pending_traces(%s)", (scope_id,)
                    ).fetchall()
                }
            except psycopg.Error as exc:
                raise self._setup_error(exc) from exc
        # Each fact with what decides its trace context: its delivery's and
        # its webhook's (docs/EPIC7_DESIGN.md §1.4).
        return tuple(fact_row((*r, *traces.get(r[0], (None, None)))) for r in rows)

    def consume_facts(
        self, handle: StageHandle, fact_ids: Sequence[uuid.UUID], scope_id: str
    ) -> None:
        """Consume the plan's facts in its stage, with its token
        (``interlock.inbox_consume``): each its scope's, and not consumed
        already. The rows commit with the stage, or not at all.

        :raises InboundFactError: If a fact is unknown, another scope's, or
            consumed already.
        :raises StageConflictError: If another open stage is consuming one.
        """
        import psycopg

        conn = self._require(handle)
        self._assert_live(handle)
        if self._token is None:
            raise StageError("facts are consumed inside a stage")
        try:
            conn.execute(self._timeouts())
            conn.execute(
                "SELECT interlock.inbox_consume(%s, %s::uuid[], %s)",
                (self._token, list(fact_ids), scope_id),
            )
        except psycopg.Error as exc:
            if exc.sqlstate == _INBOUND:
                raise InboundFactError(f"the stage could not consume a fact: {exc}") from exc
            if exc.sqlstate == _UNIQUE:
                raise InboundFactError(
                    f"a fact the plan consumes was consumed already: {exc}"
                ) from exc
            if exc.sqlstate in _CONFLICTS:
                raise StageConflictError(
                    f"another stage is consuming a fact this plan consumes: {exc}"
                ) from exc
            raise StageError(f"could not consume the plan's facts: {exc}") from exc
        self._facts = tuple(fact_ids)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        """What each window holds for each key the plan adds to, exactly.

        First, on the stage's own connection, a transaction-scoped advisory
        lock on every key, taken in one order (``interlock.window_lock``), so
        no two stages wait on each other in a cycle: no stage can add to a
        key this one holds until this one commits or rolls back. Then the
        history, read on a second connection in ``READ COMMITTED``
        (``interlock.window_totals``), which sees every commit, those after
        this stage's snapshot included, and is closed once it has read. What
        the plan adds is written with the stage's token when it commits.

        :raises StageConflictError: If a key stayed locked by another stage
            past the lock timeout.
        """
        import psycopg

        conn = self._require(handle)
        self._assert_live(handle)
        # Connected before locking, so connecting is not inside the wait the
        # lock imposes on others, and within the pool timeout, since the
        # stage's own locks are held meanwhile; closed once it has read, so
        # the stage holds one session again by its commit.
        with self._reader(bounded=True) as side:
            locking = time.monotonic()
            try:
                conn.execute(self._timeouts())
                self._lock_windows(conn, charges)
            except psycopg.Error as exc:
                if exc.sqlstate in _CONFLICTS:
                    self._waited("window_lock", time.monotonic() - locking)
                    raise StageConflictError(
                        f"a rate window this plan adds to stayed locked by another stage: {exc}"
                    ) from exc
                raise self._setup_error(exc) from exc
            self._waited("window_lock", time.monotonic() - locking)
            try:
                rows = side.execute(
                    "SELECT out_window, out_key, out_total "
                    "FROM interlock.window_totals(%s::text[], %s::text[], %s::bigint[])",
                    (
                        [c.window for c in charges],
                        [c.key for c in charges],
                        [c.span // timedelta(microseconds=1) for c in charges],
                    ),
                ).fetchall()
            except psycopg.Error as exc:
                if exc.sqlstate == _PRUNED:
                    raise SubstrateConfigurationError(_PRUNED_WINDOW) from exc
                raise self._setup_error(exc) from exc
        held = {(str(w), str(k)): Decimal(str(total)) for w, k, total in rows}
        self._charges = tuple(charges)
        return tuple(
            WindowMeasure(c.window, c.key, held.get((c.window, c.key), Decimal(0)), c.amount)
            for c in charges
        )

    def _waited(self, wait: str, seconds: float) -> None:
        """A wait the stage made: for its windows' connection, or for their keys' locks."""
        name = (
            "interlock_pool_wait_seconds"
            if wait == "pool"
            else "interlock_window_lock_wait_seconds"
        )
        self._metrics.observe(name, seconds)
        self._metrics.observe("interlock_wait_max_seconds", seconds, wait=wait)

    def _lock_windows(self, conn: psycopg.Connection[Any], charges: Sequence[WindowCharge]) -> None:
        """Lock every key the plan adds to until the stage ends, in one order."""
        locks = sorted({window_lock(c.window, c.key) for c in charges})
        conn.execute("SELECT interlock.window_lock(%s::bigint[])", (locks,))

    @contextmanager
    def _reader(self, *, bounded: bool) -> Iterator[psycopg.Connection[Any]]:
        """A second connection, outside the stage, for one read, in one
        ``READ COMMITTED`` transaction: each statement sees every commit before
        it, and nothing set outlives the transaction in a session that a
        transaction-mode pooler hands on to the next client.

        :param bounded: Whether the connection must be had within the pool
            timeout, or :class:`PoolExhaustedError`: for a stage that holds
            its locks while it waits.
        """
        import psycopg

        asked = time.monotonic()
        try:
            side = self._connect(timeout=self._pool_seconds if bounded else None)
        except SubstrateUnavailableError as exc:
            if bounded and _exhausted(exc.__cause__ or exc):
                raise self._exhausted_error(exc, asked) from exc
            raise
        try:
            watch = _Watch(side, self._pool_seconds if bounded else None)
            try:
                with watch:
                    side.execute(
                        "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; "
                        f"SET LOCAL statement_timeout = {max(1, int(self._stage_seconds * 1000))}"
                    )
            except psycopg.Error as exc:
                if bounded and (watch.fired or _exhausted(exc)):
                    raise self._exhausted_error(exc, asked) from exc
                raise SubstrateUnavailableError(f"cannot read outside the stage: {exc}") from exc
            if watch.fired:  # had, but only after the bound: a cancel may follow it
                raise self._exhausted_error(None, asked)
            if bounded:
                self._waited("pool", time.monotonic() - asked)
            yield side
        finally:
            side.close()

    def _exhausted_error(self, cause: BaseException | None, asked: float) -> PoolExhaustedError:
        self._metrics.inc("interlock_pool_exhausted_total")
        self._waited("pool", time.monotonic() - asked)
        return PoolExhaustedError(
            f"no connection came free within {self._pool_seconds:g}s to read the rate windows: "
            f"the pool, or the server's limit, is held by other stages"
            + ("" if cause is None else f" ({cause})")
        )

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Make the staged work durable, with its ``interlock.stages`` row,
        and what the plan adds to each rate window it was measured against.

        :raises StageError: If the transaction had already failed, or the
            server refused the commit. PostgreSQL answers ``COMMIT`` on a
            failed transaction with a rollback, not an error, so the answer is
            checked.
        :raises CommitUnsettledError: If the connection was lost with the
            ``COMMIT`` sent. The server may have committed, may still be
            committing, or may have rolled back; no answer came back to say
            which, so the stage's marker has to (see :meth:`resolve_intent`).
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
        if self._charges:
            try:
                conn.execute(
                    "SELECT interlock.window_add(%s, %s::text[], %s::text[], %s::numeric[])",
                    (
                        self._token,
                        [c.window for c in self._charges],
                        [c.key for c in self._charges],
                        [c.amount for c in self._charges],
                    ),
                )
            except psycopg.Error as exc:
                raise StageError(
                    f"could not record what the plan adds to its windows: {exc}"
                ) from exc
        if self._traceparent is not None and self._enqueued:
            try:
                conn.execute(
                    "SELECT interlock.outbox_trace(%s, %s)", (self._token, self._traceparent)
                )
            except psycopg.Error as exc:
                raise StageError(f"could not keep the plan's trace context: {exc}") from exc
        try:
            cursor = conn.execute("COMMIT")
        except psycopg.Error as exc:
            if conn.broken or conn.closed:
                # No answer, as opposed to an error the server sent: that one
                # means it rolled back. This means nothing either way.
                raise CommitUnsettledError(
                    f"stage {handle.stage_id}: the connection was lost with COMMIT sent, so "
                    f"whether it committed is the server's to say ({exc})"
                ) from exc
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

    def savepoint(self, handle: StageHandle, name: str) -> None:
        """Mark the stage's state now, to return to with :meth:`rollback_to`.

        The capture table, the stage's own settings and a failed statement's
        aborted state all roll back with it, so a trial that errors does not
        end the stage.
        """
        self._savepoint_statement(handle, "SAVEPOINT", name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        """Undo everything since :meth:`savepoint` ``name``; the mark stays."""
        self._savepoint_statement(handle, "ROLLBACK TO SAVEPOINT", name)

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        """Forget a mark, keeping what ran since it."""
        self._savepoint_statement(handle, "RELEASE SAVEPOINT", name)

    def _savepoint_statement(self, handle: StageHandle, verb: str, name: str) -> None:
        import psycopg

        conn = self._require(handle)
        _identifier(name)
        try:
            conn.execute(f"{verb} {name}")
        except psycopg.Error as exc:
            raise StageError(f"{verb} {name} failed: {exc}") from exc

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
        self._reset_outbound()

    # -- internals ------------------------------------------------------------

    def _connect(self, *, timeout: float | None = None) -> psycopg.Connection[Any]:
        """A connection of the stage role's. Nothing is prepared on the server:
        a transaction-mode pooler hands the server's session, and what was
        prepared in it, on to other clients."""
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
                prepare_threshold=None,
                application_name="interlock",
                connect_timeout=(
                    max(1, int(self._stage_seconds))
                    if timeout is None
                    else max(2, math.ceil(timeout))
                ),
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
        outbox = conn.execute("SELECT to_regclass('interlock.outbox') IS NOT NULL").fetchone()
        if outbox is None or not outbox[0]:
            raise SubstrateConfigurationError(
                "Interlock in this database was installed by an older version, without "
                "the outbox. Run `interlock install` to upgrade it in place"
            )
        version = installed_version(conn)
        if version < int(INSTALL_VERSION):
            raise SubstrateConfigurationError(
                f"Interlock in this database was installed by version {version}. Run "
                f"`interlock install` to upgrade it in place to version {INSTALL_VERSION}"
            )
        guards = {
            (str(r[0]), str(r[1])): (str(r[2]), str(r[3]))
            for r in conn.execute(
                """
                SELECT c.relname::text, t.tgname::text, t.tgenabled::text,
                       pn.nspname::text || '.' || p.proname::text
                  FROM pg_catalog.pg_trigger t
                  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
                  JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
                 WHERE n.nspname = 'interlock'
                   AND c.relname IN ('outbox', 'outbox_attempts', 'outbox_state', 'window_ledger')
                """
            ).fetchall()
        }
        for table, trigger, function in OUTBOX_TRIGGER_NAMES:
            if guards.get((table, trigger)) != ("A", function):
                problems.append(
                    f"interlock.{table}: {trigger} is missing or not ENABLE ALWAYS, so a "
                    f"committed request or its delivery log could be rewritten"
                )
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
        internal = conn.execute(
            members
            + """
            SELECT DISTINCT c.relname::text
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              CROSS JOIN member_of m
             WHERE n.nspname = 'interlock' AND c.relkind IN ('r', 'p', 'v')
               AND (pg_catalog.has_table_privilege(
                        m.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE')
                    OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'INSERT, UPDATE'))
             ORDER BY 1
            """
        ).fetchall()
        if internal:
            raise SubstrateConfigurationError(
                f"the stage's role ({roles}) can write Interlock's own table(s) "
                f"{', '.join('interlock.' + str(r[0]) for r in internal)}; a stage writes "
                f"them only through the installed functions, which check its token. Revoke "
                f"the grant"
            )
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
                f"Interlock is not installed in this database, is installed by an older "
                f"version, or not for this role: {exc}. Run `interlock install`"
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
        if sqlstate == _WINDOWS:
            return ForbiddenStatementError(
                f"{who} refused: {exc}. What other plans added to a rate window, and the "
                f"inbox, are read outside every stage, never by a plan's statement",
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
