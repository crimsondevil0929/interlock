"""The transactional outbox on SQLite (``docs/EPIC3_DESIGN.md`` §2).

The same outbox as PostgreSQL's (``docs/OUTBOX_DESIGN.md``), in the database
file itself: ``_interlock_sinks``, ``_interlock_outbox``,
``_interlock_outbox_state`` and ``_interlock_outbox_attempts``, created by
:func:`install_sqlite_outbox`. A stage writes its requests in its own
``BEGIN IMMEDIATE`` transaction (:func:`enqueue`); a relay delivers them through
a :class:`SqliteOutboxStore`.

**Concurrency.** SQLite has one writer at a time, and that is the mechanism:
every write here is a short ``BEGIN IMMEDIATE`` transaction, which takes the
write lock as it begins. A claim reads the due messages and leases them under
that lock, so no other claim, call record, outcome or stage can write until it
commits, and the next claim reads the leases and passes them by: what
PostgreSQL's ``SKIP LOCKED`` does by skipping, SQLite does by queueing. No
transaction ever starts as a read and becomes a write, which WAL refuses once
another writer has committed. A relay never holds the lock while it calls a
sink.

**Gates.** The stage's own authorizer refuses agent statements any write to
these tables; a store's connection carries an authorizer of its own, admitting
writes to delivery state and the delivery log only (and, for an operator's
compensations, the outbox). Triggers make the outbox and the log append-only,
and every log row must sit at its message's head, link to it, and hash to what
it holds, recomputed by ``interlock_event_hash``: an application function only
Interlock registers, so a connection without it cannot append to the log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from agentgov.receipts.canonical import canonical_bytes, loads_strict

from interlock.deliveries import (
    LogEvent,
    LoggedMessage,
    MessageView,
    event_hash,
    genesis_hash,
    parse_instant,
)
from interlock.exceptions import (
    OutboundRequestError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.outbound import typed_sink
from interlock.outbox_store import Checkpoint, milliseconds
from interlock.types import OutboundDelta, _frozen

if TYPE_CHECKING:
    from interlock.outbound import SinkSpec
    from interlock.relay import DeliveryResult, Lease
    from interlock.types import Effect

__all__ = [
    "OUTBOX_TABLES",
    "SqliteOutboxStore",
    "enqueue",
    "install_sqlite_outbox",
    "outbox_installed",
    "stage_requests",
]

logger = logging.getLogger("interlock.sqlite_outbox")

SINKS: Final = "_interlock_sinks"
OUTBOX: Final = "_interlock_outbox"
STATE: Final = "_interlock_outbox_state"
LOG: Final = "_interlock_outbox_attempts"
OUTBOX_TABLES: Final = frozenset({SINKS, OUTBOX, STATE, LOG})

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

_STATES: Final = "'pending', 'leased', 'held', 'delivered', 'dead', 'cancelled'"
_EVENTS: Final = (
    "'sending', 'delivered', 'retryable', 'permanent', 'unknown', 'lost', 'held', "
    "'deferred', 'expired', 'refused', 'dependency_failed', 'released', 'requeued', "
    "'cancelled', 'compensated'"
)

_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS main._interlock_commits "
    "(stage_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, committed_at TEXT NOT NULL)",
    f"""CREATE TABLE IF NOT EXISTS main.{SINKS} (
        name              TEXT PRIMARY KEY,
        kind              TEXT NOT NULL DEFAULT 'http'
                          CHECK (kind IN ('http', 'stripe', 'sendgrid')),
        operations        TEXT NOT NULL,
        cost_per_call     TEXT NOT NULL,
        idempotency       TEXT NOT NULL CHECK (idempotency IN ('header', 'none')),
        max_payload_bytes INTEGER NOT NULL CHECK (max_payload_bytes > 0),
        not_after_seconds INTEGER NOT NULL CHECK (not_after_seconds > 0),
        max_attempts      INTEGER NOT NULL CHECK (max_attempts > 0),
        backoff_base_ms   INTEGER NOT NULL CHECK (backoff_base_ms > 0),
        backoff_cap_ms    INTEGER NOT NULL CHECK (backoff_cap_ms >= backoff_base_ms),
        unknown_outcome   TEXT NOT NULL CHECK (unknown_outcome IN ('redeliver', 'dead-letter')),
        config_hash       TEXT NOT NULL,
        enabled           INTEGER NOT NULL DEFAULT 1
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{OUTBOX} (
        message_id      TEXT PRIMARY KEY,
        stage_id        TEXT NOT NULL
                        REFERENCES _interlock_commits (stage_id) DEFERRABLE INITIALLY DEFERRED,
        plan_id         TEXT NOT NULL,
        scope_id        TEXT NOT NULL,
        effect_id       TEXT NOT NULL,
        seq             INTEGER NOT NULL,
        depends_on      TEXT NOT NULL DEFAULT '[]',
        sink            TEXT NOT NULL REFERENCES {SINKS} (name),
        operation       TEXT NOT NULL,
        tenant_id       TEXT,
        payload         TEXT NOT NULL,
        payload_hash    TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        cost            TEXT NOT NULL,
        compensation    TEXT,
        compensates     TEXT REFERENCES {OUTBOX} (message_id),
        not_after       INTEGER NOT NULL,
        enqueued_at     INTEGER NOT NULL,
        UNIQUE (stage_id, effect_id)
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{STATE} (
        message_id      TEXT PRIMARY KEY REFERENCES {OUTBOX} (message_id),
        state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ({_STATES})),
        attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        attempt_floor   INTEGER NOT NULL DEFAULT 0 CHECK (attempt_floor >= 0),
        fence           INTEGER NOT NULL DEFAULT 0,
        lease_owner     TEXT,
        lease_expires   INTEGER,
        next_attempt_at INTEGER NOT NULL,
        reason          TEXT,
        log_seq         INTEGER NOT NULL DEFAULT 0,
        log_head        TEXT NOT NULL,
        updated_at      INTEGER NOT NULL
    )""",
    f"CREATE INDEX IF NOT EXISTS main._interlock_outbox_ready ON {STATE} (next_attempt_at) "
    f"WHERE state IN ('pending', 'leased')",
    f"""CREATE TABLE IF NOT EXISTS main.{LOG} (
        message_id      TEXT NOT NULL REFERENCES {OUTBOX} (message_id),
        seq             INTEGER NOT NULL CHECK (seq > 0),
        attempt         INTEGER CHECK (attempt > 0),
        event           TEXT NOT NULL CHECK (event IN ({_EVENTS})),
        actor           TEXT NOT NULL,
        at              TEXT NOT NULL,
        status_code     INTEGER,
        response_digest TEXT,
        detail          TEXT,
        state_after     TEXT CHECK (state_after IN ({_STATES})),
        remote_ref      TEXT,
        authority       TEXT,
        prev_hash       TEXT NOT NULL,
        event_hash      TEXT NOT NULL,
        PRIMARY KEY (message_id, seq)
    )""",
    # The request the checkers adjudicated, and its delivery log, are never edited.
    f"CREATE TRIGGER IF NOT EXISTS _interlock_outbox_no_update BEFORE UPDATE ON {OUTBOX} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {OUTBOX} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_outbox_no_delete BEFORE DELETE ON {OUTBOX} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {OUTBOX} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_log_no_update BEFORE UPDATE ON {LOG} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {LOG} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_log_no_delete BEFORE DELETE ON {LOG} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {LOG} is append-only'); END",
    # Every row sits at its message's head, links to it, and hashes to what it
    # holds. interlock_event_hash exists only on Interlock's own connections.
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_log_link BEFORE INSERT ON {LOG}
    BEGIN
        SELECT RAISE(ABORT, 'interlock: a delivery-log row must extend its message''s log')
         WHERE NEW.seq IS NOT (SELECT s.log_seq + 1 FROM {STATE} AS s
                                WHERE s.message_id = NEW.message_id)
            OR NEW.prev_hash IS NOT (SELECT s.log_head FROM {STATE} AS s
                                      WHERE s.message_id = NEW.message_id)
            OR NEW.event_hash IS NOT interlock_event_hash(
                   NEW.prev_hash, NEW.message_id, NEW.seq, NEW.attempt, NEW.event, NEW.actor,
                   NEW.at, NEW.status_code, NEW.response_digest, NEW.detail, NEW.state_after,
                   NEW.remote_ref, NEW.authority);
    END""",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_log_head AFTER INSERT ON {LOG}
    BEGIN
        UPDATE {STATE} SET log_seq = NEW.seq, log_head = NEW.event_hash
         WHERE message_id = NEW.message_id;
    END""",
)

LOG_TRIGGERS: Final = (
    "_interlock_outbox_no_update",
    "_interlock_outbox_no_delete",
    "_interlock_log_no_update",
    "_interlock_log_no_delete",
    "_interlock_log_link",
    "_interlock_log_head",
)


# --------------------------------------------------------------------------
# Time: microseconds since the epoch, on this host's clock, which every
# process that may open the file (WAL: one host) shares.
# --------------------------------------------------------------------------


def now_us() -> int:
    return time.time_ns() // 1000


def instant(us: int) -> datetime:
    return _EPOCH + timedelta(microseconds=us)


def instant_text(us: int) -> str:
    return instant(us).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _us(span: timedelta) -> int:
    return int(span / timedelta(microseconds=1))


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------


def register(conn: sqlite3.Connection) -> None:
    """Register what the delivery log's triggers need on ``conn``."""
    conn.create_function("interlock_event_hash", 13, _event_hash_sql, deterministic=True)


def _event_hash_sql(
    prev: str,
    message: str,
    seq: int,
    attempt: int | None,
    event: str,
    actor: str,
    at: str,
    status: int | None,
    digest: str | None,
    detail: str | None,
    state_after: str | None,
    remote_ref: str | None,
    authority: str | None,
) -> str:
    return event_hash(
        prev,
        uuid.UUID(message),
        int(seq),
        attempt,
        event,
        actor,
        at,
        status,
        digest,
        detail,
        state_after,
        remote_ref,
        authority,
    )


def outbox_installed(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN (?, ?, ?, ?)",
        (SINKS, OUTBOX, STATE, LOG),
    ).fetchone()
    return bool(row and row[0] == 4)


def install_sqlite_outbox(path: str | Path, sinks: Iterable[SinkSpec] = ()) -> None:
    """Install the outbox in a SQLite file, and mirror the sink registry. Idempotent.

    Switches the file to WAL first, so a relay's and an operator's reads never
    wait on a stage: the setting is persistent, and every process that opens
    the file must then be on this host. A sink installed before and not listed
    now is disabled, not deleted: requests in the outbox name it.

    :raises SubstrateConfigurationError: If the file cannot be put in WAL mode
        (an in-memory database, say).
    """
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=30)
    try:
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            raise SubstrateConfigurationError(
                f"{path} could not be switched to WAL (it is {mode[0] if mode else '?'}); "
                f"the outbox needs a file database"
            )
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA:
                conn.execute(statement)
            listed = list(sinks)
            for sink in listed:
                conn.execute(
                    f"INSERT INTO {SINKS} (name, kind, operations, cost_per_call, idempotency, "
                    f"max_payload_bytes, not_after_seconds, max_attempts, backoff_base_ms, "
                    f"backoff_cap_ms, unknown_outcome, config_hash, enabled) "
                    f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1) "
                    f"ON CONFLICT (name) DO UPDATE SET kind = excluded.kind, "
                    f"operations = excluded.operations, cost_per_call = excluded.cost_per_call, "
                    f"idempotency = excluded.idempotency, "
                    f"max_payload_bytes = excluded.max_payload_bytes, "
                    f"not_after_seconds = excluded.not_after_seconds, "
                    f"max_attempts = excluded.max_attempts, "
                    f"backoff_base_ms = excluded.backoff_base_ms, "
                    f"backoff_cap_ms = excluded.backoff_cap_ms, "
                    f"unknown_outcome = excluded.unknown_outcome, "
                    f"config_hash = excluded.config_hash, enabled = 1",
                    (
                        sink.name,
                        sink.kind,
                        json.dumps([op.name for op in sink.operations]),
                        str(sink.cost_per_call),
                        sink.idempotency,
                        sink.max_payload_bytes,
                        int(sink.not_after.total_seconds()),
                        sink.max_attempts,
                        milliseconds(sink.backoff_base),
                        milliseconds(sink.backoff_cap),
                        sink.unknown_outcome,
                        sink.config_hash(),
                    ),
                )
            conn.execute(
                f"UPDATE {SINKS} SET enabled = 0 "
                f"WHERE name NOT IN (SELECT value FROM json_each(?))",
                (json.dumps([s.name for s in listed]),),
            )
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


# --------------------------------------------------------------------------
# The stage's side: written in the stage's own transaction
# --------------------------------------------------------------------------


def enqueue(
    conn: sqlite3.Connection,
    *,
    stage_id: uuid.UUID,
    plan_id: str,
    scope_id: str,
    effect: Effect,
    seq: int,
    waits_for: Iterable[str],
    idempotency_key: str,
) -> uuid.UUID:
    """Write one request, its delivery state and its log's genesis, inside the
    stage's transaction: it commits with the stage's marker, or not at all.

    The sink, the operation, the size and the hash are checked against this
    file's own registry, as PostgreSQL's ``enqueue`` checks its own; the price
    is stored with the request.

    :raises OutboundRequestError: On a sink or operation the registry does
        not have enabled, a payload over its bound or not matching its hash,
        a typed sink's request its rule refuses (a Stripe charge without the
        refund that undoes it), or a request already in the outbox.
    """
    request = effect.request
    assert request is not None
    sink = conn.execute(
        f"SELECT kind, operations, max_payload_bytes, not_after_seconds, cost_per_call "
        f"FROM {SINKS} WHERE name = ? AND enabled = 1",
        (request.sink,),
    ).fetchone()
    if sink is None:
        raise OutboundRequestError(
            f"effect {effect.effect_id!r} refused by the outbox: no enabled sink named "
            f"{request.sink!r} is installed",
            reason="unregistered_sink",
            sink=request.sink,
        )
    if request.operation not in json.loads(sink[1]):
        raise OutboundRequestError(
            f"effect {effect.effect_id!r} refused by the outbox: sink {request.sink!r} "
            f"installs no operation {request.operation!r}",
            reason="unregistered_operation",
            sink=request.sink,
        )
    payload = request.canonical_payload
    if len(payload) > int(sink[2]):
        raise OutboundRequestError(
            f"effect {effect.effect_id!r} refused by the outbox: payload of {len(payload)} "
            f"bytes exceeds sink {request.sink!r}'s bound of {sink[2]}",
            reason="payload_size",
            sink=request.sink,
        )
    if hashlib.sha256(payload).hexdigest() != request.payload_hash:
        raise OutboundRequestError(
            f"effect {effect.effect_id!r} refused by the outbox: payload does not match its hash",
            reason="payload_hash",
            sink=request.sink,
        )
    typed = typed_sink(str(sink[0]))
    if typed is not None:
        # The typed sink's rule, a second time, from the kind this file holds:
        # whatever registry the engine was configured with.
        problem = typed.compensation_problem(
            request.operation,
            request.payload,
            None if request.compensation is None else request.compensation.to_json(),
        )
        if problem is not None:
            raise OutboundRequestError(
                f"effect {effect.effect_id!r} refused by the outbox: sink {request.sink!r} "
                f"refuses the request: {problem}",
                reason="compensation",
                sink=request.sink,
            )
    message_id = uuid.uuid4()
    enqueued = now_us()
    window = request.not_after if request.not_after is not None else timedelta(seconds=int(sink[3]))
    compensation = (
        None
        if request.compensation is None
        else canonical_bytes(request.compensation.to_json()).decode("utf-8")
    )
    depends = sorted(waits_for)
    try:
        conn.execute(
            f"INSERT INTO {OUTBOX} (message_id, stage_id, plan_id, scope_id, effect_id, seq, "
            f"depends_on, sink, operation, tenant_id, payload, payload_hash, idempotency_key, "
            f"cost, compensation, not_after, enqueued_at) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(message_id),
                str(stage_id),
                plan_id,
                scope_id,
                effect.effect_id,
                seq,
                json.dumps(depends),
                request.sink,
                request.operation,
                effect.tenant_id,
                payload.decode("utf-8"),
                request.payload_hash,
                idempotency_key,
                str(sink[4]),
                compensation,
                enqueued + _us(window),
                enqueued,
            ),
        )
    except sqlite3.IntegrityError as exc:
        if "idempotency_key" in str(exc):
            raise OutboundRequestError(
                f"effect {effect.effect_id!r}: this plan's request is already in the outbox "
                f"(its idempotency key is taken); a request commits at most once",
                reason="duplicate",
                sink=request.sink,
            ) from exc
        raise
    conn.execute(
        f"INSERT INTO {STATE} (message_id, log_head, next_attempt_at, updated_at) "
        f"VALUES (?, ?, ?, ?)",
        (
            str(message_id),
            genesis_hash(
                message_id,
                stage_id,
                plan_id,
                scope_id,
                effect.effect_id,
                request.sink,
                request.operation,
                idempotency_key,
                request.payload_hash,
            ),
            enqueued,
            enqueued,
        ),
    )
    return message_id


def stage_requests(
    conn: sqlite3.Connection, stage_id: uuid.UUID, limit: int
) -> list[OutboundDelta]:
    """The stage's requests, as written, for its diff."""
    rows = conn.execute(
        f"SELECT message_id, effect_id, depends_on, sink, operation, tenant_id, payload, "
        f"payload_hash, idempotency_key, cost FROM {OUTBOX} WHERE stage_id = ? "
        f"ORDER BY seq LIMIT ?",
        (str(stage_id), limit),
    ).fetchall()
    return [
        OutboundDelta(
            message_id=uuid.UUID(str(r[0])),
            effect_id=str(r[1]),  # type: ignore[arg-type]
            sink=str(r[3]),
            operation=str(r[4]),
            tenant_id=None if r[5] is None else str(r[5]),
            payload=_frozen(loads_strict(str(r[6]))),
            payload_hash=str(r[7]),
            idempotency_key=str(r[8]),
            depends_on=tuple(json.loads(r[2])),
            cost=Decimal(str(r[9])),
        )
        for r in rows
    ]


# --------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------

RELAY: Final = frozenset({STATE, LOG})
"""What a relay's connection may write."""
OPERATOR: Final = frozenset({OUTBOX, STATE, LOG})
"""What an operator's connection may write: compensations are new requests."""

_OUTCOMES: Final = ("delivered", "retryable", "permanent", "unknown")


def _no_checkpoint(point: str, lease: Lease | None) -> None:
    return None


class SqliteOutboxStore:
    """The outbox in a SQLite file: the state machine of the ``relay_*``
    functions, transition for transition, in Python, under ``BEGIN IMMEDIATE``.

    :param path: The database file, with the outbox installed.
    :param writes: What this connection may write: :data:`RELAY` for a relay,
        :data:`OPERATOR` for an operator's actions.
    :param busy_seconds: How long a write waits for the lock. Longer than a
        stage may live (``max_stage_seconds``): a stage holds the lock for its
        whole life.
    :raises SubstrateConfigurationError: If the outbox is not installed.
    :raises SubstrateUnavailableError: If the file cannot be opened.
    """

    __slots__ = ("_conn", "_path", "_writable", "checkpoint")

    def __init__(
        self,
        path: str | Path,
        *,
        writes: frozenset[str] = RELAY,
        busy_seconds: float = 30.0,
    ) -> None:
        self._path = str(path)
        self._writable = writes
        self.checkpoint: Checkpoint = _no_checkpoint
        try:
            conn = sqlite3.connect(
                f"file:{quote(self._path)}?mode=rw",
                uri=True,
                isolation_level=None,
                timeout=busy_seconds,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open the outbox at {path}: {exc}") from exc
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=ON")
            if not outbox_installed(conn):
                raise SubstrateConfigurationError(
                    f"no outbox in {path}: run `interlock install` with [[sinks]] configured"
                )
            mode = conn.execute("PRAGMA journal_mode").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                logger.warning(
                    "%s is not in WAL mode: relays and stages will wait on each other's "
                    "reads. `interlock install` switches it",
                    path,
                )
            register(conn)
            conn.set_authorizer(self._authorize)
        except sqlite3.Error as exc:
            conn.close()
            raise SubstrateUnavailableError(f"cannot open the outbox at {path}: {exc}") from exc
        except BaseException:
            conn.close()
            raise
        self._conn = conn

    def _authorize(
        self, action: int, arg1: str | None, arg2: str | None, db: str | None, trigger: str | None
    ) -> int:
        if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
            table = (arg1 or "").lower()
            if table in self._writable or table.startswith("sqlite_"):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        self._conn.close()

    # -- transactions -----------------------------------------------------------

    @contextmanager
    def _writing(self) -> Iterator[sqlite3.Connection]:
        """One write transaction, holding the database's write lock from its
        first statement to its last."""
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise SubstrateUnavailableError(
                f"the outbox at {self._path} stayed locked: {exc}"
            ) from exc
        try:
            yield conn
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        try:
            conn.execute("COMMIT")
        except sqlite3.OperationalError as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise SubstrateUnavailableError(f"the outbox at {self._path}: {exc}") from exc

    # -- the log ---------------------------------------------------------------

    def _log(
        self,
        conn: sqlite3.Connection,
        message: str,
        attempt: int | None,
        event: str,
        actor: str,
        *,
        state_after: str | None,
        detail: str | None = None,
        status: int | None = None,
        digest: str | None = None,
        remote_ref: str | None = None,
        authority: str | None = None,
    ) -> str:
        head = conn.execute(
            f"SELECT log_seq, log_head FROM {STATE} WHERE message_id = ?", (message,)
        ).fetchone()
        seq = int(head[0]) + 1
        at = instant_text(now_us())
        actor = (actor or "?")[:200]
        digest = None if digest is None else digest[:128]
        detail = None if detail is None else detail[:1000]
        remote_ref = None if remote_ref is None else remote_ref[:255]
        digest_ = event_hash(
            str(head[1]),
            uuid.UUID(message),
            seq,
            attempt,
            event,
            actor,
            at,
            status,
            digest,
            detail,
            state_after,
            remote_ref,
            authority,
        )
        conn.execute(
            f"INSERT INTO {LOG} (message_id, seq, attempt, event, actor, at, status_code, "
            f"response_digest, detail, state_after, remote_ref, authority, prev_hash, "
            f"event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                message,
                seq,
                attempt,
                event,
                actor,
                at,
                status,
                digest,
                detail,
                state_after,
                remote_ref,
                authority,
                str(head[1]),
                digest_,
            ),
        )
        return digest_

    def _settle(
        self,
        conn: sqlite3.Connection,
        message: str,
        state: str,
        reason: str | None,
        due: int | None = None,
    ) -> None:
        now = now_us()
        conn.execute(
            f"UPDATE {STATE} SET state = ?, reason = ?, lease_owner = NULL, "
            f"lease_expires = NULL, next_attempt_at = ?, updated_at = ? WHERE message_id = ?",
            (state, None if reason is None else reason[:1000], due or now, now, message),
        )

    def _fail_dependants(self, conn: sqlite3.Connection, message: str, actor: str) -> int:
        failed = 0
        dependants = conn.execute(
            f"SELECT d.message_id, o.effect_id FROM {OUTBOX} AS o "
            f"JOIN {OUTBOX} AS d ON d.stage_id = o.stage_id "
            f"AND o.effect_id IN (SELECT value FROM json_each(d.depends_on)) "
            f"JOIN {STATE} AS ds ON ds.message_id = d.message_id "
            f"WHERE o.message_id = ? AND ds.state IN ('pending', 'held') ORDER BY d.seq",
            (message,),
        ).fetchall()
        for dependant, effect in dependants:
            self._log(
                conn,
                str(dependant),
                None,
                "dependency_failed",
                actor,
                state_after="dead",
                detail=f"waits for {effect}, which will not be delivered",
            )
            self._settle(conn, str(dependant), "dead", f"dependency failed: {effect}")
            failed += 1 + self._fail_dependants(conn, str(dependant), actor)
        return failed

    def _expire(self, conn: sqlite3.Connection, message: str, actor: str, deadline: int) -> None:
        self._log(
            conn,
            message,
            None,
            "expired",
            actor,
            state_after="dead",
            detail=f"not delivered by its deadline, {instant_text(deadline)}",
        )
        self._settle(conn, message, "dead", "expired")
        self._fail_dependants(conn, message, actor)

    # -- the relay ------------------------------------------------------------

    def claim(
        self, relay_id: str, lease: timedelta, limit: int, sinks: Sequence[str], deadline: float
    ) -> list[Lease]:
        from interlock.relay import Lease

        if not relay_id or lease <= timedelta(0) or limit <= 0:
            raise ValueError("a claim needs a relay id, a positive lease and a positive limit")
        leases: list[Lease] = []
        with self._writing() as conn:
            now = now_us()
            until = now + _us(lease)
            rows = conn.execute(
                f"SELECT s.message_id, s.state, s.attempts, s.attempt_floor, s.lease_owner, "
                f"o.plan_id, o.scope_id, o.effect_id, o.sink, o.operation, o.tenant_id, "
                f"o.payload, o.payload_hash, o.idempotency_key, o.not_after, k.idempotency, "
                f"k.max_attempts, k.backoff_base_ms, k.backoff_cap_ms, k.unknown_outcome "
                f"FROM {STATE} AS s JOIN {OUTBOX} AS o ON o.message_id = s.message_id "
                f"JOIN {SINKS} AS k ON k.name = o.sink "
                f"WHERE s.state IN ('pending', 'leased') AND s.next_attempt_at <= ? "
                f"AND o.sink IN (SELECT value FROM json_each(?)) "
                f"AND NOT EXISTS (SELECT 1 FROM {OUTBOX} AS dep "
                f"JOIN {STATE} AS ds ON ds.message_id = dep.message_id "
                f"WHERE dep.stage_id = o.stage_id "
                f"AND dep.effect_id IN (SELECT value FROM json_each(o.depends_on)) "
                f"AND ds.state <> 'delivered') "
                f"ORDER BY s.next_attempt_at, o.enqueued_at, o.seq LIMIT ?",
                (now, json.dumps(list(sinks)), limit),
            ).fetchall()
            for m in rows:
                message = str(m[0])
                if m[1] == "leased":
                    last = conn.execute(
                        f"SELECT event, attempt FROM {LOG} WHERE message_id = ? "
                        f"ORDER BY seq DESC LIMIT 1",
                        (message,),
                    ).fetchone()
                    if last is not None and last[0] == "sending":
                        fate: str | None = None
                        if m[19] == "dead-letter":
                            fate = (
                                "outcome unknown: the sink may have acted, and this sink's "
                                "unknown outcomes are not redelivered"
                            )
                        elif int(m[2]) - int(m[3]) >= int(m[16]):
                            fate = "attempts exhausted"
                        self._log(
                            conn,
                            message,
                            int(last[1]),
                            "lost",
                            relay_id,
                            state_after="pending" if fate is None else "dead",
                            detail=f"the lease of {m[4] or '?'} ran out mid-call; the sink "
                            f"may have acted",
                        )
                        if fate is not None:
                            self._settle(conn, message, "dead", fate)
                            self._fail_dependants(conn, message, relay_id)
                            continue
                if int(m[14]) < now:
                    self._expire(conn, message, relay_id, int(m[14]))
                    continue
                conn.execute(
                    f"UPDATE {STATE} SET state = 'leased', fence = fence + 1, lease_owner = ?, "
                    f"lease_expires = ?, next_attempt_at = ?, updated_at = ? "
                    f"WHERE message_id = ?",
                    (relay_id, until, until, now, message),
                )
                fence = conn.execute(
                    f"SELECT fence FROM {STATE} WHERE message_id = ?", (message,)
                ).fetchone()[0]
                leases.append(
                    Lease(
                        message_id=uuid.UUID(message),
                        fence=int(fence),
                        attempts=int(m[2]),
                        attempt_floor=int(m[3]),
                        plan_id=str(m[5]),
                        scope_id=str(m[6]),
                        effect_id=str(m[7]),
                        sink=str(m[8]),
                        operation=str(m[9]),
                        tenant_id=None if m[10] is None else str(m[10]),
                        payload_text=str(m[11]),
                        payload_hash=str(m[12]),
                        idempotency_key=str(m[13]),
                        not_after=instant(int(m[14])),
                        idempotency=str(m[15]),
                        max_attempts=int(m[16]),
                        backoff_base=timedelta(milliseconds=int(m[17])),
                        backoff_cap=timedelta(milliseconds=int(m[18])),
                        unknown_outcome=str(m[19]),
                        lease_expires=instant(until),
                        deadline=deadline,
                    )
                )
            self.checkpoint("claim-uncommitted", None)
        return leases

    def _owned(
        self, conn: sqlite3.Connection, lease: Lease, relay_id: str
    ) -> sqlite3.Row | tuple[Any, ...] | None:
        row = conn.execute(
            f"SELECT state, lease_owner, fence, lease_expires, attempts, attempt_floor "
            f"FROM {STATE} WHERE message_id = ?",
            (str(lease.message_id),),
        ).fetchone()
        if row is None or row[0] != "leased" or row[1] != relay_id or int(row[2]) != lease.fence:
            return None
        return row  # type: ignore[no-any-return]

    def sending(self, lease: Lease, relay_id: str, detail: str) -> int | None:
        message = str(lease.message_id)
        with self._writing() as conn:
            owned = self._owned(conn, lease, relay_id)
            now = now_us()
            if owned is None or owned[3] is None or int(owned[3]) <= now:
                return None
            sink = conn.execute(
                f"SELECT o.not_after, k.name, k.enabled FROM {OUTBOX} AS o "
                f"JOIN {SINKS} AS k ON k.name = o.sink WHERE o.message_id = ?",
                (message,),
            ).fetchone()
            if int(sink[0]) < now:
                self._expire(conn, message, relay_id, int(sink[0]))
                return None
            if not sink[2]:
                self._log(
                    conn,
                    message,
                    None,
                    "held",
                    relay_id,
                    state_after="held",
                    detail=f"sink {sink[1]} is disabled",
                )
                self._settle(conn, message, "held", "sink disabled")
                return None
            attempt = int(owned[4]) + 1
            conn.execute(
                f"UPDATE {STATE} SET attempts = ?, updated_at = ? WHERE message_id = ?",
                (attempt, now, message),
            )
            self._log(
                conn, message, attempt, "sending", relay_id, state_after="leased", detail=detail
            )
            self.checkpoint("sending-uncommitted", lease)
        return attempt

    def outcome(
        self, lease: Lease, relay_id: str, attempt: int, result: DeliveryResult, delay: timedelta
    ) -> str | None:
        from interlock.exceptions import InterlockError

        message = str(lease.message_id)
        if result.outcome not in _OUTCOMES:
            raise ValueError(f"{result.outcome!r} is not an outcome")
        for tries in range(3):
            try:
                with self._writing() as conn:
                    state = conn.execute(
                        f"SELECT state, lease_owner, fence, attempts, attempt_floor "
                        f"FROM {STATE} WHERE message_id = ?",
                        (message,),
                    ).fetchone()
                    started = conn.execute(
                        f"SELECT 1 FROM {LOG} WHERE message_id = ? AND attempt = ? "
                        f"AND event = 'sending' AND actor = ?",
                        (message, attempt, relay_id),
                    ).fetchone()
                    if state is None or started is None:
                        raise InterlockError(
                            f"relay {relay_id} started no attempt {attempt} on message {message}"
                        )
                    reported = conn.execute(
                        f"SELECT 1 FROM {LOG} WHERE message_id = ? AND attempt = ? AND event IN "
                        f"('delivered', 'retryable', 'permanent', 'unknown')",
                        (message, attempt),
                    ).fetchone()
                    if reported is not None:
                        return None
                    policy = conn.execute(
                        f"SELECT k.max_attempts, k.unknown_outcome, o.not_after FROM {OUTBOX} AS o "
                        f"JOIN {SINKS} AS k ON k.name = o.sink WHERE o.message_id = ?",
                        (message,),
                    ).fetchone()
                    owned = (
                        state[0] == "leased"
                        and state[1] == relay_id
                        and int(state[2]) == lease.fence
                    )
                    due = now_us() + _us(max(delay, timedelta(0)))
                    next_state: str | None
                    why: str | None = None
                    if result.outcome == "delivered":
                        next_state = None if state[0] == "delivered" else "delivered"
                        if state[0] in ("dead", "cancelled"):
                            why = (
                                f"delivered after the message was {state[0]}; requests that "
                                f"waited for it stay dead until requeued"
                            )
                    elif not owned:
                        next_state = None
                    elif result.outcome == "permanent":
                        next_state, why = "dead", "permanent failure"
                    elif result.outcome == "unknown" and policy[1] == "dead-letter":
                        next_state = "dead"
                        why = (
                            "outcome unknown: the sink may have acted, and this sink's unknown "
                            "outcomes are not redelivered"
                        )
                    elif int(state[3]) - int(state[4]) >= int(policy[0]):
                        next_state, why = "dead", "attempts exhausted"
                    elif due > int(policy[2]):
                        next_state, why = (
                            "dead",
                            "its deadline passes before its next attempt is due",
                        )
                    else:
                        next_state = "pending"
                        why = result.outcome + (
                            "" if result.status_code is None else f" {result.status_code}"
                        )
                    detail = result.detail or None
                    if why is not None and next_state == "delivered":
                        detail = f"{detail}; {why}" if detail else why
                    self._log(
                        conn,
                        message,
                        attempt,
                        result.outcome,
                        relay_id,
                        state_after=next_state,
                        detail=detail,
                        status=result.status_code,
                        digest=result.response_digest,
                        remote_ref=result.remote_ref if result.outcome == "delivered" else None,
                    )
                    if next_state == "pending":
                        self._settle(conn, message, "pending", why, due)
                    elif next_state is not None:
                        self._settle(conn, message, next_state, why or next_state)
                        if next_state == "dead":
                            self._fail_dependants(conn, message, relay_id)
                    self.checkpoint("outcome-uncommitted", lease)
                return next_state
            except SubstrateUnavailableError:
                if tries == 2:
                    raise
                logger.warning(
                    "relay %s: the outbox stayed locked recording message %s, attempt %d; retrying",
                    relay_id,
                    message,
                    attempt,
                )
        return None  # pragma: no cover - the loop returns or raises

    def hold(self, lease: Lease, relay_id: str, reason: str) -> bool:
        with self._writing() as conn:
            if self._owned(conn, lease, relay_id) is None:
                return False
            message = str(lease.message_id)
            self._log(conn, message, None, "held", relay_id, state_after="held", detail=reason)
            self._settle(conn, message, "held", reason)
        return True

    def defer(self, lease: Lease, relay_id: str, reason: str, delay: timedelta) -> bool:
        with self._writing() as conn:
            if self._owned(conn, lease, relay_id) is None:
                return False
            message = str(lease.message_id)
            self._log(
                conn, message, None, "deferred", relay_id, state_after="pending", detail=reason
            )
            self._settle(conn, message, "pending", reason, now_us() + _us(max(delay, timedelta(0))))
        return True

    def refuse(self, lease: Lease, relay_id: str, reason: str) -> bool:
        with self._writing() as conn:
            if self._owned(conn, lease, relay_id) is None:
                return False
            message = str(lease.message_id)
            self._log(conn, message, None, "refused", relay_id, state_after="dead", detail=reason)
            self._settle(conn, message, "dead", f"refused: {reason}")
            self._fail_dependants(conn, message, relay_id)
        return True

    # -- operators ----------------------------------------------------------------

    def _at_head(self, conn: sqlite3.Connection, message: str, expected: str | None) -> bool:
        if expected is None:
            return True
        row = conn.execute(
            f"SELECT log_head FROM {STATE} WHERE message_id = ?", (message,)
        ).fetchone()
        return row is not None and str(row[0]) == expected

    def release(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        authority: str | None = None,
        expected_head: str | None = None,
    ) -> bool:
        """A held message back to pending. ``False`` if it was not held, or
        its log moved past ``expected_head``."""
        message = str(message_id)
        with self._writing() as conn:
            if not self._release(conn, message, actor, authority, expected_head):
                return False
        return True

    def _release(
        self,
        conn: sqlite3.Connection,
        message: str,
        actor: str,
        authority: str | None,
        expected_head: str | None,
    ) -> bool:
        state = conn.execute(
            f"SELECT state FROM {STATE} WHERE message_id = ?", (message,)
        ).fetchone()
        if state is None or state[0] != "held" or not self._at_head(conn, message, expected_head):
            return False
        self._log(
            conn,
            message,
            None,
            "released",
            actor,
            state_after="pending",
            detail="released by an operator",
            authority=authority,
        )
        self._settle(conn, message, "pending", "released")
        return True

    def release_scope(self, scope_id: str, *, actor: str, authority: str | None = None) -> int:
        """Release every held message of a scope, oldest first."""
        released = 0
        with self._writing() as conn:
            held = conn.execute(
                f"SELECT s.message_id FROM {STATE} AS s JOIN {OUTBOX} AS o "
                f"ON o.message_id = s.message_id WHERE o.scope_id = ? AND s.state = 'held' "
                f"ORDER BY o.enqueued_at, o.seq",
                (scope_id,),
            ).fetchall()
            for (message,) in held:
                if self._release(conn, str(message), actor, authority, None):
                    released += 1
        return released

    def cancel(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        reason: str,
        authority: str | None = None,
        expected_head: str | None = None,
    ) -> bool:
        """Cancel a pending, held or dead message; its dependants die."""
        message = str(message_id)
        with self._writing() as conn:
            state = conn.execute(
                f"SELECT state FROM {STATE} WHERE message_id = ?", (message,)
            ).fetchone()
            if (
                state is None
                or state[0] not in ("pending", "held", "dead")
                or not self._at_head(conn, message, expected_head)
            ):
                return False
            why = reason or "cancelled by an operator"
            self._log(
                conn,
                message,
                None,
                "cancelled",
                actor,
                state_after="cancelled",
                detail=why,
                authority=authority,
            )
            self._settle(conn, message, "cancelled", why)
            self._fail_dependants(conn, message, actor)
        return True

    def requeue(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        authority: str | None = None,
        expected_head: str | None = None,
    ) -> int:
        """A dead message back to pending with a fresh budget, and the requests
        that died waiting for it. Not one past its deadline."""
        with self._writing() as conn:
            return self._requeue(conn, str(message_id), actor, authority, expected_head)

    def _requeue(
        self,
        conn: sqlite3.Connection,
        message: str,
        actor: str,
        authority: str | None,
        expected_head: str | None,
    ) -> int:
        row = conn.execute(
            f"SELECT s.state, o.not_after, o.effect_id, o.stage_id FROM {STATE} AS s "
            f"JOIN {OUTBOX} AS o ON o.message_id = s.message_id WHERE s.message_id = ?",
            (message,),
        ).fetchone()
        if (
            row is None
            or row[0] != "dead"
            or int(row[1]) <= now_us()
            or not self._at_head(conn, message, expected_head)
        ):
            return 0
        self._log(
            conn,
            message,
            None,
            "requeued",
            actor,
            state_after="pending",
            detail="requeued by an operator",
            authority=authority,
        )
        conn.execute(
            f"UPDATE {STATE} SET attempt_floor = attempts WHERE message_id = ?", (message,)
        )
        self._settle(conn, message, "pending", "requeued")
        requeued = 1
        effect, stage = str(row[2]), str(row[3])
        for (dependant,) in conn.execute(
            f"SELECT d.message_id FROM {OUTBOX} AS d JOIN {STATE} AS ds "
            f"ON ds.message_id = d.message_id WHERE d.stage_id = ? "
            f"AND ? IN (SELECT value FROM json_each(d.depends_on)) "
            f"AND ds.state = 'dead' AND ds.reason = ? ORDER BY d.seq",
            (stage, effect, f"dependency failed: {effect}"),
        ).fetchall():
            requeued += self._requeue(conn, str(dependant), actor, authority, None)
        return requeued

    # -- reading ---------------------------------------------------------------

    def snapshot(
        self, message_ids: Sequence[uuid.UUID] | None
    ) -> tuple[list[LoggedMessage], list[LogEvent]]:
        ids = None if message_ids is None else json.dumps([str(m) for m in message_ids])
        messages = [
            LoggedMessage(
                message_id=uuid.UUID(str(m[0])),
                stage_id=uuid.UUID(str(m[1])),
                plan_id=str(m[2]),
                scope_id=str(m[3]),
                effect_id=str(m[4]),
                sink=str(m[5]),
                operation=str(m[6]),
                idempotency_key=str(m[7]),
                payload_hash=str(m[8]),
                state=str(m[9]),
                attempts=int(m[10]),
                log_seq=int(m[11]),
                log_head=str(m[12]),
            )
            for m in self._conn.execute(
                f"SELECT o.message_id, o.stage_id, o.plan_id, o.scope_id, o.effect_id, o.sink, "
                f"o.operation, o.idempotency_key, o.payload_hash, s.state, s.attempts, "
                f"s.log_seq, s.log_head FROM {OUTBOX} AS o JOIN {STATE} AS s "
                f"ON s.message_id = o.message_id "
                f"WHERE ?1 IS NULL OR o.message_id IN (SELECT value FROM json_each(?1)) "
                f"ORDER BY o.enqueued_at, o.message_id",
                (ids,),
            ).fetchall()
        ]
        events = [
            LogEvent(
                message_id=uuid.UUID(str(r[0])),
                seq=int(r[1]),
                attempt=None if r[2] is None else int(r[2]),
                event=str(r[3]),
                actor=str(r[4]),
                at=parse_instant(str(r[5])),
                status_code=None if r[6] is None else int(r[6]),
                response_digest=None if r[7] is None else str(r[7]),
                detail=None if r[8] is None else str(r[8]),
                state_after=None if r[9] is None else str(r[9]),
                prev_hash=str(r[12]),
                event_hash=str(r[13]),
                remote_ref=None if r[10] is None else str(r[10]),
                authority=None if r[11] is None else str(r[11]),
            )
            for r in self._conn.execute(
                f"SELECT message_id, seq, attempt, event, actor, at, status_code, "
                f"response_digest, detail, state_after, remote_ref, authority, prev_hash, "
                f"event_hash FROM {LOG} "
                f"WHERE ?1 IS NULL OR message_id IN (SELECT value FROM json_each(?1)) "
                f"ORDER BY message_id, seq",
                (ids,),
            ).fetchall()
        ]
        return messages, events

    def views(
        self, *, state: str | None, scope_id: str | None, limit: int
    ) -> tuple[MessageView, ...]:
        rows = self._conn.execute(
            f"SELECT o.message_id, o.plan_id, o.scope_id, o.effect_id, o.sink, o.operation, "
            f"o.tenant_id, o.cost, s.state, s.attempts, s.reason, s.lease_owner, o.not_after, "
            f"o.enqueued_at, s.next_attempt_at FROM {OUTBOX} AS o JOIN {STATE} AS s "
            f"ON s.message_id = o.message_id "
            f"WHERE (?1 IS NULL OR s.state = ?1) AND (?2 IS NULL OR o.scope_id = ?2) "
            f"ORDER BY o.enqueued_at, o.seq LIMIT ?3",
            (state, scope_id, limit),
        ).fetchall()
        return tuple(
            MessageView(
                message_id=uuid.UUID(str(r[0])),
                plan_id=str(r[1]),
                scope_id=str(r[2]),
                effect_id=str(r[3]),
                sink=str(r[4]),
                operation=str(r[5]),
                tenant_id=None if r[6] is None else str(r[6]),
                cost=Decimal(str(r[7])),
                state=str(r[8]),
                attempts=int(r[9]),
                reason=None if r[10] is None else str(r[10]),
                lease_owner=None if r[11] is None else str(r[11]),
                not_after=instant(int(r[12])),
                enqueued_at=instant(int(r[13])),
                next_attempt_at=instant(int(r[14])),
            )
            for r in rows
        )

    def counts(self) -> dict[str, int]:
        return {
            str(state): int(count)
            for state, count in self._conn.execute(
                f"SELECT state, count(*) FROM {STATE} GROUP BY state ORDER BY state"
            ).fetchall()
        }

    def heads(self, message_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]:
        """Each message's delivery-log head, as an operator sees it."""
        return {
            uuid.UUID(str(m)): str(h)
            for m, h in self._conn.execute(
                f"SELECT message_id, log_head FROM {STATE} "
                f"WHERE message_id IN (SELECT value FROM json_each(?))",
                (json.dumps([str(m) for m in message_ids]),),
            ).fetchall()
        }


def parse_payload(text: str) -> Any:
    """A stored payload, as the relay re-reads it."""
    return loads_strict(text)
