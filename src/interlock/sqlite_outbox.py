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
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from agentgov.receipts.canonical import canonical_bytes, loads_strict

from interlock.compaction import (
    GENESIS,
    CheckpointRow,
    Tombstone,
    WindowRow,
    tombstone_root,
    window_root,
)
from interlock.compaction import Checkpoint as CheckpointBody
from interlock.deliveries import (
    _REGISTRY_COLUMNS,
    AuthorizedRow,
    Compensable,
    LegacySet,
    LogEvent,
    LoggedMessage,
    MessageView,
    Settled,
    _registry_row,
    event_hash,
    genesis_hash,
    parse_instant,
)
from interlock.exceptions import (
    OutboundRequestError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.inbox_sql import (
    SQLITE_CONSUMED,
    SQLITE_EVENTS,
    SQLITE_FACTS,
    SQLITE_INBOX_SCHEMA,
    SQLITE_INBOX_TABLES,
    SQLITE_SOURCES,
    SQLITE_TRACES,
)
from interlock.outbound import bind, placeholders, typed_sink
from interlock.outbox_store import Checkpoint, milliseconds
from interlock.types import InboundFact, OutboundDelta, _frozen

if TYPE_CHECKING:
    from interlock.inbox import DeliveredRef, InboundEvent, InboundSource
    from interlock.keys import Revocation
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
    "trace_stage",
]

logger = logging.getLogger("interlock.sqlite_outbox")

VERSION: Final = 7
"""The outbox version this module installs: 7 records revoked keys and their
seals (``docs/EPIC8_DESIGN.md`` §2); 6 keeps trace context beside the outbox
and the inbox (``docs/EPIC7_DESIGN.md`` §1); 5 compacts under checkpoints
(``docs/EPIC5_DESIGN.md`` §1)."""

SINKS: Final = "_interlock_sinks"
OUTBOX: Final = "_interlock_outbox"
STATE: Final = "_interlock_outbox_state"
LOG: Final = "_interlock_outbox_attempts"
EPOCHS: Final = "_interlock_outbox_epochs"
LEGACY: Final = "_interlock_outbox_legacy"
SETTLEMENTS: Final = "_interlock_outbox_settlements"
CHECKPOINTS: Final = "_interlock_checkpoints"
COMPACTED: Final = "_interlock_outbox_compacted"
TRACES: Final = "_interlock_outbox_traces"
"""Each request's trace context, its plan's (version 6, ``docs/EPIC7_DESIGN.md``
§1.3): in no hash, and gone with the request."""
REVOCATIONS: Final = "_interlock_key_revocations"
SEALS: Final = "_interlock_key_seals"
"""Revoked relay and inbox keys, and the seal of each: every row the key had
attested when it was revoked (version 7, ``docs/EPIC8_DESIGN.md`` §2). Never
changed."""
OUTBOX_TABLES: Final = frozenset(
    {
        SINKS,
        OUTBOX,
        STATE,
        LOG,
        EPOCHS,
        LEGACY,
        SETTLEMENTS,
        CHECKPOINTS,
        COMPACTED,
        TRACES,
        REVOCATIONS,
        SEALS,
    }
    | SQLITE_INBOX_TABLES
)

WINDOWS_TABLE: Final = "_interlock_windows"
"""What each committed plan added to each rate window (:mod:`interlock.windows`),
written beside its commit marker, which it references: a row exists exactly
when its stage committed. ``amount`` is a decimal numeral, ``at`` microseconds
since the epoch. Created by the substrate and by the outbox's install alike,
which guards it (version 5): pruned only under a checkpoint."""
WINDOWS_DDL: Final = (
    f"CREATE TABLE IF NOT EXISTS main.{WINDOWS_TABLE} ("
    f"stage_id TEXT NOT NULL REFERENCES _interlock_commits (stage_id) "
    f"DEFERRABLE INITIALLY DEFERRED, "
    f"window_name TEXT NOT NULL, key TEXT NOT NULL, amount TEXT NOT NULL, "
    f"at INTEGER NOT NULL, PRIMARY KEY (stage_id, window_name, key))",
    f"CREATE INDEX IF NOT EXISTS main.{WINDOWS_TABLE}_by_key "
    f"ON {WINDOWS_TABLE} (window_name, key, at)",
)

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

_STATES: Final = "'pending', 'leased', 'held', 'delivered', 'dead', 'cancelled'"
_HEX: Final = "[0-9a-f]"
_TRACE_CHECK: Final = (
    f"traceparent GLOB '00-{_HEX * 32}-{_HEX * 16}-{_HEX * 2}' "
    f"AND substr(traceparent, 4, 32) <> '{'0' * 32}' "
    f"AND substr(traceparent, 37, 16) <> '{'0' * 16}'"
)
"""A stored ``traceparent`` is one: :data:`interlock.trace.TRACEPARENT_PATTERN`."""
_EVENTS: Final = (
    "'sending', 'delivered', 'retryable', 'permanent', 'unknown', 'lost', 'held', "
    "'deferred', 'expired', 'refused', 'dependency_failed', 'released', 'requeued', "
    "'cancelled', 'compensated'"
)

_ATTESTATION_GLOB: Final = (
    '{"alg":"ed25519","key_id":"' + "[0-9a-f]" * 16 + '","signature":"' + "[0-9a-f]" * 128 + '"}'
)
"""An attestation's shape, ``{alg, key_id, signature}`` as canonical JSON:
the trigger checks it, verification checks the signature."""

_COMPACTING: Final = (
    f"SELECT 1 FROM {COMPACTED} AS t JOIN {CHECKPOINTS} AS c ON c.seq = t.checkpoint "
    f"WHERE t.message_id = OLD.message_id AND c.open = 1"
)
"""Whether the row's message was tombstoned by a checkpoint still open: one the
transaction deleting it wrote, and closes before it commits."""

_SCHEMA_TEMPLATE: Final = (
    "CREATE TABLE IF NOT EXISTS main._interlock_commits "
    "(stage_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, committed_at TEXT NOT NULL)",
    *WINDOWS_DDL,
    # Version 5: checkpoints, and the tombstones of what they pruned.
    f"""CREATE TABLE IF NOT EXISTS main.{CHECKPOINTS} (
        seq             INTEGER PRIMARY KEY CHECK (seq > 0),
        authority       TEXT NOT NULL CHECK (length(authority) = 64
                                             AND authority NOT GLOB '*[^0-9a-f]*'),
        body            TEXT NOT NULL,
        digest          TEXT NOT NULL,
        prev            TEXT NOT NULL,
        windows_horizon INTEGER,
        open            INTEGER NOT NULL DEFAULT 0 CHECK (open IN (0, 1)),
        at              INTEGER NOT NULL
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{COMPACTED} (
        message_id  TEXT PRIMARY KEY,
        checkpoint  INTEGER NOT NULL REFERENCES {CHECKPOINTS} (seq),
        stage_id    TEXT NOT NULL,
        plan_id     TEXT NOT NULL,
        state       TEXT NOT NULL CHECK (state IN ('delivered', 'cancelled')),
        log_seq     INTEGER NOT NULL,
        log_head    TEXT NOT NULL,
        receipt_id  TEXT,
        credit      TEXT,
        cost        TEXT NOT NULL,
        compensates TEXT
    )""",
    f"CREATE INDEX IF NOT EXISTS main.{COMPACTED}_by_checkpoint ON {COMPACTED} (checkpoint)",
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
        attestation     TEXT,
        prev_hash       TEXT NOT NULL,
        event_hash      TEXT NOT NULL,
        PRIMARY KEY (message_id, seq)
    )""",
    # The request the checkers adjudicated, and its delivery log, are never edited.
    f"CREATE TRIGGER IF NOT EXISTS _interlock_outbox_no_update BEFORE UPDATE ON {OUTBOX} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {OUTBOX} is append-only'); END",
    # Version 5 (docs/EPIC5_DESIGN.md §1.5): a message a checkpoint still open
    # tombstoned may be deleted, by the transaction that opened it; nothing else.
    f"CREATE TRIGGER IF NOT EXISTS _interlock_outbox_no_delete BEFORE DELETE ON {OUTBOX} "
    f"WHEN NOT EXISTS ({{compacting}}) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {OUTBOX} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_log_no_update BEFORE UPDATE ON {LOG} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {LOG} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_log_no_delete BEFORE DELETE ON {LOG} "
    f"WHEN NOT EXISTS ({{compacting}}) "
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
                   NEW.remote_ref, NEW.authority, NEW.attestation);
    END""",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_log_head AFTER INSERT ON {LOG}
    BEGIN
        UPDATE {STATE} SET log_seq = NEW.seq, log_head = NEW.event_hash
         WHERE message_id = NEW.message_id;
    END""",
    # An operator's row carries the authority of a signed intent
    # (docs/EPIC3_DESIGN.md §6): the hash of an operator.intent record.
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_log_authority BEFORE INSERT ON {LOG}
    WHEN NEW.event IN ('released', 'cancelled', 'requeued', 'compensated')
     AND (NEW.authority IS NULL OR length(NEW.authority) <> 64
          OR NEW.authority GLOB '*[^0-9a-f]*')
    BEGIN
        SELECT RAISE(ABORT, 'interlock: an operator action needs a signed authority');
    END""",
    # What a sink answered is recorded only as the relay that heard it signed
    # it (docs/EPIC4_DESIGN.md §2): an Ed25519 signature, as canonical JSON.
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_log_attested BEFORE INSERT ON {LOG}
    WHEN NEW.event IN ('delivered', 'retryable', 'permanent', 'unknown')
     AND (NEW.attestation IS NULL OR NEW.attestation NOT GLOB '{_ATTESTATION_GLOB}')
    BEGIN
        SELECT RAISE(ABORT, 'interlock: a relay''s outcome needs the relay''s attestation');
    END""",
    # When this outbox was installed: every operator row after it is signed.
    f"CREATE TABLE IF NOT EXISTS main.{EPOCHS} (version TEXT PRIMARY KEY, at INTEGER NOT NULL)",
    # The legacy set (interlock.deliveries.LegacySet): recorded once, as
    # version 4 is first installed, and never written again.
    f"CREATE TABLE IF NOT EXISTS main.{LEGACY} (message_id TEXT NOT NULL, seq INTEGER NOT NULL, "
    f"event_hash TEXT NOT NULL, PRIMARY KEY (message_id, seq))",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_legacy_no_update BEFORE UPDATE ON {LEGACY} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {LEGACY} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_legacy_no_delete BEFORE DELETE ON {LEGACY} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {LEGACY} is append-only'); END",
    # What settlement did with each delivered request (interlock.settlement):
    # one row per message, never changed.
    f"CREATE TABLE IF NOT EXISTS main.{SETTLEMENTS} ("
    f"message_id TEXT PRIMARY KEY REFERENCES {OUTBOX} (message_id), receipt_id TEXT, "
    f"credit TEXT, note TEXT NOT NULL, settled_at INTEGER NOT NULL)",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_settlements_no_update BEFORE UPDATE "
    f"ON {SETTLEMENTS} BEGIN SELECT RAISE(ABORT, 'interlock: {SETTLEMENTS} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_settlements_no_delete BEFORE DELETE "
    f"ON {SETTLEMENTS} WHEN NOT EXISTS ({{compacting}}) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {SETTLEMENTS} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_legacy_sealed BEFORE INSERT ON {LEGACY} "
    f"WHEN EXISTS (SELECT 1 FROM {EPOCHS} WHERE version = '4') "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: the legacy set was recorded when version 4 was "
    f"installed'); END",
    # Version 5: a state row goes only with its message, compacted; the
    # checkpoints and tombstones never change, but for a checkpoint closing;
    # the rate windows' history is pruned only under an open checkpoint.
    f"CREATE TRIGGER IF NOT EXISTS _interlock_state_no_delete BEFORE DELETE ON {STATE} "
    f"WHEN NOT EXISTS ({{compacting}}) "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: a delivery state goes only with its message'); END",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_checkpoints_no_update BEFORE UPDATE
    ON {CHECKPOINTS}
    WHEN NOT (OLD.open = 1 AND NEW.open = 0 AND NEW.seq IS OLD.seq
              AND NEW.authority IS OLD.authority AND NEW.body IS OLD.body
              AND NEW.digest IS OLD.digest AND NEW.prev IS OLD.prev
              AND NEW.windows_horizon IS OLD.windows_horizon AND NEW.at IS OLD.at)
    BEGIN SELECT RAISE(ABORT, 'interlock: {CHECKPOINTS} is append-only'); END""",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_checkpoints_no_delete BEFORE DELETE "
    f"ON {CHECKPOINTS} BEGIN SELECT RAISE(ABORT, 'interlock: {CHECKPOINTS} is append-only'); "
    f"END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_compacted_no_update BEFORE UPDATE ON {COMPACTED} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {COMPACTED} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_compacted_no_delete BEFORE DELETE ON {COMPACTED} "
    f"BEGIN SELECT RAISE(ABORT, 'interlock: {COMPACTED} is append-only'); END",
    f"CREATE TRIGGER IF NOT EXISTS _interlock_windows_no_update BEFORE UPDATE "
    f"ON {WINDOWS_TABLE} BEGIN SELECT RAISE(ABORT, 'interlock: {WINDOWS_TABLE} is the rate "
    f"windows'' history'); END",
    f"""CREATE TRIGGER IF NOT EXISTS _interlock_windows_no_delete BEFORE DELETE
    ON {WINDOWS_TABLE}
    WHEN NOT EXISTS (SELECT 1 FROM {CHECKPOINTS} AS c
                      WHERE c.open = 1 AND c.windows_horizon IS NOT NULL
                        AND OLD.at <= c.windows_horizon)
    BEGIN SELECT RAISE(ABORT, 'interlock: {WINDOWS_TABLE} is the rate windows'' history'); END""",
    # Version 5: the inbox (docs/EPIC5_DESIGN.md §2).
    *SQLITE_INBOX_SCHEMA,
    # Version 6 (docs/EPIC7_DESIGN.md §1): trace context, beside the rows it
    # describes, in none of their hashes, and deleted with them.
    f"""CREATE TABLE IF NOT EXISTS main.{TRACES} (
        message_id  TEXT PRIMARY KEY REFERENCES {OUTBOX} (message_id) ON DELETE CASCADE,
        traceparent TEXT NOT NULL CHECK ({_TRACE_CHECK})
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{SQLITE_TRACES} (
        source      TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        traceparent TEXT NOT NULL CHECK ({_TRACE_CHECK}),
        PRIMARY KEY (source, seq),
        FOREIGN KEY (source, seq) REFERENCES {SQLITE_EVENTS} (source, seq) ON DELETE CASCADE
    )""",
    # Version 7 (docs/EPIC8_DESIGN.md §2): revoked keys and their seals, written
    # by an operator's revocation alone, and never changed.
    f"""CREATE TABLE IF NOT EXISTS main.{REVOCATIONS} (
        key_id      TEXT PRIMARY KEY
                    CHECK (length(key_id) = 16 AND key_id NOT GLOB '*[^0-9a-f]*'),
        role        TEXT NOT NULL CHECK (role IN ('relay', 'inbox')),
        revoked_at  INTEGER NOT NULL,
        authority   TEXT NOT NULL UNIQUE,
        seal_count  INTEGER NOT NULL CHECK (seal_count >= 0),
        seal_digest TEXT NOT NULL
    )""",
    f"""CREATE TABLE IF NOT EXISTS main.{SEALS} (
        key_id   TEXT NOT NULL,
        kind     TEXT NOT NULL CHECK (kind IN ('outcome', 'event', 'fact')),
        ref      TEXT NOT NULL,
        row_hash TEXT NOT NULL,
        PRIMARY KEY (key_id, kind, ref)
    )""",
    *(
        f"CREATE TRIGGER IF NOT EXISTS _interlock_{name}_no_{op.lower()} BEFORE {op} ON "
        f"{table} BEGIN SELECT RAISE(ABORT, 'interlock: {table} is append-only'); END"
        for name, table in (("revocations", REVOCATIONS), ("seals", SEALS))
        for op in ("UPDATE", "DELETE")
    ),
)
_SCHEMA: Final = tuple(
    statement.replace("{compacting}", _COMPACTING) for statement in _SCHEMA_TEMPLATE
)

LOG_TRIGGERS: Final = (
    "_interlock_outbox_no_update",
    "_interlock_outbox_no_delete",
    "_interlock_log_no_update",
    "_interlock_log_no_delete",
    "_interlock_log_link",
    "_interlock_log_head",
    "_interlock_log_authority",
    "_interlock_log_attested",
)
_REDEFINED: Final = (
    "_interlock_log_link",
    "_interlock_log_attested",
    "_interlock_outbox_no_delete",
    "_interlock_log_no_delete",
    "_interlock_settlements_no_delete",
)
"""Triggers whose definition a later version changed: dropped and created
again at every install, so an upgraded file runs the current ones."""


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


# --------------------------------------------------------------------------
# Revoked keys (version 7, docs/EPIC8_DESIGN.md §2): what a write checks, what
# a revocation seals, what verification reads. The file's write lock orders a
# revocation against every attested write.
# --------------------------------------------------------------------------


def _has_revocations(conn: sqlite3.Connection) -> bool:
    found = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (REVOCATIONS,)
    ).fetchone()
    return found is not None


def refuse_revoked(conn: sqlite3.Connection, attestation: str | None) -> None:
    """Refuse a row attested by a revoked key, inside the transaction that
    would write it.

    :raises KeyRevokedError: If the attestation names a revoked key.
    """
    from interlock.exceptions import KeyRevokedError
    from interlock.keys import attestation_key

    key_id = attestation_key(attestation)
    if key_id is None or not _has_revocations(conn):
        return
    if conn.execute(f"SELECT 1 FROM {REVOCATIONS} WHERE key_id = ?", (key_id,)).fetchone():
        raise KeyRevokedError(f"key {key_id} was revoked: it attests nothing new")


def sealed_rows(conn: sqlite3.Connection, role: str, key_id: str) -> set[tuple[str, str, str]]:
    """Every row ``key_id`` attested that the file holds: what its revocation
    seals, ``(kind, reference, row hash)``."""
    from interlock.keys import attestation_key, event_ref, fact_ref, fact_row_hash, outcome_ref

    members: set[tuple[str, str, str]] = set()
    if role == "relay":
        for message, seq, row_hash, attestation in conn.execute(
            f"SELECT message_id, seq, event_hash, attestation FROM {LOG} "
            f"WHERE attestation IS NOT NULL"
        ):
            if attestation_key(attestation) == key_id:
                members.add(("outcome", outcome_ref(message, int(seq)), str(row_hash)))
        return members
    for source, seq, row_hash, attestation in conn.execute(
        f"SELECT source, seq, event_hash, attestation FROM {SQLITE_EVENTS}"
    ):
        if attestation_key(attestation) == key_id:
            members.add(("event", event_ref(str(source), int(seq)), str(row_hash)))
    for source, seq, attestation in conn.execute(
        f"SELECT source, event_seq, attestation FROM {SQLITE_FACTS}"
    ):
        if attestation_key(attestation) == key_id:
            members.add(("fact", fact_ref(str(source), int(seq)), fact_row_hash(str(attestation))))
    return members


def read_revocations(conn: sqlite3.Connection) -> dict[str, Revocation]:
    """Every revoked key, with its seal, as the file holds them."""
    from interlock.keys import Revocation

    if not _has_revocations(conn):
        return {}
    # The revocations first: one committed after this read brings its seal
    # into the next, never a revocation without its seal.
    revoked = conn.execute(
        f"SELECT key_id, role, revoked_at, authority, seal_count, seal_digest FROM {REVOCATIONS}"
    ).fetchall()
    members: dict[str, set[tuple[str, str, str]]] = {}
    for key_id, kind, ref, row_hash in conn.execute(
        f"SELECT key_id, kind, ref, row_hash FROM {SEALS}"
    ):
        members.setdefault(str(key_id), set()).add((str(kind), str(ref), str(row_hash)))
    return {
        str(r[0]): Revocation(
            key_id=str(r[0]),
            role=str(r[1]),
            revoked_at=instant(int(r[2])),
            authority=str(r[3]),
            count=int(r[4]),
            digest=str(r[5]),
            members=frozenset(members.get(str(r[0]), ())),
        )
        for r in revoked
    }


def _us(span: timedelta) -> int:
    return int(span / timedelta(microseconds=1))


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------


def register(conn: sqlite3.Connection) -> None:
    """Register what the delivery log's and the inbox log's triggers need on
    ``conn``."""
    from interlock.inbox_store import register as register_inbox

    conn.create_function("interlock_event_hash", 14, _event_hash_sql, deterministic=True)
    register_inbox(conn)


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
    attestation: str | None,
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
        attestation,
    )


def installed_version(conn: sqlite3.Connection) -> int:
    """Which version installed the outbox in this file: 7 when it records
    revoked keys and their seals, 6 when it keeps trace context, 5 when
    vacuums compact it under checkpoints, 4 when its delivery log records
    relays' attestations, 3 before; 0 when there is none."""
    if not outbox_installed(conn):
        return 0
    columns = {str(r[1]) for r in conn.execute(f"PRAGMA table_info({LOG})").fetchall()}
    if "attestation" not in columns:
        return 3
    tables = {
        str(r[0])
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?, ?)",
            (CHECKPOINTS, TRACES, REVOCATIONS),
        ).fetchall()
    }
    if CHECKPOINTS not in tables:
        return 4
    if TRACES not in tables:
        return 5
    return 7 if REVOCATIONS in tables else 6


def outbox_installed(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN (?, ?, ?, ?)",
        (SINKS, OUTBOX, STATE, LOG),
    ).fetchone()
    return bool(row and row[0] == 4)


def install_sqlite_outbox(
    path: str | Path, sinks: Iterable[SinkSpec] = (), sources: Iterable[InboundSource] = ()
) -> LegacySet:
    """Install the outbox in a SQLite file, and mirror the sink registry. Idempotent.

    Switches the file to WAL first, so a relay's and an operator's reads never
    wait on a stage: the setting is persistent, and every process that opens
    the file must then be on this host. A sink installed before and not listed
    now is disabled, not deleted: requests in the outbox name it.

    The install that first brings version 4 records the legacy set
    (:class:`~interlock.deliveries.LegacySet`); no later one adds to it.

    :returns: The legacy set, as this install's transaction read it: what a
        signed install vouches for.
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
            if installed_version(conn) == 3:
                # Version 4 over 3, in place: the column, and the triggers
                # that changed. Every row written before keeps its hash.
                conn.execute(f"ALTER TABLE {LOG} ADD COLUMN attestation TEXT")
            for trigger in _REDEFINED:
                conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            for statement in _SCHEMA:
                conn.execute(statement)
            if conn.execute(f"SELECT 1 FROM {EPOCHS} WHERE version = '4'").fetchone() is None:
                # Version 4 is being installed: the rows written before the
                # proof their kind now carries are the legacy set, recorded
                # here once, under the write lock this transaction holds.
                conn.execute(
                    f"INSERT INTO {LEGACY} (message_id, seq, event_hash) "
                    f"SELECT message_id, seq, event_hash FROM {LOG} "
                    f"WHERE (event IN ('delivered', 'retryable', 'permanent', 'unknown') "
                    f"       AND attestation IS NULL) "
                    f"   OR (event IN ('released', 'cancelled', 'requeued', 'compensated') "
                    f"       AND authority IS NULL)"
                )
            for version in ("3", "4"):
                conn.execute(
                    f"INSERT OR IGNORE INTO {EPOCHS} (version, at) VALUES (?, ?)",
                    (version, now_us()),
                )
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
            _install_sources(conn, list(sources))
            legacy = _legacy(conn)
            assert legacy is not None
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return legacy


def _install_sources(conn: sqlite3.Connection, sources: Sequence[InboundSource]) -> None:
    """Mirror the inbound sources: what the inbox records events of. A source
    installed before and not listed now is disabled, not deleted: its log stays."""
    from interlock.inbox import inbox_genesis

    for source in sources:
        conn.execute(
            f"INSERT INTO {SQLITE_SOURCES} (name, kind, config_hash, enabled, log_seq, log_head) "
            f"VALUES (?, ?, ?, 1, 0, ?) ON CONFLICT (name) DO UPDATE SET kind = excluded.kind, "
            f"config_hash = excluded.config_hash, enabled = 1",
            (source.name, source.kind, source.config_hash(), inbox_genesis(source.name)),
        )
    conn.execute(
        f"UPDATE {SQLITE_SOURCES} SET enabled = 0 "
        f"WHERE name NOT IN (SELECT value FROM json_each(?))",
        (json.dumps([s.name for s in sources]),),
    )


def _legacy(conn: sqlite3.Connection) -> LegacySet | None:
    if (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (LEGACY,)
        ).fetchone()
        is None
    ):
        return None
    return LegacySet(
        {
            (uuid.UUID(str(r[0])), int(r[1])): str(r[2])
            for r in conn.execute(f"SELECT message_id, seq, event_hash FROM {LEGACY}")
        }
    )


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


def trace_stage(conn: sqlite3.Connection, stage_id: uuid.UUID, traceparent: str) -> None:
    """Give every request the stage enqueued its plan's trace context, in the
    stage's transaction (``docs/EPIC7_DESIGN.md`` §1.3)."""
    conn.execute(
        f"INSERT INTO {TRACES} (message_id, traceparent) "
        f"SELECT message_id, ? FROM {OUTBOX} WHERE stage_id = ?",
        (traceparent, str(stage_id)),
    )


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
OPERATOR: Final = frozenset({OUTBOX, STATE, LOG, TRACES, REVOCATIONS, SEALS})
"""What an operator's connection may write: compensations are new requests,
in the trace of the request they compensate; and revocations, with their seals."""
SETTLER: Final = frozenset({SETTLEMENTS})
"""What settlement's connection may write: its record, and nothing else."""
INBOX: Final = frozenset({SQLITE_SOURCES, SQLITE_EVENTS, SQLITE_FACTS, SQLITE_TRACES})
"""What the inbox process's connection may write: its log and its facts."""
COMPACTOR: Final = frozenset(
    {
        OUTBOX,
        STATE,
        LOG,
        SETTLEMENTS,
        CHECKPOINTS,
        COMPACTED,
        WINDOWS_TABLE,
        SQLITE_EVENTS,
        SQLITE_FACTS,
        SQLITE_CONSUMED,
        TRACES,
        SQLITE_TRACES,
    }
)
"""What a vacuum's connection may write: checkpoints and tombstones, and the
rows it prunes under them, the inbox's prefixes included (an operator's,
whose other actions it takes too), and with them their trace context."""

_OUTCOMES: Final = ("delivered", "retryable", "permanent", "unknown")


def _no_checkpoint(point: str, lease: Lease | None) -> None:
    return None


class SqliteOutboxStore:
    """The outbox in a SQLite file: the state machine of the ``relay_*``
    functions, transition for transition, in Python, under ``BEGIN IMMEDIATE``.

    :param path: The database file, with the outbox installed.
    :param writes: What this connection may write: :data:`RELAY` for a relay,
        :data:`OPERATOR` for an operator's actions, :data:`SETTLER` for
        settlement.
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
            version = installed_version(conn)
            if version == 0:
                raise SubstrateConfigurationError(
                    f"no outbox in {path}: run `interlock install` with [[sinks]] configured"
                )
            if version < VERSION:
                raise SubstrateConfigurationError(
                    f"the outbox in {path} was installed by version {version}: run "
                    f"`interlock install` to upgrade it in place to version {VERSION}"
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

    # -- keys (version 7, docs/EPIC8_DESIGN.md §2) ---------------------------------

    def revoked(self, key_id: str) -> bool:
        """Whether ``key_id`` was revoked: a relay asks before it claims, so
        one indexed read, and no seal."""
        if not _has_revocations(self._conn):
            return False
        found = self._conn.execute(
            f"SELECT 1 FROM {REVOCATIONS} WHERE key_id = ?", (key_id,)
        ).fetchone()
        return found is not None

    def revocations(self) -> dict[str, Revocation]:
        """Every revoked key, with its seal."""
        return read_revocations(self._conn)

    def revoke_key(self, role: str, key_id: str, *, authority: str) -> tuple[int, str]:
        """An operator's revocation, under ``authority``, the hash of the signed
        intent: the seal of every row the key attested, and the revocation, in
        one write transaction, which every attested write waits on.

        :returns: The seal's count and digest.
        :raises KeyRevokedError: If the key is revoked already.
        """
        from interlock.exceptions import KeyRevokedError
        from interlock.keys import SEALED_ROLES, seal_digest

        if role not in SEALED_ROLES:
            raise ValueError(f"the database seals a relay's or an inbox's key, not a {role}'s")
        with self._writing() as conn:
            if conn.execute(f"SELECT 1 FROM {REVOCATIONS} WHERE key_id = ?", (key_id,)).fetchone():
                raise KeyRevokedError(f"key {key_id} is revoked already")
            members = sealed_rows(conn, role, key_id)
            digest = seal_digest(members)
            conn.execute(
                f"INSERT INTO {REVOCATIONS} "
                f"(key_id, role, revoked_at, authority, seal_count, seal_digest) "
                f"VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, role, now_us(), authority, len(members), digest),
            )
            conn.executemany(
                f"INSERT INTO {SEALS} (key_id, kind, ref, row_hash) VALUES (?, ?, ?, ?)",
                [(key_id, *member) for member in sorted(members)],
            )
        return len(members), digest

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
        attestation: str | None = None,
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
            attestation,
        )
        conn.execute(
            f"INSERT INTO {LOG} (message_id, seq, attempt, event, actor, at, status_code, "
            f"response_digest, detail, state_after, remote_ref, authority, attestation, "
            f"prev_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                attestation,
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
                f"k.max_attempts, k.backoff_base_ms, k.backoff_cap_ms, k.unknown_outcome, "
                f"t.traceparent "
                f"FROM {STATE} AS s JOIN {OUTBOX} AS o ON o.message_id = s.message_id "
                f"JOIN {SINKS} AS k ON k.name = o.sink "
                f"LEFT JOIN {TRACES} AS t ON t.message_id = o.message_id "
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
                        traceparent=None if m[20] is None else str(m[20]),
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
        self,
        lease: Lease,
        relay_id: str,
        attempt: int,
        result: DeliveryResult,
        delay: timedelta,
        attestation: str,
    ) -> str | None:
        from interlock.exceptions import InterlockError

        message = str(lease.message_id)
        if result.outcome not in _OUTCOMES:
            raise ValueError(f"{result.outcome!r} is not an outcome")
        for tries in range(3):
            try:
                with self._writing() as conn:
                    refuse_revoked(conn, attestation)
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
                        attestation=attestation,
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
    #
    # Each writes its rows under the authority of the operator's signed intent
    # (the trigger refuses an operator row without one), and only while the
    # message's log is at the head the operator saw when they signed.

    def _at(
        self, conn: sqlite3.Connection, message: str, expected_head: str, states: Sequence[str]
    ) -> bool:
        row = conn.execute(
            f"SELECT state, log_head FROM {STATE} WHERE message_id = ?", (message,)
        ).fetchone()
        return row is not None and row[0] in states and str(row[1]) == expected_head

    def release(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> bool:
        """A held message back to pending. ``False`` if it was not held, or
        its log moved past ``expected_head``."""
        message = str(message_id)
        with self._writing() as conn:
            if not self._at(conn, message, expected_head, ("held",)):
                return False
            self._log(
                conn,
                message,
                None,
                "released",
                _operator(actor),
                state_after="pending",
                detail="released by an operator",
                authority=authority,
            )
            self._settle(conn, message, "pending", "released")
        return True

    def cancel(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        reason: str,
        authority: str,
        expected_head: str,
    ) -> bool:
        """Cancel a pending, held or dead message; its dependants die."""
        message = str(message_id)
        with self._writing() as conn:
            if not self._at(conn, message, expected_head, ("pending", "held", "dead")):
                return False
            why = reason or "cancelled by an operator"
            self._log(
                conn,
                message,
                None,
                "cancelled",
                _operator(actor),
                state_after="cancelled",
                detail=why,
                authority=authority,
            )
            self._settle(conn, message, "cancelled", why)
            self._fail_dependants(conn, message, _operator(actor))
        return True

    def requeue(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> int:
        """A dead message back to pending with a fresh budget, and the requests
        that died waiting for it, under one authority. Not one past its
        deadline."""
        message = str(message_id)
        with self._writing() as conn:
            if not self._at(conn, message, expected_head, ("dead",)):
                return 0
            return self._requeue(conn, message, _operator(actor), authority)

    def _requeue(self, conn: sqlite3.Connection, message: str, actor: str, authority: str) -> int:
        row = conn.execute(
            f"SELECT s.state, o.not_after, o.effect_id, o.stage_id FROM {STATE} AS s "
            f"JOIN {OUTBOX} AS o ON o.message_id = s.message_id WHERE s.message_id = ?",
            (message,),
        ).fetchone()
        if row is None or row[0] != "dead" or int(row[1]) <= now_us():
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
            requeued += self._requeue(conn, str(dependant), actor, authority)
        return requeued

    def compensate(
        self,
        original: uuid.UUID,
        *,
        actor: str,
        authority: str,
        expected_head: str,
        message_id: uuid.UUID,
        payload: bytes,
        idempotency_key: str,
    ) -> bool:
        """Enqueue the compensation ``original`` carried, as PostgreSQL's
        ``outbox_compensate`` does: ``payload`` must be that compensation,
        its placeholder bound to what the original's delivery created.

        :raises OutboundRequestError: If it is not, its sink refuses it, or
            the original was compensated already.
        """
        message = str(original)
        with self._writing() as conn:
            if not self._at(conn, message, expected_head, ("delivered",)):
                return False
            o = conn.execute(
                f"SELECT stage_id, plan_id, scope_id, effect_id, tenant_id, compensation "
                f"FROM {OUTBOX} WHERE message_id = ?",
                (message,),
            ).fetchone()
            if o[5] is None:
                return False
            document = loads_strict(str(o[5]))
            ref = conn.execute(
                f"SELECT remote_ref FROM {LOG} WHERE message_id = ? AND event = 'delivered' "
                f"ORDER BY seq DESC LIMIT 1",
                (message,),
            ).fetchone()
            remote_ref = None if ref is None or ref[0] is None else str(ref[0])
            if remote_ref is None and placeholders(document["payload"]):
                return False
            sink_name, operation = str(document["sink"]), str(document["operation"])
            if loads_strict(payload) != bind(document["payload"], remote_ref or ""):
                raise OutboundRequestError(
                    f"the payload is not the compensation message {original} carried, bound to "
                    f"what its delivery created",
                    reason="compensation",
                    sink=sink_name,
                )
            sink = conn.execute(
                f"SELECT operations, max_payload_bytes, not_after_seconds, cost_per_call "
                f"FROM {SINKS} WHERE name = ? AND enabled = 1",
                (sink_name,),
            ).fetchone()
            if sink is None or operation not in json.loads(sink[0]):
                raise OutboundRequestError(
                    f"sink {sink_name!r} is not installed with operation {operation!r}",
                    reason="unregistered_operation" if sink is not None else "unregistered_sink",
                    sink=sink_name,
                )
            if len(payload) > int(sink[1]):
                raise OutboundRequestError(
                    "the compensation exceeds its sink's bound",
                    reason="payload_size",
                    sink=sink_name,
                )
            effect = f"compensate:{o[3]}"
            waits = [
                str(r[0])
                for r in conn.execute(
                    f"SELECT c.effect_id FROM {OUTBOX} AS d JOIN {OUTBOX} AS c "
                    f"ON c.compensates = d.message_id WHERE d.stage_id = ? "
                    f"AND ? IN (SELECT value FROM json_each(d.depends_on)) ORDER BY c.effect_id",
                    (str(o[0]), str(o[3])),
                ).fetchall()
            ]
            seq = conn.execute(
                f"SELECT coalesce(max(seq), 0) + 1 FROM {OUTBOX} WHERE stage_id = ?", (str(o[0]),)
            ).fetchone()[0]
            enqueued = now_us()
            window = document.get("not_after_seconds") or int(sink[2])
            payload_hash = hashlib.sha256(payload).hexdigest()
            try:
                conn.execute(
                    f"INSERT INTO {OUTBOX} (message_id, stage_id, plan_id, scope_id, effect_id, "
                    f"seq, depends_on, sink, operation, tenant_id, payload, payload_hash, "
                    f"idempotency_key, cost, compensation, compensates, not_after, enqueued_at) "
                    f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                    (
                        str(message_id),
                        str(o[0]),
                        str(o[1]),
                        str(o[2]),
                        effect,
                        int(seq),
                        json.dumps(waits),
                        sink_name,
                        operation,
                        o[4],
                        payload.decode("utf-8"),
                        payload_hash,
                        idempotency_key,
                        str(sink[3]),
                        message,
                        enqueued + int(window) * 1_000_000,
                        enqueued,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise OutboundRequestError(
                    f"message {original} was compensated already: a compensation is enqueued once",
                    reason="duplicate",
                    sink=sink_name,
                ) from exc
            conn.execute(
                f"INSERT INTO {STATE} (message_id, log_head, next_attempt_at, updated_at) "
                f"VALUES (?, ?, ?, ?)",
                (
                    str(message_id),
                    genesis_hash(
                        message_id,
                        uuid.UUID(str(o[0])),
                        str(o[1]),
                        str(o[2]),
                        effect,
                        sink_name,
                        operation,
                        idempotency_key,
                        payload_hash,
                    ),
                    enqueued,
                    enqueued,
                ),
            )
            # The undo of the same work: in the trace of what it undoes.
            conn.execute(
                f"INSERT INTO {TRACES} (message_id, traceparent) "
                f"SELECT ?, traceparent FROM {TRACES} WHERE message_id = ?",
                (str(message_id), message),
            )
            self._log(
                conn,
                message,
                None,
                "compensated",
                _operator(actor),
                state_after=None,
                detail=f"compensated by {message_id}",
                authority=authority,
            )
        return True

    # -- reading ---------------------------------------------------------------

    @contextmanager
    def consistent(self) -> Iterator[None]:
        """Every read inside sees one state of the database: a read
        transaction, or the one already open (:func:`interlock.deliveries.consistent`)."""
        conn = self._conn
        if conn.in_transaction:
            yield
            return
        conn.execute("BEGIN")
        try:
            yield
        finally:
            if conn.in_transaction:
                conn.execute("COMMIT")  # it read; there is nothing to keep or undo

    def snapshot(
        self, message_ids: Sequence[uuid.UUID] | None
    ) -> tuple[list[LoggedMessage], list[LogEvent]]:
        with self.consistent():
            return self._snapshot(message_ids)

    def _snapshot(
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
                cost=Decimal(str(m[13])),
                compensates=None if m[14] is None else uuid.UUID(str(m[14])),
            )
            for m in self._conn.execute(
                f"SELECT o.message_id, o.stage_id, o.plan_id, o.scope_id, o.effect_id, o.sink, "
                f"o.operation, o.idempotency_key, o.payload_hash, s.state, s.attempts, "
                f"s.log_seq, s.log_head, o.cost, o.compensates FROM {OUTBOX} AS o "
                f"JOIN {STATE} AS s "
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
                attestation=None if r[14] is None else str(r[14]),
            )
            for r in self._conn.execute(
                f"SELECT message_id, seq, attempt, event, actor, at, status_code, "
                f"response_digest, detail, state_after, remote_ref, authority, prev_hash, "
                f"event_hash, attestation FROM {LOG} "
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

    def registry(self) -> list[dict[str, Any]]:
        return [
            _registry_row(r)
            for r in self._conn.execute(
                f"SELECT {', '.join(_REGISTRY_COLUMNS)} FROM {SINKS} ORDER BY name"
            ).fetchall()
        ]

    def epoch(self, version: str = "3") -> datetime | None:
        row = self._conn.execute(
            f"SELECT at FROM {EPOCHS} WHERE version = ?", (version,)
        ).fetchone()
        return None if row is None else instant(int(row[0]))

    def legacy(self) -> LegacySet | None:
        return _legacy(self._conn)

    def settlements(self) -> dict[uuid.UUID, Settled]:
        return {
            uuid.UUID(str(r[0])): Settled(
                uuid.UUID(str(r[0])),
                None if r[1] is None else str(r[1]),
                None if r[2] is None else str(r[2]),
                str(r[3]),
                instant(int(r[4])),
            )
            for r in self._conn.execute(
                f"SELECT message_id, receipt_id, credit, note, settled_at FROM {SETTLEMENTS}"
            )
        }

    def settle(
        self, message_id: uuid.UUID, *, receipt_id: str | None, credit: str | None, note: str
    ) -> bool:
        """Record a delivered request's settlement, once, as
        ``interlock.outbox_settle`` does. ``False`` when it was settled already.

        :raises InterlockError: If the message is not delivered.
        """
        from interlock.exceptions import InterlockError

        with self._writing() as conn:
            row = conn.execute(
                f"SELECT state FROM {STATE} WHERE message_id = ?", (str(message_id),)
            ).fetchone()
            if row is None or row[0] != "delivered":
                raise InterlockError(
                    f"message {message_id} is {row[0] if row else 'not in the outbox'}: only "
                    f"a delivered request is settled"
                )
            cursor = conn.execute(
                f"INSERT OR IGNORE INTO {SETTLEMENTS} "
                f"(message_id, receipt_id, credit, note, settled_at) VALUES (?, ?, ?, ?, ?)",
                (str(message_id), receipt_id, credit, note, now_us()),
            )
            return cursor.rowcount == 1

    def authorized(self, authority: str) -> list[AuthorizedRow]:
        return [
            AuthorizedRow(uuid.UUID(str(r[0])), int(r[1]), str(r[2]), str(r[3]))
            for r in self._conn.execute(
                f"SELECT message_id, seq, event, event_hash FROM {LOG} WHERE authority = ? "
                f"ORDER BY message_id, seq",
                (authority,),
            ).fetchall()
        ]

    def held(self, scope_id: str) -> list[uuid.UUID]:
        return [
            uuid.UUID(str(r[0]))
            for r in self._conn.execute(
                f"SELECT s.message_id FROM {STATE} AS s JOIN {OUTBOX} AS o "
                f"ON o.message_id = s.message_id WHERE o.scope_id = ? AND s.state = 'held' "
                f"ORDER BY o.enqueued_at, o.seq",
                (scope_id,),
            ).fetchall()
        ]

    def plan_of(self, message_id: uuid.UUID) -> str | None:
        row = self._conn.execute(
            f"SELECT plan_id FROM {OUTBOX} WHERE message_id = ?", (str(message_id),)
        ).fetchone()
        return None if row is None else str(row[0])

    def compensables(self, plan_id: str) -> list[Compensable]:
        return [
            Compensable(
                message_id=uuid.UUID(str(r[0])),
                plan_id=str(r[1]),
                stage_id=uuid.UUID(str(r[2])),
                effect_id=str(r[3]),
                depends_on=tuple(json.loads(r[4])),
                state=str(r[5]),
                not_after=instant(int(r[6])),
                log_head=str(r[7]),
                compensation=None if r[8] is None else loads_strict(str(r[8])),
                remote_ref=None if r[9] is None else str(r[9]),
                compensated_by=None if r[10] is None else uuid.UUID(str(r[10])),
                compensates=None if r[11] is None else uuid.UUID(str(r[11])),
            )
            for r in self._conn.execute(
                f"SELECT o.message_id, o.plan_id, o.stage_id, o.effect_id, o.depends_on, "
                f"s.state, o.not_after, s.log_head, o.compensation, "
                f"(SELECT a.remote_ref FROM {LOG} AS a WHERE a.message_id = o.message_id "
                f" AND a.event = 'delivered' ORDER BY a.seq DESC LIMIT 1), "
                f"(SELECT c.message_id FROM {OUTBOX} AS c WHERE c.compensates = o.message_id), "
                f"o.compensates FROM {OUTBOX} AS o JOIN {STATE} AS s "
                f"ON s.message_id = o.message_id WHERE o.plan_id = ? ORDER BY o.seq",
                (plan_id,),
            ).fetchall()
        ]

    # -- compaction (docs/EPIC5_DESIGN.md §1) -----------------------------------

    def checkpoints(self) -> list[CheckpointRow]:
        """Every checkpoint, in order."""
        return [
            CheckpointRow(
                seq=int(r[0]),
                authority=str(r[1]),
                body=str(r[2]),
                digest=str(r[3]),
                prev=str(r[4]),
                windows_horizon=None if r[5] is None else instant(int(r[5])),
                open=bool(r[6]),
            )
            for r in self._conn.execute(
                f"SELECT seq, authority, body, digest, prev, windows_horizon, open "
                f"FROM {CHECKPOINTS} ORDER BY seq"
            ).fetchall()
        ]

    def compacted(self) -> dict[uuid.UUID, Tombstone]:
        """Every message a checkpoint pruned, by id."""
        tombstones = (_tombstone(r) for r in self._conn.execute(_TOMBSTONES.format(where="1")))
        return {t.message_id: t for t in tombstones}

    def window_rows(self, horizon: datetime) -> list[WindowRow]:
        """The rate windows' history at or before ``horizon``: what a vacuum
        with that window horizon prunes."""
        return _window_rows(self._conn, _microseconds(horizon))

    def database_now(self) -> datetime:
        """The clock the outbox's instants are on: this host's."""
        return instant(now_us())

    def compact(
        self,
        authority: str,
        body: str,
        heads: Sequence[Mapping[str, Any]],
        *,
        before_commit: Callable[[], None] | None = None,
    ) -> dict[str, int]:
        """A vacuum's act, as ``interlock.outbox_compact`` does it: record the
        checkpoint ``body`` under ``authority``, tombstone the messages at the
        ``heads`` that were verified, recompute what the checkpoint commits to
        from what the file holds, and delete. All of it, or nothing.

        :param before_commit: Called inside the transaction, everything done
            but its commit: the crash tests stop the process there.
        :raises CompactionRefusedError: If a message moved, the checkpoint does
            not follow the last one, or the file holds other than what the
            checkpoint commits to. Nothing is pruned.
        """
        from interlock.exceptions import CompactionRefusedError

        checkpoint = CheckpointBody.parse(body)
        targets = json.dumps([str(h["message"]) for h in heads])
        with self._writing() as conn:
            last = conn.execute(
                f"SELECT seq, digest FROM {CHECKPOINTS} ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous = GENESIS if last is None else str(last[1])
            if checkpoint.seq != (0 if last is None else int(last[0])) + 1 or (
                checkpoint.prev != previous
            ):
                raise CompactionRefusedError(
                    f"checkpoint {checkpoint.seq} does not follow checkpoint "
                    f"{0 if last is None else last[0]}"
                )
            horizon = (
                None
                if checkpoint.windows_horizon is None
                else _microseconds(parse_instant(checkpoint.windows_horizon))
            )
            conn.execute(
                f"INSERT INTO {CHECKPOINTS} "
                f"(seq, authority, body, digest, prev, windows_horizon, open, at) "
                f"VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (
                    checkpoint.seq,
                    authority,
                    body,
                    hashlib.sha256(body.encode("utf-8")).hexdigest(),
                    previous,
                    horizon,
                    now_us(),
                ),
            )
            for head in heads:
                row = conn.execute(
                    f"SELECT state, log_seq, log_head, lease_owner FROM {STATE} "
                    f"WHERE message_id = ?",
                    (str(head["message"]),),
                ).fetchone()
                if row is None or int(row[1]) != int(head["seq"]) or row[2] != head["head"]:
                    raise CompactionRefusedError(
                        f"message {head['message']} moved after it was verified"
                    )
                settled = conn.execute(
                    f"SELECT 1 FROM {SETTLEMENTS} WHERE message_id = ?", (str(head["message"]),)
                ).fetchone()
                if (
                    row[0] not in ("delivered", "cancelled")
                    or row[3] is not None
                    or (row[0] == "delivered" and settled is None)
                ):
                    raise CompactionRefusedError(
                        f"message {head['message']} is not final and settled"
                    )
            if conn.execute(
                f"SELECT 1 FROM {LEGACY} WHERE message_id IN (SELECT value FROM json_each(?))",
                (targets,),
            ).fetchone():
                raise CompactionRefusedError("the legacy set's messages are kept")
            if conn.execute(
                f"SELECT 1 FROM {OUTBOX} AS o WHERE o.stage_id IN ("
                f"  SELECT t.stage_id FROM {OUTBOX} AS t "
                f"   WHERE t.message_id IN (SELECT value FROM json_each(?1))) "
                f"AND o.message_id NOT IN (SELECT value FROM json_each(?1))",
                (targets,),
            ).fetchone():
                raise CompactionRefusedError("a stage is compacted whole or not at all")
            conn.execute(
                f"INSERT INTO {COMPACTED} (message_id, checkpoint, stage_id, plan_id, state, "
                f"log_seq, log_head, receipt_id, credit, cost, compensates) "
                f"SELECT o.message_id, ?, o.stage_id, o.plan_id, s.state, s.log_seq, s.log_head, "
                f"x.receipt_id, x.credit, o.cost, o.compensates FROM {OUTBOX} AS o "
                f"JOIN {STATE} AS s ON s.message_id = o.message_id "
                f"LEFT JOIN {SETTLEMENTS} AS x ON x.message_id = o.message_id "
                f"WHERE o.message_id IN (SELECT value FROM json_each(?))",
                (checkpoint.seq, targets),
            )
            # What the checkpoint commits to, recomputed from what the file
            # holds, and held to what was signed.
            tombstones = [
                _tombstone(r)
                for r in conn.execute(
                    _TOMBSTONES.format(where="checkpoint = ?"), (checkpoint.seq,)
                ).fetchall()
            ]
            (log_rows,) = conn.execute(
                f"SELECT count(*) FROM {LOG} WHERE message_id IN (SELECT value FROM json_each(?))",
                (targets,),
            ).fetchone()
            if (tombstone_root(tombstones), len(tombstones), int(log_rows)) != (
                checkpoint.root,
                checkpoint.messages,
                checkpoint.rows,
            ):
                raise CompactionRefusedError(
                    "the messages are not the ones the checkpoint commits to"
                )
            pruned = [] if horizon is None else _window_rows(conn, horizon)
            if (window_root(pruned), len(pruned)) != (
                checkpoint.window_root,
                checkpoint.window_rows,
            ):
                raise CompactionRefusedError(
                    "the window history is not the one the checkpoint commits to"
                )
            events, facts = _inbox_cuts(conn, checkpoint)
            for table in (SETTLEMENTS, LOG, STATE, OUTBOX):
                conn.execute(
                    f"DELETE FROM {table} WHERE message_id IN (SELECT value FROM json_each(?))",
                    (targets,),
                )
            if horizon is not None:
                conn.execute(f"DELETE FROM {WINDOWS_TABLE} WHERE at <= ?", (horizon,))
            for cut in checkpoint.inbox_cuts():
                conn.execute(
                    f"DELETE FROM {SQLITE_CONSUMED} WHERE fact_id IN (SELECT fact_id FROM "
                    f"{SQLITE_FACTS} WHERE source = ? AND event_seq <= ?)",
                    (cut.source, cut.through),
                )
                conn.execute(
                    f"DELETE FROM {SQLITE_FACTS} WHERE source = ? AND event_seq <= ?",
                    (cut.source, cut.through),
                )
                conn.execute(
                    f"DELETE FROM {SQLITE_EVENTS} WHERE source = ? AND seq <= ?",
                    (cut.source, cut.through),
                )
            conn.execute(f"UPDATE {CHECKPOINTS} SET open = 0 WHERE seq = ?", (checkpoint.seq,))
            if before_commit is not None:
                before_commit()
        return {
            "checkpoint": checkpoint.seq,
            "messages": len(tombstones),
            "rows": int(log_rows),
            "windows": len(pruned),
            "inbox_events": events,
            "inbox_facts": facts,
        }

    # -- the inbox (docs/EPIC5_DESIGN.md §2) ------------------------------------

    def record_event(self, **event: Any) -> tuple[int, bool]:
        """Append a verified event to its source's log, once."""
        from interlock.inbox_store import sqlite_record_event

        with self._writing() as conn:
            recorded = sqlite_record_event(conn, **event)
            self.checkpoint("record-uncommitted", None)
            return recorded

    def event(self, source: str, seq: int) -> InboundEvent:
        from interlock.inbox_store import sqlite_event

        return sqlite_event(self._conn, source, seq)

    def record_fact(self, fact: InboundFact) -> bool:
        """Bind an event to the delivery it names, once."""
        from interlock.inbox_store import sqlite_record_fact

        with self._writing() as conn:
            fresh = sqlite_record_fact(conn, fact, now_us())
            self.checkpoint("match-uncommitted", None)
            return fresh

    def delivered_with(self, ref: str) -> list[DeliveredRef]:
        from interlock.inbox_store import sqlite_delivered_with

        return sqlite_delivered_with(self._conn, ref)

    def unmatched(self, since: datetime) -> list[InboundEvent]:
        from interlock.inbox_store import sqlite_unmatched

        return sqlite_unmatched(self._conn, since)

    def inbound_events(self) -> list[InboundEvent]:
        from interlock.inbox_store import sqlite_events

        return sqlite_events(self._conn)

    def inbound_heads(self) -> dict[str, tuple[int, str]]:
        from interlock.inbox_store import sqlite_heads

        return sqlite_heads(self._conn)

    def inbound_starts(self) -> dict[str, tuple[int, str]]:
        from interlock.inbox_store import sqlite_starts

        return sqlite_starts(self._conn, self.checkpoints())

    def inbound_facts(self) -> list[InboundFact]:
        from interlock.inbox_store import sqlite_facts

        return sqlite_facts(self._conn, orphans=True)

    def inbound_consumed(self) -> dict[uuid.UUID, uuid.UUID]:
        from interlock.inbox_store import sqlite_consumed

        return sqlite_consumed(self._conn)

    def inbound_raw(self, source: str, through: int) -> dict[int, tuple[str, str]]:
        from interlock.inbox_store import sqlite_raw

        return sqlite_raw(self._conn, source, through)

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


_TOMBSTONES: Final = (
    f"SELECT message_id, checkpoint, stage_id, plan_id, state, log_seq, log_head, receipt_id, "
    f"credit, cost, compensates FROM {COMPACTED} WHERE {{where}} ORDER BY message_id"
)


def _tombstone(r: Sequence[Any]) -> Tombstone:
    return Tombstone(
        message_id=uuid.UUID(str(r[0])),
        checkpoint=int(r[1]),
        stage_id=uuid.UUID(str(r[2])),
        plan_id=str(r[3]),
        state=str(r[4]),
        log_seq=int(r[5]),
        log_head=str(r[6]),
        receipt_id=None if r[7] is None else str(r[7]),
        credit=None if r[8] is None else str(r[8]),
        cost=str(r[9]),
        compensates=None if r[10] is None else uuid.UUID(str(r[10])),
    )


def _inbox_cuts(conn: sqlite3.Connection, checkpoint: CheckpointBody) -> tuple[int, int]:
    """Within a compaction's transaction: hold each inbound source's cut to the
    log as it was verified, every fact in it consumed, and the facts to the
    fold the checkpoint carries, as ``interlock.outbox_compact`` does. The
    events and facts it prunes.

    :raises CompactionRefusedError: If a cut does not hold.
    """
    from interlock.compaction import inbox_root
    from interlock.exceptions import CompactionRefusedError
    from interlock.inbox_store import sqlite_facts

    cuts = checkpoint.inbox_cuts()
    if not cuts:
        return 0, 0
    events = 0
    pairs: list[tuple[InboundFact, uuid.UUID | None]] = []
    for cut in cuts:
        first, counted = conn.execute(
            f"SELECT min(seq), count(*) FROM {SQLITE_EVENTS} WHERE source = ? AND seq <= ?",
            (cut.source, cut.through),
        ).fetchone()
        linked = conn.execute(
            f"SELECT 1 FROM {SQLITE_EVENTS} WHERE source = ? AND seq = ? AND prev_hash = ?",
            (cut.source, cut.start + 1, cut.prev),
        ).fetchone()
        headed = conn.execute(
            f"SELECT 1 FROM {SQLITE_EVENTS} WHERE source = ? AND seq = ? AND event_hash = ?",
            (cut.source, cut.through, cut.head),
        ).fetchone()
        if (
            int(counted) != cut.events
            or cut.through - cut.start != cut.events
            or first != cut.start + 1
            or linked is None
            or headed is None
        ):
            raise CompactionRefusedError(f"inbound source {cut.source} moved after it was verified")
        found = sqlite_facts(conn, "f.source = ? AND f.event_seq <= ?", cut.source, cut.through)
        consumed = {
            uuid.UUID(str(r[0])): uuid.UUID(str(r[1]))
            for r in conn.execute(
                f"SELECT c.fact_id, c.stage_id FROM {SQLITE_CONSUMED} AS c "
                f"JOIN {SQLITE_FACTS} AS f ON f.fact_id = c.fact_id "
                f"WHERE f.source = ? AND f.event_seq <= ?",
                (cut.source, cut.through),
            ).fetchall()
        }
        if any(f.fact_id not in consumed for f in found):
            raise CompactionRefusedError(f"a fact of inbound source {cut.source} is still pending")
        if (len(found), len(found)) != (cut.facts, cut.consumed):
            raise CompactionRefusedError(
                f"the facts of inbound source {cut.source} are not the ones the checkpoint "
                f"commits to"
            )
        pairs += [(f, consumed[f.fact_id]) for f in found]
        events += cut.events
    if (inbox_root(pairs), len(pairs)) != (
        checkpoint.inbox.get("root"),
        checkpoint.inbox.get("facts"),
    ):
        raise CompactionRefusedError("the facts are not the ones the checkpoint commits to")
    return events, len(pairs)


def _window_rows(conn: sqlite3.Connection, horizon: int) -> list[WindowRow]:
    if (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (WINDOWS_TABLE,)
        ).fetchone()
        is None
    ):
        return []
    return [
        WindowRow(
            stage_id=uuid.UUID(str(r[0])),
            window=str(r[1]),
            key=str(r[2]),
            amount=Decimal(str(r[3])),
            at=instant(int(r[4])),
        )
        for r in conn.execute(
            f"SELECT stage_id, window_name, key, amount, at FROM {WINDOWS_TABLE} WHERE at <= ?",
            (horizon,),
        ).fetchall()
    ]


def _microseconds(at: datetime) -> int:
    return (at - _EPOCH) // timedelta(microseconds=1)


def _operator(actor: str) -> str:
    if not actor:
        raise ValueError("an operator action names who took it")
    return actor if actor.startswith("operator:") else f"operator:{actor}"


def parse_payload(text: str) -> Any:
    """A stored payload, as the relay re-reads it."""
    return loads_strict(text)
