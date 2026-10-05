"""Where the inbox records, and what verification reads of it, on both stores.

- :class:`PostgresInboxStore`: an inbox role's connection. Every write goes
  through ``interlock.inbox_record`` or ``interlock.inbox_match``, which link
  the log and hold a binding to what the database can check.
- On SQLite, the store (:class:`~interlock.sqlite_outbox.SqliteOutboxStore`,
  opened with :data:`~interlock.sqlite_outbox.INBOX`) does the same steps under
  ``BEGIN IMMEDIATE``, with the helpers here; a trigger refuses an event that
  does not extend its source's log, through a function only Interlock's own
  connections register.

Every reader, a store or a PostgreSQL connection, can read the inbox for
:func:`interlock.inbox.verify_inbox` (:func:`inbox_reader`).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentgov.receipts.canonical import canonical_bytes

from interlock.compaction import instant_text
from interlock.deliveries import PostgresReader, parse_instant
from interlock.inbox import DeliveredRef, InboundEvent, event_hash, frozen_fields, inbox_genesis
from interlock.inbox_sql import SQLITE_CONSUMED, SQLITE_EVENTS, SQLITE_FACTS, SQLITE_SOURCES
from interlock.outbox_store import Checkpoint, _no_checkpoint
from interlock.types import InboundFact

if TYPE_CHECKING:
    import psycopg

__all__ = ["PostgresInboxStore", "inbox_reader"]

_FACT_COLUMNS = (
    "f.fact_id, f.source, f.event_seq, f.event_hash, f.message_id, f.delivery_seq, "
    "f.delivery_hash, f.remote_ref, f.scope_id, f.plan_id, f.tenant_id, f.attestation, "
    "e.event_id, e.event_type, e.vendor_at, e.received_at, e.body_hash, e.part, e.refs, "
    "e.fields, e.withheld, e.attestation"
)
_EVENT_COLUMNS = (
    "source, seq, event_id, event_type, vendor_at, received_at, body_hash, part, refs, fields, "
    "withheld, attestation, prev_hash, event_hash"
)


def _json(value: object) -> str:
    return canonical_bytes(value).decode("utf-8")


def _instant(value: object) -> datetime:
    return value if isinstance(value, datetime) else parse_instant(str(value))


def fact_row(r: Sequence[Any]) -> InboundFact:
    """An :class:`~interlock.types.InboundFact` from a row of the fact's and
    its event's columns, as both stores and ``interlock.stage_facts`` return
    them. A fact whose event row is gone (read for verification) carries an
    empty event, which no attestation verifies."""
    if r[12] is None:
        return _orphan(r)
    return InboundFact(
        fact_id=r[0] if isinstance(r[0], uuid.UUID) else uuid.UUID(str(r[0])),
        source=str(r[1]),
        event_seq=int(r[2]),
        event_hash=str(r[3]),
        message_id=r[4] if isinstance(r[4], uuid.UUID) else uuid.UUID(str(r[4])),
        delivery_seq=int(r[5]),
        delivery_hash=str(r[6]),
        remote_ref=str(r[7]),
        scope_id=str(r[8]),
        plan_id=str(r[9]),
        tenant_id=None if r[10] is None else str(r[10]),
        attestation=str(r[11]),
        event_id=str(r[12]),
        kind=str(r[13]),
        vendor_at=None if r[14] is None else _instant(r[14]),
        received_at=_instant(r[15]),
        body_hash=str(r[16]),
        part=int(r[17]),
        refs=tuple(json.loads(str(r[18]))),
        fields=frozen_fields(str(r[19])),
        withheld=tuple(json.loads(str(r[20]))),
        event_attestation=str(r[21]),
    )


def _orphan(r: Sequence[Any]) -> InboundFact:
    return InboundFact(
        fact_id=r[0] if isinstance(r[0], uuid.UUID) else uuid.UUID(str(r[0])),
        source=str(r[1]),
        event_seq=int(r[2]),
        event_hash=str(r[3]),
        message_id=r[4] if isinstance(r[4], uuid.UUID) else uuid.UUID(str(r[4])),
        delivery_seq=int(r[5]),
        delivery_hash=str(r[6]),
        remote_ref=str(r[7]),
        scope_id=str(r[8]),
        plan_id=str(r[9]),
        tenant_id=None if r[10] is None else str(r[10]),
        attestation=str(r[11]),
        event_id="",
        kind="",
        vendor_at=None,
        received_at=datetime.fromtimestamp(0, UTC),
        body_hash="",
        part=0,
        refs=(),
        fields=frozen_fields("{}"),
        withheld=(),
        event_attestation="",
    )


def _event_row(r: Sequence[Any]) -> InboundEvent:
    return InboundEvent(
        source=str(r[0]),
        seq=int(r[1]),
        event_id=str(r[2]),
        kind=str(r[3]),
        vendor_at=None if r[4] is None else _instant(r[4]),
        received_at=_instant(r[5]),
        body_hash=str(r[6]),
        part=int(r[7]),
        refs=tuple(json.loads(str(r[8]))),
        fields=frozen_fields(str(r[9])),
        withheld=tuple(json.loads(str(r[10]))),
        attestation=str(r[11]),
        prev_hash=str(r[12]),
        event_hash=str(r[13]),
    )


def inbox_reader(source: object) -> Any:
    """``source`` as the inbox's reader: a store already is one; a PostgreSQL
    connection, or a reader of the outbox over one, is wrapped."""
    if hasattr(source, "inbound_events"):
        return source
    if isinstance(source, PostgresReader):
        return PostgresInboxStore(source.connection)
    return PostgresInboxStore(source)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------


class PostgresInboxStore(PostgresReader):
    """The inbox on PostgreSQL: an inbox role's connection (``inbox_roles``),
    or any reader's for verification."""

    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        super().__init__(conn)
        self.checkpoint: Checkpoint = _no_checkpoint
        """Called inside each write's transaction, before it commits: the
        crash tests stop the process there."""

    # -- writing, as the inbox ----------------------------------------------

    def record_event(
        self,
        *,
        source: str,
        event_id: str,
        kind: str,
        vendor_at: datetime | None,
        received_at: datetime,
        body: str,
        body_hash: str,
        signature: str,
        part: int,
        refs: Sequence[str],
        fields: Mapping[str, Any],
        withheld: Sequence[str],
        attestation: str,
    ) -> tuple[int, bool]:
        with self._conn.transaction():
            row = self._conn.execute(
                "SELECT out_seq, out_event_hash, out_fresh FROM interlock.inbox_record("
                "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    source,
                    event_id,
                    kind,
                    vendor_at,
                    received_at,
                    body,
                    body_hash,
                    signature,
                    part,
                    _json(list(refs)),
                    _json(dict(fields)),
                    _json(list(withheld)),
                    attestation,
                ),
            ).fetchone()
            self.checkpoint("record-uncommitted", None)
        assert row is not None
        return int(row[0]), bool(row[2])

    def event(self, source: str, seq: int) -> InboundEvent:
        row = self._conn.execute(
            f"SELECT {_EVENT_COLUMNS} FROM interlock.inbox_events WHERE source = %s AND seq = %s",
            (source, seq),
        ).fetchone()
        assert row is not None
        return _event_row(row)

    def record_fact(self, fact: InboundFact) -> bool:
        with self._conn.transaction():
            row = self._conn.execute(
                "SELECT interlock.inbox_match(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    fact.fact_id,
                    fact.source,
                    fact.event_seq,
                    fact.event_hash,
                    fact.message_id,
                    fact.delivery_seq,
                    fact.delivery_hash,
                    fact.remote_ref,
                    fact.scope_id,
                    fact.plan_id,
                    fact.tenant_id,
                    fact.attestation,
                ),
            ).fetchone()
            self.checkpoint("match-uncommitted", None)
        return bool(row and row[0])

    def delivered_with(self, ref: str) -> list[DeliveredRef]:
        return [
            DeliveredRef(r[0], int(r[1]), str(r[2]), str(r[3]), str(r[4]), r[5])
            for r in self._conn.execute(
                "SELECT a.message_id, a.seq, a.event_hash, o.scope_id, o.plan_id, o.tenant_id "
                "FROM interlock.outbox_attempts AS a "
                "JOIN interlock.outbox AS o ON o.message_id = a.message_id "
                "WHERE a.event = 'delivered' AND a.remote_ref = %s ORDER BY a.message_id, a.seq",
                (ref,),
            )
        ]

    def unmatched(self, since: datetime) -> list[InboundEvent]:
        return [
            _event_row(r)
            for r in self._conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM interlock.inbox_events AS e "
                f"WHERE e.received_at >= %s AND NOT EXISTS ("
                f"  SELECT 1 FROM interlock.inbox_facts AS f "
                f"   WHERE f.source = e.source AND f.event_seq = e.seq) "
                f"ORDER BY e.received_at, e.source, e.seq",
                (since,),
            )
        ]

    # -- reading, for verification ------------------------------------------

    def inbound_events(self) -> list[InboundEvent]:
        if not self._exists("interlock.inbox_events"):
            return []
        return [
            _event_row(r)
            for r in self._conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM interlock.inbox_events ORDER BY source, seq"
            )
        ]

    def inbound_heads(self) -> dict[str, tuple[int, str]]:
        if not self._exists("interlock.inbox_sources"):
            return {}
        return {
            str(r[0]): (int(r[1]), str(r[2]))
            for r in self._conn.execute(
                "SELECT name, log_seq, log_head FROM interlock.inbox_sources"
            )
        }

    def inbound_starts(self) -> dict[str, tuple[int, str]]:
        """Where each source's log starts now: its genesis, or the cut the
        latest checkpoint that pruned a prefix of it left."""
        return _starts(self.checkpoints(), self.inbound_heads())

    def inbound_facts(self) -> list[InboundFact]:
        if not self._exists("interlock.inbox_facts"):
            return []
        # Every fact, its event's row or not: verification finds the one whose
        # event is gone.
        return [
            fact_row(r)
            for r in self._conn.execute(
                f"SELECT {_FACT_COLUMNS} FROM interlock.inbox_facts AS f "
                f"LEFT JOIN interlock.inbox_events AS e "
                f"ON e.source = f.source AND e.seq = f.event_seq ORDER BY f.fact_id"
            )
        ]

    def inbound_consumed(self) -> dict[uuid.UUID, uuid.UUID]:
        if not self._exists("interlock.inbox_consumed"):
            return {}
        return {
            r[0]: r[1]
            for r in self._conn.execute("SELECT fact_id, stage_id FROM interlock.inbox_consumed")
        }

    def inbound_raw(self, source: str, through: int) -> dict[int, tuple[str, str]]:
        """Each of ``source``'s events up to ``through``, as the vendor sent
        it: its body and its signature headers, for an archive."""
        return {
            int(r[0]): (str(r[1]), str(r[2]))
            for r in self._conn.execute(
                "SELECT seq, body, signature FROM interlock.inbox_events "
                "WHERE source = %s AND seq <= %s",
                (source, through),
            )
        }


def _starts(checkpoints: Sequence[Any], heads: Mapping[str, Any]) -> dict[str, tuple[int, str]]:
    """Each source's start: the cut the latest checkpoint pruning it left, or
    its genesis. A checkpoint that does not parse cuts nothing here; the
    operator log's verification names it."""
    starts: dict[str, tuple[int, str]] = {}
    for row in sorted(checkpoints, key=lambda r: r.seq):
        try:
            cuts = row.checkpoint().inbox_cuts()
        except (ValueError, KeyError, TypeError):
            continue
        for cut in cuts:
            starts[cut.source] = (cut.through, cut.head)
    return {name: starts.get(name, (0, inbox_genesis(name))) for name in heads}


# --------------------------------------------------------------------------
# SQLite: the steps, for SqliteOutboxStore
# --------------------------------------------------------------------------


def register(conn: sqlite3.Connection) -> None:
    """Register what the inbox log's trigger needs on ``conn``."""
    conn.create_function("interlock_inbox_hash", 13, _inbox_hash_sql, deterministic=True)


def _inbox_hash_sql(
    prev: str,
    source: str,
    seq: int,
    event_id: str,
    kind: str,
    vendor_at: str | None,
    received_at: str,
    body_hash: str,
    part: int,
    refs: str,
    fields: str,
    withheld: str,
    attestation: str,
) -> str:
    return event_hash(
        prev,
        source,
        int(seq),
        event_id,
        kind,
        None if vendor_at is None else parse_instant(vendor_at),
        parse_instant(received_at),
        body_hash,
        int(part),
        json.loads(refs),
        json.loads(fields),
        json.loads(withheld),
        attestation,
    )


def sqlite_record_event(
    conn: sqlite3.Connection,
    *,
    source: str,
    event_id: str,
    kind: str,
    vendor_at: datetime | None,
    received_at: datetime,
    body: str,
    body_hash: str,
    signature: str,
    part: int,
    refs: Sequence[str],
    fields: Mapping[str, Any],
    withheld: Sequence[str],
    attestation: str,
) -> tuple[int, bool]:
    """Within a ``BEGIN IMMEDIATE`` transaction: append the event once."""
    from interlock.exceptions import InterlockError

    head = conn.execute(
        f"SELECT log_seq, log_head FROM {SQLITE_SOURCES} WHERE name = ? AND enabled = 1",
        (source,),
    ).fetchone()
    if head is None:
        raise InterlockError(f"no enabled inbound source {source}")
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != body_hash:
        raise InterlockError("the body does not match its hash")
    found = conn.execute(
        f"SELECT seq FROM {SQLITE_EVENTS} WHERE source = ? AND event_id = ?", (source, event_id)
    ).fetchone()
    if found is not None:
        return int(found[0]), False
    seq = int(head[0]) + 1
    digest = event_hash(
        str(head[1]),
        source,
        seq,
        event_id,
        kind,
        vendor_at,
        received_at,
        body_hash,
        part,
        refs,
        fields,
        withheld,
        attestation,
    )
    conn.execute(
        f"INSERT INTO {SQLITE_EVENTS} (source, seq, event_id, event_type, vendor_at, received_at, "
        f"body, body_hash, signature, part, refs, fields, withheld, attestation, prev_hash, "
        f"event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source,
            seq,
            event_id,
            kind,
            None if vendor_at is None else instant_text(vendor_at),
            instant_text(received_at),
            body,
            body_hash,
            signature,
            part,
            _json(list(refs)),
            _json(dict(fields)),
            _json(list(withheld)),
            attestation,
            str(head[1]),
            digest,
        ),
    )
    return seq, True


def sqlite_event(conn: sqlite3.Connection, source: str, seq: int) -> InboundEvent:
    row = conn.execute(
        f"SELECT {_EVENT_COLUMNS} FROM {SQLITE_EVENTS} WHERE source = ? AND seq = ?",
        (source, seq),
    ).fetchone()
    assert row is not None
    return _event_row(row)


def sqlite_record_fact(conn: sqlite3.Connection, fact: InboundFact, now_us: int) -> bool:
    """Within a ``BEGIN IMMEDIATE`` transaction: the binding, held to what the
    file can check, once per event."""
    from interlock.exceptions import InterlockError

    if (
        conn.execute(
            f"SELECT 1 FROM {SQLITE_EVENTS} WHERE source = ? AND seq = ? AND event_hash = ?",
            (fact.source, fact.event_seq, fact.event_hash),
        ).fetchone()
        is None
    ):
        raise InterlockError(f"no event {fact.event_seq} of source {fact.source} at that hash")
    if (
        conn.execute(
            "SELECT 1 FROM _interlock_outbox_attempts AS a "
            "JOIN _interlock_outbox AS o ON o.message_id = a.message_id "
            "WHERE a.message_id = ? AND a.seq = ? AND a.event = 'delivered' "
            "AND a.event_hash = ? AND a.remote_ref = ? AND o.scope_id = ? AND o.plan_id = ? "
            "AND o.tenant_id IS ?",
            (
                str(fact.message_id),
                fact.delivery_seq,
                fact.delivery_hash,
                fact.remote_ref,
                fact.scope_id,
                fact.plan_id,
                fact.tenant_id,
            ),
        ).fetchone()
        is None
    ):
        raise InterlockError(f"message {fact.message_id} delivered nothing named {fact.remote_ref}")
    cursor = conn.execute(
        f"INSERT OR IGNORE INTO {SQLITE_FACTS} (fact_id, source, event_seq, event_hash, "
        f"message_id, delivery_seq, delivery_hash, remote_ref, scope_id, plan_id, tenant_id, "
        f"attestation, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(fact.fact_id),
            fact.source,
            fact.event_seq,
            fact.event_hash,
            str(fact.message_id),
            fact.delivery_seq,
            fact.delivery_hash,
            fact.remote_ref,
            fact.scope_id,
            fact.plan_id,
            fact.tenant_id,
            fact.attestation,
            now_us,
        ),
    )
    return cursor.rowcount == 1


def sqlite_delivered_with(conn: sqlite3.Connection, ref: str) -> list[DeliveredRef]:
    return [
        DeliveredRef(uuid.UUID(str(r[0])), int(r[1]), str(r[2]), str(r[3]), str(r[4]), r[5])
        for r in conn.execute(
            "SELECT a.message_id, a.seq, a.event_hash, o.scope_id, o.plan_id, o.tenant_id "
            "FROM _interlock_outbox_attempts AS a "
            "JOIN _interlock_outbox AS o ON o.message_id = a.message_id "
            "WHERE a.event = 'delivered' AND a.remote_ref = ? ORDER BY a.message_id, a.seq",
            (ref,),
        ).fetchall()
    ]


def sqlite_unmatched(conn: sqlite3.Connection, since: datetime) -> list[InboundEvent]:
    return [
        _event_row(r)
        for r in conn.execute(
            f"SELECT {_EVENT_COLUMNS} FROM {SQLITE_EVENTS} AS e WHERE e.received_at >= ? "
            f"AND NOT EXISTS (SELECT 1 FROM {SQLITE_FACTS} AS f "
            f"                 WHERE f.source = e.source AND f.event_seq = e.seq) "
            f"ORDER BY e.received_at, e.source, e.seq",
            (instant_text(since),),
        ).fetchall()
    ]


def sqlite_has(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def sqlite_events(conn: sqlite3.Connection) -> list[InboundEvent]:
    if not sqlite_has(conn, SQLITE_EVENTS):
        return []
    return [
        _event_row(r)
        for r in conn.execute(
            f"SELECT {_EVENT_COLUMNS} FROM {SQLITE_EVENTS} ORDER BY source, seq"
        ).fetchall()
    ]


def sqlite_heads(conn: sqlite3.Connection) -> dict[str, tuple[int, str]]:
    if not sqlite_has(conn, SQLITE_SOURCES):
        return {}
    return {
        str(r[0]): (int(r[1]), str(r[2]))
        for r in conn.execute(f"SELECT name, log_seq, log_head FROM {SQLITE_SOURCES}").fetchall()
    }


def sqlite_facts(
    conn: sqlite3.Connection, where: str = "1", *params: object, orphans: bool = False
) -> list[InboundFact]:
    """Facts with their events; with ``orphans``, those whose event row is
    gone too, for verification to find."""
    if not sqlite_has(conn, SQLITE_FACTS):
        return []
    join = "LEFT JOIN" if orphans else "JOIN"
    return [
        fact_row(r)
        for r in conn.execute(
            f"SELECT {_FACT_COLUMNS} FROM {SQLITE_FACTS} AS f "
            f"{join} {SQLITE_EVENTS} AS e ON e.source = f.source AND e.seq = f.event_seq "
            f"WHERE {where} ORDER BY f.fact_id",
            params,
        ).fetchall()
    ]


def sqlite_consumed(conn: sqlite3.Connection) -> dict[uuid.UUID, uuid.UUID]:
    if not sqlite_has(conn, SQLITE_CONSUMED):
        return {}
    return {
        uuid.UUID(str(r[0])): uuid.UUID(str(r[1]))
        for r in conn.execute(f"SELECT fact_id, stage_id FROM {SQLITE_CONSUMED}").fetchall()
    }


def sqlite_raw(conn: sqlite3.Connection, source: str, through: int) -> dict[int, tuple[str, str]]:
    return {
        int(r[0]): (str(r[1]), str(r[2]))
        for r in conn.execute(
            f"SELECT seq, body, signature FROM {SQLITE_EVENTS} WHERE source = ? AND seq <= ?",
            (source, through),
        ).fetchall()
    }


def sqlite_starts(
    conn: sqlite3.Connection, checkpoints: Sequence[Any]
) -> dict[str, tuple[int, str]]:
    return _starts(checkpoints, sqlite_heads(conn))
