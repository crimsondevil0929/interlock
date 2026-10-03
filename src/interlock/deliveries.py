"""The outbox's delivery log, read and verified from outside the database, and
the operator's actions on messages (``docs/OUTBOX_DESIGN.md`` §7, §8).

Every change to a message's delivery state is a row of its delivery log,
``interlock.outbox_attempts``, linked by hash to the row before it from a
genesis bound to the request: a call started, an outcome, a lease that ran out
mid-call, a hold, a release, a cancellation, a requeue. The database links the
rows (``interlock.outbox_log_link``); :func:`verify_delivery_log` recomputes
every link here, with an independent implementation of the same framing, and
checks that the state each message is in is the state its log leads to.

The operator's actions run as the installer, never the relay: releasing a
message the breaker held is a person's decision, not a process's.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:
    import psycopg

__all__ = [
    "LogEvent",
    "LoggedMessage",
    "MessageView",
    "OutboxReader",
    "PostgresReader",
    "cancel",
    "event_hash",
    "frame",
    "genesis_hash",
    "message_log",
    "messages",
    "parse_instant",
    "reader",
    "release",
    "release_scope",
    "requeue",
    "state_counts",
    "verify_delivery_log",
]

GENESIS_TAG: Final = "interlock-outbox-genesis-v1"
EVENT_TAG: Final = "interlock-outbox-event-v1"
EVENT_TAG_V2: Final = "interlock-outbox-event-v2"
"""Rows that carry a ``remote_ref`` or an ``authority`` (schema version 3)
are framed with both; every other row as in version 2, so no hash written
before them changes."""

OUTCOMES: Final = frozenset({"delivered", "retryable", "permanent", "unknown"})
"""Events that report what a call returned. ``lost`` is not one: it is the
inference, by the relay that took the lease over, that nobody will report."""

_OPERATIONAL: Final = frozenset({"pending", "leased"})


def frame(*fields: str | None) -> str:
    """Length-prefixed framing, as ``interlock.outbox_frame`` frames: each
    field as ``<UTF-8 byte length>:<text>``, ``None`` as ``-``."""
    return "".join("-" if f is None else f"{len(f.encode('utf-8'))}:{f}" for f in fields)


def _digest(*fields: str | None) -> str:
    return hashlib.sha256(frame(*fields).encode("utf-8")).hexdigest()


def _instant(at: datetime | str) -> str:
    """An instant as the log hashes it: UTC, to the microsecond. SQLite
    stores the text itself, which is returned unchanged."""
    if isinstance(at, str):
        return at
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_instant(text: str) -> datetime:
    """The inverse of the log's instant format."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _text(value: object) -> str | None:
    return None if value is None else str(value)


def genesis_hash(
    message_id: uuid.UUID,
    stage_id: uuid.UUID,
    plan_id: str,
    scope_id: str,
    effect_id: str,
    sink: str,
    operation: str,
    idempotency_key: str,
    payload_hash: str,
) -> str:
    """Where a message's delivery log starts: bound to the request it delivers."""
    return _digest(
        GENESIS_TAG,
        str(message_id),
        str(stage_id),
        plan_id,
        scope_id,
        effect_id,
        sink,
        operation,
        idempotency_key,
        payload_hash,
    )


def event_hash(
    prev_hash: str,
    message_id: uuid.UUID,
    seq: int,
    attempt: int | None,
    event: str,
    actor: str,
    at: datetime | str,
    status_code: int | None,
    response_digest: str | None,
    detail: str | None,
    state_after: str | None,
    remote_ref: str | None = None,
    authority: str | None = None,
) -> str:
    """The hash of one delivery-log row, as ``interlock.outbox_event_hash``
    computes it, and SQLite's ``interlock_event_hash``."""
    fields: list[str | None] = [
        prev_hash,
        str(message_id),
        str(seq),
        _text(attempt),
        event,
        actor,
        _instant(at),
        _text(status_code),
        response_digest,
        detail,
        state_after,
    ]
    if remote_ref is None and authority is None:
        return _digest(EVENT_TAG, *fields)
    return _digest(EVENT_TAG_V2, *fields, remote_ref, authority)


@dataclass(frozen=True, slots=True)
class LogEvent:
    """One row of a message's delivery log.

    :ivar attempt: The call this event belongs to: its ``sending``, its
        outcome, or the ``lost`` recorded when its lease ran out first.
        ``None`` for a change of state that involved no call.
    :ivar state_after: The state the event moved the message to, or ``None``
        when it moved nothing: an outcome a relay reported after its lease
        was taken over.
    :ivar remote_ref: What a delivered call created, as the sink named it: a
        Stripe ``pi_...``. A compensation binds to it.
    :ivar authority: The signed operator record behind an operator's row.
    """

    message_id: uuid.UUID
    seq: int
    attempt: int | None
    event: str
    actor: str
    at: datetime
    status_code: int | None
    response_digest: str | None
    detail: str | None
    state_after: str | None
    prev_hash: str
    event_hash: str
    remote_ref: str | None = None
    authority: str | None = None

    def recomputed(self) -> str:
        return event_hash(
            self.prev_hash,
            self.message_id,
            self.seq,
            self.attempt,
            self.event,
            self.actor,
            self.at,
            self.status_code,
            self.response_digest,
            self.detail,
            self.state_after,
            self.remote_ref,
            self.authority,
        )


_EVENTS: Final = (
    "SELECT message_id, seq, attempt, event, actor, at, status_code, response_digest, "
    "detail, state_after, prev_hash, event_hash, NULL::text, NULL::text "
    "FROM interlock.outbox_attempts "
    "WHERE %(ids)s::uuid[] IS NULL OR message_id = ANY (%(ids)s::uuid[]) "
    "ORDER BY message_id, seq"
)

_MESSAGES: Final = (
    "SELECT o.message_id, o.stage_id, o.plan_id, o.scope_id, o.effect_id, o.sink, "
    "o.operation, o.idempotency_key, o.payload_hash, s.state, s.attempts, s.log_seq, "
    "s.log_head FROM interlock.outbox o JOIN interlock.outbox_state s USING (message_id) "
    "WHERE %(ids)s::uuid[] IS NULL OR o.message_id = ANY (%(ids)s::uuid[]) "
    "ORDER BY o.enqueued_at, o.message_id"
)


def _event(row: Sequence[Any]) -> LogEvent:
    return LogEvent(
        message_id=row[0],
        seq=int(row[1]),
        attempt=None if row[2] is None else int(row[2]),
        event=str(row[3]),
        actor=str(row[4]),
        at=row[5],
        status_code=None if row[6] is None else int(row[6]),
        response_digest=_text(row[7]),
        detail=_text(row[8]),
        state_after=_text(row[9]),
        prev_hash=str(row[10]),
        event_hash=str(row[11]),
        remote_ref=_text(row[12]) if len(row) > 12 else None,
        authority=_text(row[13]) if len(row) > 13 else None,
    )


@dataclass(frozen=True, slots=True)
class LoggedMessage:
    """A message as its delivery log is verified: what its genesis binds,
    and the state and head its state row records."""

    message_id: uuid.UUID
    stage_id: uuid.UUID
    plan_id: str
    scope_id: str
    effect_id: str
    sink: str
    operation: str
    idempotency_key: str
    payload_hash: str
    state: str
    attempts: int
    log_seq: int
    log_head: str

    def genesis(self) -> str:
        return genesis_hash(
            self.message_id,
            self.stage_id,
            self.plan_id,
            self.scope_id,
            self.effect_id,
            self.sink,
            self.operation,
            self.idempotency_key,
            self.payload_hash,
        )


class OutboxReader(Protocol):
    """What verification and inspection read, from either store."""

    def snapshot(
        self, message_ids: Sequence[uuid.UUID] | None
    ) -> tuple[list[LoggedMessage], list[LogEvent]]:
        """Messages and their log rows, in log order."""
        ...

    def views(
        self, *, state: str | None, scope_id: str | None, limit: int
    ) -> tuple[MessageView, ...]: ...

    def counts(self) -> dict[str, int]: ...


class PostgresReader:
    """An :class:`OutboxReader` over a PostgreSQL connection."""

    __slots__ = ("_conn",)

    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        self._conn = conn

    def snapshot(
        self, message_ids: Sequence[uuid.UUID] | None
    ) -> tuple[list[LoggedMessage], list[LogEvent]]:
        params = {"ids": None if message_ids is None else list(message_ids)}
        found = [
            LoggedMessage(
                message_id=m[0],
                stage_id=m[1],
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
            for m in self._conn.execute(_MESSAGES, params).fetchall()
        ]
        return found, [_event(row) for row in self._conn.execute(_EVENTS, params)]

    def views(
        self, *, state: str | None, scope_id: str | None, limit: int
    ) -> tuple[MessageView, ...]:
        rows = self._conn.execute(
            "SELECT o.message_id, o.plan_id, o.scope_id, o.effect_id, o.sink, o.operation, "
            "o.tenant_id, o.cost, s.state, s.attempts, s.reason, s.lease_owner, o.not_after, "
            "o.enqueued_at, s.next_attempt_at "
            "FROM interlock.outbox o JOIN interlock.outbox_state s USING (message_id) "
            "WHERE (%(state)s::text IS NULL OR s.state = %(state)s) "
            "AND (%(scope)s::text IS NULL OR o.scope_id = %(scope)s) "
            "ORDER BY o.enqueued_at, o.seq LIMIT %(limit)s",
            {"state": state, "scope": scope_id, "limit": limit},
        ).fetchall()
        return tuple(
            MessageView(
                message_id=r[0],
                plan_id=str(r[1]),
                scope_id=str(r[2]),
                effect_id=str(r[3]),
                sink=str(r[4]),
                operation=str(r[5]),
                tenant_id=_text(r[6]),
                cost=Decimal(str(r[7])),
                state=str(r[8]),
                attempts=int(r[9]),
                reason=_text(r[10]),
                lease_owner=_text(r[11]),
                not_after=r[12],
                enqueued_at=r[13],
                next_attempt_at=r[14],
            )
            for r in rows
        )

    def counts(self) -> dict[str, int]:
        return {
            str(state): int(count)
            for state, count in self._conn.execute(
                "SELECT state, count(*) FROM interlock.outbox_state GROUP BY state ORDER BY state"
            )
        }


def reader(source: object) -> OutboxReader:
    """``source`` as an :class:`OutboxReader`: a store already is one; a
    PostgreSQL connection is wrapped."""
    if hasattr(source, "snapshot"):
        return source  # type: ignore[return-value]
    return PostgresReader(source)  # type: ignore[arg-type]


def message_log(source: object, message_id: uuid.UUID) -> tuple[LogEvent, ...]:
    """A message's delivery log, in order."""
    _, events = reader(source).snapshot([message_id])
    return tuple(events)


def verify_delivery_log(
    source: object, *, message_ids: Iterable[uuid.UUID] | None = None
) -> tuple[str, ...]:
    """Recompute every message's delivery log, and check it against the
    message's state.

    For each message: the log starts at the genesis its request implies, every
    row links to the one before it and hashes to what it says, the head the
    state row records is the last row, the calls are numbered 1, 2, 3...
    with no outcome reported twice and none without its call, and the state
    the message is in is the state its log leads to. A ``delivered`` state
    needs a ``delivered`` row, and a ``delivered`` row a ``delivered`` state.

    :param source: A PostgreSQL connection, or an outbox store.
    :param message_ids: Only these messages. All of them by default.
    :returns: Every problem found, naming its message. Empty when the logs
        verify.
    """
    found_messages, events = reader(source).snapshot(
        None if message_ids is None else list(message_ids)
    )
    logs: dict[uuid.UUID, list[LogEvent]] = {}
    for event in events:
        logs.setdefault(event.message_id, []).append(event)
    problems: list[str] = []
    for m in found_messages:
        found = _verify_one(
            logs.pop(m.message_id, []),
            genesis=m.genesis(),
            state=m.state,
            attempts=m.attempts,
            log_seq=m.log_seq,
            log_head=m.log_head,
        )
        problems += [f"message {m.message_id}: {p}" for p in found]
    for orphan in logs:
        problems.append(f"message {orphan}: delivery-log rows for a message the outbox lacks")
    return tuple(problems)


def _verify_one(
    events: Sequence[LogEvent],
    *,
    genesis: str,
    state: str,
    attempts: int,
    log_seq: int,
    log_head: str,
) -> list[str]:
    problems: list[str] = []
    expected = genesis
    for index, event in enumerate(events, start=1):
        if event.seq != index:
            problems.append(f"row {event.seq} is out of place (expected row {index})")
            return problems
        if event.prev_hash != expected:
            problems.append(f"row {index} does not link to the row before it")
            return problems
        if event.recomputed() != event.event_hash:
            problems.append(f"row {index} ({event.event}) does not hash to what it records")
            return problems
        expected = event.event_hash
    if log_seq != len(events) or log_head != expected:
        problems.append(
            f"the log's head is row {log_seq}, but the log ends at row {len(events)}, "
            f"or with a different hash: a row was removed or rewritten"
        )
    calls = [e.attempt for e in events if e.event == "sending"]
    if calls != list(range(1, len(calls) + 1)):
        problems.append(f"calls are numbered {calls}, not 1, 2, 3...")
    if attempts != len(calls):
        problems.append(f"the state counts {attempts} call(s), and the log {len(calls)}")
    started: set[int | None] = set()
    reported: Counter[int | None] = Counter()
    lost: Counter[int | None] = Counter()
    for event in events:
        if event.event == "sending":
            started.add(event.attempt)
        elif event.event in OUTCOMES or event.event == "lost":
            if event.attempt not in started:
                problems.append(f"row {event.seq} ({event.event}) reports a call never started")
            (reported if event.event in OUTCOMES else lost)[event.attempt] += 1
    for attempt, count in (reported + lost).items():
        if reported[attempt] > 1 or lost[attempt] > 1:
            problems.append(f"call {attempt} has {count} outcomes")
    delivered = any(e.event == "delivered" for e in events)
    if delivered != (state == "delivered"):
        problems.append(
            f"the message is {state}, and its log "
            f"{'records' if delivered else 'records no'} delivery"
        )
    logged = next((e.state_after for e in reversed(events) if e.state_after is not None), None)
    logged = logged or "pending"
    if state in _OPERATIONAL:
        if logged not in _OPERATIONAL:
            problems.append(f"the message is {state}, and its log leads to {logged}")
    elif logged != state:
        problems.append(f"the message is {state}, and its log leads to {logged}")
    return problems


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MessageView:
    """One message and where its delivery stands."""

    message_id: uuid.UUID
    plan_id: str
    scope_id: str
    effect_id: str
    sink: str
    operation: str
    tenant_id: str | None
    cost: Decimal
    state: str
    attempts: int
    reason: str | None
    lease_owner: str | None
    not_after: datetime
    enqueued_at: datetime
    next_attempt_at: datetime


def messages(
    source: object,
    *,
    state: str | None = None,
    scope_id: str | None = None,
    limit: int = 100,
) -> tuple[MessageView, ...]:
    """Messages, oldest first, optionally in one state or for one scope."""
    return reader(source).views(state=state, scope_id=scope_id, limit=limit)


def state_counts(source: object) -> dict[str, int]:
    """How many messages are in each state."""
    return reader(source).counts()


# --------------------------------------------------------------------------
# Operator actions. Run as the installer: the functions are granted to no role.
# --------------------------------------------------------------------------


def _operator(actor: str) -> str:
    if not actor:
        raise ValueError("an operator action names who took it")
    return f"operator:{actor}"


def release(conn: psycopg.Connection[Any], message_id: uuid.UUID, *, actor: str) -> bool:
    """Release a held message for delivery. ``False`` if it was not held."""
    row = conn.execute(
        "SELECT interlock.outbox_release(%s, %s)", (message_id, _operator(actor))
    ).fetchone()
    return bool(row and row[0])


def release_scope(conn: psycopg.Connection[Any], scope_id: str, *, actor: str) -> int:
    """Release every held message of a scope, oldest first. Returns how many."""
    row = conn.execute(
        "SELECT interlock.outbox_release_scope(%s, %s)", (scope_id, _operator(actor))
    ).fetchone()
    return int(row[0]) if row else 0


def cancel(
    conn: psycopg.Connection[Any], message_id: uuid.UUID, *, actor: str, reason: str
) -> bool:
    """Cancel a pending, held or dead message; the requests that wait for it
    die with it. ``False`` if it is being delivered, or was."""
    row = conn.execute(
        "SELECT interlock.outbox_cancel(%s, %s, %s)", (message_id, _operator(actor), reason)
    ).fetchone()
    return bool(row and row[0])


def requeue(conn: psycopg.Connection[Any], message_id: uuid.UUID, *, actor: str) -> int:
    """Send a dead message back for delivery with a fresh budget of attempts,
    and the requests that died waiting for it. Returns how many were
    requeued: none if it is not dead, or is past its deadline."""
    row = conn.execute(
        "SELECT interlock.outbox_requeue(%s, %s)", (message_id, _operator(actor))
    ).fetchone()
    return int(row[0]) if row else 0
