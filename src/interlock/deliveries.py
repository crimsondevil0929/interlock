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
import json
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final, Protocol

from agentgov.receipts.canonical import loads_strict

from interlock.exceptions import OutboundRequestError

if TYPE_CHECKING:
    import psycopg

__all__ = [
    "ACTION_EVENTS",
    "OPERATOR_EVENTS",
    "AuthorizedRow",
    "Compensable",
    "LogEvent",
    "LoggedMessage",
    "MessageView",
    "OutboxOperations",
    "OutboxReader",
    "PostgresOperations",
    "PostgresReader",
    "cancel",
    "compensate",
    "event_hash",
    "frame",
    "genesis_hash",
    "message_log",
    "messages",
    "operations",
    "parse_instant",
    "reader",
    "registry_digest",
    "release",
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

ACTION_EVENTS: Final = {
    "release": "released",
    "cancel": "cancelled",
    "requeue": "requeued",
    "compensate": "compensated",
}
"""Each operator action, and the delivery-log event it writes."""
OPERATOR_EVENTS: Final = frozenset(ACTION_EVENTS.values())
"""Events only an operator writes, each under a signed intent's authority
(schema version 3; docs/EPIC3_DESIGN.md §6)."""


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
    "detail, state_after, prev_hash, event_hash, {extra} "
    "FROM interlock.outbox_attempts "
    "WHERE %(ids)s::uuid[] IS NULL OR message_id = ANY (%(ids)s::uuid[]) "
    "ORDER BY message_id, seq"
)
_EXTRA_V3: Final = "remote_ref, authority"
_EXTRA_V2: Final = "NULL::text, NULL::text"
"""Version 2 had neither column; its logs are read, and verified, as they are
before an upgrade."""

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
        remote_ref=_text(row[12]),
        authority=_text(row[13]),
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

    def epoch(self) -> datetime | None:
        """When schema version 3 was first installed: an operator's row without
        an authority older than this is version 2's."""
        ...

    def registry(self) -> list[dict[str, Any]]:
        """Every sink as the database mirrors it, every column, in one form
        for both stores: what a signed install vouches for."""
        ...


def registry_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    """A digest of a sink registry as :meth:`OutboxReader.registry` reads it."""
    from interlock.types import canonical_hash

    ordered = sorted(rows, key=lambda row: str(row["name"]))
    return canonical_hash([dict(row) for row in ordered])


_REGISTRY_COLUMNS: Final = (
    "name",
    "kind",
    "operations",
    "cost_per_call",
    "idempotency",
    "max_payload_bytes",
    "not_after_seconds",
    "max_attempts",
    "backoff_base_ms",
    "backoff_cap_ms",
    "unknown_outcome",
    "config_hash",
    "enabled",
)


def _registry_row(values: Sequence[Any]) -> dict[str, Any]:
    row = dict(zip(_REGISTRY_COLUMNS, values, strict=True))
    operations = row["operations"]
    row["operations"] = sorted(
        json.loads(operations) if isinstance(operations, str) else operations
    )
    for key in (
        "max_payload_bytes",
        "not_after_seconds",
        "max_attempts",
        "backoff_base_ms",
        "backoff_cap_ms",
    ):
        row[key] = int(row[key])
    row["enabled"] = bool(row["enabled"])
    for key in ("name", "kind", "cost_per_call", "idempotency", "unknown_outcome", "config_hash"):
        row[key] = str(row[key])
    return row


@dataclass(frozen=True, slots=True)
class AuthorizedRow:
    """A delivery-log row an operator's intent wrote: it carries its authority."""

    message_id: uuid.UUID
    seq: int
    event: str
    event_hash: str


@dataclass(frozen=True, slots=True)
class Compensable:
    """A message of a plan, as compensating it needs it read."""

    message_id: uuid.UUID
    plan_id: str
    stage_id: uuid.UUID
    effect_id: str
    depends_on: tuple[str, ...]
    state: str
    not_after: datetime
    log_head: str
    compensation: Mapping[str, Any] | None
    """The request that undoes this one, as the plan carried it."""
    remote_ref: str | None
    """What its delivered call created, as the delivery log recorded it."""
    compensated_by: uuid.UUID | None
    """The compensation already enqueued for it."""
    compensates: uuid.UUID | None
    """The message this one is the compensation of."""


class OutboxOperations(OutboxReader, Protocol):
    """An operator's actions, on either store. Each writes its delivery-log
    rows under ``authority``, the hash of the operator's signed intent, and
    only while the message's log is at ``expected_head``: ``False`` (or 0)
    when the message is not in a state the action applies to, or its log
    moved. :class:`interlock.operators.Operator` is what calls them."""

    def heads(self, message_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]: ...

    def authorized(self, authority: str) -> list[AuthorizedRow]:
        """The rows that carry ``authority``, in log order."""
        ...

    def held(self, scope_id: str) -> list[uuid.UUID]:
        """The held messages of a scope, oldest first."""
        ...

    def plan_of(self, message_id: uuid.UUID) -> str | None: ...

    def compensables(self, plan_id: str) -> list[Compensable]: ...

    def release(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> bool: ...

    def cancel(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        reason: str,
        authority: str,
        expected_head: str,
    ) -> bool: ...

    def requeue(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> int: ...

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
    ) -> bool: ...


class PostgresReader:
    """An :class:`OutboxReader` over a PostgreSQL connection."""

    __slots__ = ("_conn",)

    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        self._conn = conn

    @contextmanager
    def _one_snapshot(self) -> Iterator[None]:
        """Read messages and logs as of one instant: a relay committing between
        the two reads would otherwise show a log ahead of its head."""
        from psycopg.pq import TransactionStatus

        if self._conn.info.transaction_status != TransactionStatus.IDLE:
            yield  # the caller's transaction, and its snapshot
            return
        with self._conn.transaction():
            self._conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            yield

    def _events(self) -> str:
        row = self._conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute "
            "WHERE attrelid = pg_catalog.to_regclass('interlock.outbox_attempts') "
            "AND attname = 'remote_ref' AND NOT attisdropped)"
        ).fetchone()
        return _EVENTS.format(extra=_EXTRA_V3 if row is not None and row[0] else _EXTRA_V2)

    def snapshot(
        self, message_ids: Sequence[uuid.UUID] | None
    ) -> tuple[list[LoggedMessage], list[LogEvent]]:
        params = {"ids": None if message_ids is None else list(message_ids)}
        with self._one_snapshot():
            return self._read(params)

    def _read(self, params: dict[str, Any]) -> tuple[list[LoggedMessage], list[LogEvent]]:
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
        events = [_event(row) for row in self._conn.execute(self._events(), params)]
        return found, events

    def epoch(self) -> datetime | None:
        row = self._conn.execute(
            "SELECT CASE WHEN pg_catalog.to_regclass('interlock.outbox_epochs') IS NULL "
            "THEN NULL ELSE (SELECT at FROM interlock.outbox_epochs WHERE version = '3') END"
        ).fetchone()
        return None if row is None else row[0]

    def registry(self) -> list[dict[str, Any]]:
        return [
            _registry_row(r)
            for r in self._conn.execute(
                "SELECT name, kind, operations, cost_per_call, idempotency, max_payload_bytes, "
                "not_after_seconds, max_attempts, backoff_base_ms, backoff_cap_ms, "
                "unknown_outcome, config_hash, enabled FROM interlock.sinks ORDER BY name"
            )
        ]

    def heads(self, message_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]:
        return {
            r[0]: str(r[1])
            for r in self._conn.execute(
                "SELECT message_id, log_head FROM interlock.outbox_state "
                "WHERE message_id = ANY (%s::uuid[])",
                (list(message_ids),),
            )
        }

    def authorized(self, authority: str) -> list[AuthorizedRow]:
        return [
            AuthorizedRow(r[0], int(r[1]), str(r[2]), str(r[3]))
            for r in self._conn.execute(
                "SELECT message_id, seq, event, event_hash FROM interlock.outbox_attempts "
                "WHERE authority = %s ORDER BY message_id, seq",
                (authority,),
            )
        ]

    def held(self, scope_id: str) -> list[uuid.UUID]:
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT o.message_id FROM interlock.outbox o "
                "JOIN interlock.outbox_state s USING (message_id) "
                "WHERE o.scope_id = %s AND s.state = 'held' ORDER BY o.enqueued_at, o.seq",
                (scope_id,),
            )
        ]

    def plan_of(self, message_id: uuid.UUID) -> str | None:
        row = self._conn.execute(
            "SELECT plan_id FROM interlock.outbox WHERE message_id = %s", (message_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def compensables(self, plan_id: str) -> list[Compensable]:
        return [
            Compensable(
                message_id=r[0],
                plan_id=str(r[1]),
                stage_id=r[2],
                effect_id=str(r[3]),
                depends_on=tuple(r[4]),
                state=str(r[5]),
                not_after=r[6],
                log_head=str(r[7]),
                compensation=None if r[8] is None else loads_strict(str(r[8])),
                remote_ref=_text(r[9]),
                compensated_by=r[10],
                compensates=r[11],
            )
            for r in self._conn.execute(
                "SELECT o.message_id, o.plan_id, o.stage_id, o.effect_id, o.depends_on, "
                "s.state, o.not_after, s.log_head, o.compensation::text, "
                "(SELECT a.remote_ref FROM interlock.outbox_attempts a "
                " WHERE a.message_id = o.message_id AND a.event = 'delivered' "
                " ORDER BY a.seq DESC LIMIT 1), "
                "(SELECT c.message_id FROM interlock.outbox c WHERE c.compensates = o.message_id), "
                "o.compensates "
                "FROM interlock.outbox o JOIN interlock.outbox_state s USING (message_id) "
                "WHERE o.plan_id = %s ORDER BY o.seq",
                (plan_id,),
            )
        ]

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
    return actor if actor.startswith("operator:") else f"operator:{actor}"


def release(
    conn: psycopg.Connection[Any],
    message_id: uuid.UUID,
    *,
    actor: str,
    authority: str,
    expected_head: str,
) -> bool:
    """Release a held message for delivery. ``False`` if it was not held, or
    its log moved past ``expected_head``."""
    row = conn.execute(
        "SELECT interlock.outbox_release(%s, %s, %s, %s)",
        (message_id, _operator(actor), authority, expected_head),
    ).fetchone()
    return bool(row and row[0])


def cancel(
    conn: psycopg.Connection[Any],
    message_id: uuid.UUID,
    *,
    actor: str,
    reason: str,
    authority: str,
    expected_head: str,
) -> bool:
    """Cancel a pending, held or dead message; the requests that wait for it
    die with it. ``False`` if it is being delivered, or was, or its log moved."""
    row = conn.execute(
        "SELECT interlock.outbox_cancel(%s, %s, %s, %s, %s)",
        (message_id, _operator(actor), reason, authority, expected_head),
    ).fetchone()
    return bool(row and row[0])


def requeue(
    conn: psycopg.Connection[Any],
    message_id: uuid.UUID,
    *,
    actor: str,
    authority: str,
    expected_head: str,
) -> int:
    """Send a dead message back for delivery with a fresh budget of attempts,
    and the requests that died waiting for it. Returns how many were
    requeued: none if it is not dead, is past its deadline, or its log moved."""
    row = conn.execute(
        "SELECT interlock.outbox_requeue(%s, %s, %s, %s)",
        (message_id, _operator(actor), authority, expected_head),
    ).fetchone()
    return int(row[0]) if row else 0


def compensate(
    conn: psycopg.Connection[Any],
    original: uuid.UUID,
    *,
    actor: str,
    authority: str,
    expected_head: str,
    message_id: uuid.UUID,
    payload: bytes,
    idempotency_key: str,
) -> bool:
    """Enqueue the compensation ``original`` carried, as ``message_id``, with
    ``payload``: the compensation's own, its placeholder bound to what the
    original's delivery created, as canonical bytes. ``False`` if the original
    is not delivered, carries no compensation, has nothing to bind its
    placeholder to, or its log moved.

    :raises OutboundRequestError: If the payload is not that compensation, its
        sink refuses it, or the original was compensated already.
    """
    import psycopg

    try:
        row = conn.execute(
            "SELECT interlock.outbox_compensate(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                original,
                _operator(actor),
                authority,
                expected_head,
                message_id,
                payload.decode("utf-8"),
                hashlib.sha256(payload).hexdigest(),
                idempotency_key,
            ),
        ).fetchone()
    except psycopg.errors.UniqueViolation as exc:
        raise OutboundRequestError(
            f"message {original} was compensated already: a compensation is enqueued once",
            reason="duplicate",
        ) from exc
    except psycopg.Error as exc:
        if getattr(exc, "sqlstate", None) != "IL004":
            raise
        detail = getattr(getattr(exc, "diag", None), "message_detail", None) or "{}"
        reason = str(json.loads(detail).get("reason", "compensation"))
        raise OutboundRequestError(str(exc), reason=reason) from exc
    return bool(row and row[0])


class PostgresOperations(PostgresReader):
    """:class:`OutboxOperations` over a PostgreSQL connection as the installer."""

    __slots__ = ()

    def release(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> bool:
        return release(
            self._conn, message_id, actor=actor, authority=authority, expected_head=expected_head
        )

    def cancel(
        self,
        message_id: uuid.UUID,
        *,
        actor: str,
        reason: str,
        authority: str,
        expected_head: str,
    ) -> bool:
        return cancel(
            self._conn,
            message_id,
            actor=actor,
            reason=reason,
            authority=authority,
            expected_head=expected_head,
        )

    def requeue(
        self, message_id: uuid.UUID, *, actor: str, authority: str, expected_head: str
    ) -> int:
        return requeue(
            self._conn, message_id, actor=actor, authority=authority, expected_head=expected_head
        )

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
        return compensate(
            self._conn,
            original,
            actor=actor,
            authority=authority,
            expected_head=expected_head,
            message_id=message_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )


def operations(source: object) -> OutboxOperations:
    """``source`` as :class:`OutboxOperations`: a SQLite store opened with
    ``writes=OPERATOR`` already is; a PostgreSQL connection, as the installer,
    is wrapped."""
    if hasattr(source, "compensate"):
        return source  # type: ignore[return-value]
    return PostgresOperations(source)  # type: ignore[arg-type]
