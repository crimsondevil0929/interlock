"""The outbox relay: delivers committed outbound requests (``docs/OUTBOX_DESIGN.md`` §7).

A relay is a separate process, under its own database role, holding the sink
credentials no agent ever sees (E4-1). It never opens a stage: it reads only
committed outbox rows, so nothing is sent before its plan commits (OB-7).

For each message it leases:

1. **Claim.** ``interlock.relay_claim`` leases due messages whose dependencies
   are delivered, ``FOR UPDATE SKIP LOCKED``: any number of relays share the
   work without waiting on each other, and no two hold the same message. Every
   claim takes the lease's next *fence*; a relay changes a message's state
   only under the fence it was leased with, so one whose lease ran out and
   was taken over cannot overwrite what its successor did.
2. **Re-check.** The payload is re-canonicalized from the stored ``jsonb`` and
   hashed: what is sent is exactly what was adjudicated (OB-2), or nothing is.
3. **Breaker.** AgentGov's breaker for the message's scope is read, fresh,
   immediately before the call. Tripped: the message is *held*, not sent,
   until an operator releases it. Unreadable: nothing is sent, and the message
   is deferred. Fail closed, both.
4. **Record, then call.** The call is recorded in the delivery log
   (``sending``, with the ledger position the breaker was read at) and
   committed *before* it is made. A relay that dies after this point leaves
   evidence that it may have called; one that dies before it provably did not.
5. **Record the outcome**, and the state it leads to: delivered; a retry,
   after :func:`retry_delay`; or dead, with the reason. One transaction.

A relay that dies mid-call leaves its lease to run out. The relay that takes
the message next records the call as ``lost`` (the sink may have acted) and,
for a sink whose ``unknown_outcome`` is ``"redeliver"``, calls again with the
same idempotency key: at least once. A sink that honours the key absorbs the
duplicate; one that does not acts twice, and the delivery log shows exactly
which call was lost. ``"dead-letter"`` makes it at most once instead.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Protocol

from agentgov.exceptions import UnknownScopeError
from agentgov.receipts.canonical import canonical_bytes, loads_strict

from interlock.anchor import _halted
from interlock.exceptions import SubstrateUnavailableError

if TYPE_CHECKING:
    import psycopg
    from agentgov.core import BudgetManager

__all__ = [
    "DELIVERED",
    "PERMANENT",
    "RETRYABLE",
    "UNKNOWN",
    "Breaker",
    "BreakerReading",
    "Delivery",
    "DeliveryResult",
    "Lease",
    "LedgerBreaker",
    "NoBreaker",
    "Relay",
    "RelayReport",
    "SinkAdapter",
    "retry_delay",
]

logger = logging.getLogger("interlock.relay")

DELIVERED: Final = "delivered"
"""The sink acted, and said so."""
RETRYABLE: Final = "retryable"
"""The sink did not act, and may if asked again: a 429, a 5xx, a refused
connection."""
PERMANENT: Final = "permanent"
"""The sink did not act, and will not: any other 4xx."""
UNKNOWN: Final = "unknown"
"""Nobody can say whether the sink acted: a timeout after the request was
sent, a connection lost before the response."""

_OUTCOMES: Final = frozenset({DELIVERED, RETRYABLE, PERMANENT, UNKNOWN})

HELD: Final = "held"
DEFERRED: Final = "deferred"
REFUSED: Final = "refused"
SKIPPED: Final = "skipped"
"""The lease was no longer this relay's when it came to act; it did nothing."""

_MARGIN: Final = 0.25
"""Seconds of lease kept back from a call's timeout, for recording its
outcome while the lease is still this relay's."""


# --------------------------------------------------------------------------
# What a relay sends, and what comes back
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Delivery:
    """One call to a sink, as the adapter makes it.

    :ivar payload: The request body: the canonical JSON bytes whose SHA-256
        is ``payload_hash``, the hash the checkers adjudicated.
    :ivar idempotency_key: The same for every call delivering this request, by
        any relay, after any crash. A sink that honours it acts once.
    :ivar timeout: Seconds the call may take, inside the relay's lease.
    """

    message_id: uuid.UUID
    sink: str
    operation: str
    idempotency_key: str
    payload: bytes
    payload_hash: str
    attempt: int
    tenant_id: str | None
    timeout: float


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """What a call returned, classified.

    :ivar outcome: :data:`DELIVERED`, :data:`RETRYABLE`, :data:`PERMANENT` or
        :data:`UNKNOWN`.
    :ivar response_digest: SHA-256 of the response body. The body itself is
        never stored: it may hold personal data.
    :ivar retry_after: The sink's ``Retry-After``, in seconds: the soonest the
        next call may be made.
    """

    outcome: str
    status_code: int | None = None
    response_digest: str | None = None
    detail: str = ""
    retry_after: float | None = None

    def __post_init__(self) -> None:
        if self.outcome not in _OUTCOMES:
            raise ValueError(f"{self.outcome!r} is not an outcome: one of {sorted(_OUTCOMES)}")


class SinkAdapter(Protocol):
    """Makes calls to one sink. Holds its endpoint and credentials; never sees
    the database. :class:`interlock.adapters.HttpAdapter` is the generic one.

    ``send`` should classify what it can and raise nothing it can classify;
    anything it raises is recorded as :data:`UNKNOWN`, since the call may
    have been made.
    """

    def send(self, delivery: Delivery) -> DeliveryResult: ...


# --------------------------------------------------------------------------
# The breaker
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BreakerReading:
    """The breaker for one scope, read at one ledger position.

    :ivar halted: Why the scope may not send, or ``None`` when it may.
    :ivar position: Where in the ledger it was read, recorded with the call
        it permits, so an audit can check that no halt preceded it.
    """

    halted: str | None
    position: str


class Breaker(Protocol):
    """Says whether a scope may send right now. Raising means it cannot say,
    and nothing is sent."""

    def check(self, scope_id: str) -> BreakerReading: ...


class LedgerBreaker:
    """AgentGov's circuit breaker, read fresh, before every call.

    Over a read-only view of the governor's ledger: the relay can follow the
    breaker and can write nothing to it. Each check catches the view up with
    the ledger, verifying what it reads, so a trip anywhere in the fleet
    committed before the check is seen by it. A scope AgentGov does not know
    is not one the relay may send for.
    """

    __slots__ = ("_manager", "_owned")

    def __init__(self, manager: BudgetManager, *, owned: bool = False) -> None:
        self._manager = manager
        self._owned = owned

    @classmethod
    def open(cls, ledger: str, *, schema: str = "agentgov") -> LedgerBreaker:
        """Open the governor's ledger read-only: a PostgreSQL connection
        string, or the path of a SQLite ledger."""
        from agentgov import BudgetManager

        if "://" in ledger or "=" in ledger:
            manager = BudgetManager.open_postgres(ledger, schema=schema, read_only=True)
        else:
            manager = BudgetManager.open_sqlite(ledger, read_only=True)
        return cls(manager, owned=True)

    def check(self, scope_id: str) -> BreakerReading:
        manager = self._manager
        manager.refresh()
        ledger = manager.ledger
        with ledger.lock:
            position = f"agentgov entry {len(ledger)}, head {ledger.head_hash[:16]}"
        try:
            manager.node(scope_id)
        except UnknownScopeError:
            return BreakerReading(
                halted=f"scope {scope_id!r} is not one AgentGov knows", position=position
            )
        halted = _halted(manager, scope_id)
        return BreakerReading(
            halted=None if halted is None else f"AgentGov has halted {halted}",
            position=position,
        )

    def close(self) -> None:
        if self._owned:
            self._manager.close()


class NoBreaker:
    """Every scope may send. For a deployment without AgentGov, and only when
    chosen explicitly: a relay never runs without a breaker by default."""

    __slots__ = ()

    def check(self, scope_id: str) -> BreakerReading:
        return BreakerReading(halted=None, position="no breaker")

    def close(self) -> None:
        return None


# --------------------------------------------------------------------------
# Retry
# --------------------------------------------------------------------------


def retry_delay(
    attempt: int,
    *,
    base: timedelta,
    cap: timedelta,
    key: str,
    retry_after: float | None = None,
) -> timedelta:
    """How long to wait after failed call number ``attempt`` before the next.

    Exponential: ``base``, doubling with each call, never above ``cap``. With
    jitter: the wait is drawn from the upper half of that, ``[d/2, d)``, so
    relays retrying a recovering sink arrive spread out rather than together,
    and none comes back sooner than half its backoff. The draw is a hash of
    the request's idempotency key and the call's number, not a random number:
    the same in a test, an audit and on every relay, and uncorrelated between
    requests. A sink's ``Retry-After`` is a floor.

    :raises ValueError: If ``attempt`` is not positive.
    """
    if attempt < 1:
        raise ValueError(f"calls are numbered from 1, not {attempt}")
    base_ms = max(1, int(base / timedelta(milliseconds=1)))
    cap_ms = max(base_ms, int(cap / timedelta(milliseconds=1)))
    ceiling = min(cap_ms, base_ms << min(attempt - 1, 62))
    draw = int.from_bytes(hashlib.sha256(f"{key}:{attempt}".encode()).digest()[:8], "big") / 2**64
    wait = timedelta(milliseconds=ceiling / 2 + ceiling / 2 * draw)
    if retry_after is not None and retry_after > 0:
        wait = max(wait, timedelta(seconds=retry_after))
    return wait


# --------------------------------------------------------------------------
# The relay
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lease:
    """A message leased to this relay by ``interlock.relay_claim``.

    :ivar fence: The lease's generation. The relay may change the message's
        state only under it.
    :ivar attempts: Calls made before this lease, by any relay.
    :ivar deadline: When the lease runs out, on this process's monotonic
        clock: taken before the claim, so never later than the database's.
    """

    message_id: uuid.UUID
    fence: int
    attempts: int
    attempt_floor: int
    plan_id: str
    scope_id: str
    effect_id: str
    sink: str
    operation: str
    tenant_id: str | None
    payload_text: str
    payload_hash: str
    idempotency_key: str
    not_after: datetime
    idempotency: str
    max_attempts: int
    backoff_base: timedelta
    backoff_cap: timedelta
    unknown_outcome: str
    lease_expires: datetime
    deadline: float

    @classmethod
    def from_row(cls, row: Sequence[Any], deadline: float) -> Lease:
        return cls(
            message_id=row[0],
            fence=int(row[1]),
            attempts=int(row[2]),
            attempt_floor=int(row[3]),
            plan_id=str(row[4]),
            scope_id=str(row[5]),
            effect_id=str(row[6]),
            sink=str(row[7]),
            operation=str(row[8]),
            tenant_id=None if row[9] is None else str(row[9]),
            payload_text=str(row[10]),
            payload_hash=str(row[11]),
            idempotency_key=str(row[12]),
            not_after=row[13],
            idempotency=str(row[14]),
            max_attempts=int(row[15]),
            backoff_base=timedelta(milliseconds=int(row[16])),
            backoff_cap=timedelta(milliseconds=int(row[17])),
            unknown_outcome=str(row[18]),
            lease_expires=row[19],
            deadline=deadline,
        )


@dataclass(frozen=True, slots=True)
class RelayReport:
    """What a relay did: messages claimed, and what became of each."""

    claimed: int = 0
    delivered: int = 0
    retrying: int = 0
    dead: int = 0
    held: int = 0
    deferred: int = 0
    refused: int = 0
    skipped: int = 0

    def __add__(self, other: RelayReport) -> RelayReport:
        return RelayReport(
            *(getattr(self, f) + getattr(other, f) for f in RelayReport.__dataclass_fields__)
        )

    def counted(self, result: str) -> RelayReport:
        field_ = {"pending": "retrying"}.get(result, result)
        if field_ not in RelayReport.__dataclass_fields__ or field_ == "claimed":
            field_ = "skipped"
        return replace(self, **{field_: getattr(self, field_) + 1})


class Relay:
    """Delivers committed outbound requests, at least once (see the module).

    One relay is one worker: one connection, one breaker, one call at a time.
    Run as many as throughput needs, in any number of processes and hosts;
    they share the work through ``FOR UPDATE SKIP LOCKED`` and never wait on
    each other.

    :param dsn: A connection string for a relay role (``relay_roles`` at
        install): it can read the outbox and call the relay functions, and
        nothing else.
    :param adapters: One per sink this relay delivers to. It claims only
        messages for these sinks.
    :param breaker: Read before every call. :class:`LedgerBreaker` for
        AgentGov; :class:`NoBreaker` only by explicit choice.
    :param lease: How long a claimed message is this relay's. At least twice
        ``timeout``, so a call that takes its whole timeout still leaves the
        lease time to record its outcome.
    :param timeout: The most one call may take.
    :param batch: Messages claimed at once. Each is delivered in turn, under
        the same lease, so a large batch needs a long lease.
    :param breaker_retry: How soon a message is tried again when the breaker
        could not be read.
    :raises ValueError: On a lease shorter than twice the timeout, or no
        adapters.
    :raises SubstrateUnavailableError: If the database cannot be reached.
    """

    __slots__ = (
        "_adapters",
        "_batch",
        "_breaker",
        "_breaker_retry",
        "_conn",
        "_dsn",
        "_lease",
        "_relay_id",
        "_timeout",
    )

    def __init__(
        self,
        dsn: str,
        *,
        adapters: Mapping[str, SinkAdapter],
        breaker: Breaker,
        relay_id: str | None = None,
        lease: timedelta = timedelta(seconds=60),
        timeout: timedelta = timedelta(seconds=10),
        batch: int = 1,
        breaker_retry: timedelta = timedelta(seconds=5),
    ) -> None:
        if not adapters:
            raise ValueError("a relay needs an adapter for at least one sink")
        if timeout <= timedelta(0) or lease < 2 * timeout:
            raise ValueError(
                f"the lease ({lease}) must be at least twice the call timeout ({timeout}), "
                f"so a call that times out leaves the lease time to record it"
            )
        if batch < 1:
            raise ValueError("a relay claims at least one message at a time")
        self._dsn = dsn
        self._adapters = dict(adapters)
        self._breaker = breaker
        self._relay_id = (
            relay_id or f"relay:{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        )
        self._lease = lease
        self._timeout = timeout
        self._batch = batch
        self._breaker_retry = breaker_retry
        self._conn: psycopg.Connection[Any] | None = None
        self._connect()

    @property
    def relay_id(self) -> str:
        """This relay's name in leases and the delivery log. Not a
        credential: the database role is what is trusted."""
        return self._relay_id

    def _connect(self) -> psycopg.Connection[Any]:
        import psycopg

        if self._conn is not None:
            try:
                self._conn.close()
            except psycopg.Error:
                pass
        try:
            conn = psycopg.connect(self._dsn, autocommit=True, application_name="interlock-relay")
            conn.execute("SET statement_timeout = '30s'")
            conn.execute("SET lock_timeout = '10s'")
            conn.execute("SET idle_in_transaction_session_timeout = '60s'")
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"the relay cannot reach its database: {exc}") from exc
        self._conn = conn
        return conn

    def _connection(self) -> psycopg.Connection[Any]:
        if self._conn is None or self._conn.closed:
            return self._connect()
        return self._conn

    def close(self) -> None:
        """Close the connection. Leases this relay holds run out on their own."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Relay:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- running -------------------------------------------------------------

    def run_once(self, limit: int | None = None) -> RelayReport:
        """Claim up to ``limit`` due messages (the relay's batch by default),
        and deliver each in turn.

        :raises SubstrateUnavailableError: If the database is lost. Leases
            held then run out, and another relay, or this one later, takes
            the messages over.
        """
        import psycopg

        try:
            leases = self._claim(limit or self._batch)
            report = RelayReport(claimed=len(leases))
            for lease in leases:
                report = report.counted(self._deliver(lease))
        except psycopg.OperationalError as exc:
            self.close()
            raise SubstrateUnavailableError(f"the relay lost its database: {exc}") from exc
        return report

    def run(self, stop: threading.Event, *, poll: float = 1.0) -> RelayReport:
        """Deliver until ``stop`` is set, polling every ``poll`` seconds when
        there is nothing due. Survives losing the database: it waits, and
        reconnects.

        :returns: Everything this run did.
        """
        total = RelayReport()
        backoff = poll
        while not stop.is_set():
            try:
                report = self.run_once()
            except SubstrateUnavailableError:
                logger.warning("relay %s: database unavailable; retrying", self._relay_id)
                stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = poll
            total = total + report
            if report.claimed == 0:
                stop.wait(poll)
        return total

    # -- one message -----------------------------------------------------------

    def _claim(self, limit: int) -> list[Lease]:
        conn = self._connection()
        seconds = self._lease.total_seconds()
        deadline = time.monotonic() + seconds
        with conn.transaction():
            rows = conn.execute(
                "SELECT * FROM interlock.relay_claim(%s, %s, %s, %s)",
                (self._relay_id, seconds, limit, sorted(self._adapters)),
            ).fetchall()
            self._reached("claim-uncommitted", None)
        leases = [Lease.from_row(row, deadline) for row in rows]
        return leases

    def _deliver(self, lease: Lease) -> str:
        """Deliver one leased message. Returns what became of it: the state it
        moved to, or :data:`HELD`, :data:`DEFERRED`, :data:`REFUSED`, or
        :data:`SKIPPED` when the lease was no longer this relay's."""
        self._reached("claimed", lease)
        payload = _verified_payload(lease)
        if payload is None:
            return self._refuse(
                lease,
                "the stored payload does not hash to the payload the plan was adjudicated with",
            )
        adapter = self._adapters[lease.sink]
        try:
            reading = self._breaker.check(lease.scope_id)
        except Exception as exc:
            return self._defer(
                lease,
                f"the breaker could not be read, so nothing was sent: {type(exc).__name__}: {exc}",
                self._breaker_retry,
            )
        if reading.halted is not None:
            return self._hold(lease, f"{reading.halted}, at {reading.position}")
        self._reached("checked", lease)
        remaining = lease.deadline - time.monotonic() - _MARGIN
        if remaining <= 0:
            return self._defer(lease, "the lease ran short before the call", timedelta(0))
        attempt = self._sending(lease, f"breaker clear at {reading.position}")
        if attempt is None:
            return SKIPPED
        self._reached("sending", lease)
        delivery = Delivery(
            message_id=lease.message_id,
            sink=lease.sink,
            operation=lease.operation,
            idempotency_key=lease.idempotency_key,
            payload=payload,
            payload_hash=lease.payload_hash,
            attempt=attempt,
            tenant_id=lease.tenant_id,
            timeout=min(self._timeout.total_seconds(), remaining),
        )
        try:
            result = adapter.send(delivery)
        except Exception as exc:
            result = DeliveryResult(
                UNKNOWN, detail=f"the adapter raised {type(exc).__name__}: {exc}"
            )
        self._reached("called", lease)
        delay = (
            retry_delay(
                attempt - lease.attempt_floor,
                base=lease.backoff_base,
                cap=lease.backoff_cap,
                key=lease.idempotency_key,
                retry_after=result.retry_after,
            )
            if result.outcome in (RETRYABLE, UNKNOWN)
            else timedelta(0)
        )
        state = self._outcome(lease, attempt, result, delay)
        self._reached("recorded", lease)
        return state if state is not None else SKIPPED

    def _sending(self, lease: Lease, detail: str) -> int | None:
        conn = self._connection()
        with conn.transaction():
            row = conn.execute(
                "SELECT interlock.relay_sending(%s, %s, %s, %s)",
                (lease.message_id, self._relay_id, lease.fence, detail),
            ).fetchone()
            self._reached("sending-uncommitted", lease)
        return None if row is None or row[0] is None else int(row[0])

    def _outcome(
        self, lease: Lease, attempt: int, result: DeliveryResult, delay: timedelta
    ) -> str | None:
        """Record what the call returned. The call already happened, so this
        is retried through a lost connection: a reply lost after the commit
        finds the outcome already recorded, which is success."""
        import psycopg

        for tries in range(3):
            try:
                conn = self._connection()
                with conn.transaction():
                    row = conn.execute(
                        "SELECT interlock.relay_outcome(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            lease.message_id,
                            self._relay_id,
                            lease.fence,
                            attempt,
                            result.outcome,
                            result.status_code,
                            result.response_digest,
                            result.detail or None,
                            int(delay / timedelta(milliseconds=1)),
                        ),
                    ).fetchone()
                    self._reached("outcome-uncommitted", lease)
                return None if row is None or row[0] is None else str(row[0])
            except psycopg.OperationalError:
                if tries == 2:
                    raise
                logger.warning(
                    "relay %s: lost the database recording message %s, attempt %d; retrying",
                    self._relay_id,
                    lease.message_id,
                    attempt,
                )
                self._connect()
            except psycopg.Error as exc:
                if getattr(exc, "sqlstate", None) == "IL002" and "already has an outcome" in str(
                    exc
                ):
                    return None
                raise
        return None  # pragma: no cover - the loop returns or raises

    def _hold(self, lease: Lease, reason: str) -> str:
        return HELD if self._fenced("relay_hold", lease, reason) else SKIPPED

    def _refuse(self, lease: Lease, reason: str) -> str:
        logger.error("relay %s: refusing message %s: %s", self._relay_id, lease.message_id, reason)
        return REFUSED if self._fenced("relay_refuse", lease, reason) else SKIPPED

    def _defer(self, lease: Lease, reason: str, delay: timedelta) -> str:
        conn = self._connection()
        with conn.transaction():
            row = conn.execute(
                "SELECT interlock.relay_defer(%s, %s, %s, %s, %s)",
                (
                    lease.message_id,
                    self._relay_id,
                    lease.fence,
                    reason,
                    int(delay / timedelta(milliseconds=1)),
                ),
            ).fetchone()
        return DEFERRED if row is not None and row[0] else SKIPPED

    def _fenced(self, function: str, lease: Lease, reason: str) -> bool:
        conn = self._connection()
        with conn.transaction():
            row = conn.execute(
                f"SELECT interlock.{function}(%s, %s, %s, %s)",
                (lease.message_id, self._relay_id, lease.fence, reason),
            ).fetchone()
        return bool(row is not None and row[0])

    def _reached(self, point: str, lease: Lease | None) -> None:
        """A point on the delivery path. Nothing happens here; the crash tests
        (``tests/relay_child.py``) stop the process at each one."""


def _verified_payload(lease: Lease) -> bytes | None:
    """The bytes to send, if the stored payload still hashes to the hash the
    plan was adjudicated with; ``None`` if it does not."""
    try:
        payload = canonical_bytes(loads_strict(lease.payload_text))
    except Exception:
        return None
    if hashlib.sha256(payload).hexdigest() != lease.payload_hash:
        return None
    return payload
