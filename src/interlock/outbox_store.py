"""Where the relay keeps delivery state: the outbox store (``docs/EPIC3_DESIGN.md`` §1).

The relay decides; the store records. :class:`interlock.relay.Relay` reads a
message's payload, checks the breaker and calls the sink. Every change it makes
to a message, a lease taken, a call recorded, an outcome, a hold, goes through
an :class:`OutboxStore`, which applies it under the message's fence and
appends it to the message's delivery log in the same transaction.

Two stores keep one state machine:

- :class:`PostgresOutboxStore`, over the ``relay_*`` functions installed in the
  ``interlock`` schema (Epic 2): claims with ``FOR UPDATE SKIP LOCKED``, the
  relay role writing nothing directly.
- :class:`interlock.sqlite_outbox.SqliteOutboxStore`, the same transitions in
  Python inside ``BEGIN IMMEDIATE``, serialized by SQLite's one write lock.

Every relay test runs against both, which is what keeps them one machine.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Protocol

from interlock.exceptions import SubstrateConfigurationError, SubstrateUnavailableError

if TYPE_CHECKING:
    import psycopg

    from interlock.relay import DeliveryResult, Lease

__all__ = ["Checkpoint", "OutboxStore", "PostgresOutboxStore"]

logger = logging.getLogger("interlock.outbox_store")

Checkpoint = Callable[[str, "Lease | None"], None]
"""Called at named points inside a store's transactions; the crash tests stop
the process there. Does nothing in production."""


def _no_checkpoint(point: str, lease: Lease | None) -> None:
    return None


class OutboxStore(Protocol):
    """The relay's view of the outbox: one message's state, changed only
    under the fence the message was leased with.

    Every method that changes state returns what it did, or ``None`` /
    ``False`` when the lease was no longer the caller's: then it did nothing,
    except record a delivered outcome, which is the truth whoever holds the
    lease.

    :raises SubstrateUnavailableError: From any method, when the database
        cannot be reached or (SQLite) stays locked past the busy timeout.
        Nothing was changed.
    """

    checkpoint: Checkpoint

    def claim(
        self, relay_id: str, lease: timedelta, limit: int, sinks: Sequence[str], deadline: float
    ) -> list[Lease]:
        """Lease up to ``limit`` due messages for these sinks."""
        ...

    def sending(self, lease: Lease, relay_id: str, detail: str) -> int | None:
        """Record the call about to be made; its attempt number, or ``None``
        when the call must not be made."""
        ...

    def outcome(
        self,
        lease: Lease,
        relay_id: str,
        attempt: int,
        result: DeliveryResult,
        delay: timedelta,
        attestation: str,
    ) -> str | None:
        """Record what a call returned, with the relay's signed attestation of
        it; the state the message is now in, or ``None`` when it was no longer
        this relay's to change."""
        ...

    def hold(self, lease: Lease, relay_id: str, reason: str) -> bool: ...

    def defer(self, lease: Lease, relay_id: str, reason: str, delay: timedelta) -> bool: ...

    def refuse(self, lease: Lease, relay_id: str, reason: str) -> bool: ...

    def close(self) -> None: ...


def milliseconds(span: timedelta) -> int:
    return int(span / timedelta(milliseconds=1))


class PostgresOutboxStore:
    """The outbox in PostgreSQL, through the relay functions.

    :param dsn: A connection string for a relay role (``relay_roles`` at
        install): it can read the outbox and call the relay functions, and
        nothing else.
    :raises SubstrateUnavailableError: If the database cannot be reached.
    """

    __slots__ = ("_conn", "_dsn", "checkpoint")

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._conn: psycopg.Connection[Any] | None = None
        self.checkpoint: Checkpoint = _no_checkpoint
        self._connect()

    def _connect(self) -> psycopg.Connection[Any]:
        import psycopg

        if self._conn is not None:
            try:
                self._conn.close()
            except psycopg.Error:
                pass
        from interlock.postgres import INSTALL_VERSION, installed_version

        try:
            conn = psycopg.connect(self._dsn, autocommit=True, application_name="interlock-relay")
            conn.execute("SET statement_timeout = '30s'")
            conn.execute("SET lock_timeout = '10s'")
            conn.execute("SET idle_in_transaction_session_timeout = '60s'")
            current = installed_version(conn) >= int(INSTALL_VERSION)
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"the relay cannot reach its database: {exc}") from exc
        if not current:
            conn.close()
            raise SubstrateConfigurationError(
                "the outbox in the relay's database was installed by an older version: run "
                "`interlock install` to upgrade it (stop every relay first)"
            )
        self._conn = conn
        return conn

    def connection(self) -> psycopg.Connection[Any]:
        """The live connection, reconnecting if it was lost."""
        if self._conn is None or self._conn.closed:
            return self._connect()
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _lost(self, exc: Exception) -> SubstrateUnavailableError:
        self.close()
        return SubstrateUnavailableError(f"the relay lost its database: {exc}")

    def claim(
        self, relay_id: str, lease: timedelta, limit: int, sinks: Sequence[str], deadline: float
    ) -> list[Lease]:
        import psycopg

        from interlock.relay import Lease

        try:
            conn = self.connection()
            with conn.transaction():
                rows = conn.execute(
                    "SELECT * FROM interlock.relay_claim(%s, %s, %s, %s)",
                    (relay_id, lease.total_seconds(), limit, sorted(sinks)),
                ).fetchall()
                self.checkpoint("claim-uncommitted", None)
        except psycopg.OperationalError as exc:
            raise self._lost(exc) from exc
        return [Lease.from_row(row, deadline) for row in rows]

    def sending(self, lease: Lease, relay_id: str, detail: str) -> int | None:
        import psycopg

        try:
            conn = self.connection()
            with conn.transaction():
                row = conn.execute(
                    "SELECT interlock.relay_sending(%s, %s, %s, %s)",
                    (lease.message_id, relay_id, lease.fence, detail),
                ).fetchone()
                self.checkpoint("sending-uncommitted", lease)
        except psycopg.OperationalError as exc:
            raise self._lost(exc) from exc
        return None if row is None or row[0] is None else int(row[0])

    def outcome(
        self,
        lease: Lease,
        relay_id: str,
        attempt: int,
        result: DeliveryResult,
        delay: timedelta,
        attestation: str,
    ) -> str | None:
        """Record what the call returned. The call already happened, so this
        is retried through a lost connection: a reply lost after the commit
        finds the outcome already recorded, which is success."""
        import psycopg

        for tries in range(3):
            try:
                conn = self.connection()
                with conn.transaction():
                    row = conn.execute(
                        "SELECT interlock.relay_outcome("
                        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            lease.message_id,
                            relay_id,
                            lease.fence,
                            attempt,
                            result.outcome,
                            result.status_code,
                            result.response_digest,
                            result.detail or None,
                            milliseconds(delay),
                            result.remote_ref,
                            attestation,
                        ),
                    ).fetchone()
                    self.checkpoint("outcome-uncommitted", lease)
                return None if row is None or row[0] is None else str(row[0])
            except psycopg.OperationalError as exc:
                if tries == 2:
                    raise self._lost(exc) from exc
                logger.warning(
                    "relay %s: lost the database recording message %s, attempt %d; retrying",
                    relay_id,
                    lease.message_id,
                    attempt,
                )
                time.sleep(0.05 * (tries + 1))
                self._conn = None
            except psycopg.Error as exc:
                if getattr(exc, "sqlstate", None) == "IL002" and "already has an outcome" in str(
                    exc
                ):
                    return None
                raise
        return None  # pragma: no cover - the loop returns or raises

    def hold(self, lease: Lease, relay_id: str, reason: str) -> bool:
        return self._fenced("relay_hold", lease, relay_id, reason)

    def refuse(self, lease: Lease, relay_id: str, reason: str) -> bool:
        return self._fenced("relay_refuse", lease, relay_id, reason)

    def defer(self, lease: Lease, relay_id: str, reason: str, delay: timedelta) -> bool:
        import psycopg

        try:
            conn = self.connection()
            with conn.transaction():
                row = conn.execute(
                    "SELECT interlock.relay_defer(%s, %s, %s, %s, %s)",
                    (lease.message_id, relay_id, lease.fence, reason, milliseconds(delay)),
                ).fetchone()
        except psycopg.OperationalError as exc:
            raise self._lost(exc) from exc
        return bool(row is not None and row[0])

    def _fenced(self, function: str, lease: Lease, relay_id: str, reason: str) -> bool:
        import psycopg

        try:
            conn = self.connection()
            with conn.transaction():
                row = conn.execute(
                    f"SELECT interlock.{function}(%s, %s, %s, %s)",
                    (lease.message_id, relay_id, lease.fence, reason),
                ).fetchone()
        except psycopg.OperationalError as exc:
            raise self._lost(exc) from exc
        return bool(row is not None and row[0])
