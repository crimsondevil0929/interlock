"""Nodes of a cluster, and the roles one node holds at a time (``docs/EPIC9_DESIGN.md`` §1).

A daemon in a cluster is a *node*. Its session, one PostgreSQL connection of
its own, holds the node's lock for as long as the process lives, and every role
the node leads: session-level advisory locks, which end with the session. So
the database alone decides when a node is gone, by ending its session. A killed
process's ends at once, its sockets closed by the kernel; a frozen one's, or
one lost to the network, once it has been silent for ``session_timeout``, which
the server enforces (``idle_session_timeout``)::

    node = ClusterNode(dsn, "interlock-0", heartbeat=1.0, session_timeout=10.0)
    node.join()                        # the node's lock: before anything recovers
    vacuum = node.leadership("vacuum")
    if vacuum.lead():                  # this node leads the role now
        ...
    node.heartbeat()                   # every second: alive, and still holding its locks
    node.leave()

Leadership decides which node works, never what keeps the work correct. A
leader that pauses past its session's bound loses the role while its step
still runs, and for that step another node may lead too: what a part that
follows a role does is safe under concurrency on its own (§1.2).

A transaction-mode pooler cannot carry the session: it hands a session's locks
to whoever runs on it next. The session reaches the server directly, or
through a pooler in session mode. Every other connection may go through one.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
import time
from collections import Counter
from typing import TYPE_CHECKING, Any, Final

from interlock.exceptions import NodeTakenError, SubstrateUnavailableError

if TYPE_CHECKING:
    import psycopg

    from interlock.telemetry import Metrics

__all__ = [
    "LEADER_LOCK",
    "NODE_LOCK",
    "NODE_NAME",
    "ClusterNode",
    "Leadership",
    "connection_name",
    "lock_key",
]

logger = logging.getLogger("interlock.cluster")

NODE_LOCK: Final = 1229737818
"""The advisory lock class of the nodes: ``(NODE_LOCK, lock_key("node", name))``."""
LEADER_LOCK: Final = 1229737819
"""The advisory lock class of the roles: ``(LEADER_LOCK, lock_key("role", role))``.
Interlock's keys lock (``docs/EPIC8_DESIGN.md`` §2.3) is ``(1229737817, 8)``."""

NODE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
"""What a node may be called: a Kubernetes pod's name fits."""

_HELD: Final = (
    "SELECT classid::bigint, objid::bigint FROM pg_catalog.pg_locks "
    "WHERE locktype = 'advisory' AND pid = pg_catalog.pg_backend_pid() "
    "AND objsubid = 2 AND granted"
)
_HOLDER: Final = (
    "SELECT a.pid, a.application_name, a.backend_start FROM pg_catalog.pg_locks AS l "
    "JOIN pg_catalog.pg_stat_activity AS a ON a.pid = l.pid "
    "WHERE l.locktype = 'advisory' AND l.classid = %s::bigint::oid "
    "AND l.objid = (%s::bigint & 4294967295)::oid AND l.objsubid = 2 AND l.granted "
    "AND l.database = (SELECT oid FROM pg_catalog.pg_database "
    "                   WHERE datname = pg_catalog.current_database())"
)


def lock_key(kind: str, name: str) -> int:
    """The second key of a node's (``kind`` ``node``) or a role's (``role``)
    advisory lock: the first four bytes of SHA-256 over ``interlock.<kind>:<name>``,
    as a signed 32-bit integer. ``interlock.node_key`` computes a node's alike
    in SQL."""
    digest = hashlib.sha256(f"interlock.{kind}:{name}".encode()).digest()
    return int.from_bytes(digest[:4], "big", signed=True)


def connection_name(part: str, node: str | None, alone: str) -> str:
    """What a part's connections are called in ``pg_stat_activity``:
    ``interlock-<part>@<node>`` in a cluster, so who holds what is plain;
    ``alone`` otherwise, as before clusters."""
    return alone if node is None else f"interlock-{part}@{node}"


class ClusterNode:
    """This process's place in the cluster: the session holding its node's
    lock and the roles it leads (see the module). Thread-safe: the parts ask
    for their roles from their own threads, and the supervisor heartbeats from
    another.

    :param dsn: The node's session: any role (an advisory lock needs no
        privilege), never through a transaction-mode pooler.
    :param node: The node's name, unique in the cluster.
    :param heartbeat: Seconds between heartbeats, and between a standby part's
        asks for its role.
    :param session_timeout: Seconds the server lets the session sit silent
        before ending it, and with it everything the node holds. At least three
        heartbeats.
    :param join_wait: How long :meth:`join` waits for the node's lock while
        another session holds it: the node's previous incarnation, whose
        session the server has not ended yet. Twice the session timeout by
        default.
    :raises ValueError: On a name or a timing that cannot work.
    """

    def __init__(
        self,
        dsn: str,
        node: str,
        *,
        heartbeat: float = 1.0,
        session_timeout: float = 10.0,
        join_wait: float | None = None,
    ) -> None:
        if not NODE_NAME.fullmatch(node):
            raise ValueError(
                f"a node is named by letters, digits, '.', '_' and '-', 63 at most, not {node!r}"
            )
        if heartbeat <= 0 or session_timeout < 3 * heartbeat:
            raise ValueError(
                f"the session timeout ({session_timeout}s) is at least three heartbeats "
                f"({heartbeat}s): a live node must never fall silent for that long"
            )
        self.node = node
        """The node's name."""
        self.heartbeat_seconds = heartbeat
        self.session_timeout = session_timeout
        self._dsn = dsn
        self._join_wait = 2 * session_timeout if join_wait is None else join_wait
        self._key = lock_key("node", node)
        self._lock = threading.RLock()
        self._conn: psycopg.Connection[Any] | None = None
        self._joined = False
        self._held: set[str] = set()
        self._roles: set[str] = set()
        self._taken: Counter[str] = Counter()
        self.counters: Counter[str] = Counter()
        """``joins``, ``heartbeats``, ``lost`` sessions: what the node did."""

    @property
    def joined(self) -> bool:
        """Whether the node's session holds its lock, as of the last word
        from the server."""
        with self._lock:
            return self._joined

    def leadership(self, role: str) -> Leadership:
        """The role ``role``, as this node's parts follow it."""
        if not role:
            raise ValueError("a role has a name")
        with self._lock:
            self._roles.add(role)
        return Leadership(self, role)

    def leads(self, role: str) -> bool:
        """Whether the node leads ``role``, as of the last word from the server."""
        with self._lock:
            return self._joined and role in self._held

    # -- joining and leaving -------------------------------------------------

    def join(self) -> None:
        """Open the node's session and take its lock, waiting for it while
        another session holds it, up to ``join_wait``.

        :raises NodeTakenError: If another session still holds it then:
            another process is this node.
        :raises SubstrateUnavailableError: If the server cannot be reached.
        """
        import psycopg

        conn = self._connect()
        try:
            deadline = time.monotonic() + self._join_wait
            while True:
                row = conn.execute(
                    "SELECT pg_catalog.pg_try_advisory_lock(%s, %s)", (NODE_LOCK, self._key)
                ).fetchone()
                if row is not None and row[0]:
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    raise NodeTakenError(
                        f"node {self.node!r} runs already: {self._holder(conn)} holds its lock, "
                        f"and has for the {self._join_wait:g}s this process waited for it"
                    )
                time.sleep(min(self.heartbeat_seconds, left))
        except psycopg.Error as exc:
            conn.close()
            raise SubstrateUnavailableError(f"node {self.node!r} cannot join: {exc}") from exc
        except BaseException:
            conn.close()
            raise
        with self._lock:
            before, self._conn = self._conn, conn
            self._joined = True
            self._held.clear()
            self.counters["joins"] += 1
        if before is not None:
            _close(before)
        logger.info("node %s joined the cluster", self.node)

    def leave(self) -> None:
        """Close the node's session, and with it every lock the node holds:
        another process may be this node from now on. Idempotent."""
        with self._lock:
            conn, self._conn = self._conn, None
            self._joined = False
            self._held.clear()
        if conn is not None:
            _close(conn)

    # -- staying -------------------------------------------------------------

    def heartbeat(self) -> None:
        """Show the server the node is alive, and that its session still holds
        the node's lock. A session gone (the server ended it, or the network
        did) takes every role with it: the node counts itself out of each at
        once, and joins again.

        :raises NodeTakenError: If another process took the node's lock while
            its session was gone.
        :raises SubstrateUnavailableError: If the server cannot be reached; the
            next heartbeat tries again.
        """
        import psycopg

        with self._lock:
            conn = self._conn
            if conn is not None and self._joined:
                try:
                    rows = conn.execute(_HELD).fetchall()
                except psycopg.Error as exc:
                    self._lose(f"its session is gone ({exc})")
                else:
                    if (NODE_LOCK, self._key) in {(int(c), _signed(int(o))) for c, o in rows}:
                        self.counters["heartbeats"] += 1
                        return
                    self._lose("its session no longer holds the node's lock")
        self.join()

    def lead(self, role: str) -> bool:
        """Whether this node leads ``role`` now: confirmed on the session when
        it holds the role (a session-level lock cannot outlive its session),
        taken when it is free. Never waits, never raises: a session gone means
        no role, until the next heartbeat joins again."""
        import psycopg

        key = lock_key("role", role)
        with self._lock:
            self._roles.add(role)
            conn = self._conn
            if conn is None or not self._joined:
                return False
            try:
                if role in self._held:
                    conn.execute("SELECT 1")
                    return True
                row = conn.execute(
                    "SELECT pg_catalog.pg_try_advisory_lock(%s, %s)", (LEADER_LOCK, key)
                ).fetchone()
            except psycopg.Error as exc:
                self._lose(f"its session is gone ({exc})")
                return False
            if row is None or not row[0]:
                return False
            self._held.add(role)
            self._taken[role] += 1
        logger.info("node %s leads %s", self.node, role)
        return True

    def resign(self, role: str) -> None:
        """Give ``role`` up, if the node leads it: another node may take it at
        its next ask."""
        import psycopg

        with self._lock:
            if role not in self._held:
                return
            self._held.discard(role)
            conn = self._conn
            if conn is None:
                return
            try:
                conn.execute(
                    "SELECT pg_catalog.pg_advisory_unlock(%s, %s)",
                    (LEADER_LOCK, lock_key("role", role)),
                )
            except psycopg.Error as exc:
                self._lose(f"its session is gone ({exc})")
                return
        logger.info("node %s resigned %s", self.node, role)

    def collect(self, metrics: Metrics) -> None:
        """What a scrape reads of the node: its lock, and each role its parts
        follow (``docs/EPIC9_DESIGN.md`` §1.4)."""
        with self._lock:
            joined = self._joined
            roles = {role: joined and role in self._held for role in self._roles}
            taken = dict(self._taken)
        metrics.set("interlock_cluster_node", int(joined), node=self.node)
        for role, held in sorted(roles.items()):
            metrics.set("interlock_cluster_leader", int(held), role=role)
            metrics.set("interlock_cluster_leaderships_total", taken.get(role, 0), role=role)

    # -- internals ---------------------------------------------------------------

    def _lose(self, why: str) -> None:
        """The session is gone, or no longer the node's: every role with it.
        Under the lock."""
        if self._held:
            logger.warning(
                "node %s: %s; it leads none of %s now",
                self.node,
                why,
                ", ".join(sorted(self._held)),
            )
        else:
            logger.warning("node %s: %s", self.node, why)
        self._held.clear()
        self._joined = False
        self.counters["lost"] += 1
        conn, self._conn = self._conn, None
        if conn is not None:
            _close(conn)

    def _connect(self) -> psycopg.Connection[Any]:
        """The node's session, set up so the server ends it once it falls
        silent: ``idle_session_timeout``, and TCP keepalives on both sides."""
        import psycopg
        from psycopg.conninfo import make_conninfo

        timeout = self.session_timeout
        idle = max(1, math.floor(timeout / 3))
        interval = max(1, math.floor(timeout / 10))
        try:
            conn = psycopg.connect(
                make_conninfo(
                    self._dsn,
                    application_name=connection_name("cluster", self.node, ""),
                    connect_timeout=max(2, math.ceil(timeout)),
                    keepalives=1,
                    keepalives_idle=idle,
                    keepalives_interval=interval,
                    keepalives_count=3,
                ),
                autocommit=True,
                prepare_threshold=None,
            )
        except psycopg.Error as exc:
            raise SubstrateUnavailableError(f"node {self.node!r} cannot connect: {exc}") from exc
        milliseconds = max(1, int(timeout * 1000))
        try:
            conn.execute(f"SET statement_timeout = {milliseconds}")
            conn.execute(
                f"SET tcp_keepalives_idle = {idle}; SET tcp_keepalives_interval = {interval}; "
                f"SET tcp_keepalives_count = 3"
            )
            try:
                conn.execute(f"SET idle_session_timeout = {milliseconds}")
            except psycopg.errors.UndefinedObject:
                # PostgreSQL before 14: the keepalives alone find a lost peer,
                # and nothing finds a frozen one.
                logger.warning(
                    "node %s: the server has no idle_session_timeout (PostgreSQL 14 or later): "
                    "a node that freezes keeps its locks until its process ends",
                    self.node,
                )
        except psycopg.Error as exc:
            _close(conn)
            raise SubstrateUnavailableError(f"node {self.node!r} cannot connect: {exc}") from exc
        return conn

    def _holder(self, conn: psycopg.Connection[Any]) -> str:
        row = conn.execute(_HOLDER, (NODE_LOCK, self._key)).fetchone()
        if row is None:
            return "another session"
        pid, name, since = row
        return f"session {pid} ({name or 'unnamed'}, since {since:%Y-%m-%d %H:%M:%S})"


class Leadership:
    """A role, as one node's parts follow it (``Service.leader``): the part
    steps only while :meth:`lead` says the node leads it."""

    __slots__ = ("_node", "role")

    def __init__(self, node: ClusterNode, role: str) -> None:
        self._node = node
        self.role = role

    @property
    def retry(self) -> float:
        """Seconds a part on standby waits before it asks again."""
        return self._node.heartbeat_seconds

    @property
    def held(self) -> bool:
        """Whether the node leads the role, as of the last word from the server."""
        return self._node.leads(self.role)

    def lead(self) -> bool:
        """Whether the node leads the role now; taking it when it is free."""
        return self._node.lead(self.role)

    def resign(self) -> None:
        self._node.resign(self.role)


def _signed(objid: int) -> int:
    """An advisory lock's ``objid``, an unsigned ``oid``, as the signed key
    that took it."""
    return objid - (1 << 32) if objid >= 1 << 31 else objid


def _close(conn: Any) -> None:
    try:
        conn.close()
    except Exception:  # closing what is gone already
        logger.debug("closing a cluster session failed", exc_info=True)
