"""The daemon: the supervisor ``interlock.toml`` describes (``docs/EPIC6_DESIGN.md`` §2.7).

:func:`build_supervisor` builds an :class:`~interlock.supervisor.InterlockSupervisor`
from a configuration and an :class:`Application`, each part connecting as its
own role:

=============  ====================================================  ==========================
Part           Built when                                            Connects as
=============  ====================================================  ==========================
engines        the application brings checkers or agents             ``[engine] database``
relays         ``[relay]``: ``workers`` of them                      ``[relay] database``
inbox          ``[[inbox.sources]]`` and ``[inbox.keys]``            ``[inbox] database``
settler        engines, and ``[receipts]``                           ``[settler] database``
vacuum         ``[vacuum] every_seconds`` and ``key``, and           ``[vacuum] database``
               ``[operators]`` with its ledger
=============  ====================================================  ==========================

Every PostgreSQL part opens a governor of the shared ledger of its own; parts
over one SQLite ledger share one, since a SQLite ledger has one writer.
``interlock daemon`` runs it::

    interlock daemon --config interlock.toml --app myapp.agents:build

With ``[cluster]``, the daemon is a node of a cluster of daemons over one
database (``docs/EPIC9_DESIGN.md``): it holds its node's lock for its life;
its relays' leases name the node; the vacuum and the inbox's matcher run on
the node that leads their role; its settler settles its own engines' plans,
leading its receipt log's role; every connection is called
``interlock-<part>@<node>``, and every session that holds what others wait
for is bounded by ``[cluster] session_timeout_seconds``::

    interlock daemon --config interlock.toml --app myapp.agents:build --node interlock-0
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import threading
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from interlock.cluster import ClusterNode, connection_name
from interlock.config import (
    CLUSTER_DATABASE_ENV,
    METRICS_DATABASE_ENV,
    NODE_ENV,
    SETTLER_DATABASE_ENV,
    is_dsn,
)
from interlock.exceptions import SubstrateConfigurationError
from interlock.supervisor import (
    AgentContext,
    EnginePool,
    InboxService,
    InterlockSupervisor,
    MetricsService,
    RelayService,
    Service,
    SettlerService,
    VacuumService,
)
from interlock.telemetry import Metrics

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.config import InterlockConfig
    from interlock.engine import EscrowEngine
    from interlock.inbox import Inbox
    from interlock.invariants import InvariantChecker
    from interlock.receipts import ReceiptIssuer
    from interlock.relay import Relay
    from interlock.sampling import Sample
    from interlock.settlement import Settler
    from interlock.vacuum import Vacuum

__all__ = ["Application", "build_supervisor", "load_application"]

logger = logging.getLogger("interlock.daemon")


@dataclass(frozen=True)
class Application:
    """What an application brings to the daemon: the policy its engines
    adjudicate with, and its agents. Infrastructure is the configuration's.

    :ivar checkers: The engines' invariants. The rate windows of
        ``[[windows]]`` are added to them.
    :ivar agents: Each ``async def agent(ctx)``, or a function run on a
        thread of its own (:class:`~interlock.supervisor.AgentContext`).
    """

    checkers: Sequence[InvariantChecker] = ()
    agents: Sequence[Callable[[AgentContext], Any]] = field(default_factory=tuple)


def load_application(target: str, config: InterlockConfig) -> Application:
    """The application ``module:callable`` names: the callable is called with
    the configuration, and returns an :class:`Application`.

    :raises SubstrateConfigurationError: If it cannot be imported, or does not
        return an application.
    """
    module_name, _, attribute = target.partition(":")
    if not module_name or not attribute:
        raise SubstrateConfigurationError(
            f"--app is module:callable, such as myapp.agents:build, not {target!r}"
        )
    try:
        build = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise SubstrateConfigurationError(f"cannot load the application {target}: {exc}") from exc
    application = build(config)
    if not isinstance(application, Application):
        raise SubstrateConfigurationError(
            f"{target} returned {type(application).__name__}, not an interlock Application"
        )
    return application


class _Membership:
    """What the parts of one daemon share about its place in a cluster
    (``docs/EPIC9_DESIGN.md`` §3.3): its node, what each part's connections
    are called, how long a session that holds what others wait for may sit
    inside a transaction, and the roles its singletons follow. Alone, outside
    a cluster: no node, the names and the 60 seconds there were before."""

    def __init__(self, cluster: ClusterNode | None) -> None:
        self.cluster = cluster

    @property
    def node(self) -> str | None:
        return None if self.cluster is None else self.cluster.node

    @property
    def bound(self) -> float:
        from interlock.wiring import ALONE

        return ALONE if self.cluster is None else self.cluster.session_timeout

    def name(self, part: str, alone: str) -> str:
        return connection_name(part, self.node, alone)

    def ledger(self, ledger: str) -> str:
        """A PostgreSQL ledger's connection string, its connections named for
        the node; a SQLite file as it is."""
        if self.node is None or not is_dsn(ledger):
            return ledger
        from psycopg.conninfo import make_conninfo

        return make_conninfo(ledger, application_name=self.name("ledger", ""))

    def follow(self, service: Service, role: str) -> Service:
        """``service``, stepping only while the node leads ``role``."""
        if self.cluster is not None:
            service.leader = self.cluster.leadership(role)
        return service


class _Governors:
    """Governors of AgentGov ledgers: one of its own for each caller of a
    PostgreSQL ledger, any number of which may share it; one shared by every
    caller of a SQLite ledger, which has one writer. In a cluster, a governor
    holding the ledger's writer lock in a transaction its node froze in holds
    it for the session timeout at most."""

    def __init__(self, membership: _Membership | None = None) -> None:
        self._lock = threading.Lock()
        self._shared: dict[str, tuple[BudgetManager, int]] = {}
        self._membership = membership or _Membership(None)

    def open(
        self, ledger: str, *, schema: str = "agentgov"
    ) -> tuple[BudgetManager, Callable[[], None]]:
        from agentgov import BudgetManager

        if is_dsn(ledger):
            membership = self._membership
            governor = BudgetManager.open_postgres(
                membership.ledger(ledger), schema=schema, idle_timeout=membership.bound
            )
            return governor, governor.close
        with self._lock:
            found = self._shared.get(ledger)
            if found is None:
                found = (BudgetManager.open_sqlite(ledger), 0)
            governor, users = found
            self._shared[ledger] = (governor, users + 1)

        def release() -> None:
            with self._lock:
                current, count = self._shared[ledger]
                if count > 1:
                    self._shared[ledger] = (current, count - 1)
                    return
                del self._shared[ledger]
            current.close()

        return governor, release


def build_supervisor(
    config: InterlockConfig,
    application: Application | None = None,
    *,
    listen: str | None = None,
    relay_key: str | None = None,
    inbox_key: str | None = None,
    metrics_listen: str | None = None,
) -> InterlockSupervisor:
    """The supervisor ``config`` describes, running ``application``'s agents
    (see the module). Keys are read and checked now, and read again by each
    part each time it opens (``docs/EPIC8_DESIGN.md`` §3): a part reopened, at
    a reload or after a failure, signs with the key its configuration points
    at then. Nothing else is opened until it runs.

    :param listen: Overrides ``[inbox] listen``, ``HOST:PORT``.
    :param metrics_listen: Overrides ``[metrics] listen``, ``HOST:PORT``: where
        ``/metrics`` is served.
    :param relay_key: Overrides ``[relay] key``, as ``INTERLOCK_RELAY_KEY`` does.
    :param inbox_key: Overrides ``[inbox] key``, as ``INTERLOCK_INBOX_KEY`` does.
    :raises SubstrateConfigurationError: If a part is configured but cannot
        be: a relay without endpoints' credentials, an inbox without keys.
    """
    from interlock.wiring import INBOX_KEY_ENV, RELAY_KEY_ENV, RefusedError

    membership = _Membership(_cluster(config))
    governors = _Governors(membership)
    services: list[Service] = []
    engines: EnginePool | None = None
    receipts = _Receipts(config)
    metrics = Metrics()
    if application is not None and (application.checkers or application.agents):
        engines = _engines(config, application, governors, receipts, metrics, membership)
    try:
        if config.relay is not None:
            key = relay_key or os.environ.get(RELAY_KEY_ENV) or config.relay.key
            services += _relays(config, key, membership)
        if config.inbox.sources and config.inbox.keys is not None:
            key = inbox_key or os.environ.get(INBOX_KEY_ENV) or config.inbox.key
            services.append(_inbox(config, key, listen, membership))
        if engines is not None and config.receipts is not None:
            services.append(_settler(config, engines, receipts, governors, membership))
        vacuum = config.vacuum
        if vacuum.every is not None and (vacuum.key is not None or vacuum.signer is not None):
            services.append(_vacuum(config, governors, membership))
        where = metrics_listen or config.metrics.listen
        if where:
            services.append(_metrics(config, where, membership))
    except RefusedError as exc:
        raise SubstrateConfigurationError(str(exc)) from exc
    supervisor = InterlockSupervisor(
        engines=engines,
        services=services,
        drain_timeout=config.daemon.drain_timeout.total_seconds(),
        restart_min=config.daemon.restart_min.total_seconds(),
        restart_max=config.daemon.restart_max.total_seconds(),
        metrics=metrics,
        cluster=membership.cluster,
    )
    supervisor.on_close(receipts.close)
    if application is not None:
        for agent in application.agents:
            supervisor.agent(agent)
    return supervisor


def _cluster(config: InterlockConfig) -> ClusterNode | None:
    """This daemon's node, as ``[cluster]`` names it; ``None`` alone."""
    settings = config.cluster
    if settings is None:
        return None
    if not settings.node:
        raise SubstrateConfigurationError(
            f"[cluster] names no node: set its node, {NODE_ENV}, or interlock daemon --node NAME"
        )
    dsn = settings.database or os.environ.get(CLUSTER_DATABASE_ENV, "")
    if not dsn:
        raise SubstrateConfigurationError(
            f"no database for node {settings.node}'s session: set [cluster] database, or "
            f"{CLUSTER_DATABASE_ENV}"
        )
    return ClusterNode(
        dsn,
        settings.node,
        heartbeat=settings.heartbeat.total_seconds(),
        session_timeout=settings.session_timeout.total_seconds(),
    )


class _Receipts:
    """The receipt log the engines and the settler share, opened on first use
    and closed after both."""

    def __init__(self, config: InterlockConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._issuer: ReceiptIssuer | None = None
        self._opened = False

    def get(self) -> ReceiptIssuer | None:
        from interlock.wiring import open_receipts

        with self._lock:
            if not self._opened:
                self._issuer = open_receipts(self._config)
                self._opened = True
            return self._issuer

    def close(self) -> None:
        with self._lock:
            issuer, self._issuer = self._issuer, None
            self._opened = False
        if issuer is not None:
            issuer.log.close()


def _engines(
    config: InterlockConfig,
    application: Application,
    governors: _Governors,
    shared: _Receipts,
    metrics: Metrics,
    membership: _Membership,
) -> EnginePool:
    from interlock.chain import EscrowChain
    from interlock.engine import EscrowEngine
    from interlock.wiring import live_keyring, open_anchor, open_substrate

    settings = config.engine

    def open_engine(index: int) -> tuple[EscrowEngine, Callable[[], None]]:
        closers: list[Callable[[], None]] = []

        def close() -> None:
            for closer in reversed(closers):
                closer()

        try:
            governor = None
            if settings.ledger is not None:
                governor, release = governors.open(settings.ledger, schema=settings.ledger_schema)
                closers.append(release)
            path = settings.chain_for(index, settings.workers)
            chain = EscrowChain(path) if path is not None else EscrowChain()
            closers.append(chain.close)
            engine = EscrowEngine(
                open_substrate(
                    config, metrics=metrics, application_name=membership.name("stage", "interlock")
                ),
                checkers=application.checkers,
                chain=chain,
                anchor=open_anchor(config, governor),
                settle_cost=settings.settle_cost,
                receipts=shared.get(),
                sinks=config.sink_registry() if config.sinks else None,
                windows=config.windows,
                # An inbox key registered while the engine runs verifies the
                # facts it attests (docs/EPIC8_DESIGN.md §3).
                inbox=live_keyring(config, "inbox"),
            )
        except BaseException:
            close()
            raise
        return engine, close

    # A node's previous incarnation may leave a stage running on the server
    # past its session: a statement waiting on a lock, then the stage's idle
    # bound. Its next waits that out before it resolves anything.
    wait = (
        0.0
        if membership.cluster is None
        else 2 * settings.max_stage_seconds + settings.lock_timeout_seconds
    )
    return EnginePool(
        open_engine,
        workers=settings.workers,
        conflict_retries=settings.conflict_retries,
        recover_wait=wait,
    )


def _metrics(config: InterlockConfig, listen: str, membership: _Membership) -> Service:
    """The metrics endpoint (``docs/EPIC7_DESIGN.md`` §2.2), sampling the
    database every ``[metrics] every_seconds`` when it may read it."""
    from interlock.sampling import sample_postgres, sample_sqlite
    from interlock.sqlite_outbox import now_us

    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit():
        raise SubstrateConfigurationError(f"metrics listen is HOST:PORT, not {listen!r}")
    every = config.metrics.every.total_seconds()
    windows = tuple(config.windows)
    sample: Callable[[], Sample] | None = None
    if config.substrate == "postgres":
        dsn = config.metrics.database or os.environ.get(METRICS_DATABASE_ENV, "")
        if dsn:
            bound = min(every, 10.0)

            name = membership.name("metrics", "interlock-metrics")

            def sample_database() -> Sample:
                return sample_postgres(dsn, windows, timeout=bound, application_name=name)

            sample = sample_database
        else:
            logger.warning(
                "metrics: no role to sample the database as ([metrics] database, an "
                "audit_roles role, or %s): only what the process measures is exported",
                METRICS_DATABASE_ENV,
            )
    else:
        path = config.metrics.database or config.database

        def sample_file() -> Sample:
            return sample_sqlite(path, windows, now_us=now_us())

        sample = sample_file
    return MetricsService(host=host, port=int(port), every=every, sample=sample, windows=windows)


def _relays(config: InterlockConfig, key: Any, membership: _Membership) -> list[Service]:
    from interlock.outbox_store import PostgresOutboxStore
    from interlock.relay import LedgerBreaker, NoBreaker, Relay
    from interlock.wiring import relay_adapters, relay_signer

    settings = config.relay
    assert settings is not None
    sqlite = config.substrate != "postgres"
    dsn = settings.database or (config.database if sqlite else "")
    if not dsn:
        raise SubstrateConfigurationError(
            "no database for the relay: set [relay] database, or INTERLOCK_RELAY_DATABASE"
        )
    relay_signer(config, key)  # a key that cannot be used stops the daemon now
    relay_adapters(settings)  # the credentials are there, or the daemon does not start

    def open_relay() -> tuple[Relay, Callable[[], None]]:
        from interlock.sqlite_outbox import SqliteOutboxStore

        # The key the configuration points at now: a new version at the key
        # service, or a new file (docs/EPIC8_DESIGN.md §3).
        signer = relay_signer(config, key)
        breaker: Any = (
            LedgerBreaker.open(membership.ledger(settings.ledger), schema=settings.ledger_schema)
            if settings.breaker == "agentgov" and settings.ledger is not None
            else NoBreaker()
        )
        store: Any = None
        node = membership.node
        try:
            store = (
                SqliteOutboxStore(dsn)
                if sqlite
                else PostgresOutboxStore(
                    dsn,
                    application_name=membership.name("relay", "interlock-relay"),
                    idle_timeout=membership.bound,
                )
            )
            relay = Relay(
                store,
                adapters=relay_adapters(settings),
                breaker=breaker,
                lease=settings.lease,
                timeout=settings.timeout,
                batch=settings.batch,
                signer=signer,
                node=node,
                relay_id=(
                    None if node is None else f"relay:{node}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
                ),
            )
        except BaseException:
            if store is not None:
                store.close()
            if isinstance(breaker, LedgerBreaker):
                breaker.close()
            raise

        def close() -> None:
            try:
                relay.close()
            finally:
                if isinstance(breaker, LedgerBreaker):
                    breaker.close()

        return relay, close

    return [
        RelayService(open_relay, name=f"relay-{n}", poll=settings.poll_seconds)
        for n in range(settings.workers)
    ]


def _inbox(
    config: InterlockConfig, key: Any, listen: str | None, membership: _Membership
) -> Service:
    from interlock.inbox import Inbox
    from interlock.wiring import inbox_signer, inbox_store, live_keyring

    settings = config.inbox
    if live_keyring(config, "relay") is None:
        raise SubstrateConfigurationError(
            "an inbox binds an event only to a delivery a registered relay attested: "
            "register the relays' keys in [relays.keys]"
        )
    inbox_signer(config, key)  # a key that cannot be used stops the daemon now
    host, _, port = (listen or settings.listen).rpartition(":")
    if not host or not port.isdigit():
        raise SubstrateConfigurationError(f"listen is HOST:PORT, not {listen or settings.listen!r}")

    def open_inbox() -> tuple[Inbox, Callable[[], None]]:
        # The key the configuration points at now, and the relays' keys the
        # operator log registers (docs/EPIC8_DESIGN.md §3).
        signer = inbox_signer(config, key)
        relays = live_keyring(config, "relay")
        assert relays is not None  # the configuration's keys are there still
        store, close = inbox_store(
            config,
            None,
            application_name=membership.name("inbox", "interlock-inbox"),
            idle_timeout=membership.bound,
        )
        return (
            Inbox(
                store,
                settings.sources,
                signer=signer,
                relays=relays,
                secrets=os.environ.get,
                max_body=settings.max_body,
                match_window=settings.match_window,
            ),
            close,
        )

    inbox = InboxService(
        open_inbox,
        host=host,
        port=int(port),
        match_every=settings.match_every.total_seconds(),
    )
    # Every node binds what it receives as it receives it; one matches what
    # came before its delivery was recorded.
    return membership.follow(inbox, "inbox-matcher")


def _settler(
    config: InterlockConfig,
    engines: EnginePool,
    shared: _Receipts,
    governors: _Governors,
    membership: _Membership,
) -> Service:
    from interlock.settlement import Settler
    from interlock.wiring import live_keyring

    if live_keyring(config, "relay") is None:
        raise SubstrateConfigurationError(
            "the settler holds every delivery to a registered relay's attestation: register "
            "the relays' keys in [relays.keys]"
        )
    sqlite = config.substrate != "postgres"
    dsn = (
        config.settler.database
        or os.environ.get(SETTLER_DATABASE_ENV)
        or (config.database if sqlite else "")
    )
    if not dsn:
        raise SubstrateConfigurationError(
            f"no database for the settler: set [settler] database, or {SETTLER_DATABASE_ENV}"
        )

    def open_settler() -> tuple[Settler, Callable[[], None]]:
        closers: list[Callable[[], None]] = []

        def close() -> None:
            for closer in reversed(closers):
                closer()

        try:
            if sqlite:
                from interlock.sqlite_outbox import SETTLER, SqliteOutboxStore

                outbox: Any = SqliteOutboxStore(dsn, writes=SETTLER)
                closers.append(outbox.close)
            else:
                import psycopg

                outbox = psycopg.connect(
                    dsn,
                    autocommit=True,
                    application_name=membership.name("settler", "interlock-settler"),
                )
                closers.append(outbox.close)
            ledger = None
            if config.engine.ledger is not None:
                ledger, release = governors.open(
                    config.engine.ledger, schema=config.engine.ledger_schema
                )
                closers.append(release)
            operators = config.operators
            receipts = shared.get()
            assert receipts is not None  # [receipts] is configured: the settler is built
            relays = live_keyring(config, "relay")
            assert relays is not None  # the configuration's keys are there still
            settler = Settler(
                outbox,
                receipts=receipts,
                chain=[engine.chain for engine in engines.engines],
                relays=relays,
                ledger=ledger,
                operator_log=None if operators is None else operators.log,
                operators=None if operators is None else operators.keyring(),
                sinks=config.sink_registry() if config.sinks else None,
                # In a cluster each node settles what its own engines committed.
                partition=membership.cluster is not None,
            )
        except BaseException:
            close()
            raise
        return settler, close

    assert config.receipts is not None  # the daemon builds a settler only beside them
    settler = SettlerService(open_settler, every=config.settler.every.total_seconds())
    return membership.follow(settler, f"settler:{config.receipts.log_id}")


def _vacuum(config: InterlockConfig, governors: _Governors, membership: _Membership) -> Service:
    from interlock.operators import OperatorLog
    from interlock.vacuum import Vacuum
    from interlock.wiring import RefusedError, compactor, live_keyring, operator_signer

    operators = config.operators
    relays = live_keyring(config, "relay")
    inbox = live_keyring(config, "inbox")
    vacuum = config.vacuum
    if operators is None or operators.ledger is None:
        raise SubstrateConfigurationError(
            "a vacuum's checkpoint is anchored into AgentGov before anything is pruned: "
            "configure [operators] with its ledger"
        )
    if relays is None:
        raise SubstrateConfigurationError(
            "a vacuum prunes only what verifies, relays' attestations included: register "
            "their keys in [relays.keys]"
        )
    assert vacuum.every is not None
    try:  # a key that cannot be used stops the daemon now
        operator_signer(config, vacuum.signer, vacuum.key, part="vacuum")
    except RefusedError as exc:
        raise SubstrateConfigurationError(str(exc)) from exc
    # One governor for every run, caught up at the start of each: opening one
    # reads the whole ledger, which grows with every plan.
    kept = _Kept(lambda: governors.open(str(operators.ledger)))

    @contextlib.contextmanager
    def open_vacuum() -> Iterator[Vacuum]:
        # Each run signs with the key the configuration points at then
        # (docs/EPIC8_DESIGN.md §3).
        signer = operator_signer(config, vacuum.signer, vacuum.key, part="vacuum")
        governor = kept.get()
        governor.refresh()
        source, close = compactor(
            config,
            vacuum.database or None,
            application_name=membership.name("vacuum", "interlock-vacuum"),
        )
        try:
            log = OperatorLog(
                operators.log,
                signer,
                operators.keyring(),
                ledger=governor,
                scope=operators.scope,
            )
            try:
                yield Vacuum(
                    log,
                    source,
                    operators=operators.keyring(),
                    relays=relays,
                    ledger=governor,
                    windows=config.windows,
                    retain=vacuum.retain,
                    margin=vacuum.margin,
                    archive=vacuum.archive,
                    inbox=inbox,
                )
            finally:
                log.close()
        finally:
            close()

    node = membership.node
    service = VacuumService(
        open_vacuum,
        every=vacuum.every.total_seconds(),
        close=kept.close,
        reason="scheduled by the daemon" + ("" if node is None else f" on {node}"),
    )
    return membership.follow(service, "vacuum")


class _Kept:
    """A governor opened on first use and kept until closed."""

    def __init__(self, open_governor: Callable[[], tuple[BudgetManager, Callable[[], None]]]):
        self._open = open_governor
        self._lock = threading.Lock()
        self._opened: tuple[BudgetManager, Callable[[], None]] | None = None

    def get(self) -> BudgetManager:
        with self._lock:
            if self._opened is None:
                self._opened = self._open()
            return self._opened[0]

    def close(self) -> None:
        with self._lock:
            opened, self._opened = self._opened, None
        if opened is not None:
            opened[1]()
