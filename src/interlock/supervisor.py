"""The supervisor: every part of Interlock in one process, on one event loop.

(``docs/EPIC6_DESIGN.md`` §2.) The engines that execute agents' plans, the
relays, the inbox's receiver and matcher, the settler and the vacuum each run
as a *service*: a control loop on the supervisor's asyncio event loop, whose
blocking steps run on a thread pool of the service's own. Every database call
in Interlock and AgentGov is synchronous, and stays so; the loop schedules
them, bounds them and stops them::

    supervisor = InterlockSupervisor(
        engines=EnginePool(open_engine, workers=4),
        services=[RelayService(open_relay), InboxService(open_inbox, host="0.0.0.0",
                  port=8787), SettlerService(open_settler), VacuumService(open_vacuum,
                  every=300)],
    )

    @supervisor.agent
    async def support(ctx: AgentContext) -> None:
        while not ctx.stopping:
            ...
            result = await ctx.execute(plan)

    asyncio.run(supervisor.run(handle_signals=True))

- **Engines.** A plan submitted is queued, and the next free worker stages it on
  its own engine. A plan that lost a race for a row or a window key
  (:class:`~interlock.exceptions.StageConflictError`) is staged again, with
  jittered backoff, up to a bound. Each worker writes its own escrow chain:
  engines sharing one would interleave AgentGov observations and break
  :meth:`~interlock.chain.EscrowChain.verify_anchors`.
- **Failure.** A service step that raises is counted, its resources closed,
  and the service opened again after an exponential backoff. A plan's failure
  is the agent's, and is returned to it.
- **Shutdown** (:meth:`InterlockSupervisor.stop`, or ``SIGTERM``/``SIGINT``) runs
  in order, each step bounded by ``drain_timeout``: agents are told to stop;
  the engines take no more plans and finish the ones they hold; the inbox
  stops accepting and matches once more; the relays finish their batches; the
  settler settles once more; a vacuum in progress finishes. Then everything is
  closed. Nothing is cut in half: a stage, a delivery, a webhook being recorded
  and a vacuum each finish or never start. A second signal skips the drains,
  and gives the closes :data:`CLOSE_GRACE` seconds.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import inspect
import logging
import random
import signal
import threading
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from interlock.exceptions import (
    ChainInUseError,
    CommitUnsettledError,
    StageConflictError,
    SupervisorStoppedError,
)

if TYPE_CHECKING:
    from interlock.builder import PlanBuilder
    from interlock.engine import EscrowEngine, StageResult
    from interlock.inbox import Inbox, InboxServer
    from interlock.relay import Relay
    from interlock.settlement import Settler
    from interlock.types import EffectPlan, InboundFact
    from interlock.vacuum import Vacuum

__all__ = [
    "AgentContext",
    "EnginePool",
    "InboxService",
    "InterlockSupervisor",
    "RelayService",
    "Service",
    "ServiceStatus",
    "SettlerService",
    "VacuumService",
]

logger = logging.getLogger("interlock.supervisor")

T = TypeVar("T")

CLOSE_GRACE = 1.0
"""Seconds a forced stop still gives the services to close, all of them
together: a close releases connections and sockets, quick but never instant."""

RUNNING = "running"
STARTING = "starting"
BACKING_OFF = "backing-off"
STOPPING = "stopping"
STOPPED = "stopped"
FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ServiceStatus:
    """A service's health, as :meth:`InterlockSupervisor.status` reports it.

    :ivar state: ``starting``, ``running``, ``backing-off``, ``stopping``,
        ``stopped``, or ``failed`` (an agent that raised).
    :ivar steps: Steps run to the end.
    :ivar failures: Steps, or opens, that raised.
    :ivar last_error: The last of them, as ``Type: message``.
    :ivar counters: The service's own: plans committed, messages delivered...
    """

    name: str
    state: str
    steps: int
    failures: int
    last_error: str | None
    counters: Mapping[str, int]


class Service:
    """One part of Interlock the supervisor runs: blocking steps, scheduled on
    the loop. A subclass implements :meth:`step`, and :meth:`open`,
    :meth:`drain` and :meth:`close` as it needs them; each runs on the
    service's own thread.

    :cvar phase: Its place in a shutdown: lower phases stop first.
    """

    phase: ClassVar[int] = 9

    def __init__(self, name: str) -> None:
        self.name = name
        self._counters: Counter[str] = Counter()
        self._counting = threading.Lock()

    def count(self, counter: str, n: int = 1) -> None:
        """Add ``n`` to one of the service's counters. Thread-safe."""
        if n:
            with self._counting:
                self._counters[counter] += n

    @property
    def counters(self) -> dict[str, int]:
        with self._counting:
            return dict(self._counters)

    def bind(self, supervisor: InterlockSupervisor) -> None:
        """Called once, before the first :meth:`open`."""

    def open(self) -> None:
        """Acquire what the service needs. Called again after a failure."""

    def step(self) -> float:
        """Do one unit of work. Returns how many seconds to wait before the
        next: ``0`` when there is more to do now."""
        raise NotImplementedError

    def drain(self) -> None:
        """At shutdown, after the last step: one last unit of work, if any."""

    def close(self) -> None:
        """Release what :meth:`open` acquired. Idempotent."""


# --------------------------------------------------------------------------
# the services
# --------------------------------------------------------------------------


class RelayService(Service):
    """One relay worker: :meth:`Relay.run_once` in a loop, resting ``poll``
    seconds when nothing is due. Run several for throughput: they share the
    work through ``FOR UPDATE SKIP LOCKED``.

    :param open_relay: Builds the relay, and its store, each time the service
        opens: the relay, closed with :meth:`Relay.close`, or the relay and
        what closes it and whatever else was opened for it.
    """

    phase = 3

    def __init__(
        self,
        open_relay: Callable[[], Relay | tuple[Relay, Callable[[], None]]],
        *,
        name: str = "relay",
        poll: float = 1.0,
    ) -> None:
        super().__init__(name)
        self._open_relay = open_relay
        self._poll = poll
        self._relay: Relay | None = None
        self._close: Callable[[], None] | None = None

    def open(self) -> None:
        opened = self._open_relay()
        if isinstance(opened, tuple):
            self._relay, self._close = opened
        else:
            self._relay, self._close = opened, opened.close

    def step(self) -> float:
        assert self._relay is not None
        report = self._relay.run_once()
        for outcome in ("claimed", "delivered", "retrying", "dead", "held", "deferred"):
            self.count(outcome, getattr(report, outcome))
        self.count("refused", report.refused)
        return 0.0 if report.claimed else self._poll

    def close(self) -> None:
        close, self._close = self._close, None
        self._relay = None
        if close is not None:
            close()


class InboxService(Service):
    """The inbox: its HTTP receiver (``POST /inbox/<source>``, and ``GET
    /healthz`` answering with the supervisor's health), and
    :meth:`Inbox.match_pending` every ``match_every`` seconds.

    :param open_inbox: Builds the inbox and returns it with what closes its
        store.
    """

    phase = 2

    def __init__(
        self,
        open_inbox: Callable[[], tuple[Inbox, Callable[[], None]]],
        *,
        host: str = "127.0.0.1",
        port: int = 8787,
        match_every: float = 5.0,
        name: str = "inbox",
    ) -> None:
        super().__init__(name)
        self._open_inbox = open_inbox
        self._host = host
        self._port = port
        self._match_every = match_every
        self._inbox: Inbox | None = None
        self._close_store: Callable[[], None] | None = None
        self._server: InboxServer | None = None
        self._health: Callable[[], tuple[int, Mapping[str, Any]]] | None = None
        self.port: int | None = None
        """The port bound, once open: the one asked for, or the one chosen
        for port 0."""

    def bind(self, supervisor: InterlockSupervisor) -> None:
        self._health = supervisor.health

    def open(self) -> None:
        from interlock.inbox import InboxServer

        inbox, close_store = self._open_inbox()
        try:
            counting = _CountingInbox(inbox, self)
            server = InboxServer(counting, self._host, self._port, health=self._health)  # type: ignore[arg-type]
            self.port = server.start()
        except BaseException:
            close_store()
            raise
        # The port chosen is kept: a restart binds the same one.
        self._port = self.port
        self._inbox, self._close_store, self._server = inbox, close_store, server

    def step(self) -> float:
        assert self._inbox is not None
        self.count("matched", self._inbox.match_pending())
        return self._match_every

    def drain(self) -> None:
        if self._server is not None:
            self._server.stop()
        if self._inbox is not None:
            self.count("matched", self._inbox.match_pending())

    def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.stop()
        close, self._close_store = self._close_store, None
        self._inbox = None
        if close is not None:
            close()


class _CountingInbox:
    """An inbox that counts what its server answered."""

    __slots__ = ("_inbox", "_max_body", "_service")

    def __init__(self, inbox: Inbox, service: Service) -> None:
        self._inbox = inbox
        self._service = service
        self._max_body = inbox._max_body

    def receive(self, name: str, headers: Mapping[str, str], body: bytes) -> Any:
        response = self._inbox.receive(name, headers, body)
        self._service.count(f"answered_{response.status}")
        if response.status == 200:
            self._service.count("recorded", int(response.body.get("recorded", 0)))
        return response


class SettlerService(Service):
    """:meth:`Settler.settle` every ``every`` seconds, and once more at
    shutdown, after the relays have stopped.

    :param open_settler: Builds the settler and returns it with what closes
        its connection.
    """

    phase = 4

    def __init__(
        self,
        open_settler: Callable[[], tuple[Settler, Callable[[], None]]],
        *,
        every: float = 5.0,
        name: str = "settler",
    ) -> None:
        super().__init__(name)
        self._open_settler = open_settler
        self._every = every
        self._settler: Settler | None = None
        self._close: Callable[[], None] | None = None

    def open(self) -> None:
        self._settler, self._close = self._open_settler()

    def step(self) -> float:
        assert self._settler is not None
        report = self._settler.settle()
        self.count("settled", len(report.settled))
        self.count("receipts", report.receipts)
        self.count("credits", report.credits)
        self.count("problems", len(report.problems))
        for problem in report.problems:
            logger.warning("settler: %s", problem)
        return self._every

    def drain(self) -> None:
        if self._settler is not None:
            self.step()

    def close(self) -> None:
        close, self._close = self._close, None
        self._settler = None
        if close is not None:
            close()


class VacuumService(Service):
    """A vacuum every ``every`` seconds (``docs/EPIC5_DESIGN.md`` §1). Each run
    opens what it signs with, the operator log included, and closes it after:
    an operator's command can use the log between runs. A run that finds the
    log in use by another writer is put off to ``busy_retry`` seconds later.

    :param open_vacuum: A context manager yielding one run's vacuum.
    :param close: Closes what the runs share between them, such as a governor
        kept open: called when the service closes, or fails and is reopened.
    """

    phase = 5

    def __init__(
        self,
        open_vacuum: Callable[[], contextlib.AbstractContextManager[Vacuum]],
        *,
        every: float,
        name: str = "vacuum",
        reason: str = "scheduled by the daemon",
        busy_retry: float = 1.0,
        close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(name)
        self._open_vacuum = open_vacuum
        self._every = every
        self._reason = reason
        self._busy_retry = busy_retry
        self._close = close

    def step(self) -> float:
        try:
            with self._open_vacuum() as vacuum:
                report = vacuum.run(reason=self._reason)
        except ChainInUseError:
            self.count("busy")
            return self._busy_retry
        self.count(report.outcome)
        self.count("messages", report.messages)
        self.count("window_rows", report.window_rows)
        self.count("inbox_events", report.inbox_events)
        for problem in report.problems:
            logger.warning("vacuum: %s", problem)
        return self._every

    def close(self) -> None:
        if self._close is not None:
            self._close()


# --------------------------------------------------------------------------
# the engines
# --------------------------------------------------------------------------


class EnginePool:
    """The engines that execute agents' plans: one per worker, each with its
    own substrate, governor and escrow chain (``docs/EPIC6_DESIGN.md`` §2.2).

    :param open_engine: Builds worker ``n``'s engine, and returns it with what
        closes it (its chain, its governor...).
    :param workers: Plans staged at once.
    :param conflict_retries: How often a plan that lost a race for a row or a
        window key is staged again before the conflict is the agent's.
    :param retry_base: The first backoff, in seconds; it doubles each retry,
        jittered, up to ``retry_cap``.
    :param recover: Resolve what a crashed predecessor left on each worker's
        chain, before the worker takes a plan.
    :param queue: How many plans may wait for a worker before a submitter
        waits too; ``workers * 16`` by default.
    """

    name = "engines"

    def __init__(
        self,
        open_engine: Callable[[int], tuple[EscrowEngine, Callable[[], None]]],
        *,
        workers: int = 1,
        conflict_retries: int = 16,
        retry_base: float = 0.005,
        retry_cap: float = 0.25,
        recover: bool = True,
        queue: int | None = None,
    ) -> None:
        if workers < 1:
            raise ValueError("an engine pool has at least one worker")
        if conflict_retries < 0:
            raise ValueError("conflict_retries is not negative")
        self.workers = workers
        self._open_engine = open_engine
        self._retries = conflict_retries
        self._retry_base = retry_base
        self._retry_cap = retry_cap
        self._recover = recover
        self.queue = queue if queue is not None else workers * 16
        self._engines: list[EscrowEngine] = []
        self._closers: list[Callable[[], None]] = []
        self._halt = threading.Event()
        self._counters: Counter[str] = Counter()
        self._counting = threading.Lock()

    def count(self, counter: str, n: int = 1) -> None:
        if n:
            with self._counting:
                self._counters[counter] += n

    @property
    def counters(self) -> dict[str, int]:
        with self._counting:
            return dict(self._counters)

    @property
    def engines(self) -> tuple[EscrowEngine, ...]:
        """Each worker's engine, once open."""
        return tuple(self._engines)

    def open(self) -> None:
        """Open every worker's engine, and recover its chain. Blocking."""
        try:
            for index in range(self.workers):
                engine, close = self._open_engine(index)
                self._engines.append(engine)
                self._closers.append(close)
                if self._recover:
                    recovered = engine.recover()
                    self.count("recovered", len(recovered))
        except BaseException:
            self.close()
            raise

    def execute(self, index: int, plan: EffectPlan) -> StageResult:
        """Stage ``plan`` on worker ``index``'s engine, again after each
        conflict, up to the bound. Blocking; one call per worker at a time.

        :raises StageConflictError: If every attempt lost its race.
        :raises SupervisorStoppedError: If the supervisor stopped while the
            plan waited to be staged again: it is not staged.
        """
        engine = self._engines[index]
        for attempt in range(self._retries + 1):
            try:
                result = engine.execute(plan)
            except StageConflictError:
                self.count("conflicts")
                if attempt == self._retries:
                    self.count("conflicts_exhausted")
                    raise
                delay = min(self._retry_cap, self._retry_base * 2**attempt)
                if self._halt.wait(random.uniform(delay / 2, delay)):  # noqa: S311 - jitter
                    self.count("cancelled")
                    raise SupervisorStoppedError(
                        f"plan {plan.plan_id} lost a race, and the supervisor stopped before "
                        f"it could be staged again: it was not committed"
                    ) from None
                continue
            except CommitUnsettledError:
                # Never staged again: its intent is open, and recovery says.
                self.count("unsettled")
                raise
            except Exception:
                self.count("failed")
                raise
            self.count("committed" if result.committed else "refused")
            return result
        raise AssertionError("unreachable")  # pragma: no cover

    def facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        """The scope's pending facts that verify. Reads on a connection of its
        own: safe beside the workers."""
        if not self._engines:
            raise SupervisorStoppedError("the engines are not open")
        return self._engines[0].facts(scope_id)

    def halt(self) -> None:
        """Stop waiting to retry: a plan that loses a race now is refused."""
        self._halt.set()

    def close(self) -> None:
        """Close every worker's engine. Idempotent."""
        closers, self._closers = self._closers, []
        self._engines = []
        for close in reversed(closers):
            try:
                close()
            except Exception:  # closing what is left matters more
                logger.exception("engines: closing a worker failed")


@dataclass
class _Job:
    plan: EffectPlan
    future: asyncio.Future[StageResult]


# --------------------------------------------------------------------------
# agents
# --------------------------------------------------------------------------


class AgentContext:
    """What an agent sees of the supervisor.

    An async agent awaits :meth:`execute`, :meth:`facts` and :meth:`sleep`; a
    synchronous agent, run on a thread of its own, calls
    :meth:`execute_blocking`, :meth:`facts_blocking` and
    :meth:`sleep_blocking`. Either returns once :attr:`stopping` is set.
    """

    def __init__(self, supervisor: InterlockSupervisor, name: str) -> None:
        self._supervisor = supervisor
        self.name = name
        self._stopping = threading.Event()
        self._awake: asyncio.Event | None = None

    @property
    def stopping(self) -> bool:
        """Whether the supervisor has begun to shut down."""
        return self._stopping.is_set()

    def plan(self, scope_id: str, *, intent: str = "") -> PlanBuilder:
        from interlock.builder import PlanBuilder

        return PlanBuilder(scope_id, intent=intent)

    async def execute(self, plan: EffectPlan) -> StageResult:
        return await self._supervisor.execute(plan)

    async def facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        return await self._supervisor.facts(scope_id)

    async def sleep(self, seconds: float) -> bool:
        """Sleep, or until stopping. Returns whether it slept the whole time."""
        if self._awake is None:
            self._awake = asyncio.Event()
            if self.stopping:
                self._awake.set()
        try:
            await asyncio.wait_for(self._awake.wait(), timeout=seconds)
        except TimeoutError:
            return True
        return False

    def execute_blocking(self, plan: EffectPlan, timeout: float | None = None) -> StageResult:
        return self._supervisor.submit(plan).result(timeout)

    def facts_blocking(self, scope_id: str) -> tuple[InboundFact, ...]:
        return self._supervisor.call(self._supervisor.facts(scope_id)).result()

    def sleep_blocking(self, seconds: float) -> bool:
        """Sleep, or until stopping. Returns whether it slept the whole time."""
        return not self._stopping.wait(seconds)

    def _stop(self) -> None:
        self._stopping.set()
        if self._awake is not None:
            self._awake.set()


@dataclass
class _Agent:
    function: Callable[[AgentContext], Any]
    context: AgentContext
    asynchronous: bool
    done: asyncio.Future[None] | None = None
    task: asyncio.Task[None] | None = None
    state: str = STARTING
    error: str | None = None


# --------------------------------------------------------------------------
# the supervisor
# --------------------------------------------------------------------------


@dataclass
class _Running:
    """A service's control loop, and what the supervisor knows of it."""

    service: Service
    executor: concurrent.futures.ThreadPoolExecutor
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    opened_once: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None
    state: str = STARTING
    opened: bool = False
    steps: int = 0
    failures: int = 0
    streak: int = 0
    last_error: str | None = None


class InterlockSupervisor:
    """Runs every part of Interlock in one process (module docstring).

    :param engines: The engines that execute agents' plans, or ``None``.
    :param services: The relays, the inbox, the settler, the vacuum: any
        :class:`Service`.
    :param drain_timeout: The most each step of a shutdown waits, in seconds.
    :param restart_min: A failed service is opened again after this many
        seconds, doubling with each failure in a row...
    :param restart_max: ...up to this many.
    """

    def __init__(
        self,
        *,
        engines: EnginePool | None = None,
        services: Sequence[Service] = (),
        drain_timeout: float = 30.0,
        restart_min: float = 0.5,
        restart_max: float = 30.0,
    ) -> None:
        names = [s.name for s in services] + (["engines"] if engines is not None else [])
        twice = sorted({n for n in names if names.count(n) > 1})
        if twice:
            raise ValueError(f"services share a name: {', '.join(twice)}")
        if restart_min <= 0 or restart_max < restart_min:
            raise ValueError("restart_min is positive, and restart_max at least it")
        self._engines = engines
        self._services = tuple(services)
        self._drain = drain_timeout
        self._restart_min = restart_min
        self._restart_max = restart_max
        self._agents: list[_Agent] = []
        self._closers: list[Callable[[], None]] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._ready: asyncio.Event | None = None
        self._force = False
        self._accepting = False
        self._queue: asyncio.Queue[_Job | None] | None = None
        self._workers: list[asyncio.Task[None]] = []
        self._running: dict[str, _Running] = {}
        self._engine_executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._reader: concurrent.futures.ThreadPoolExecutor | None = None
        self._engine_state = STARTING if engines is not None else STOPPED
        self._engine_error: str | None = None
        self._finished = threading.Event()

    # -- registration -----------------------------------------------------

    def agent(
        self, function: Callable[[AgentContext], Any], *, name: str | None = None
    ) -> Callable[[AgentContext], Any]:
        """Register an agent: ``async def agent(ctx)``, run on the loop, or a
        function run on a thread of its own. Usable as a decorator.

        :raises RuntimeError: Once the supervisor is running.
        """
        if self._loop is not None:
            raise RuntimeError("agents are registered before the supervisor runs")
        label = name or getattr(function, "__name__", "agent")
        self._agents.append(
            _Agent(
                function,
                AgentContext(self, f"{label}-{len(self._agents)}"),
                inspect.iscoroutinefunction(function),
            )
        )
        return function

    def on_close(self, close: Callable[[], None]) -> None:
        """Run ``close`` last, after every service and engine has closed: for
        what they share, such as the receipt log."""
        self._closers.append(close)

    # -- running ----------------------------------------------------------

    async def run(self, *, handle_signals: bool = False) -> None:
        """Start everything, run until :meth:`stop`, then shut down in order.

        :param handle_signals: Stop on ``SIGTERM`` or ``SIGINT``, and skip the
            remaining drains on a second. Main thread only.
        :raises Exception: What opening the engines raised: nothing else is
            started then.
        """
        if self._loop is not None:
            raise RuntimeError("a supervisor runs once")
        loop = asyncio.get_running_loop()
        self._loop = loop
        self._stop = asyncio.Event()
        self._ready = asyncio.Event()
        if handle_signals:
            self._install_signals(loop)
        try:
            await self._start()
            await self._stop.wait()
        finally:
            try:
                await self._shutdown()
            finally:
                if handle_signals:
                    for signum in (signal.SIGTERM, signal.SIGINT):
                        loop.remove_signal_handler(signum)
                self._finished.set()

    async def ready(self) -> None:
        """Wait until the engines are open and every service has opened once
        (or failed to). Agents are started by then."""
        while self._ready is None:
            await asyncio.sleep(0.01)
        await self._ready.wait()

    def stop(self, *, force: bool = False) -> None:
        """Begin the shutdown. Thread-safe and idempotent. ``force`` skips the
        drains, and waits :data:`CLOSE_GRACE` seconds at most for the services
        to close: what is cut is left as a crash leaves it, and recovered."""
        loop = self._loop
        if loop is None or self._stop is None:
            return
        if force:
            self._force = True
            if self._engines is not None:
                self._engines.halt()
        if loop.is_closed():
            return
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(self._stop.set)

    def wait_finished(self, timeout: float | None = None) -> bool:
        """From another thread: wait until :meth:`run` has returned."""
        return self._finished.wait(timeout)

    def _install_signals(self, loop: asyncio.AbstractEventLoop) -> None:
        def on_signal() -> None:
            assert self._stop is not None
            if self._stop.is_set():
                logger.warning("a second signal: skipping the remaining drains")
                self.stop(force=True)
            else:
                logger.info("signal received: shutting down")
                self.stop()

        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, on_signal)

    async def _start(self) -> None:
        assert self._loop is not None and self._ready is not None
        if self._engines is not None:
            self._engine_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self._engines.workers, thread_name_prefix="interlock-engine"
            )
            self._reader = concurrent.futures.ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="interlock-facts"
            )
            try:
                await self._loop.run_in_executor(self._engine_executor, self._engines.open)
            except BaseException as exc:
                self._engine_state = FAILED
                self._engine_error = f"{type(exc).__name__}: {exc}"
                raise
            self._engine_state = RUNNING
            self._queue = asyncio.Queue(maxsize=self._engines.queue)
            self._workers = [
                self._loop.create_task(self._engine_worker(index), name=f"engine-{index}")
                for index in range(self._engines.workers)
            ]
            self._accepting = True
        for service in self._services:
            service.bind(self)
            running = _Running(
                service,
                concurrent.futures.ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix=f"interlock-{service.name}"
                ),
            )
            self._running[service.name] = running
            running.task = self._loop.create_task(self._service_loop(running), name=service.name)
        for running in self._running.values():
            await running.opened_once.wait()
        for agent in self._agents:
            self._start_agent(agent)
        self._ready.set()

    # -- the engines --------------------------------------------------------

    async def execute(self, plan: EffectPlan) -> StageResult:
        """Stage ``plan`` on the next free engine, retrying lost races, and
        return its result.

        :raises SupervisorStoppedError: If the supervisor is not accepting
            plans: not started, shutting down, or without engines.
        """
        if not self._accepting or self._queue is None or self._loop is None:
            raise SupervisorStoppedError("the supervisor is not accepting plans")
        future: asyncio.Future[StageResult] = self._loop.create_future()
        self._engine_count("submitted")
        await self._queue.put(_Job(plan, future))
        return await future

    def submit(self, plan: EffectPlan) -> concurrent.futures.Future[StageResult]:
        """:meth:`execute`, from any thread."""
        return self.call(self.execute(plan))

    def call(self, coroutine: Awaitable[T]) -> concurrent.futures.Future[T]:
        """Run a coroutine on the supervisor's loop, from any thread."""
        if self._loop is None:
            if inspect.iscoroutine(coroutine):
                coroutine.close()
            raise SupervisorStoppedError("the supervisor is not running")
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop)  # type: ignore[arg-type]

    async def facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        """The scope's pending inbound facts that verify, read beside the
        engines."""
        if self._engines is None or self._reader is None or self._loop is None:
            raise SupervisorStoppedError("the supervisor has no engines")
        return await self._loop.run_in_executor(self._reader, self._engines.facts, scope_id)

    def _engine_count(self, counter: str) -> None:
        if self._engines is not None:
            self._engines.count(counter)

    async def _engine_worker(self, index: int) -> None:
        assert self._queue is not None and self._engines is not None and self._loop is not None
        while True:
            job = await self._queue.get()
            if job is None:
                return
            if job.future.cancelled():
                continue
            try:
                result = await self._loop.run_in_executor(
                    self._engine_executor, self._engines.execute, index, job.plan
                )
            except BaseException as exc:
                if not job.future.done():
                    job.future.set_exception(exc)
                if isinstance(exc, asyncio.CancelledError):  # pragma: no cover - never cancelled
                    raise
                continue
            if not job.future.done():
                job.future.set_result(result)

    # -- the services ------------------------------------------------------

    async def _service_loop(self, running: _Running) -> None:
        assert self._loop is not None
        service = running.service
        while not running.stop.is_set():
            try:
                if not running.opened:
                    running.state = STARTING
                    await self._loop.run_in_executor(running.executor, service.open)
                    running.opened = True
                    running.opened_once.set()
                running.state = RUNNING
                delay = await self._loop.run_in_executor(running.executor, service.step)
                running.steps += 1
                running.streak = 0
            except Exception as exc:
                running.failures += 1
                running.streak += 1
                running.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "%s failed (%d in a row): %s", service.name, running.streak, running.last_error
                )
                if running.opened:
                    running.opened = False
                    try:
                        await self._loop.run_in_executor(running.executor, service.close)
                    except Exception:
                        logger.exception("%s: closing after a failure failed", service.name)
                running.opened_once.set()
                running.state = BACKING_OFF
                delay = min(self._restart_max, self._restart_min * 2 ** (running.streak - 1))
            if delay > 0:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(running.stop.wait(), timeout=delay)

    # -- agents --------------------------------------------------------------

    def _start_agent(self, agent: _Agent) -> None:
        assert self._loop is not None
        agent.state = RUNNING
        if agent.asynchronous:
            agent.task = self._loop.create_task(
                self._run_async_agent(agent), name=agent.context.name
            )
            return
        loop = self._loop
        done: asyncio.Future[None] = loop.create_future()
        agent.done = done

        def finished(error: BaseException | None) -> None:
            if error is not None:
                agent.state = FAILED
                agent.error = f"{type(error).__name__}: {error}"
            else:
                agent.state = STOPPED
            if not done.done():
                done.set_result(None)

        def run() -> None:
            error: BaseException | None = None
            try:
                agent.function(agent.context)
            except BaseException as exc:  # reported, as an agent's own failure
                logger.exception("agent %s failed", agent.context.name)
                error = exc
            with contextlib.suppress(RuntimeError):  # the loop is gone: nothing to tell
                loop.call_soon_threadsafe(finished, error)

        threading.Thread(target=run, name=f"interlock-{agent.context.name}", daemon=True).start()

    async def _run_async_agent(self, agent: _Agent) -> None:
        try:
            await agent.function(agent.context)
        except asyncio.CancelledError:
            agent.state = STOPPED
            raise
        except Exception as exc:
            logger.exception("agent %s failed", agent.context.name)
            agent.state = FAILED
            agent.error = f"{type(exc).__name__}: {exc}"
            return
        agent.state = STOPPED

    # -- shutdown ----------------------------------------------------------

    async def _wait(self, awaitables: Sequence[Awaitable[Any]], what: str) -> bool:
        """Wait for ``awaitables`` up to the drain bound: not at all once
        forced. Returns whether all finished."""
        pending = [asyncio.ensure_future(a) for a in awaitables]
        if not pending:
            return True
        _, waiting = await asyncio.wait(pending, timeout=0 if self._force else self._drain)
        if waiting:
            logger.warning("shutdown: %d of %s did not finish in time", len(waiting), what)
            return False
        return True

    async def _shutdown(self) -> None:
        assert self._loop is not None
        # 1. Agents.
        for agent in self._agents:
            agent.context._stop()
        await self._wait(
            [a.task for a in self._agents if a.task is not None]
            + [a.done for a in self._agents if a.done is not None],
            "the agents",
        )
        for agent in self._agents:
            if agent.task is not None and not agent.task.done():
                agent.task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await agent.task
        # 2. Engines: no more plans; the queued ones until the deadline.
        self._accepting = False
        engines_idle = True
        if self._queue is not None:
            assert self._engines is not None
            self._engine_state = STOPPING
            if not await self._wait([self._drained()], "the queued plans"):
                self._cancel_queued()
            self._engines.halt()
            for _ in self._workers:
                self._queue.put_nowait(None)
            if self._force:
                engines_idle = await self._wait(self._workers, "the running plans")
            else:
                # Running plans always finish: a stage is never cut.
                await asyncio.gather(*self._workers, return_exceptions=True)
            # A submission that won a place in the queue as it closed.
            self._cancel_queued()
            self._engine_state = STOPPED
        # 3-6. Services, by phase.
        for phase in sorted({r.service.phase for r in self._running.values()}):
            group = [r for r in self._running.values() if r.service.phase == phase]
            for running in group:
                running.state = STOPPING
                running.stop.set()
            await self._wait([r.task for r in group if r.task is not None], "the services")
            for running in group:
                # A service still in its step is not drained: the drain would
                # only queue behind the step, past the bound.
                idle = running.task is None or running.task.done()
                if running.opened and idle and not self._force:
                    try:
                        await self._wait(
                            [self._loop.run_in_executor(running.executor, running.service.drain)],
                            f"{running.service.name}'s drain",
                        )
                    except Exception:
                        logger.exception("%s: its drain failed", running.service.name)
        # 7. Close: the services, the engines, then what they share. The
        # services close together, each on its own thread, within one bound:
        # the drain bound, or once forced a grace, since a close only releases
        # connections and sockets, quick but never instant. A close behind a
        # step still running is left to run after it.
        closing: dict[asyncio.Future[None], str] = {}
        for running in self._running.values():
            try:
                closing[self._loop.run_in_executor(running.executor, running.service.close)] = (
                    running.service.name
                )
            except Exception:
                logger.exception("%s: closing failed", running.service.name)
        if closing:
            bound = min(CLOSE_GRACE, self._drain) if self._force else self._drain
            await asyncio.wait(list(closing), timeout=bound)
            for closed, name in closing.items():
                if not closed.done():
                    logger.warning("shutdown: %s's close did not finish in time", name)
                elif not closed.cancelled() and closed.exception() is not None:
                    logger.error("%s: closing failed", name, exc_info=closed.exception())
        for running in self._running.values():
            running.opened = False
            running.state = STOPPED
            running.executor.shutdown(wait=False)
        if self._engines is not None:
            if self._engine_executor is not None:
                if engines_idle:
                    await self._loop.run_in_executor(self._engine_executor, self._engines.close)
                else:  # forced: a stage still runs, and is left as a crash leaves it
                    logger.warning("shutdown: the engines are left open to a running stage")
                self._engine_executor.shutdown(wait=False)
            if self._reader is not None:
                self._reader.shutdown(wait=False)
        for close in reversed(self._closers):
            try:
                close()
            except Exception:
                logger.exception("closing a shared resource failed")

    async def _drained(self) -> None:
        """Until every queued plan has been taken by a worker, or no worker is
        left to take one (the loop is being torn down). The ones taken are
        answered as they finish."""
        assert self._queue is not None
        while not self._queue.empty() and not all(w.done() for w in self._workers):
            await asyncio.sleep(0.01)

    def _cancel_queued(self) -> None:
        assert self._queue is not None
        while True:
            try:
                job = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if job is None:
                continue
            if not job.future.done():
                self._engine_count("cancelled")
                job.future.set_exception(
                    SupervisorStoppedError(
                        f"plan {job.plan.plan_id} was still queued when the supervisor stopped: "
                        f"it was never staged"
                    )
                )

    # -- health ------------------------------------------------------------

    def status(self) -> dict[str, ServiceStatus]:
        """Every part's health: the engines, each service and each agent."""
        report: dict[str, ServiceStatus] = {}
        if self._engines is not None:
            report["engines"] = ServiceStatus(
                "engines",
                self._engine_state,
                self._engines.counters.get("committed", 0)
                + self._engines.counters.get("refused", 0),
                self._engines.counters.get("failed", 0),
                self._engine_error,
                self._engines.counters,
            )
        for name, running in self._running.items():
            report[name] = ServiceStatus(
                name,
                running.state,
                running.steps,
                running.failures,
                running.last_error,
                running.service.counters,
            )
        for agent in self._agents:
            report[agent.context.name] = ServiceStatus(
                agent.context.name, agent.state, 0, int(agent.error is not None), agent.error, {}
            )
        return report

    @property
    def inbox_port(self) -> int | None:
        """The port the inbox listens on, once it is open; ``None`` without one."""
        for running in self._running.values():
            if isinstance(running.service, InboxService):
                return running.service.port
        return None

    def health(self) -> tuple[int, dict[str, Any]]:
        """``GET /healthz``: ``200`` while the engines and every service are
        running, ``503`` otherwise, with :meth:`status` as JSON."""
        report = self.status()
        services = [s for name, s in report.items() if name == "engines" or name in self._running]
        healthy = bool(services) and all(s.state == RUNNING for s in services)
        body = {
            "status": "ok" if healthy else "degraded",
            "services": {
                name: {
                    "state": s.state,
                    "steps": s.steps,
                    "failures": s.failures,
                    "last_error": s.last_error,
                    "counters": dict(s.counters),
                }
                for name, s in report.items()
            },
        }
        return (200 if healthy else 503), body
