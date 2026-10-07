"""The supervisor (``docs/EPIC6_DESIGN.md`` §2), with services and engines it
can be watched through: no database here. ``tests/test_daemon.py`` runs the
real parts, on both stores.

- A service's steps run on its own thread, paced by what each returns.
- A step that raises closes the service and opens it again, after a backoff
  that doubles with each failure in a row.
- Shutdown runs in order: agents, engines, then services by phase, each
  drained and closed; every wait is bounded, and a forced stop waits for
  nothing.
- The engines retry a plan that lost a race, never one whose commit is
  unsettled; plans queued at a stop are staged until the deadline, and the
  rest refused, never half-staged.
- Health is ``200`` while everything runs, ``503`` otherwise.
"""

from __future__ import annotations

import asyncio
import os
import signal
import threading
import time
from collections.abc import Callable
from typing import Any, cast

import pytest

from interlock import PlanBuilder
from interlock.exceptions import (
    CommitUnsettledError,
    StageConflictError,
    SupervisorStoppedError,
)
from interlock.supervisor import (
    AgentContext,
    EnginePool,
    InterlockSupervisor,
    Service,
)
from interlock.types import EffectPlan


def plan(n: int = 0) -> EffectPlan:
    return (
        PlanBuilder("agent", intent=f"plan {n}")
        .update(table="orders", statement="UPDATE orders SET status = 'x' WHERE id = 1")
        .build()
    )


class Recorder(Service):
    """A service writing what happened to it into a shared log."""

    def __init__(
        self,
        name: str,
        log: list[tuple[str, str]],
        *,
        phase: int = 3,
        fail: int = 0,
        step_seconds: float = 0.0,
        every: float = 0.01,
        fail_open: int = 0,
    ) -> None:
        super().__init__(name)
        self.phase = phase  # type: ignore[misc]
        self.log = log
        self.fail = fail
        self.fail_open = fail_open
        self.step_seconds = step_seconds
        self.every = every
        self.threads: set[str] = set()

    def open(self) -> None:
        self.log.append((self.name, "open"))
        if self.fail_open:
            self.fail_open -= 1
            raise RuntimeError("cannot open")

    def step(self) -> float:
        self.threads.add(threading.current_thread().name)
        self.log.append((self.name, "step"))
        if self.fail:
            self.fail -= 1
            raise RuntimeError("a step failed")
        if self.step_seconds:
            time.sleep(self.step_seconds)
        self.count("steps")
        return self.every

    def drain(self) -> None:
        self.log.append((self.name, "drain"))

    def close(self) -> None:
        self.log.append((self.name, "close"))


class Result:
    def __init__(self, committed: bool) -> None:
        self.committed = committed


class FakeEngine:
    """An engine answering from a script: ``"commit"``, ``"refuse"``,
    ``"conflict"``, ``"unsettled"``, or seconds to take, then commit."""

    def __init__(self, script: list[Any] | None = None) -> None:
        self.script = list(script or [])
        self.staged: list[str] = []
        self.lock = threading.Lock()

    def recover(self) -> tuple[()]:
        return ()

    def facts(self, scope_id: str) -> tuple[()]:
        return ()

    def execute(self, plan: EffectPlan) -> Result:
        with self.lock:
            step = self.script.pop(0) if self.script else "commit"
            self.staged.append(plan.plan_id)
        if step == "conflict":
            raise StageConflictError("lost the race")
        if step == "unsettled":
            raise CommitUnsettledError("lost the answer")
        if isinstance(step, float):
            time.sleep(step)
            step = "commit"
        return Result(step == "commit")


def pool(engines: list[FakeEngine], **kwargs: Any) -> EnginePool:
    closed: list[int] = []

    def open_engine(index: int) -> tuple[Any, Callable[[], None]]:
        return engines[index], lambda: closed.append(index)

    built = EnginePool(open_engine, workers=len(engines), **kwargs)
    built.closed = closed  # type: ignore[attr-defined]
    return built


def run(supervisor: InterlockSupervisor, body: Callable[[], Any]) -> Any:
    """Run ``supervisor`` while ``body`` runs on the loop, then stop it."""

    async def main() -> Any:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        try:
            return await body()
        finally:
            supervisor.stop()
            await running

    return asyncio.run(main())


# -- services --------------------------------------------------------------------


def test_a_service_steps_on_its_own_thread_paced_by_each_step() -> None:
    log: list[tuple[str, str]] = []
    fast = Recorder("fast", log, every=0.005)
    slow = Recorder("slow", log, every=10.0)
    supervisor = InterlockSupervisor(services=[fast, slow])

    async def body() -> None:
        await asyncio.sleep(0.2)

    run(supervisor, body)
    assert fast.counters["steps"] > 5
    assert slow.counters["steps"] == 1
    assert fast.threads.isdisjoint(slow.threads)
    status = supervisor.status()
    assert {name: s.state for name, s in status.items()} == {"fast": "stopped", "slow": "stopped"}
    assert status["fast"].steps == fast.counters["steps"]


def test_a_failing_service_is_reopened_after_a_doubling_backoff() -> None:
    log: list[tuple[str, str]] = []
    flaky = Recorder("flaky", log, fail=3, every=0.01)
    supervisor = InterlockSupervisor(services=[flaky], restart_min=0.02, restart_max=0.05)
    started = time.monotonic()

    async def body() -> None:
        while flaky.counters.get("steps", 0) < 2:
            await asyncio.sleep(0.005)

    run(supervisor, body)
    # Three failures: backed off 0.02, 0.04, then the cap, 0.05.
    assert time.monotonic() - started >= 0.11
    status = supervisor.status()["flaky"]
    assert (status.failures, status.last_error) == (3, "RuntimeError: a step failed")
    events = [event for name, event in log]
    # Each failure closed the service, and it was opened again.
    assert events[:9] == ["open", "step", "close"] * 3


def test_a_service_that_cannot_open_is_retried_and_reported() -> None:
    log: list[tuple[str, str]] = []
    stubborn = Recorder("stubborn", log, fail_open=2)
    supervisor = InterlockSupervisor(services=[stubborn], restart_min=0.01, restart_max=0.01)

    async def body() -> None:
        while stubborn.counters.get("steps", 0) < 1:
            await asyncio.sleep(0.005)

    run(supervisor, body)
    assert supervisor.status()["stubborn"].failures == 2
    assert log[:3] == [("stubborn", "open")] * 3


def test_shutdown_runs_in_order_and_drains_and_closes_each_service() -> None:
    log: list[tuple[str, str]] = []
    services = [
        Recorder("vacuum", log, phase=5),
        Recorder("relay", log, phase=3),
        Recorder("inbox", log, phase=2),
        Recorder("settler", log, phase=4),
    ]
    engine = FakeEngine()
    supervisor = InterlockSupervisor(engines=pool([engine]), services=services)
    stopped_at: list[str] = []

    async def agent(ctx: AgentContext) -> None:
        while not ctx.stopping:
            await ctx.sleep(1.0)
        stopped_at.append("agent")
        log.append(("agent", "stopped"))

    supervisor.agent(agent)

    async def body() -> None:
        await asyncio.sleep(0.05)

    run(supervisor, body)
    after = [(n, e) for n, e in log if e in ("drain", "close", "stopped")]
    assert after[0] == ("agent", "stopped")
    drains = [n for n, e in after if e == "drain"]
    assert drains == ["inbox", "relay", "settler", "vacuum"]
    closes = [n for n, e in after if e == "close"]
    assert sorted(closes) == ["inbox", "relay", "settler", "vacuum"]
    assert after.index(("vacuum", "drain")) < after.index(("inbox", "close"))
    assert supervisor.status()["engines"].state == "stopped"
    assert stopped_at == ["agent"]


def test_every_shutdown_wait_is_bounded() -> None:
    log: list[tuple[str, str]] = []
    stuck = Recorder("stuck", log, step_seconds=1.0)
    supervisor = InterlockSupervisor(services=[stuck], drain_timeout=0.1)
    started = time.monotonic()

    async def body() -> None:
        await asyncio.sleep(0.05)

    run(supervisor, body)
    # The step in flight was waited for 0.1s, not its whole second, and not
    # drained; its close runs once the step ends.
    assert time.monotonic() - started < 0.9
    assert ("stuck", "drain") not in log
    deadline = time.monotonic() + 3
    while ("stuck", "close") not in log and time.monotonic() < deadline:
        time.sleep(0.01)
    # Nor drained once the step ended: a drain queued behind it would run then.
    assert log[-1] == ("stuck", "close") and ("stuck", "drain") not in log


def test_a_forced_stop_skips_the_drains() -> None:
    log: list[tuple[str, str]] = []
    service = Recorder("relay", log)
    stuck = Recorder("stuck", log, step_seconds=1.0)
    supervisor = InterlockSupervisor(services=[service, stuck], drain_timeout=30)

    async def main() -> float:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        await asyncio.sleep(0.05)
        began = time.monotonic()
        supervisor.stop(force=True)
        await running
        return time.monotonic() - began

    # Not the step in flight, nor the 30s drain bound: nothing is waited for.
    assert asyncio.run(main()) < 0.5
    assert ("relay", "drain") not in log and ("stuck", "drain") not in log
    assert ("relay", "close") in log


def test_health_is_ok_only_while_everything_runs() -> None:
    log: list[tuple[str, str]] = []
    good = Recorder("good", log)
    flaky = Recorder("flaky", log, fail=1000)
    supervisor = InterlockSupervisor(services=[good, flaky], restart_min=0.05, restart_max=0.05)

    async def body() -> tuple[int, dict[str, Any]]:
        await asyncio.sleep(0.03)
        return supervisor.health()

    status, report = run(supervisor, body)
    assert status == 503 and report["status"] == "degraded"
    assert report["services"]["flaky"]["state"] == "backing-off"
    assert report["services"]["good"]["state"] == "running"
    healthy = InterlockSupervisor(services=[Recorder("only", log)])

    async def check() -> tuple[int, dict[str, Any]]:
        await asyncio.sleep(0.02)
        return healthy.health()

    assert run(healthy, check)[0] == 200


def test_names_and_bounds_are_checked() -> None:
    log: list[tuple[str, str]] = []
    with pytest.raises(ValueError, match="share a name"):
        InterlockSupervisor(services=[Recorder("a", log), Recorder("a", log)])
    with pytest.raises(ValueError, match="restart_min"):
        InterlockSupervisor(restart_min=0)
    with pytest.raises(ValueError, match="at least one worker"):
        EnginePool(lambda n: (FakeEngine(), lambda: None), workers=0)  # type: ignore[arg-type,return-value]


# -- engines ---------------------------------------------------------------------


def test_plans_run_concurrently_one_per_worker() -> None:
    engines = [FakeEngine([0.1] * 4) for _ in range(4)]
    supervisor = InterlockSupervisor(engines=pool(engines))
    started = time.monotonic()

    async def body() -> list[Any]:
        return list(await asyncio.gather(*(supervisor.execute(plan(n)) for n in range(8))))

    results = run(supervisor, body)
    assert all(r.committed for r in results)
    # Eight plans of 0.1s on four workers: two rounds, not eight.
    assert time.monotonic() - started < 0.6
    assert sum(len(e.staged) for e in engines) == 8
    counters = supervisor.status()["engines"].counters
    assert (counters["submitted"], counters["committed"]) == (8, 8)


def test_a_lost_race_is_retried_and_an_unsettled_commit_never() -> None:
    engine = FakeEngine(["conflict", "conflict", "commit", "unsettled"])
    supervisor = InterlockSupervisor(engines=pool([engine], conflict_retries=3))

    async def body() -> tuple[Any, BaseException | None]:
        first = await supervisor.execute(plan(1))
        try:
            await supervisor.execute(plan(2))
        except CommitUnsettledError as exc:
            return first, exc
        return first, None

    first, unsettled = run(supervisor, body)
    assert first.committed and isinstance(unsettled, CommitUnsettledError)
    # The first plan staged three times; the unsettled one once.
    assert len(engine.staged) == 4
    counters = supervisor.status()["engines"].counters
    assert (counters["conflicts"], counters["unsettled"]) == (2, 1)


def test_a_race_lost_every_time_is_the_agents() -> None:
    engine = FakeEngine(["conflict"] * 10)
    supervisor = InterlockSupervisor(engines=pool([engine], conflict_retries=2))

    async def body() -> BaseException | None:
        try:
            await supervisor.execute(plan())
        except StageConflictError as exc:
            return exc
        return None

    assert isinstance(run(supervisor, body), StageConflictError)
    assert len(engine.staged) == 3
    assert supervisor.status()["engines"].counters["conflicts_exhausted"] == 1


def test_a_plan_waiting_to_race_again_is_refused_when_the_supervisor_stops() -> None:
    """A plan between two attempts is not staged again once the supervisor
    stops: it is refused, never half-staged, and the stop does not wait out
    its backoff."""
    engine = FakeEngine(["conflict"] * 10)
    supervisor = InterlockSupervisor(
        engines=pool([engine], conflict_retries=5, retry_base=5.0, retry_cap=5.0)
    )

    async def main() -> BaseException | None:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        waiting = asyncio.create_task(supervisor.execute(plan()))
        while not engine.staged:
            await asyncio.sleep(0.01)
        began = time.monotonic()
        supervisor.stop()
        await running
        assert time.monotonic() - began < 3
        try:
            await waiting
        except SupervisorStoppedError as exc:
            return exc
        return None

    assert isinstance(asyncio.run(main()), SupervisorStoppedError)
    assert len(engine.staged) == 1
    assert supervisor.status()["engines"].counters["cancelled"] == 1


def test_a_vacuum_that_finds_the_operator_log_busy_tries_again_soon() -> None:
    from contextlib import contextmanager
    from types import SimpleNamespace

    from interlock.exceptions import ChainInUseError
    from interlock.supervisor import VacuumService

    runs: list[str] = []

    class Run:
        def run(self, *, reason: str) -> Any:
            runs.append(reason)
            return SimpleNamespace(
                outcome="applied", messages=2, window_rows=3, inbox_events=4, problems=()
            )

    @contextmanager
    def open_vacuum() -> Any:
        if not runs and not busy:
            busy.append(True)
            raise ChainInUseError("an operator holds the log")
        yield Run()

    busy: list[bool] = []
    closed: list[bool] = []
    service = VacuumService(
        open_vacuum, every=60, busy_retry=0.05, close=lambda: closed.append(True)
    )
    supervisor = InterlockSupervisor(services=[service])

    async def body() -> None:
        deadline = time.monotonic() + 2  # the busy retry, not the 60s interval
        while not runs:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)

    run(supervisor, body)
    counters = supervisor.status()["vacuum"].counters
    assert (counters["busy"], counters["applied"], counters["messages"]) == (1, 1, 2)
    assert runs == ["scheduled by the daemon"] and closed == [True]


def test_at_a_stop_queued_plans_run_until_the_deadline_and_the_rest_are_refused() -> None:
    engine = FakeEngine([0.2] * 10)
    supervisor = InterlockSupervisor(engines=pool([engine]), drain_timeout=0.3)
    outcomes: list[str] = []

    async def main() -> None:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        submitted = [asyncio.create_task(supervisor.execute(plan(n))) for n in range(6)]
        await asyncio.sleep(0.05)
        supervisor.stop()
        for task in submitted:
            try:
                await task
                outcomes.append("committed")
            except SupervisorStoppedError:
                outcomes.append("refused")
        await running
        with pytest.raises(SupervisorStoppedError, match="not accepting"):
            await supervisor.execute(plan(99))

    asyncio.run(main())
    # One running at the stop, one or two taken before the deadline; the
    # rest never staged.
    assert outcomes.count("committed") == len(engine.staged)
    assert 2 <= len(engine.staged) <= 3
    assert outcomes.count("refused") == 6 - len(engine.staged)
    assert supervisor.status()["engines"].counters["cancelled"] == outcomes.count("refused")


def test_engines_are_closed_after_the_services() -> None:
    log: list[tuple[str, str]] = []
    engines = pool([FakeEngine()])
    supervisor = InterlockSupervisor(engines=engines, services=[Recorder("settler", log)])
    closed: list[str] = []
    supervisor.on_close(lambda: closed.append("shared"))

    async def body() -> None:
        await asyncio.sleep(0.02)

    run(supervisor, body)
    assert engines.closed == [0]  # type: ignore[attr-defined]
    assert closed == ["shared"]
    assert ("settler", "close") in log


def test_an_engine_that_cannot_open_fails_the_start() -> None:
    def broken(index: int) -> tuple[Any, Callable[[], None]]:
        raise RuntimeError("no database")

    supervisor = InterlockSupervisor(engines=EnginePool(broken))
    with pytest.raises(RuntimeError, match="no database"):
        asyncio.run(supervisor.run())
    assert supervisor.status()["engines"].state == "failed"


# -- agents ----------------------------------------------------------------------


def test_async_and_threaded_agents_run_and_stop() -> None:
    engine = FakeEngine()
    supervisor = InterlockSupervisor(engines=pool([engine]))
    seen: list[str] = []

    @supervisor.agent
    async def eager(ctx: AgentContext) -> None:
        while not ctx.stopping:
            result = await ctx.execute(plan())
            assert result.committed
            seen.append("async")
            await ctx.sleep(0.01)

    def patient(ctx: AgentContext) -> None:
        while not ctx.stopping:
            assert ctx.execute_blocking(plan()).committed
            assert ctx.facts_blocking("agent") == ()
            seen.append("thread")
            ctx.sleep_blocking(0.01)

    supervisor.agent(patient, name="patient")

    async def body() -> None:
        while not ({"async", "thread"} <= set(seen)):
            await asyncio.sleep(0.01)

    run(supervisor, body)
    states = {n: s.state for n, s in supervisor.status().items() if n != "engines"}
    assert states == {"eager-0": "stopped", "patient-1": "stopped"}


def test_an_agent_that_raises_is_reported_and_the_rest_run_on() -> None:
    supervisor = InterlockSupervisor(engines=pool([FakeEngine()]))

    async def broken(ctx: AgentContext) -> None:
        raise ValueError("a bug")

    supervisor.agent(broken)

    async def body() -> int:
        await asyncio.sleep(0.02)
        return len(supervisor.status())

    run(supervisor, body)
    status = supervisor.status()["broken-0"]
    assert (status.state, status.last_error) == ("failed", "ValueError: a bug")
    with pytest.raises(RuntimeError, match="before the supervisor runs"):
        supervisor.agent(broken)


def test_a_submission_from_another_thread() -> None:
    supervisor = InterlockSupervisor(engines=pool([FakeEngine()]))
    results: list[bool] = []

    async def body() -> None:
        def submit() -> None:
            results.append(supervisor.submit(plan()).result(timeout=5).committed)

        thread = threading.Thread(target=submit)
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(0.01)

    run(supervisor, body)
    assert results == [True]
    with pytest.raises(SupervisorStoppedError):
        InterlockSupervisor().submit(plan())


# -- signals ---------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_sigterm_stops_and_a_second_skips_the_drains() -> None:
    log: list[tuple[str, str]] = []
    slow = Recorder("relay", log, step_seconds=0.3)
    supervisor = InterlockSupervisor(services=[slow], drain_timeout=5.0)

    async def main() -> None:
        running = asyncio.create_task(supervisor.run(handle_signals=True))
        await supervisor.ready()
        await asyncio.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(0.05)
        os.kill(os.getpid(), signal.SIGTERM)
        await running

    started = time.monotonic()
    asyncio.run(main())
    assert time.monotonic() - started < 2.0
    assert ("relay", "drain") not in log
    assert supervisor.wait_finished(0)
    # The handlers are removed with the run.
    assert signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, cast(Any, None))
