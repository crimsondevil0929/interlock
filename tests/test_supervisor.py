"""The supervisor (``docs/EPIC6_DESIGN.md`` §2), with services and engines it
can be watched through: no database here. ``tests/test_daemon.py`` runs the
real parts, on both stores.

- A service's steps run on its own thread, paced by what each returns.
- A step that raises closes the service and opens it again, after a backoff
  that doubles with each failure in a row.
- Shutdown runs in order: agents, engines, then services by phase, each
  drained; then they all close together. Every wait is bounded, and a forced
  stop waits for nothing but the closes, for a grace.
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
    CLOSE_GRACE,
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
        hold: threading.Event | None = None,
        close_seconds: float = 0.0,
        closing: threading.Barrier | None = None,
    ) -> None:
        super().__init__(name)
        self.phase = phase  # type: ignore[misc]
        self.log = log
        self.fail = fail
        self.fail_open = fail_open
        self.step_seconds = step_seconds
        self.every = every
        self.hold = hold
        self.close_seconds = close_seconds
        self.closing = closing
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
        if self.hold is not None:  # stuck until released, or for 10s
            self.hold.wait(10)
        self.count("steps")
        return self.every

    def drain(self) -> None:
        self.log.append((self.name, "drain"))

    def close(self) -> None:
        if self.closing is not None:
            self.closing.wait()
        if self.close_seconds:
            time.sleep(self.close_seconds)
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


def test_the_services_close_together() -> None:
    log: list[tuple[str, str]] = []
    # Each close waits for the others to begin: closed one at a time, none ends.
    together = threading.Barrier(3, timeout=5)
    services = [Recorder(name, log, closing=together) for name in ("inbox", "relay", "settler")]
    supervisor = InterlockSupervisor(services=services)

    async def body() -> None:
        await asyncio.sleep(0.02)

    run(supervisor, body)
    assert sorted(n for n, e in log if e == "close") == ["inbox", "relay", "settler"]


def test_a_close_that_fails_is_reported_and_the_others_still_close(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Broken(Recorder):
        def close(self) -> None:
            raise RuntimeError("the socket is gone")

    log: list[tuple[str, str]] = []
    supervisor = InterlockSupervisor(services=[Broken("relay", log), Recorder("settler", log)])

    async def body() -> None:
        await asyncio.sleep(0.02)

    run(supervisor, body)
    assert ("settler", "close") in log
    assert "relay: closing failed" in caplog.text and "the socket is gone" in caplog.text
    assert {name: s.state for name, s in supervisor.status().items()} == {
        "relay": "stopped",
        "settler": "stopped",
    }


def test_a_forced_stop_skips_the_drains_and_gives_the_closes_a_grace() -> None:
    log: list[tuple[str, str]] = []
    release = threading.Event()
    idle = Recorder("relay", log, close_seconds=0.2)
    stuck = Recorder("stuck", log, hold=release)
    supervisor = InterlockSupervisor(services=[idle, stuck], drain_timeout=30)

    async def main() -> float:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        deadline = time.monotonic() + 5
        while ("stuck", "step") not in log:  # its step is in flight
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        began = time.monotonic()
        supervisor.stop(force=True)
        await running
        return time.monotonic() - began

    try:
        elapsed = asyncio.run(main())
        # Not the step in flight, nor the 30s drain bound: the closes' grace.
        assert elapsed < CLOSE_GRACE + 1.0
        assert ("relay", "drain") not in log and ("stuck", "drain") not in log
        # The idle service's close ran to its end before the stop returned; the
        # one behind the step in flight is left to run after it.
        assert ("relay", "close") in log
        assert ("stuck", "close") not in log
    finally:
        release.set()
    deadline = time.monotonic() + 3
    while ("stuck", "close") not in log and time.monotonic() < deadline:
        time.sleep(0.01)
    assert log[-1] == ("stuck", "close") and ("stuck", "drain") not in log


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


# -- reload (docs/EPIC8_DESIGN.md §3) ----------------------------------------------


def test_a_reload_opens_every_service_again_between_its_steps() -> None:
    log: list[tuple[str, str]] = []
    release = threading.Event()
    busy = Recorder("busy", log, hold=release)
    idle = Recorder("idle", log, every=10.0)
    engine = FakeEngine()
    engines = pool([engine])
    supervisor = InterlockSupervisor(engines=engines, services=[busy, idle])

    async def body() -> dict[str, str | None]:
        while ("busy", "step") not in log:
            await asyncio.sleep(0.005)
        reloading = asyncio.ensure_future(supervisor.reload())
        await asyncio.sleep(0.05)
        # The idle one is woken from its wait; the busy one finishes its step.
        assert log.count(("idle", "open")) == 2
        assert log.count(("busy", "open")) == 1 and not reloading.done()
        release.set()
        return await reloading

    assert run(supervisor, body) == {"busy": None, "idle": None}
    busy_log = [event for name, event in log if name == "busy"]
    assert busy_log[:4] == ["open", "step", "close", "open"]
    # Opened again, and its next step left where its pace put it.
    assert log.count(("idle", "step")) == 1
    assert busy.counters["reloads"] == idle.counters["reloads"] == 1
    # The engines were not touched.
    assert engines.closed == [0]  # type: ignore[attr-defined]
    assert all(s.failures == 0 for s in supervisor.status().values())


def test_a_service_that_cannot_open_again_backs_off_and_the_reload_says_why() -> None:
    log: list[tuple[str, str]] = []
    fragile = Recorder("fragile", log, every=10.0)
    supervisor = InterlockSupervisor(services=[fragile], restart_min=0.02, restart_max=0.02)

    async def body() -> dict[str, str | None]:
        fragile.fail_open = 1
        outcome = await supervisor.reload()
        while fragile.counters.get("steps", 0) < 2:
            await asyncio.sleep(0.005)
        return outcome

    assert run(supervisor, body) == {"fragile": "RuntimeError: cannot open"}
    status = supervisor.status()["fragile"]
    assert status.failures == 1 and status.last_error == "RuntimeError: cannot open"
    events = [event for name, event in log]
    # Closed for the reload; the open that failed, closed as any failure is;
    # opened again after the backoff.
    assert events[:7] == ["open", "step", "close", "open", "close", "open", "step"]


def test_a_reload_opens_a_service_backing_off_at_once() -> None:
    log: list[tuple[str, str]] = []
    down = Recorder("down", log, fail_open=1, every=10.0)
    supervisor = InterlockSupervisor(services=[down], restart_min=30.0, restart_max=30.0)
    started = time.monotonic()

    async def body() -> dict[str, str | None]:
        return await supervisor.reload()

    assert run(supervisor, body) == {"down": None}
    assert time.monotonic() - started < 5.0
    assert [event for name, event in log][:3] == ["open", "open", "step"]


def test_a_reload_is_refused_unless_the_supervisor_runs() -> None:
    supervisor = InterlockSupervisor(services=[Recorder("a", [])])
    with pytest.raises(SupervisorStoppedError):
        asyncio.run(supervisor.reload())

    async def body() -> None:
        supervisor.stop()
        await asyncio.sleep(0)
        with pytest.raises(SupervisorStoppedError):
            await supervisor.reload()

    run(supervisor, body)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_sighup_reloads_and_says_what_it_did() -> None:
    log: list[tuple[str, str]] = []
    relay = Recorder("relay", log, every=10.0)
    supervisor = InterlockSupervisor(services=[relay])
    told: list[dict[str, str | None]] = []
    supervisor.on_reload(lambda outcome: told.append(dict(outcome)))

    async def main() -> None:
        running = asyncio.create_task(supervisor.run(handle_signals=True))
        await supervisor.ready()
        os.kill(os.getpid(), signal.SIGHUP)
        while not told:
            await asyncio.sleep(0.005)
        supervisor.stop()
        await running

    asyncio.run(main())
    assert told == [{"relay": None}]
    assert log.count(("relay", "open")) == 2
    # The handlers are removed with the run.
    assert signal.getsignal(signal.SIGHUP) in (signal.SIG_DFL, cast(Any, None))


def test_a_failed_service_is_backing_off_while_it_closes() -> None:
    log: list[tuple[str, str]] = []
    slow = Recorder("slow", log, fail=1, close_seconds=0.3)
    supervisor = InterlockSupervisor(services=[slow], restart_min=0.01, restart_max=0.01)
    seen: list[tuple[str, int]] = []

    async def body() -> None:
        while ("slow", "close") not in log:
            status = supervisor.status()["slow"]
            seen.append((status.state, status.failures))
            await asyncio.sleep(0.01)

    run(supervisor, body)
    # Counted as failed, and never reported running, until it had closed.
    assert ("running", 1) not in seen and ("backing-off", 1) in seen


def test_an_inbox_swapped_answers_what_it_took_and_the_new_one_the_rest() -> None:
    from interlock.supervisor import _CountingInbox

    class Answer:
        status = 202

        def __init__(self) -> None:
            self.body: dict[str, int] = {}

    class Fake:
        _max_body = 1024

        def __init__(self, gate: threading.Event | None = None) -> None:
            self.gate = gate
            self.took: list[bytes] = []
            self._sources = {"s": object()}

        def receive(self, name: str, headers: dict[str, str], body: bytes) -> Answer:
            self.took.append(body)
            if self.gate is not None:
                self.gate.wait(10)
            return Answer()

    gate = threading.Event()
    old, new = Fake(gate), Fake()
    counting = _CountingInbox(cast(Any, old), Recorder("inbox", []))
    in_flight = threading.Thread(target=counting.receive, args=("s", {}, b"first"))
    in_flight.start()
    while not old.took:
        time.sleep(0.005)
    swapped = threading.Thread(target=counting.swap, args=(cast(Any, new),))
    swapped.start()
    time.sleep(0.05)
    # Every later webhook is the new inbox's; the swap waits for the old one's.
    counting.receive("s", {}, b"second")
    assert swapped.is_alive() and new.took == [b"second"]
    gate.set()
    swapped.join(5)
    in_flight.join(5)
    assert not swapped.is_alive() and old.took == [b"first"]


def test_a_reload_keeps_the_settlers_and_the_vacuums_governors() -> None:
    """Neither holds a key a reload rotates, and each holds an AgentGov
    governor, which opens under the ledger's writer lock while every engine
    waits: a reload opens neither again (``docs/EPIC8_DESIGN.md`` §3)."""
    from interlock.supervisor import SettlerService, VacuumService

    opened: list[str] = []
    closed: list[str] = []

    class Settled:
        def settle(self) -> Any:
            class Report:
                settled: tuple[()] = ()
                receipts = credits = 0
                problems: tuple[()] = ()
                lags: tuple[()] = ()

            return Report()

    def open_settler() -> tuple[Any, Callable[[], None]]:
        opened.append("settler")
        return Settled(), lambda: closed.append("settler")

    settler = SettlerService(open_settler, every=10.0)
    vacuum = VacuumService(
        lambda: cast(Any, None), every=10.0, close=lambda: closed.append("vacuum")
    )
    vacuum.step = lambda: 10.0  # type: ignore[method-assign]
    supervisor = InterlockSupervisor(services=[settler, vacuum])

    async def body() -> dict[str, str | None]:
        return await supervisor.reload()

    assert run(supervisor, body) == {"settler": None, "vacuum": None}
    # Opened once, at the start; closed once, at the stop.
    assert opened == ["settler"] and sorted(closed) == ["settler", "vacuum"]
