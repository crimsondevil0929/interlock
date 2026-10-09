"""What each part measures, and the daemon's endpoint (``docs/EPIC7_DESIGN.md`` §2.3).

- The engines: each plan's outcome and time, its wait for a worker, every
  race it lost and why, every refusal by a rate window; their saturation.
- Every part: its state, its steps and their time, its failures.
- The relay, each call and what came of it; the settler, each receipt's lag.
- PostgreSQL's waits, for the windows' connection and for their keys' locks.
- ``MetricsService``: what it samples, a sample that fails, and the endpoint.
- The daemon, configured with ``[metrics]``, end to end.
"""

from __future__ import annotations

import asyncio
import time
import urllib.request
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from interlock.exceptions import PoolExhaustedError
from interlock.sampling import STATES, Sample
from interlock.supervisor import InterlockSupervisor, MetricsService
from interlock.telemetry import Metrics
from interlock.types import EffectPlan
from interlock.windows import RateWindow, Requests
from tests.outbox_env import BACKENDS, Outbox, build_either, mail, sms
from tests.settling import Bench
from tests.test_metrics import parse
from tests.test_supervisor import FakeEngine, Recorder, plan, pool, run


class Scripted(FakeEngine):
    """A fake engine whose script may also lose a race for the pool, or be
    refused by a rate window."""

    def execute(self, plan: EffectPlan) -> Any:
        with self.lock:
            step = self.script[0] if self.script else None
            if step in ("pool", "window"):
                self.script.pop(0)
                self.staged.append(plan.plan_id)
        if step == "pool":
            raise PoolExhaustedError("the pool is held")
        if step == "window":
            violation = SimpleNamespace(invariant="rate_window:mail_per_hour")
            return SimpleNamespace(committed=False, verdict=SimpleNamespace(blocking=[violation]))
        return super().execute(plan)


def _series(metrics: Metrics, name: str) -> dict[tuple[tuple[str, str], ...], float]:
    return parse(metrics.render()).get(name, {})


# --------------------------------------------------------------------------
# the engines and every part
# --------------------------------------------------------------------------


def test_the_engines_are_measured_plan_by_plan() -> None:
    engine = Scripted(["commit", "refuse", "conflict", "commit", "pool", "commit", "window"])
    supervisor = InterlockSupervisor(engines=pool([engine]))

    async def body() -> None:
        for n in range(5):
            await supervisor.execute(plan(n))
        scraped = parse(supervisor.metrics.render())
        assert scraped["interlock_engine_workers"] == {(): 1}
        assert scraped["interlock_engine_queue_depth"] == {(): 0}
        assert scraped["interlock_service_up"][(("service", "engines"),)] == 1

    run(supervisor, body)
    metrics = supervisor.metrics
    assert _series(metrics, "interlock_plans_total") == {
        (("outcome", "committed"),): 3,
        (("outcome", "refused"),): 2,
    }
    assert _series(metrics, "interlock_plan_conflicts_total") == {
        (("cause", "lock"),): 1,
        (("cause", "pool"),): 1,
    }
    assert _series(metrics, "interlock_window_refusals_total") == {
        (("window", "mail_per_hour"),): 1
    }
    assert metrics.value("interlock_engine_queue_wait_seconds") == 5
    assert metrics.value("interlock_plan_seconds", outcome="committed") == 3


def test_every_part_is_measured_step_by_step() -> None:
    log: list[tuple[str, str]] = []
    flaky = Recorder("flaky", log, fail=1, every=0.01)
    supervisor = InterlockSupervisor(services=[flaky], restart_min=0.01, restart_max=0.01)

    async def body() -> None:
        # The supervisor's own count: the service's ticks inside its step,
        # before the supervisor has seen the step end.
        while supervisor.status()["flaky"].steps < 3:
            await asyncio.sleep(0.005)
        scraped = parse(supervisor.metrics.render())
        assert scraped["interlock_service_up"] == {(("service", "flaky"),): 1}
        assert scraped["interlock_service_failures_total"] == {(("service", "flaky"),): 1}
        assert scraped["interlock_service_steps_total"][(("service", "flaky"),)] >= 3

    run(supervisor, body)
    # The failed step's time is counted too.
    assert supervisor.metrics.value("interlock_service_step_seconds", service="flaky") >= 4


# --------------------------------------------------------------------------
# the metrics service
# --------------------------------------------------------------------------


def _get(port: int, path: str) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as answer:
        return str(answer.read().decode())


def test_the_metrics_service_samples_serves_and_outlives_a_failed_sample() -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 4, Requests("mail"))
    reads = [
        Sample(
            states={**dict.fromkeys(STATES, 0), "pending": 3, "dead": 1},
            oldest_due=12.5,
            backlog=2,
            oldest_unsettled=7.0,
            facts_pending=5,
            events_unmatched=1,
            windows={"mail_per_hour": (Decimal(3), 2)},
        )
    ]

    def sample() -> Sample:
        if not reads:
            raise RuntimeError("the database is away")
        return reads.pop()

    service = MetricsService(port=0, every=0.02, sample=sample, windows=[window])
    supervisor = InterlockSupervisor(services=[service])

    async def body() -> None:
        deadline = time.monotonic() + 5
        while supervisor.metrics.value("interlock_metrics_sample_errors_total") < 2:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        port = supervisor.metrics_port
        assert port is not None
        text = await asyncio.to_thread(_get, port, "/metrics")
        scraped = parse(text)
        assert scraped["interlock_outbox_messages"][(("state", "pending"),)] == 3
        assert scraped["interlock_outbox_messages"][(("state", "leased"),)] == 0
        assert scraped["interlock_outbox_oldest_due_seconds"] == {(): 12.5}
        assert scraped["interlock_settlement_backlog"] == {(): 2}
        assert scraped["interlock_inbox_facts_pending"] == {(): 5}
        assert scraped["interlock_window_limit"] == {(("window", "mail_per_hour"),): 4}
        assert scraped["interlock_window_saturation"] == {(("window", "mail_per_hour"),): 0.75}
        assert scraped["interlock_window_keys"] == {(("window", "mail_per_hour"),): 2}
        # Failed samples are counted; the service runs on, and so does the endpoint.
        assert scraped["interlock_service_up"][(("service", "metrics"),)] == 1
        assert '"status": "ok"' in await asyncio.to_thread(_get, port, "/healthz")

    run(supervisor, body)


# --------------------------------------------------------------------------
# the relay, the settler, PostgreSQL's waits
# --------------------------------------------------------------------------


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def test_the_relay_measures_each_call(outbox: Outbox) -> None:
    from tests.fakesink import status

    outbox.commit(mail(1), mail(2), sms(3))
    outbox.sink("sms").script(status(400))
    metrics = Metrics()
    with outbox.relay(metrics=metrics) as relay:
        outbox.drain(relay)
    assert _series(metrics, "interlock_deliveries_total") == {
        (("sink", "mail"), ("outcome", "delivered")): 2,
        (("sink", "sms"), ("outcome", "permanent")): 1,
    }
    assert metrics.value("interlock_delivery_seconds", sink="mail") == 2


def test_the_settler_reports_each_receipts_lag(outbox: Outbox, tmp_path: Path) -> None:
    bench = Bench(outbox, tmp_path)
    try:
        bench.book_together(1)
        bench.book_together(2)
        bench.deliver()
        time.sleep(0.05)
        report = bench.settler().settle()
        assert report.receipts == 2 and len(report.lags) == 2
        assert all(lag >= 0.05 for lag in report.lags)
        # Settled once: nothing more to report.
        assert bench.settler().settle().lags == ()
    finally:
        bench.close()


def test_postgresql_measures_its_waits(outbox: Outbox) -> None:
    from interlock import PostgresSubstrate
    from tests.conftest import OBSERVED
    from tests.outbox_env import PostgresOutbox
    from tests.schemas import specs
    from tests.test_windows import requests_plan

    if not isinstance(outbox, PostgresOutbox):
        pytest.skip("PostgreSQL's waits")
    metrics = Metrics()
    substrate = PostgresSubstrate(outbox.pg.agent, tables=specs(*OBSERVED), metrics=metrics)
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    engine = outbox.engine(substrate=substrate, windows=[window])
    assert engine.execute(requests_plan(mail(1))).committed
    assert metrics.value("interlock_pool_wait_seconds") == 1
    assert metrics.value("interlock_window_lock_wait_seconds") == 1
    assert metrics.value("interlock_wait_max_seconds", wait="pool") > 0
    assert metrics.value("interlock_pool_exhausted_total") == 0
