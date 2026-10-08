"""What the metrics cost the daemon (``docs/EPIC7_DESIGN.md`` §2.5).

Plans through the supervisor's whole path (its queue, an engine worker, the
engine pool, a real SQLite stage), measured into the registry and into
``NullMetrics``, in alternating rounds so the machine's drift falls on both::

    uv run python scripts/metrics_overhead.py --plans 2000 --rounds 5

Prints plans per second for each, and the median of the paired rounds'
differences: a round's noise (the disk's fsyncs, mostly) is many times the
registry's cost, which it also prints, timed alone: the calls one plan makes,
and those PostgreSQL's waits add.
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
import statistics
import sys
import tempfile
import time
import timeit
from pathlib import Path
from typing import Any

from interlock import BlastRadius, EscrowEngine, PlanBuilder, SqliteSubstrate, TableSpec
from interlock.supervisor import EnginePool, InterlockSupervisor
from interlock.telemetry import Metrics, NullMetrics

ORDERS = TableSpec(name="orders", primary_key="id", columns=("id", "status", "tenant"))


def _database(directory: Path) -> str:
    path = directory / "bench.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT, tenant TEXT)")
        conn.executemany(
            "INSERT INTO orders (id, status, tenant) VALUES (?, 'new', 'acme')",
            [(n,) for n in range(1, 101)],
        )
    return str(path)


def _plan(n: int) -> Any:
    return (
        PlanBuilder("bench")
        .update(
            table="orders",
            statement="UPDATE orders SET status = :s WHERE id = :id",
            parameters={"s": f"s{n}", "id": 1 + n % 100},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )


def _round(path: str, plans: int, metrics: Metrics) -> float:
    def open_engine(index: int) -> tuple[Any, Any]:
        engine = EscrowEngine(SqliteSubstrate(path, tables=[ORDERS]), checkers=[BlastRadius(5)])
        return engine, lambda: None

    supervisor = InterlockSupervisor(engines=EnginePool(open_engine, workers=1), metrics=metrics)

    async def main() -> float:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        began = time.perf_counter()
        for n in range(plans):
            result = await supervisor.execute(_plan(n))
            assert result.committed
        took = time.perf_counter() - began
        supervisor.stop()
        await running
        return plans / took

    return asyncio.run(main())


def _one_plan(metrics: Metrics) -> None:
    """The registry's calls for one plan: its wait for a worker, its outcome
    and its time."""
    queued = time.monotonic()
    metrics.observe("interlock_engine_queue_wait_seconds", time.monotonic() - queued)
    staged = time.monotonic()
    metrics.inc("interlock_plans_total", outcome="committed")
    metrics.observe("interlock_plan_seconds", time.monotonic() - staged, outcome="committed")


def _waits(metrics: Metrics) -> None:
    """What PostgreSQL adds for a plan with a rate window: its two waits."""
    for wait, name in (
        ("pool", "interlock_pool_wait_seconds"),
        ("window_lock", "interlock_window_lock_wait_seconds"),
    ):
        metrics.observe(name, 0.001)
        metrics.observe("interlock_wait_max_seconds", 0.001, wait=wait)


def _microseconds(call: Any, metrics: Metrics, number: int = 100_000) -> float:
    return 1e6 * min(timeit.repeat(lambda: call(metrics), number=number, repeat=5)) / number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--plans", type=int, default=2000)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as directory:
        path = _database(Path(directory))
        _round(path, 200, NullMetrics())  # warm up
        measured: list[float] = []
        nothing: list[float] = []
        for _ in range(args.rounds):
            nothing.append(_round(path, args.plans, NullMetrics()))
            measured.append(_round(path, args.plans, Metrics()))
    plain, metered = statistics.median(nothing), statistics.median(measured)
    paired = statistics.median(100 * (m - n) / n for m, n in zip(measured, nothing, strict=True))
    print(f"plans per second, median of {args.rounds} rounds of {args.plans}:")
    print(f"  NullMetrics  {plain:8.1f}  ({', '.join(f'{v:.0f}' for v in nothing)})")
    print(f"  Metrics      {metered:8.1f}  ({', '.join(f'{v:.0f}' for v in measured)})")
    print(f"  difference, median of the paired rounds  {paired:+.1f}%")
    print("the registry alone, microseconds:")
    for label, call in (("one plan", _one_plan), ("PostgreSQL's waits", _waits)):
        spent = _microseconds(call, Metrics()) - _microseconds(call, NullMetrics())
        print(f"  {label:20s} {spent:5.2f}  ({100 * spent * plain / 1e6:.2f}% of a plan here)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
