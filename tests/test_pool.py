"""The rate windows' second connection (``docs/EPIC7_DESIGN.md`` §3).

- Had within the pool timeout, or :class:`PoolExhaustedError`, retryable:
  whether a pooler answers the cancel of a client it is holding or not, and
  whether the server refuses the connection outright.
- Refused, the stage is aborted: it holds no lock, and the plan commits once a
  connection is free.
- The read is one transaction that leaves nothing in the session, and nothing
  is prepared on the server, for a transaction-mode pooler.
- An agent's facts are read the pooler-safe way too, waiting their turn.
- Behind a real PgBouncer (``INTERLOCK_TEST_PGBOUNCER``), the stage that would
  wait on itself fails fast; plans from several workers all commit; and the
  server connections are left as the pool found them.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from interlock import BlastRadius, PlanBuilder, PostgresSubstrate
from interlock.exceptions import PoolExhaustedError, StageConflictError
from interlock.supervisor import EnginePool
from interlock.windows import RateWindow, Requests
from tests.conftest import OBSERVED, Pg
from tests.fakepg import fake_pooler
from tests.outbox_env import SCOPE, PostgresOutbox, build_outbox, mail
from tests.schemas import specs

PGBOUNCER = os.environ.get("INTERLOCK_TEST_PGBOUNCER", "")
"""``host:port`` of a PgBouncer in transaction mode, two server connections per
pool, in front of the test cluster (``tests/pgbouncer/pgbouncer.ini``)."""


def _substrate(dsn: str, pool: float) -> PostgresSubstrate:
    return PostgresSubstrate(dsn, tables=specs(*OBSERVED), pool_timeout_seconds=pool)


def test_the_pool_timeout_defaults_to_the_lock_timeout_and_reaches_the_substrate(
    tmp_path: Path,
) -> None:
    from interlock.config import ConfigError, load_config
    from interlock.wiring import open_substrate

    spec = specs("orders")
    assert PostgresSubstrate("", tables=spec, lock_timeout_seconds=1.5)._pool_seconds == 1.5
    assert PostgresSubstrate("", tables=spec, pool_timeout_seconds=0.25)._pool_seconds == 0.25
    with pytest.raises(ValueError, match="positive"):
        PostgresSubstrate("", tables=spec, pool_timeout_seconds=0)
    body = (
        'substrate = "postgres"\ndatabase = "postgresql://agent@db/app"\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id", "status"]\n[engine]\n'
    )
    path = tmp_path / "interlock.toml"
    path.write_text(body + "pool_timeout_seconds = 0.5\n")
    substrate = open_substrate(load_config(path))
    assert isinstance(substrate, PostgresSubstrate) and substrate._pool_seconds == 0.5
    path.write_text(body + "lock_timeout_seconds = 1.25\n")
    config = load_config(path)
    assert config.engine.pool_timeout_seconds is None
    assert open_substrate(config)._pool_seconds == 1.25  # type: ignore[attr-defined]
    path.write_text(body + "pool_timeout_seconds = 0\n")
    with pytest.raises(ConfigError, match="pool_timeout_seconds"):
        load_config(path)


# --------------------------------------------------------------------------
# a pooler's queue, faked
# --------------------------------------------------------------------------


@pytest.mark.parametrize("answers_cancel", [True, False], ids=["answers", "ignores"])
def test_a_queued_read_fails_fast_and_retryably(answers_cancel: bool) -> None:
    with fake_pooler(answers_cancel=answers_cancel) as fake:
        substrate = _substrate(fake.dsn, pool=0.3)
        began = time.monotonic()
        with pytest.raises(PoolExhaustedError) as raised, substrate._reader(bounded=True):
            pass
        took = time.monotonic() - began
        # Cancelled when the bound ran out; when the pooler kept holding the
        # client, the socket shut a quarter second later ended the wait.
        assert fake.cancels == 1
        first = fake.queries[0]
    assert isinstance(raised.value, StageConflictError)
    assert 0.3 <= took < (1.3 if answers_cancel else 1.6)
    # One transaction, and nothing set for the session a pooler hands on.
    assert b"BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY" in first
    assert b"SET LOCAL statement_timeout" in first and b"SESSION" not in first


def test_an_agents_facts_wait_their_turn() -> None:
    with fake_pooler(answers_cancel=True) as fake:
        substrate = _substrate(fake.dsn, pool=0.2)
        outcome: list[str] = []

        def read() -> None:
            try:
                with substrate._reader(bounded=False):
                    outcome.append("had")
            except Exception as exc:
                outcome.append(type(exc).__name__)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(1.0)
        # Past the bound, still queued: no stage's locks wait on it.
        assert reader.is_alive() and outcome == []
    reader.join(5)
    assert outcome == ["SubstrateUnavailableError"]


# --------------------------------------------------------------------------
# the server's own limit
# --------------------------------------------------------------------------


@pytest.fixture
def outbox(pg: Pg, tmp_path: Path) -> Iterator[PostgresOutbox]:
    yield from build_outbox(pg, tmp_path)


def _limit(outbox: PostgresOutbox, limit: int) -> None:
    with psycopg.connect(outbox.pg.cluster, autocommit=True) as conn:
        conn.execute(
            sql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(
                sql.Identifier(outbox.pg.role), sql.Literal(limit)
            )
        )


def _locking_plan() -> Any:
    return (
        PlanBuilder(SCOPE)
        .update(table="orders", statement="UPDATE orders SET status = 'held' WHERE id = 500")
        .enqueue(sink="mail", operation="send", payload=mail(1).payload)
        .build()
    )


def test_a_connection_refused_for_want_of_one_aborts_the_stage(outbox: PostgresOutbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    engine = outbox.engine(windows=[window], checkers=[BlastRadius(10)])
    _limit(outbox, 1)  # the stage's own session, and no second
    try:
        with pytest.raises(PoolExhaustedError):
            engine.execute(_locking_plan())
        # Nothing held: the order the stage updated is free at once.
        with psycopg.connect(outbox.pg.admin, autocommit=True) as conn:
            conn.execute("SET lock_timeout = '200ms'")
            conn.execute("UPDATE orders SET status = 'free' WHERE id = 500")
    finally:
        _limit(outbox, -1)
    assert engine.execute(_locking_plan()).committed


def test_nothing_is_prepared_on_the_server(outbox: PostgresOutbox) -> None:
    substrate = outbox.substrate()
    conn = substrate._connect()
    try:
        assert conn.prepare_threshold is None
    finally:
        conn.close()
    # A whole stage, enqueue and windows included, prepares nothing.
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    engine = outbox.engine(windows=[window], checkers=[BlastRadius(10)])
    seen: list[int] = []
    original = PostgresSubstrate.commit

    def commit(self: PostgresSubstrate, handle: Any) -> Any:
        assert self._conn is not None
        row = self._conn.execute("SELECT count(*) FROM pg_prepared_statements").fetchone()
        assert row is not None
        seen.append(int(row[0]))
        return original(self, handle)

    PostgresSubstrate.commit = commit  # type: ignore[method-assign]
    try:
        assert engine.execute(_locking_plan()).committed
    finally:
        PostgresSubstrate.commit = original  # type: ignore[method-assign]
    assert seen == [0]


# --------------------------------------------------------------------------
# a real PgBouncer
# --------------------------------------------------------------------------


def _through_pgbouncer(dsn: str) -> str:
    host, _, port = PGBOUNCER.partition(":")
    params = conninfo_to_dict(dsn)
    params.update(host=host, port=port)
    return make_conninfo("", **params)


@pytest.mark.skipif(not PGBOUNCER, reason="set INTERLOCK_TEST_PGBOUNCER (host:port) to run")
def test_behind_pgbouncer_a_stage_left_no_connection_fails_fast(outbox: PostgresOutbox) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    pooled = PostgresSubstrate(
        _through_pgbouncer(outbox.pg.agent),
        tables=specs(*OBSERVED),
        pool_timeout_seconds=0.5,
    )
    engine = outbox.engine(substrate=pooled, windows=[window], checkers=[BlastRadius(10)])
    # Another transaction holds one of the pool's two server connections: the
    # stage takes the other, and its second has none left to wait for.
    with psycopg.connect(_through_pgbouncer(outbox.pg.agent)) as holder:
        holder.execute("SELECT 1")
        began = time.monotonic()
        with pytest.raises(PoolExhaustedError):
            engine.execute(_locking_plan())
        took = time.monotonic() - began
        holder.rollback()
    assert took < 0.5 + 1.0 + 1.0
    # Nothing held, nothing left in the pool's sessions: it commits now.
    assert engine.execute(_locking_plan()).committed


def _pooled_workers(outbox: PostgresOutbox, workers: int, plans: int) -> tuple[list[bool], int]:
    """``plans`` plans from each of ``workers`` engine workers through the
    PgBouncer pool: what each came to, and how many races were run again."""
    window = RateWindow("mail_per_hour", timedelta(hours=1), 1000, Requests("mail"))

    def open_engine(index: int) -> tuple[Any, Any]:
        substrate = PostgresSubstrate(
            _through_pgbouncer(outbox.pg.agent),
            tables=specs(*OBSERVED),
            pool_timeout_seconds=0.3,
        )
        return outbox.engine(substrate=substrate, windows=[window]), lambda: None

    pool = EnginePool(open_engine, workers=workers, conflict_retries=200, retry_cap=0.5)
    pool.open()
    results: list[bool] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        for n in range(plans):
            plan = (
                PlanBuilder(SCOPE)
                .enqueue(sink="mail", operation="send", payload=mail(index * 100 + n).payload)
                .build()
            )
            committed = pool.execute(index, plan).committed
            with lock:
                results.append(committed)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
    finally:
        pool.close()
    return results, pool.counters.get("conflicts", 0)


@pytest.mark.skipif(not PGBOUNCER, reason="set INTERLOCK_TEST_PGBOUNCER (host:port) to run")
def test_behind_pgbouncer_a_pool_one_larger_than_the_workers_never_waits(
    outbox: PostgresOutbox,
) -> None:
    # Two server connections, one worker: its stage's, and its windows' read.
    results, retried = _pooled_workers(outbox, workers=1, plans=6)
    assert results == [True] * 6 and retried == 0


@pytest.mark.skipif(not PGBOUNCER, reason="set INTERLOCK_TEST_PGBOUNCER (host:port) to run")
def test_behind_pgbouncer_a_pool_too_small_is_slow_and_never_stuck(
    outbox: PostgresOutbox,
) -> None:
    # Two workers, two server connections: two stages can hold both and each
    # ask for a second. Each fails fast, is staged again, and every plan commits.
    results, retried = _pooled_workers(outbox, workers=2, plans=4)
    assert results == [True] * 8 and retried > 0


@pytest.mark.skipif(not PGBOUNCER, reason="set INTERLOCK_TEST_PGBOUNCER (host:port) to run")
def test_behind_pgbouncer_the_server_connections_are_left_as_found(
    outbox: PostgresOutbox,
) -> None:
    window = RateWindow("mail_per_hour", timedelta(hours=1), 10, Requests("mail"))
    pooled = PostgresSubstrate(_through_pgbouncer(outbox.pg.agent), tables=specs(*OBSERVED))
    engine = outbox.engine(substrate=pooled, windows=[window], checkers=[BlastRadius(10)])
    # Each plan takes both server connections: its stage's, and its windows' read.
    for _ in range(3):
        assert engine.execute(_locking_plan()).committed
    # Two clients, each in a transaction, hold both server connections: between
    # them they see every session the pool keeps.
    clients = [
        psycopg.connect(_through_pgbouncer(outbox.pg.agent), prepare_threshold=None)
        for _ in range(2)
    ]
    try:
        seen = [
            client.execute(
                "SELECT pg_backend_pid(), current_setting('statement_timeout'), "
                "current_setting('lock_timeout'), "
                "current_setting('default_transaction_isolation'), "
                "current_setting('default_transaction_read_only')"
            ).fetchone()
            for client in clients
        ]
    finally:
        for client in clients:
            client.close()
    assert len({row[0] for row in seen if row}) == 2
    assert [row[1:] for row in seen if row] == [("0", "0", "read committed", "off")] * 2
