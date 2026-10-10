"""Nodes and leadership (``docs/EPIC9_DESIGN.md`` §1), on PostgreSQL: a node's
lock held for its life and refused to a second process; a role held by one
node at a time; a node gone (left, killed, silent past its session's bound)
taking every role with it; and the supervisor joining before the engines,
stepping a led service only while its node leads, and leaving last.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from interlock.cluster import LEADER_LOCK, NODE_LOCK, ClusterNode, connection_name, lock_key
from interlock.config import ConfigError, load_config
from interlock.exceptions import NodeTakenError
from interlock.supervisor import EnginePool, InterlockSupervisor
from interlock.telemetry import Metrics
from tests.test_supervisor import FakeEngine, Recorder, run

FAST = {"heartbeat": 0.1, "session_timeout": 0.6}


@pytest.fixture
def nodes(pg_database: str) -> Iterator[Callable[..., ClusterNode]]:
    """Nodes of a cluster on a fresh database: each left at the end."""
    made: list[ClusterNode] = []

    def node(name: str, **kwargs: Any) -> ClusterNode:
        built = ClusterNode(pg_database, name, **{**FAST, **kwargs})
        made.append(built)
        return built

    yield node
    for built in made:
        built.leave()


def holders(dsn: str, kind: int, key: int) -> list[str]:
    """The sessions holding an advisory lock, by application name."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        return [
            str(r[0])
            for r in conn.execute(
                "SELECT a.application_name FROM pg_locks l JOIN pg_stat_activity a "
                "ON a.pid = l.pid WHERE l.locktype = 'advisory' AND l.classid = %s::bigint::oid "
                "AND l.objid = (%s::bigint & 4294967295)::oid AND l.objsubid = 2 AND l.granted",
                (kind, key),
            )
        ]


def released(dsn: str, kind: int, key: int, within: float = 5.0) -> bool:
    """Whether an advisory lock is soon held by no session: a session closed
    lets go of its locks as its server process exits, a moment after."""
    deadline = time.monotonic() + within
    while holders(dsn, kind, key):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


def session(dsn: str, name: str) -> Any:
    """A connection called ``name``, as a part of a node opens one."""
    import psycopg

    return psycopg.connect(dsn, autocommit=True, application_name=name)


def ended(dsn: str, pid: int, within: float = 5.0) -> bool:
    """Whether the server process ``pid`` is soon gone."""
    import psycopg

    deadline = time.monotonic() + within
    with psycopg.connect(dsn, autocommit=True) as conn:
        while True:
            row = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (pid,))
            if not row.fetchone()[0]:  # type: ignore[index]
                return True
            if time.monotonic() > deadline:
                return False
            time.sleep(0.02)


def terminate(dsn: str, application: str) -> None:
    """The server ends a session, as it does one whose client died."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = %s",
            (application,),
        )


# -- the node -------------------------------------------------------------------


def test_a_node_holds_its_lock_for_its_life(pg_database: str, nodes: Any) -> None:
    a = nodes("a")
    a.join()
    assert a.joined
    assert holders(pg_database, NODE_LOCK, lock_key("node", "a")) == ["interlock-cluster@a"]
    a.heartbeat()
    assert a.counters["heartbeats"] == 1
    a.leave()
    assert not a.joined
    assert released(pg_database, NODE_LOCK, lock_key("node", "a"))


def test_a_second_process_is_refused_a_node_that_runs(nodes: Any) -> None:
    nodes("a").join()
    twin = nodes("a", join_wait=0.3)
    started = time.monotonic()
    with pytest.raises(NodeTakenError, match=r"node 'a' runs already: session \d+ "):
        twin.join()
    # It waited for the session to end before refusing.
    assert time.monotonic() - started >= 0.3
    assert not twin.joined


def test_a_node_is_admitted_once_its_holder_leaves(nodes: Any) -> None:
    first = nodes("a")
    first.join()
    second = nodes("a", join_wait=10)
    threading.Timer(0.3, first.leave).start()
    started = time.monotonic()
    second.join()
    assert second.joined
    assert 0.25 <= time.monotonic() - started < 5


def test_a_node_silent_past_its_session_timeout_holds_nothing(pg_database: str, nodes: Any) -> None:
    a = nodes("a")
    a.join()
    assert a.lead("vacuum")
    b = nodes("b")
    b.join()
    assert not b.lead("vacuum")
    # Frozen: no heartbeat from a, while b heartbeats. The server ends a's
    # session, and its locks with it.
    deadline = time.monotonic() + 1.2
    while time.monotonic() < deadline:
        b.heartbeat()
        time.sleep(0.1)
    assert b.counters["lost"] == 0
    assert holders(pg_database, NODE_LOCK, lock_key("node", "a")) == []
    assert b.lead("vacuum")
    assert holders(pg_database, LEADER_LOCK, lock_key("role", "vacuum")) == ["interlock-cluster@b"]
    # Another process may be node a now.
    nodes("a", join_wait=0.5).join()


def test_one_node_leads_a_role_at_a_time(pg_database: str, nodes: Any) -> None:
    a, b = nodes("a"), nodes("b")
    a.join()
    b.join()
    vacuum_a, vacuum_b = a.leadership("vacuum"), b.leadership("vacuum")
    assert vacuum_a.lead() and not vacuum_b.lead()
    assert vacuum_a.lead()  # confirmed again, never taken twice
    assert vacuum_a.held and not vacuum_b.held
    # Another role is another lock.
    assert b.lead("inbox-matcher") and not a.lead("inbox-matcher")
    vacuum_a.resign()
    assert not vacuum_a.held
    assert vacuum_b.lead() and not vacuum_a.lead()
    assert holders(pg_database, LEADER_LOCK, lock_key("role", "vacuum")) == ["interlock-cluster@b"]


def test_a_node_whose_session_ends_counts_itself_out_of_every_role_and_joins_again(
    pg_database: str, nodes: Any
) -> None:
    a, b = nodes("a"), nodes("b")
    a.join()
    b.join()
    assert a.lead("vacuum") and a.lead("inbox-matcher")
    terminate(pg_database, "interlock-cluster@a")
    # Its standby takes the role at its next ask: the lock went with the session.
    assert b.lead("vacuum")
    # The leader finds out at once, and leads nothing.
    assert not a.lead("inbox-matcher")
    assert not a.leads("vacuum") and not a.joined
    assert a.counters["lost"] == 1
    a.heartbeat()  # joins again: its lock was free
    assert a.joined and a.counters["joins"] == 2
    assert not a.lead("vacuum")
    assert a.lead("inbox-matcher")


def test_a_heartbeat_finds_a_lost_session_and_drops_its_roles(pg_database: str, nodes: Any) -> None:
    a = nodes("a")
    a.join()
    assert a.lead("vacuum")
    terminate(pg_database, "interlock-cluster@a")
    a.heartbeat()
    assert a.joined and a.counters["lost"] == 1 and a.counters["joins"] == 2
    assert not a.leads("vacuum")
    assert a.lead("vacuum")


def test_a_node_whose_name_another_process_took_meanwhile_is_refused(
    pg_database: str, nodes: Any
) -> None:
    a = nodes("a", join_wait=0.3)
    a.join()
    terminate(pg_database, "interlock-cluster@a")
    nodes("a").join()
    with pytest.raises(NodeTakenError):
        a.heartbeat()
    assert not a.joined


def test_a_gone_nodes_sessions_are_ended_at_a_survivors_heartbeat(
    pg_database: str, nodes: Any
) -> None:
    """Fencing (§1.5): a node gone, its lock free and its sessions still on the
    server, one inside a transaction holding a lock the cluster would wait
    for. The next heartbeat of a node that survives ends each of them. A live
    node's sessions, the survivor's own, what no node opened, and the gone
    node's next incarnation's are left alone."""
    import psycopg

    a, b, c = nodes("a"), nodes("b"), nodes("c")
    for node in (a, b, c):
        node.join()
    stage = session(pg_database, "interlock-stage@a")
    stage.execute("BEGIN")
    stage.execute("SELECT pg_advisory_xact_lock(1, 1)")  # as a frozen stage holds a lock
    ledger = session(pg_database, "interlock-ledger@a")
    kept = [
        session(pg_database, "interlock-relay@c"),  # a node alive
        session(pg_database, "interlock-relay@b"),  # the survivor's own
        session(pg_database, "psql@a"),  # no node's
        session(pg_database, "interlock-relay@" + "a" * 41),  # no node is named so
    ]
    gone = [stage.info.backend_pid, ledger.info.backend_pid]
    b.heartbeat()
    assert b.counters["fenced"] == 0  # a is alive: nothing is ended
    terminate(pg_database, "interlock-cluster@a")
    b.heartbeat()
    assert b.counters["fenced"] == 2
    assert all(ended(pg_database, pid) for pid in gone)
    with psycopg.connect(pg_database, autocommit=True) as other:
        assert other.execute("SELECT pg_try_advisory_lock(1, 1)").fetchone() == (True,)
    for conn in kept:
        assert conn.execute("SELECT 1").fetchone() == (1,)
    # Its next incarnation holds the node's lock: its sessions are its own.
    nodes("a").join()
    fresh = session(pg_database, "interlock-stage@a")
    b.heartbeat()
    assert b.counters["fenced"] == 2
    assert fresh.execute("SELECT 1").fetchone() == (1,)
    metrics = Metrics()
    b.collect(metrics)
    assert metrics.value("interlock_cluster_fenced_total") == 2
    for conn in [stage, ledger, fresh, *kept]:
        conn.close()


def test_a_node_that_may_not_end_a_gone_nodes_sessions_says_so_once(
    pg_admin_dsn: str, pg_database: str, nodes: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Ending another role's session takes pg_signal_backend, and a
    superuser's a superuser: a node without it says so once, and keeps
    heartbeating. The sessions end at their own bounds."""
    from psycopg.conninfo import make_conninfo

    from tests.conftest import PASSWORD, create_role, drop_role

    role = f"fenceless_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, role)
    try:
        a = nodes("a")
        a.join()
        held = session(pg_database, "interlock-ledger@a")  # a superuser's session
        b = ClusterNode(
            make_conninfo(pg_database, user=role, password=PASSWORD),
            "b",
            heartbeat=FAST["heartbeat"],
            session_timeout=FAST["session_timeout"],
        )
        try:
            b.join()
            terminate(pg_database, "interlock-cluster@a")
            with caplog.at_level("WARNING", logger="interlock.cluster"):
                b.heartbeat()
                b.heartbeat()
            assert b.joined and b.counters["fenced"] == 0
            assert caplog.text.count("cannot end a gone node's sessions") == 1
            assert held.execute("SELECT 1").fetchone() == (1,)
        finally:
            b.leave()
            held.close()
    finally:
        drop_role(pg_admin_dsn, pg_database, role)


def test_a_daemons_node_joins_only_the_database_interlock_is_installed_in(
    pg_database: str,
) -> None:
    """A node's lock is its database's own, and the relays look for it in
    theirs: a daemon's node refuses a database without Interlock's storage."""
    import psycopg

    from interlock.exceptions import SubstrateConfigurationError
    from interlock.postgres import install

    node = ClusterNode(
        pg_database,
        "a",
        heartbeat=FAST["heartbeat"],
        session_timeout=FAST["session_timeout"],
        storage=True,
    )
    with pytest.raises(SubstrateConfigurationError, match="holds no Interlock storage"):
        node.join()
    assert not node.joined
    with psycopg.connect(pg_database, autocommit=True) as conn:
        install(conn, [])
    try:
        node.join()
        assert node.joined
    finally:
        node.leave()


def test_names_and_timings_that_cannot_work_are_refused(pg_database: str) -> None:
    with pytest.raises(ValueError, match="named by letters"):
        ClusterNode(pg_database, "-a")
    # 40 characters at most: every connection's name holds the node's whole.
    assert ClusterNode(pg_database, "a" * 40).node == "a" * 40
    with pytest.raises(ValueError, match="named by letters"):
        ClusterNode(pg_database, "a" * 41)
    with pytest.raises(ValueError, match="three heartbeats"):
        ClusterNode(pg_database, "a", heartbeat=1, session_timeout=2.9)


def test_what_a_scrape_reads_of_the_node(nodes: Any) -> None:
    a, b = nodes("a"), nodes("b")
    a.join()
    b.join()
    vacuum = a.leadership("vacuum")
    a.leadership("inbox-matcher")
    assert vacuum.lead()
    metrics = Metrics()
    a.collect(metrics)
    assert metrics.value("interlock_cluster_node", node="a") == 1
    assert metrics.value("interlock_cluster_leader", role="vacuum") == 1
    assert metrics.value("interlock_cluster_leader", role="inbox-matcher") == 0
    assert metrics.value("interlock_cluster_leaderships_total", role="vacuum") == 1
    a.leave()
    a.collect(metrics)
    assert metrics.value("interlock_cluster_node", node="a") == 0
    assert metrics.value("interlock_cluster_leader", role="vacuum") == 0


def test_connection_names() -> None:
    assert connection_name("relay", "node-1", "interlock-relay") == "interlock-relay@node-1"
    assert connection_name("relay", None, "interlock-relay") == "interlock-relay"
    # The keys are the ones the SQL side computes: SHA-256's first four bytes.
    assert lock_key("node", "a") == lock_key("node", "a") != lock_key("role", "a")
    assert -(2**31) <= lock_key("node", "node-1") < 2**31


# -- the supervisor ---------------------------------------------------------------


def test_a_led_service_steps_only_while_its_node_leads(nodes: Any) -> None:
    rival = nodes("rival")
    rival.join()
    assert rival.lead("vacuum")
    node = nodes("a")
    log: list[tuple[str, str]] = []
    vacuum = Recorder("vacuum", log, every=0.01)
    vacuum.leader = node.leadership("vacuum")
    relay = Recorder("relay", log, every=0.01)
    supervisor = InterlockSupervisor(services=[vacuum, relay], cluster=node)

    async def body() -> None:
        await asyncio.sleep(0.4)
        status = supervisor.status()
        assert status["vacuum"].state == "standby"
        assert status["vacuum"].steps == 0 and vacuum.counters.get("steps", 0) == 0
        assert status["relay"].state == "running" and relay.counters["steps"] > 0
        assert status["cluster"].state == "running"
        code, health = supervisor.health()
        assert code == 200, health
        assert health["services"]["vacuum"]["state"] == "standby"
        rival.resign("vacuum")  # the rival leaves the role: this node takes it
        deadline = time.monotonic() + 5
        while vacuum.counters.get("steps", 0) < 3 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert supervisor.status()["vacuum"].state == "running"
        assert not rival.lead("vacuum")

    run(supervisor, body)
    assert vacuum.counters["steps"] >= 3
    # A leader drains as it stops.
    assert ("vacuum", "drain") in log
    # Stopped, it resigned and left: the rival takes the role at once.
    assert rival.lead("vacuum")


def test_a_standby_service_does_not_drain(nodes: Any) -> None:
    rival = nodes("rival")
    rival.join()
    assert rival.lead("vacuum")
    node = nodes("a")
    log: list[tuple[str, str]] = []
    vacuum = Recorder("vacuum", log)
    vacuum.leader = node.leadership("vacuum")
    supervisor = InterlockSupervisor(services=[vacuum], cluster=node)

    async def body() -> None:
        await asyncio.sleep(0.3)

    run(supervisor, body)
    assert ("vacuum", "drain") not in log
    assert ("vacuum", "close") in log


def test_a_failed_leader_steps_aside(nodes: Any) -> None:
    node = nodes("a")
    rival = nodes("rival")
    rival.join()
    log: list[tuple[str, str]] = []
    vacuum = Recorder("vacuum", log, fail=1)
    vacuum.leader = node.leadership("vacuum")
    supervisor = InterlockSupervisor(
        services=[vacuum], cluster=node, restart_min=2.0, restart_max=2.0
    )
    taken: list[bool] = []

    async def body() -> None:
        deadline = time.monotonic() + 5
        while not supervisor.status()["vacuum"].failures and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        # Backing off for two seconds, the failed leader has resigned the role
        # as it closed: the rival takes it well within the backoff.
        within = time.monotonic() + 1.5
        while not await asyncio.to_thread(rival.lead, "vacuum") and time.monotonic() < within:
            await asyncio.sleep(0.02)
        taken.append(rival.leads("vacuum"))

    run(supervisor, body)
    assert taken == [True]


def test_the_node_joins_before_the_engines_open_and_leaves_after_everything_closed(
    pg_database: str, nodes: Any
) -> None:
    node = nodes("a")
    seen: dict[str, list[str]] = {}

    class Watched(FakeEngine):
        def recover(self) -> tuple[()]:
            seen["recovering"] = holders(pg_database, NODE_LOCK, lock_key("node", "a"))
            return ()

    def open_engine(index: int) -> tuple[Any, Callable[[], None]]:
        def close() -> None:
            seen["closing"] = holders(pg_database, NODE_LOCK, lock_key("node", "a"))

        return Watched(), close

    supervisor = InterlockSupervisor(engines=EnginePool(open_engine), cluster=node)

    def shared() -> None:
        seen["shared"] = holders(pg_database, NODE_LOCK, lock_key("node", "a"))

    supervisor.on_close(shared)

    async def body() -> None:
        await asyncio.sleep(0.05)

    run(supervisor, body)
    assert seen == {
        "recovering": ["interlock-cluster@a"],
        "closing": ["interlock-cluster@a"],
        "shared": ["interlock-cluster@a"],
    }
    assert holders(pg_database, NODE_LOCK, lock_key("node", "a")) == []
    assert supervisor.status()["cluster"].state == "stopped"


def test_a_supervisor_does_not_start_as_a_node_that_runs(nodes: Any) -> None:
    nodes("a").join()
    log: list[tuple[str, str]] = []
    supervisor = InterlockSupervisor(
        services=[Recorder("relay", log)], cluster=nodes("a", join_wait=0.2)
    )
    with pytest.raises(NodeTakenError):
        asyncio.run(supervisor.run())
    assert log == []  # nothing opened
    assert supervisor.status()["cluster"].state == "failed"


def test_a_supervisor_whose_node_was_taken_stops(pg_database: str, nodes: Any) -> None:
    node = nodes("a", join_wait=0.2)
    log: list[tuple[str, str]] = []
    supervisor = InterlockSupervisor(services=[Recorder("relay", log)], cluster=node)

    async def main() -> None:
        running = asyncio.create_task(supervisor.run())
        await supervisor.ready()
        terminate(pg_database, "interlock-cluster@a")
        await asyncio.to_thread(nodes("a").join)
        await asyncio.wait_for(running, timeout=10)

    asyncio.run(main())
    status = supervisor.status()
    assert status["cluster"].state == "failed"
    assert "NodeTakenError" in str(status["cluster"].last_error)
    assert status["relay"].state == "stopped"


def test_the_heartbeat_keeps_a_node_whose_session_ends_in_the_cluster(
    pg_database: str, nodes: Any
) -> None:
    node = nodes("a")
    supervisor = InterlockSupervisor(services=[Recorder("relay", [])], cluster=node)

    async def body() -> None:
        terminate(pg_database, "interlock-cluster@a")
        deadline = time.monotonic() + 5
        while node.counters["joins"] < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert node.joined and node.counters["lost"] == 1
        assert supervisor.status()["cluster"].state == "running"

    run(supervisor, body)


# -- configuration -----------------------------------------------------------------


CONFIG = """
substrate = "{substrate}"
database = "postgresql://owner@db/app"

[[tables]]
name = "orders"
columns = ["id"]

[cluster]
{body}
"""


def config(tmp_path: Path, body: str, substrate: str = "postgres") -> Path:
    path = tmp_path / "interlock.toml"
    path.write_text(CONFIG.format(substrate=substrate, body=body), encoding="utf-8")
    return path


def test_the_cluster_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTERLOCK_NODE", raising=False)
    loaded = load_config(
        config(
            tmp_path,
            'node = "interlock-0"\ndatabase = "postgresql://a@db/app"\n'
            "heartbeat_seconds = 0.5\nsession_timeout_seconds = 4",
        )
    )
    assert loaded.cluster is not None
    assert (loaded.cluster.node, loaded.cluster.database) == (
        "interlock-0",
        "postgresql://a@db/app",
    )
    assert loaded.cluster.heartbeat.total_seconds() == 0.5
    assert loaded.cluster.session_timeout.total_seconds() == 4
    # The environment names the node, as a StatefulSet's pod does; --node overrides both.
    monkeypatch.setenv("INTERLOCK_NODE", "interlock-2")
    loaded = load_config(config(tmp_path, 'node = "interlock-0"'))
    assert loaded.cluster is not None and loaded.cluster.node == "interlock-2"
    named = loaded.with_node("interlock-5")
    assert named.cluster is not None and named.cluster.node == "interlock-5"
    assert loaded.with_node(None) is loaded
    monkeypatch.delenv("INTERLOCK_NODE")
    assert load_config(config(tmp_path, "")).cluster is not None
    assert load_config(config(tmp_path, "")).cluster.node == ""  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("body", "substrate", "error"),
    [
        ('node = "a"', "sqlite", "needs PostgreSQL"),
        ('node = "-a"', "postgres", "named by letters"),
        ("heartbeat_seconds = 2\nsession_timeout_seconds = 5", "postgres", "three heartbeat"),
        ("heartbeat_seconds = 0", "postgres", "positive number"),
        ('nodes = "a"', "postgres", "unknown key"),
    ],
)
def test_a_cluster_section_that_cannot_work_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, substrate: str, error: str
) -> None:
    monkeypatch.delenv("INTERLOCK_NODE", raising=False)
    with pytest.raises(ConfigError, match=error):
        load_config(config(tmp_path, body, substrate))


def test_a_node_named_without_a_cluster_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "postgres"\ndatabase = "postgresql://a@db/app"\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="configure \\[cluster\\]"):
        load_config(path).with_node("a")
    with pytest.raises(ConfigError, match="named by letters"):
        load_config(config(tmp_path, "")).with_node("not a name")


# -- what a node holds, bounded (docs/EPIC9_DESIGN.md §3.3) ---------------------------


def test_a_governor_frozen_holding_the_ledger_holds_it_no_longer_than_the_bound(
    pg_database: str, nodes: Any
) -> None:
    """A node's AgentGov governor that freezes holding the ledger's writer lock,
    every governor of the fleet waiting, holds it for the node's session
    timeout, and is named for the node while it does."""
    import psycopg
    from agentgov import BudgetManager

    from interlock.daemon import _Governors, _Membership

    with BudgetManager.open_postgres(pg_database) as owner:
        owner.open_root("agent", "10")
    governors = _Governors(_Membership(nodes("a", heartbeat=0.3, session_timeout=1.0)))
    frozen, close = governors.open(pg_database)
    other = BudgetManager.open_postgres(pg_database)
    stuck = threading.Event()

    store: Any = frozen.store

    def freeze() -> None:
        with contextlib.suppress(Exception), store.writer():
            stuck.set()
            time.sleep(3.0)  # past the bound: the server ends the session meanwhile

    holder = threading.Thread(target=freeze)
    holder.start()
    try:
        assert stuck.wait(10)
        with psycopg.connect(pg_database, autocommit=True) as conn:
            names = {
                str(r[0])
                for r in conn.execute(
                    "SELECT application_name FROM pg_stat_activity WHERE state LIKE 'idle in%'"
                )
            }
        assert "interlock-ledger@a" in names
        began = time.monotonic()
        other.open_root("other", "1")
        assert 0.5 < time.monotonic() - began < 2.5
    finally:
        holder.join(10)
        other.close()
        with contextlib.suppress(Exception):
            close()
