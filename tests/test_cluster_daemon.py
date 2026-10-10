"""Two daemons on one database (``docs/EPIC9_DESIGN.md`` §1 to §3), each
``interlock daemon`` in a process of its own, as two pods of a StatefulSet run:
node ``a`` holds a lease with its call in flight and leads the vacuum, and is
killed with ``SIGKILL``. Node ``b`` takes the lease over at its next claim, far
inside the lease's minute, calls again under the same key, which the sink
answers from what it already did; and takes the vacuum's role. The scale of it,
with webhooks, agents, a freeze and a ledger, is the soak's
(``scripts/live_stress_test.py``).
"""

from __future__ import annotations

import io
import signal
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import psycopg
import pytest
from agentgov import BudgetManager
from psycopg.conninfo import make_conninfo

from interlock import BlastRadius, EscrowEngine, PlanBuilder, PostgresSubstrate
from interlock.attestations import verify_attestations
from interlock.cli import main
from interlock.cluster import LEADER_LOCK, NODE_LOCK, lock_key
from interlock.config import load_config
from interlock.deliveries import message_log, verify_delivery_log
from interlock.operators import generate_key
from interlock.substrate import TableSpec
from tests.conftest import PASSWORD, create_role, drop_role
from tests.fakesink import FakeSink
from tests.test_daemon import Daemon

T = TypeVar("T")

CONFIG = """
substrate = "postgres"
database = "{owner}"
stage_roles = ["{stage}"]
relay_roles = ["{relay}"]

[[tables]]
name = "orders"
columns = ["id", "status"]

[[sinks]]
name = "mail"
backoff_base_seconds = 0.05
backoff_cap_seconds = 0.2

[[sinks.operations]]
name = "send"

[relays.keys]
relay = "{relay_key}"

[relay]
key = "{shared}/relay.key"
database = "{relay_dsn}"
breaker = "none"
lease_seconds = 60
timeout_seconds = 25
poll_seconds = 0.05

[[relay.endpoints]]
sink = "mail"
url = "{sink}"
routes = {{ send = "POST /mail/send" }}

[operators]
log = "{shared}/operators.ilok1"
ledger = "{owner}"

[operators.keys]
installer = "{installer_key}"
vacuum = "{vacuum_key}"

[vacuum]
every_seconds = 1
retain_seconds = 3600
database = "{owner}"
key = "{shared}/vacuum.key"

[cluster]
node = "{node}"
database = "{owner}"
heartbeat_seconds = 0.2
session_timeout_seconds = 2
"""


@dataclass
class Cluster:
    owner: str
    stage: str
    shared: Path
    sink: FakeSink
    configs: dict[str, Path]

    def fetch(self, sql: str, *params: object) -> list[tuple[Any, ...]]:
        with psycopg.connect(self.owner, autocommit=True) as conn:
            return [tuple(r) for r in conn.execute(sql, params)]

    def holder(self, kind: int, name: str) -> str | None:
        """The node whose session holds a node's or a role's lock."""
        key = lock_key("node" if kind == NODE_LOCK else "role", name)
        rows = self.fetch(
            "SELECT a.application_name FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
            "WHERE l.locktype = 'advisory' AND l.classid = %s::bigint::oid "
            "AND l.objid = (%s::bigint & 4294967295)::oid AND l.objsubid = 2 AND l.granted",
            kind,
            key,
        )
        return str(rows[0][0]).removeprefix("interlock-cluster@") if rows else None


@pytest.fixture
def cluster(pg_admin_dsn: str, pg_database: str, tmp_path: Path) -> Iterator[Cluster]:
    """One database with the outbox installed, a stage and a relay role, the
    AgentGov ledger the operator log anchors into, a sink that honours keys,
    and a configuration for each of nodes ``a`` and ``b``."""
    tag = uuid.uuid4().hex[:8]
    stage, relay = f"il_stage_{tag}", f"il_relay_{tag}"
    for role in (stage, relay):
        create_role(pg_admin_dsn, role)
    shared = tmp_path / "shared"
    shared.mkdir()
    keys = {name: generate_key(shared / f"{name}.key") for name in ("relay", "installer", "vacuum")}
    sink = FakeSink(honour_keys=True)
    try:
        with psycopg.connect(pg_database, autocommit=True) as conn:
            conn.execute("CREATE TABLE orders (id bigint PRIMARY KEY, status text)")
            conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO {stage}")
        with BudgetManager.open_postgres(pg_database) as governor:
            governor.open_root("agent", "10")
            governor.open_root("interlock-operators", "1")
        configs: dict[str, Path] = {}
        for node in ("a", "b"):
            home = tmp_path / node
            home.mkdir()
            configs[node] = home / "interlock.toml"
            configs[node].write_text(
                CONFIG.format(
                    owner=pg_database,
                    stage=stage,
                    relay=relay,
                    relay_dsn=make_conninfo(pg_database, user=relay, password=PASSWORD),
                    relay_key=keys["relay"].public_key().spec(),
                    installer_key=keys["installer"].public_key().spec(),
                    vacuum_key=keys["vacuum"].public_key().spec(),
                    shared=shared,
                    sink=sink.url,
                    node=node,
                ),
                encoding="utf-8",
            )
        out = io.StringIO()
        code = main(
            ["install", "--config", str(configs["a"]), "--key", str(shared / "installer.key")],
            out=out,
        )
        assert code == 0, out.getvalue()
        yield Cluster(
            pg_database,
            make_conninfo(pg_database, user=stage, password=PASSWORD),
            shared,
            sink,
            configs,
        )
    finally:
        sink.close()
        for role in (stage, relay):
            drop_role(pg_admin_dsn, pg_database, role)


def until(check: Callable[[], T], what: str, timeout: float = 20.0) -> T:
    deadline = time.monotonic() + timeout
    while not (found := check()):
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.02)
    return found


def enqueue(cluster: Cluster) -> uuid.UUID:
    """A plan that sends one mail, committed: its message."""
    engine = EscrowEngine(
        PostgresSubstrate(
            cluster.stage, tables=[TableSpec("orders", primary_key="id", columns=("id", "status"))]
        ),
        checkers=[BlastRadius(5)],
        sinks=load_config(cluster.configs["a"]).sink_registry(),
    )
    plan = (
        PlanBuilder("agent")
        .enqueue(sink="mail", operation="send", payload={"to": "a@acme.test", "subject": "hi"})
        .build()
    )
    assert engine.execute(plan).committed
    ((message,),) = cluster.fetch(
        "SELECT message_id FROM interlock.outbox WHERE plan_id = %s", plan.plan_id
    )
    return uuid.UUID(str(message))


def test_a_node_killed_mid_call_loses_its_lease_and_its_role_at_once(cluster: Cluster) -> None:
    cluster.sink.script(("hold",))  # the first call is answered when released
    a = Daemon(cluster.configs["a"])
    b: Daemon | None = None
    try:
        a.wait_for("interlock daemon running as node a")
        until(lambda: cluster.holder(LEADER_LOCK, "vacuum") == "a", "a to lead the vacuum")
        message = enqueue(cluster)
        # a's relay takes the message and calls; the sink holds the call.
        assert cluster.sink.arrived.wait(20)
        ((leased_to,),) = cluster.fetch(
            "SELECT lease_node FROM interlock.outbox_state WHERE message_id = %s", message
        )
        assert leased_to == "a"
        # Who holds what is plain in pg_stat_activity: each connection names its node.
        names = {
            str(row[0])
            for row in cluster.fetch(
                "SELECT application_name FROM pg_stat_activity WHERE application_name LIKE %s",
                "interlock-%@a",
            )
        }
        assert {"interlock-cluster@a", "interlock-relay@a"} <= names, names
        b = Daemon(cluster.configs["b"])
        b.wait_for("interlock daemon running as node b")
        assert cluster.holder(NODE_LOCK, "b") == "b"
        assert cluster.holder(LEADER_LOCK, "vacuum") == "a"  # b is on standby

        a.process.send_signal(signal.SIGKILL)
        killed = time.monotonic()
        assert a.process.wait(10) == -signal.SIGKILL

        def taken() -> bool:
            rows = cluster.fetch(
                "SELECT state, lease_node FROM interlock.outbox_state WHERE message_id = %s",
                message,
            )
            return rows == [("delivered", None)]

        until(taken, "b to take a's lease over and deliver")
        took = time.monotonic() - killed
        # Far inside the lease's minute: the database said a was gone.
        assert took < 10, took
        until(lambda: cluster.holder(LEADER_LOCK, "vacuum") == "b", "b to take the vacuum")
        assert cluster.holder(NODE_LOCK, "a") is None
    finally:
        cluster.sink.release.set()
        if a.process.poll() is None:
            a.process.kill()
            a.process.wait()
        if b is not None:
            code = b.stop()
            assert code == 0, (b.lines, b.errors)

    with psycopg.connect(cluster.owner, autocommit=True) as conn:
        log = message_log(conn, message)
        events = [(e.event, e.actor.split(":")[1] if ":" in e.actor else e.actor) for e in log]
        assert events == [("sending", "a"), ("lost", "b"), ("sending", "b"), ("delivered", "b")]
        assert log[1].detail is not None and "was gone mid-call" in log[1].detail
        assert verify_delivery_log(conn) == ()
        relays = load_config(cluster.configs["a"]).relay_keyring()
        assert relays is not None
        assert verify_attestations(conn, relays).problems == ()
    # Two calls under one key, one act: the sink answered the second from the first.
    calls = cluster.sink.calls
    assert len(calls) == 2 and len({c.key for c in calls}) == 1
    assert sum(c.acted for c in calls) == 1


def test_a_frozen_node_is_fenced_once_its_session_times_out(cluster: Cluster) -> None:
    """A node frozen (``SIGSTOP``) keeps every connection open, as a host lost
    to the network leaves them: its idle sessions would stay for as long as it
    does. Once the server ends its cluster session, at the session timeout,
    the other node's next heartbeat ends every one of them (§1.5)."""
    a = Daemon(cluster.configs["a"])
    b = Daemon(cluster.configs["b"])
    try:
        a.wait_for("interlock daemon running as node a")
        b.wait_for("interlock daemon running as node b")

        def sessions() -> set[str]:
            return {
                str(row[0])
                for row in cluster.fetch(
                    "SELECT application_name FROM pg_stat_activity WHERE application_name LIKE %s",
                    "interlock-%@a",
                )
            }

        until(lambda: "interlock-relay@a" in sessions(), "a's relays to connect")
        a.process.send_signal(signal.SIGSTOP)
        frozen = time.monotonic()
        until(lambda: cluster.holder(NODE_LOCK, "a") is None, "a's session to time out")
        until(lambda: not sessions(), "b to end a's sessions")
        fenced = time.monotonic() - frozen
        # Its session timeout (2 s) and a heartbeat of b's, never a bound per session.
        assert fenced < 6, fenced
    finally:
        a.process.kill()
        a.process.wait()
        assert b.stop() == 0, (b.lines, b.errors)
    assert any("node a is gone; its sessions ended" in line for line in b.lines + b.errors)


WIRING = """
[engine]
ledger = "{owner}"

[receipts]
log = "{home}/receipts.jsonl"
key = "{home}/receipts.key"
log_id = "receipts-w"

[settler]
database = "{owner}"
every_seconds = 1

[inbox]
key = "{home}/inbox.key"
listen = "127.0.0.1:0"
database = "{owner}"

[[inbox.sources]]
name = "stripe"
kind = "stripe"
secret_env = "WIRING_WEBHOOK_SECRET"

[inbox.keys]
inbox = "{inbox}"
"""


def test_a_nodes_parts_follow_their_roles_and_bound_their_sessions(
    cluster: Cluster, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The daemon as a node (§3): the vacuum, the inbox's matcher and the
    settler of the node's receipt log follow their roles, and the settler
    settles only the node's own plans; every session that holds what others
    wait for is bounded by the session timeout, and called for its node; and
    recovery waits out a predecessor's transactions."""
    import interlock.outbox_store
    import interlock.settlement
    import interlock.wiring
    from interlock.daemon import Application, build_supervisor

    home = tmp_path / "w"
    home.mkdir()
    generate_key(home / "receipts.key")
    inbox = generate_key(home / "inbox.key").public_key().spec()
    path = home / "interlock.toml"
    base = cluster.configs["a"].read_text().replace('node = "a"', 'node = "w"')
    path.write_text(base + WIRING.format(owner=cluster.owner, home=home, inbox=inbox))

    sessions: list[tuple[str, float]] = []
    bounded = interlock.wiring.bounded_session

    def bounded_spy(dsn: str, *, application_name: str, idle_timeout: float) -> Any:
        sessions.append((application_name, idle_timeout))
        return bounded(dsn, application_name=application_name, idle_timeout=idle_timeout)

    stores: list[dict[str, Any]] = []
    store = interlock.outbox_store.PostgresOutboxStore

    def store_spy(dsn: str, **kwargs: Any) -> Any:
        stores.append(kwargs)
        return store(dsn, **kwargs)

    settlers: list[dict[str, Any]] = []

    class Settler:
        def __init__(self, outbox: object, **kwargs: Any) -> None:
            settlers.append(kwargs)

    monkeypatch.setattr(interlock.wiring, "bounded_session", bounded_spy)
    monkeypatch.setattr(interlock.outbox_store, "PostgresOutboxStore", store_spy)
    monkeypatch.setattr(interlock.settlement, "Settler", Settler)
    config = load_config(path)
    supervisor = build_supervisor(config, Application(checkers=[BlastRadius(5)]))
    try:
        services = {service.name: service for service in supervisor._services}
        roles = {
            name: None if service.leader is None else service.leader.role
            for name, service in services.items()
        }
        assert roles == {
            "relay-0": None,
            "inbox": "inbox-matcher",
            "settler": "settler:receipts-w",
            "vacuum": "vacuum",
        }
        for name in ("relay-0", "inbox", "settler"):
            services[name].open()
            services[name].close()
        assert stores == [{"application_name": "interlock-relay@w", "idle_timeout": 2.0}]
        assert sessions == [("interlock-inbox@w", 2.0)]
        (settler,) = settlers
        assert settler["partition"] is True
        engines = supervisor._engines
        assert engines is not None
        assert engines._recover_wait == 2 * 10.0 + 2.0  # twice the stage bound, and its lock's
    finally:
        for close in reversed(supervisor._closers):
            close()


def test_a_daemons_node_refuses_a_database_without_interlock(
    cluster: Cluster, pg_admin_dsn: str, tmp_path: Path
) -> None:
    """A node's lock is its database's own, and the relays look for it in
    Interlock's: a daemon whose [cluster] database is another is refused."""
    from psycopg import sql

    from interlock.daemon import _cluster
    from interlock.exceptions import SubstrateConfigurationError

    name = f"interlock_t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        elsewhere = make_conninfo(pg_admin_dsn, dbname=name)
        path = tmp_path / "elsewhere.toml"
        text = cluster.configs["a"].read_text()
        path.write_text(
            text.replace(
                f'[cluster]\nnode = "a"\ndatabase = "{cluster.owner}"',
                f'[cluster]\nnode = "a"\ndatabase = "{elsewhere}"',
            )
        )
        assert elsewhere in path.read_text()
        node = _cluster(load_config(path))
        assert node is not None
        with pytest.raises(SubstrateConfigurationError, match="holds no Interlock storage"):
            node.join()
    finally:
        with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def test_a_second_daemon_as_a_node_that_runs_is_refused(cluster: Cluster) -> None:
    a = Daemon(cluster.configs["a"])
    try:
        a.wait_for("interlock daemon running as node a")
        twin = subprocess.run(  # noqa: S603
            a.process.args,
            capture_output=True,
            text=True,
            timeout=60,
            env=a.environment,
            cwd=a.cwd,
        )
        assert twin.returncode == 3, (twin.stdout, twin.stderr)
        assert "node 'a' runs already" in twin.stderr
    finally:
        assert a.stop() == 0


def test_the_command_line_names_the_node_and_a_cluster_needs_one(cluster: Cluster) -> None:
    named = Daemon(cluster.configs["a"], "--node", "c")
    try:
        named.wait_for("interlock daemon running as node c")
        assert cluster.holder(NODE_LOCK, "c") == "c" and cluster.holder(NODE_LOCK, "a") is None
    finally:
        assert named.stop() == 0
    text = cluster.configs["b"].read_text()
    cluster.configs["b"].write_text(text.replace('node = "b"\n', ""))
    nameless = Daemon(cluster.configs["b"])
    assert nameless.process.wait(60) == 3
    nameless.stop()
    assert any("[cluster] names no node" in line for line in nameless.errors), nameless.errors
