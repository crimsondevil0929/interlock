"""Leases that follow their node (``docs/EPIC9_DESIGN.md`` §2), on PostgreSQL:
storage version 8 records the cluster node whose relay holds each lease, and a
claim takes over the lease of a node no session holds the lock of, at once,
where any other lease only runs out.

- A node gone mid-call: its call recorded lost, made again under the same key,
  answered once by the sink; the old relay's outcome refused by the fence.
- A node alive, or a relay that names no node: its lease waits to run out.
- The node's key computed alike in SQL and in Python; a relay of version 7
  still claiming through the old signature; version 7 upgraded in place.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from interlock import postgres as installer
from interlock.cluster import ClusterNode, lock_key
from interlock.relay import DeliveryResult
from interlock.telemetry import Metrics
from tests.outbox_env import RELAY_SINKS, PostgresOutbox, build_outbox, mail

LONG = timedelta(seconds=60)
"""A lease that will not run out during a test."""


@pytest.fixture
def outbox(pg: object, tmp_path: Path) -> Iterator[PostgresOutbox]:
    built = build_outbox(pg, tmp_path)  # type: ignore[arg-type]
    for env in built:
        assert isinstance(env, PostgresOutbox)
        yield env


@pytest.fixture
def node(outbox: PostgresOutbox) -> Iterator[ClusterNode]:
    """Node ``a``, joined: alive while the test runs, unless it leaves."""
    joined = ClusterNode(outbox.pg.admin, "a", heartbeat=0.1, session_timeout=5)
    joined.join()
    yield joined
    joined.leave()


def lease_node(outbox: PostgresOutbox, message: uuid.UUID) -> object:
    ((named,),) = outbox.fetch(
        "SELECT lease_node FROM interlock.outbox_state WHERE message_id = %s", message
    )
    return named


def test_a_lease_of_a_node_that_is_gone_is_taken_over_at_once(
    outbox: PostgresOutbox, node: ClusterNode
) -> None:
    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", node="a", lease=LONG)
    (lease,) = slow._claim(1)
    assert lease.taken_from is None
    assert lease_node(outbox, message) == "a"
    assert slow._sending(lease, "breaker clear at test") == 1
    # Node a dies: the database ends its session, and its lock with it.
    node.leave()
    metrics = Metrics()
    with outbox.relay(relay_id="fast", node="b", lease=LONG, metrics=metrics) as fast:
        (taken,) = fast._claim(1)
        assert taken.taken_from == "a" and taken.message_id == message
        assert fast._deliver(taken) == "delivered"
    assert metrics.value("interlock_lease_takeovers_total") == 1
    # Too late for the relay that was a's: the fence moved with the claim.
    late = slow._outcome(lease, 1, DeliveryResult("delivered", status_code=201), timedelta(0))
    assert late is None
    slow.close()
    log = outbox.log(message)
    assert [(e.event, e.attempt, e.actor, e.state_after) for e in log] == [
        ("sending", 1, "slow", "leased"),
        ("lost", 1, "fast", "pending"),
        ("sending", 2, "fast", "leased"),
        ("delivered", 2, "fast", "delivered"),
        ("delivered", 1, "slow", None),
    ]
    assert log[1].detail == "the node a of slow was gone mid-call; the sink may have acted"
    # The call made again carried the first one's key: a sink that honours it
    # acts once, whichever of the two calls reached it.
    (call,) = outbox.sink("mail").calls
    assert call.key == lease.idempotency_key and call.attempt == 2
    # Delivered, the lease names no node any more.
    assert lease_node(outbox, message) is None
    outbox.verify()


def test_a_lease_of_a_node_that_is_alive_waits_to_run_out(
    outbox: PostgresOutbox, node: ClusterNode
) -> None:
    _, (message,) = outbox.commit(mail(1))
    with outbox.relay(relay_id="slow", node="a", lease=LONG) as slow:
        assert len(slow._claim(1)) == 1
        with outbox.relay(relay_id="fast", node="b", lease=LONG) as fast:
            assert fast._claim(5) == []
    assert outbox.state(message) == "leased"


def test_a_lease_naming_no_node_only_runs_out(outbox: PostgresOutbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    with outbox.relay(
        relay_id="alone", lease=timedelta(seconds=1), timeout=timedelta(seconds=0.4)
    ) as alone:
        assert len(alone._claim(1)) == 1
        assert lease_node(outbox, message) is None
        with outbox.relay(relay_id="fast", node="b", lease=LONG) as fast:
            assert fast._claim(5) == []
            time.sleep(1.1)
            (taken,) = fast._claim(5)
            # Run out, not taken from a node.
            assert taken.taken_from is None


def test_a_lease_taken_from_a_node_gone_before_its_call_is_simply_leased_again(
    outbox: PostgresOutbox, node: ClusterNode
) -> None:
    _, (message,) = outbox.commit(mail(1))
    slow = outbox.relay(relay_id="slow", node="a", lease=LONG)
    (lease,) = slow._claim(1)
    node.leave()
    with outbox.relay(relay_id="fast", node="b", lease=LONG) as fast:
        (taken,) = fast._claim(1)
        assert taken.taken_from == "a" and taken.fence == lease.fence + 1
        assert fast._deliver(taken) == "delivered"
    # It never called: nothing was lost.
    assert slow._deliver(lease) == "skipped"
    slow.close()
    assert [e.event for e in outbox.log(message)] == ["sending", "delivered"]
    assert len(outbox.sink("mail").calls) == 1


def test_the_node_key_is_computed_alike_in_sql(outbox: PostgresOutbox) -> None:
    for name in ("a", "node-1", "interlock-0", "x" * 63, "nöde"):
        ((key,),) = outbox.fetch("SELECT interlock.node_key(%s)", name)
        assert key == lock_key("node", name), name


def test_a_relay_of_version_7_claims_through_the_old_signature(
    outbox: PostgresOutbox, node: ClusterNode
) -> None:
    """Its four arguments still answer, as version 7 did: it names no node,
    and it takes over the leases of a node that is gone, as any relay does."""
    import psycopg

    _, (first, second) = outbox.commit(mail(1), mail(2))
    with outbox.relay(relay_id="new", node="a", lease=LONG) as new:
        assert len(new._claim(1)) == 1
    node.leave()
    with psycopg.connect(outbox.relay_dsn, autocommit=True) as conn, conn.transaction():
        rows = conn.execute(
            "SELECT * FROM interlock.relay_claim(%s, %s, %s, %s)", ("old", 60.0, 5, ["mail"])
        ).fetchall()
    assert len(rows[0]) == 20
    assert {row[0] for row in rows} == {first, second}
    assert lease_node(outbox, first) is None and lease_node(outbox, second) is None


def test_version_7_upgrades_in_place(outbox: PostgresOutbox, node: ClusterNode) -> None:
    _, (message,) = outbox.commit(mail(1))
    with outbox.admin() as conn:
        conn.execute("ALTER TABLE interlock.outbox_state DROP COLUMN lease_node")
        assert installer.installed_version(conn) == 7
    outbox.reinstall(RELAY_SINKS)
    with outbox.admin() as conn:
        assert installer.installed_version(conn) == int(installer.INSTALL_VERSION) == 8
    with outbox.relay(relay_id="slow", node="a", lease=LONG) as slow:
        slow._claim(1)
    assert lease_node(outbox, message) == "a"
    node.leave()
    with outbox.relay(relay_id="fast", node="b", lease=LONG) as fast:
        outbox.drain(fast)
    assert outbox.state(message) == "delivered"
    outbox.verify()


def test_the_lock_the_claim_reads_is_the_one_a_node_holds(
    outbox: PostgresOutbox, node: ClusterNode
) -> None:
    """The claim finds a node alive by trying its lock: the very lock
    ClusterNode.join takes, under the key interlock.node_key computes."""
    ((alive,),) = outbox.fetch(
        "SELECT NOT pg_try_advisory_xact_lock_shared(1229737818, interlock.node_key('a'))"
    )
    assert alive
    assert lock_key("node", "a") != lock_key("node", "b")
