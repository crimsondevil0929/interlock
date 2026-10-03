"""Version 3 installed over version 2, in place (``docs/EPIC3_DESIGN.md`` §3).

The database starts as version 2 left it: installed from version 2's own SQL
(``tests/outbox_v2.py``, frozen), with traffic version 2's relay wrote: a
message delivered, one that failed and waits for its retry, one never
tried. Then version 3 is installed over it, and:

- every delivery-log row written under version 2 keeps its hash, and every log
  still verifies;
- the messages version 2 left pending are delivered under version 3, their
  logs continuing across the upgrade, a delivered call's ``remote_ref``
  recorded under version 3's framing;
- until the upgrade, version 3 refuses the database, plainly: a stage, and a
  relay, each say to run ``interlock install``.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import make_conninfo  # noqa: E402

import interlock.postgres as installer  # noqa: E402
from interlock import EscrowEngine, PlanBuilder, PostgresSubstrate  # noqa: E402
from interlock.deliveries import message_log, verify_delivery_log  # noqa: E402
from interlock.exceptions import SubstrateConfigurationError  # noqa: E402
from interlock.outbox_store import PostgresOutboxStore  # noqa: E402
from interlock.relay import (  # noqa: E402
    DELIVERED,
    RETRYABLE,
    Delivery,
    DeliveryResult,
    NoBreaker,
    Relay,
)
from tests import outbox_v2 as v2  # noqa: E402
from tests.conftest import OBSERVED, PASSWORD, create_role, drop_role  # noqa: E402
from tests.outbox_env import REGISTRY, RELAY_SINKS, SCOPE, mail  # noqa: E402
from tests.schemas import specs  # noqa: E402

VERSION_2: dict[str, Any] = {
    "OUTBOX_GUARD": v2.OUTBOX_GUARD,
    "OUTBOX_TABLES": v2.OUTBOX_TABLES,
    "OUTBOX_FUNCTIONS": v2.OUTBOX_FUNCTIONS,
    "OUTBOX_TRIGGERS": v2.OUTBOX_TRIGGERS,
    "_RELAY_FUNCTIONS": v2.RELAY_FUNCTIONS_V2,
    "_install_sinks": v2.install_sinks_v2,
    "_OUTBOX_TABLES": (
        "interlock.sinks",
        "interlock.outbox",
        "interlock.outbox_state",
        "interlock.outbox_attempts",
    ),
    "INSTALL_VERSION": "2",
}


@dataclass(frozen=True)
class Upgrade:
    admin: str
    agent: str
    relay: str
    stage_role: str
    relay_role: str

    def install(self) -> None:
        with psycopg.connect(self.admin, autocommit=True) as conn:
            installer.install(
                conn,
                specs(*OBSERVED),
                stage_roles=[self.stage_role],
                sinks=RELAY_SINKS,
                relay_roles=[self.relay_role],
            )

    def engine(self) -> EscrowEngine:
        return EscrowEngine(
            PostgresSubstrate(self.agent, tables=specs(*OBSERVED)), checkers=[], sinks=REGISTRY
        )

    def log_rows(self) -> list[tuple[Any, ...]]:
        with psycopg.connect(self.admin) as conn:
            return list(
                conn.execute(
                    "SELECT message_id, seq, event, prev_hash, event_hash "
                    "FROM interlock.outbox_attempts ORDER BY message_id, seq"
                )
            )


@pytest.fixture
def upgrade(
    pg_admin_dsn: str, pg_back_office: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Upgrade]:
    """A back office version 2 installed, its outbox included."""
    stage_role = f"il_agent_{uuid.uuid4().hex[:10]}"
    relay_role = f"il_relay_{uuid.uuid4().hex[:10]}"
    create_role(pg_admin_dsn, stage_role)
    create_role(pg_admin_dsn, relay_role)
    env = Upgrade(
        admin=pg_back_office,
        agent=make_conninfo(pg_back_office, user=stage_role, password=PASSWORD),
        relay=make_conninfo(pg_back_office, user=relay_role, password=PASSWORD),
        stage_role=stage_role,
        relay_role=relay_role,
    )
    try:
        with monkeypatch.context() as patch:
            for name, value in VERSION_2.items():
                patch.setattr(installer, name, value)
            env.install()
        with psycopg.connect(pg_back_office, autocommit=True) as conn:
            conn.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(OBSERVED)} TO {stage_role}"
            )
            conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {stage_role}")
        yield env
    finally:
        drop_role(pg_admin_dsn, pg_back_office, relay_role)
        drop_role(pg_admin_dsn, pg_back_office, stage_role)


class Version2Store(PostgresOutboxStore):
    """Version 2's relay: the same calls, and the nine-argument outcome."""

    def _connect(self) -> Any:
        if self._conn is not None:
            self._conn.close()
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        return self._conn

    def outcome(
        self, lease: Any, relay_id: str, attempt: int, result: DeliveryResult, delay: timedelta
    ) -> str | None:
        conn = self.connection()
        with conn.transaction():
            row = conn.execute(
                "SELECT interlock.relay_outcome(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    lease.message_id,
                    relay_id,
                    lease.fence,
                    attempt,
                    result.outcome,
                    result.status_code,
                    result.response_digest,
                    result.detail or None,
                    int(delay / timedelta(milliseconds=1)),
                ),
            ).fetchone()
        return None if row is None or row[0] is None else str(row[0])


class Scripted:
    """An adapter answering from a list, and recording a reference when it delivers."""

    def __init__(self, *outcomes: str) -> None:
        self._outcomes = list(outcomes)

    def send(self, delivery: Delivery) -> DeliveryResult:
        outcome = self._outcomes.pop(0) if self._outcomes else DELIVERED
        if outcome == DELIVERED:
            return DeliveryResult(DELIVERED, status_code=200, remote_ref=f"ref_{delivery.attempt}")
        return DeliveryResult(outcome, status_code=503, detail="scripted")


def test_version_3_over_version_2_keeps_every_log_and_carries_on(
    upgrade: Upgrade, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Version 3 refuses version 2's database, and says what to do.
    with pytest.raises(SubstrateConfigurationError, match="installed by version 2"):
        upgrade.engine().execute(PlanBuilder(SCOPE).enqueue(**_mail(0)).build())
    with pytest.raises(SubstrateConfigurationError, match="interlock install"):
        PostgresOutboxStore(upgrade.relay)

    # Traffic under version 2: staged (enqueue and stage_outbox are the same in
    # both versions), and relayed by version 2's relay: one message delivered,
    # one failed and waiting for its retry, one never tried.
    with monkeypatch.context() as patch:
        patch.setattr(installer, "installed_v3", lambda conn: True)
        engine = upgrade.engine()
        for n in range(3):
            assert engine.execute(PlanBuilder(SCOPE).enqueue(**_mail(n)).build()).committed
    with Relay(
        Version2Store(upgrade.relay),
        adapters={"mail": Scripted(DELIVERED)},
        breaker=NoBreaker(),
        relay_id="version-2",
    ) as ok:
        (lease,) = ok._claim(1)
        assert ok._deliver(lease) == "delivered"
        delivered = lease.message_id
    with Relay(
        Version2Store(upgrade.relay),
        adapters={"mail": Scripted(RETRYABLE)},
        breaker=NoBreaker(),
        relay_id="version-2-failing",
    ) as failing:
        (lease,) = failing._claim(1)
        assert failing._deliver(lease) == "pending"
        failed = lease.message_id
    with psycopg.connect(upgrade.admin) as conn:
        (untried,) = (
            row[0]
            for row in conn.execute(
                "SELECT message_id FROM interlock.outbox WHERE message_id <> ALL (%s)",
                ([delivered, failed],),
            )
        )
        assert verify_delivery_log(conn) == ()
    before = upgrade.log_rows()
    assert len(before) == 4, "version 2 wrote two calls' logs"

    # The upgrade, in place.
    upgrade.install()
    with psycopg.connect(upgrade.admin) as conn:
        version = conn.execute("SELECT DISTINCT version FROM interlock.installation").fetchall()
        assert version == [("3",)]
        assert installer.installed_v3(conn)
        kinds = dict(conn.execute("SELECT name, kind FROM interlock.sinks").fetchall())
        assert set(kinds.values()) == {"http"}
        # Every row version 2 wrote, unchanged; every log, verifying.
        assert upgrade.log_rows() == before
        assert verify_delivery_log(conn) == ()
    upgrade.install()  # and again: nothing changes
    assert upgrade.log_rows() == before

    # Version 3 delivers what version 2 left, its logs continuing.
    with Relay(
        PostgresOutboxStore(upgrade.relay),
        adapters={"mail": Scripted()},
        breaker=NoBreaker(),
        relay_id="version-3",
        lease=timedelta(seconds=5),
        timeout=timedelta(seconds=1),
    ) as new:
        for _ in range(200):
            new.run_once(limit=10)
            with psycopg.connect(upgrade.admin) as conn:
                left = conn.execute(
                    "SELECT count(*) FROM interlock.outbox_state WHERE state <> 'delivered'"
                ).fetchone()
            if left == (0,):
                break
            time.sleep(0.05)
    with psycopg.connect(upgrade.admin) as conn:
        assert verify_delivery_log(conn) == ()
        retried = message_log(conn, failed)
        assert [(e.event, e.remote_ref) for e in retried] == [
            ("sending", None),
            ("retryable", None),
            ("sending", None),
            ("delivered", "ref_2"),
        ]
        assert [(e.event, e.remote_ref) for e in message_log(conn, untried)] == [
            ("sending", None),
            ("delivered", "ref_1"),
        ]
        assert [e.event for e in message_log(conn, delivered)] == ["sending", "delivered"]
    after = upgrade.log_rows()
    assert set(before) <= set(after) and len(after) == len(before) + 4


def _mail(n: int) -> dict[str, Any]:
    request = mail(n)
    return {"sink": request.sink, "operation": request.operation, "payload": request.payload}


def test_the_frozen_fixture_is_version_2(upgrade: Upgrade) -> None:
    """The fixture installed what version 2 did: no column version 3 adds."""
    with psycopg.connect(upgrade.admin) as conn:
        assert not installer.installed_v3(conn)
        version = conn.execute("SELECT DISTINCT version FROM interlock.installation").fetchall()
        assert version == [("2",)]
    assert Path(v2.__file__).name == "outbox_v2.py"
