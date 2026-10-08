"""Version 5 installed over version 4, in place (``docs/EPIC5_DESIGN.md`` §4).

The database starts as version 4 left it, installed from version 4's own code,
frozen (``tests/outbox_v4.py``, ``tests/sqlite_outbox_v4.py``), with
version 4's traffic: messages delivered by its relay and settled, one failed
and waiting for its retry, rate-window history. Then version 5 is installed
over it, twice, on both stores:

- every delivery-log row keeps its hash, every log verifies, every outcome is
  attested by the relay that recorded it, and the legacy set is unchanged;
- a relay of version 4 left running delivers what was left: no relay function
  changed, so no relay needs a restart;
- the guards now admit a deletion only under a checkpoint, and a vacuum prunes
  version 4's settled history, after which everything still verifies;
- until the upgrade, version 5 refuses the database, plainly.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager

import interlock.postgres as installer
from interlock import EscrowEngine, PlanBuilder, PostgresSubstrate, SqliteSubstrate
from interlock.attestations import verify_attestations
from interlock.deliveries import operations, settlements, verify_delivery_log
from interlock.exceptions import SubstrateConfigurationError
from interlock.operators import OperatorLog, verify_operators
from interlock.outbox_store import PostgresOutboxStore
from interlock.records import Keyring, read_records
from interlock.relay import DELIVERED, RETRYABLE, NoBreaker, Relay
from interlock.sqlite_outbox import (
    COMPACTOR,
    VERSION,
    SqliteOutboxStore,
    install_sqlite_outbox,
    installed_version,
)
from interlock.vacuum import Vacuum
from interlock.windows import Plans, RateWindow
from tests import outbox_v4 as v4
from tests import sqlite_outbox_v4 as lite4
from tests.conftest import OBSERVED, PASSWORD, build_sqlite_back_office, create_role, drop_role
from tests.outbox_env import (
    NO_INBOX,
    REGISTRY,
    RELAY_SINKS,
    RELAYS,
    SCOPE,
    Scripted,
    mail,
    relay_signer,
)
from tests.schemas import specs

WINDOW = RateWindow("plans_per_scope", timedelta(milliseconds=50), 1000, Plans(), "scope")

VERSION_4: dict[str, Any] = {
    "OUTBOX_GUARD": v4.OUTBOX_GUARD,
    "OUTBOX_TABLES": v4.OUTBOX_TABLES,
    "OUTBOX_FUNCTIONS": v4.OUTBOX_FUNCTIONS,
    "OUTBOX_TRIGGERS": v4.OUTBOX_TRIGGERS,
    "_FUNCTIONS": v4.FUNCTIONS_V4,
    "_SCHEMA": v4.SCHEMA_V4,
    "_RELAY_FUNCTIONS": v4.RELAY_FUNCTIONS_V4,
    "_SETTLER_FUNCTIONS": v4.SETTLER_FUNCTIONS_V4,
    "_install_sinks": v4.install_sinks_v4,
    "_OUTBOX_TABLES": v4.OUTBOX_TABLES_V4,
    "INSTALL_VERSION": v4.INSTALL_VERSION_V4,
    **NO_INBOX,
}


def _plan(n: int) -> Any:
    request = mail(n)
    return (
        PlanBuilder(SCOPE)
        .enqueue(sink=request.sink, operation=request.operation, payload=dict(request.payload))
        .build()
    )


def _vacuum_and_verify(source: Any, compactor: Any, tmp_path: Path, delivered: int) -> None:
    """A vacuum over the upgraded history prunes what version 4 delivered and
    settled, and everything verifies before and after."""
    ledger = BudgetManager.open_sqlite(str(tmp_path / "governor.db"))
    try:
        ledger.open_root("operators", "1")
        from agentgov.receipts.signing import Ed25519Signer

        key = Ed25519Signer.generate()
        keyring = Keyring({"ops": key.public_key()})
        log = OperatorLog(tmp_path / "ops.ilok1", key, keyring, ledger=ledger, scope="operators")
        try:
            time.sleep(0.1)
            report = Vacuum(
                log,
                compactor,
                operators=keyring,
                relays=RELAYS,
                ledger=ledger,
                windows=[WINDOW],
                retain=timedelta(0),
                margin=timedelta(0),
            ).run()
        finally:
            log.close()
        assert report.outcome == "applied", report.problems
        assert report.messages == delivered and report.window_rows >= 1
        records = read_records(tmp_path / "ops.ilok1")
        entries = list(ledger.audit_trail())
        assert verify_operators(source, records, keyring, ledger=entries).problems == ()
        assert verify_delivery_log(source) == ()
        assert verify_attestations(source, RELAYS).problems == ()
    finally:
        ledger.close()


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------


class Version4Store(PostgresOutboxStore):
    """Version 4's relay store: the same calls, from code that asks only that
    version 4 be installed."""

    def _connect(self) -> Any:
        import psycopg

        if self._conn is not None:
            self._conn.close()
        self._conn = psycopg.connect(self._dsn, autocommit=True, application_name="relay-v4")
        return self._conn

    def _traces(self, conn: Any, messages: list[Any]) -> dict[Any, str]:
        return {}  # a version before 6 kept no trace context


@pytest.fixture
def roles(pg_admin_dsn: str, pg_back_office: str) -> Iterator[tuple[str, str]]:
    stage_role = f"il_agent_{uuid.uuid4().hex[:10]}"
    relay_role = f"il_relay_{uuid.uuid4().hex[:10]}"
    create_role(pg_admin_dsn, stage_role)
    create_role(pg_admin_dsn, relay_role)
    try:
        yield stage_role, relay_role
    finally:
        drop_role(pg_admin_dsn, pg_back_office, relay_role)
        drop_role(pg_admin_dsn, pg_back_office, stage_role)


def test_version_5_over_version_4_on_postgres(
    pg_back_office: str,
    roles: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import psycopg
    from psycopg.conninfo import make_conninfo

    stage_role, relay_role = roles
    agent = make_conninfo(pg_back_office, user=stage_role, password=PASSWORD)
    relay_dsn = make_conninfo(pg_back_office, user=relay_role, password=PASSWORD)

    def install() -> None:
        with psycopg.connect(pg_back_office, autocommit=True) as conn:
            installer.install(
                conn,
                specs(*OBSERVED),
                stage_roles=[stage_role],
                sinks=RELAY_SINKS,
                relay_roles=[relay_role],
            )

    with monkeypatch.context() as patch:
        for name, value in VERSION_4.items():
            patch.setattr(installer, name, value)
        install()
    with psycopg.connect(pg_back_office, autocommit=True) as conn:
        conn.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(OBSERVED)} TO {stage_role}"
        )
        conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {stage_role}")
        assert installer.installed_version(conn) == 4

    def engine() -> EscrowEngine:
        return EscrowEngine(
            PostgresSubstrate(agent, tables=specs(*OBSERVED)),
            checkers=[],
            sinks=REGISTRY,
            windows=[WINDOW],
        )

    # Version 5 refuses version 4's database, and says what to do.
    with pytest.raises(SubstrateConfigurationError, match="installed by version 4"):
        engine().execute(_plan(0))

    # Version 4's traffic: staged and relayed by version 4.
    with monkeypatch.context() as patch:
        patch.setattr(installer, "installed_version", lambda conn: int(installer.INSTALL_VERSION))
        patch.setattr(installer, "OUTBOX_TRIGGER_NAMES", v4.OUTBOX_TRIGGER_NAMES)
        for n in range(3):
            assert engine().execute(_plan(n)).committed
    # A relay of version 4 left running.
    old = Version4Store(relay_dsn)
    for outcome, expected in ((DELIVERED, "delivered"), (RETRYABLE, "pending")):
        with Relay(
            old, adapters={"mail": Scripted(outcome)}, breaker=NoBreaker(), signer=relay_signer()
        ) as relay:
            (lease,) = relay._claim(1)
            assert relay._deliver(lease) == expected
    with psycopg.connect(pg_back_office, autocommit=True) as conn:
        before = conn.execute(
            "SELECT message_id, seq, event_hash FROM interlock.outbox_attempts ORDER BY 1, 2"
        ).fetchall()
        windows = conn.execute("SELECT count(*) FROM interlock.window_ledger").fetchone()
        assert windows == (3,)

    # Version 5, in place, twice.
    install()
    install()
    with psycopg.connect(pg_back_office, autocommit=True) as conn:
        # Over version 4, an install brings the current version: 5's, and 6's.
        assert installer.installed_version(conn) == int(installer.INSTALL_VERSION) == 6
        assert (
            conn.execute(
                "SELECT message_id, seq, event_hash FROM interlock.outbox_attempts ORDER BY 1, 2"
            ).fetchall()
            == before
        )
        assert verify_delivery_log(conn) == ()
        assert verify_attestations(conn, RELAYS).problems == ()
        legacy = operations(conn).legacy()
        assert legacy is not None and len(legacy) == 0

    # The relay left running delivers the rest: no relay function changed.
    with Relay(
        old, adapters={"mail": Scripted()}, breaker=NoBreaker(), signer=relay_signer()
    ) as relay:
        for _ in range(100):
            relay.run_once(limit=10)
            with psycopg.connect(pg_back_office) as conn:
                row = conn.execute(
                    "SELECT count(*) FROM interlock.outbox_state WHERE state <> 'delivered'"
                ).fetchone()
                assert row is not None
                (left,) = row
            if left == 0:
                break
            time.sleep(0.05)
    assert left == 0

    # Version 5 vacuums version 4's history, once it is settled.
    with psycopg.connect(pg_back_office, autocommit=True) as conn:
        source = settlements(conn)
        messages, _ = source.snapshot(None)
        for message in messages:
            assert source.settle(message.message_id, receipt_id=None, credit=None, note="v4")
        _vacuum_and_verify(conn, operations(conn), tmp_path, delivered=3)
        assert conn.execute("SELECT count(*) FROM interlock.outbox").fetchone() == (0,)


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------


def test_version_5_over_version_4_on_sqlite(tmp_path: Path) -> None:
    path = build_sqlite_back_office(tmp_path / "app.sqlite")
    lite4.install_sqlite_outbox(path, RELAY_SINKS)
    with pytest.raises(SubstrateConfigurationError, match="installed by version 4"):
        SqliteOutboxStore(path)
    engine = EscrowEngine(
        SqliteSubstrate(path, tables=specs(*OBSERVED)),
        checkers=[],
        sinks=REGISTRY,
        windows=[WINDOW],
    )
    for n in range(3):
        assert engine.execute(_plan(n)).committed
    # A relay of version 4, its store open across the upgrade: left running.
    old = lite4.SqliteOutboxStore(path)
    for outcome, expected in ((DELIVERED, "delivered"), (RETRYABLE, "pending")):
        relay = Relay(
            old, adapters={"mail": Scripted(outcome)}, breaker=NoBreaker(), signer=relay_signer()
        )
        (lease,) = relay._claim(1)
        assert relay._deliver(lease) == expected
    with closing(sqlite3.connect(path)) as conn:
        before = conn.execute(
            "SELECT message_id, seq, event_hash FROM _interlock_outbox_attempts ORDER BY 1, 2"
        ).fetchall()

    # Version 5, in place, twice; and with it the current version, 6.
    install_sqlite_outbox(path, RELAY_SINKS)
    install_sqlite_outbox(path, RELAY_SINKS)
    with closing(sqlite3.connect(path)) as conn:
        assert installed_version(conn) == VERSION == 6
        assert (
            conn.execute(
                "SELECT message_id, seq, event_hash FROM _interlock_outbox_attempts ORDER BY 1, 2"
            ).fetchall()
            == before
        )
        # The guards now admit a deletion only under a checkpoint.
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM _interlock_outbox_attempts")
        with pytest.raises(sqlite3.IntegrityError, match="history"):
            conn.execute("DELETE FROM _interlock_windows")

    # The relay left running delivers the rest.
    with Relay(
        old, adapters={"mail": Scripted()}, breaker=NoBreaker(), signer=relay_signer()
    ) as relay:
        for _ in range(100):
            relay.run_once(limit=10)
            with closing(sqlite3.connect(path)) as conn:
                (left,) = conn.execute(
                    "SELECT count(*) FROM _interlock_outbox_state WHERE state <> 'delivered'"
                ).fetchone()
            if left == 0:
                break
            time.sleep(0.05)
    assert left == 0

    store = SqliteOutboxStore(path, writes=COMPACTOR)
    try:
        assert verify_delivery_log(store) == ()
        assert verify_attestations(store, RELAYS).problems == ()
        messages, _ = store.snapshot(None)
        settler = SqliteOutboxStore(path, writes=frozenset({"_interlock_outbox_settlements"}))
        try:
            for message in messages:
                assert settler.settle(message.message_id, receipt_id=None, credit=None, note="v4")
        finally:
            settler.close()
        _vacuum_and_verify(store, store, tmp_path, delivered=3)
        assert store.counts() == {}
    finally:
        store.close()
