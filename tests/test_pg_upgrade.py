"""The current version installed over versions 2 and 3, in place
(``docs/EPIC3_DESIGN.md`` §3, ``docs/EPIC4_DESIGN.md`` §2), through version 4's
changes and every one since (``docs/EPIC5_DESIGN.md`` §4).

The database starts as an older version left it: installed from that
version's own SQL (``tests/outbox_v2.py``, ``tests/outbox_v3.py``, frozen),
with traffic that version's relay wrote: a message delivered, one that failed
and waits for its retry, one never tried. Then version 4 is installed over
it, and:

- every delivery-log row written before keeps its hash, and every log still
  verifies;
- the messages left pending are delivered under version 4, their logs
  continuing across the upgrade, a delivered call's ``remote_ref`` recorded,
  and every outcome attested by the relay that recorded it;
- the old outcomes, which no relay signed, are counted as legacy; nothing
  else is;
- a relay of version 3 left running cannot record an outcome: version 4
  has no function that records one unattested;
- until the upgrade, version 4 refuses the database, plainly: a stage, and a
  relay, each say to run ``interlock install``.
"""

from __future__ import annotations

import dataclasses
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
from interlock.attestations import verify_attestations  # noqa: E402
from interlock.deliveries import (  # noqa: E402
    LegacyVouch,
    PostgresReader,
    message_log,
    verify_delivery_log,
)
from interlock.exceptions import SubstrateConfigurationError  # noqa: E402
from interlock.operators import verify_operators  # noqa: E402
from interlock.outbox_store import PostgresOutboxStore, milliseconds  # noqa: E402
from interlock.records import read_records  # noqa: E402
from interlock.relay import (  # noqa: E402
    DELIVERED,
    RETRYABLE,
    DeliveryResult,
    NoBreaker,
    Relay,
)
from tests import outbox_v2 as v2  # noqa: E402
from tests import outbox_v3 as v3  # noqa: E402
from tests.conftest import OBSERVED, PASSWORD, create_role, drop_role  # noqa: E402
from tests.outbox_env import (  # noqa: E402
    INSTALLERS,
    NO_INBOX,
    REGISTRY,
    RELAY_SINKS,
    RELAYS,
    SCOPE,
    Scripted,
    claim_before_version_8,
    mail,
    relay_signer,
    vouch,
)
from tests.schemas import specs  # noqa: E402

CURRENT = int(installer.INSTALL_VERSION)
"""The version installed over the old ones: 4 when these tests were written,
the outbox's current one now."""

OLD_GUARDS: dict[int, Any] = {2: v2.OUTBOX_TRIGGER_NAMES, 3: v3.OUTBOX_TRIGGER_NAMES}
"""The guards each old version installed, which a stage staged against it
before the upgrade checks instead of the current version's."""

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
    **NO_INBOX,
}

VERSION_3: dict[str, Any] = {
    "OUTBOX_GUARD": v3.OUTBOX_GUARD,
    "OUTBOX_TABLES": v3.OUTBOX_TABLES,
    "OUTBOX_FUNCTIONS": v3.OUTBOX_FUNCTIONS,
    "OUTBOX_TRIGGERS": v3.OUTBOX_TRIGGERS,
    "_RELAY_FUNCTIONS": v3.RELAY_FUNCTIONS_V3,
    "_install_sinks": v3.install_sinks_v3,
    "_OUTBOX_TABLES": v3.OUTBOX_TABLES_V3,
    "INSTALL_VERSION": "3",
    **NO_INBOX,
}


@dataclass(frozen=True)
class Upgrade:
    admin: str
    agent: str
    relay: str
    stage_role: str
    relay_role: str
    operators: Path
    """The operator log the upgrade's install is signed into."""

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


def _installed(
    pg_admin_dsn: str,
    back_office: str,
    monkeypatch: pytest.MonkeyPatch,
    version: dict[str, Any],
    operators: Path,
) -> Iterator[Upgrade]:
    stage_role = f"il_agent_{uuid.uuid4().hex[:10]}"
    relay_role = f"il_relay_{uuid.uuid4().hex[:10]}"
    create_role(pg_admin_dsn, stage_role)
    create_role(pg_admin_dsn, relay_role)
    env = Upgrade(
        admin=back_office,
        agent=make_conninfo(back_office, user=stage_role, password=PASSWORD),
        relay=make_conninfo(back_office, user=relay_role, password=PASSWORD),
        stage_role=stage_role,
        relay_role=relay_role,
        operators=operators,
    )
    try:
        with monkeypatch.context() as patch:
            for name, value in version.items():
                patch.setattr(installer, name, value)
            env.install()
        with psycopg.connect(back_office, autocommit=True) as conn:
            conn.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(OBSERVED)} TO {stage_role}"
            )
            conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {stage_role}")
        yield env
    finally:
        drop_role(pg_admin_dsn, back_office, relay_role)
        drop_role(pg_admin_dsn, back_office, stage_role)


@pytest.fixture
def upgrade(
    pg_admin_dsn: str, pg_back_office: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Upgrade]:
    """A back office version 2 installed, its outbox included."""
    yield from _installed(
        pg_admin_dsn, pg_back_office, monkeypatch, VERSION_2, tmp_path / "operators.ilok1"
    )


@pytest.fixture
def upgrade3(
    pg_admin_dsn: str, pg_back_office: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Upgrade]:
    """A back office version 3 installed."""
    yield from _installed(
        pg_admin_dsn, pg_back_office, monkeypatch, VERSION_3, tmp_path / "operators.ilok1"
    )


class OldStore(PostgresOutboxStore):
    """An older relay's store: the same calls, and the outcome of its own
    version, which no relay attests."""

    def _connect(self) -> Any:
        if self._conn is not None:
            self._conn.close()
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        return self._conn

    def _arguments(self, result: DeliveryResult) -> tuple[object, ...]:
        raise NotImplementedError

    def _traces(self, conn: Any, messages: list[Any]) -> dict[Any, str]:
        return {}  # a version before 6 kept no trace context

    def claim(
        self,
        relay_id: str,
        lease: timedelta,
        limit: int,
        sinks: Any,
        deadline: float,
        *,
        node: str | None = None,
    ) -> list[Any]:
        return claim_before_version_8(self, relay_id, lease, limit, sinks, deadline)

    def outcome(
        self,
        lease: Any,
        relay_id: str,
        attempt: int,
        result: DeliveryResult,
        delay: timedelta,
        attestation: str,
    ) -> str | None:
        arguments = (
            lease.message_id,
            relay_id,
            lease.fence,
            attempt,
            result.outcome,
            result.status_code,
            result.response_digest,
            result.detail or None,
            milliseconds(delay),
            *self._arguments(result),
        )
        conn = self.connection()
        with conn.transaction():
            row = conn.execute(
                f"SELECT interlock.relay_outcome({', '.join(['%s'] * len(arguments))})",
                arguments,
            ).fetchone()
        return None if row is None or row[0] is None else str(row[0])


class Version2Store(OldStore):
    """Version 2's relay: the nine-argument outcome."""

    def _arguments(self, result: DeliveryResult) -> tuple[object, ...]:
        return ()


class Version3Store(OldStore):
    """Version 3's relay: the ten-argument outcome, with what the call created."""

    def _arguments(self, result: DeliveryResult) -> tuple[object, ...]:
        return (result.remote_ref,)


@dataclass(frozen=True)
class Traffic:
    delivered: uuid.UUID
    failed: uuid.UUID
    untried: uuid.UUID
    rows: list[tuple[Any, ...]]
    """Every delivery-log row the old version wrote."""


def _old_traffic(
    upgrade: Upgrade, store: type[OldStore], version: int, monkeypatch: pytest.MonkeyPatch
) -> Traffic:
    """Traffic under the old version: staged (enqueue and stage_outbox are the
    same in every version), and relayed by its own relay: one message
    delivered, one failed and waiting for its retry, one never tried."""
    # Version 4 refuses the old database, and says what to do.
    with pytest.raises(SubstrateConfigurationError, match=f"installed by version {version}"):
        upgrade.engine().execute(PlanBuilder(SCOPE).enqueue(**_mail(0)).build())
    with pytest.raises(SubstrateConfigurationError, match="interlock install"):
        PostgresOutboxStore(upgrade.relay)

    with monkeypatch.context() as patch:
        patch.setattr(installer, "installed_version", lambda conn: CURRENT)
        patch.setattr(installer, "OUTBOX_TRIGGER_NAMES", OLD_GUARDS[version])
        engine = upgrade.engine()
        for n in range(3):
            assert engine.execute(PlanBuilder(SCOPE).enqueue(**_mail(n)).build()).committed
    with Relay(
        store(upgrade.relay),
        adapters={"mail": Scripted(DELIVERED)},
        breaker=NoBreaker(),
        relay_id=f"version-{version}",
        signer=relay_signer(),
    ) as ok:
        (lease,) = ok._claim(1)
        assert ok._deliver(lease) == "delivered"
        delivered = lease.message_id
    with Relay(
        store(upgrade.relay),
        adapters={"mail": Scripted(RETRYABLE)},
        breaker=NoBreaker(),
        relay_id=f"version-{version}-failing",
        signer=relay_signer(),
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
    rows = upgrade.log_rows()
    assert len(rows) == 4, f"version {version} wrote two calls' logs"
    return Traffic(delivered, failed, untried, rows)


def _upgraded(upgrade: Upgrade, traffic: Traffic, *, operator_rows: int = 0) -> LegacyVouch:
    """Version 4, in place: every old row unchanged, every log verifying, the
    old outcomes (and ``operator_rows`` unsigned operator rows) the legacy set,
    recorded once and vouched for by the install's signature."""
    upgrade.install()
    with psycopg.connect(upgrade.admin, autocommit=True) as conn:
        version = conn.execute("SELECT DISTINCT version FROM interlock.installation").fetchall()
        assert version == [(installer.INSTALL_VERSION,)]
        assert installer.installed_version(conn) == CURRENT
        kinds = dict(conn.execute("SELECT name, kind FROM interlock.sinks").fetchall())
        assert set(kinds.values()) == {"http"}
        assert upgrade.log_rows() == traffic.rows
        assert verify_delivery_log(conn) == ()
        recorded = PostgresReader(conn).legacy()
        assert recorded is not None and len(recorded) == 2 + operator_rows
        (unvouched,) = verify_attestations(conn, RELAYS).problems
        assert "no signed install vouches" in unvouched
        vouched = vouch(conn, upgrade.operators)
        report = verify_attestations(conn, RELAYS, legacy=vouched)
        assert (report.problems, report.attested, report.legacy) == ((), 0, 2)
        operators = verify_operators(conn, read_records(upgrade.operators), INSTALLERS)
        assert (operators.problems, operators.legacy) == ((), operator_rows)
    upgrade.install()  # and again: nothing changes
    assert upgrade.log_rows() == traffic.rows
    with psycopg.connect(upgrade.admin, autocommit=True) as conn:
        again = PostgresReader(conn).legacy()
        assert again is not None and again.digest == vouched.digest
    return vouched


def _deliver_all(upgrade: Upgrade) -> None:
    """Version 4's relay delivers what the old version left."""
    with Relay(
        PostgresOutboxStore(upgrade.relay),
        adapters={"mail": Scripted()},
        breaker=NoBreaker(),
        relay_id="version-4",
        lease=timedelta(seconds=5),
        timeout=timedelta(seconds=1),
        signer=relay_signer(),
    ) as new:
        for _ in range(200):
            new.run_once(limit=10)
            with psycopg.connect(upgrade.admin) as conn:
                left = conn.execute(
                    "SELECT count(*) FROM interlock.outbox_state "
                    "WHERE state IN ('pending', 'leased', 'held')"
                ).fetchone()
            if left == (0,):
                return
            time.sleep(0.05)
    raise AssertionError("version 4 did not deliver what was left")


def test_version_4_over_version_2_keeps_every_log_and_carries_on(
    upgrade: Upgrade, monkeypatch: pytest.MonkeyPatch
) -> None:
    traffic = _old_traffic(upgrade, Version2Store, 2, monkeypatch)
    # And an operator's action under version 2, which had no operator log:
    # a cancel no one signed.
    with monkeypatch.context() as patch:
        patch.setattr(installer, "installed_version", lambda conn: CURRENT)
        patch.setattr(installer, "OUTBOX_TRIGGER_NAMES", OLD_GUARDS[2])
        plan = PlanBuilder(SCOPE).enqueue(**_mail(9)).build()
        assert upgrade.engine().execute(plan).committed
    with psycopg.connect(upgrade.admin, autocommit=True) as conn:
        found = conn.execute(
            "SELECT message_id FROM interlock.outbox WHERE plan_id = %s", (plan.plan_id,)
        ).fetchone()
        assert found is not None
        cancelled = found[0]
        cancel = "SELECT interlock.outbox_cancel(%s, 'operator:dba', 'version 2')"
        assert conn.execute(cancel, (cancelled,)).fetchone() == (True,)
    traffic = dataclasses.replace(traffic, rows=upgrade.log_rows())
    vouched = _upgraded(upgrade, traffic, operator_rows=1)
    _deliver_all(upgrade)
    with psycopg.connect(upgrade.admin) as conn:
        assert verify_delivery_log(conn) == ()
        retried = message_log(conn, traffic.failed)
        assert [(e.event, e.remote_ref, e.attestation is not None) for e in retried] == [
            ("sending", None, False),
            ("retryable", None, False),
            ("sending", None, False),
            ("delivered", "ref_2", True),
        ]
        assert [(e.event, e.remote_ref) for e in message_log(conn, traffic.untried)] == [
            ("sending", None),
            ("delivered", "ref_1"),
        ]
        assert [e.event for e in message_log(conn, traffic.delivered)] == ["sending", "delivered"]
        report = verify_attestations(conn, RELAYS, legacy=vouched)
        assert (report.problems, report.attested, report.legacy) == ((), 2, 2)
    after = upgrade.log_rows()
    assert set(traffic.rows) <= set(after) and len(after) == len(traffic.rows) + 4


def test_version_4_over_version_3_keeps_every_log_and_carries_on(
    upgrade3: Upgrade, monkeypatch: pytest.MonkeyPatch
) -> None:
    traffic = _old_traffic(upgrade3, Version3Store, 3, monkeypatch)
    with psycopg.connect(upgrade3.admin) as conn:
        assert [(e.event, e.remote_ref) for e in message_log(conn, traffic.delivered)] == [
            ("sending", None),
            ("delivered", "ref_1"),
        ]
    vouched = _upgraded(upgrade3, traffic)

    # A relay of version 3 left running claims and starts a call, but cannot
    # record what came back: version 4 records no outcome unattested. The
    # call is the next relay's to find lost.
    late = Version3Store(upgrade3.relay)
    try:
        (lease,) = late.claim("version-3-late", timedelta(seconds=1), 1, ["mail"], 0.0)
        attempt = late.sending(lease, "version-3-late", "breaker clear at test")
        assert attempt is not None
        result = DeliveryResult(DELIVERED, status_code=200, remote_ref="ref_late")
        with pytest.raises(psycopg.errors.UndefinedFunction):
            late.outcome(lease, "version-3-late", attempt, result, timedelta(0), "")
    finally:
        late.close()
    time.sleep(1.2)
    _deliver_all(upgrade3)
    with psycopg.connect(upgrade3.admin) as conn:
        assert verify_delivery_log(conn) == ()
        stranded = message_log(conn, lease.message_id)
        assert [(e.event, e.actor) for e in stranded[-4:]] == [
            ("sending", "version-3-late"),
            ("lost", "version-4"),
            ("sending", "version-4"),
            ("delivered", "version-4"),
        ]
        report = verify_attestations(conn, RELAYS, legacy=vouched)
        assert (report.problems, report.attested, report.legacy) == ((), 2, 2)


def _mail(n: int) -> dict[str, Any]:
    request = mail(n)
    return {"sink": request.sink, "operation": request.operation, "payload": request.payload}


def _is_version(env: Upgrade, version: int) -> None:
    with psycopg.connect(env.admin) as conn:
        assert installer.installed_version(conn) == version
        rows = conn.execute("SELECT DISTINCT version FROM interlock.installation").fetchall()
        assert rows == [(str(version),)]


def test_the_frozen_fixture_is_version_2(upgrade: Upgrade) -> None:
    """The fixture installed what version 2 did: no column a later one adds."""
    _is_version(upgrade, 2)
    assert Path(v2.__file__).name == "outbox_v2.py"


def test_the_frozen_fixture_is_version_3(upgrade3: Upgrade) -> None:
    """The fixture installed what version 3 did: no attestation column."""
    _is_version(upgrade3, 3)
    assert Path(v3.__file__).name == "outbox_v3.py"
