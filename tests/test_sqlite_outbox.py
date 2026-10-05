"""The outbox on SQLite (``docs/EPIC3_DESIGN.md`` §2): what only SQLite has.

The relay's behaviour on SQLite is the conformance suite's: every test in
``test_relay.py`` that takes ``outbox`` runs here too. This file checks what
is SQLite's own:

- ``interlock install`` switches the file to WAL and installs the outbox and
  its triggers; installing again changes nothing.
- The gate is the authorizer: no statement of the agent's may write the
  outbox, whatever it names; and the relay's connection may write delivery
  state and the log only.
- A request is bound to its stage's commit marker by a deferred foreign key:
  in the outbox exactly when the stage committed.
- The write lock does what ``SKIP LOCKED`` does: a relay cannot lease what an
  open stage wrote, and waits for a stage rather than failing.
- The delivery log is linked by the database: a connection without
  Interlock's function cannot append to it at all, and a row that does not
  extend its message's log is refused. A log rewritten around the triggers
  does not verify.
- The command line, end to end, on a SQLite file.
"""

from __future__ import annotations

import io
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    BlastRadius,
    EscrowEngine,
    EscrowRuntime,
    ForbiddenStatementError,
    PlanBuilder,
    SqliteSubstrate,
    StageError,
    SubstrateConfigurationError,
)
from interlock.deliveries import verify_delivery_log
from interlock.exceptions import OutboundRequestError, SubstrateUnavailableError
from interlock.operators import generate_key
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.relay import DeliveryResult, NoBreaker, Relay, attest
from interlock.sqlite_outbox import (
    LOG_TRIGGERS,
    SqliteOutboxStore,
    install_sqlite_outbox,
)
from interlock.types import EffectId, OutboundRequest
from tests.conftest import OBSERVED, build_sqlite_back_office
from tests.outbox_env import (
    REGISTRY,
    RELAY_SINKS,
    SqliteOutbox,
    build_sqlite_outbox,
    mail,
    relay_signer,
    relays_section,
)
from tests.schemas import MAIL_SEND_SCHEMA, specs


@pytest.fixture
def outbox(tmp_path: Path) -> Iterator[SqliteOutbox]:
    yield from build_sqlite_outbox(tmp_path)


def ship(**payload: Any) -> PlanBuilder:
    return (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'shipped' WHERE id = 500",
            tenant_id="acme",
            effect_id=EffectId("ship"),
        )
        .enqueue(
            sink="mail",
            operation="send",
            payload=payload or {"to": "ann@acme.test", "subject": "Shipped"},
            effect_id=EffectId("notify"),
        )
    )


def count(outbox: SqliteOutbox, table: str) -> int:
    with closing(outbox.raw()) as conn:
        row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()
        return int(row[0])


# --------------------------------------------------------------------------
# installation
# --------------------------------------------------------------------------


def test_install_switches_to_wal_and_is_idempotent(tmp_path: Path) -> None:
    path = build_sqlite_back_office(tmp_path / "db.sqlite")
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    install_sqlite_outbox(path, RELAY_SINKS)
    install_sqlite_outbox(path, RELAY_SINKS)
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        triggers = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        assert set(LOG_TRIGGERS) <= triggers
        sinks = conn.execute(
            "SELECT name, kind, operations, cost_per_call, enabled FROM _interlock_sinks "
            "ORDER BY name"
        ).fetchall()
    assert sinks == [
        ("mail", "http", '["send"]', "0.002", 1),
        ("pager", "http", '["page"]', "0", 1),
        ("payments", "http", '["refund"]', "0.01", 1),
        ("sms", "http", '["send"]', "0", 1),
    ]
    install_sqlite_outbox(path, RELAY_SINKS[:1])
    with closing(sqlite3.connect(path)) as conn:
        enabled = dict(conn.execute("SELECT name, enabled FROM _interlock_sinks").fetchall())
    assert enabled == {"mail": 1, "pager": 0, "payments": 0, "sms": 0}


def test_an_in_memory_database_has_no_outbox() -> None:
    with pytest.raises(SubstrateConfigurationError, match="WAL"):
        install_sqlite_outbox(":memory:", RELAY_SINKS)


def test_a_store_needs_the_outbox(tmp_path: Path) -> None:
    path = build_sqlite_back_office(tmp_path / "db.sqlite")
    with pytest.raises(SubstrateConfigurationError, match="no outbox"):
        SqliteOutboxStore(path)
    with pytest.raises(SubstrateUnavailableError):
        SqliteOutboxStore(tmp_path / "missing.sqlite")


def test_the_substrate_has_an_outbox_only_once_it_is_installed(tmp_path: Path) -> None:
    path = build_sqlite_back_office(tmp_path / "db.sqlite")
    substrate = SqliteSubstrate(path, tables=specs(*OBSERVED))
    assert not substrate.capabilities.outbound
    install_sqlite_outbox(path, RELAY_SINKS)
    assert substrate.capabilities.outbound
    unmarked = SqliteSubstrate(path, tables=specs(*OBSERVED), commit_markers=False)
    assert not unmarked.capabilities.outbound, "a request is bound to the commit marker"
    engine = EscrowEngine(unmarked, checkers=[], sinks=REGISTRY)
    with pytest.raises(OutboundRequestError) as caught:
        engine.execute(ship().build())
    assert caught.value.reason == "substrate"


# --------------------------------------------------------------------------
# staging
# --------------------------------------------------------------------------


def test_a_request_commits_with_its_stage_and_its_marker(outbox: SqliteOutbox) -> None:
    plan = ship().build()
    result = outbox.engine().execute(plan)
    assert result.committed
    assert result.diff is not None
    (staged,) = result.diff.outbound
    assert (staged.sink, staged.cost, staged.depends_on) == ("mail", Decimal("0.002"), ())
    with closing(outbox.raw()) as conn:
        row = conn.execute(
            "SELECT o.stage_id, o.plan_id, o.scope_id, o.payload, o.cost, c.plan_id "
            "FROM _interlock_outbox o JOIN _interlock_commits c USING (stage_id)"
        ).fetchone()
    assert row is not None and (row[1], row[2], row[4], row[5]) == (
        plan.plan_id,
        "agent",
        "0.002",
        plan.plan_id,
    )
    request = plan.effects[1].request
    assert request is not None and row[3].encode() == request.canonical_payload
    assert outbox.state(staged.message_id) == "pending"


def test_a_refused_or_failed_plan_leaves_nothing(outbox: SqliteOutbox) -> None:
    refused = outbox.engine(checkers=[BlastRadius(0)]).execute(ship().build())
    assert not refused.committed and refused.diff is not None and refused.diff.outbound
    failing = ship().update(
        table="orders", statement="UPDATE orders SET total = 'x' + 1 WHERE id = no_such_column"
    )
    with pytest.raises(StageError):
        outbox.engine().execute(failing.build())
    assert count(outbox, "_interlock_outbox") == 0
    assert count(outbox, "_interlock_outbox_state") == 0
    assert count(outbox, "_interlock_commits") == 0


def test_an_outbox_row_without_a_committed_stage_cannot_exist(outbox: SqliteOutbox) -> None:
    """The deferred foreign key: a row naming a stage with no commit marker
    fails at COMMIT, however it was written."""
    with closing(outbox.raw()) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN")
        conn.execute(
            "INSERT INTO _interlock_outbox (message_id, stage_id, plan_id, scope_id, "
            "effect_id, seq, sink, operation, payload, payload_hash, idempotency_key, cost, "
            "not_after, enqueued_at) VALUES (?, ?, 'p', 'agent', 'e', 1, 'mail', 'send', "
            "'{}', 'h', 'k', '0', 0, 0)",
            (str(uuid.uuid4()), str(uuid.uuid4())),
        )
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            conn.execute("COMMIT")
        conn.execute("ROLLBACK")
    assert count(outbox, "_interlock_outbox") == 0


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO _interlock_outbox (message_id) VALUES ('x')",
        "UPDATE _interlock_outbox_state SET state = 'delivered'",
        "DELETE FROM _interlock_outbox_attempts",
        "UPDATE _interlock_sinks SET max_payload_bytes = 1000000000",
    ],
)
def test_the_agents_sql_cannot_write_the_outbox(outbox: SqliteOutbox, statement: str) -> None:
    """The authorizer refuses at prepare time: the statement never runs, and
    the stage rolls back."""
    plan = ship().update(table="orders", statement=statement).build()
    with pytest.raises(ForbiddenStatementError, match="only the substrate"):
        outbox.engine().execute(plan)
    assert count(outbox, "_interlock_outbox") == 0


def test_the_database_refuses_what_its_registry_does_not_hold(outbox: SqliteOutbox) -> None:
    wider = SinkRegistry(
        [
            SinkSpec("mail", (OperationSpec("send"), OperationSpec("digest"))),
            SinkSpec("sms", (OperationSpec("send"),)),
            SinkSpec("fax", (OperationSpec("send"),)),
        ]
    )
    install_sqlite_outbox(outbox.path, RELAY_SINKS[:1])  # sms: disabled
    for sink, operation, reason in (
        ("fax", "send", "unregistered_sink"),
        ("sms", "send", "unregistered_sink"),
        ("mail", "digest", "unregistered_operation"),
    ):
        plan = PlanBuilder("agent").enqueue(sink=sink, operation=operation, payload={}).build()
        engine = EscrowEngine(
            SqliteSubstrate(outbox.path, tables=specs(*OBSERVED)), checkers=[], sinks=wider
        )
        with pytest.raises(OutboundRequestError) as caught:
            engine.execute(plan)
        assert caught.value.reason == reason
    assert count(outbox, "_interlock_outbox") == 0


def test_a_price_the_file_disagrees_with_is_refused(outbox: SqliteOutbox) -> None:
    dearer = SinkSpec(
        "mail",
        (OperationSpec("send", schema=MAIL_SEND_SCHEMA),),
        cost_per_call=Decimal("0.003"),
        max_payload_bytes=4096,
    )
    install_sqlite_outbox(outbox.path, (dearer, *RELAY_SINKS[1:]))
    with pytest.raises(SubstrateConfigurationError, match=r"0\.003"):
        outbox.engine().execute(ship().build())
    assert count(outbox, "_interlock_outbox") == 0


def test_a_request_commits_at_most_once(outbox: SqliteOutbox) -> None:
    plan = ship().build()
    assert outbox.engine().execute(plan).committed
    with pytest.raises(OutboundRequestError) as caught:
        outbox.engine().execute(plan)
    assert caught.value.reason == "duplicate"
    assert count(outbox, "_interlock_outbox") == 1


def test_repair_stages_requests_in_savepoints_and_commits_none(outbox: SqliteOutbox) -> None:
    plan = (
        ship()
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'cancelled'",
            effect_id=EffectId("everything"),
            independent=True,
        )
        .build()
    )
    engine = outbox.engine(checkers=[BlastRadius(1)])
    repair = engine.repair(plan)
    assert repair.proposal is not None and set(repair.kept) == {"ship", "notify"}
    assert count(outbox, "_interlock_outbox") == 0
    assert engine.execute(repair.proposal).committed
    assert count(outbox, "_interlock_outbox") == 1


def test_the_runtime_takes_a_sink_registry(outbox: SqliteOutbox) -> None:
    runtime = EscrowRuntime(
        outbox.path,
        tables=specs(*OBSERVED),
        scope_id="agent",
        checkers=[BlastRadius(10)],
        sinks=REGISTRY,
        acknowledge_cascades=("shipment_events", "ledger_entries"),
    )
    result = runtime.engine.execute(
        runtime.plan()
        .enqueue(sink="mail", operation="send", payload={"to": "a@b.c", "subject": "s"})
        .build()
    )
    assert result.committed and count(outbox, "_interlock_outbox") == 1


# --------------------------------------------------------------------------
# the write lock
# --------------------------------------------------------------------------


def test_an_open_stage_holds_the_relay_off(outbox: SqliteOutbox) -> None:
    """OB-7, by SQLite's lock: while a stage is open, a relay can neither see
    its request nor take the lock to lease anything. When the stage commits,
    the request is delivered."""
    staged = threading.Event()
    gate = threading.Event()

    class Holding(SqliteSubstrate):
        def commit(self, handle: Any) -> Any:
            staged.set()
            assert gate.wait(10)
            return super().commit(handle)

    engine = outbox.engine(substrate=outbox.substrate(Holding), checkers=[BlastRadius(10)])
    results: list[Any] = []
    stager = threading.Thread(target=lambda: results.append(engine.execute(ship().build())))
    stager.start()
    try:
        assert staged.wait(10)
        assert outbox.states() == {}, "nothing written by an open stage is visible"
        impatient = Relay(
            SqliteOutboxStore(outbox.path, busy_seconds=0.2),
            adapters=outbox.adapters(),
            breaker=NoBreaker(),
            lease=timedelta(seconds=5),
            timeout=timedelta(seconds=2),
            signer=relay_signer(),
        )
        with pytest.raises(SubstrateUnavailableError, match="locked"):
            impatient.run_once()
        impatient.close()
        gate.set()
        stager.join(10)
        assert results and results[0].committed
    finally:
        gate.set()
        stager.join(10)
    with outbox.relay(breaker=NoBreaker()) as relay:
        assert relay.run_once().delivered == 1


def test_a_relay_waits_for_a_stage_rather_than_failing(outbox: SqliteOutbox) -> None:
    outbox.commit(mail(1))
    staged = threading.Event()

    class Slow(SqliteSubstrate):
        def commit(self, handle: Any) -> Any:
            staged.set()
            time.sleep(0.5)
            return super().commit(handle)

    engine = outbox.engine(substrate=outbox.substrate(Slow), checkers=[BlastRadius(10)])
    stager = threading.Thread(target=lambda: engine.execute(ship().build()))
    stager.start()
    assert staged.wait(10)
    started = time.monotonic()
    with outbox.relay(breaker=NoBreaker()) as relay:
        assert relay.run_once(limit=10).claimed >= 1
    assert time.monotonic() - started >= 0.3, "it queued behind the stage's lock"
    stager.join(10)


def test_the_relays_connection_writes_only_delivery_state_and_the_log(
    outbox: SqliteOutbox,
) -> None:
    store = SqliteOutboxStore(outbox.path)
    conn = store._conn
    try:
        for statement in (
            "UPDATE orders SET total = 0",
            "INSERT INTO _interlock_outbox (message_id) VALUES ('x')",
            "UPDATE _interlock_sinks SET enabled = 1",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                conn.execute(statement)
    finally:
        store.close()


def test_an_outcome_waits_out_a_lock_held_past_its_busy_timeout(outbox: SqliteOutbox) -> None:
    """The call already happened, so recording its outcome is tried again
    when the lock is held longer than the store waits."""
    _, (message,) = outbox.commit(mail(1))
    store = SqliteOutboxStore(outbox.path, busy_seconds=0.15)
    blocker = sqlite3.connect(outbox.path, isolation_level=None, check_same_thread=False)
    try:
        (lease,) = store.claim("r", timedelta(seconds=10), 1, ["mail"], 0.0)
        attempt = store.sending(lease, "r", "breaker clear at test")
        assert attempt == 1
        blocker.execute("BEGIN IMMEDIATE")
        threading.Timer(0.25, lambda: blocker.execute("ROLLBACK")).start()
        result = DeliveryResult("delivered", status_code=202)
        attestation = attest(lease, attempt, result, relay_signer())
        assert store.outcome(lease, "r", attempt, result, timedelta(0), attestation) == "delivered"
    finally:
        store.close()
        blocker.close()
    assert outbox.events(message) == [("sending", 1), ("delivered", 1)]


def test_an_outcome_that_never_gets_the_lock_is_left_to_the_lease(
    outbox: SqliteOutbox,
) -> None:
    """Three waits, then the store gives up: nothing is recorded, and the
    relay that takes the message over records the call lost."""
    _, (message,) = outbox.commit(mail(1))
    store = SqliteOutboxStore(outbox.path, busy_seconds=0.05)
    blocker = sqlite3.connect(outbox.path, isolation_level=None)
    try:
        (lease,) = store.claim("r", timedelta(milliseconds=500), 1, ["mail"], 0.0)
        attempt = store.sending(lease, "r", "breaker clear at test")
        assert attempt == 1
        blocker.execute("BEGIN IMMEDIATE")
        result = DeliveryResult("delivered")
        attestation = attest(lease, attempt, result, relay_signer())
        with pytest.raises(SubstrateUnavailableError, match="locked"):
            store.outcome(lease, "r", attempt, result, timedelta(0), attestation)
        blocker.execute("ROLLBACK")
    finally:
        store.close()
        blocker.close()
    time.sleep(0.6)
    with outbox.relay(breaker=NoBreaker()) as relay:
        outbox.drain(relay)
    assert outbox.events(message) == [("sending", 1), ("lost", 1), ("sending", 2), ("delivered", 2)]


def test_a_claim_needs_a_relay_a_lease_and_a_limit(outbox: SqliteOutbox) -> None:
    store = outbox.store()
    try:
        for relay_id, lease, limit in (
            ("", timedelta(seconds=1), 1),
            ("r", timedelta(0), 1),
            ("r", timedelta(seconds=1), 0),
        ):
            with pytest.raises(ValueError, match="positive lease"):
                store.claim(relay_id, lease, limit, ["mail"], 0.0)
    finally:
        store.close()


# --------------------------------------------------------------------------
# the delivery log
# --------------------------------------------------------------------------


def delivered(outbox: SqliteOutbox, *requests: OutboundRequest) -> list[uuid.UUID]:
    _, messages = outbox.commit(*(requests or (mail(1),)))
    with outbox.relay(breaker=NoBreaker()) as relay:
        outbox.drain(relay)
    return messages


def test_a_connection_without_interlock_cannot_append_to_the_log(outbox: SqliteOutbox) -> None:
    (message,) = delivered(outbox)
    head = outbox.row(message)
    with closing(outbox.raw()) as conn:
        with pytest.raises(sqlite3.OperationalError, match="interlock_event_hash"):
            conn.execute(
                "INSERT INTO _interlock_outbox_attempts (message_id, seq, event, actor, at, "
                "prev_hash, event_hash, state_after) VALUES (?, ?, 'released', 'dba', "
                "'2026-10-03T00:00:00.000000Z', ?, 'forged', 'pending')",
                (str(message), int(head["log_seq"]) + 1, head["log_head"]),
            )
    outbox.verify()


def test_a_row_that_does_not_extend_its_log_is_refused(outbox: SqliteOutbox) -> None:
    from interlock.sqlite_outbox import register

    (message,) = delivered(outbox)
    with closing(outbox.raw()) as conn:
        register(conn)
        for seq, prev in ((1, "0" * 64), (99, outbox.row(message)["log_head"])):
            with pytest.raises(sqlite3.IntegrityError, match="must extend"):
                conn.execute(
                    "INSERT INTO _interlock_outbox_attempts (message_id, seq, event, actor, at, "
                    "prev_hash, event_hash) VALUES (?, ?, 'held', 'dba', "
                    "'2026-10-03T00:00:00.000000Z', ?, 'x')",
                    (str(message), seq, prev),
                )
        # And an operator's row needs a signed authority before anything else.
        with pytest.raises(sqlite3.IntegrityError, match="signed authority"):
            conn.execute(
                "INSERT INTO _interlock_outbox_attempts (message_id, seq, event, actor, at, "
                "prev_hash, event_hash) VALUES (?, 99, 'released', 'dba', "
                "'2026-10-03T00:00:00.000000Z', 'x', 'x')",
                (str(message),),
            )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE _interlock_outbox SET payload = '{}'",
        "DELETE FROM _interlock_outbox",
        "UPDATE _interlock_outbox_attempts SET detail = 'honest'",
        "DELETE FROM _interlock_outbox_attempts",
    ],
)
def test_the_outbox_and_its_log_are_append_only(outbox: SqliteOutbox, statement: str) -> None:
    delivered(outbox)
    with closing(outbox.raw()) as conn, pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(statement)


def test_a_log_rewritten_around_the_triggers_does_not_verify(outbox: SqliteOutbox) -> None:
    """Whoever can write the file can drop the triggers. Then the log no
    longer hashes, and a state set directly is not the state its log leads
    to: verification names both."""
    rewritten, forged = delivered(outbox, mail(1), mail(2))
    with closing(outbox.raw()) as conn:
        conn.execute("DROP TRIGGER _interlock_log_no_update")
        conn.execute(
            "UPDATE _interlock_outbox_attempts SET detail = 'breaker clear, honest' "
            "WHERE message_id = ? AND seq = 1",
            (str(rewritten),),
        )
        conn.execute(
            "UPDATE _interlock_outbox_state SET state = 'pending' WHERE message_id = ?",
            (str(forged),),
        )
    assert set(verify_delivery_log(outbox.operator())) == {
        f"message {rewritten}: row 1 (sending) does not hash to what it records",
        f"message {forged}: the message is pending, and its log records delivery",
        f"message {forged}: the message is pending, and its log leads to delivered",
    }


# --------------------------------------------------------------------------
# the command line
# --------------------------------------------------------------------------

CONFIG = """
substrate = "sqlite"
database = "{database}"

[[tables]]
name = "orders"
columns = ["id", "customer_id", "tenant", "status", "total"]
tenant_column = "tenant"

[[sinks]]
name = "mail"
cost_per_call = "0.002"
backoff_base_seconds = 0.02
backoff_cap_seconds = 0.16

[[sinks.operations]]
name = "send"

[relay]
key = "relay.key"
breaker = "none"
lease_seconds = 4
timeout_seconds = 1

[[relay.endpoints]]
sink = "mail"
url = "{url}"
routes = {{ send = "POST /mail/send" }}
"""


def cli(*argv: str) -> tuple[int, str]:
    from interlock.cli import main

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def test_the_command_line_on_a_sqlite_file(tmp_path: Path) -> None:
    from tests.fakesink import FakeSink, status

    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    sink = FakeSink()
    try:
        path = tmp_path / "interlock.toml"
        key = generate_key(tmp_path / "ops.key")
        path.write_text(
            CONFIG.format(database=database, url=sink.url)
            + f'\n[operators]\nlog = "operators.ilok1"\n'
            f'[operators.keys]\nops = "{key.public_key().spec()}"\n' + relays_section(tmp_path)
        )
        # With [operators], installing changes the registry an operator signs for.
        assert cli("install", "--config", str(path))[0] == 2
        code, out = cli("install", "--config", str(path), "--key", str(tmp_path / "ops.key"))
        assert code == 0 and "the outbox, the inbox, and WAL mode" in out
        assert "registered sink: mail" in out
        assert "signed by ops: the sink registry" in out
        registry = SinkRegistry(
            [SinkSpec("mail", (OperationSpec("send"),), cost_per_call=Decimal("0.002"))]
        )
        engine = EscrowEngine(
            SqliteSubstrate(database, tables=specs("orders")), checkers=[], sinks=registry
        )
        for n in range(2):
            plan = (
                PlanBuilder("agent")
                .enqueue(sink="mail", operation="send", payload={"n": n})
                .build()
            )
            assert engine.execute(plan).committed
        sink.script(status(400))
        code, out = cli("relay", "--config", str(path), "--once")
        assert code == 0 and "claimed 2: delivered 1" in out and "dead 1" in out
        code, out = cli("outbox", "status", "--config", str(path))
        assert code == 0 and "delivered  1" in out and "dead       1" in out
        code, out = cli("outbox", "list", "--state", "dead", "--config", str(path))
        dead = uuid.UUID(out.split()[0])
        # Unsigned, an operator's action is refused; signed, it is recorded.
        assert cli("outbox", "requeue", str(dead), "--config", str(path))[0] == 2
        code, out = cli(
            "outbox",
            "requeue",
            str(dead),
            "--config",
            str(path),
            "--key",
            str(tmp_path / "ops.key"),
        )
        assert code == 0 and "signed by ops" in out and "operator.applied" in out
        assert cli("relay", "--config", str(path), "--once")[0] == 0
        code, out = cli("outbox", "show", str(dead), "--config", str(path))
        assert code == 0 and [line.split()[2] for line in out.splitlines()] == [
            "sending",
            "permanent",
            "requeued",
            "sending",
            "delivered",
        ]
        code, out = cli("outbox", "verify", "--config", str(path))
        assert code == 0 and "every operator action is signed" in out
    finally:
        sink.close()


def test_the_outbox_command_needs_an_installed_outbox(tmp_path: Path) -> None:
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = tmp_path / "interlock.toml"
    path.write_text(
        f'substrate = "sqlite"\ndatabase = "{database}"\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id"]\n'
    )
    assert cli("outbox", "status", "--config", str(path))[0] == 3


def test_relay_roles_are_postgresqls(tmp_path: Path) -> None:
    from interlock.config import ConfigError, load_config

    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "sqlite"\ndatabase = "x.sqlite"\nrelay_roles = ["r"]\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id"]\n'
    )
    with pytest.raises(ConfigError, match="PostgreSQL roles"):
        load_config(path)
