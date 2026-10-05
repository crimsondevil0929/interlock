"""Relays' attestations, and ghost deliveries (``docs/EPIC4_DESIGN.md`` §1.1, §2).

On both stores:

- every outcome a relay records carries its Ed25519 attestation, which
  verifies under the relay's registered key, over the request as the outbox
  committed it and the outcome as the row records it;
- the database refuses an outcome row without one, or with anything that is
  not one;
- a ghost delivery, written around Interlock and linked and hashed perfectly,
  is named: with no attestation, with one by a key no relay is registered
  with, with one copied from another call, with a genuine one whose row was
  rewritten; and so is an outcome backdated to pass for one recorded before
  version 4.

And: a relay attests with Ed25519 only; ``interlock relay`` starts only with
a key registered in ``[relays.keys]``; ``interlock keygen --role relay``
makes one; version 4 installed over a SQLite file version 3 installed and
relayed (``tests/sqlite_outbox_v3.py``, frozen) keeps every row and counts
version 3's outcomes as legacy. PostgreSQL's upgrades are
``tests/test_pg_upgrade.py``.
"""

from __future__ import annotations

import io
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.receipts import Attestation, AttestedOutcome, DeliveredRequest
from agentgov.receipts.canonical import canonical_bytes
from agentgov.receipts.signing import Ed25519Signer, HmacKey, Signer

from interlock import EscrowEngine, PlanBuilder, SqliteSubstrate
from interlock.attestations import attestation_of, verify_attestations
from interlock.cli import main
from interlock.deliveries import OUTCOMES, LogEvent, reader, verify_delivery_log
from interlock.exceptions import SubstrateConfigurationError
from interlock.operators import OperatorRefusedError
from interlock.relay import DELIVERED, RETRYABLE, DeliveryResult, NoBreaker, Relay
from interlock.sqlite_outbox import (
    OPERATOR,
    VERSION,
    SqliteOutboxStore,
    install_sqlite_outbox,
    installed_version,
)
from tests import sqlite_outbox_v3 as v3
from tests.conftest import OBSERVED, build_sqlite_back_office
from tests.fakesink import DROP, FakeSink, status
from tests.outbox_env import (
    BACKENDS,
    INSTALLER,
    INSTALLERS,
    REGISTRY,
    RELAY_SINKS,
    RELAYS,
    SCOPE,
    Outbox,
    PostgresOutbox,
    Scripted,
    SqliteOutbox,
    build_either,
    mail,
    page,
    relay_signer,
    relays_section,
    sms,
    vouch,
)
from tests.schemas import specs


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def signature_json(statement: Attestation, signer: Signer) -> str:
    """A signed statement's signature, as an outcome row stores it."""
    signed = statement.sign(signer).signature
    assert signed is not None
    return canonical_bytes(signed.to_json()).decode("ascii")


def statement(
    outbox: Outbox, message: uuid.UUID, *, attempt: int, result: str = DELIVERED
) -> Attestation:
    """What a relay would attest for a call on ``message``: the request as
    the outbox holds it, and ``result``, answered 200."""
    (logged,), _ = reader(outbox.operator()).snapshot([message])
    return Attestation(
        request=DeliveredRequest(
            message_id=str(message),
            effect_id=logged.effect_id,
            sink=logged.sink,
            operation=logged.operation,
            payload_hash=logged.payload_hash,
            idempotency_key=logged.idempotency_key,
        ),
        outcome=AttestedOutcome(attempt=attempt, result=result, status_code=200),
    )


def ghost(outbox: Outbox, message: uuid.UUID, attestation: str | None, **row: Any) -> None:
    """A delivery no relay made: a call and its ``delivered`` outcome, written
    around Interlock, linked, hashed and counted exactly as a relay's."""
    outbox.forge(
        message,
        "sending",
        authority=None,
        state_after="leased",
        actor="relay:ghost",
        attempt=1,
        detail="breaker clear",
        at=row.get("at"),
    )
    outbox.forge(
        message,
        DELIVERED,
        authority=None,
        state_after=DELIVERED,
        actor="relay:ghost",
        attempt=1,
        status_code=200,
        detail=None,
        attestation=attestation,
        **row,
    )


def problems(outbox: Outbox) -> tuple[str, ...]:
    """What only the attestations show: the delivery logs and the operator
    log verify."""
    assert verify_delivery_log(outbox.operator()) == ()
    assert outbox.verify_operators().problems == ()
    return outbox.attestations().problems


# --------------------------------------------------------------------------
# attested outcomes
# --------------------------------------------------------------------------


def test_every_outcome_carries_its_relays_attestation(outbox: Outbox) -> None:
    """Delivered, retryable, permanent and unknown alike: each verifies under
    the relay's key, over the request and the outcome as the rows hold them."""
    _, messages = outbox.commit(mail(1), sms(2), page(3))
    outbox.sink("mail").script(status(503))
    outbox.sink("sms").script(status(400))
    outbox.sink("pager").script(DROP)
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert [outbox.state(m) for m in messages] == ["delivered", "dead", "dead"]
    outcomes: list[tuple[uuid.UUID, LogEvent]] = [
        (m, e) for m in messages for e in outbox.log(m) if e.event in OUTCOMES
    ]
    assert sorted(e.event for _, e in outcomes) == [
        "delivered",
        "permanent",
        "retryable",
        "unknown",
    ]
    (logged, _) = reader(outbox.operator()).snapshot(None)
    by_id = {m.message_id: m for m in logged}
    key = relay_signer().public_key()
    for message, event in outcomes:
        assert event.attestation is not None and key.key_id in event.attestation
        attestation_of(by_id[message], event).verify(key)
    report = outbox.attestations()
    assert (report.problems, report.attested, report.legacy) == ((), 4, 0)
    outbox.verify()


def test_the_database_refuses_an_outcome_without_an_attestation(outbox: Outbox) -> None:
    """Whatever writes through Interlock's own functions: an outcome row
    carries a relay's Ed25519 signature, in its exact shape, or none is
    written."""
    _, (message,) = outbox.commit(mail(1))
    store = outbox.store()
    try:
        (lease,) = store.claim("r", timedelta(seconds=10), 1, ["mail"], 0.0)
        attempt = store.sending(lease, "r", "breaker clear at test")
        assert attempt == 1
        result = DeliveryResult(DELIVERED, status_code=200)
        genuine = signature_json(statement(outbox, message, attempt=1), relay_signer())
        for refused in (
            "",
            "{}",
            genuine.replace('"ed25519"', '"hmac-sha256"'),
            genuine.replace('"signature":"', '"signature":"0'),
            genuine[:-3] + '"}',
            genuine + " ",
        ):
            with pytest.raises(Exception, match="attestation") as caught:
                store.outcome(lease, "r", attempt, result, timedelta(0), refused)
            if outbox.backend == "postgres":
                assert getattr(caught.value, "sqlstate", None) == "IL008"
        assert outbox.events(message) == [("sending", 1)]
        assert store.outcome(lease, "r", attempt, result, timedelta(0), genuine) == DELIVERED
    finally:
        store.close()
    outbox.verify()


def test_a_relay_attests_with_ed25519_only(outbox: Outbox) -> None:
    """An HMAC key verifies only for whoever holds it: anyone who could check
    the attestation could make one."""
    with pytest.raises(ValueError, match="Ed25519"):
        outbox.relay(signer=HmacKey(b"k" * 32))


# --------------------------------------------------------------------------
# ghost deliveries
# --------------------------------------------------------------------------


def test_a_delivery_no_relay_attested_is_named(outbox: Outbox) -> None:
    _, (message,) = outbox.commit(mail(1))
    ghost(outbox, message, None)
    assert outbox.state(message) == DELIVERED
    (found,) = problems(outbox)
    assert str(message) in found and "carries no relay attestation" in found


def test_a_delivery_attested_by_an_unregistered_key_is_named(outbox: Outbox) -> None:
    """The forger's own key signs the very statement a relay would have."""
    _, (message,) = outbox.commit(mail(1))
    rogue = Ed25519Signer.generate()
    ghost(outbox, message, signature_json(statement(outbox, message, attempt=1), rogue))
    (found,) = problems(outbox)
    assert f"attested by key {rogue.key_id}, which is no registered relay's" in found


def test_an_attestation_copied_from_another_delivery_is_named(outbox: Outbox) -> None:
    """A genuine signature, by the registered relay, over another request."""
    _, (real, target) = outbox.commit(mail(1), mail(2))
    with outbox.relay() as relay:
        assert relay.run_once(limit=1).delivered == 1  # the older one
    (delivered,) = [e for e in outbox.log(real) if e.event == DELIVERED]
    ghost(outbox, target, delivered.attestation)
    (found,) = problems(outbox)
    assert f"message {target}: row 2 (delivered) says what relay relay never attested" in found


def test_a_failure_rewritten_as_a_delivery_is_named(outbox: Outbox) -> None:
    """The relay's genuine row, its outcome turned from ``permanent`` to
    ``delivered`` and every hash recomputed: the signature still says
    ``permanent``."""
    _, (message,) = outbox.commit(sms(1))
    outbox.sink("sms").script(status(400))
    with outbox.relay() as relay:
        outbox.drain(relay)
    assert outbox.state(message) == "dead"
    outbox.rewrite_last(message, event=DELIVERED, state_after=DELIVERED)
    assert outbox.state(message) == DELIVERED
    (found,) = problems(outbox)
    assert f"message {message}: row 2 (delivered) says what relay relay never attested" in found


def test_an_unattested_outcome_outside_the_legacy_set_is_named_however_dated(
    outbox: Outbox,
) -> None:
    """Dated before version 4 was installed, on an empty log or after a call a
    relay started: neither is in the legacy set version 4 recorded, and the
    date buys nothing."""
    epoch = reader(outbox.operator()).epoch("4")
    assert epoch is not None
    before = epoch - timedelta(hours=1)
    _, (started, untried) = outbox.commit(mail(1), mail(2))
    store = outbox.store()
    try:
        (lease,) = store.claim("r", timedelta(seconds=10), 1, ["mail"], 0.0)
        assert lease.message_id == started  # the older one
        assert store.sending(lease, "r", "breaker clear at test") == 1
    finally:
        store.close()
    ghost(outbox, untried, None, at=before)
    outbox.forge(
        started,
        DELIVERED,
        authority=None,
        state_after=DELIVERED,
        actor="r",
        attempt=1,
        status_code=200,
        detail=None,
        at=before,
    )
    found = problems(outbox)
    assert len(found) == 2
    for message in (untried, started):
        assert any(
            f"{message}: row 2 (delivered) carries no relay attestation, and is not in the "
            f"legacy set" in p
            for p in found
        )
    assert outbox.attestations().legacy == 0


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
    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


@pytest.fixture
def sink() -> Iterator[FakeSink]:
    fake = FakeSink()
    try:
        yield fake
    finally:
        fake.close()


def _commit(database: str, n: int) -> None:
    from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec

    registry = SinkRegistry(
        [SinkSpec("mail", (OperationSpec("send"),), cost_per_call=Decimal("0.002"))]
    )
    engine = EscrowEngine(
        SqliteSubstrate(database, tables=specs("orders")), checkers=[], sinks=registry
    )
    plan = PlanBuilder("agent").enqueue(sink="mail", operation="send", payload={"n": n}).build()
    assert engine.execute(plan).committed


def test_the_relay_command_starts_only_with_a_registered_key(
    tmp_path: Path,
    sink: FakeSink,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("INTERLOCK_RELAY_KEY", raising=False)
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = tmp_path / "interlock.toml"
    config = CONFIG.format(database=database, url=sink.url)
    path.write_text(config.replace('key = "relay.key"\n', ""))
    assert cli("install", "--config", str(path))[0] == 0
    _commit(database, 1)

    # No key: the relay says how to give it one, and sends nothing.
    assert cli("relay", "--config", str(path), "--once")[0] == 2
    assert "a relay signs every outcome it records" in capsys.readouterr().err

    # A new key, written once, never overwritten.
    keygen = ("keygen", "--role", "relay", "--out", str(tmp_path / "relay.key"), "--name")
    code, out = cli(*keygen, "east-1")
    assert code == 0
    assert stat.S_IMODE((tmp_path / "relay.key").stat().st_mode) == 0o600
    table, line = out.splitlines()[1:3]
    assert table == "[relays.keys]" and line.startswith('east-1 = "ed25519:')
    assert cli(*keygen, "west-1")[0] == 2
    assert "never overwritten" in capsys.readouterr().err

    # The key, not registered: nothing it signed would verify.
    path.write_text(config)
    assert cli("relay", "--config", str(path), "--once")[0] == 2
    err = capsys.readouterr().err
    assert "is not registered" in err and "[relays.keys]" in err
    # Registered under another relay's name, a key it was never given.
    other = Ed25519Signer.generate().public_key().spec()
    path.write_text(config + f'\n[relays.keys]\nwest-1 = "{other}"\n')
    assert cli("relay", "--config", str(path), "--once")[0] == 2
    assert "is not registered" in capsys.readouterr().err
    assert sink.calls == []

    # A key that cannot be read.
    path.write_text(config + f"\n[relays.keys]\n{line}\n")
    code, _ = cli("relay", "--config", str(path), "--once", "--key", str(tmp_path / "nope.key"))
    assert code == 2 and "cannot read the relay key" in capsys.readouterr().err

    # Registered: it delivers, and every outcome is its.
    code, out = cli("relay", "--config", str(path), "--once")
    assert code == 0 and "claimed 1: delivered 1" in out
    code, out = cli("outbox", "list", "--config", str(path))
    message = out.split()[0]
    code, out = cli("outbox", "show", message, "--config", str(path))
    assert code == 0 and "attested by east-1" in out.splitlines()[1]
    code, out = cli("outbox", "verify", "--config", str(path))
    assert (code, out.splitlines()[:2]) == (
        0,
        ["every delivery log verifies", "every outcome is attested by a registered relay (1)"],
    )


def test_the_relay_key_comes_from_the_flag_then_the_environment_then_the_file(
    tmp_path: Path, sink: FakeSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = tmp_path / "interlock.toml"
    path.write_text(CONFIG.format(database=database, url=sink.url) + relays_section(tmp_path))
    assert cli("install", "--config", str(path))[0] == 0
    unregistered = tmp_path / "unregistered.key"
    unregistered.write_text("11" * 32 + "\n")
    _commit(database, 1)
    monkeypatch.setenv("INTERLOCK_RELAY_KEY", str(unregistered))
    assert cli("relay", "--config", str(path), "--once")[0] == 2, "the environment beats the file"
    code, out = cli("relay", "--config", str(path), "--once", "--key", str(tmp_path / "relay.key"))
    assert code == 0 and "delivered 1" in out, "the flag beats the environment"


def test_verify_names_a_ghost_delivery_and_says_when_it_cannot_check(
    tmp_path: Path, sink: FakeSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INTERLOCK_RELAY_KEY", raising=False)
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = tmp_path / "interlock.toml"
    config = CONFIG.format(database=database, url=sink.url)
    path.write_text(config + relays_section(tmp_path))
    assert cli("install", "--config", str(path))[0] == 0
    _commit(database, 1)
    _commit(database, 2)
    with closing(sqlite3.connect(database)) as conn:
        (first,) = conn.execute(
            "SELECT message_id FROM _interlock_outbox ORDER BY seq LIMIT 1"
        ).fetchone()
    owner = owned(database, tmp_path)
    try:
        ghost(owner, uuid.UUID(first), None)
    finally:
        owner.close()
    code, out = cli("outbox", "verify", "--config", str(path))
    assert code == 1 and f"message {first}" in out and "no relay reported" in out
    path.write_text(config)
    code, out = cli("outbox", "verify", "--config", str(path))
    assert code == 0 and "relays' attestations not checked" in out


def owned(database: str, tmp_path: Path) -> SqliteOutbox:
    """The file, as its owner reaches it: to forge in."""
    ledger = str(tmp_path / "governor.db")
    return SqliteOutbox(database, ledger, BudgetManager.open_sqlite(ledger))


# --------------------------------------------------------------------------
# version 4 over version 3, on SQLite
# --------------------------------------------------------------------------


class Version3Store(v3.SqliteOutboxStore):
    """Version 3's relay: its outcome records no attestation."""

    def outcome(  # type: ignore[override]
        self,
        lease: Any,
        relay_id: str,
        attempt: int,
        result: DeliveryResult,
        delay: timedelta,
        attestation: str,
    ) -> str | None:
        return super().outcome(lease, relay_id, attempt, result, delay)


def _log_rows(path: str) -> list[tuple[Any, ...]]:
    with closing(sqlite3.connect(path)) as conn:
        return list(
            conn.execute(
                "SELECT message_id, seq, event, prev_hash, event_hash "
                "FROM _interlock_outbox_attempts ORDER BY message_id, seq"
            )
        )


def test_version_4_over_version_3_on_sqlite(tmp_path: Path) -> None:
    path = build_sqlite_back_office(tmp_path / "app.sqlite")
    v3.install_sqlite_outbox(path, RELAY_SINKS)
    with pytest.raises(SubstrateConfigurationError, match="installed by version 3"):
        SqliteOutboxStore(path)

    # Version 3's traffic: one delivered, one failed and due again, one untried.
    engine = EscrowEngine(
        SqliteSubstrate(path, tables=specs(*OBSERVED)), checkers=[], sinks=REGISTRY
    )
    for n in range(3):
        request = mail(n)
        plan = PlanBuilder(SCOPE).enqueue(
            sink=request.sink, operation=request.operation, payload=request.payload
        )
        assert engine.execute(plan.build()).committed
    for outcome, expected in ((DELIVERED, "delivered"), (RETRYABLE, "pending")):
        with Relay(
            Version3Store(path),
            adapters={"mail": Scripted(outcome)},
            breaker=NoBreaker(),
            relay_id="version-3",
            signer=relay_signer(),
        ) as old:
            (lease,) = old._claim(1)
            assert old._deliver(lease) == expected
    before = _log_rows(path)
    assert len(before) == 4

    # The upgrade, in place, twice.
    install_sqlite_outbox(path, RELAY_SINKS)
    install_sqlite_outbox(path, RELAY_SINKS)
    with closing(sqlite3.connect(path)) as conn:
        assert installed_version(conn) == VERSION
    assert _log_rows(path) == before
    operator = SqliteOutboxStore(path, writes=OPERATOR)
    try:
        assert verify_delivery_log(operator) == ()
        # Version 3's two outcomes are the legacy set, recorded once: the
        # second install added nothing.
        recorded = operator.legacy()
        assert recorded is not None and len(recorded) == 2
        # Until a signed install vouches for it, it rests on the database's word.
        (unvouched,) = verify_attestations(operator, RELAYS).problems
        assert "2 outcome(s) from before version 4" in unvouched
        assert "no signed install vouches" in unvouched
        vouched = vouch(operator, tmp_path / "operators.ilok1")
        assert (vouched.rows, vouched.digest) == (2, recorded.digest)
        report = verify_attestations(operator, RELAYS, legacy=vouched)
        assert (report.problems, report.attested, report.legacy) == ((), 0, 2)
    finally:
        operator.close()

    # A relay of version 3 left running records nothing, not even a call:
    # the log's link trigger hashes the attestation too, through a function
    # only version 4 registers.
    late = Version3Store(path)
    try:
        (lease,) = late.claim("version-3-late", timedelta(seconds=1), 1, ["mail"], 0.0)
        with pytest.raises(sqlite3.OperationalError, match="interlock_event_hash"):
            late.sending(lease, "version-3-late", "breaker clear at test")
    finally:
        late.close()

    # Version 4 delivers the rest, every outcome attested.
    new = Relay(
        SqliteOutboxStore(path),
        adapters={"mail": Scripted()},
        breaker=NoBreaker(),
        relay_id="version-4",
        lease=timedelta(seconds=2),
        timeout=timedelta(seconds=0.5),
        signer=relay_signer(),
    )
    with new:
        for _ in range(200):
            new.run_once(limit=10)
            with closing(sqlite3.connect(path)) as conn:
                (left,) = conn.execute(
                    "SELECT count(*) FROM _interlock_outbox_state WHERE state <> 'delivered'"
                ).fetchone()
            if left == 0:
                break
            time.sleep(0.05)
    after = _log_rows(path)
    assert set(before) <= set(after)
    operator = SqliteOutboxStore(path, writes=OPERATOR)
    try:
        assert verify_delivery_log(operator) == ()
        report = verify_attestations(operator, RELAYS, legacy=vouched)
        assert (report.problems, report.attested, report.legacy) == ((), 2, 2)
    finally:
        operator.close()
    assert Path(v3.__file__).name == "sqlite_outbox_v3.py"


def _version_3_traffic(path: str) -> uuid.UUID:
    """Three requests staged under version 3, one delivered by its relay: the
    delivered message."""
    v3.install_sqlite_outbox(path, RELAY_SINKS)
    engine = EscrowEngine(
        SqliteSubstrate(path, tables=specs(*OBSERVED)), checkers=[], sinks=REGISTRY
    )
    for n in range(3):
        request = mail(n)
        plan = PlanBuilder(SCOPE).enqueue(
            sink=request.sink, operation=request.operation, payload=request.payload
        )
        assert engine.execute(plan.build()).committed
    with Relay(
        Version3Store(path),
        adapters={"mail": Scripted(DELIVERED)},
        breaker=NoBreaker(),
        relay_id="version-3",
        signer=relay_signer(),
    ) as old:
        (lease,) = old._claim(1)
        assert old._deliver(lease) == "delivered"
        return lease.message_id


def test_a_row_forged_into_an_old_log_is_not_legacy(tmp_path: Path) -> None:
    """The gap the legacy set closes: on messages version 3 enqueued, an
    unattested outcome dated before version 4, in a log version 4 never wrote
    to, or after a call it started, is not in the set version 4 recorded and
    an install vouched for. Version 3's own outcome is."""
    path = build_sqlite_back_office(tmp_path / "app.sqlite")
    delivered = _version_3_traffic(path)
    install_sqlite_outbox(path, RELAY_SINKS)
    owner = owned(path, tmp_path)
    try:
        vouched = vouch(owner.operator(), tmp_path / "operators.ilok1")
        assert vouched.rows == 1
        store = SqliteOutboxStore(path)
        try:
            (lease,) = store.claim("r", timedelta(seconds=10), 1, ["mail"], 0.0)
            assert store.sending(lease, "r", "breaker clear at test") == 1
        finally:
            store.close()
        messages = [m.message_id for m in reader(owner.operator()).snapshot(None)[0]]
        (untried,) = [m for m in messages if m not in (delivered, lease.message_id)]
        epoch = reader(owner.operator()).epoch("4")
        assert epoch is not None
        ghost(owner, untried, None, at=epoch - timedelta(days=30))
        owner.forge(
            lease.message_id,
            DELIVERED,
            authority=None,
            state_after=DELIVERED,
            actor="r",
            attempt=1,
            status_code=200,
            detail=None,
            at=epoch - timedelta(seconds=1),
        )
        report = verify_attestations(owner.operator(), RELAYS, legacy=vouched)
        assert len(report.problems) == 2
        for message in (untried, lease.message_id):
            assert any(
                f"{message}: row 2 (delivered) carries no relay attestation, and is not in "
                f"the legacy set" in p
                for p in report.problems
            )
        assert report.legacy == 1
    finally:
        owner.close()


def test_a_legacy_row_rewritten_after_the_upgrade_is_named(tmp_path: Path) -> None:
    """Version 3's delivered row, rewritten and its log relinked to match: the
    log verifies, but the legacy set names the row as it was, and the row as it
    is now is in no set."""
    path = build_sqlite_back_office(tmp_path / "app.sqlite")
    delivered = _version_3_traffic(path)
    install_sqlite_outbox(path, RELAY_SINKS)
    owner = owned(path, tmp_path)
    try:
        vouched = vouch(owner.operator(), tmp_path / "operators.ilok1")
        owner.rewrite_last(delivered, status_code=299)
        assert verify_delivery_log(owner.operator()) == ()
        report = verify_attestations(owner.operator(), RELAYS, legacy=vouched)
        assert len(report.problems) == 2
        assert any("is not in the legacy set" in p for p in report.problems)
        assert any(
            f"names row 2 of message {delivered}, which its log no longer holds" in p
            for p in report.problems
        )
    finally:
        owner.close()


def test_the_legacy_set_is_recorded_once(outbox: Outbox, tmp_path: Path) -> None:
    """A row forged after version 4 is installed is not swept into the legacy
    set by installing again."""
    vouched = vouch(outbox.operator(), tmp_path / "operators.ilok1")
    _, (message,) = outbox.commit(mail(1))
    ghost(outbox, message, None)
    outbox.reinstall(RELAY_SINKS)
    recorded = reader(outbox.operator()).legacy()
    assert recorded is not None and len(recorded) == 0
    report = verify_attestations(outbox.operator(), RELAYS, legacy=vouched)
    (found,) = report.problems
    assert "is not in the legacy set" in found


def test_the_legacy_set_takes_no_row_after_version_4(outbox: Outbox) -> None:
    """Sealed: the owner's plain insert is refused."""
    _, (message,) = outbox.commit(mail(1))
    ghost(outbox, message, None)
    (last,) = outbox.log(message)[-1:]
    if isinstance(outbox, PostgresOutbox):
        import psycopg

        with pytest.raises(psycopg.Error, match="recorded when version 4 was installed"):
            outbox.operator().execute(
                "INSERT INTO interlock.outbox_legacy VALUES (%s, %s, %s)",
                (message, last.seq, last.event_hash),
            )
    else:
        assert isinstance(outbox, SqliteOutbox)
        with closing(outbox.raw()) as conn, pytest.raises(sqlite3.Error, match="version 4"):
            conn.execute(
                "INSERT INTO _interlock_outbox_legacy VALUES (?, ?, ?)",
                (str(message), last.seq, last.event_hash),
            )


def _admit_to_legacy(outbox: Outbox, message: uuid.UUID) -> None:
    """The owner writes a row into the legacy set itself, around its seal."""
    (last,) = outbox.log(message)[-1:]
    if isinstance(outbox, PostgresOutbox):
        conn = outbox.operator()
        conn.execute("ALTER TABLE interlock.outbox_legacy DISABLE TRIGGER legacy_sealed")
        conn.execute(
            "INSERT INTO interlock.outbox_legacy (message_id, seq, event_hash) VALUES (%s, %s, %s)",
            (message, last.seq, last.event_hash),
        )
    else:
        assert isinstance(outbox, SqliteOutbox)
        with closing(outbox.raw()) as conn:
            conn.execute("DROP TRIGGER _interlock_legacy_sealed")
            conn.execute(
                "INSERT INTO _interlock_outbox_legacy (message_id, seq, event_hash) "
                "VALUES (?, ?, ?)",
                (str(message), last.seq, last.event_hash),
            )


def test_a_legacy_set_edited_after_its_vouch_is_named_and_never_vouched_again(
    outbox: Outbox, tmp_path: Path
) -> None:
    log = tmp_path / "operators.ilok1"
    vouched = vouch(outbox.operator(), log)
    _, (message,) = outbox.commit(mail(1))
    ghost(outbox, message, None)
    _admit_to_legacy(outbox, message)
    report = verify_attestations(outbox.operator(), RELAYS, legacy=vouched)
    (found,) = report.problems
    assert found == (
        f"the legacy set (1 row(s)) is not the one operator record {vouched.record} vouched "
        f"for (0 row(s)): it was edited around Interlock"
    )
    assert report.legacy == 0
    with pytest.raises(OperatorRefusedError, match="is not the one operator record 1"):
        vouch(outbox.operator(), log)


def test_an_install_vouches_only_for_the_set_its_transaction_read(
    outbox: Outbox, tmp_path: Path
) -> None:
    from interlock.deliveries import LegacySet, operations
    from interlock.operators import Operator, OperatorLog

    other = LegacySet({(uuid.uuid4(), 2): "0" * 64})
    with OperatorLog(tmp_path / "operators.ilok1", INSTALLER, INSTALLERS) as log:
        operator = Operator(log, operations(outbox.operator()))
        with pytest.raises(OperatorRefusedError, match="changed between the install"):
            operator.installed(other)
        assert log.records() == ()


def test_an_install_record_vouching_for_another_legacy_set_is_named(
    outbox: Outbox, tmp_path: Path
) -> None:
    """The first install that vouches for the legacy set pins it: a later
    record vouching for another, however it came to be signed, is named."""
    from interlock.deliveries import registry_digest
    from interlock.operators import INSTALLED, OperatorLog, verify_operators
    from interlock.records import read_records

    log = tmp_path / "operators.ilok1"
    vouch(outbox.operator(), log)
    with OperatorLog(log, INSTALLER, INSTALLERS) as signed:
        signed.append(
            INSTALLED,
            {
                "registry": registry_digest(reader(outbox.operator()).registry()),
                "sinks": {},
                "legacy": {"rows": 7, "digest": "0" * 64},
            },
        )
    report = verify_operators(outbox.operator(), read_records(log), INSTALLERS)
    assert report.problems == (
        "operator record 2 vouches for another legacy set than record 1 did: the set "
        "changed after it was first vouched for",
    )


def test_install_signs_the_legacy_set_and_verify_holds_the_database_to_it(
    tmp_path: Path, sink: FakeSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    from interlock.operators import generate_key

    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    key = generate_key(tmp_path / "ops.key")
    path = tmp_path / "interlock.toml"
    path.write_text(
        CONFIG.format(database=database, url=sink.url)
        + relays_section(tmp_path)
        + f'\n[operators]\nlog = "operators.ilok1"\n'
        f'[operators.keys]\nops = "{key.public_key().spec()}"\n'
    )
    monkeypatch.setenv("INTERLOCK_OPERATOR_KEY", str(tmp_path / "ops.key"))
    code, out = cli("install", "--config", str(path))
    assert code == 0
    assert "signed by ops: the sink registry and the legacy set (0 row(s)" in out
    code, out = cli("outbox", "verify", "--config", str(path))
    assert code == 0 and "every outcome is attested by a registered relay (0)" in out

    # The owner writes a row of their own into the set, and a delivery to go with it.
    _commit(database, 1)
    owner = owned(database, tmp_path)
    try:
        (message,) = [m.message_id for m in reader(owner.operator()).snapshot(None)[0]]
        ghost(owner, message, None)
        _admit_to_legacy(owner, message)
    finally:
        owner.close()
    code, out = cli("outbox", "verify", "--config", str(path))
    assert code == 1
    assert "the legacy set (1 row(s)) is not the one operator record 1 vouched for" in out
    assert out.count("is not the one operator record 1 vouched for") == 1
    # And no install will vouch for it now.
    code, _ = cli("install", "--config", str(path))
    assert code == 1
