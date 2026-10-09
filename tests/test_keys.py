"""Keys: registration, revocation and its seal (``docs/EPIC8_DESIGN.md`` §2), on both stores.

- A revocation seals exactly the rows its key attested; the database's digest
  is the one Python computes, and the one the operator signs.
- A revoked key attests nothing new: a relay holding it stops before it
  claims, and the database refuses what it would write, whatever asked first.
- History verifies after: every sealed row, by every verifier.
- A row written around the refusal is named; so is a seal edited, a
  revocation deleted, or one no operator signed.
- An inbox's key, likewise: its events and facts sealed, its new ones refused.
- An operator's key is revoked in the log: what it signs after does not hold.
- A revocation killed between its phases is resolved from the database.
- On PostgreSQL, a write in flight when the revocation comes is sealed, not
  lost and not refused.
- Version 6 upgrades in place.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts.signing import Ed25519Signer

from interlock.attestations import verify_attestations
from interlock.deliveries import reader
from interlock.exceptions import KeyRevokedError, RecordIntegrityError
from interlock.inbox import verify_inbox
from interlock.keys import (
    KeyRegistry,
    attestation_key,
    event_ref,
    fact_ref,
    fact_row_hash,
    outcome_ref,
    revocations_of,
    seal_digest,
    verify_keys,
)
from interlock.operators import OperatorLog, OperatorRefusedError
from interlock.records import (
    RecordKind,
    RecordLog,
    SignedRecord,
    UntrustedSignerError,
    read_records,
)
from interlock.relay import DeliveryResult, attest
from interlock.sqlite_outbox import OPERATOR, VERSION, SqliteOutboxStore, install_sqlite_outbox
from interlock.sqlite_outbox import installed_version as sqlite_version
from tests.inbox_env import INBOX_KEYS, InboxSite, inbox_signer, inbox_site, stripe_webhook
from tests.inbox_env import refund_event as refund_webhook
from tests.outbox_env import (
    BACKENDS,
    RELAY_SINKS,
    RELAYS,
    Outbox,
    PostgresOutbox,
    SqliteOutbox,
    build_either,
    mail,
    relay_signer,
)

RELAY_ID = relay_signer().key_id
INBOX_ID = inbox_signer().key_id


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def roots(outbox: Outbox) -> dict[str, dict[str, str]]:
    """The configuration's keyrings, as the tests configure them."""
    outbox.operator_key("ops")
    return {
        "relay": {"relay": relay_signer().public_key().spec()},
        "inbox": {"inbox": inbox_signer().public_key().spec()},
        "operator": {name: key.public_key().spec() for name, key in outbox.keys.items()},
    }


def records(outbox: Outbox) -> tuple[SignedRecord, ...]:
    """The operator log's records, none before the first action."""
    return read_records(outbox.operator_log) if outbox.operator_log.exists() else ()


def registry(outbox: Outbox) -> KeyRegistry:
    return KeyRegistry.build(roots(outbox), records(outbox))


def outcomes_by(outbox: Outbox, key_id: str) -> set[tuple[str, str, str]]:
    """Every outcome row ``key_id`` attested, as a seal holds it."""
    _, events = reader(outbox.operator()).snapshot(None)
    return {
        ("outcome", outcome_ref(e.message_id, e.seq), e.event_hash)
        for e in events
        if attestation_key(e.attestation) == key_id
    }


def revoke(outbox: Outbox, role: str, key_id: str, **kwargs: Any) -> Any:
    with outbox.signed("ops", **kwargs) as operator:
        return operator.revoke_key(role, key_id, reason="rotated", roots=roots(outbox))


def deliver(outbox: Outbox, *requests: Any, signer: Ed25519Signer | None = None) -> None:
    outbox.commit(*requests)
    with outbox.relay(signer=signer or relay_signer()) as relay:
        outbox.drain(relay)


def problems(outbox: Outbox, relays: Any = None) -> tuple[str, ...]:
    keyring = relays if relays is not None else registry(outbox).keyring("relay")
    return (
        verify_attestations(outbox.operator(), keyring).problems
        + verify_keys(outbox.operator(), records(outbox), roots(outbox)).problems
    )


def forge(path: Path, signer: Ed25519Signer, kind: RecordKind, body: dict[str, Any]) -> None:
    """A record ``signer`` signs, linked to the log's last and appended to its
    file as anyone who can write the file appends one: past every check."""
    import dataclasses
    import json

    from agentgov.receipts import canonical_bytes

    last = read_records(path)[-1]
    unsigned = SignedRecord(
        log=last.log,
        seq=last.seq + 1,
        kind=kind.value,
        issued_at="2026-10-09T00:00:00.000000Z",
        scope=last.scope,
        body_json=canonical_bytes(body),
        prev=last.record_hash,
        alg=signer.alg,
        key_id=signer.key_id,
        signature=b"",
    )
    record = dataclasses.replace(unsigned, signature=signer.sign(unsigned.signing_input()))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record.to_json(), sort_keys=True, separators=(",", ":")) + "\n")


# --------------------------------------------------------------------------
# the seal
# --------------------------------------------------------------------------


def test_a_revocation_seals_exactly_what_the_key_attested(outbox: Outbox) -> None:
    deliver(outbox, mail(1), mail(2), mail(3))
    attested = outcomes_by(outbox, RELAY_ID)
    assert len(attested) == 3
    outcome = revoke(outbox, "relay", RELAY_ID)
    assert outcome.intent.body == {
        "action": "revoke-key",
        "role": "relay",
        "key_id": RELAY_ID,
        "reason": "rotated",
        "targets": [],
        "operator": "ops",
    }
    (revoked,) = revocations_of(outbox.operator()).values()
    # The database's seal, its digest, and the one the operator signed, agree.
    assert revoked.members == attested and revoked.count == 3
    assert revoked.digest == seal_digest(attested) == outcome.record.body["seal"]["digest"]
    assert revoked.authority == outcome.intent.record_hash
    # History verifies: every row the key attested is in its seal.
    assert problems(outbox) == ()
    report = verify_keys(outbox.operator(), records(outbox), roots(outbox))
    assert (report.revoked, report.registered) == (1, 0)
    with pytest.raises(OperatorRefusedError, match="revoked already"):
        revoke(outbox, "relay", RELAY_ID)


def test_a_revoked_key_attests_nothing_new(outbox: Outbox) -> None:
    deliver(outbox, mail(1))
    revoke(outbox, "relay", RELAY_ID)
    outbox.commit(mail(2))
    # A relay holding the key stops before it claims, and calls nothing.
    with outbox.relay() as relay, pytest.raises(KeyRevokedError):
        relay.run_once()
    assert len(outbox.sink("mail").calls) == 1  # mail(1)'s, before the revocation
    # Whatever asks first, the database refuses what the key attests.
    store = outbox.store()
    (lease,) = store.claim("rogue", timedelta(seconds=1), 1, ["mail"], time.monotonic() + 1)
    attempt = store.sending(lease, "rogue", "calling")
    assert attempt is not None
    result = DeliveryResult("delivered", status_code=200, response_digest="0" * 64)
    with pytest.raises(KeyRevokedError):
        store.outcome(
            lease,
            "rogue",
            attempt,
            result,
            timedelta(0),
            attest(lease, attempt, result, relay_signer()),
        )
    store.close()
    # A key an operator registered delivers it.
    rotated = Ed25519Signer.generate()
    with outbox.signed("ops") as operator:
        operator.register_key("relay", "relay-2", rotated.public_key(), roots=roots(outbox))
    time.sleep(1.1)  # the rogue's lease runs out
    with outbox.relay(signer=rotated) as relay:
        outbox.drain(relay)
    assert outcomes_by(outbox, rotated.key_id)
    assert problems(outbox) == ()


def test_a_row_written_around_the_refusal_is_named(
    outbox: Outbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    deliver(outbox, mail(1))
    revoke(outbox, "relay", RELAY_ID)
    # An owner of the database writes past the refusal: the key's row, after.
    if isinstance(outbox, PostgresOutbox):
        with outbox.admin() as conn:
            conn.execute(
                "CREATE OR REPLACE FUNCTION interlock.key_unrevoked(p_attestation text) "
                "RETURNS void LANGUAGE sql AS 'SELECT NULL'"
            )
    else:
        monkeypatch.setattr("interlock.sqlite_outbox.refuse_revoked", lambda conn, a: None)
    # ...through the store, past the relay's own check too.
    outbox.commit(mail(2))
    store = outbox.store()
    (lease,) = store.claim("forger", timedelta(seconds=10), 1, ["mail"], time.monotonic() + 10)
    attempt = store.sending(lease, "forger", "calling")
    assert attempt is not None
    result = DeliveryResult("delivered", status_code=200, response_digest="0" * 64)
    attestation = attest(lease, attempt, result, relay_signer())
    store.outcome(lease, "forger", attempt, result, timedelta(0), attestation)
    store.close()
    found = problems(outbox)
    assert len(found) == 1 and "its revocation did not seal it" in found[0], found


def _owner_sql(outbox: Outbox, *statements: str) -> None:
    """Statements as the database's owner, past its guards."""
    if isinstance(outbox, PostgresOutbox):
        with outbox.admin() as conn:
            for table in ("key_seals", "key_revocations"):
                conn.execute(f"ALTER TABLE interlock.{table} DISABLE TRIGGER USER")
            for statement in statements:
                conn.execute(statement.replace("{t}", "interlock.key_"))
        return
    assert isinstance(outbox, SqliteOutbox)
    with closing(sqlite3.connect(outbox.path)) as conn:
        for trigger in (
            "_interlock_seals_no_delete",
            "_interlock_seals_no_update",
            "_interlock_revocations_no_delete",
            "_interlock_revocations_no_update",
        ):
            conn.execute(f"DROP TRIGGER {trigger}")
        for statement in statements:
            conn.execute(statement.replace("{t}", "_interlock_key_"))
        conn.commit()


@pytest.mark.parametrize(
    ("statement", "named"),
    [
        ("DELETE FROM {t}seals WHERE ref LIKE '%:2'", "no longer hashes to its digest"),
        ("UPDATE {t}revocations SET seal_count = 9", "the operator signed 3"),
        ("DELETE FROM {t}revocations", "the database holds none: deleted around Interlock"),
    ],
)
def test_a_seal_edited_or_deleted_is_named(outbox: Outbox, statement: str, named: str) -> None:
    deliver(outbox, mail(1), mail(2), mail(3))
    revoke(outbox, "relay", RELAY_ID)
    assert problems(outbox) == ()
    _owner_sql(outbox, statement)
    found = verify_keys(outbox.operator(), records(outbox), roots(outbox))
    assert any(named in p for p in found.problems), found.problems


def test_a_revocation_no_operator_signed_is_named(outbox: Outbox) -> None:
    deliver(outbox, mail(1))
    authority = "ab" * 32
    if isinstance(outbox, PostgresOutbox):
        with outbox.admin() as conn:
            conn.execute(
                "SELECT * FROM interlock.key_revoke('relay', %s, %s)", (RELAY_ID, authority)
            )
    else:
        assert isinstance(outbox, SqliteOutbox)
        with closing(SqliteOutboxStore(outbox.path, writes=OPERATOR)) as store:
            store.revoke_key("relay", RELAY_ID, authority=authority)
    found = verify_keys(outbox.operator(), records(outbox), roots(outbox))
    assert any("no signed revoke-key intent holds" in p for p in found.problems), found.problems


# --------------------------------------------------------------------------
# an inbox's key
# --------------------------------------------------------------------------


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def test_an_inbox_key_revoked_seals_its_events_and_facts(site: InboxSite) -> None:
    outbox = site.outbox
    site.deliver("re_1", "re_2")
    inbox = site.inbox()
    for n, ref in enumerate(("re_1", "re_2")):
        assert site.receive(inbox, "stripe", stripe_webhook(refund_webhook(ref, event_id=f"e{n}")))
    revoke(outbox, "inbox", INBOX_ID)
    (revoked,) = revocations_of(site.reader()).values()
    kinds = sorted(kind for kind, _, _ in revoked.members)
    assert kinds == ["event", "event", "fact", "fact"]
    facts = site.reader().inbound_facts()
    assert {
        ("fact", fact_ref(f.source, f.event_seq), fact_row_hash(f.attestation)) for f in facts
    } | {
        ("event", event_ref(e.source, e.seq), e.event_hash) for e in site.reader().inbound_events()
    } == set(revoked.members)
    # Its history verifies; nothing new it attests is recorded.
    assert verify_inbox(site.reader(), INBOX_KEYS, relays=RELAYS).problems == ()
    answer = site.receive(inbox, "stripe", stripe_webhook(refund_webhook("re_1", event_id="e9")))
    assert answer.status >= 500 and site.events() == 2
    assert verify_keys(outbox.operator(), records(outbox), roots(outbox)).problems == ()


# --------------------------------------------------------------------------
# an operator's key
# --------------------------------------------------------------------------


def test_an_operator_key_is_registered_and_revoked_in_the_log(outbox: Outbox) -> None:
    keys = roots(outbox)
    newcomer = Ed25519Signer.generate()
    with outbox.signed("ops") as operator:
        operator.register_key("operator", "newcomer", newcomer.public_key(), roots=keys)
        with pytest.raises(OperatorRefusedError, match="their own key"):
            operator.revoke_key("operator", outbox.keys["ops"].key_id, roots=keys)
    # Registered by a record, the newcomer signs; and revokes the old key.
    with OperatorLog(outbox.operator_log, newcomer, outbox.keyring()) as log:
        assert log.operator == "newcomer"
        from interlock.operators import Operator

        Operator(log, outbox.operations()).revoke_key(
            "operator", outbox.keys["ops"].key_id, roots=keys
        )
    with pytest.raises(UntrustedSignerError, match="was revoked by record"):
        OperatorLog(outbox.operator_log, outbox.keys["ops"], outbox.keyring())
    # A record the old key signs after its revocation does not hold.
    forge(outbox.operator_log, outbox.keys["ops"], RecordKind.OPERATOR_INSTALLED, {"forged": 1})
    with pytest.raises(RecordIntegrityError, match=r"after record \d+ revoked it"):
        RecordLog.load(outbox.operator_log, outbox.keyring())
    assert any("revoked it" in p for p in outbox.verify_operators().problems)


def test_a_registration_by_no_trusted_operator_adds_nothing(outbox: Outbox) -> None:
    keys = roots(outbox)
    stranger = Ed25519Signer.generate()
    relay = Ed25519Signer.generate()
    with outbox.signed("ops") as operator:  # a log to append to
        operator.register_key("inbox", "spare", Ed25519Signer.generate().public_key(), roots=keys)
    forge(
        outbox.operator_log,
        stranger,
        RecordKind.KEY_REGISTERED,
        {"role": "relay", "name": "x", "key": relay.public_key().spec(), "key_id": relay.key_id},
    )
    built = KeyRegistry.build(keys, records(outbox))
    assert relay.key_id not in built.keyring("relay") and built.ignored


# --------------------------------------------------------------------------
# crashes, races, upgrades
# --------------------------------------------------------------------------


class KilledError(Exception):
    pass


@pytest.mark.parametrize(("point", "applied"), [("intent", False), ("acted", True)])
def test_a_revocation_killed_between_its_phases_is_resolved(
    outbox: Outbox, point: str, applied: bool
) -> None:
    deliver(outbox, mail(1))

    def stop(at: str) -> None:
        if at == point:
            raise KilledError(at)

    with pytest.raises(KilledError):
        revoke(outbox, "relay", RELAY_ID, checkpoint=stop)
    with outbox.signed("ops") as operator:
        (resolved,) = operator.resolve()
    assert resolved.kind == ("operator.applied" if applied else "operator.abandoned")
    assert (RELAY_ID in revocations_of(outbox.operator())) is applied
    if applied:
        assert resolved.body["seal"]["count"] == 1
    assert problems(outbox) == ()


def test_a_write_in_flight_when_the_revocation_comes_is_sealed(outbox: Outbox) -> None:
    if not isinstance(outbox, PostgresOutbox):
        pytest.skip("SQLite's write lock orders them: one writer at a time")
    import psycopg

    deliver(outbox, mail(1))
    outbox.commit(mail(2))
    store = outbox.store()
    (lease,) = store.claim("racer", timedelta(seconds=10), 1, ["mail"], time.monotonic() + 10)
    attempt = store.sending(lease, "racer", "calling")
    assert attempt is not None
    result = DeliveryResult("delivered", status_code=200, response_digest="0" * 64)
    attestation = attest(lease, attempt, result, relay_signer())
    with psycopg.connect(outbox.relay_target()["dsn"]) as writer:
        # The outcome, written and not committed: the keys lock held shared.
        writer.execute(
            "SELECT interlock.relay_outcome(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                lease.message_id,
                "racer",
                lease.fence,
                attempt,
                "delivered",
                200,
                "0" * 64,
                None,
                0,
                None,
                attestation,
            ),
        )
        revoked: list[Any] = []
        revoking = threading.Thread(
            target=lambda: revoked.append(revoke(outbox, "relay", RELAY_ID))
        )
        revoking.start()
        revoking.join(0.5)
        assert revoking.is_alive()  # it waits for the write in flight
        writer.commit()
    revoking.join(10)
    store.close()
    (sealed,) = revocations_of(outbox.operator()).values()
    assert sealed.count == 2 == len(outcomes_by(outbox, RELAY_ID))
    assert problems(outbox) == ()


def test_version_6_upgrades_in_place(outbox: Outbox) -> None:
    if isinstance(outbox, PostgresOutbox):
        from interlock.postgres import installed_version as pg_version

        with outbox.admin() as conn:
            conn.execute("DROP TABLE interlock.key_seals, interlock.key_revocations")
            assert pg_version(conn) == 6
        outbox.reinstall(RELAY_SINKS)
        with outbox.admin() as conn:
            assert pg_version(conn) == 7
    else:
        assert isinstance(outbox, SqliteOutbox)
        with closing(sqlite3.connect(outbox.path)) as conn:
            conn.execute("DROP TABLE _interlock_key_seals")
            conn.execute("DROP TABLE _interlock_key_revocations")
            conn.commit()
            assert sqlite_version(conn) == 6
        install_sqlite_outbox(outbox.path, RELAY_SINKS)
        with closing(sqlite3.connect(outbox.path)) as conn:
            assert sqlite_version(conn) == VERSION == 7
    deliver(outbox, mail(1))
    revoke(outbox, "relay", RELAY_ID)
    assert problems(outbox) == ()
