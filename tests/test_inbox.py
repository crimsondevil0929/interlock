"""The inbox on both stores (``docs/EPIC5_DESIGN.md`` §2): a vendor's webhook
verified, recorded in its source's hash-linked log, bound to the delivery
whose relay-attested reference it names, and attested as a fact; and nothing
recorded for a webhook that does not verify.

- Every forged webhook is answered and records nothing.
- A vendor's retry records nothing twice.
- An event that arrives before its delivery is recorded is bound once it is.
- An event naming what two messages' deliveries created is bound to neither,
  and one naming a delivery no registered relay attested is bound to nothing.
- Verification finds what the database's owner could do around Interlock: an
  event rewritten or deleted, an event or a fact appended with a chain that
  links but an attestation no registered inbox made.
- The database itself refuses what is not the inbox's to write.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from interlock.exceptions import InterlockError
from interlock.inbox import InboxReport, Response, verify_fact, verify_inbox
from interlock.records import Keyring
from tests.inbox_env import (
    INBOX_KEYS,
    OTHER_SENDGRID_KEY,
    SECRETS,
    InboxSite,
    append_event,
    delete_event,
    inbox_signer,
    inbox_site,
    insert_fact,
    refund,
    refund_event,
    rewrite_event,
    sendgrid_webhook,
    standard_webhook,
    stripe_webhook,
)
from tests.outbox_env import BACKENDS, RELAYS, Outbox, PostgresOutbox, build_either

psycopg = pytest.importorskip("psycopg")

from agentgov.receipts.signing import Ed25519Signer  # noqa: E402

STRANGER = Ed25519Signer(bytes.fromhex("9f" * 32))
"""A key no ``[inbox.keys]`` registers."""


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Any) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _report(site: InboxSite) -> InboxReport:
    return verify_inbox(site.reader(), INBOX_KEYS, relays=RELAYS)


# -- received, recorded, bound, attested --------------------------------------


def test_a_signed_webhook_naming_a_delivery_becomes_an_attested_fact(site: InboxSite) -> None:
    (message,) = site.deliver("re_1")
    inbox = site.inbox()
    answer = site.receive(inbox, "stripe", stripe_webhook(refund_event("re_1")))
    assert answer == Response(200, {"recorded": 1, "matched": 1})

    (fact,) = site.reader().inbound_facts()
    delivered = site.outbox.log(message)[-1]
    assert (fact.message_id, fact.delivery_seq, fact.delivery_hash, fact.remote_ref) == (
        message,
        delivered.seq,
        delivered.event_hash,
        "re_1",
    )
    assert (fact.scope_id, fact.kind, fact.source, fact.event_seq) == (
        "agent",
        "charge.refund.updated",
        "stripe",
        1,
    )
    assert dict(fact.fields) == {
        "object": "refund",
        "id": "re_1",
        "status": "succeeded",
        "amount": 2500,
        "currency": "usd",
        "charge": "ch_1",
        "payment_intent": "pi_1",
        "livemode": False,
    }
    assert verify_fact(fact, INBOX_KEYS) is None
    assert verify_fact(fact, Keyring({"other": STRANGER.public_key()})) is not None
    assert _report(site) == InboxReport((), 1, 1, 0)


def test_each_vendor_scheme_is_received_and_bound(site: InboxSite) -> None:
    site.deliver("r_9", "sgmsg1")
    inbox = site.inbox()
    hooks = standard_webhook(
        {
            "type": "refund.failed",
            "data": {"id": "r_9", "status": "failed", "amount": "25.00", "note": "Pay me now"},
        },
        webhook_id="msg_77",
    )
    assert site.receive(inbox, "hooks", hooks) == Response(200, {"recorded": 1, "matched": 1})
    batch = sendgrid_webhook(
        [
            {"sg_event_id": "sge_1", "event": "delivered", "sg_message_id": "sgmsg1.filter0"},
            {"sg_event_id": "sge_2", "event": "open", "sg_message_id": "sgmsg1.filter0"},
        ]
    )
    assert site.receive(inbox, "sendgrid", batch) == Response(200, {"recorded": 2, "matched": 2})
    facts = {(f.source, f.event_id): f for f in site.reader().inbound_facts()}
    assert set(facts) == {("hooks", "msg_77"), ("sendgrid", "sge_1"), ("sendgrid", "sge_2")}
    failed = facts["hooks", "msg_77"]
    assert dict(failed.fields) == {"status": "failed", "amount": "25.00"}
    assert failed.withheld == ("note",)
    assert [facts["sendgrid", e].part for e in ("sge_1", "sge_2")] == [0, 1]
    assert _report(site) == InboxReport((), 3, 3, 0)


# -- the forgery matrix, at the receiver ------------------------------------------


def _event() -> dict[str, Any]:
    return refund_event("re_1")


def _swap(webhook: tuple[dict[str, str], bytes], body: bytes) -> tuple[dict[str, str], bytes]:
    return webhook[0], body


FORGED: list[tuple[str, str, Callable[[], tuple[dict[str, str], bytes]], int]] = [
    ("stripe", "another secret", lambda: stripe_webhook(_event(), secret="whsec_x"), 401),
    (
        "stripe",
        "the body changed",
        lambda: _swap(stripe_webhook(_event()), json.dumps(refund_event("re_2")).encode()),
        401,
    ),
    (
        "stripe",
        "replayed after the tolerance",
        lambda: stripe_webhook(_event(), at=datetime.now(UTC) - timedelta(minutes=6)),
        401,
    ),
    (
        "stripe",
        "signed for the future",
        lambda: stripe_webhook(_event(), at=datetime.now(UTC) + timedelta(minutes=6)),
        401,
    ),
    (
        "stripe",
        "no signature",
        lambda: ({"Content-Type": "application/json"}, json.dumps(_event()).encode()),
        400,
    ),
    ("hooks", "another key", lambda: standard_webhook({"type": "x"}, key=b"k" * 32), 401),
    (
        "hooks",
        "the id changed",
        lambda: (
            {**standard_webhook({"type": "x", "data": {"id": "r"}})[0], "webhook-id": "msg_2"},
            standard_webhook({"type": "x", "data": {"id": "r"}})[1],
        ),
        401,
    ),
    (
        "sendgrid",
        "another account",
        lambda: sendgrid_webhook(
            [{"sg_event_id": "a", "event": "delivered"}], key=OTHER_SENDGRID_KEY
        ),
        401,
    ),
    (
        "stripe",
        "a valid signature over a body that is not JSON",
        lambda: stripe_webhook({}, body=b"{not json"),
        400,
    ),
    (
        "stripe",
        "a valid signature over an event without an id",
        lambda: stripe_webhook({"type": "charge.refunded"}),
        400,
    ),
    ("sendgrid", "a valid signature over no batch", lambda: sendgrid_webhook([], body=b"{}"), 400),
    ("paypal", "an unknown source", lambda: stripe_webhook(_event()), 404),
    (
        "stripe",
        "not JSON",
        lambda: (
            {**stripe_webhook(_event())[0], "Content-Type": "text/plain"},
            stripe_webhook(_event())[1],
        ),
        415,
    ),
    (
        "stripe",
        "too large",
        lambda: stripe_webhook({}, body=b"[" + b" " * (256 * 1024) + b"]"),
        413,
    ),
]


@pytest.mark.parametrize(
    ("source", "forged", "status"),
    [(s, f, c) for s, _, f, c in FORGED],
    ids=[f"{s}: {name}" for s, name, _, _ in FORGED],
)
def test_a_webhook_that_does_not_verify_is_answered_and_records_nothing(
    site: InboxSite,
    source: str,
    forged: Callable[[], tuple[dict[str, str], bytes]],
    status: int,
) -> None:
    site.deliver("re_1")
    inbox = site.inbox()
    answer = site.receive(inbox, source, forged())
    assert answer.status == status
    assert "error" in answer.body
    assert (site.events(), site.facts()) == (0, 0)


def test_a_source_whose_secret_is_not_in_the_environment_records_nothing(
    site: InboxSite,
) -> None:
    inbox = site.inbox(secrets=lambda name: None)
    answer = site.receive(inbox, "stripe", stripe_webhook(_event()))
    assert answer.status == 503
    assert site.events() == 0
    # SendGrid's key is public, in the configuration: no secret to miss.
    batch = sendgrid_webhook([{"sg_event_id": "a", "event": "delivered"}])
    assert site.receive(inbox, "sendgrid", batch).status == 200


# -- retries, order, ambiguity ----------------------------------------------------


def test_a_vendors_retry_records_nothing_twice(site: InboxSite) -> None:
    site.deliver("re_1")
    inbox = site.inbox()
    webhook = stripe_webhook(_event())
    assert site.receive(inbox, "stripe", webhook) == Response(200, {"recorded": 1, "matched": 1})
    # Signed again, later: the same event id.
    again = stripe_webhook(_event(), at=datetime.now(UTC) + timedelta(seconds=30))
    assert site.receive(inbox, "stripe", again) == Response(200, {"recorded": 0, "matched": 1})
    assert site.receive(inbox, "stripe", webhook).body["recorded"] == 0
    assert (site.events(), site.facts()) == (1, 1)
    # Another event about the same refund is another fact.
    later = stripe_webhook(refund_event("re_1", event_id="evt_2", status="failed"))
    assert site.receive(inbox, "stripe", later).body == {"recorded": 1, "matched": 1}
    assert (site.events(), site.facts()) == (2, 2)
    assert _report(site) == InboxReport((), 2, 2, 0)


def test_an_event_before_its_delivery_is_bound_once_the_delivery_is_recorded(
    site: InboxSite,
) -> None:
    inbox = site.inbox()
    answer = site.receive(inbox, "stripe", stripe_webhook(_event()))
    assert answer == Response(200, {"recorded": 1, "matched": 0})
    assert inbox.match_pending() == 0
    (message,) = site.deliver("re_1")
    assert inbox.match_pending() == 1
    assert inbox.match_pending() == 0
    (fact,) = site.reader().inbound_facts()
    assert fact.message_id == message
    assert _report(site) == InboxReport((), 1, 1, 0)


def test_an_unmatched_event_is_tried_only_within_the_match_window(site: InboxSite) -> None:
    received = datetime.now(UTC)
    assert site.receive(site.inbox(), "stripe", stripe_webhook(_event())).body["matched"] == 0
    site.deliver("re_1")
    late = site.inbox(
        match_window=timedelta(minutes=1), clock=lambda: received + timedelta(minutes=2)
    )
    assert late.match_pending() == 0
    assert site.inbox(match_window=timedelta(minutes=5)).match_pending() == 1


def test_an_event_naming_two_messages_deliveries_is_bound_to_neither(site: InboxSite) -> None:
    site.deliver("re_dup", "re_dup")
    inbox = site.inbox()
    assert site.receive(inbox, "stripe", stripe_webhook(refund_event("re_dup"))).body == {
        "recorded": 1,
        "matched": 0,
    }
    assert inbox.match_pending() == 0
    assert site.facts() == 0


def test_a_later_reference_is_tried_when_the_first_names_nothing(site: InboxSite) -> None:
    (message,) = site.deliver("pi_1")
    inbox = site.inbox()
    # The refund's own id was never delivered; its payment intent was.
    answer = site.receive(inbox, "stripe", stripe_webhook(refund_event("re_unknown")))
    assert answer.body == {"recorded": 1, "matched": 1}
    (fact,) = site.reader().inbound_facts()
    assert (fact.message_id, fact.remote_ref) == (message, "pi_1")


def test_a_delivery_no_registered_relay_attested_binds_nothing(site: InboxSite) -> None:
    _, (message,) = site.outbox.commit(refund("re_ghost"))
    # The owner writes the delivery a relay never made: linked and hashed as
    # Interlock would, but signed by no registered relay.
    site.outbox.forge(message, "sending", authority=None, state_after="leased", attempt=1)
    site.outbox.forge(
        message,
        "delivered",
        authority=None,
        state_after="delivered",
        attempt=1,
        status_code=200,
        remote_ref="re_ghost",
        attestation=json.dumps(
            {"alg": "ed25519", "key_id": "0" * 16, "signature": "0" * 128},
            separators=(",", ":"),
        ),
    )
    inbox = site.inbox()
    assert site.receive(inbox, "stripe", stripe_webhook(refund_event("re_ghost"))).body == {
        "recorded": 1,
        "matched": 0,
    }
    assert site.facts() == 0


def test_a_delivery_whose_key_names_another_plan_binds_nothing(site: InboxSite) -> None:
    (message,) = site.deliver("re_1")
    site.outbox.tamper(message, plan_id="plan-of-another")
    inbox = site.inbox()
    assert site.receive(inbox, "stripe", stripe_webhook(_event())).body["matched"] == 0


# -- what verification finds ------------------------------------------------------


def _three_events(site: InboxSite) -> None:
    site.deliver("re_1")
    inbox = site.inbox()
    for n in (1, 2, 3):
        webhook = stripe_webhook(refund_event("re_1", event_id=f"evt_{n}"))
        assert site.receive(inbox, "stripe", webhook).status == 200
    assert _report(site) == InboxReport((), 3, 3, 0)


def test_verification_finds_an_event_rewritten_in_place(site: InboxSite) -> None:
    _three_events(site)
    rewrite_event(site, "stripe", 2, fields='{"status":"failed"}')
    problems = _report(site).problems
    assert any("event 2 does not hash to what it records" in p for p in problems)


def test_verification_finds_an_event_deleted_from_the_middle(site: InboxSite) -> None:
    _three_events(site)
    facts = {f.event_seq: f for f in site.reader().inbound_facts()}
    del facts  # the fact naming event 2 stays: its event is gone
    delete_event(site, "stripe", 2)
    problems = _report(site).problems
    assert any("event 3 does not link to the event before it" in p for p in problems)
    assert any("names an event its source's log does not hold as named" in p for p in problems)


def test_verification_finds_a_linked_event_no_registered_inbox_attested(site: InboxSite) -> None:
    _three_events(site)
    seq = append_event(site, "stripe", signer=STRANGER, event_id="evt_ghost", refs=("re_1",))
    problems = _report(site).problems
    assert problems == (
        f"inbound source stripe: event {seq}: it is attested by key {STRANGER.key_id}, no "
        f"registered inbox's",
    )
    # The inbox's own key, over what the owner wrote, verifies: what a stolen
    # inbox key could do, and why it is the inbox's alone.
    other = append_event(site, "stripe", signer=inbox_signer(), event_id="evt_inside")
    assert len(_report(site).problems) == 1
    assert other == seq + 1


def test_a_fact_written_around_the_inbox_is_found_and_never_consumed(site: InboxSite) -> None:
    _three_events(site)
    (genuine, *_) = site.reader().inbound_facts()
    seq = append_event(site, "stripe", signer=inbox_signer(), event_id="evt_4", refs=("re_1",))
    event = next(e for e in site.reader().inbound_events() if e.seq == seq)
    # A fact the owner wrote for the event, signed with a key of their own...
    forged = dataclasses.replace(
        genuine,
        fact_id=uuid.uuid4(),
        event_seq=seq,
        event_hash=event.event_hash,
        attestation=json.dumps(
            {"alg": "ed25519", "key_id": STRANGER.key_id, "signature": "ab" * 64},
            separators=(",", ":"),
        ),
    )
    insert_fact(site, forged)
    problems = _report(site).problems
    assert any(
        f"fact {forged.fact_id}: its binding: it is attested by key {STRANGER.key_id}" in p
        for p in problems
    )
    # ...is left out of what an engine is offered.
    engine = site.outbox.engine(inbox=INBOX_KEYS)
    assert forged.fact_id not in {f.fact_id for f in engine.facts("agent")}
    assert genuine.fact_id in {f.fact_id for f in engine.facts("agent")}


def test_a_fact_cannot_carry_another_events_attested_content(site: InboxSite) -> None:
    site.deliver("re_1", "re_2")
    inbox = site.inbox()
    site.receive(inbox, "stripe", stripe_webhook(refund_event("re_1", event_id="evt_1")))
    site.receive(
        inbox, "stripe", stripe_webhook(refund_event("re_2", event_id="evt_2", status="failed"))
    )
    one, two = sorted(site.reader().inbound_facts(), key=lambda f: f.event_seq)
    # Fact 1's binding, carrying event 2's content: every attestation genuine,
    # what the owner could serve by rewriting event 1's row as event 2's.
    swapped = dataclasses.replace(
        one,
        event_id=two.event_id,
        kind=two.kind,
        vendor_at=two.vendor_at,
        received_at=two.received_at,
        body_hash=two.body_hash,
        part=two.part,
        refs=two.refs,
        fields=two.fields,
        withheld=two.withheld,
        event_attestation=two.event_attestation,
    )
    found = verify_fact(swapped, INBOX_KEYS)
    assert found is not None and found.startswith("its binding: ")
    # And event 2's binding moved onto event 1: the statement names the event.
    moved = dataclasses.replace(
        two, event_seq=one.event_seq, event_hash=one.event_hash, attestation=two.attestation
    )
    assert verify_fact(moved, INBOX_KEYS) is not None


def test_the_engine_is_offered_only_its_scopes_attested_facts(site: InboxSite) -> None:
    site.deliver("re_1")
    site.deliver("re_2", scope="other")
    inbox = site.inbox()
    site.receive(inbox, "stripe", stripe_webhook(refund_event("re_1", event_id="evt_1")))
    site.receive(inbox, "stripe", stripe_webhook(refund_event("re_2", event_id="evt_2")))
    engine = site.outbox.engine(inbox=INBOX_KEYS)
    (mine,) = engine.facts("agent")
    (theirs,) = engine.facts("other")
    assert (mine.remote_ref, theirs.remote_ref) == ("re_1", "re_2")
    assert engine.facts("nobody") == ()
    stranger = site.outbox.engine(inbox=Keyring({"x": STRANGER.public_key()}))
    assert stranger.facts("agent") == ()


# -- what the database refuses ------------------------------------------------------


def test_the_logs_and_facts_are_append_only(site: InboxSite) -> None:
    site.deliver("re_1")
    site.receive(site.inbox(), "stripe", stripe_webhook(_event()))
    tables = (
        ("interlock.inbox_events", "_interlock_inbox_events"),
        ("interlock.inbox_facts", "_interlock_inbox_facts"),
    )
    for postgres, sqlite in tables:
        table = postgres if site.outbox.backend == "postgres" else sqlite
        for statement in (f"UPDATE {table} SET source = source", f"DELETE FROM {table}"):
            with pytest.raises(Exception, match="append-only"):
                site.outbox.fetch(statement)
    assert (site.events(), site.facts()) == (1, 1)


def test_an_event_that_does_not_extend_its_log_is_refused(site: InboxSite) -> None:
    store = site.store()
    statement_attestation = json.dumps(
        {"alg": "ed25519", "key_id": "0" * 16, "signature": "0" * 128}, separators=(",", ":")
    )
    good = {
        "source": "stripe",
        "event_id": "evt_1",
        "kind": "charge.refunded",
        "vendor_at": None,
        "received_at": datetime.now(UTC),
        "body": "{}",
        "body_hash": __import__("hashlib").sha256(b"{}").hexdigest(),
        "signature": "{}",
        "part": 0,
        "refs": [],
        "fields": {},
        "withheld": [],
        "attestation": statement_attestation,
    }
    with pytest.raises((InterlockError, psycopg.Error), match="body does not match"):
        store.record_event(**{**good, "body_hash": "0" * 64})
    with pytest.raises((InterlockError, psycopg.Error), match="inbound source"):
        store.record_event(**{**good, "source": "paypal"})
    with pytest.raises(Exception, match=r"attestation|extend its source"):
        store.record_event(**{**good, "attestation": "unsigned"})
    assert store.record_event(**good) == (1, True)
    assert store.record_event(**good) == (1, False)
    assert site.events() == 1


def test_a_fact_binding_nothing_delivered_is_refused(site: InboxSite) -> None:
    (message,) = site.deliver("re_1")
    site.receive(site.inbox(), "stripe", stripe_webhook(_event()))
    (fact,) = site.reader().inbound_facts()
    store = site.store()
    for wrong in (
        {"remote_ref": "re_other"},
        {"scope_id": "other"},
        {"plan_id": "another-plan"},
        {"delivery_seq": 1},
        {"delivery_hash": "0" * 64},
        {"event_hash": "0" * 64},
        {"message_id": uuid.uuid4()},
    ):
        with pytest.raises((InterlockError, psycopg.Error)):
            store.record_fact(dataclasses.replace(fact, fact_id=uuid.uuid4(), **wrong))
    with pytest.raises(Exception, match="attestation"):
        store.record_fact(dataclasses.replace(fact, fact_id=uuid.uuid4(), attestation="x"))
    # The binding as made, again: one fact per event.
    assert store.record_fact(dataclasses.replace(fact, fact_id=uuid.uuid4())) is False
    assert site.facts() == 1
    assert message == fact.message_id


def test_the_inbox_role_writes_only_through_its_functions(site: InboxSite) -> None:
    if site.outbox.backend != "postgres":
        # SQLite's inbox store may write the inbox's tables, and only those.
        store = site.store()
        with pytest.raises(Exception, match="not authorized"):
            store._conn.execute("DELETE FROM _interlock_outbox_attempts")
        with pytest.raises(Exception, match="not authorized"):
            store._conn.execute("INSERT INTO _interlock_inbox_consumed VALUES ('a', 'b', 0)")
        return
    with psycopg.connect(site.target["dsn"], autocommit=True) as conn:
        for statement in (
            "INSERT INTO interlock.inbox_sources VALUES ('x', 'http', '', true, 0, '')",
            "UPDATE interlock.inbox_sources SET log_seq = 0",
            "DELETE FROM interlock.inbox_facts",
            "INSERT INTO interlock.inbox_consumed VALUES (gen_random_uuid(), gen_random_uuid())",
            "UPDATE interlock.outbox_attempts SET remote_ref = 're_1'",
            "SELECT interlock.inbox_consume('\\x00'::bytea, ARRAY[]::uuid[], 'agent')",
            "SELECT * FROM interlock.inbox_pending('agent')",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)


def test_no_stage_role_reads_the_inbox(site: InboxSite) -> None:
    site.deliver("re_1")
    site.receive(site.inbox(), "stripe", stripe_webhook(_event()))
    if not isinstance(site.outbox, PostgresOutbox):
        return  # the authorizer's refusal is tested with the engine
    with psycopg.connect(site.outbox.pg.agent, autocommit=True) as conn:
        for table in ("inbox_sources", "inbox_events", "inbox_facts", "inbox_consumed"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(f"SELECT * FROM interlock.{table}")
        # Outside a stage, its scope's facts, typed: the 22 columns of a fact
        # and its event, and no body.
        (row,) = conn.execute("SELECT * FROM interlock.inbox_pending('agent')").fetchall()
        assert len(row) == 22
        assert conn.execute("SELECT * FROM interlock.inbox_pending('other')").fetchall() == []
        # No stage of its own in this transaction: nothing consumed to read.
        assert conn.execute("SELECT * FROM interlock.stage_facts(10)").fetchall() == []


def test_the_tests_sources_are_the_inbox_environment(site: InboxSite) -> None:
    assert set(SECRETS) == {"STRIPE_WEBHOOK_SECRET", "HOOKS_SECRET"}
    assert site.target["store"] in BACKENDS


def _rewrite_fact(site: InboxSite, fact_id: uuid.UUID, **columns: object) -> None:
    """Rewrite a fact's columns in place, as the database's owner could."""
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("ALTER TABLE interlock.inbox_facts DISABLE TRIGGER inbox_facts_append_only")
        conn.execute(
            f"UPDATE interlock.inbox_facts SET "
            f"{', '.join(f'{name} = %({name})s' for name in columns)} WHERE fact_id = %(fact)s",
            {**columns, "fact": fact_id},
        )
        conn.execute(
            "ALTER TABLE interlock.inbox_facts ENABLE ALWAYS TRIGGER inbox_facts_append_only"
        )
        return
    conn = site.outbox.raw()  # type: ignore[attr-defined]
    try:
        conn.execute("DROP TRIGGER IF EXISTS _interlock_inbox_facts_no_update")
        conn.execute(
            f"UPDATE _interlock_inbox_facts SET "
            f"{', '.join(f'{name} = :{name}' for name in columns)} WHERE fact_id = :fact",
            {**columns, "fact": str(fact_id)},
        )
    finally:
        conn.close()


def test_a_fact_moved_to_another_scope_is_named_and_offered_to_neither(site: InboxSite) -> None:
    site.deliver("re_1")
    site.receive(site.inbox(), "stripe", stripe_webhook(_event()))
    (fact,) = site.reader().inbound_facts()
    _rewrite_fact(site, fact.fact_id, scope_id="other")
    engine = site.outbox.engine(inbox=INBOX_KEYS)
    assert engine.facts("agent") == ()
    assert engine.facts("other") == ()
    problems = _report(site).problems
    assert f"fact {fact.fact_id}'s scope or plan is not its message's" in problems
    assert any(p.startswith(f"fact {fact.fact_id}: its binding: ") for p in problems)


def test_a_genuine_attestation_copied_onto_another_fact_is_refused(site: InboxSite) -> None:
    site.deliver("re_1", "re_2")
    inbox = site.inbox()
    site.receive(inbox, "stripe", stripe_webhook(refund_event("re_1", event_id="evt_1")))
    site.receive(inbox, "stripe", stripe_webhook(refund_event("re_2", event_id="evt_2")))
    one, two = sorted(site.reader().inbound_facts(), key=lambda f: f.event_seq)
    # The owner gives fact 2 fact 1's attestation: genuine, and another's.
    _rewrite_fact(site, two.fact_id, attestation=one.attestation)
    engine = site.outbox.engine(inbox=INBOX_KEYS)
    assert [f.fact_id for f in engine.facts("agent")] == [one.fact_id]
    problems = _report(site).problems
    assert any(p.startswith(f"fact {two.fact_id}: its binding: ") for p in problems)


def test_sqlites_log_trigger_refuses_an_event_that_does_not_hash(site: InboxSite) -> None:
    import sqlite3

    from interlock.compaction import instant_text
    from interlock.inbox import event_hash

    if site.outbox.backend != "sqlite":
        return  # PostgreSQL's trigger computes the link and the hash itself
    store = site.store()
    seq, prev = 1, site.reader().inbound_heads()["stripe"][1]
    now = datetime.now(UTC)
    attestation = json.dumps(
        {"alg": "ed25519", "key_id": "0" * 16, "signature": "0" * 128}, separators=(",", ":")
    )
    row = {
        "source": "stripe",
        "seq": seq,
        "event_id": "evt_raw",
        "event_type": "charge.refunded",
        "received_at": instant_text(now),
        "body": "{}",
        "body_hash": "0" * 64,
        "signature": "{}",
        "part": 0,
        "refs": "[]",
        "fields": "{}",
        "withheld": "[]",
        "attestation": attestation,
        "prev_hash": prev,
        "event_hash": "0" * 64,
    }
    insert = (
        f"INSERT INTO _interlock_inbox_events ({', '.join(row)}) "
        f"VALUES ({', '.join(f':{c}' for c in row)})"
    )
    with pytest.raises(sqlite3.IntegrityError, match="must extend its source"):
        store._conn.execute(insert, row)
    for wrong in ({"seq": 2}, {"prev_hash": "1" * 64}):
        with pytest.raises(sqlite3.IntegrityError, match="must extend its source"):
            store._conn.execute(insert, {**row, **wrong})
    row["event_hash"] = event_hash(
        prev,
        "stripe",
        seq,
        "evt_raw",
        "charge.refunded",
        None,
        now,
        "0" * 64,
        0,
        [],
        {},
        [],
        attestation,
    )
    store._conn.execute(insert, row)
    assert site.reader().inbound_heads()["stripe"] == (1, row["event_hash"])
