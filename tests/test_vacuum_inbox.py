"""The vacuum and the inbox (``docs/EPIC5_DESIGN.md`` §1.1 to §1.4, §2.3), on both
stores: each inbound source's longest prefix of events older than the
retention, each bound to nothing or by a fact some stage consumed, goes under
the checkpoint, which names where the log was cut and the hash there; the
rest of the log links to it, and goes on.

- A pending fact stops its source's prefix, and so does a recent event.
- Without ``[inbox.keys]`` the inbox stays; a source that does not verify is
  kept whole; a finding that is no one source's prunes nothing.
- The database refuses, on its own, a cut other than the one verified: a log
  that moved, a pending fact, facts other than the signed ones.
- A prefix deleted around Interlock, or a pruned event restored, is named.
- An archive proves the pruned prefix, bodies and facts included.
"""

from __future__ import annotations

import io
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from interlock import BlastRadius, PlanBuilder
from interlock.compaction import GENESIS, Checkpoint, InboxCut, inbox_root
from interlock.exceptions import CompactionRefusedError
from interlock.inbox import InboxReport, inbox_genesis, verify_inbox
from interlock.types import InboundFact
from interlock.vacuum import verify_archive
from tests.inbox_env import (
    INBOX_KEYS,
    InboxSite,
    delete_event,
    inbox_signer,
    inbox_site,
    refund_event,
    rewrite_event,
    standard_webhook,
    stripe_webhook,
)
from tests.outbox_env import BACKENDS, RELAYS, Outbox, PostgresOutbox, build_either
from tests.test_vacuum import _body

RETAIN = timedelta(hours=1)
THEN = datetime.now(UTC) - timedelta(hours=2)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _consume(site: InboxSite, fact: InboundFact) -> None:
    engine = site.outbox.engine(inbox=INBOX_KEYS, checkers=[BlastRadius(10)])
    plan = (
        PlanBuilder("agent")
        .consume(fact)
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'reacted' WHERE id = 500",
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )
    assert engine.execute(plan).committed


def _history(site: InboxSite) -> dict[str, InboundFact]:
    """Two hours ago: on ``stripe``, events 1 (consumed), 2 (bound to
    nothing), 3 (consumed), 4 (pending) and 5 (consumed); on ``hooks``, an
    event bound to nothing. Just now, on ``hooks``, another. The facts by
    event id."""
    site.deliver("re_1", "re_2", "re_3")
    old = site.inbox(clock=lambda: THEN)
    for n, ref in ((1, "re_1"), (2, "re_none"), (3, "re_2"), (4, "re_3"), (5, "re_1")):
        webhook = stripe_webhook(refund_event(ref, event_id=f"evt_{n}"), at=THEN)
        assert site.receive(old, "stripe", webhook).status == 200
    hooks = standard_webhook({"type": "x.y", "data": {"id": "r_x"}}, webhook_id="msg_1", at=THEN)
    assert site.receive(old, "hooks", hooks).status == 200
    recent = standard_webhook({"type": "x.y", "data": {"id": "r_y"}}, webhook_id="msg_2")
    assert site.receive(site.inbox(), "hooks", recent).status == 200
    facts = {f.event_id: f for f in site.reader().inbound_facts()}
    assert set(facts) == {"evt_1", "evt_3", "evt_4", "evt_5"}
    for event in ("evt_1", "evt_3", "evt_5"):
        _consume(site, facts[event])
    return facts


def _vacuum(site: InboxSite, **settings: Any) -> Any:
    settings.setdefault("retain", RETAIN)
    settings.setdefault("inbox", INBOX_KEYS)
    with site.outbox.vacuum(**settings) as vacuum:
        return vacuum.run(reason="the inbox's history")


def _report(site: InboxSite) -> InboxReport:
    return verify_inbox(site.reader(), INBOX_KEYS, relays=RELAYS)


def test_an_inbound_prefix_goes_under_the_checkpoint_and_the_log_goes_on(
    site: InboxSite,
) -> None:
    facts = _history(site)
    heads = {e.seq: e.event_hash for e in site.reader().inbound_events() if e.source == "stripe"}
    hooks_head = next(
        e.event_hash for e in site.reader().inbound_events() if e.source == "hooks" and e.seq == 1
    )
    report = _vacuum(site)
    assert (report.outcome, report.inbox_events, report.messages) == ("applied", 4, 0)
    cuts = report.checkpoint.inbox_cuts()
    assert cuts == (
        InboxCut("hooks", 0, inbox_genesis("hooks"), 1, hooks_head, 1, 0, 0),
        InboxCut("stripe", 0, inbox_genesis("stripe"), 3, heads[3], 3, 2, 2),
    )
    assert report.checkpoint.inbox["facts"] == 2

    # What is left: stripe's events 4 and 5, hooks' recent one; the pending
    # fact, and the fact consumed after it.
    left = sorted((e.source, e.seq) for e in site.reader().inbound_events())
    assert left == [("hooks", 2), ("stripe", 4), ("stripe", 5)]
    assert {f.event_id for f in site.reader().inbound_facts()} == {"evt_4", "evt_5"}
    assert set(site.reader().inbound_consumed()) == {facts["evt_5"].fact_id}
    assert site.reader().inbound_starts() == {
        "stripe": (3, heads[3]),
        "hooks": (1, hooks_head),
        "sendgrid": (0, inbox_genesis("sendgrid")),
    }
    assert _report(site) == InboxReport((), 3, 2, 1)
    site.outbox.verify()

    # The pending fact is still the agent's to consume, and the log goes on.
    engine = site.outbox.engine(inbox=INBOX_KEYS)
    assert [f.event_id for f in engine.facts("agent")] == ["evt_4"]
    later = stripe_webhook(refund_event("re_3", event_id="evt_6"))
    assert site.receive(site.inbox(), "stripe", later).body == {"recorded": 1, "matched": 1}
    assert _report(site) == InboxReport((), 4, 3, 1)

    # A second vacuum cuts on from the first, once the pending fact is spent.
    _consume(site, facts["evt_4"])
    second = _vacuum(site)
    assert second.outcome == "applied"
    (cut,) = second.checkpoint.inbox_cuts()
    assert (cut.source, cut.start, cut.prev, cut.through) == ("stripe", 3, heads[3], 5)
    assert _report(site) == InboxReport((), 2, 1, 0)
    site.outbox.verify()
    assert _vacuum(site).outcome == "nothing"


def test_without_the_inbox_keys_the_inbox_stays(site: InboxSite) -> None:
    _history(site)
    events = site.events()
    report = _vacuum(site, inbox=None)
    assert report.outcome == "nothing"
    assert site.events() == events


def test_a_source_that_does_not_verify_is_kept_whole(site: InboxSite) -> None:
    _history(site)
    rewrite_event(site, "stripe", 2, event_type="charge.dispute.created")
    report = _vacuum(site)
    assert report.outcome == "applied"
    (kept,) = report.inbox_kept
    assert kept[0] == "stripe" and "event 2 does not hash" in kept[1]
    assert [c.source for c in report.checkpoint.inbox_cuts()] == ["hooks"]
    assert sum(1 for e in site.reader().inbound_events() if e.source == "stripe") == 5


def test_a_finding_no_ones_source_prunes_nothing(site: InboxSite) -> None:
    _history(site)
    stray = uuid.uuid4()
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("SET session_replication_role = replica")
        conn.execute(
            "INSERT INTO interlock.inbox_consumed (fact_id, stage_id) VALUES (%s, %s)",
            (stray, uuid.uuid4()),
        )
        conn.execute("SET session_replication_role = DEFAULT")
    else:
        conn = site.outbox.raw()  # type: ignore[attr-defined]
        try:
            conn.execute(
                "INSERT INTO _interlock_inbox_consumed VALUES (?, ?, 0)",
                (str(stray), str(uuid.uuid4())),
            )
        finally:
            conn.close()
    report = _vacuum(site)
    assert report.outcome == "refused"
    assert report.problems == (f"fact {stray} was consumed, and the inbox holds no such fact",)


def test_the_archive_proves_the_pruned_inbox(site: InboxSite, tmp_path: Path) -> None:
    _history(site)
    report = _vacuum(site, archive=tmp_path / "archive")
    assert report.outcome == "applied" and report.archive is not None
    path = report.archive
    checkpoint = report.checkpoint
    assert verify_archive(path, checkpoint, relays=RELAYS, inbox=INBOX_KEYS) == []
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    events = [line for line in lines if line.get("kind") == "inbox-event"]
    assert [(e["source"], e["seq"]) for e in events] == [("hooks", 1)] + [
        ("stripe", n) for n in (1, 2, 3)
    ]
    assert all(e["body"] and e["signature"] for e in events)
    assert len([line for line in lines if line.get("kind") == "inbox-fact"]) == 2

    def tampered(change: Any) -> list[str]:
        copied = [dict(line) for line in lines]
        change(copied)
        forged = tmp_path / "forged.jsonl"
        forged.write_text("".join(json.dumps(line) + "\n" for line in copied))
        return verify_archive(forged, checkpoint, relays=RELAYS, inbox=INBOX_KEYS)

    def field(copied: list[dict[str, Any]]) -> None:
        next(c for c in copied if c.get("kind") == "inbox-event")["fields"] = {"id": "re_9"}

    def body(copied: list[dict[str, Any]]) -> None:
        next(c for c in copied if c.get("kind") == "inbox-event")["body"] = "{}"

    def dropped(copied: list[dict[str, Any]]) -> None:
        copied.remove(next(c for c in copied if c.get("kind") == "inbox-fact"))

    def consumer(copied: list[dict[str, Any]]) -> None:
        next(c for c in copied if c.get("kind") == "inbox-fact")["consumed_by"] = str(uuid.uuid4())

    assert any("does not hash to what it records" in p for p in tampered(field))
    assert any("not the one it was received with" in p for p in tampered(body))
    assert any("do not fold to checkpoint" in p for p in tampered(dropped))
    assert any("do not fold to checkpoint" in p for p in tampered(consumer))
    # The file is the one the checkpoint carries: any change shows.
    assert tampered(lambda copied: None) == [
        f"forged.jsonl is not the archive checkpoint {checkpoint.seq} carries"
    ]


def test_the_database_refuses_a_cut_that_does_not_hold(site: InboxSite) -> None:
    facts = _history(site)
    stripe = sorted(
        (e for e in site.reader().inbound_events() if e.source == "stripe"), key=lambda e: e.seq
    )
    consumed = site.reader().inbound_consumed()

    def body(through: int, head: str, pairs: list[tuple[InboundFact, Any]], **cut: Any) -> str:
        sources = [
            {
                "source": "stripe",
                "from": 0,
                "prev": inbox_genesis("stripe"),
                "through": through,
                "head": head,
                "events": through,
                "facts": len(pairs),
                "consumed": len(pairs),
                **cut,
            }
        ]
        inbox = {"sources": sources, "facts": len(pairs), "root": inbox_root(pairs)}
        return _body(site.outbox, inbox=inbox).canonical()

    good = [(facts[e], consumed[facts[e].fact_id]) for e in ("evt_1", "evt_3")]
    compactor = site.outbox.compactor()
    refusals = [
        (body(3, "0" * 64, good), "moved after it was verified"),
        (body(3, stripe[2].event_hash, good, prev="1" * 64), "moved after it was verified"),
        (body(3, stripe[2].event_hash, good, events=2), "moved after it was verified"),
        (body(4, stripe[3].event_hash, good), "still pending"),
        (body(3, stripe[2].event_hash, good[:1]), "not the ones the checkpoint commits to"),
        (
            body(3, stripe[2].event_hash, [(facts["evt_1"], uuid.uuid4()), good[1]]),
            "the facts are not the ones",
        ),
    ]
    for crafted, message in refusals:
        with pytest.raises(CompactionRefusedError, match=message):
            compactor.compact("a" * 64, crafted, [])
    assert compactor.checkpoints() == []
    assert site.events() == 7
    # The cut as verified is accepted, by the database alone.
    done = compactor.compact("a" * 64, body(3, stripe[2].event_hash, good), [])
    assert (done["inbox_events"], done["inbox_facts"]) == (3, 2)
    assert site.events() == 4


def test_the_inbox_goes_only_under_a_checkpoint(site: InboxSite) -> None:
    _history(site)
    for table in ("inbox_events", "inbox_facts", "inbox_consumed"):
        name = f"interlock.{table}" if site.outbox.backend == "postgres" else f"_interlock_{table}"
        with pytest.raises(Exception, match="append-only"):
            site.outbox.fetch(f"DELETE FROM {name}")
    assert site.events() == 7


def test_a_prefix_deleted_around_interlock_is_named(site: InboxSite) -> None:
    _history(site)
    for seq in (1, 2):
        delete_event(site, "stripe", seq)
    problems = _report(site).problems
    assert any("inbound source stripe: event 3 does not link" in p for p in problems)


def test_a_pruned_event_restored_is_named(site: InboxSite, tmp_path: Path) -> None:
    _history(site)
    report = _vacuum(site, archive=tmp_path / "archive")
    assert report.outcome == "applied"
    assert _report(site).problems == ()
    # The owner writes event 3 back, from the archive, around Interlock.
    archived = next(
        json.loads(line)
        for line in report.archive.read_text().splitlines()
        if '"seq":3' in line and '"stripe"' in line and "inbox-event" in line
    )
    columns = {
        "source": "stripe",
        "seq": 3,
        "event_id": archived["event_id"],
        "event_type": archived["type"],
        "vendor_at": archived["vendor_at"],
        "received_at": archived["received_at"],
        "body": archived["body"],
        "body_hash": archived["body_hash"],
        "signature": archived["signature"],
        "part": archived["part"],
        "refs": json.dumps(archived["refs"], separators=(",", ":")),
        "fields": json.dumps(archived["fields"], separators=(",", ":"), sort_keys=True),
        "withheld": json.dumps(archived["withheld"]),
        "attestation": archived["attestation"],
        "prev_hash": archived["prev_hash"],
        "event_hash": archived["event_hash"],
    }
    if isinstance(site.outbox, PostgresOutbox):
        conn = site.outbox.operator()
        conn.execute("ALTER TABLE interlock.inbox_events DISABLE TRIGGER inbox_log_link")
        conn.execute(
            f"INSERT INTO interlock.inbox_events ({', '.join(columns)}) "
            f"VALUES ({', '.join(f'%({c})s' for c in columns)})",
            columns,
        )
        conn.execute("ALTER TABLE interlock.inbox_events ENABLE ALWAYS TRIGGER inbox_log_link")
    else:
        conn = site.outbox.raw()  # type: ignore[attr-defined]
        try:
            conn.execute("DROP TRIGGER _interlock_inbox_link")
            conn.execute("DROP TRIGGER _interlock_inbox_head")
            conn.execute(
                f"INSERT INTO _interlock_inbox_events ({', '.join(columns)}) "
                f"VALUES ({', '.join(f':{c}' for c in columns)})",
                columns,
            )
        finally:
            conn.close()
    problems = _report(site).problems
    assert any("inbound source stripe: event 3 does not link" in p for p in problems)


def test_interlock_vacuum_cuts_the_inbox_on_the_command_line(
    site: InboxSite, tmp_path: Path
) -> None:
    from agentgov import BudgetManager

    from interlock.cli import main
    from interlock.operators import generate_key
    from tests.outbox_env import relay_signer
    from tests.test_vacuum import _config

    _history(site)
    outbox = site.outbox
    outbox.governor.open_root("operators", "1")
    outbox.governor.close()
    key = tmp_path / "vac.key"
    outbox.keys["vac"] = generate_key(key)
    relays = f'[relays.keys]\nrelay = "{relay_signer().public_key().spec()}"\n'
    config = _config(outbox, tmp_path, relays=relays)
    inbox = f'\n[inbox.keys]\ninbox = "{inbox_signer().public_key().spec()}"\n'
    config.write_text(config.read_text() + inbox)

    def cli(*argv: str) -> tuple[int, str]:
        out = io.StringIO()
        return main(list(argv), out=out), out.getvalue()

    code, out = cli("vacuum", "--config", str(config), "--key", str(key))
    assert code == 0, out
    # Retention 0: stripe's events up to the pending fact, and hooks' (its
    # recent one too, unless the database's clock is behind this one's).
    pruned = re.search(r"0 window row\(s\), (\d) inbound event\(s\)", out)
    assert pruned is not None and int(pruned.group(1)) in (4, 5), out
    archive = tmp_path / "archive" / "checkpoint-1.jsonl"
    code, out = cli("vacuum", "--config", str(config), "--verify-archive", str(archive))
    assert code == 0, out
    code, out = cli("inbox", "verify", "--config", str(config))
    assert code == 0, out
    outbox.governor = BudgetManager.open_sqlite(outbox.ledger_path)


def test_a_cut_round_trips_through_its_checkpoint() -> None:
    cut = InboxCut("s", 1, GENESIS, 2, "h", 1, 0, 0)
    assert InboxCut.parse(cut.body()) == cut
    body = Checkpoint(
        seq=1,
        prev=GENESIS,
        windows_horizon=None,
        outbox_horizon=None,
        messages=0,
        rows=0,
        root="r",
        window_rows=0,
        window_root="w",
        agentgov=(0, GENESIS),
        inbox={"sources": [cut.body()], "facts": 0, "root": inbox_root([])},
    )
    assert Checkpoint.parse(body.canonical()).inbox_cuts() == (cut,)
    assert Checkpoint.parse(body.canonical()) == body


# --------------------------------------------------------------------------
# one state of the database, whatever the inbox records meanwhile
# --------------------------------------------------------------------------


def test_a_verifier_reads_one_state_of_the_database_while_the_inbox_records(
    site: InboxSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``verify_inbox`` reads events, heads, facts and deliveries in turn. An
    event and its fact the inbox records between two of those reads are after
    all of them: never a fact whose event was read too early to see, nor a
    head past the log read."""
    site.deliver("re_1", "re_2")
    inbox = site.inbox()
    webhook = stripe_webhook(refund_event("re_1", event_id="evt_1"))
    assert site.receive(inbox, "stripe", webhook).status == 200
    reader = site.reader()
    kind: Any = type(reader)
    read = kind.inbound_events

    def racing(self: Any) -> Any:
        events = read(self)
        if self is reader:
            late = stripe_webhook(refund_event("re_2", event_id="evt_2"))
            assert site.receive(inbox, "stripe", late).status == 200
        return events

    monkeypatch.setattr(kind, "inbound_events", racing)
    report = verify_inbox(reader, INBOX_KEYS, relays=RELAYS)
    monkeypatch.undo()
    assert (report.problems, report.events, report.facts) == ((), 1, 1)
    after = _report(site)
    assert (after.problems, after.events, after.facts) == ((), 2, 2)


def test_a_vacuum_reads_one_state_of_the_database_while_the_inbox_records(
    site: InboxSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The vacuum's survey reads the outbox, the inbox and the operator log in
    turn while the daemon's relays, inbox and settler go on. What the inbox
    records meanwhile is the next vacuum's: this one prunes the prefix it
    verified, and is not refused for a fact it read without its event."""
    from interlock.inbox_store import PostgresInboxStore
    from interlock.sqlite_outbox import SqliteOutboxStore

    _history(site)
    kind: Any = PostgresInboxStore if isinstance(site.outbox, PostgresOutbox) else SqliteOutboxStore
    read = kind.inbound_events
    inbox = site.inbox()
    recorded: list[int] = []

    def racing(self: Any) -> Any:
        events = read(self)
        if not recorded:
            late = stripe_webhook(refund_event("re_2", event_id="evt_late"))
            recorded.append(site.receive(inbox, "stripe", late).status)
        return events

    monkeypatch.setattr(kind, "inbound_events", racing)
    report = _vacuum(site)
    monkeypatch.undo()
    assert recorded == [200]
    # The prefix it verified: stripe's events 1 to 3, and hooks' first.
    assert (report.outcome, report.problems, report.inbox_events) == ("applied", (), 4)
    assert _report(site).problems == ()
