"""The inbox, and a plan consuming its fact, killed at every point
(``docs/EPIC5_DESIGN.md`` §5), on both stores.

An inbox in a process of its own (``tests/inbox_child.py``) SIGKILLs itself
after verifying a vendor's signature, inside the transaction appending the
event, after it commits, inside the transaction binding it, and after that
commits. After each:

- what is recorded is exactly what committed: no event half-appended, no
  log head ahead of its last event, no fact without its event;
- every chain, attestation and binding verifies as the crash left it;
- the vendor's retry, which a webhook without a 2xx answer always gets,
  records what is missing and nothing twice: one event, one fact.

A SendGrid batch killed between its events leaves the events before the
kill, and the retry records the rest. A forged webhook never reaches the
first point.

An engine consuming a fact is killed with the fact consumed in its stage,
with its effect applied too, and after its commit: the fact is consumed
exactly when the plan's effects committed, and a plan consuming it after is
admitted, or refused, accordingly.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from interlock import BlastRadius, PlanBuilder
from interlock.exceptions import InboundFactError
from interlock.inbox import InboxReport, Response, verify_inbox
from tests.children import Child
from tests.inbox_env import (
    INBOX_KEYS,
    InboxSite,
    inbox_site,
    refund_event,
    sendgrid_webhook,
    stripe_webhook,
)
from tests.outbox_env import BACKENDS, RELAYS, Outbox, PostgresOutbox, build_either

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX")


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _report(site: InboxSite) -> InboxReport:
    return verify_inbox(site.reader(), INBOX_KEYS, relays=RELAYS)


def _killed(
    site: InboxSite,
    tmp_path: Path,
    scenario: dict[str, Any],
    *,
    role: str | None = None,
) -> None:
    child = Child(scenario, tmp_path, 0, module="tests.inbox_child")
    child.wait_for("started")
    assert child.wait_for("killed").at == scenario["kill_at"]
    assert child.process.wait(timeout=30) < 0, child.stderr()
    site.settle(role)


POINTS = [
    ("verified", 0, 0),
    ("record-uncommitted", 0, 0),
    ("recorded", 1, 0),
    ("match-uncommitted", 1, 0),
    ("matched", 1, 1),
]


@pytest.mark.parametrize(("kill_at", "events", "facts"), POINTS, ids=[p[0] for p in POINTS])
def test_an_inbox_killed_at_each_point_records_once_when_the_vendor_retries(
    site: InboxSite, tmp_path: Path, kill_at: str, events: int, facts: int
) -> None:
    site.deliver("re_1")
    headers, body = stripe_webhook(refund_event("re_1"))
    _killed(
        site,
        tmp_path,
        {
            "mode": "receive",
            **site.target,
            "source": "stripe",
            "headers": headers,
            "body": body.hex(),
            "kill_at": kill_at,
        },
    )
    # Exactly what committed, and all of it verifies.
    assert (site.events(), site.facts()) == (events, facts)
    assert _report(site) == InboxReport((), events, facts, 0)
    heads = site.reader().inbound_heads()
    assert heads["stripe"][0] == events

    # The vendor retries what was never answered 2xx.
    answer = site.receive(site.inbox(), "stripe", (headers, body))
    assert answer == Response(200, {"recorded": 1 - events, "matched": 1})
    assert (site.events(), site.facts()) == (1, 1)
    assert _report(site) == InboxReport((), 1, 1, 0)


BATCH_POINTS = [
    ("record-uncommitted", 2, 1, 1),
    ("recorded", 2, 2, 1),
    ("matched", 1, 1, 1),
    ("match-uncommitted", 2, 2, 1),
]


@pytest.mark.parametrize(
    ("kill_at", "occurrence", "events", "facts"),
    BATCH_POINTS,
    ids=[f"{p[0]} #{p[1]}" for p in BATCH_POINTS],
)
def test_a_batch_killed_between_its_events_is_completed_by_the_retry(
    site: InboxSite, tmp_path: Path, kill_at: str, occurrence: int, events: int, facts: int
) -> None:
    site.deliver("sgmsg1")
    headers, body = sendgrid_webhook(
        [
            {"sg_event_id": "sge_1", "event": "delivered", "sg_message_id": "sgmsg1.f0"},
            {"sg_event_id": "sge_2", "event": "open", "sg_message_id": "sgmsg1.f0"},
        ]
    )
    _killed(
        site,
        tmp_path,
        {
            "mode": "receive",
            **site.target,
            "source": "sendgrid",
            "headers": headers,
            "body": body.hex(),
            "kill_at": kill_at,
            "occurrence": occurrence,
        },
    )
    assert (site.events(), site.facts()) == (events, facts)
    assert _report(site).problems == ()
    answer = site.receive(site.inbox(), "sendgrid", (headers, body))
    assert answer == Response(200, {"recorded": 2 - events, "matched": 2})
    assert (site.events(), site.facts()) == (2, 2)
    assert _report(site) == InboxReport((), 2, 2, 0)


def test_a_forged_webhook_never_reaches_the_first_point(site: InboxSite, tmp_path: Path) -> None:
    site.deliver("re_1")
    headers, body = stripe_webhook(refund_event("re_1"), secret="whsec_forged")
    child = Child(
        {
            "mode": "receive",
            **site.target,
            "source": "stripe",
            "headers": headers,
            "body": body.hex(),
            "kill_at": "verified",
        },
        tmp_path,
        0,
        module="tests.inbox_child",
    )
    child.wait_for("started")
    finished = child.wait_for("finished")
    assert finished.raw["status"] == 401
    assert child.process.wait(timeout=30) == 0
    assert (site.events(), site.facts()) == (0, 0)


CONSUME_POINTS = [("consumed", False), ("applied", False), ("committed", True)]


@pytest.mark.parametrize(
    ("kill_at", "committed"), CONSUME_POINTS, ids=[p[0] for p in CONSUME_POINTS]
)
def test_a_plan_killed_mid_stage_consumes_its_fact_exactly_with_its_commit(
    site: InboxSite, tmp_path: Path, kill_at: str, committed: bool
) -> None:
    site.deliver("re_1")
    site.receive(site.inbox(), "stripe", stripe_webhook(refund_event("re_1")))
    engine = site.outbox.engine(inbox=INBOX_KEYS, checkers=[BlastRadius(10)])
    (fact,) = engine.facts("agent")
    outbox = site.outbox
    if isinstance(outbox, PostgresOutbox):
        target = {"store": "postgres", "dsn": outbox.pg.agent}
        role: str | None = outbox.pg.role
    else:
        target = {"store": "sqlite", "dsn": site.target["dsn"]}
        role = None
    _killed(
        site,
        tmp_path,
        {"mode": "consume", **target, "fact": str(fact.fact_id), "kill_at": kill_at},
        role=role,
    )
    status = outbox.fetch("SELECT status FROM orders WHERE id = 500")[0][0]
    consumed = set(site.reader().inbound_consumed())
    # The fact is consumed exactly when the plan's effects committed.
    assert (status, consumed) == (("refunded", {fact.fact_id}) if committed else ("open", set()))
    report = _report(site)
    assert (report.problems, report.consumed) == ((), int(committed))

    named = outbox.named("status")
    again = (
        PlanBuilder("agent")
        .consume(fact)
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = {named} WHERE id = 500",
            parameters={"status": "refunded-again"},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )
    if committed:
        with pytest.raises(InboundFactError):
            engine.execute(again)
        assert engine.facts("agent") == ()
    else:
        assert engine.execute(again).committed
        assert set(site.reader().inbound_consumed()) == {fact.fact_id}


VACUUM_POINTS = [("transaction", False), ("acted", True)]


@pytest.mark.parametrize(("kill_at", "pruned"), VACUUM_POINTS, ids=[p[0] for p in VACUUM_POINTS])
def test_a_vacuum_killed_mid_act_cuts_the_inbox_all_or_nothing(
    site: InboxSite, tmp_path: Path, kill_at: str, pruned: bool
) -> None:
    from datetime import UTC, datetime, timedelta

    from agentgov import BudgetManager

    from interlock.operators import generate_key
    from tests.inbox_env import inbox_signer

    outbox = site.outbox
    site.deliver("re_1")
    then = datetime.now(UTC) - timedelta(hours=2)
    old = site.inbox(clock=lambda: then)
    for n, ref in ((1, "re_1"), (2, "re_none")):
        webhook = stripe_webhook(refund_event(ref, event_id=f"evt_{n}"), at=then)
        assert site.receive(old, "stripe", webhook).status == 200
    engine = outbox.engine(inbox=INBOX_KEYS, checkers=[BlastRadius(10)])
    (fact,) = engine.facts("agent")
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

    outbox.governor.open_root("operators", "1")
    outbox.governor.close()
    key = tmp_path / "vac.key"
    outbox.keys["vac"] = generate_key(key)
    outbox.operator_key("bob")
    child = Child(
        {
            **outbox.operator_target(),
            "log": str(outbox.operator_log),
            "key": str(key),
            "keys": {name: k.public_key().spec() for name, k in outbox.keys.items()},
            "ledger": outbox.ledger_path,
            "kill_at": kill_at,
            "inbox": {"inbox": inbox_signer().public_key().spec()},
        },
        tmp_path,
        0,
        module="tests.vacuum_child",
    )
    child.wait_for("started")
    assert child.wait_for("killed").at == kill_at
    assert child.process.wait(timeout=30) < 0, child.stderr()
    outbox.settle()
    outbox.governor = BudgetManager.open_sqlite(outbox.ledger_path)

    # All of the cut, or none of it.
    assert (site.events(), site.facts()) == ((0, 0) if pruned else (2, 1))
    assert _report(site).problems == ()
    with outbox.signed("bob", ledger=outbox.governor) as bob:
        assert [r.kind for r in bob.resolve()] == (
            ["operator.applied"] if pruned else ["operator.abandoned"]
        )
    outbox.verify()
    with outbox.vacuum("bob", inbox=INBOX_KEYS) as vacuum:
        second = vacuum.run()
    assert second.outcome == ("nothing" if pruned else "applied")
    assert (site.events(), site.facts()) == (0, 0)
    assert _report(site) == InboxReport((), 0, 0, 0)
    outbox.verify()
