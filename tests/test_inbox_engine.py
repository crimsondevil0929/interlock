"""Facts in plans, on both stores (``docs/EPIC5_DESIGN.md`` §2.6, §2.7): a plan
consumes its scope's attested facts, in its stage's own transaction, exactly
once and exactly when it commits; the stage reads them back for the diff,
where they are verified again, as measured; and checkers judge the plan's
reaction against what the vendor said.

- A fact is consumed with its plan's commit, once: a second plan naming it is
  refused, and a refused or repaired plan consumes nothing.
- A fact of another scope, an unknown one, a forged one, or one whose
  attestation does not verify under ``[inbox.keys]`` is refused at admission.
- What the stage reads back is verified again: a diff carrying a fact other
  than the inbox attested is refused, whatever admission saw.
- No statement of a plan reads the inbox.
- Two stages racing to consume one fact: one consumes it.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

from interlock import BlastRadius, EscrowEngine, FactAgreement, PlanBuilder
from interlock.exceptions import (
    ForbiddenStatementError,
    InboundFactError,
    InterlockError,
    StageConflictError,
)
from interlock.feedback import AgentFeedback
from interlock.inbox import verify_inbox
from interlock.receipts import receipt_rows
from interlock.records import Keyring
from interlock.types import INBOX_TARGET, EffectDiff, EffectPlan, InboundFact
from tests.inbox_env import (
    INBOX_KEYS,
    InboxSite,
    append_event,
    inbox_signer,
    inbox_site,
    insert_fact,
    refund_event,
    stripe_webhook,
)
from tests.outbox_env import BACKENDS, RELAYS, Outbox, PostgresOutbox, build_either
from tests.test_inbox import STRANGER

psycopg = pytest.importorskip("psycopg")


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Any) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _engine(site: InboxSite, **kwargs: Any) -> EscrowEngine:
    kwargs.setdefault("inbox", INBOX_KEYS)
    kwargs.setdefault("checkers", [BlastRadius(10)])
    return site.outbox.engine(**kwargs)


def _fact(site: InboxSite, ref: str = "re_1", *, scope: str = "agent", **event: Any) -> InboundFact:
    """A fact about a refund delivered for ``scope``: received, bound, attested."""
    site.deliver(ref, scope=scope)
    event.setdefault("event_id", f"evt_{ref}")
    answer = site.receive(site.inbox(), "stripe", stripe_webhook(refund_event(ref, **event)))
    assert answer.body == {"recorded": 1, "matched": 1}
    (fact,) = [f for f in _engine(site).facts(scope) if f.remote_ref == ref]
    return fact


def _reaction(
    site: InboxSite, *facts: InboundFact | uuid.UUID, status: str = "refunded", scope: str = "agent"
) -> EffectPlan:
    """A plan that marks order 500 ``status``, consuming ``facts``."""
    builder = PlanBuilder(scope)
    for fact in facts:
        builder.consume(fact)
    named = site.outbox.named("status")
    return builder.update(
        table="orders",
        statement=f"UPDATE orders SET status = {named} WHERE id = 500",
        parameters={"status": status},
        tenant_id="acme",
        stated_rows=1,
    ).build()


def _status(site: InboxSite) -> str:
    return str(site.outbox.fetch("SELECT status FROM orders WHERE id = 500")[0][0])


# -- consumed with the plan's commit, once -----------------------------------------


def test_a_plan_consumes_its_scopes_fact_with_its_commit(site: InboxSite) -> None:
    fact = _fact(site)
    engine = _engine(site)
    plan = _reaction(site, fact)
    assert plan.facts == (fact.fact_id,)
    result = engine.execute(plan)
    assert result.committed, result.feedback
    # Read back from the database, as the stage consumed it.
    assert result.diff is not None
    assert result.diff.facts == (fact,)
    assert engine.facts("agent") == ()
    assert _status(site) == "refunded"
    report = verify_inbox(site.reader(), INBOX_KEYS, relays=RELAYS)
    assert (report.problems, report.consumed) == ((), 1)
    consumed = site.reader().inbound_consumed()
    assert set(consumed) == {fact.fact_id}
    # The receipt commits to it, as a row of the inbox.
    (row,) = [r for r in receipt_rows(result.diff) if r.table == INBOX_TARGET]
    assert row.pk == str(fact.fact_id)


def test_a_fact_is_consumed_once(site: InboxSite) -> None:
    fact = _fact(site)
    engine = _engine(site)
    assert engine.execute(_reaction(site, fact)).committed
    with pytest.raises(InboundFactError) as refused:
        engine.execute(_reaction(site, fact, status="again"))
    feedback = refused.value.feedback
    assert isinstance(feedback, AgentFeedback)
    assert feedback.to_json()["constraints"][0]["constraint"] == "inbound_fact"
    assert _status(site) == "refunded"


def test_a_refused_plan_consumes_nothing(site: InboxSite) -> None:
    fact = _fact(site)
    refused = _engine(site, checkers=[BlastRadius(0)]).execute(_reaction(site, fact))
    assert not refused.committed
    assert [f.fact_id for f in _engine(site).facts("agent")] == [fact.fact_id]
    assert site.reader().inbound_consumed() == {}
    assert _engine(site).execute(_reaction(site, fact)).committed


def test_a_repair_is_judged_with_the_facts_and_consumes_nothing(site: InboxSite) -> None:
    fact = _fact(site)
    engine = _engine(site, checkers=[BlastRadius(1)])
    named = site.outbox.named("total")
    plan = (
        PlanBuilder("agent")
        .consume(fact)
        .update(
            table="orders",
            statement=f"UPDATE orders SET total = {named} WHERE tenant = 'acme'",
            parameters={"total": "1.00"},
            tenant_id="acme",
            stated_rows=2,
        )
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'refunded' WHERE id = 500",
            tenant_id="acme",
            stated_rows=1,
            independent=True,
        )
        .build()
    )
    repair = engine.repair(plan)
    assert repair.proposal is not None
    assert repair.proposal.facts == (fact.fact_id,)
    assert [f.fact_id for f in engine.facts("agent")] == [fact.fact_id]
    assert engine.execute(repair.proposal).committed
    assert engine.facts("agent") == ()


# -- refused at admission -----------------------------------------------------------


def test_a_fact_of_another_scope_is_refused(site: InboxSite) -> None:
    theirs = _fact(site, "re_2", scope="other")
    with pytest.raises(InboundFactError, match="not pending for scope 'agent'"):
        _engine(site).execute(_reaction(site, theirs))
    with pytest.raises(InboundFactError):
        _engine(site).execute(_reaction(site, uuid.uuid4()))
    assert [f.fact_id for f in _engine(site).facts("other")] == [theirs.fact_id]


def test_a_plan_naming_a_fact_twice_is_refused(site: InboxSite) -> None:
    fact = _fact(site)
    plan = dataclasses.replace(_reaction(site, fact), facts=(fact.fact_id, fact.fact_id))
    with pytest.raises(InboundFactError, match="more than once"):
        _engine(site).execute(plan)
    assert [f.fact_id for f in _engine(site).facts("agent")] == [fact.fact_id]


def test_an_engine_without_inbox_keys_takes_no_facts(site: InboxSite) -> None:
    fact = _fact(site)
    engine = site.outbox.engine(checkers=[BlastRadius(10)])
    with pytest.raises(InboundFactError, match="inbox"):
        engine.facts("agent")
    with pytest.raises(InboundFactError, match="verifies none"):
        engine.execute(_reaction(site, fact))
    with pytest.raises(InboundFactError, match="verifies none"):
        engine.repair(_reaction(site, fact))


def test_a_fact_attested_by_no_registered_inbox_is_refused(site: InboxSite) -> None:
    fact = _fact(site)
    stranger = _engine(site, inbox=Keyring({"x": STRANGER.public_key()}))
    assert stranger.facts("agent") == ()
    with pytest.raises(InboundFactError, match="not attested"):
        stranger.execute(_reaction(site, fact))


def test_a_fact_written_around_the_inbox_is_never_consumed(site: InboxSite) -> None:
    genuine = _fact(site)
    # The owner appends an event and binds it to the delivery, around the
    # inbox: the event's chain links, the fact's attestation is the owner's.
    seq = append_event(site, "stripe", signer=inbox_signer(), event_id="evt_x", refs=("re_1",))
    event = next(e for e in site.reader().inbound_events() if e.seq == seq)
    forged = dataclasses.replace(
        genuine,
        fact_id=uuid.uuid4(),
        event_seq=seq,
        event_hash=event.event_hash,
        attestation=genuine.attestation.replace(genuine.attestation[-20:-2], "0" * 18),
    )
    insert_fact(site, forged)
    # A second binding of the genuine event: one fact per event.
    with pytest.raises(Exception):  # noqa: B017 - either store's unique-key error
        insert_fact(site, dataclasses.replace(forged, fact_id=uuid.uuid4(), event_seq=1))
    engine = _engine(site)
    assert [f.fact_id for f in engine.facts("agent")] == [genuine.fact_id]
    with pytest.raises(InboundFactError, match="not attested"):
        engine.execute(_reaction(site, forged))
    assert engine.execute(_reaction(site, genuine)).committed


# -- verified again, as measured ----------------------------------------------------


class Rewriting:
    """A substrate whose diff carries a fact other than the stage read: what a
    compromised read path would hand the checkers."""

    def __init__(self, inner: Any, change: Any) -> None:
        self._inner = inner
        self._change = change

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def diff(self, handle: Any) -> EffectDiff:
        measured: EffectDiff = self._inner.diff(handle)
        return dataclasses.replace(measured, facts=self._change(measured.facts))


@pytest.mark.parametrize(
    "change",
    [
        lambda facts: tuple(
            dataclasses.replace(f, fields={**f.fields, "status": "failed"}) for f in facts
        ),
        lambda facts: tuple(dataclasses.replace(f, scope_id="other") for f in facts),
        lambda facts: (),
        lambda facts: (*facts, dataclasses.replace(facts[0], fact_id=uuid.uuid4())),
    ],
    ids=["fields rewritten", "another scope", "dropped", "one more"],
)
def test_what_the_stage_reads_back_is_verified_as_measured(site: InboxSite, change: Any) -> None:
    fact = _fact(site)
    engine = _engine(site, substrate=Rewriting(site.outbox.substrate(), change))
    with pytest.raises(InboundFactError, match=r"as its stage read it|not the ones it names"):
        engine.execute(_reaction(site, fact))
    # Rolled back with the stage: the fact pending, the row untouched.
    assert [f.fact_id for f in _engine(site).facts("agent")] == [fact.fact_id]
    assert _status(site) == "open"


def test_no_statement_of_a_plan_reads_the_inbox(site: InboxSite) -> None:
    fact = _fact(site)
    if site.outbox.backend == "postgres":
        statement = (
            "UPDATE orders SET status = (SELECT out_type FROM interlock.inbox_pending('agent') "
            "LIMIT 1) WHERE id = 500"
        )
    else:
        statement = (
            "UPDATE orders SET status = (SELECT event_type FROM _interlock_inbox_events "
            "LIMIT 1) WHERE id = 500"
        )
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement=statement, tenant_id="acme", stated_rows=1)
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as refused:
        _engine(site).execute(plan)
    assert refused.value.reason == "protected"
    assert [f.fact_id for f in _engine(site).facts("agent")] == [fact.fact_id]
    if site.outbox.backend == "sqlite":
        for table in ("_interlock_inbox_facts", "_interlock_inbox_consumed"):
            plan = (
                PlanBuilder("agent")
                .update(
                    table="orders",
                    statement=f"UPDATE orders SET status = (SELECT count(*) FROM {table}) "
                    f"WHERE id = 500",
                    tenant_id="acme",
                    stated_rows=1,
                )
                .build()
            )
            with pytest.raises(ForbiddenStatementError):
                _engine(site).execute(plan)


# -- two stages, one fact -------------------------------------------------------------


def test_two_stages_racing_for_one_fact_consume_it_once(site: InboxSite) -> None:
    fact = _fact(site)
    plan = _reaction(site, fact)
    first = site.outbox.substrate()
    handle = first.open(plan)
    first.consume_facts(handle, [fact.fact_id], "agent")
    if isinstance(site.outbox, PostgresOutbox):
        # The second waits on the first's key, past its lock timeout.
        second = type(first)(
            site.outbox.pg.agent, tables=first.table_specs, lock_timeout_seconds=0.2
        )
        other = second.open(_reaction(site, fact, status="second"))
        with pytest.raises(StageConflictError):
            second.consume_facts(other, [fact.fact_id], "agent")
        second.close(other)
    first.commit(handle)
    first.close(handle)
    third = site.outbox.substrate()
    late = third.open(_reaction(site, fact, status="third"))
    try:
        with pytest.raises(InboundFactError):
            third.consume_facts(late, [fact.fact_id], "agent")
    finally:
        third.close(late)
    assert set(site.reader().inbound_consumed()) == {fact.fact_id}


def test_a_stage_consumes_only_its_scopes_facts(site: InboxSite) -> None:
    fact = _fact(site)
    substrate = site.outbox.substrate()
    handle = substrate.open(_reaction(site, fact))
    try:
        with pytest.raises(InboundFactError):
            substrate.consume_facts(handle, [fact.fact_id], "other")
    finally:
        substrate.close(handle)
    handle = substrate.open(_reaction(site, fact))
    try:
        with pytest.raises(InboundFactError):
            substrate.consume_facts(handle, [uuid.uuid4()], "agent")
    finally:
        substrate.close(handle)
    assert site.reader().inbound_consumed() == {}


# -- the reaction answers to the fact (FactAgreement) -----------------------------------


def _agreement() -> FactAgreement:
    return FactAgreement(
        "charge.refund.updated", field="status", table="orders", column="status", exempt=["open"]
    )


def test_a_reaction_must_say_what_the_fact_says(site: InboxSite) -> None:
    succeeded = _fact(site, "re_1", status="succeeded")
    failed = _fact(site, "re_2", status="failed")
    engine = _engine(site, checkers=[BlastRadius(10), _agreement()])
    # Without the fact: refused, whatever the agent was told.
    refused = engine.execute(_reaction(site, status="succeeded"))
    assert not refused.committed
    assert refused.feedback is not None
    (constraint,) = refused.feedback.to_json()["constraints"]
    assert constraint["constraint"] == "fact_agreement"
    assert "failed" not in str(refused.feedback.to_json())
    # With a fact that says otherwise: refused.
    assert not engine.execute(_reaction(site, failed, status="succeeded")).committed
    # With the fact that says so: committed.
    assert engine.execute(_reaction(site, succeeded, status="succeeded")).committed
    assert _status(site) == "succeeded"
    # An exempt value needs no fact.
    assert engine.execute(_reaction(site, status="open")).committed
    # The failed fact is still pending: a refused plan consumed nothing.
    assert [f.fact_id for f in engine.facts("agent")] == [failed.fact_id]


def test_facts_round_trip_exactly(site: InboxSite) -> None:
    fact = _fact(site)
    result = _engine(site).execute(_reaction(site, fact))
    assert result.diff is not None
    (read,) = result.diff.facts
    assert read == fact
    assert read.received_at.tzinfo is not None
    assert result.diff.content_hash() != dataclasses.replace(result.diff, facts=()).content_hash()
    assert isinstance(read.fields["amount"], int)
    assert timedelta(0) <= read.received_at - read.vendor_at <= timedelta(seconds=5)  # type: ignore[operator]


def test_a_store_without_the_inbox_says_so(outbox: Outbox) -> None:
    if outbox.backend == "postgres":
        outbox.operator().execute("DROP FUNCTION interlock.inbox_pending(text)")
    else:
        outbox.fetch("DROP TABLE _interlock_inbox_consumed")
        outbox.fetch("DROP TABLE _interlock_inbox_facts")
    with pytest.raises(InterlockError, match=r"inbox|not installed"):
        outbox.engine(inbox=INBOX_KEYS).facts("agent")


def test_nothing_but_the_stage_consumes_a_fact(site: InboxSite) -> None:
    fact = _fact(site)
    if isinstance(site.outbox, PostgresOutbox):
        statement = (
            f"UPDATE orders SET status = (SELECT interlock.inbox_consume("
            f"'\\x00'::bytea, ARRAY['{fact.fact_id}']::uuid[], 'agent')::text) WHERE id = 500"
        )
        # Outside a stage, as the stage's role: no stage of this transaction.
        with psycopg.connect(site.outbox.pg.agent, autocommit=True) as conn:
            with pytest.raises(psycopg.Error, match="did not consume"):
                conn.execute(
                    "SELECT interlock.inbox_consume(%s, %s::uuid[], 'agent')",
                    (b"\x00" * 32, [fact.fact_id]),
                )
    else:
        statement = f"INSERT INTO _interlock_inbox_consumed VALUES ('{fact.fact_id}', 'x', 0)"
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement=statement, tenant_id="acme", stated_rows=1)
        .build()
    )
    with pytest.raises(ForbiddenStatementError) as refused:
        _engine(site).execute(plan)
    assert refused.value.reason == "protected"
    assert [f.fact_id for f in _engine(site).facts("agent")] == [fact.fact_id]
