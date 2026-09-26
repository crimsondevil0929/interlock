"""Extension quotes (M4): a signed price for finishing, instead of a tripped breaker.

Tested against a real AgentGov ledger:

- A call that fits is held; one that does not is quoted, and nothing trips.
- The quote's three parts: spend to date read from the ledger, proof of work
  from the ARC1 receipts of plans committed on the back-office schema (in
  SQLite and PostgreSQL) with a checkpoint every one of them is provable
  against, and an estimate whose arithmetic is checked to the cent.
- A scope spent out is quoted; a scope halted for safety is not.
- Answers: a root topped up and its spent breaker reset, a delegated scope
  extended beside itself, and a quote answered once, in time, by the guard
  that issued it.
- Recovery: a spent reserve comes with a quote, and a grant lets it go on.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.core import Authorization, EntryType
from agentgov.exceptions import CircuitOpenError
from agentgov.receipts import HmacKey, ReceiptLog, verify_bundle

from interlock import EscrowEngine, LedgerAnchor, PlanBuilder
from interlock.exceptions import ExtensionError, RecoveryError, RecoveryExhaustedError
from interlock.extension import BudgetGuard, ExtensionRequest, Milestones
from interlock.receipts import ReceiptIssuer
from interlock.records import RecordKind, RecordLog, check_anchors
from interlock.recovery import RecoveryPolicy, RecoveryRuntime, Trip, TripKind
from tests.conftest import Pg
from tests.plans import pg_engine, pg_placeholder, sqlite_engine, support_batch

HISTORY: list[object] = [
    {"role": "user", "content": "Close out the support queue."},
    {"role": "assistant", "content": [{"type": "text", "text": "Working on it."}]},
]
REPLY = {"role": "assistant", "content": [{"type": "text", "text": "Understood."}]}


def governor() -> BudgetManager:
    gov = BudgetManager()
    gov.open_root("org", "10")
    gov.delegate("org", "support-agent", "5")
    return gov


def guard_for(gov: BudgetManager, **kwargs: Any) -> BudgetGuard:
    return BudgetGuard(gov, RecordLog(HmacKey.generate(), log_id="support"), **kwargs)


def spend(gov: BudgetManager, scope: str, amount: str) -> None:
    gov.capture(gov.authorize(scope, amount), amount)


def quoted(outcome: Authorization | ExtensionRequest) -> ExtensionRequest:
    assert isinstance(outcome, ExtensionRequest), outcome
    return outcome


# --------------------------------------------------------------------------
# asking
# --------------------------------------------------------------------------


def test_a_call_that_fits_is_simply_held() -> None:
    gov = governor()
    held = guard_for(gov).authorize("support-agent", "1.00", memo="turn 1")
    assert isinstance(held, Authorization) and held.scope_id == "support-agent"
    assert gov.available("support-agent") == Decimal("4.00")
    with pytest.raises(ValueError, match="positive"):
        guard_for(gov).authorize("support-agent", "0")


def test_a_call_that_does_not_fit_is_quoted_and_nothing_trips() -> None:
    gov = governor()
    guard = guard_for(gov)
    spend(gov, "support-agent", "4.60")
    quote = quoted(guard.authorize("support-agent", "0.50"))

    assert not gov.is_halted("support-agent")
    assert not [e for e in gov.audit_trail() if e.entry_type is EntryType.CIRCUIT_TRIPPED]
    assert quote.spend.spent == Decimal("4.60") and quote.spend.held == 0
    assert quote.spend.available == Decimal("0.40")
    assert quote.spend.scopes == (("support-agent", Decimal("4.60")),)
    estimate = quote.estimate
    assert (estimate.method, estimate.completion, estimate.total) == (
        "next_call",
        Decimal("0.50"),
        Decimal("0.63"),  # 0.50 and 25%, rounded up to the cent
    )
    assert quote.requested == Decimal("0.23")  # 0.63 less the 0.40 left
    assert quote.halted_by is None and guard.pending() == (quote,)

    record = quote.record
    assert record.kind == RecordKind.EXTENSION_QUOTED and record.scope == "support-agent"
    assert record.body["requested"] == "0.23000000" and record.body["quote"] == quote.quote_id
    guard.records.verify()
    assert check_anchors(guard.records.records(), gov.audit_trail()) == 1
    text = quote.render()
    assert text.startswith("Extension requested for support-agent: 0.23000000.")
    assert "the next call alone = 0.50000000" in text


def test_declared_milestones_price_the_rest_of_the_task() -> None:
    gov = governor()
    guard = guard_for(gov, margin=Decimal("0.25"))
    spend(gov, "support-agent", "3.60")
    done = Milestones(done=3, total=5, unit="tickets")
    quote = quoted(guard.authorize("support-agent", "1.50", milestones=done))
    estimate = quote.estimate
    assert estimate.method == "milestones"
    assert (estimate.unit_cost, estimate.remaining) == (Decimal("1.20"), 2)
    assert estimate.completion == Decimal("2.40") and estimate.total == Decimal("3.00")
    assert quote.requested == Decimal("1.60")  # 3.00 to finish, 1.40 left
    assert quote.progress.milestones == done
    assert "declared 3 of 5 tickets done" in quote.render()
    assert "1.20000000 per unit x 2 remaining" in quote.render()
    with pytest.raises(ValueError, match="milestones"):
        Milestones(done=6, total=5)


def test_a_scope_spent_out_is_quoted_and_a_safety_halt_is_not() -> None:
    gov = governor()
    guard = guard_for(gov)
    spend(gov, "support-agent", "5.00")  # to zero: AgentGov trips it
    assert gov.is_halted("support-agent")
    quote = quoted(guard.authorize("support-agent", "0.10"))
    assert quote.halted_by == "spend envelope exhausted"
    assert quote.requested == Decimal("0.13")

    unsafe = governor()
    unsafe.trip("support-agent", "cognitive breaker [exact_repeat]: 2 calls")
    with pytest.raises(CircuitOpenError):
        guard_for(unsafe).authorize("support-agent", "0.10")
    frozen = governor()
    frozen.trip("org", "operator: freeze")
    with pytest.raises(CircuitOpenError) as caught:
        guard_for(frozen).authorize("support-agent", "0.10")
    assert caught.value.tripped_scope_id == "org"


# --------------------------------------------------------------------------
# proof of work, on the back-office schema
# --------------------------------------------------------------------------


def proof_of_work(
    engine: EscrowEngine, gov: BudgetManager, placeholder: Callable[[str], str], key: HmacKey
) -> None:
    """Two plans commit and one is refused; the quote proves the two."""
    p = placeholder
    log = engine.receipts.log if engine.receipts is not None else None
    assert log is not None
    committed = []
    for order, status in ((500, "held"), (501, "review")):
        plan = (
            PlanBuilder("support-agent")
            .update(
                table="orders",
                statement=f"UPDATE orders SET status = {p('s')} WHERE id = {p('id')}",
                parameters={"s": status, "id": order},
                tenant_id="acme",
            )
            .build()
        )
        result = engine.execute(plan)
        assert result.committed and result.receipt is not None
        committed.append(result.receipt)
    assert not engine.execute(support_batch(placeholder)).committed

    guard = guard_for(gov, receipts=log)
    quote = quoted(guard.authorize("support-agent", "9.00"))
    progress = quote.progress
    assert (progress.committed, progress.rows, progress.log) == (2, 2, log.log_id)
    assert progress.receipts == tuple(r.receipt_id for r in committed)
    assert progress.checkpoint is not None
    checkpoint = log.checkpoints()[-1]
    assert progress.checkpoint == (checkpoint.tree_size, checkpoint.root_hash)
    for receipt_id in progress.receipts:
        index = log.index_of(receipt_id)
        assert index is not None
        report = verify_bundle(log.bundle(index, checkpoint), issuer_key=key)
        assert report.passed, report.to_json()
    assert f"2 plan(s) committed (2 rows), provable in receipt log {log.log_id}" in quote.render()


def receipted(key: HmacKey) -> ReceiptIssuer:
    return ReceiptIssuer(ReceiptLog("interlock-receipts", key))


def test_sqlite_the_quote_proves_the_work_its_receipts_record(back_office: str) -> None:
    gov, key = governor(), HmacKey.generate()
    engine = sqlite_engine(back_office, anchor=LedgerAnchor(governed=gov), receipts=receipted(key))
    proof_of_work(engine, gov, lambda n: f":{n}", key)


def test_postgres_the_quote_proves_the_work_its_receipts_record(pg: Pg) -> None:
    gov, key = governor(), HmacKey.generate()
    engine = pg_engine(pg, anchor=LedgerAnchor(governed=gov), receipts=receipted(key))
    proof_of_work(engine, gov, pg_placeholder, key)


def test_without_a_receipt_log_a_quote_proves_only_its_records() -> None:
    gov = governor()
    quote = quoted(guard_for(gov).authorize("support-agent", "9.00"))
    assert quote.progress.committed == 0 and quote.progress.checkpoint is None


# --------------------------------------------------------------------------
# answering
# --------------------------------------------------------------------------


def test_a_root_is_topped_up_and_its_spent_breaker_reset() -> None:
    gov = BudgetManager()
    gov.open_root("solo", "1.00")
    guard = guard_for(gov)
    spend(gov, "solo", "1.00")
    quote = quoted(guard.authorize("solo", "0.20"))
    grant = guard.grant(quote, approved_by="ops@acme.test")
    assert (grant.scope_id, grant.amount, grant.reset) == ("solo", quote.requested, True)
    assert not gov.is_halted("solo") and gov.available("solo") == quote.requested
    assert isinstance(guard.authorize("solo", "0.20"), Authorization)
    body = grant.record.body
    assert body["source"] == "fund" and body["reset"] is True and body["from"] is None
    assert body["quote"] == {
        "id": quote.quote_id,
        "seq": quote.record.seq,
        "hash": quote.record.record_hash,
    }
    assert [e.entry_type for e in gov.audit_trail("solo")].count(EntryType.CIRCUIT_RESET) == 1
    assert guard.pending() == ()


def test_a_delegated_scope_is_extended_beside_itself() -> None:
    gov = governor()
    guard = guard_for(gov)
    spend(gov, "support-agent", "4.60")
    first = guard.grant(quoted(guard.authorize("support-agent", "0.50")), approved_by="ops")
    assert first.scope_id == "support-agent/ext-1" and not first.reset
    assert (first.amount, first.carried) == (Decimal("0.23"), Decimal("0.40"))
    assert gov.node("support-agent/ext-1").parent_id == "org"
    assert gov.available("support-agent/ext-1") == Decimal("0.63")  # the 0.40 came along
    assert gov.available("support-agent") == 0 and gov.available("org") == Decimal("4.77")
    body = first.record.body
    assert (body["source"], body["from"], body["carried"]) == ("delegate", "org", "0.40000000")

    spend(gov, "support-agent/ext-1", "0.20")
    again = quoted(guard.authorize("support-agent/ext-1", "0.50", task="support-agent"))
    assert again.spend.scopes == (
        ("support-agent", Decimal("4.60")),
        ("support-agent/ext-1", Decimal("0.20")),
    )
    assert again.spend.spent == Decimal("4.80")
    second = guard.grant(again, approved_by="ops", amount="1.00")
    assert (second.scope_id, second.amount) == ("support-agent/ext-2", Decimal("1.00"))
    assert gov.available("support-agent/ext-2") == Decimal("1.43")
    gov.verify_integrity()


def test_a_quote_is_answered_once_in_time_by_the_guard_that_issued_it() -> None:
    now = [datetime(2026, 9, 26, 9, 0, tzinfo=UTC)]
    gov = governor()
    guard = guard_for(gov, clock=lambda: now[0], ttl=timedelta(minutes=30))
    spend(gov, "support-agent", "4.60")

    granted = quoted(guard.authorize("support-agent", "0.50"))
    with pytest.raises(ValueError, match="approved"):
        guard.grant(granted, approved_by=" ")
    with pytest.raises(ValueError, match="positive"):
        guard.grant(granted, approved_by="ops", amount="0")
    guard.grant(granted, approved_by="ops")
    with pytest.raises(ExtensionError, match="already granted"):
        guard.grant(granted, approved_by="ops")

    declined = quoted(guard.authorize("support-agent", "0.50"))
    record = guard.decline(declined, declined_by="ops", reason="finish tomorrow")
    assert record.kind == RecordKind.EXTENSION_DECLINED
    assert record.body["reason"] == "finish tomorrow"
    with pytest.raises(ExtensionError, match="already declined"):
        guard.grant(declined, approved_by="ops")
    with pytest.raises(ValueError, match="declined"):
        guard.decline(declined, declined_by="")

    late = quoted(guard.authorize("support-agent", "0.50"))
    now[0] += timedelta(hours=1)
    with pytest.raises(ExtensionError, match="expired"):
        guard.grant(late, approved_by="ops")
    guard.decline(late, declined_by="ops")  # an expired quote can still be declined

    stranger = guard_for(gov)
    with pytest.raises(ExtensionError, match="not issued by this guard"):
        stranger.grant(dataclasses.replace(late), approved_by="ops")
    guard.records.verify()
    assert check_anchors(guard.records.records(), gov.audit_trail()) == len(guard.records)


def test_a_grant_the_funder_cannot_make_leaves_the_quote_open() -> None:
    gov = BudgetManager()
    gov.open_root("org", "5")
    gov.delegate("org", "support-agent", "5")  # org keeps nothing
    guard = guard_for(gov)
    spend(gov, "support-agent", "4.60")
    quote = quoted(guard.authorize("support-agent", "0.50"))
    with pytest.raises(ExtensionError, match="parent 'org' cannot fund"):
        guard.grant(quote, approved_by="ops")
    assert guard.pending() == (quote,)
    assert "support-agent/ext-1" not in gov.scopes()
    assert gov.available("support-agent") == Decimal("0.40")  # nothing moved
    gov.trip("org", "operator: freeze")
    with pytest.raises(ExtensionError, match="is halted by 'org'"):
        guard.grant(quote, approved_by="ops")


def test_a_grant_never_lifts_a_safety_halt() -> None:
    gov = BudgetManager()
    gov.open_root("solo", "1.00")
    guard = guard_for(gov)
    quote = guard.quote("solo", "2.00")  # asked for directly
    assert quote.requested == Decimal("1.50")
    gov.trip("solo", "operator: suspicious traffic")
    with pytest.raises(ExtensionError, match="reason other than money"):
        guard.grant(quote, approved_by="ops")
    assert gov.is_halted("solo") and gov.available("solo") == Decimal("1.00")


def test_spend_to_date_is_net_of_vendor_refunds() -> None:
    gov = governor()
    spend(gov, "support-agent", "4.60")
    gov.refund("support-agent", "0.10", memo="vendor credit")
    quote = quoted(guard_for(gov).authorize("support-agent", "0.80"))
    assert quote.spend.spent == Decimal("4.50") and quote.spend.available == Decimal("0.50")


def test_a_ledger_that_cannot_be_written_quotes_but_cannot_grant(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = str(tmp_path / "gov.db")
    writer = BudgetManager.open_sqlite(path)
    writer.open_root("solo", "1.00")
    spend(writer, "solo", "1.00")
    writer.close()
    reader = BudgetManager.open_sqlite(path, read_only=True)
    guard = guard_for(reader)
    with caplog.at_level(logging.WARNING, logger="interlock.extension"):
        quote = quoted(guard.authorize("solo", "0.20"))
    assert "could not be anchored" in caplog.text  # the quote stands, unanchored
    with pytest.raises(ExtensionError, match="the treasury for 'solo' cannot fund"):
        guard.grant(quote, approved_by="ops")
    assert guard.pending() == (quote,)
    reader.close()


def test_a_margin_is_never_negative() -> None:
    with pytest.raises(ValueError, match="margin"):
        guard_for(governor(), margin=Decimal("-0.1"))


# --------------------------------------------------------------------------
# recovery
# --------------------------------------------------------------------------


POLICY = RecoveryPolicy(reserve=Decimal("0.20"), step_estimate=Decimal("0.10"))


def trip() -> Trip:
    return Trip(TripKind.BUDGET, "support-agent")


def test_a_spent_reserve_is_quoted_and_a_grant_lets_recovery_go_on() -> None:
    gov = governor()
    records = RecordLog(HmacKey.generate(), log_id="support")
    guard = BudgetGuard(gov, records)
    runtime = RecoveryRuntime(gov, "support-agent", POLICY, records, guard=guard)
    step = runtime.recover(trip(), HISTORY, max_tokens=4096)  # ceiling
    runtime.settle(step, "0.08")
    step = runtime.recover(trip(), [*step.messages, REPLY], max_tokens=4096)  # guidance
    runtime.settle(step, "0.08")
    messages = [*step.messages, REPLY]
    looping = Trip(TripKind.THRASHING, "support-agent")  # its guidance is still to give

    with pytest.raises(RecoveryExhaustedError, match="reserve has") as caught:
        runtime.recover(looping, messages, max_tokens=4096)
    quote = caught.value.quote
    assert isinstance(quote, ExtensionRequest)
    assert (quote.scope_id, quote.task) == ("support-agent/recovery", "support-agent")
    assert quote.progress.recovery_steps == 2
    assert "0 plan(s) committed (0 rows); 2 recovery step(s)" in quote.render()
    assert [s for s, _ in quote.spend.scopes] == ["support-agent", "support-agent/recovery"]
    assert (quote.spend.available, quote.requested) == (Decimal("0.04"), Decimal("0.09"))

    unrelated = BudgetGuard(governor(), RecordLog(HmacKey.generate()))
    stray = quoted(unrelated.authorize("support-agent", "9.00"))
    with pytest.raises(RecoveryError, match="not the recovery"):
        runtime.extend(unrelated.grant(stray, approved_by="ops", amount="1.00"))

    grant = guard.grant(quote, approved_by="ops")
    assert grant.scope_id == "support-agent/recovery/ext-1" and grant.carried == Decimal("0.04")
    runtime.extend(grant)
    assert runtime.billing_scope == grant.scope_id
    step = runtime.recover(looping, messages, max_tokens=4096)
    assert step.record.body["hold"]["scope"] == grant.scope_id
    runtime.settle(step, "0.02")
    held = runtime.hold("0.05")  # the task's own calls go on, billed there too
    assert isinstance(held, Authorization) and held.scope_id == grant.scope_id
    runtime.capture(held, "0.05")
    assert isinstance(runtime.hold("9.00"), ExtensionRequest)

    closed = runtime.close()
    assert closed is not None
    assert closed.body["scopes"] == ["support-agent/recovery", grant.scope_id]
    assert Decimal(closed.body["spent"]) == Decimal("0.23")
    assert Decimal(closed.body["returned"]) == Decimal("0.06")
    records.verify()
    assert check_anchors(records.records(), gov.audit_trail()) == len(records)
    gov.verify_integrity()


def test_a_recovery_scope_spent_to_zero_is_quoted_and_a_restart_keeps_the_grant() -> None:
    gov = governor()
    records = RecordLog(HmacKey.generate(), log_id="support")
    guard = BudgetGuard(gov, records)
    policy = dataclasses.replace(POLICY, reserve=Decimal("0.10"))
    runtime = RecoveryRuntime(gov, "support-agent", policy, records, guard=guard)
    step = runtime.recover(trip(), HISTORY, max_tokens=4096)
    runtime.settle(step, "0.10")  # to zero: AgentGov trips the recovery scope
    with pytest.raises(RecoveryExhaustedError, match="halted") as caught:
        runtime.recover(trip(), [*step.messages, REPLY], max_tokens=4096)
    quote = caught.value.quote
    assert isinstance(quote, ExtensionRequest)
    assert quote.halted_by == "spend envelope exhausted"
    grant = guard.grant(quote, approved_by="ops")
    runtime.extend(grant)
    resumed = runtime.recover(trip(), [*step.messages, REPLY], max_tokens=4096)
    assert resumed.record.body["hold"]["scope"] == grant.scope_id

    # A runtime restarted over the same records bills where the grant put it.
    runtime.settle(resumed, "0.01")
    again = RecoveryRuntime(gov, "support-agent", policy, records, guard=guard)
    assert again.billing_scope == grant.scope_id
    assert again.opened.body["adopted"]["billing"] == grant.scope_id


def test_without_a_guard_a_spent_reserve_carries_no_quote() -> None:
    gov = governor()
    runtime = RecoveryRuntime(
        gov,
        "support-agent",
        dataclasses.replace(POLICY, reserve=Decimal("0.10")),
        RecordLog(HmacKey.generate()),
    )
    step = runtime.recover(trip(), HISTORY, max_tokens=4096)
    runtime.settle(step, "0.05")
    with pytest.raises(RecoveryExhaustedError) as caught:
        runtime.recover(trip(), [*step.messages, REPLY], max_tokens=4096)
    assert caught.value.quote is None


def test_a_quote_record_names_its_ledger_position() -> None:
    gov = governor()
    guard = guard_for(gov)
    spend(gov, "support-agent", "4.60")
    before = len(gov.ledger)
    quote = quoted(guard.authorize("support-agent", "0.50"))
    assert quote.record.body["ledger"]["sequence"] == before
    assert quote.expires_at - quote.issued_at == timedelta(hours=1)
