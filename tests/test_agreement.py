"""``CrossEffectAgreement``: an outbound request must say what the rows it rides
with say (``docs/OUTBOX_DESIGN.md`` §5.2).

The semantic blind spot a row diff alone leaves: every row can be valid, every
request well-formed, and the two contradict each other. A refund row the plan
inserted for 50.00 beside a refund request for 5000.00 is the shape a
prompt-injected payload takes. The checker reads both halves as measured, the
request back from the outbox and the rows from the capture, and refuses the
plan before it commits: nothing is written, nothing reaches the relay.

First without a database, one rule at a time; then end to end on PostgreSQL,
through a real stage, a real outbox, a real relay and a real HTTP sink.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import BlastRadius, CrossEffectAgreement, PlanBuilder, StageState
from interlock.adjudication import adjudicate
from interlock.feedback import Guidance
from interlock.receipts import checker_records
from interlock.types import (
    EffectDiff,
    EffectId,
    EffectPlan,
    InvariantViolation,
    OutboundDelta,
    RowDelta,
    _frozen,
)

REFUND = CrossEffectAgreement(
    "payments", "refund", field="amount", table="refunds", column="amount"
)
PAIRED = CrossEffectAgreement(
    "payments",
    "refund",
    field="amount",
    table="refunds",
    column="amount",
    key=("order_item", "order_item_id"),
)


def plan() -> EffectPlan:
    """The plan the agent proposed: a refund row, and the refund call."""
    return (
        PlanBuilder("agent")
        .insert(
            table="refunds",
            statement=(
                "INSERT INTO refunds (id, order_item_id, amount) VALUES (%(id)s, 5000, %(a)s)"
            ),
            parameters={"id": 9100, "a": "50.00"},
            effect_id=EffectId("row"),
        )
        .enqueue(
            sink="payments",
            operation="refund",
            payload={"order_item": 5000, "amount": "50.00"},
            effect_id=EffectId("pay"),
        )
        .build()
    )


def row(refund: int, amount: str, *, item: int = 5000, table: str = "refunds") -> RowDelta:
    return RowDelta(
        table,
        str(refund),
        None,
        {"id": refund, "order_item_id": item, "amount": Decimal(amount)},
    )


def request(
    amount: object = "50.00",
    *,
    item: object = 5000,
    sink: str = "payments",
    operation: str = "refund",
    effect: str = "pay",
    **extra: object,
) -> OutboundDelta:
    payload: dict[str, Any] = {"order_item": item, "amount": amount, **extra}
    return OutboundDelta(
        message_id=uuid.uuid4(),
        effect_id=EffectId(effect),
        sink=sink,
        operation=operation,
        tenant_id="acme",
        payload=_frozen(payload),
        payload_hash="h",
        idempotency_key=f"key-{effect}",
    )


def diff(*deltas: RowDelta, outbound: tuple[OutboundDelta, ...] = ()) -> EffectDiff:
    return EffectDiff(
        plan_id=plan().plan_id,
        stage_id=uuid.uuid4(),
        substrate_id="postgres:test",
        computed_at=datetime.now(UTC),
        deltas=deltas,
        outbound=outbound,
    )


def violations(
    checker: CrossEffectAgreement, measured: EffectDiff
) -> tuple[InvariantViolation, ...]:
    return checker.check(plan(), measured)


# --------------------------------------------------------------------------
# the rule
# --------------------------------------------------------------------------


def test_a_request_that_says_what_its_rows_say_passes() -> None:
    assert violations(REFUND, diff(row(9100, "50.00"), outbound=(request("50.00"),))) == ()
    assert violations(REFUND, diff(row(9100, "50.00"), outbound=(request("50"),))) == ()
    assert violations(REFUND, diff(row(9100, "50.00"), outbound=(request(50),))) == ()


def test_an_injected_amount_is_caught_by_arithmetic() -> None:
    (refused,) = violations(REFUND, diff(row(9100, "50.00"), outbound=(request("5000.00"),)))
    assert refused.invariant == "cross_effect_agreement:payments.refund.amount=refunds.amount"
    assert refused.evidence["requested"] == "5000.00"
    assert refused.evidence["measured"] == "50.00"
    assert "asks for 5000.00 at amount" in refused.message


def test_strict_both_ways() -> None:
    """The rule says the two go together: an extra refund call with no refund
    row, and a refund row with no call, are both refused."""
    (alone,) = violations(REFUND, diff(outbound=(request("50.00"),)))
    assert "has no refunds rows to agree with" in alone.message
    (unpaid,) = violations(REFUND, diff(row(9100, "50.00")))
    assert "with no payments.refund request" in unpaid.message
    assert violations(REFUND, diff()) == ()


def test_requests_and_rows_it_does_not_govern_are_ignored() -> None:
    other = request("5000.00", sink="mail", operation="send")
    elsewhere = row(1, "5000.00", table="ledger_entries")
    assert violations(REFUND, diff(elsewhere, outbound=(other,))) == ()


def test_without_a_key_the_totals_must_agree() -> None:
    both = diff(
        row(9100, "25.00"),
        row(9101, "25.00", item=5001),
        outbound=(request("30.00"), request("20.00", item=5001, effect="pay2")),
    )
    assert violations(REFUND, both) == (), "the totals agree"
    paired = violations(PAIRED, both)
    assert sorted(v.evidence["key"] for v in paired) == ["5000", "5001"]
    assert {(v.evidence["requested"], v.evidence["measured"]) for v in paired} == {
        ("30.00", "25.00"),
        ("20.00", "25.00"),
    }


def test_a_key_pairs_each_request_with_its_own_rows() -> None:
    fine = diff(
        row(9100, "30.00"),
        row(9101, "20.00", item=5001),
        outbound=(request("30.00"), request("20.00", item=5001, effect="pay2")),
    )
    assert violations(PAIRED, fine) == ()
    (stray,) = violations(
        PAIRED, diff(row(9100, "30.00"), outbound=(request("30.00"), request("9.00", item=5002)))
    )
    assert stray.evidence["key"] == "5002" and "has no refunds rows" in stray.message
    (keyless,) = violations(
        PAIRED,
        diff(row(9100, "30.00"), outbound=(request("30.00"), request("1.00", item=None))),
    )
    assert "has no order_item" in keyless.message


def test_net_holds_a_credit_to_the_balance_it_moves() -> None:
    credit = CrossEffectAgreement(
        "payments", "refund", field="amount", table="accounts", column="balance", measure="net"
    )
    moved = RowDelta(
        "accounts",
        "100",
        {"id": 100, "balance": Decimal("500.00")},
        {"id": 100, "balance": Decimal("550.00")},
    )
    assert violations(credit, diff(moved, outbound=(request("50.00"),))) == ()
    (refused,) = violations(credit, diff(moved, outbound=(request("500.00"),)))
    assert (refused.evidence["requested"], refused.evidence["measured"]) == ("500.00", "50.00")
    opened = RowDelta("accounts", "101", None, {"id": 101, "balance": Decimal("50.00")})
    assert violations(credit, diff(opened, outbound=(request("50.00"),))) == ()


def test_value_compares_exactly() -> None:
    currency = CrossEffectAgreement(
        "payments",
        "refund",
        field="currency",
        table="refunds",
        column="currency",
        measure="value",
    )

    def priced(code: object) -> RowDelta:
        return RowDelta("refunds", "9100", None, {"id": 9100, "currency": code})

    assert violations(currency, diff(priced("USD"), outbound=(request(currency="USD"),))) == ()
    (wrong,) = violations(currency, diff(priced("USD"), outbound=(request(currency="EUR"),)))
    assert "EUR" not in wrong.message and "USD" not in wrong.message, "values are not echoed"
    split = diff(
        priced("USD"),
        RowDelta("refunds", "9101", None, {"id": 9101, "currency": "EUR"}),
        outbound=(request(currency="USD"),),
    )
    (disagreeing,) = violations(currency, split)
    assert "2 different currency values" in disagreeing.message
    assert violations(currency, diff(priced(9100), outbound=(request(currency="9100"),))) == ()
    assert violations(currency, diff(priced(7), outbound=(request(currency="007"),)))
    assert violations(currency, diff(priced("USD"), outbound=(request(),)))
    assert violations(currency, diff(priced(None), outbound=(request(currency=None),)))


def test_the_field_is_a_path_into_the_payload() -> None:
    nested = CrossEffectAgreement(
        "payments", "refund", field="refund.lines.0.amount", table="refunds", column="amount"
    )
    deep = request(refund={"lines": [{"amount": "50.00"}]})
    assert violations(nested, diff(row(9100, "50.00"), outbound=(deep,))) == ()
    shallow = request(refund={"lines": []})
    (missing,) = violations(nested, diff(row(9100, "50.00"), outbound=(shallow,)))
    assert "carries no number at refund.lines.0.amount" in missing.message
    (words,) = violations(REFUND, diff(row(9100, "50.00"), outbound=(request("fifty"),)))
    assert "carries no number" in words.message
    (flagged,) = violations(REFUND, diff(row(9100, "50.00"), outbound=(request(True),)))
    assert "carries no number" in flagged.message


def test_a_row_without_a_number_is_a_disagreement() -> None:
    blank = RowDelta("refunds", "9100", None, {"id": 9100, "order_item_id": 5000, "amount": None})
    (refused,) = violations(REFUND, diff(blank, outbound=(request("50.00"),)))
    assert "holds no number in amount" in refused.message


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"measure": "average"}, "measure"),
        ({"field": ""}, "field"),
        ({"table": " "}, "table"),
        ({"key": ("order_item",)}, "pair"),
        ({"key": ("order_item", "")}, "pair"),
    ],
)
def test_a_rule_that_cannot_be_checked_is_refused(kwargs: dict[str, Any], match: str) -> None:
    arguments: dict[str, Any] = {"field": "amount", "table": "refunds", "column": "amount"}
    with pytest.raises(ValueError, match=match):
        CrossEffectAgreement("payments", "refund", **(arguments | kwargs))


# --------------------------------------------------------------------------
# what the agent and the operator are told
# --------------------------------------------------------------------------


def test_the_agent_is_told_the_rule_and_never_the_amounts() -> None:
    judged = adjudicate(
        plan(),
        diff(row(9100, "50.00"), outbound=(request("5000.00"),)),
        [REFUND],
        stage_id=uuid.uuid4(),
    )
    assert not judged.admitted
    feedback = judged.feedback(committed=False)
    (constraint,) = feedback.constraints
    assert constraint.guidance is Guidance.OUTBOUND_AGREEMENT
    text = feedback.render() + json.dumps(feedback.to_json())
    assert "cross_effect_agreement" in text
    assert "refunds.amount" in text, "the plan names refunds, so its column may be named"
    assert "5000" not in text and "50.00" not in text
    (operator,) = judged.refusal().evidence.violations
    assert operator.evidence["requested"] == "5000.00", "the operator sees the amounts"


def test_each_configuration_is_its_own_record() -> None:
    (one,) = checker_records([REFUND])
    (two,) = checker_records([PAIRED])
    assert one.name == two.name and one.config_hash != two.config_hash


# --------------------------------------------------------------------------
# end to end, on each store
# --------------------------------------------------------------------------

from tests.outbox_env import BACKENDS, Outbox, build_either  # noqa: E402


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def refund_plan(
    outbox: Outbox, refund: int, recorded: str, requested: str | None, *, item: int = 5000
) -> EffectPlan:
    builder = PlanBuilder("agent", intent=f"refund {refund}")
    value = outbox.named
    builder.insert(
        table="refunds",
        statement=(
            "INSERT INTO refunds (id, order_item_id, amount) "
            f"VALUES ({value('id')}, {value('item')}, {value('amount')})"
        ),
        parameters={"id": refund, "item": item, "amount": recorded},
        effect_id=EffectId("row"),
        stated_rows=1,
    )
    if requested is not None:
        builder.enqueue(
            sink="payments",
            operation="refund",
            payload={"order_item": item, "amount": requested},
            effect_id=EffectId("pay"),
        )
    return builder.build()


def refunds(outbox: Outbox) -> dict[int, Decimal]:
    return {
        int(r[0]): Decimal(str(r[1]))
        for r in outbox.fetch("SELECT id, amount FROM refunds WHERE id >= 9100")
    }


def outboxed(outbox: Outbox) -> int:
    return outbox.requests()


def test_an_injected_refund_is_refused_before_commit_and_never_sent(outbox: Outbox) -> None:
    """The agent inserts the refund row the ticket asked for, 50.00, and is
    talked by a tool result into asking the payment API for 5000.00. The
    rows and the request are both well-formed; together they contradict each
    other, and the plan is refused: no row, no request, no call."""
    engine = outbox.engine(checkers=[BlastRadius(10), PAIRED])
    result = engine.execute(refund_plan(outbox, 9100, recorded="50.00", requested="5000.00"))
    assert not result.committed and result.state is StageState.ABORTED
    assert result.verdict is not None
    (blocked,) = result.verdict.blocking
    assert blocked.invariant.startswith("cross_effect_agreement")
    assert blocked.evidence["requested"] == "5000.00"
    # What the database holds: SQLite keeps a NUMERIC 50.00 as the integer 50.
    assert Decimal(str(blocked.evidence["measured"])) == Decimal("50.00")
    assert result.diff is not None and result.diff.outbound, "it was judged on the stored request"
    assert refunds(outbox) == {} and outboxed(outbox) == 0
    with outbox.relay() as relay:
        assert relay.run_once(limit=10).claimed == 0
    assert outbox.sink("payments").calls == []
    assert result.feedback is not None and "5000" not in result.feedback.render()

    # The honest plan commits, and the relay sends exactly what the row says.
    assert engine.execute(refund_plan(outbox, 9101, recorded="50.00", requested="50.00")).committed
    with outbox.relay() as relay:
        outbox.drain(relay)
    (call,) = outbox.sink("payments").calls
    assert json.loads(call.body)["amount"] == "50.00"
    assert refunds(outbox) == {9101: Decimal("50.00")}


def test_a_refund_call_with_no_refund_row_is_refused(outbox: Outbox) -> None:
    """The other injection: an extra call riding on an unrelated plan."""
    engine = outbox.engine(checkers=[BlastRadius(10), PAIRED])
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'refunded' WHERE id = 500",
            effect_id=EffectId("status"),
        )
        .enqueue(
            sink="payments",
            operation="refund",
            payload={"order_item": 5000, "amount": "5000.00"},
            effect_id=EffectId("pay"),
        )
        .build()
    )
    result = engine.execute(plan)
    assert not result.committed
    assert result.verdict is not None
    (blocked,) = result.verdict.blocking
    assert "has no refunds rows to agree with" in blocked.message
    assert outboxed(outbox) == 0


def test_a_refund_row_with_no_call_is_refused(outbox: Outbox) -> None:
    engine = outbox.engine(checkers=[BlastRadius(10), PAIRED])
    result = engine.execute(refund_plan(outbox, 9100, recorded="50.00", requested=None))
    assert not result.committed
    assert result.verdict is not None
    (blocked,) = result.verdict.blocking
    assert "with no payments.refund request" in blocked.message
    assert refunds(outbox) == {}
