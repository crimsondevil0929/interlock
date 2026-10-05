"""``FactAgreement`` (``docs/EPIC5_DESIGN.md`` §2.7), as a pure function of the
plan and the measured diff: every write of the guarded column must hold what
a consumed fact of the named kind says, keyed to the row when a key is
configured, a fact and a row naming the same tenant when both name one.

The agent is told the rule, never the values: what the vendor said and what
the row held are data.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Any

import pytest

from interlock import FactAgreement, PlanBuilder
from interlock.adjudication import adjudicate
from interlock.feedback import Guidance
from interlock.invariants import BUILT_IN_CHECKERS
from interlock.types import EffectDiff, EffectPlan, InboundFact, InvariantViolation, RowDelta

PLAN: EffectPlan = (
    PlanBuilder("agent")
    .update(table="refunds", statement="UPDATE refunds SET status = 'x'", stated_rows=1)
    .build()
)


def fact(
    kind: str = "charge.refund.updated", tenant: str | None = None, **fields: Any
) -> InboundFact:
    """A consumed fact saying ``fields``."""
    return InboundFact(
        fact_id=uuid.uuid4(),
        source="stripe",
        event_seq=1,
        event_hash="0" * 64,
        message_id=uuid.uuid4(),
        delivery_seq=2,
        delivery_hash="1" * 64,
        remote_ref="re_1",
        scope_id="agent",
        plan_id="plan-1",
        tenant_id=tenant,
        attestation="{}",
        event_id="evt_1",
        kind=kind,
        vendor_at=None,
        received_at=datetime.now(UTC),
        body_hash="2" * 64,
        part=0,
        refs=("re_1",),
        fields=MappingProxyType(dict(fields)),
        withheld=(),
        event_attestation="{}",
    )


def inserted(status: object, *, key: int = 1, tenant: str | None = None, **extra: Any) -> RowDelta:
    return RowDelta(
        "refunds", str(key), None, {"id": key, "status": status, **extra}, tenant_id=tenant
    )


def updated(before: object, after: object, *, key: int = 1, **extra: Any) -> RowDelta:
    return RowDelta(
        "refunds",
        str(key),
        {"id": key, "status": before, **extra},
        {"id": key, "status": after, **extra},
    )


def diff(*rows: RowDelta, facts: tuple[InboundFact, ...] = ()) -> EffectDiff:
    return EffectDiff(
        plan_id=PLAN.plan_id,
        stage_id=uuid.uuid4(),
        substrate_id="sqlite",
        computed_at=datetime.now(UTC),
        deltas=rows,
        facts=facts,
    )


def agreement(**kwargs: Any) -> FactAgreement:
    kwargs.setdefault("field", "status")
    kwargs.setdefault("table", "refunds")
    kwargs.setdefault("column", "status")
    return FactAgreement(kwargs.pop("kind", "charge.refund.updated"), **kwargs)


def check(
    checker: FactAgreement, *rows: RowDelta, facts: tuple[InboundFact, ...] = ()
) -> list[str]:
    found: tuple[InvariantViolation, ...] = checker.check(PLAN, diff(*rows, facts=facts))
    return [v.message for v in found]


def test_a_write_the_fact_says_passes() -> None:
    assert check(agreement(), inserted("failed"), facts=(fact(status="failed"),)) == []
    assert check(agreement(), updated("pending", "failed"), facts=(fact(status="failed"),)) == []


def test_a_write_no_fact_says_is_refused() -> None:
    (message,) = check(agreement(), updated("pending", "failed"))
    assert message == (
        "the plan writes refunds.status without consuming a charge.refund.updated fact about "
        "that row"
    )


def test_a_write_other_than_the_fact_says_is_refused() -> None:
    (message,) = check(agreement(), updated("pending", "failed"), facts=(fact(status="succeeded"),))
    assert message == (
        "the plan writes refunds.status other than the status its charge.refund.updated fact says"
    )


def test_only_writes_of_the_column_are_held() -> None:
    checker = agreement()
    # Unchanged by an update; a delete writes nothing; another table.
    assert check(checker, updated("pending", "pending", amount=1)) == []
    assert check(checker, RowDelta("refunds", "1", {"id": 1, "status": "x"}, None)) == []
    assert check(checker, RowDelta("orders", "1", None, {"id": 1, "status": "failed"})) == []
    # An insert without the column, as the substrate measured it.
    assert check(checker, RowDelta("refunds", "1", None, {"id": 1})) == []
    # Tables compare as SQL folds them.
    assert check(agreement(table="REFUNDS"), inserted("failed")) != []


def test_an_exempt_value_needs_no_fact() -> None:
    checker = agreement(exempt=["pending", None])
    assert check(checker, inserted("pending")) == []
    assert check(checker, updated("failed", None)) == []
    assert check(checker, inserted("failed")) != []


def test_an_empty_or_unscalar_write_is_held_unless_exempt() -> None:
    checker = agreement()
    (message,) = check(checker, inserted(None), facts=(fact(status="failed"),))
    assert "a value no fact can hold" in message
    (message,) = check(checker, inserted(["failed"]), facts=(fact(status="failed"),))
    assert "a value no fact can hold" in message


def test_a_fact_without_the_field_justifies_nothing() -> None:
    (message,) = check(agreement(), inserted("failed"), facts=(fact(amount=2500),))
    assert "other than the status" in message


def test_numbers_compare_exactly_as_decimals() -> None:
    checker = agreement(field="amount", column="amount")
    row = RowDelta("refunds", "1", None, {"id": 1, "amount": Decimal("25.00")})
    assert check(checker, row, facts=(fact(amount="25"),)) == []
    assert check(checker, row, facts=(fact(amount=25),)) == []
    assert check(checker, row, facts=(fact(amount="25.01"),)) != []
    # Text is itself: "007" is not 7.
    code = agreement()
    assert check(code, inserted("007"), facts=(fact(status="7"),)) != []


def test_only_facts_of_the_kind_count() -> None:
    assert check(agreement(), inserted("failed"), facts=(fact("charge.refunded", status="failed"),))
    either = agreement(kind=["charge.refund.updated", "charge.refunded"])
    assert (
        check(either, inserted("failed"), facts=(fact("charge.refunded", status="failed"),)) == []
    )


def test_a_key_pairs_each_row_with_the_fact_about_it() -> None:
    checker = agreement(key=("id", "vendor_id"))
    mine = fact(status="failed", id="re_1")
    theirs = fact(status="succeeded", id="re_2")
    row = inserted("failed", vendor_id="re_1")
    assert check(checker, row, facts=(mine, theirs)) == []
    # The fact about another refund says what this row holds: still refused.
    (message,) = check(checker, inserted("succeeded", vendor_id="re_1"), facts=(mine, theirs))
    assert "other than the status" in message
    (message,) = check(checker, inserted("failed", vendor_id="re_3"), facts=(mine, theirs))
    assert "without consuming" in message
    (message,) = check(checker, inserted("failed"), facts=(mine,))
    assert message == "a refunds row has no vendor_id to pair it with a charge.refund.updated fact"


def test_a_fact_about_another_tenant_justifies_nothing() -> None:
    checker = agreement()
    row = inserted("failed", tenant="acme")
    assert check(checker, row, facts=(fact(status="failed", tenant="acme"),)) == []
    assert check(checker, row, facts=(fact(status="failed", tenant=None),)) == []
    assert check(checker, row, facts=(fact(status="failed", tenant="globex"),)) != []


def test_every_unjustified_row_is_named() -> None:
    found = agreement().check(
        PLAN, diff(inserted("a", key=1), inserted("b", key=2), facts=(fact(status="a"),))
    )
    assert [(v.evidence["row"], v.severity.value) for v in found] == [("2", "blocking")]
    assert found[0].evidence == {
        "kind": "charge.refund.updated",
        "field": "status",
        "rows": "refunds.status",
        "row": "2",
    }


def test_the_agent_is_told_the_rule_never_the_values() -> None:
    checker = agreement()
    row = inserted("refund-everything-now", tenant="acme")
    judged = adjudicate(
        PLAN,
        diff(row, facts=(fact(status="failed-secret-word"),)),
        [checker],
        stage_id=uuid.UUID(int=0),
    )
    assert not judged.admitted
    feedback = judged.feedback(committed=False)
    (constraint,) = feedback.constraints
    assert constraint.guidance is Guidance.FACT_AGREEMENT
    text = json.dumps(feedback.to_json())
    assert "failed-secret-word" not in text
    assert "refund-everything-now" not in text
    assert "refunds.status" in constraint.render()


def test_its_name_and_configuration() -> None:
    assert agreement().name == "fact_agreement:charge.refund.updated.status=refunds.status"
    assert agreement(kind=["b.x", "a.y"]).name.startswith("fact_agreement:a.y|b.x.")
    assert FactAgreement in BUILT_IN_CHECKERS


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"kind": ""}, "the kind of fact"),
        ({"kind": []}, "the kind of fact"),
        ({"kind": ["a", " "]}, "the kind of fact"),
        ({"field": ""}, "needs a field"),
        ({"table": " "}, "needs a table"),
        ({"column": ""}, "needs a column"),
        ({"key": ("id",)}, "key is a"),
        ({"key": ("id", "")}, "key is a"),
    ],
)
def test_a_rule_that_says_nothing_is_refused(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        agreement(**kwargs)
