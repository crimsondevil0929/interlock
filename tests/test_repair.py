"""Checked repair (M2): the largest admissible part of a refused plan, by experiment.

The search is tested three ways:

- Pure, against predicates chosen to break shortcuts: a debit that is only
  admissible with its credit (non-monotonic), dependency chains, a budget
  that runs out, a stage that expires. A property test checks, over random
  dependency graphs and random admissibility, that whatever is proposed was
  admitted, and that with enough budget it is a largest admissible sub-plan.
- Through the engine on the back-office schema, in SQLite and PostgreSQL,
  where every candidate is staged in a savepoint and rolled back. The
  database is byte-for-byte unchanged by a repair.
- With ARC1 receipts: the refusal gets one, the resubmitted proposal's
  receipt names it as ``repair_of``, and both verify with agentgov's own
  verifier, against the ledger when one is attached.
"""

from __future__ import annotations

import dataclasses
import itertools
import logging
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.exceptions import ReceiptLogError
from agentgov.receipts import ActionReceipt, HmacKey, ReceiptLog, verify_bundle
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from interlock import (
    BlastRadius,
    EffectKind,
    EscrowEngine,
    LedgerAnchor,
    PlanBuilder,
    SqliteSubstrate,
    StageResult,
    TenantDrawdownGuard,
    TenantIsolation,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    CyclicPlanError,
    PlanError,
    StageError,
    StageExpiredError,
    SubstrateUnavailableError,
)
from interlock.receipts import ReceiptIssuer
from interlock.repair import Trial, search
from interlock.types import Effect, EffectId, EffectOutcome, EffectPlan, StageHandle
from tests.conftest import OBSERVED, Pg
from tests.schemas import specs

# --------------------------------------------------------------------------
# the search, pure
# --------------------------------------------------------------------------


def dag(*edges: tuple[str, Sequence[str]]) -> EffectPlan:
    """A plan whose effects are named and wired exactly as given."""
    builder = PlanBuilder("agent")
    for name, after in edges:
        builder.add(
            EffectKind.UPDATE,
            table="orders",
            statement="SELECT 1",
            effect_id=EffectId(name),
            after=[EffectId(a) for a in after] if after else None,
            independent=not after,
        )
    return builder.build()


def judge(rule: Callable[[frozenset[str]], bool]) -> tuple[list[frozenset[str]], Any]:
    seen: list[frozenset[str]] = []

    def evaluate(kept: frozenset[EffectId]) -> Trial:
        seen.append(frozenset(kept))
        return Trial(kept=kept, admitted=rule(frozenset(kept)))

    return seen, evaluate


def test_an_admissible_plan_needs_one_trial() -> None:
    plan = dag(("a", ()), ("b", ()))
    seen, evaluate = judge(lambda kept: True)
    result = search(plan, evaluate, max_trials=8)
    assert (result.kept, result.trials, result.exhaustive) == (frozenset({"a", "b"}), 1, True)
    assert seen == [{"a", "b"}]


def test_one_bad_step_is_dropped_and_explained() -> None:
    plan = dag(("a", ()), ("b", ()), ("c", ()))
    _, evaluate = judge(lambda kept: "b" not in kept)
    result = search(plan, evaluate, max_trials=16)
    assert result.kept == frozenset({"a", "c"}) and result.exhaustive
    assert set(result.probes) == {"b"} and not result.probes[EffectId("b")].admitted


def test_a_debit_is_kept_with_the_credit_that_balances_it() -> None:
    """Non-monotonic: the debit alone is refused, the pair is admitted. A
    search that dropped whatever failed on its own would keep only the
    credit; this one keeps both and drops only the step that is wrong."""
    plan = dag(("debit", ()), ("credit", ()), ("other_tenant", ()))

    def rule(kept: frozenset[str]) -> bool:
        return "other_tenant" not in kept and ("debit" not in kept or "credit" in kept)

    seen, evaluate = judge(rule)
    result = search(plan, evaluate, max_trials=16)
    assert result.kept == frozenset({"debit", "credit"}) and result.exhaustive
    assert not rule(frozenset({"debit"}))  # the shortcut's answer would be wrong
    assert frozenset({"debit"}) not in seen  # and the search never needed to ask


def test_dropping_a_step_drops_what_depends_on_it() -> None:
    plan = dag(("a", ()), ("b", ("a",)), ("c", ("b",)))
    _, evaluate = judge(lambda kept: "b" not in kept)
    result = search(plan, evaluate, max_trials=16)
    assert result.kept == frozenset({"a"}) and result.exhaustive
    _, evaluate = judge(lambda kept: "c" not in kept)
    assert search(plan, evaluate, max_trials=16).kept == frozenset({"a", "b"})


def test_only_runnable_sub_plans_are_ever_staged() -> None:
    plan = dag(("a", ()), ("b", ("a",)), ("c", ("a",)), ("d", ("b", "c")))
    deps = {"b": {"a"}, "c": {"a"}, "d": {"b", "c"}}
    seen, evaluate = judge(lambda kept: kept == {"a"})
    search(plan, evaluate, max_trials=64)
    for kept in seen:
        for effect in kept:
            assert deps.get(effect, set()) <= kept
    assert len(seen) == len(set(seen))  # no candidate twice


def test_a_spent_budget_falls_back_to_a_sound_greedy_pass() -> None:
    names = [f"e{i}" for i in range(8)]
    plan = dag(*((n, ()) for n in names))
    admissible = {"e0", "e2", "e4"}
    seen, evaluate = judge(lambda kept: kept <= admissible)
    result = search(plan, evaluate, max_trials=12)
    assert result.stopped == "budget" and not result.exhaustive
    assert result.kept is not None and result.kept <= admissible
    assert result.trials == len(seen) <= 12


def test_nothing_admissible_is_reported_as_such() -> None:
    plan = dag(("a", ()), ("b", ()))
    _, evaluate = judge(lambda kept: False)
    result = search(plan, evaluate, max_trials=16)
    assert result.kept is None and result.exhaustive and result.stopped is None


def test_an_expired_stage_ends_the_search() -> None:
    plan = dag(("a", ()), ("b", ()), ("c", ()))
    calls = 0

    def evaluate(kept: frozenset[EffectId]) -> Trial:
        nonlocal calls
        calls += 1
        if calls == 3:
            return Trial(kept=kept, admitted=False, error=StageExpiredError("expired"))
        return Trial(kept=kept, admitted=False)

    result = search(plan, evaluate, max_trials=32)
    assert (result.stopped, result.kept, calls) == ("expired", None, 3)


def test_the_search_is_deterministic() -> None:
    plan = dag(("a", ()), ("b", ()), ("c", ("a",)), ("d", ()))
    first, evaluate = judge(lambda kept: len(kept) <= 2 and "d" in kept)
    search(plan, evaluate, max_trials=32)
    second, evaluate = judge(lambda kept: len(kept) <= 2 and "d" in kept)
    search(plan, evaluate, max_trials=32)
    assert first == second


def test_a_repair_needs_a_trial() -> None:
    with pytest.raises(ValueError, match="at least one trial"):
        search(dag(("a", ())), judge(lambda k: True)[1], max_trials=0)


def test_a_level_too_wide_to_list_falls_back_to_the_greedy_pass() -> None:
    """201 independent steps: the second level would hold 20,100 candidates,
    past what the search will enumerate, so it stops listing and goes greedy
    with the trials it has left."""
    plan = dag(*((f"e{i:03}", ()) for i in range(201)))
    seen, evaluate = judge(lambda kept: len(kept) <= 150)
    result = search(plan, evaluate, max_trials=1000)
    assert result.stopped == "budget" and not result.exhaustive
    assert result.kept is not None and len(result.kept) == 150
    assert result.trials == len(seen) < 1000


def test_a_stage_expiring_in_the_greedy_pass_keeps_what_it_had() -> None:
    plan = dag(*((f"e{i}", ()) for i in range(8)))
    calls = 0

    def evaluate(kept: frozenset[EffectId]) -> Trial:
        nonlocal calls
        calls += 1
        if calls == 9:
            return Trial(kept=kept, admitted=False, error=StageExpiredError("expired"))
        return Trial(kept=kept, admitted=kept <= {"e0", "e1"})

    result = search(plan, evaluate, max_trials=12)
    assert (result.stopped, result.exhaustive, result.probes) == ("expired", False, {})
    assert result.kept == frozenset({"e0", "e1"})


def down_sets(plan: EffectPlan) -> list[frozenset[str]]:
    ids = [e.effect_id for e in plan.effects]
    deps = {e.effect_id: set(e.depends_on) for e in plan.effects}
    found: list[frozenset[str]] = []
    for size in range(1, len(ids) + 1):
        for combo in itertools.combinations(ids, size):
            kept = frozenset(combo)
            if all(deps[e] <= kept for e in kept):
                found.append(kept)
    return found


@st.composite
def random_plans(draw: st.DrawFn) -> tuple[EffectPlan, frozenset[frozenset[str]]]:
    n = draw(st.integers(1, 6))
    edges: list[tuple[str, Sequence[str]]] = []
    for i in range(n):
        earlier = [f"e{j}" for j in range(i)]
        after = draw(st.lists(st.sampled_from(earlier), unique=True, max_size=2)) if earlier else []
        edges.append((f"e{i}", after))
    plan = dag(*edges)
    candidates = down_sets(plan)
    admissible = draw(st.lists(st.sampled_from(candidates), unique=True)) if candidates else []
    return plan, frozenset(admissible)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(random_plans(), st.integers(1, 40))
def test_proposals_are_admitted_and_largest_when_the_budget_allows(
    case: tuple[EffectPlan, frozenset[frozenset[str]]], budget: int
) -> None:
    plan, admissible = case
    seen, evaluate = judge(lambda kept: kept in admissible)
    result = search(plan, evaluate, max_trials=budget)
    assert result.trials == len(seen) == len(set(seen)) <= budget
    if result.kept is not None:
        assert result.kept in admissible
    if result.exhaustive:
        best = max((len(a) for a in admissible), default=0)
        assert (len(result.kept) if result.kept else 0) == best
    if budget >= len(down_sets(plan)) + len(plan.effects) + 1:
        assert result.exhaustive or result.kept is None


# --------------------------------------------------------------------------
# through the engine: SQLite
# --------------------------------------------------------------------------


def snapshot(path: str) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows: list[tuple[Any, ...]] = []
        for table in ("orders", "order_items", "accounts", "refunds", "shipments"):
            rows += [(table, *r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
        return rows
    finally:
        conn.close()


def support_batch(placeholder: Callable[[str], str] = lambda n: f":{n}") -> EffectPlan:
    """Four corrections for tenant acme, and one that reaches globex."""
    p = placeholder
    return (
        PlanBuilder("support-agent", intent="apply ticket 9001 corrections")
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = 'held' WHERE id = {p('a')}",
            parameters={"a": 500},
            tenant_id="acme",
            effect_id=EffectId("hold_500"),
            independent=True,
        )
        .update(
            table="orders",
            statement=f"UPDATE orders SET total = {p('t')} WHERE id = {p('a')}",
            parameters={"t": 30, "a": 501},
            tenant_id="acme",
            effect_id=EffectId("reprice_501"),
            independent=True,
        )
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = 'held' WHERE id = {p('a')}",
            parameters={"a": 600},
            tenant_id="acme",
            effect_id=EffectId("hold_600"),
            independent=True,
        )
        .update(
            table="order_items",
            statement=f"UPDATE order_items SET qty = qty + 1 WHERE order_id = {p('a')}",
            parameters={"a": 500},
            tenant_id="acme",
            effect_id=EffectId("bump_items_500"),
            after=[EffectId("hold_500")],
        )
        .build()
    )


def transfer(placeholder: Callable[[str], str] = lambda n: f":{n}") -> EffectPlan:
    """A debit and its balancing credit within acme, and a globex write."""
    p = placeholder
    return (
        PlanBuilder("treasury-agent", intent="rebalance acme accounts")
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance - {p('x')} WHERE id = 100",
            parameters={"x": 400},
            tenant_id="acme",
            effect_id=EffectId("debit"),
            independent=True,
        )
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance + {p('x')} WHERE id = 101",
            parameters={"x": 400},
            tenant_id="acme",
            effect_id=EffectId("credit"),
            independent=True,
        )
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance + {p('x')} WHERE id = 200",
            parameters={"x": 1},
            tenant_id="acme",
            effect_id=EffectId("globex_touch"),
            independent=True,
        )
        .build()
    )


def sqlite_engine(path: str, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        SqliteSubstrate(
            path,
            tables=specs("orders", "order_items", "refunds", "shipments", "accounts"),
            acknowledge_cascades=["stock_reservations", "ledger_entries"],
        ),
        checkers=[
            TenantIsolation(1),
            BlastRadius(10),
            TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
        ],
        **kwargs,
    )


def test_repair_keeps_the_acme_work_and_drops_the_globex_step(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    plan = support_batch()
    refused = engine.execute(plan)
    assert not refused.committed and refused.blocked_by == ("tenant_isolation",)

    before = snapshot(back_office)
    repair = engine.repair(plan)
    assert snapshot(back_office) == before  # every trial rolled back

    assert repair.proposal is not None and repair.exhaustive
    assert repair.kept == ("hold_500", "reprice_501", "bump_items_500")
    (dropped,) = repair.dropped
    assert (dropped.effect_id, dropped.cause) == ("hold_600", "refused")
    assert dropped.invariants == ("tenant_isolation",)
    assert repair.proposal.repair_of == plan.plan_id
    text = repair.feedback.render()
    assert "keep hold_500, reprice_501, bump_items_500; drop hold_600" in text
    assert "globex" not in text

    proposed = [r for r in engine.chain.records() if r.record_type is RecordType.REPAIR_PROPOSED]
    assert [r.payload_hash for r in proposed] == [repair.proposal.content_hash()]

    result = engine.execute(repair.proposal)
    assert result.committed
    admitted = [r for r in engine.chain.records() if r.plan_id == repair.proposal.plan_id]
    assert admitted[0].note.startswith(f"repair of {plan.plan_id}")
    engine.chain.verify()


def test_repair_keeps_a_debit_with_its_credit_on_a_real_drawdown_guard(back_office: str) -> None:
    """acme holds 750 across accounts 100 and 101. The debit alone is a 53%
    drawdown for acme and is refused; the debit and credit together move
    nothing and are admitted. The globex write is the only thing wrong."""
    engine = sqlite_engine(back_office)
    plan = transfer()
    assert not engine.execute(plan).committed
    alone = (
        PlanBuilder("treasury-agent")
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance - 400 WHERE id = 100",
            tenant_id="acme",
        )
        .build()
    )
    assert engine.execute(alone).blocked_by == ("tenant_drawdown_guard:accounts.balance",)

    repair = engine.repair(plan)
    assert repair.kept == ("debit", "credit")
    assert [d.effect_id for d in repair.dropped] == ["globex_touch"]
    assert repair.proposal is not None
    assert engine.execute(repair.proposal).committed
    conn = sqlite3.connect(back_office)
    assert conn.execute("SELECT id, balance FROM accounts ORDER BY id").fetchall() == [
        (100, 100),
        (101, 650),
        (200, 900),
    ]
    conn.close()


def test_a_proposal_is_admitted_once_and_only_as_proposed(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    plan = support_batch()
    repair = engine.repair(plan)
    assert repair.proposal is not None

    first, *rest = repair.proposal.effects
    widened = dataclasses.replace(first, statement="UPDATE orders SET status = 'held'")
    altered = dataclasses.replace(repair.proposal, effects=(widened, *rest))
    with pytest.raises(PlanError, match="no such proposal") as caught:
        engine.execute(altered)
    assert caught.value.feedback is not None
    forged = dataclasses.replace(support_batch(), repair_of=plan.plan_id)
    with pytest.raises(PlanError, match="no such proposal"):
        engine.execute(forged)

    assert engine.execute(repair.proposal).committed
    with pytest.raises(PlanError, match="already committed"):
        engine.execute(repair.proposal)


def test_a_proposal_from_another_engine_is_not_recognised(back_office: str) -> None:
    repair = sqlite_engine(back_office).repair(support_batch())
    assert repair.proposal is not None
    with pytest.raises(PlanError, match="no such proposal"):
        sqlite_engine(back_office).execute(repair.proposal)


def test_inadmissible_and_failing_steps_are_dropped_with_their_dependents(back_office: str) -> None:
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'x' WHERE id = 500",
            tenant_id="acme",
            effect_id=EffectId("ok"),
            independent=True,
        )
        .update(
            table="orders",
            statement="DROP TABLE refunds",
            tenant_id="acme",
            effect_id=EffectId("ddl"),
            independent=True,
        )
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'y' WHERE id = 501",
            tenant_id="acme",
            effect_id=EffectId("after_ddl"),
            after=[EffectId("ddl")],
        )
        .update(
            table="orders",
            statement="UPDATE orders SET no_such_column = 1",
            tenant_id="acme",
            effect_id=EffectId("broken"),
            independent=True,
        )
        .delete(
            table="orders",
            statement="DELETE FROM orders WHERE id = 501",
            tenant_id="acme",
            effect_id=EffectId("cascade"),
            independent=True,
        )
        .build()
    )
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("orders")), checkers=[])
    repair = engine.repair(plan)
    assert repair.kept == ("ok",)
    causes = {
        d.effect_id: (d.cause, [c.guidance.value for c in d.constraints]) for d in repair.dropped
    }
    assert causes == {
        "ddl": ("inadmissible", ["statement_kind"]),
        "after_ddl": ("depends", []),
        "broken": ("refused", ["statement_failed"]),
        "cascade": ("refused", ["cascade"]),
    }
    assert "no_such_column" not in repair.feedback.render()


def test_an_admissible_plan_needs_no_repair(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'x' WHERE id = 500",
            tenant_id="acme",
        )
        .build()
    )
    repair = engine.repair(plan)
    assert repair.already_admissible and repair.proposal is None and repair.trials == 1
    assert "admissible as it stands" in repair.feedback.render()


def test_nothing_admissible_says_so(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET status = 'x'", tenant_id="acme")
        .build()
    )
    repair = engine.repair(plan)
    assert repair.proposal is None and not repair.already_admissible
    assert "needs rewriting" in repair.feedback.render()
    assert not [r for r in engine.chain.records() if r.record_type is RecordType.REPAIR_PROPOSED]


def test_a_substrate_without_savepoints_cannot_repair(back_office: str) -> None:
    class Plain:
        def __init__(self, inner: SqliteSubstrate) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            if name in ("savepoint", "rollback_to"):
                raise AttributeError(name)
            return getattr(self._inner, name)

    engine = EscrowEngine(Plain(SqliteSubstrate(back_office, tables=specs("orders"))), checkers=[])
    with pytest.raises(StageError, match="savepoints"):
        engine.repair(support_batch())


def test_savepoints_roll_the_measurement_back_too(back_office: str) -> None:
    substrate = SqliteSubstrate(back_office, tables=specs("orders"))
    plan = support_batch()
    handle = substrate.open(plan)
    try:
        substrate.savepoint(handle, "mark")
        substrate.apply(handle, plan.effects[0])
        assert substrate.diff(handle).blast_radius == 1
        substrate.rollback_to(handle, "mark")
        assert substrate.diff(handle).blast_radius == 0
        substrate.apply(handle, plan.effects[0])
        substrate.release_savepoint(handle, "mark")
        assert substrate.diff(handle).blast_radius == 1
        with pytest.raises(StageError):
            substrate.rollback_to(handle, "mark")
        with pytest.raises(ValueError):
            substrate.savepoint(handle, "bad name")
    finally:
        substrate.close(handle)


def test_repair_checks_the_plan_as_admission_would(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    plan = support_batch()
    with pytest.raises(ValueError, match="at least one trial"):
        engine.repair(plan, max_trials=0)
    first, second, *rest = plan.effects
    cyclic = dataclasses.replace(
        plan,
        effects=(
            dataclasses.replace(first, depends_on=(second.effect_id,)),
            dataclasses.replace(second, depends_on=(first.effect_id,)),
            *rest,
        ),
    )
    with pytest.raises(CyclicPlanError) as caught:
        engine.repair(cyclic)
    assert caught.value.feedback is not None
    assert not engine.chain.records()


def test_steps_admission_would_refuse_are_dropped_before_anything_is_staged(
    back_office: str,
) -> None:
    plan = (
        PlanBuilder("agent")
        .update(
            table="customers",
            statement="UPDATE customers SET email = 'x' WHERE id = 10",
            tenant_id="acme",
            effect_id=EffectId("unobserved"),
            independent=True,
        )
        .update(
            table="warehouse:orders",
            statement="UPDATE orders SET status = 'x' WHERE id = 500",
            tenant_id="acme",
            effect_id=EffectId("elsewhere"),
            independent=True,
        )
        .delete(
            table="orders",
            statement="DELETE FROM orders WHERE id = 501",
            tenant_id="acme",
            effect_id=EffectId("no_undo"),
            independent=True,
            reversible=False,
        )
        .build()
    )
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("orders")), checkers=[])
    repair = engine.repair(plan)
    assert (repair.proposal, repair.trials, repair.exhaustive) == (None, 0, True)
    causes = {d.effect_id: d.cause for d in repair.dropped}
    assert causes == dict.fromkeys(("unobserved", "elsewhere", "no_undo"), "inadmissible")
    assert not engine.chain.records()


def test_a_small_budget_still_proposes_an_admitted_plan(back_office: str) -> None:
    engine = sqlite_engine(back_office)
    repair = engine.repair(support_batch(), max_trials=3)
    assert (repair.stopped, repair.exhaustive, repair.trials) == ("budget", False, 3)
    assert repair.kept == ("hold_500",)
    assert {d.effect_id: d.cause for d in repair.dropped} == dict.fromkeys(
        ("reprice_501", "hold_600", "bump_items_500"), "unevaluated"
    )
    text = repair.feedback.render()
    assert text.startswith("Resubmit a part of the plan") and "not tried alone" in text
    assert repair.proposal is not None and engine.execute(repair.proposal).committed


def test_a_lost_substrate_ends_the_search_and_rolls_the_stage_back(back_office: str) -> None:
    class Lost(SqliteSubstrate):
        applied = 0

        def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
            self.applied += 1
            if self.applied == 3:
                raise SubstrateUnavailableError("connection lost")
            return super().apply(handle, effect)

    engine = EscrowEngine(
        Lost(back_office, tables=specs("orders", "order_items")), checkers=[TenantIsolation(1)]
    )
    before = snapshot(back_office)
    with pytest.raises(SubstrateUnavailableError) as caught:
        engine.repair(support_batch())
    assert caught.value.feedback is not None
    assert snapshot(back_office) == before
    last = engine.chain.records()[-1]
    assert (last.record_type, last.note) == (RecordType.ABORTED, "repair search failed")


def test_a_proposal_is_staged_by_one_caller_at_a_time(back_office: str) -> None:
    entered, release = threading.Event(), threading.Event()

    class Held(SqliteSubstrate):
        hold = False

        def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
            if self.hold:
                entered.set()
                release.wait(10)
            return super().apply(handle, effect)

    substrate = Held(back_office, tables=specs("orders", "order_items"))
    engine = EscrowEngine(substrate, checkers=[TenantIsolation(1)])
    proposal = engine.repair(support_batch()).proposal
    assert proposal is not None
    substrate.hold = True
    results: list[StageResult] = []
    worker = threading.Thread(target=lambda: results.append(engine.execute(proposal)))
    worker.start()
    try:
        assert entered.wait(10)
        with pytest.raises(PlanError, match="being staged already"):
            engine.execute(proposal)
    finally:
        release.set()
        worker.join(10)
    assert [r.committed for r in results] == [True]
    with pytest.raises(PlanError, match="already committed"):
        engine.execute(proposal)


# --------------------------------------------------------------------------
# receipts
# --------------------------------------------------------------------------


def test_the_repaired_plans_receipt_names_the_refusal(back_office: str, tmp_path: Path) -> None:
    key = HmacKey.generate()
    log = ReceiptLog("interlock-test", key, path=tmp_path / "receipts.jsonl")
    engine = sqlite_engine(back_office, receipts=ReceiptIssuer(log, issuer="interlock@test"))

    plan = support_batch()
    refused = engine.execute(plan)
    assert refused.receipt is not None
    assert refused.receipt.outcome.status.value == "refused"
    assert not refused.receipt.decision.admitted

    repair = engine.repair(plan)
    assert repair.receipt is not None and repair.proposal is not None
    committed = engine.execute(repair.proposal)
    assert committed.receipt is not None
    assert committed.receipt.decision.repair_of == repair.receipt.receipt_id
    assert committed.receipt.outcome.status.value == "committed"
    assert committed.receipt.effect.row_count == 4
    assert committed.receipt.intent.plan_hash == repair.proposal.content_hash()

    records = {r.record_hash: r for r in engine.chain.records()}
    for receipt in (refused.receipt, repair.receipt, committed.receipt):
        escrow = receipt.anchors.escrow
        assert escrow is not None
        record = records[escrow.head]
        assert record.sequence == escrow.seq
        assert f"receipt {receipt.receipt_id}" in record.note
        index = log.index_of(receipt.receipt_id)
        assert index is not None
        report = verify_bundle(log.bundle(index, log.checkpoint()), issuer_key=key)
        assert report.passed, report.to_json()
    log.close()


def test_receipts_verify_against_a_governed_ledger(back_office: str, tmp_path: Path) -> None:
    gov = BudgetManager.open_sqlite(str(tmp_path / "gov.db"))
    gov.open_root("org", "10")
    gov.delegate("org", "support-agent", "5")
    key = HmacKey.generate()
    log = ReceiptLog("interlock-test", key)
    engine = sqlite_engine(
        back_office,
        anchor=LedgerAnchor(governed=gov),
        settle_cost="0.25",
        receipts=ReceiptIssuer(log),
    )
    repair = engine.repair(support_batch())
    assert repair.proposal is not None
    result = engine.execute(repair.proposal)
    receipt = result.receipt
    assert receipt is not None
    assert receipt.cost.settled_usd == Decimal("0.25")
    assert len(receipt.cost.ledger_txn_ids) == 1
    assert receipt.authority.scope_path == ("org", "support-agent")
    index = log.index_of(receipt.receipt_id)
    assert index is not None
    report = verify_bundle(log.bundle(index, log.checkpoint()), issuer_key=key, ledger=gov)
    assert report.passed, report.to_json()
    gov.close()


def test_a_receipt_issuer_takes_a_32_byte_row_secret() -> None:
    log = ReceiptLog("interlock-test", HmacKey.generate())
    with pytest.raises(ValueError, match="32 bytes"):
        ReceiptIssuer(log, row_secret=b"short")
    assert ReceiptIssuer(log, row_secret=bytes(32)).log is log


def test_a_receipt_that_cannot_be_issued_leaves_the_commit_standing(
    back_office: str, caplog: pytest.LogCaptureFixture
) -> None:
    class Unissuable(ReceiptIssuer):
        def issue(self, **kwargs: Any) -> ActionReceipt:
            raise ReceiptLogError("witness unreachable")

    log = ReceiptLog("interlock-test", HmacKey.generate())
    engine = sqlite_engine(back_office, receipts=Unissuable(log))
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'x' WHERE id = 500",
            tenant_id="acme",
        )
        .build()
    )
    with caplog.at_level(logging.WARNING, logger="interlock.engine"):
        result = engine.execute(plan)
    assert result.committed and result.receipt is None
    (terminal,) = [r for r in engine.chain.records() if r.record_type is RecordType.COMMITTED]
    named = re.search(r"; receipt ([0-9a-f-]{36})", terminal.note)
    assert named is not None
    assert f"receipt {named.group(1)} for plan {plan.plan_id} could not be issued" in caplog.text


def test_a_receipt_says_what_its_substrate_did_not_check(back_office: str) -> None:
    class Unchecked:
        """A driver that reads no foreign keys and refuses no tables."""

        def __init__(self, inner: SqliteSubstrate) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            if name in ("cascade_report", "enforces_table_access"):
                raise AttributeError(name)
            return getattr(self._inner, name)

    log = ReceiptLog("interlock-test", HmacKey.generate())
    engine = EscrowEngine(
        Unchecked(SqliteSubstrate(back_office, tables=specs("orders"))),
        checkers=[],
        receipts=ReceiptIssuer(log),
    )
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'x' WHERE id = 500",
            tenant_id="acme",
        )
        .build()
    )
    receipt = engine.execute(plan).receipt
    assert receipt is not None
    assert not receipt.coverage.cascade_closed and not receipt.coverage.authorizer_on
    assert receipt.coverage.known_gaps == (
        "foreign-key cascades were not checked",
        "writes to unobserved tables were not refused",
    )


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------


def pg_engine(env: Pg, **kwargs: Any) -> EscrowEngine:
    from interlock import PostgresSubstrate

    return EscrowEngine(
        PostgresSubstrate(
            env.agent,
            tables=specs(*OBSERVED),
            acknowledge_cascades=["shipment_events", "ledger_entries"],
        ),
        checkers=[
            TenantIsolation(1),
            BlastRadius(10),
            TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
        ],
        **kwargs,
    )


def pg_snapshot(env: Pg) -> list[tuple[Any, ...]]:
    import psycopg

    with psycopg.connect(env.admin) as conn:
        rows: list[tuple[Any, ...]] = []
        for table in ("orders", "order_items", "accounts", "refunds", "shipments"):
            rows += [
                (table, *r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            ]
        return rows


def test_postgres_repair_is_non_monotonic_and_leaves_nothing_behind(pg: Pg) -> None:
    engine = pg_engine(pg)
    plan = transfer(lambda n: f"%({n})s")
    before = pg_snapshot(pg)
    repair = engine.repair(plan)
    assert pg_snapshot(pg) == before
    assert repair.kept == ("debit", "credit") and repair.exhaustive
    assert repair.proposal is not None
    assert engine.execute(repair.proposal).committed


def test_postgres_repair_survives_a_trial_the_database_aborts(pg: Pg, tmp_path: Path) -> None:
    """A gated delete aborts PostgreSQL's transaction; the savepoint brings
    the stage back and the search goes on."""
    key = HmacKey.generate()
    log = ReceiptLog("interlock-pg", key)
    from interlock import PostgresSubstrate

    engine = EscrowEngine(
        PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)),
        checkers=[TenantIsolation(1)],
        receipts=ReceiptIssuer(log),
    )
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'held' WHERE id = 500",
            tenant_id="acme",
            effect_id=EffectId("hold"),
            independent=True,
        )
        .delete(
            table="shipments",
            statement="DELETE FROM shipments WHERE id = 700",
            tenant_id="acme",
            effect_id=EffectId("purge_shipment"),
            independent=True,
        )
        .update(
            table="orders",
            statement="UPDATE orders SET total = total WHERE id = 501",
            tenant_id="acme",
            effect_id=EffectId("touch"),
            independent=True,
        )
        .build()
    )
    repair = engine.repair(plan)
    assert repair.kept == ("hold", "touch")
    (dropped,) = repair.dropped
    assert (dropped.effect_id, dropped.cause) == ("purge_shipment", "refused")
    assert [c.guidance.value for c in dropped.constraints] == ["cascade"]
    assert repair.receipt is None  # the whole plan errored: nothing was adjudicated to refuse
    assert repair.proposal is not None
    result = engine.execute(repair.proposal)
    assert result.committed and result.receipt is not None
    assert result.receipt.decision.repair_of is None
    assert result.receipt.outcome.substrate_txid is not None
