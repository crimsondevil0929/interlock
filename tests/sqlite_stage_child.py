"""The process the SQLite crash tests kill (``tests/test_sqlite_stage_crash.py``).

``python -m tests.sqlite_stage_child <scenario.json>`` builds what a production
process builds over SQLite: a substrate staging in the back office's file, the
outbox installed beside it, a durable escrow chain, and a governed AgentGov
ledger that takes each plan's reverse anchor and settles its cost. It resolves
whatever a crashed predecessor left open, runs the scenario's refunds (each
with the customer's email), and at the scenario's kill point prints one JSON
line saying where it stopped. Then it waits for SIGKILL.

Kill points, in the order a plan reaches them:

=============  ===============================================================
``apply``      the stage's ``BEGIN IMMEDIATE`` is open, ``effect`` effects
               applied: with ``effect`` 4, the email is in the stage's outbox
``intent``     ``COMMIT_INTENT`` is on disk; the stage still open
``marked``     the commit marker is written beside the stage's outbox rows;
               ``COMMIT`` has begun running and not yet written anything
``commit``     ``COMMIT`` is running: the child says so and goes on, and the
               parent kills it as soon as it reads that, wherever it got to
``committed``  ``COMMIT`` returned; ``COMMITTED`` not yet appended
``recorded``   ``COMMITTED`` appended; no reverse anchor yet
=============  ===============================================================

With no kill point the child runs every plan, reports ``finished`` and waits:
the parent kills it at a moment of its own choosing.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn

from agentgov import BudgetManager

from interlock import EscrowEngine, PlanBuilder, SqliteSubstrate
from interlock.outbound import SinkRegistry
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectId,
    EffectOutcome,
    EffectPlan,
    PlanId,
    StageHandle,
)
from tests.conftest import OBSERVED
from tests.crash_child import (
    ACKNOWLEDGED,
    SCOPE,
    Anchor,
    Chain,
    Kill,
    Refund,
    checkers,
    say,
    stop,
    windows,
)
from tests.schemas import TEST_SINKS, specs


def plan(refund: Refund) -> EffectPlan:
    """:meth:`Refund.plan`, in SQLite's dialect: three tables and the email."""
    amount = str(refund.amount)
    builder = (
        PlanBuilder(SCOPE, intent=f"refund {refund.plan_id}", plan_id=PlanId(refund.plan_id))
        .insert(
            table="refunds",
            statement="INSERT INTO refunds (id, order_item_id, amount) VALUES (:id, 5000, :amount)",
            parameters={"id": refund.refund_id, "amount": amount},
            effect_id=EffectId("refund_row"),
            stated_rows=1,
        )
        .update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance + :amount WHERE id = 100",
            parameters={"amount": amount},
            tenant_id="acme",
            effect_id=EffectId("credit"),
            stated_rows=1,
        )
        .update(
            table="order_items",
            statement="UPDATE order_items SET qty = qty + 1 WHERE id = 5000",
            effect_id=EffectId("count"),
            stated_rows=1,
        )
        .enqueue(
            sink="mail",
            operation="send",
            payload={
                "to": "customer@acme.test",
                "subject": f"refund {refund.plan_id}",
                "body": f"We refunded {amount}.",
            },
            tenant_id="acme",
            effect_id=EffectId("notify"),
            after=[EffectId("refund_row")],
        )
    )
    if refund.globex:
        builder.update(
            table="accounts",
            statement="UPDATE accounts SET balance = balance + 0.01 WHERE id = 200",
            tenant_id="globex",
            effect_id=EffectId("globex"),
            stated_rows=1,
            after=[EffectId("count")],
        )
    return builder.build()


class Substrate(SqliteSubstrate):
    """``SqliteSubstrate``, stopping at the kill points inside a stage."""

    __slots__ = ("_applied", "_kill")

    def __init__(self, path: str, kill: Kill, **kwargs: Any) -> None:
        super().__init__(path, **kwargs)
        self._kill = kill
        self._applied = 0

    def open(self, plan: EffectPlan) -> StageHandle:
        handle = super().open(plan)
        self._applied = 0
        if self._kill.due("marked", plan.plan_id) or self._kill.due("commit", plan.plan_id):
            # Called as each statement starts to run: for COMMIT, after the
            # marker and every request are written, before anything commits.
            self._require(handle).set_trace_callback(lambda sql: self._traced(sql, handle))
        return handle

    def _traced(self, sql: str, handle: StageHandle) -> None:
        if sql.strip().upper() != "COMMIT":
            return
        if self._kill.due("marked", handle.plan_id):
            stop("marked", **self.context(handle))
        say("committing", **self.context(handle))

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        outcome = super().apply(handle, effect)
        self._applied += 1
        if self._kill.due("apply", handle.plan_id) and self._applied == self._kill.effect:
            stop("apply", **self.context(handle))
        return outcome

    def commit(self, handle: StageHandle) -> CommitReceipt:
        receipt = super().commit(handle)
        if self._kill.due("committed", handle.plan_id):
            stop("committed", **self.context(handle))
        return receipt

    def context(self, handle: StageHandle) -> dict[str, object]:
        return {"plan_id": handle.plan_id, "stage_id": str(handle.stage_id)}


def build(scenario: Mapping[str, Any], kill: Kill) -> EscrowEngine:
    substrate = Substrate(
        str(scenario["database"]),
        kill,
        tables=specs(*OBSERVED),
        acknowledge_cascades=ACKNOWLEDGED,
        max_stage_seconds=float(scenario.get("stage_seconds", 10.0)),
    )
    governor = BudgetManager.open_sqlite(str(scenario["ledger"]))
    return EscrowEngine(
        substrate,
        checkers=checkers(),
        chain=Chain(str(scenario["chain"]), kill),
        anchor=Anchor(governor, kill, same_transaction=False),
        settle_cost=str(scenario.get("settle", "0.25")),
        sinks=SinkRegistry(TEST_SINKS),
        windows=windows(),
    )


def run(scenario: Mapping[str, Any]) -> NoReturn:
    raw_kill: Mapping[str, Any] = scenario.get("kill") or {}
    kill = Kill(
        at=str(raw_kill.get("at", "")),
        plan=str(raw_kill.get("plan", "")),
        effect=int(raw_kill.get("effect", 0)),
    )
    engine = build(scenario, kill)
    recovered = engine.recover() if scenario.get("recover") else ()
    say("started", recovered=[r.sequence for r in recovered], sqlite=sqlite3.sqlite_version)
    for raw in scenario.get("plans", ()):
        engine.execute(plan(Refund.from_json(raw)))
    stop("finished", sequence=len(engine.chain))


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
