"""The process the crash tests kill.

``python -m tests.crash_child <scenario.json>`` builds what a production
process builds: a PostgreSQL substrate staging as the agent's role, a durable
escrow chain, a governed AgentGov ledger that takes each plan's reverse anchor
and settles its cost, and a durable ARC1 receipt log whose checkpoints a
witness cosigns. It resolves whatever a crashed predecessor left open, as a
restarted process does, runs the scenario's plans, and at the scenario's kill
point prints one JSON line saying where it stopped. Then it waits.

The parent ends it with ``SIGKILL``. No ``finally`` runs and nothing is
flushed or closed, so what the parent finds is what a crash at that point
leaves behind.

Kill points, in the order a plan reaches them:

=============  ===============================================================
``apply``      the stage's transaction is open, ``effect`` effects applied
``intent``     ``COMMIT_INTENT`` is on disk; ``COMMIT`` not yet sent
``commit``     about to send ``COMMIT``: the child says so, then sends it, and
               the parent kills it while the server is still committing
``committed``  ``COMMIT`` returned; ``COMMITTED`` not yet appended
``recorded``   ``COMMITTED`` appended; no reverse anchor, no receipt
``anchored``   the reverse anchor settled in the ledger; no receipt yet
``torn``       half of a ``record``-type line written, the rest never
``recovered``  startup recovery appended its first record
=============  ===============================================================

``plan`` picks the plan whose stage stops (the first by default). With no kill
point the child runs every plan, reports ``finished`` and waits: the parent
kills it at a moment of its own choosing.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, NoReturn

from agentgov import BudgetManager
from agentgov.core import LedgerEntry
from agentgov.receipts import CheckpointPolicy, FileWitness, HmacKey, ReceiptLog

from interlock import (
    BlastRadius,
    EscrowChain,
    EscrowEngine,
    LedgerAnchor,
    PlanBuilder,
    PostgresSubstrate,
    ReceiptIssuer,
    TenantDrawdownGuard,
    TenantIsolation,
)
from interlock.chain import EscrowRecord, RecordType
from interlock.types import (
    GENESIS_HASH,
    CommitReceipt,
    Effect,
    EffectId,
    EffectOutcome,
    EffectPlan,
    PlanId,
    StageHandle,
)
from tests.conftest import OBSERVED
from tests.schemas import specs

SCOPE = "support-agent"
LOG_ID = "crash-receipts"
WITNESS_ID = "crash-witness"
ACKNOWLEDGED = ("shipment_events", "ledger_entries")


@dataclass(frozen=True)
class Refund:
    """One refund: a refund row, the customer's credit, the item's count.

    Three tables in one plan, so a crash can only ever leave all three or
    none. The refund row's key is unique per plan and the item's ``qty`` rises
    by one per committed refund, so the database says exactly which plans
    committed, and how many times.
    """

    plan_id: str
    refund_id: int
    amount: Decimal
    globex: bool = False
    """Also credit globex's account: refused by tenant isolation."""

    def to_json(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "refund_id": self.refund_id,
            "amount": str(self.amount),
            "globex": self.globex,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> Refund:
        return cls(
            plan_id=str(raw["plan_id"]),
            refund_id=int(raw["refund_id"]),
            amount=Decimal(str(raw["amount"])),
            globex=bool(raw.get("globex", False)),
        )

    def plan(self) -> EffectPlan:
        builder = (
            PlanBuilder(SCOPE, intent=f"refund {self.plan_id}", plan_id=PlanId(self.plan_id))
            .insert(
                table="refunds",
                statement="INSERT INTO refunds (id, order_item_id, amount) "
                "VALUES (%(id)s, 5000, %(amount)s)",
                parameters={"id": self.refund_id, "amount": self.amount},
                effect_id=EffectId("refund_row"),
                stated_rows=1,
            )
            .update(
                table="accounts",
                statement="UPDATE accounts SET balance = balance + %(amount)s WHERE id = 100",
                parameters={"amount": self.amount},
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
        )
        if self.globex:
            builder.update(
                table="accounts",
                statement="UPDATE accounts SET balance = balance + 0.01 WHERE id = 200",
                tenant_id="globex",
                effect_id=EffectId("globex"),
                stated_rows=1,
            )
        return builder.build()


def checkers() -> list[Any]:
    """The back office's checkers, as tests.plans.pg_engine has them."""
    return [
        TenantIsolation(1),
        BlastRadius(10),
        TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
    ]


@dataclass(frozen=True)
class Kill:
    at: str = ""
    plan: str = ""
    effect: int = 0
    record: str = ""

    def due(self, point: str, plan_id: str) -> bool:
        return self.at == point and (not self.plan or self.plan == plan_id)


def say(event: str, **context: object) -> None:
    print(json.dumps({"event": event, "pid": os.getpid(), **context}, default=str), flush=True)


def stop(point: str, **context: object) -> NoReturn:
    """Say where the process stopped, then wait for SIGKILL."""
    say("stopped", at=point, **context)
    while True:
        time.sleep(3600)


class Substrate(PostgresSubstrate):
    """``PostgresSubstrate``, stopping at the kill points inside a stage."""

    __slots__ = ("_applied", "_kill")

    def __init__(self, dsn: str, kill: Kill, **kwargs: Any) -> None:
        super().__init__(dsn, **kwargs)
        self._kill = kill
        self._applied = 0

    def open(self, plan: EffectPlan) -> StageHandle:
        self._applied = 0
        return super().open(plan)

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        outcome = super().apply(handle, effect)
        self._applied += 1
        if self._kill.due("apply", handle.plan_id) and self._applied == self._kill.effect:
            stop("apply", **self.context(handle))
        return outcome

    def commit(self, handle: StageHandle) -> CommitReceipt:
        if self._kill.due("commit", handle.plan_id):
            say("committing", **self.context(handle))
        receipt = super().commit(handle)
        if self._kill.due("committed", handle.plan_id):
            stop("committed", **self.context(handle))
        return receipt

    def context(self, handle: StageHandle) -> dict[str, object]:
        conn = self._conn
        return {
            "plan_id": handle.plan_id,
            "stage_id": str(handle.stage_id),
            "txid": self.transaction_id(handle),
            "backend_pid": conn.info.backend_pid if conn is not None else None,
        }


class Chain(EscrowChain):
    """``EscrowChain``, stopping at the kill points around its appends."""

    __slots__ = ("_kill",)

    def __init__(self, path: str, kill: Kill) -> None:
        self._kill = kill
        super().__init__(path)

    def append(
        self,
        record_type: RecordType,
        *,
        plan_id: PlanId,
        payload_hash: str,
        stage_id: uuid.UUID | None = None,
        anchored: bool = False,
        agentgov_head_hash: str = GENESIS_HASH,
        agentgov_sequence: int = -1,
        note: str = "",
    ) -> EscrowRecord:
        record = super().append(
            record_type,
            plan_id=plan_id,
            payload_hash=payload_hash,
            stage_id=stage_id,
            anchored=anchored,
            agentgov_head_hash=agentgov_head_hash,
            agentgov_sequence=agentgov_sequence,
            note=note,
        )
        if record_type is RecordType.COMMIT_INTENT and self._kill.due("intent", plan_id):
            stop("intent", **_described(record))
        if record_type is RecordType.COMMITTED and self._kill.due("recorded", plan_id):
            stop("recorded", **_described(record))
        if note.startswith("recovered:") and self._kill.at == "recovered":
            stop("recovered", **_described(record))
        return record

    def _write(self, path: Path, record: EscrowRecord) -> None:
        if record.record_type.value == self._kill.record and self._kill.due("torn", record.plan_id):
            line = (json.dumps(record.to_json(), separators=(",", ":")) + "\n").encode()
            with path.open("ab") as handle:
                handle.write(line[: len(line) // 2])
                handle.flush()
                os.fsync(handle.fileno())
            stop("torn", **_described(record), written=len(line) // 2, length=len(line))
        super()._write(path, record)


class Anchor(LedgerAnchor):
    """``LedgerAnchor``, stopping once the reverse anchor has settled."""

    __slots__ = ("_kill",)

    def __init__(self, governed: BudgetManager, kill: Kill) -> None:
        super().__init__(governed=governed)
        self._kill = kill

    def reverse_anchor(
        self, scope_id: str, record_hash: str, *, cost: Decimal | str = "0"
    ) -> LedgerEntry | None:
        entry = super().reverse_anchor(scope_id, record_hash, cost=cost)
        if self._kill.at == "anchored":
            stop(
                "anchored",
                head=record_hash,
                entry=entry.entry_hash if entry is not None else None,
                memo=entry.memo if entry is not None else None,
            )
        return entry


def _described(record: EscrowRecord) -> dict[str, object]:
    return {
        "plan_id": record.plan_id,
        "stage_id": str(record.stage_id) if record.stage_id else None,
        "sequence": record.sequence,
        "record_hash": record.record_hash,
        "note": record.note,
    }


def build(scenario: Mapping[str, Any], kill: Kill) -> EscrowEngine:
    """The engine a production process builds, from the scenario."""
    substrate = Substrate(
        str(scenario["dsn"]),
        kill,
        tables=specs(*OBSERVED),
        acknowledge_cascades=ACKNOWLEDGED,
        max_stage_seconds=float(scenario.get("stage_seconds", 10.0)),
        lock_timeout_seconds=float(scenario.get("lock_seconds", 2.0)),
    )
    chain = Chain(str(scenario["chain"]), kill)
    governor = BudgetManager.open_sqlite(str(scenario["ledger"]))
    log_key = HmacKey(bytes.fromhex(str(scenario["log_key"])))
    witness = FileWitness(
        str(scenario["witness"]),
        HmacKey(bytes.fromhex(str(scenario["witness_key"]))),
        witness_id=WITNESS_ID,
        logs={LOG_ID: log_key},
    )
    log = ReceiptLog(
        LOG_ID,
        log_key,
        path=str(scenario["receipts"]),
        witnesses=[witness],
        policy=CheckpointPolicy(every_receipts=int(scenario.get("checkpoint_every", 3))),
    )
    return EscrowEngine(
        substrate,
        checkers=checkers(),
        chain=chain,
        anchor=Anchor(governor, kill),
        settle_cost=str(scenario.get("settle", "0.25")),
        receipts=ReceiptIssuer(log, row_secret=bytes.fromhex(str(scenario["row_secret"]))),
    )


def run(scenario: Mapping[str, Any]) -> NoReturn:
    raw_kill: Mapping[str, Any] = scenario.get("kill") or {}
    kill = Kill(
        at=str(raw_kill.get("at", "")),
        plan=str(raw_kill.get("plan", "")),
        effect=int(raw_kill.get("effect", 0)),
        record=str(raw_kill.get("record", "")),
    )
    engine = build(scenario, kill)
    recovered: Sequence[EscrowRecord] = engine.recover() if scenario.get("recover") else ()
    say("started", recovered=[r.sequence for r in recovered])
    for raw in scenario.get("plans", ()):
        engine.execute(Refund.from_json(raw).plan())
    stop("finished", sequence=len(engine.chain))


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
