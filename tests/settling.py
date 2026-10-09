"""Settlement's bench, for ``tests/test_settlement.py`` and the crash child
``tests/settle_child.py``.

A back office whose engine issues ARC1 receipts into a receipt log and charges
every plan to the AgentGov ledger: its settle cost, and each request's
``cost_per_call``. A ``bookings`` sink whose ``book`` is undone by ``cancel``,
each booking moving a customer amount (``FIAT``) that is nobody's budget.
Relays that attest; an operator who compensates.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentgov.receipts import ActionReceipt, DeliveryReceipt, HmacKey, ReceiptLog, verify_bundle

from interlock import BlastRadius, EscrowChain, EscrowEngine, LedgerAnchor, PlanBuilder
from interlock.adapters import HttpAdapter
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec, bind
from interlock.receipts import ReceiptIssuer
from interlock.relay import NoBreaker, Relay
from interlock.settlement import Settler
from interlock.types import EffectId, OutboundRequest, outbound_key
from tests.outbox_env import RELAY_SINKS, RELAYS, SCOPE, Outbox, relay_signer

BOOKINGS = SinkSpec(
    "bookings",
    (OperationSpec("book", compensation="cancel"), OperationSpec("cancel")),
    cost_per_call=Decimal("0.25"),
    backoff_base=timedelta(milliseconds=20),
    backoff_cap=timedelta(milliseconds=160),
)
SINKS = (*RELAY_SINKS, BOOKINGS)
REGISTRY = SinkRegistry(SINKS)
ROUTES = {"book": "POST /bookings/book", "cancel": "POST /bookings/cancel"}
LOG_ID = "settlement-receipts"
LOG_KEY = HmacKey(bytes.fromhex("4b" * 32))
ROW_SECRET = bytes.fromhex("5a" * 32)
SETTLE_COST = Decimal("0.05")
FIAT = "500.00"
"""What a booking moves: the customer's money, never the agent's budget."""


def booking(*ns: int, traceparent: str | None = None) -> PlanBuilder:
    """A plan that books each of ``ns``, one request each, in
    ``traceparent``'s trace when given."""
    builder = PlanBuilder(SCOPE, traceparent=traceparent)
    for n in ns:
        builder = builder.enqueue(
            sink="bookings",
            operation="book",
            payload={"booking": n, "amount": FIAT},
            compensation=OutboundRequest("bookings", "cancel", {"booking": n}),
        )
    return builder


class Bench:
    """One back office, its receipt log and escrow chain, ready to book,
    deliver, compensate and settle."""

    def __init__(self, outbox: Outbox, workdir: Path) -> None:
        self.outbox = outbox
        self.workdir = workdir
        outbox.reinstall(SINKS)
        self.log: ReceiptLog = ReceiptLog(LOG_ID, LOG_KEY, path=self.receipts)
        self.issuer = ReceiptIssuer(self.log, row_secret=ROW_SECRET)
        self.chain = EscrowChain(self.chain_path)
        self._sources: list[Any] = []

    @property
    def receipts(self) -> Path:
        return self.workdir / "receipts.jsonl"

    @property
    def chain_path(self) -> Path:
        return self.workdir / "escrow.jsonl"

    def engine(self, *, charged: bool = True) -> EscrowEngine:
        return self.outbox.engine(
            checkers=[BlastRadius(100)],
            sinks=REGISTRY,
            receipts=self.issuer,
            chain=self.chain,
            anchor=LedgerAnchor(governed=self.outbox.governor) if charged else None,
            settle_cost=str(SETTLE_COST),
        )

    def book(self, n: int, *, charged: bool = True) -> uuid.UUID:
        """Commit a plan that books ``n``: its one request."""
        (message,) = self.book_together(n, charged=charged)
        return message

    def book_together(
        self, *ns: int, charged: bool = True, traceparent: str | None = None
    ) -> list[uuid.UUID]:
        """Commit one plan that books each of ``ns``: its requests."""
        plan = booking(*ns, traceparent=traceparent).build()
        result = self.engine(charged=charged).execute(plan)
        assert result.committed, result.feedback
        return self.outbox.messages(plan.plan_id)

    def deliver(self) -> None:
        sink = self.outbox.sink("bookings", honour_keys=True)
        relay = Relay(
            self.outbox.store(),
            adapters={"bookings": HttpAdapter(sink.url, routes=ROUTES)},
            breaker=NoBreaker(),
            signer=relay_signer(),
        )
        with relay:
            self.outbox.drain(relay)

    def compensate(
        self, message: uuid.UUID, *, checkpoint: Callable[[str], None] | None = None
    ) -> uuid.UUID:
        """An operator compensates ``message``, signed: the compensation."""
        with self.outbox.signed("ops", checkpoint=checkpoint) as operator:
            outcome = operator.compensate([message], registry=REGISTRY)
        assert outcome.applied
        (target,) = outcome.intent.body["targets"]
        return uuid.UUID(str(target["compensation"]["message"]))

    def compensate_around(
        self, message: uuid.UUID, authority: str, *, key: str | None = None
    ) -> uuid.UUID:
        """A compensation of ``message`` enqueued around the operators, as the
        database's owner could: through the outbox's own function, under
        ``authority``, with no signed intent naming it; under the key an
        operator would derive, or ``key``. The compensation."""
        operations = self.outbox.operations()
        plan = operations.plan_of(message)
        assert plan is not None
        (original,) = [c for c in operations.compensables(plan) if c.message_id == message]
        document = original.compensation
        assert document is not None
        request = OutboundRequest(
            str(document["sink"]),
            str(document["operation"]),
            bind(document["payload"], original.remote_ref or ""),
        )
        forged = uuid.uuid4()
        assert operations.compensate(
            message,
            actor="operator:dba",
            authority=authority,
            expected_head=original.log_head,
            message_id=forged,
            payload=request.canonical_payload,
            idempotency_key=key or outbound_key(plan, EffectId(f"compensate:{original.effect_id}")),
        )
        return forged

    def source(self) -> Any:
        source = self.outbox.settler()
        self._sources.append(source)
        return source

    def settler(
        self,
        *,
        ledger: bool = True,
        operators: bool = True,
        sinks: SinkRegistry | None = REGISTRY,
        checkpoint: Callable[[str, uuid.UUID], None] | None = None,
    ) -> Settler:
        return Settler(
            self.source(),
            receipts=self.issuer,
            chain=self.chain,
            relays=RELAYS,
            ledger=self.outbox.governor if ledger else None,
            operator_log=self.outbox.operator_log if operators else None,
            operators=self.outbox.keyring() if operators else None,
            sinks=sinks,
            checkpoint=checkpoint,
        )

    def deliveries(self) -> dict[str, list[DeliveryReceipt]]:
        """The log's delivery receipts, by message."""
        found: dict[str, list[DeliveryReceipt]] = {}
        for receipt in self.log.deliveries():
            found.setdefault(receipt.request.message_id, []).append(receipt)
        return found

    def verified(self, receipt: DeliveryReceipt) -> int:
        """agentgov's verdict on a delivery receipt's bundle, its action's
        bundle beside it: the exit code (0 passes)."""
        index = self.log.index_of(receipt.receipt_id)
        action = self.log.index_of(receipt.action.receipt_id)
        assert index is not None and action is not None
        assert isinstance(self.log.receipt(action), ActionReceipt)
        report = verify_bundle(
            self.log.bundle(index),
            issuer_key=LOG_KEY,
            relay_keys=[relay_signer().public_key()],
            action=self.log.bundle(action),
        )
        return report.exit_code

    def scenario(self) -> dict[str, object]:
        """What a settler in another process needs."""
        return {
            **self.outbox.settler_target(),
            "receipts": str(self.receipts),
            "chain": str(self.chain_path),
            "ledger": self.outbox.ledger_path,
            "operator_log": str(self.outbox.operator_log),
            "operators": {name: key.public_key().spec() for name, key in self.outbox.keys.items()},
        }

    def close(self) -> None:
        for source in self._sources:
            source.close()
        self._sources.clear()
        self.log.close()
        self.chain.close()
