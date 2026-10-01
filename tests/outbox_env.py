"""What the relay's tests share: a back office with the outbox installed, a
relay role, an AgentGov ledger whose breaker the relay reads, and sinks with
backoff short enough to test.

Three sinks, one per delivery guarantee the relay can give:

- ``mail`` honours idempotency keys: at least once, absorbed to once.
- ``sms`` does not, and redelivers an unknown outcome: at least once, and a
  lost call can act twice.
- ``pager`` does not, and dead-letters an unknown outcome: at most once.

And ``payments``, which honours keys, for refunds checked against their rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
from agentgov import BudgetManager
from psycopg.conninfo import make_conninfo

from interlock import BlastRadius, EscrowEngine, PlanBuilder, PostgresSubstrate
from interlock.adapters import HttpAdapter
from interlock.deliveries import LogEvent, message_log, verify_delivery_log
from interlock.outbound import DEAD_LETTER, OperationSpec, SinkRegistry, SinkSpec
from interlock.postgres import install
from interlock.relay import Breaker, LedgerBreaker, Relay
from interlock.types import EffectId, EffectPlan, OutboundRequest
from tests.conftest import OBSERVED, PASSWORD, Pg, create_role, drop_role
from tests.fakesink import FakeSink
from tests.schemas import MAIL_SEND_SCHEMA, specs

SCOPE = "agent"

_FAST: dict[str, Any] = {
    "backoff_base": timedelta(milliseconds=20),
    "backoff_cap": timedelta(milliseconds=160),
    "max_attempts": 5,
}

RELAY_SINKS: tuple[SinkSpec, ...] = (
    SinkSpec(
        "mail",
        (OperationSpec("send", schema=MAIL_SEND_SCHEMA),),
        cost_per_call=Decimal("0.002"),
        max_payload_bytes=4096,
        **_FAST,
    ),
    SinkSpec("sms", (OperationSpec("send"),), idempotency="none", **_FAST),
    SinkSpec(
        "pager",
        (OperationSpec("page"),),
        idempotency="none",
        unknown_outcome=DEAD_LETTER,
        **_FAST,
    ),
    SinkSpec("payments", (OperationSpec("refund"),), cost_per_call=Decimal("0.01"), **_FAST),
)
REGISTRY = SinkRegistry(RELAY_SINKS)
ROUTES: Mapping[str, Mapping[str, str]] = {
    "mail": {"send": "POST /mail/send"},
    "sms": {"send": "POST /sms/send"},
    "pager": {"page": "POST /pager/page"},
    "payments": {"refund": "POST /payments/refund"},
}


def mail(n: int = 0, **extra: Any) -> OutboundRequest:
    return OutboundRequest(
        "mail", "send", {"to": f"customer{n}@acme.test", "subject": f"note {n}", **extra}
    )


def sms(n: int = 0) -> OutboundRequest:
    return OutboundRequest("sms", "send", {"to": "+15550100", "text": f"note {n}"})


def page(n: int = 0) -> OutboundRequest:
    return OutboundRequest("pager", "page", {"service": "billing", "note": f"note {n}"})


@dataclass
class Outbox:
    pg: Pg
    relay_dsn: str
    relay_role: str
    ledger_path: str
    governor: BudgetManager
    sinks: dict[str, FakeSink] = field(default_factory=dict)

    # -- staging -------------------------------------------------------------

    def engine(self, **kwargs: Any) -> EscrowEngine:
        checkers = kwargs.pop("checkers", [BlastRadius(100)])
        return EscrowEngine(
            PostgresSubstrate(self.pg.agent, tables=specs(*OBSERVED)),
            checkers=checkers,
            sinks=REGISTRY,
            **kwargs,
        )

    def commit(
        self,
        *requests: OutboundRequest,
        scope: str = SCOPE,
        independent: bool = True,
        not_after: timedelta | None = None,
    ) -> tuple[EffectPlan, list[uuid.UUID]]:
        """Commit one plan that enqueues ``requests``, independent of each
        other unless ``independent`` is false (then each waits for the one
        before it). Returns the plan and its messages, in order."""
        builder = PlanBuilder(scope)
        for index, request in enumerate(requests):
            builder.enqueue(
                sink=request.sink,
                operation=request.operation,
                payload=request.payload,
                not_after=not_after or request.not_after,
                effect_id=EffectId(f"r{index}"),
                independent=independent,
            )
        plan = builder.build()
        result = self.engine(checkers=[BlastRadius(0)]).execute(plan)
        assert result.committed, result.feedback
        return plan, self.messages(plan.plan_id)

    def messages(self, plan_id: str) -> list[uuid.UUID]:
        with psycopg.connect(self.pg.admin) as conn:
            return [
                r[0]
                for r in conn.execute(
                    "SELECT message_id FROM interlock.outbox WHERE plan_id = %s ORDER BY seq",
                    (plan_id,),
                )
            ]

    # -- relaying -------------------------------------------------------------

    def sink(self, name: str, *, honour_keys: bool | None = None) -> FakeSink:
        if name not in self.sinks:
            keys = (name in ("mail", "payments")) if honour_keys is None else honour_keys
            self.sinks[name] = FakeSink(honour_keys=keys)
        return self.sinks[name]

    def adapters(self) -> dict[str, HttpAdapter]:
        for name in ROUTES:
            self.sink(name)
        return {
            name: HttpAdapter(sink.url, routes=ROUTES[name]) for name, sink in self.sinks.items()
        }

    def breaker(self) -> LedgerBreaker:
        return LedgerBreaker.open(self.ledger_path)

    def relay(self, *, breaker: Breaker | None = None, **kwargs: Any) -> Relay:
        kwargs.setdefault("lease", timedelta(seconds=10))
        kwargs.setdefault("timeout", timedelta(seconds=2))
        return Relay(
            self.relay_dsn,
            adapters=self.adapters(),
            breaker=breaker or self.breaker(),
            **kwargs,
        )

    def drain(self, relay: Relay, *, rounds: int = 200, pause: float = 0.02) -> None:
        """Run ``relay`` until nothing is pending, leased or due."""
        import time

        for _ in range(rounds):
            report = relay.run_once(limit=50)
            if report.claimed == 0 and not self.unsettled():
                return
            if report.claimed == 0:
                time.sleep(pause)
        raise AssertionError(f"the outbox did not settle: {self.states()}")

    # -- reading -------------------------------------------------------------

    def state(self, message: uuid.UUID) -> str:
        return str(self.row(message)["state"])

    def row(self, message: uuid.UUID) -> dict[str, Any]:
        from psycopg.rows import dict_row

        with psycopg.connect(self.pg.admin, row_factory=dict_row) as conn:
            row = conn.execute(
                "SELECT * FROM interlock.outbox_state WHERE message_id = %s", (message,)
            ).fetchone()
            assert row is not None
            return dict(row)

    def states(self) -> dict[str, int]:
        with psycopg.connect(self.pg.admin) as conn:
            return {
                str(r[0]): int(r[1])
                for r in conn.execute(
                    "SELECT state, count(*) FROM interlock.outbox_state GROUP BY state"
                )
            }

    def unsettled(self) -> int:
        with psycopg.connect(self.pg.admin) as conn:
            row = conn.execute(
                "SELECT count(*) FROM interlock.outbox_state WHERE state IN ('pending', 'leased')"
            ).fetchone()
            return int(row[0]) if row else 0

    def log(self, message: uuid.UUID) -> tuple[LogEvent, ...]:
        with psycopg.connect(self.pg.admin) as conn:
            return message_log(conn, message)

    def events(self, message: uuid.UUID) -> list[tuple[str, int | None]]:
        return [(e.event, e.attempt) for e in self.log(message)]

    def verify(self) -> None:
        with psycopg.connect(self.pg.admin) as conn:
            problems = verify_delivery_log(conn)
        assert problems == (), problems

    def admin(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self.pg.admin, autocommit=True)

    def close(self) -> None:
        for sink in self.sinks.values():
            sink.close()
        self.governor.close()


def build_outbox(pg: Pg, tmp_path: Path) -> Iterator[Outbox]:
    role = f"il_relay_{uuid.uuid4().hex[:8]}"
    create_role(pg.cluster, role)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            install(
                conn,
                specs(*OBSERVED),
                stage_roles=[pg.role],
                sinks=RELAY_SINKS,
                relay_roles=[role],
            )
        ledger = tmp_path / "governor.db"
        governor = BudgetManager.open_sqlite(str(ledger))
        governor.open_root(SCOPE, "100")
        env = Outbox(
            pg=pg,
            relay_dsn=make_conninfo(pg.admin, user=role, password=PASSWORD),
            relay_role=role,
            ledger_path=str(ledger),
            governor=governor,
        )
        try:
            yield env
        finally:
            env.close()
    finally:
        drop_role(pg.cluster, pg.admin, role)
