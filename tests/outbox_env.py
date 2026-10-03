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

import json
import sqlite3
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
from agentgov import BudgetManager
from psycopg.conninfo import make_conninfo

from interlock import (
    BlastRadius,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
    SqliteSubstrate,
    deliveries,
)
from interlock.adapters import HttpAdapter
from interlock.deliveries import LogEvent, message_log, state_counts, verify_delivery_log
from interlock.outbound import DEAD_LETTER, OperationSpec, SinkRegistry, SinkSpec
from interlock.outbox_store import OutboxStore, PostgresOutboxStore
from interlock.postgres import install
from interlock.relay import Breaker, LedgerBreaker, Relay
from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore, install_sqlite_outbox, now_us
from interlock.types import EffectId, EffectPlan, OutboundRequest
from tests.conftest import (
    OBSERVED,
    PASSWORD,
    Pg,
    build_sqlite_back_office,
    create_role,
    drop_role,
)
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


class Outbox:
    """An outbox to test the relay against, on either store. The shared part
    of a test environment: the sinks, the ledger and its breaker, committing
    requests, running relays, reading states and logs, and an operator's
    actions. :class:`PostgresOutbox` and :class:`SqliteOutbox` supply the
    database."""

    backend = "?"

    def __init__(self, ledger_path: str, governor: BudgetManager) -> None:
        self.ledger_path = ledger_path
        self.governor = governor
        self.sinks: dict[str, FakeSink] = {}

    # -- the database: each backend's own ------------------------------------

    def substrate(self, kind: type[Any] | None = None) -> Any:
        raise NotImplementedError

    def store(self) -> OutboxStore:
        """A relay's store."""
        raise NotImplementedError

    def operator(self) -> Any:
        """A connection or store an operator's actions and reads go through."""
        raise NotImplementedError

    def messages(self, plan_id: str) -> list[uuid.UUID]:
        raise NotImplementedError

    def row(self, message: uuid.UUID) -> dict[str, Any]:
        raise NotImplementedError

    def depends(self, message: uuid.UUID) -> list[str]:
        raise NotImplementedError

    def tamper_payload(self, message: uuid.UUID, payload: str) -> None:
        """Rewrite a stored payload around Interlock: its owner lifting the
        append-only guard."""
        raise NotImplementedError

    def release(self, message: uuid.UUID, *, actor: str) -> bool:
        raise NotImplementedError

    def release_scope(self, scope: str, *, actor: str) -> int:
        raise NotImplementedError

    def cancel(self, message: uuid.UUID, *, actor: str, reason: str) -> bool:
        raise NotImplementedError

    def requeue(self, message: uuid.UUID, *, actor: str) -> int:
        raise NotImplementedError

    def relay_target(self) -> dict[str, str]:
        """Where a relay in another process finds the outbox: the store's
        kind, and its connection string or file."""
        raise NotImplementedError

    def lease_left(self, message: uuid.UUID) -> float:
        """Seconds left on the message's lease, by the database's clock; 0
        when it is not leased."""
        raise NotImplementedError

    def settle(self) -> None:
        """Wait until whatever transactions dead relays had open are gone."""
        raise NotImplementedError

    def reinstall(self, sinks: tuple[SinkSpec, ...]) -> None:
        """Install again, with these sinks."""
        raise NotImplementedError

    def fetch(self, sql: str, *params: object) -> list[tuple[Any, ...]]:
        """Rows of a query in the backend's own dialect, as its owner reads them."""
        raise NotImplementedError

    def named(self, name: str) -> str:
        """A named statement parameter, in the backend's style."""
        raise NotImplementedError

    def requests(self) -> int:
        """How many requests the outbox holds."""
        raise NotImplementedError

    # -- staging -------------------------------------------------------------

    def engine(self, **kwargs: Any) -> EscrowEngine:
        checkers = kwargs.pop("checkers", [BlastRadius(100)])
        substrate = kwargs.pop("substrate", None) or self.substrate()
        sinks = kwargs.pop("sinks", REGISTRY)
        return EscrowEngine(substrate, checkers=checkers, sinks=sinks, **kwargs)

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
            self.store(),
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

    def states(self) -> dict[str, int]:
        return state_counts(self.operator())

    def unsettled(self) -> int:
        counts = self.states()
        return counts.get("pending", 0) + counts.get("leased", 0)

    def log(self, message: uuid.UUID) -> tuple[LogEvent, ...]:
        return message_log(self.operator(), message)

    def events(self, message: uuid.UUID) -> list[tuple[str, int | None]]:
        return [(e.event, e.attempt) for e in self.log(message)]

    def verify(self) -> None:
        problems = verify_delivery_log(self.operator())
        assert problems == (), problems

    def close(self) -> None:
        for sink in self.sinks.values():
            sink.close()
        self.governor.close()


class PostgresOutbox(Outbox):
    backend = "postgres"

    def __init__(
        self, pg: Pg, relay_dsn: str, relay_role: str, ledger_path: str, governor: BudgetManager
    ) -> None:
        super().__init__(ledger_path, governor)
        self.pg = pg
        self.relay_dsn = relay_dsn
        self.relay_role = relay_role
        self._admin: psycopg.Connection[Any] | None = None

    def substrate(self, kind: type[Any] | None = None) -> Any:
        return (kind or PostgresSubstrate)(self.pg.agent, tables=specs(*OBSERVED))

    def store(self) -> OutboxStore:
        return PostgresOutboxStore(self.relay_dsn)

    def admin(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self.pg.admin, autocommit=True)

    def operator(self) -> Any:
        if self._admin is None or self._admin.closed:
            self._admin = self.admin()
        return self._admin

    def messages(self, plan_id: str) -> list[uuid.UUID]:
        return [
            r[0]
            for r in self.operator().execute(
                "SELECT message_id FROM interlock.outbox WHERE plan_id = %s ORDER BY seq",
                (plan_id,),
            )
        ]

    def row(self, message: uuid.UUID) -> dict[str, Any]:
        from psycopg.rows import dict_row

        with psycopg.connect(self.pg.admin, row_factory=dict_row) as conn:
            row = conn.execute(
                "SELECT * FROM interlock.outbox_state WHERE message_id = %s", (message,)
            ).fetchone()
            assert row is not None
            return dict(row)

    def depends(self, message: uuid.UUID) -> list[str]:
        row = (
            self.operator()
            .execute("SELECT depends_on FROM interlock.outbox WHERE message_id = %s", (message,))
            .fetchone()
        )
        return list(row[0])

    def tamper_payload(self, message: uuid.UUID, payload: str) -> None:
        conn = self.operator()
        conn.execute("ALTER TABLE interlock.outbox DISABLE TRIGGER outbox_append_only")
        conn.execute(
            "UPDATE interlock.outbox SET payload = %s::jsonb WHERE message_id = %s",
            (payload, message),
        )
        conn.execute("ALTER TABLE interlock.outbox ENABLE ALWAYS TRIGGER outbox_append_only")

    def release(self, message: uuid.UUID, *, actor: str) -> bool:
        return deliveries.release(self.operator(), message, actor=actor)

    def release_scope(self, scope: str, *, actor: str) -> int:
        return deliveries.release_scope(self.operator(), scope, actor=actor)

    def cancel(self, message: uuid.UUID, *, actor: str, reason: str) -> bool:
        return deliveries.cancel(self.operator(), message, actor=actor, reason=reason)

    def requeue(self, message: uuid.UUID, *, actor: str) -> int:
        return deliveries.requeue(self.operator(), message, actor=actor)

    def relay_target(self) -> dict[str, str]:
        return {"store": "postgres", "dsn": self.relay_dsn}

    def lease_left(self, message: uuid.UUID) -> float:
        row = (
            self.operator()
            .execute(
                "SELECT extract(epoch FROM lease_expires - clock_timestamp()) "
                "FROM interlock.outbox_state WHERE message_id = %s AND state = 'leased'",
                (message,),
            )
            .fetchone()
        )
        return 0.0 if row is None or row[0] is None else max(0.0, float(row[0]))

    def settle(self) -> None:
        """The server ends a dead relay's session, and rolls back what it had
        open, when it notices the connection gone."""
        deadline = time.monotonic() + 30
        while True:
            row = (
                self.operator()
                .execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (self.relay_role,)
                )
                .fetchone()
            )
            if row == (0,):
                return
            if time.monotonic() > deadline:
                raise AssertionError("the dead relays' sessions did not end")
            time.sleep(0.02)

    def reinstall(self, sinks: tuple[SinkSpec, ...]) -> None:
        install(
            self.operator(),
            specs(*OBSERVED),
            stage_roles=[self.pg.role],
            sinks=sinks,
            relay_roles=[self.relay_role],
        )

    def fetch(self, sql: str, *params: object) -> list[tuple[Any, ...]]:
        return [tuple(r) for r in self.operator().execute(sql, params)]

    def named(self, name: str) -> str:
        return f"%({name})s"

    def requests(self) -> int:
        return int(self.fetch("SELECT count(*) FROM interlock.outbox")[0][0])

    def close(self) -> None:
        if self._admin is not None:
            self._admin.close()
        super().close()


class SqliteOutbox(Outbox):
    backend = "sqlite"

    def __init__(self, path: str, ledger_path: str, governor: BudgetManager) -> None:
        super().__init__(ledger_path, governor)
        self.path = path
        self._operator: SqliteOutboxStore | None = None

    def substrate(self, kind: type[Any] | None = None) -> Any:
        return (kind or SqliteSubstrate)(self.path, tables=specs(*OBSERVED))

    def store(self) -> OutboxStore:
        return SqliteOutboxStore(self.path)

    def operator(self) -> SqliteOutboxStore:
        if self._operator is None:
            self._operator = SqliteOutboxStore(self.path, writes=OPERATOR)
        return self._operator

    def raw(self) -> sqlite3.Connection:
        """A plain connection to the file, as its owner might open one: no
        Interlock function registered, no authorizer."""
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def messages(self, plan_id: str) -> list[uuid.UUID]:
        with closing(self.raw()) as conn:
            return [
                uuid.UUID(r[0])
                for r in conn.execute(
                    "SELECT message_id FROM _interlock_outbox WHERE plan_id = ? ORDER BY seq",
                    (plan_id,),
                )
            ]

    def row(self, message: uuid.UUID) -> dict[str, Any]:
        with closing(self.raw()) as conn:
            row = conn.execute(
                "SELECT * FROM _interlock_outbox_state WHERE message_id = ?", (str(message),)
            ).fetchone()
            assert row is not None
            return dict(row)

    def depends(self, message: uuid.UUID) -> list[str]:
        with closing(self.raw()) as conn:
            row = conn.execute(
                "SELECT depends_on FROM _interlock_outbox WHERE message_id = ?", (str(message),)
            ).fetchone()
            return list(json.loads(row[0]))

    def tamper_payload(self, message: uuid.UUID, payload: str) -> None:
        with closing(self.raw()) as conn:
            conn.execute("DROP TRIGGER _interlock_outbox_no_update")
            conn.execute(
                "UPDATE _interlock_outbox SET payload = ? WHERE message_id = ?",
                (payload, str(message)),
            )

    def release(self, message: uuid.UUID, *, actor: str) -> bool:
        return self.operator().release(message, actor=f"operator:{actor}")

    def release_scope(self, scope: str, *, actor: str) -> int:
        return self.operator().release_scope(scope, actor=f"operator:{actor}")

    def cancel(self, message: uuid.UUID, *, actor: str, reason: str) -> bool:
        return self.operator().cancel(message, actor=f"operator:{actor}", reason=reason)

    def requeue(self, message: uuid.UUID, *, actor: str) -> int:
        return self.operator().requeue(message, actor=f"operator:{actor}")

    def relay_target(self) -> dict[str, str]:
        return {"store": "sqlite", "dsn": self.path}

    def lease_left(self, message: uuid.UUID) -> float:
        row = self.row(message)
        if row["state"] != "leased" or row["lease_expires"] is None:
            return 0.0
        return max(0.0, (int(row["lease_expires"]) - now_us()) / 1e6)

    def settle(self) -> None:
        """The kernel released a dead relay's locks with its process, and a
        transaction it had open never wrote its commit frame: the write lock
        is free at once."""
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=1)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")

    def reinstall(self, sinks: tuple[SinkSpec, ...]) -> None:
        install_sqlite_outbox(self.path, sinks)

    def fetch(self, sql: str, *params: object) -> list[tuple[Any, ...]]:
        with closing(self.raw()) as conn:
            return [tuple(r) for r in conn.execute(sql, params)]

    def named(self, name: str) -> str:
        return f":{name}"

    def requests(self) -> int:
        return int(self.fetch("SELECT count(*) FROM _interlock_outbox")[0][0])

    def close(self) -> None:
        if self._operator is not None:
            self._operator.close()
        super().close()


def _ledger(tmp_path: Path) -> tuple[str, BudgetManager]:
    ledger = tmp_path / "governor.db"
    governor = BudgetManager.open_sqlite(str(ledger))
    governor.open_root(SCOPE, "100")
    return str(ledger), governor


def build_outbox(pg: Pg, tmp_path: Path) -> Iterator[PostgresOutbox]:
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
        ledger, governor = _ledger(tmp_path)
        env = PostgresOutbox(
            pg,
            relay_dsn=make_conninfo(pg.admin, user=role, password=PASSWORD),
            relay_role=role,
            ledger_path=ledger,
            governor=governor,
        )
        try:
            yield env
        finally:
            env.close()
    finally:
        drop_role(pg.cluster, pg.admin, role)


def build_sqlite_outbox(tmp_path: Path) -> Iterator[SqliteOutbox]:
    path = build_sqlite_back_office(tmp_path / "back_office.db")
    install_sqlite_outbox(path, RELAY_SINKS)
    ledger, governor = _ledger(tmp_path)
    env = SqliteOutbox(path, ledger, governor)
    try:
        yield env
    finally:
        env.close()


BACKENDS = ("postgres", "sqlite")


def build_either(request: Any, tmp_path: Path) -> Iterator[Outbox]:
    """The outbox on the store a parametrized fixture names: PostgreSQL
    (skipped without a test database) or SQLite."""
    if request.param == "postgres":
        yield from build_outbox(request.getfixturevalue("pg"), tmp_path)
    else:
        yield from build_sqlite_outbox(tmp_path)
