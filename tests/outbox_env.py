"""What the relay's tests share: a back office with the outbox installed, a
relay role, an AgentGov ledger whose breaker the relay reads, and sinks with
backoff short enough to test.

Three sinks, one per delivery guarantee the relay can give:

- ``mail`` honours idempotency keys: at least once, absorbed to once.
- ``sms`` does not, and redelivers an unknown outcome: at least once, and a
  lost call can act twice.
- ``pager`` does not, and dead-letters an unknown outcome: at most once.

And ``payments``, which honours keys, for refunds checked against their rows.

Every relay signs what it records with :data:`RELAY_SEED`'s key, registered
as ``relay``: the relays' keyring is :meth:`Outbox.relays`.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
from agentgov import BudgetManager
from agentgov.exceptions import DuplicateScopeError
from agentgov.receipts.signing import Ed25519Signer
from psycopg.conninfo import make_conninfo

from interlock import (
    BlastRadius,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
    SqliteSubstrate,
    deliveries,
)
from interlock import postgres as installer
from interlock.adapters import HttpAdapter
from interlock.attestations import AttestationReport, verify_attestations
from interlock.deliveries import (
    LegacyVouch,
    LogEvent,
    OutboxOperations,
    event_hash,
    message_log,
    state_counts,
    verify_delivery_log,
)
from interlock.operators import (
    Operator,
    OperatorLog,
    OperatorRefusedError,
    OperatorReport,
    legacy_vouch,
    verify_operators,
)
from interlock.outbound import DEAD_LETTER, OperationSpec, SinkRegistry, SinkSpec
from interlock.outbox_store import OutboxStore, PostgresOutboxStore
from interlock.postgres import install
from interlock.records import Keyring, read_records
from interlock.relay import (
    DELIVERED,
    Breaker,
    Delivery,
    DeliveryResult,
    Lease,
    LedgerBreaker,
    Relay,
)
from interlock.sqlite_outbox import (
    COMPACTOR,
    OPERATOR,
    SETTLER,
    SqliteOutboxStore,
    install_sqlite_outbox,
    instant_text,
    now_us,
)
from interlock.types import EffectId, EffectPlan, OutboundRequest
from interlock.vacuum import Vacuum
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

RELAY_SEED = bytes.fromhex("5e" * 32)
"""The tests' relays' key: one for every relay, as one fleet might share it."""


def relay_signer() -> Ed25519Signer:
    return Ed25519Signer(RELAY_SEED)


def claim_before_version_8(
    store: PostgresOutboxStore,
    relay_id: str,
    lease: timedelta,
    limit: int,
    sinks: Any,
    deadline: float,
) -> list[Lease]:
    """A claim as a relay made it before version 8: four arguments, no node
    (``docs/EPIC9_DESIGN.md`` §2), and no trace context."""
    conn = store.connection()
    with conn.transaction():
        rows = conn.execute(
            "SELECT * FROM interlock.relay_claim(%s, %s, %s, %s)",
            (relay_id, lease.total_seconds(), limit, sorted(sinks)),
        ).fetchall()
    return [Lease.from_row(row, deadline) for row in rows]


RELAYS = Keyring({"relay": relay_signer().public_key()})
"""``[relays.keys]``, as the tests register their relays."""


INSTALLER = Ed25519Signer(bytes.fromhex("1e" * 32))
"""The operator who signs installs in the tests."""
INSTALLERS = Keyring({"installer": INSTALLER.public_key()})


NO_INBOX: dict[str, Any] = {
    "INBOX_TABLES": "SELECT 1",
    "INBOX_FUNCTIONS": "SELECT 1",
    "INBOX_TRIGGERS": "SELECT 1",
    "_INBOX_TABLES": (),
    "_INBOX_FUNCTIONS": (),
    "_install_sources": lambda conn, sources: None,
    "_STAGE_FUNCTIONS": tuple(
        f
        for f in installer._STAGE_FUNCTIONS
        if not f.startswith(("interlock.inbox_", "interlock.stage_facts", "interlock.outbox_trace"))
    ),
}
"""What an install by a version before the inbox (5), and so before trace
context (6), leaves out, patched over the current installer with that
version's own SQL (``tests/outbox_v2.py``...)."""


def vouch(source: object, log: Path) -> LegacyVouch:
    """Sign an install record over ``source`` into the operator log at
    ``log``, as ``interlock install`` under ``[operators]`` does after it
    installs; the legacy set it vouches for."""
    with OperatorLog(log, INSTALLER, INSTALLERS) as signed:
        Operator(signed, deliveries.operations(source)).installed()
        found = legacy_vouch(signed.records(), INSTALLERS)
    assert found is not None
    return found


def relays_section(directory: Path) -> str:
    """The tests' relay key written to ``relay.key`` in ``directory``, beside a
    configuration file whose ``[relay]`` says ``key = "relay.key"``; and the
    ``[relays.keys]`` table that registers it."""
    path = directory / "relay.key"
    if not path.exists():
        path.write_text(RELAY_SEED.hex() + "\n")
    return f'\n[relays.keys]\nrelay = "{relay_signer().public_key().spec()}"\n'


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


class Scripted:
    """An adapter answering from a list, then delivering; a delivered call
    records a reference, as a sink names what it made."""

    def __init__(self, *outcomes: str) -> None:
        self._outcomes = list(outcomes)

    def send(self, delivery: Delivery) -> DeliveryResult:
        outcome = self._outcomes.pop(0) if self._outcomes else DELIVERED
        if outcome == DELIVERED:
            return DeliveryResult(DELIVERED, status_code=200, remote_ref=f"ref_{delivery.attempt}")
        return DeliveryResult(outcome, status_code=503, detail="scripted")


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
        self.keys: dict[str, Ed25519Signer] = {}

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

    def tamper(self, message: uuid.UUID, **columns: object) -> None:
        """Rewrite a stored request's columns around Interlock (``cost``,
        ``plan_id``, ``scope_id``): its owner lifting the append-only guard."""
        raise NotImplementedError

    def operations(self) -> OutboxOperations:
        """What an operator's actions go through, on this store."""
        raise NotImplementedError

    def forge(
        self,
        message: uuid.UUID,
        event: str,
        *,
        authority: str | None,
        state_after: str | None,
        actor: str = "operator:dba",
        **columns: Any,
    ) -> None:
        """A ghost edit, as the database's owner could make one: a delivery-log
        row written around Interlock's triggers, linked and hashed exactly as
        Interlock would have, the head advanced and the state set to match.
        The delivery log alone cannot tell it from a real one.

        ``columns`` writes a relay's columns too, for a ghost delivery:
        ``attempt``, ``status_code``, ``response_digest``, ``remote_ref``,
        ``attestation``, ``detail``; and ``at``, to backdate the row. A forged
        ``sending`` counts as a call."""
        raise NotImplementedError

    def rewrite_last(self, message: uuid.UUID, **changes: Any) -> None:
        """A ghost rewrite: the message's last delivery-log row changed in place
        around Interlock's triggers, rehashed, the head and the state set to
        match. The delivery log alone cannot tell."""
        raise NotImplementedError

    def _rewritten(self, message: uuid.UUID, changes: Mapping[str, Any]) -> LogEvent:
        last = self.log(message)[-1]
        changed = dataclasses.replace(last, **changes)
        return dataclasses.replace(changed, event_hash=changed.recomputed())

    def _forged(
        self,
        message: uuid.UUID,
        event: str,
        authority: str | None,
        state_after: str | None,
        actor: str,
        at: datetime | str,
        columns: Mapping[str, Any],
    ) -> dict[str, Any]:
        """The forged row, every column, hashed and linked to the head."""
        head = self.row(message)
        seq, prev = int(head["log_seq"]) + 1, str(head["log_head"])
        row: dict[str, Any] = {
            "attempt": None,
            "status_code": None,
            "response_digest": None,
            "detail": "edited",
            "remote_ref": None,
            "attestation": None,
            **columns,
        }
        digest = event_hash(
            prev,
            message,
            seq,
            row["attempt"],
            event,
            actor,
            at,
            row["status_code"],
            row["response_digest"],
            row["detail"],
            state_after,
            row["remote_ref"],
            authority,
            row["attestation"],
        )
        return {
            **row,
            "message_id": message,
            "seq": seq,
            "event": event,
            "actor": actor,
            "at": at,
            "state_after": state_after,
            "authority": authority,
            "prev_hash": prev,
            "event_hash": digest,
        }

    # -- operators: every action signed, as `interlock outbox` signs it ---------

    def operator_key(self, actor: str) -> Ed25519Signer:
        if actor not in self.keys:
            self.keys[actor] = Ed25519Signer.generate()
        return self.keys[actor]

    def keyring(self) -> Keyring:
        return Keyring({name: key.public_key() for name, key in self.keys.items()})

    @property
    def operator_log(self) -> Path:
        return Path(self.ledger_path).parent / "operators.ilok1"

    @contextmanager
    def signed(
        self,
        actor: str = "ops",
        *,
        checkpoint: Callable[[str], None] | None = None,
        ledger: BudgetManager | None = None,
    ) -> Iterator[Operator]:
        """An operator session, as one ``interlock outbox`` command opens it."""
        key = self.operator_key(actor)
        log = OperatorLog(self.operator_log, key, self.keyring(), ledger=ledger, scope="operators")
        try:
            yield Operator(log, self.operations(), checkpoint=checkpoint)
        finally:
            log.close()

    def release(self, message: uuid.UUID, *, actor: str) -> bool:
        with self.signed(actor) as operator:
            return operator.release([message]).applied

    def release_scope(self, scope: str, *, actor: str) -> int:
        with self.signed(actor) as operator:
            try:
                return operator.release_scope(scope).count("released")
            except OperatorRefusedError:
                return 0

    def cancel(self, message: uuid.UUID, *, actor: str, reason: str) -> bool:
        with self.signed(actor) as operator:
            return operator.cancel(message, reason=reason).applied

    def requeue(self, message: uuid.UUID, *, actor: str) -> int:
        with self.signed(actor) as operator:
            return operator.requeue(message).count("requeued")

    def verify_operators(self) -> OperatorReport:
        records = read_records(self.operator_log) if self.operator_log.exists() else ()
        return verify_operators(self.operator(), records, self.keyring())

    # -- the vacuum (docs/EPIC5_DESIGN.md §1) --------------------------------

    def compactor(self) -> Any:
        """What a vacuum acts through: the installer on PostgreSQL, a store
        that may prune on SQLite."""
        raise NotImplementedError

    @contextmanager
    def vacuum(
        self,
        actor: str = "ops",
        *,
        ledger: BudgetManager | None = None,
        anchored: bool = True,
        **settings: Any,
    ) -> Iterator[Vacuum]:
        """A vacuum, as one ``interlock vacuum`` command runs it: its operator
        log anchored into the ledger (unless ``anchored`` is false), every
        operator's and relay's key, retention 0 unless ``settings`` says."""
        governor = ledger if ledger is not None else self.governor
        try:
            governor.open_root("operators", "1")
        except DuplicateScopeError:
            pass
        log = OperatorLog(
            self.operator_log,
            self.operator_key(actor),
            self.keyring(),
            ledger=governor if anchored else None,
            scope="operators",
        )
        settings.setdefault("retain", timedelta(0))
        try:
            yield Vacuum(
                log,
                self.compactor(),
                operators=self.keyring(),
                relays=RELAYS,
                ledger=governor,
                **settings,
            )
        finally:
            log.close()

    def relay_target(self) -> dict[str, str]:
        """Where a relay in another process finds the outbox: the store's
        kind, and its connection string or file."""
        raise NotImplementedError

    def settler(self) -> Any:
        """The outbox as settlement reads and writes it: a connection as the
        settler role, or a store that writes settlements only. The caller
        closes it."""
        raise NotImplementedError

    def settler_target(self) -> dict[str, str]:
        """Where settlement in another process finds the outbox."""
        raise NotImplementedError

    def lease_left(self, message: uuid.UUID) -> float:
        """Seconds left on the message's lease, by the database's clock; 0
        when it is not leased."""
        raise NotImplementedError

    def operator_target(self) -> dict[str, str]:
        """Where an operator in another process acts: as the installer on
        PostgreSQL, the file on SQLite."""
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
        traceparent: str | None = None,
    ) -> tuple[EffectPlan, list[uuid.UUID]]:
        """Commit one plan that enqueues ``requests``, independent of each
        other unless ``independent`` is false (then each waits for the one
        before it), in ``traceparent``'s trace when given. Returns the plan
        and its messages, in order."""
        builder = PlanBuilder(scope, traceparent=traceparent)
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

    def relays(self) -> Keyring:
        """``[relays.keys]``: the key every test relay signs with."""
        return RELAYS

    def relay(self, *, breaker: Breaker | None = None, **kwargs: Any) -> Relay:
        kwargs.setdefault("lease", timedelta(seconds=10))
        kwargs.setdefault("timeout", timedelta(seconds=2))
        kwargs.setdefault("signer", relay_signer())
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
        """Every delivery log verifies, every outcome is a registered relay's,
        and every operator row is signed."""
        assert self.verify_operators().problems == ()
        self.verify_logs()

    def verify_logs(self) -> None:
        problems = verify_delivery_log(self.operator())
        assert problems == (), problems
        report = self.attestations()
        assert report.problems == (), report.problems

    def attestations(self) -> AttestationReport:
        return verify_attestations(self.operator(), self.relays())

    def close(self) -> None:
        for sink in self.sinks.values():
            sink.close()
        self.governor.close()


class PostgresOutbox(Outbox):
    backend = "postgres"

    def __init__(
        self,
        pg: Pg,
        relay_dsn: str,
        relay_role: str,
        ledger_path: str,
        governor: BudgetManager,
        settler_dsn: str = "",
        settler_role: str = "",
    ) -> None:
        super().__init__(ledger_path, governor)
        self.pg = pg
        self.relay_dsn = relay_dsn
        self.relay_role = relay_role
        self.settler_dsn = settler_dsn
        self.settler_role = settler_role
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

    def tamper(self, message: uuid.UUID, **columns: object) -> None:
        conn = self.operator()
        conn.execute("ALTER TABLE interlock.outbox DISABLE TRIGGER outbox_append_only")
        conn.execute(
            f"UPDATE interlock.outbox SET {', '.join(f'{name} = %({name})s' for name in columns)} "
            f"WHERE message_id = %(message)s",
            {**columns, "message": message},
        )
        conn.execute("ALTER TABLE interlock.outbox ENABLE ALWAYS TRIGGER outbox_append_only")

    def operations(self) -> OutboxOperations:
        return deliveries.operations(self.operator())

    def compactor(self) -> Any:
        return deliveries.operations(self.operator())

    def forge(
        self,
        message: uuid.UUID,
        event: str,
        *,
        authority: str | None,
        state_after: str | None,
        actor: str = "operator:dba",
        **columns: Any,
    ) -> None:
        at = columns.pop("at", None) or datetime.now(UTC)
        row = self._forged(message, event, authority, state_after, actor, at, columns)
        conn = self.operator()
        conn.execute("ALTER TABLE interlock.outbox_attempts DISABLE TRIGGER outbox_log_link")
        conn.execute(
            f"INSERT INTO interlock.outbox_attempts ({', '.join(row)}) "
            f"VALUES ({', '.join(f'%({name})s' for name in row)})",
            row,
        )
        conn.execute(
            "UPDATE interlock.outbox_state SET log_seq = %s, log_head = %s, "
            "state = coalesce(%s, state), attempts = attempts + %s WHERE message_id = %s",
            (row["seq"], row["event_hash"], state_after, int(event == "sending"), message),
        )
        conn.execute("ALTER TABLE interlock.outbox_attempts ENABLE ALWAYS TRIGGER outbox_log_link")

    def rewrite_last(self, message: uuid.UUID, **changes: Any) -> None:
        row = self._rewritten(message, changes)
        conn = self.operator()
        conn.execute("ALTER TABLE interlock.outbox_attempts DISABLE TRIGGER attempts_append_only")
        conn.execute(
            f"UPDATE interlock.outbox_attempts SET "
            f"{', '.join(f'{name} = %({name})s' for name in changes)}, "
            f"event_hash = %(event_hash)s WHERE message_id = %(message)s AND seq = %(seq)s",
            {**changes, "event_hash": row.event_hash, "message": message, "seq": row.seq},
        )
        conn.execute(
            "UPDATE interlock.outbox_state SET log_head = %s, state = coalesce(%s, state) "
            "WHERE message_id = %s",
            (row.event_hash, row.state_after, message),
        )
        conn.execute(
            "ALTER TABLE interlock.outbox_attempts ENABLE ALWAYS TRIGGER attempts_append_only"
        )

    def relay_target(self) -> dict[str, str]:
        return {"store": "postgres", "dsn": self.relay_dsn, "key": RELAY_SEED.hex()}

    def settler(self) -> Any:
        return psycopg.connect(self.settler_dsn, autocommit=True)

    def settler_target(self) -> dict[str, str]:
        return {"store": "postgres", "dsn": self.settler_dsn}

    def operator_target(self) -> dict[str, str]:
        return {"store": "postgres", "dsn": self.pg.admin}

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
            settler_roles=[self.settler_role] if self.settler_role else [],
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
        self._compactor: SqliteOutboxStore | None = None

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

    def tamper(self, message: uuid.UUID, **columns: object) -> None:
        values = {k: str(v) if isinstance(v, Decimal) else v for k, v in columns.items()}
        with closing(self.raw()) as conn:
            conn.execute("DROP TRIGGER IF EXISTS _interlock_outbox_no_update")
            conn.execute(
                f"UPDATE _interlock_outbox SET {', '.join(f'{name} = :{name}' for name in values)} "
                f"WHERE message_id = :message",
                {**values, "message": str(message)},
            )

    def operations(self) -> OutboxOperations:
        return self.operator()

    def compactor(self) -> SqliteOutboxStore:
        if self._compactor is None:
            self._compactor = SqliteOutboxStore(self.path, writes=COMPACTOR)
        return self._compactor

    def forge(
        self,
        message: uuid.UUID,
        event: str,
        *,
        authority: str | None,
        state_after: str | None,
        actor: str = "operator:dba",
        **columns: Any,
    ) -> None:
        when = columns.pop("at", None)
        at = instant_text(now_us() if when is None else _microseconds(when))
        row = self._forged(message, event, authority, state_after, actor, at, columns)
        row["message_id"] = str(message)
        with closing(self.raw()) as conn:
            for trigger in (
                "_interlock_log_link",
                "_interlock_log_attested",
                "_interlock_log_authority",
                "_interlock_log_head",
            ):
                conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            conn.execute(
                f"INSERT INTO _interlock_outbox_attempts ({', '.join(row)}) "
                f"VALUES ({', '.join(f':{name}' for name in row)})",
                row,
            )
            conn.execute(
                "UPDATE _interlock_outbox_state SET log_seq = ?, log_head = ?, "
                "state = coalesce(?, state), attempts = attempts + ? WHERE message_id = ?",
                (row["seq"], row["event_hash"], state_after, int(event == "sending"), str(message)),
            )

    def rewrite_last(self, message: uuid.UUID, **changes: Any) -> None:
        row = self._rewritten(message, changes)
        with closing(self.raw()) as conn:
            conn.execute("DROP TRIGGER IF EXISTS _interlock_log_no_update")
            conn.execute(
                f"UPDATE _interlock_outbox_attempts SET "
                f"{', '.join(f'{name} = :{name}' for name in changes)}, "
                f"event_hash = :event_hash WHERE message_id = :message AND seq = :seq",
                {**changes, "event_hash": row.event_hash, "message": str(message), "seq": row.seq},
            )
            conn.execute(
                "UPDATE _interlock_outbox_state SET log_head = ?, state = coalesce(?, state) "
                "WHERE message_id = ?",
                (row.event_hash, row.state_after, str(message)),
            )

    def relay_target(self) -> dict[str, str]:
        return {"store": "sqlite", "dsn": self.path, "key": RELAY_SEED.hex()}

    def settler(self) -> Any:
        return SqliteOutboxStore(self.path, writes=SETTLER)

    def settler_target(self) -> dict[str, str]:
        return {"store": "sqlite", "dsn": self.path}

    def operator_target(self) -> dict[str, str]:
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
        if self._compactor is not None:
            self._compactor.close()
        super().close()


def _microseconds(at: datetime) -> int:
    return (at - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1)


def _ledger(tmp_path: Path) -> tuple[str, BudgetManager]:
    ledger = tmp_path / "governor.db"
    governor = BudgetManager.open_sqlite(str(ledger))
    governor.open_root(SCOPE, "100")
    return str(ledger), governor


def build_outbox(pg: Pg, tmp_path: Path) -> Iterator[PostgresOutbox]:
    role = f"il_relay_{uuid.uuid4().hex[:8]}"
    settler = f"il_settle_{uuid.uuid4().hex[:8]}"
    create_role(pg.cluster, role)
    create_role(pg.cluster, settler)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            install(
                conn,
                specs(*OBSERVED),
                stage_roles=[pg.role],
                sinks=RELAY_SINKS,
                relay_roles=[role],
                settler_roles=[settler],
            )
        ledger, governor = _ledger(tmp_path)
        env = PostgresOutbox(
            pg,
            relay_dsn=make_conninfo(pg.admin, user=role, password=PASSWORD),
            relay_role=role,
            ledger_path=ledger,
            governor=governor,
            settler_dsn=make_conninfo(pg.admin, user=settler, password=PASSWORD),
            settler_role=settler,
        )
        try:
            yield env
        finally:
            env.close()
    finally:
        drop_role(pg.cluster, pg.admin, settler)
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
