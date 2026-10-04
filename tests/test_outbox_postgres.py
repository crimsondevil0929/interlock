"""The transactional outbox (Epic 2, phases 0 and 1), against a real PostgreSQL.

An ``ENQUEUE`` effect is written to ``interlock.outbox`` inside the stage's
transaction, through the token-gated ``interlock.enqueue``, so it commits with
the plan's rows and its stage marker or not at all. Nothing is delivered yet:
the relay is phase 3. What is checked:

- ``install`` creates the outbox, mirrors the sink registry, and grants the
  stage, relay and audit roles exactly what each needs; installing over
  version 1 upgrades in place.
- A committed plan leaves exactly its requests, as staged, with their
  delivery state; a refused, failed or rolled-back plan leaves none.
- The agent's own SQL runs in the same transaction, as the same role, and
  still cannot enqueue, read the outbox, or read the stage's token hash.
- ``interlock.enqueue`` refuses, on its own, a wrong token, an unknown or
  disabled sink or operation, an oversized payload, and a payload that does
  not match its hash.
- The outbox and its attempts are append-only, for the table owner too.
- Delivery order, idempotency keys, receipts and repair.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")
from agentgov.receipts import HmacKey, ReceiptLog, verify_bundle  # noqa: E402
from agentgov.receipts.canonical import canonical_bytes, loads_strict  # noqa: E402
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from interlock import (  # noqa: E402
    BlastRadius,
    EscrowChain,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
    ReceiptIssuer,
    StageState,
)
from interlock.chain import RecordType  # noqa: E402
from interlock.exceptions import (  # noqa: E402
    ForbiddenStatementError,
    OutboundRequestError,
    StageError,
    SubstrateConfigurationError,
)
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec  # noqa: E402
from interlock.postgres import INSTALL_VERSION, install  # noqa: E402
from interlock.types import EffectId, EffectPlan, OutboundRequest, outbound_key  # noqa: E402
from tests.conftest import OBSERVED, PASSWORD, Pg, create_role, drop_role  # noqa: E402
from tests.schemas import TEST_SINKS, specs  # noqa: E402

REGISTRY = SinkRegistry(TEST_SINKS)
MAIL = {"to": "ann@acme.test", "subject": "Your order", "body": "It shipped."}
HOOK = SinkSpec("hook", (OperationSpec("post"),))
"""A sink with no schema, for payloads the mail schema would refuse."""


def engine(env: Pg, *checkers: Any, sinks: SinkRegistry = REGISTRY, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        PostgresSubstrate(env.agent, tables=specs(*OBSERVED)),
        checkers=list(checkers) or [BlastRadius(100)],
        sinks=sinks,
        **kwargs,
    )


def ship(**payload: Any) -> PlanBuilder:
    """Mark order 500 shipped and tell the customer, in one plan."""
    return (
        PlanBuilder("agent", intent="ship order 500")
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'shipped' WHERE id = 500",
            tenant_id="acme",
            stated_rows=1,
            effect_id=EffectId("ship"),
        )
        .enqueue(
            sink="mail",
            operation="send",
            payload=payload or MAIL,
            tenant_id="acme",
            effect_id=EffectId("notify"),
        )
    )


def rows(dsn: str, query: str, *params: object) -> list[dict[str, Any]]:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        found: list[dict[str, Any]] = conn.execute(query, params or None).fetchall()
        return found


def scalar(dsn: str, query: str, *params: object) -> Any:
    with psycopg.connect(dsn) as conn:
        row = conn.execute(query, params or None).fetchone()
        return None if row is None else row[0]


def outbox(env: Pg) -> list[dict[str, Any]]:
    return rows(env.admin, "SELECT * FROM interlock.outbox ORDER BY stage_id, seq")


def untouched(env: Pg) -> None:
    """Nothing committed: no request, no delivery state, no marker, no row."""
    assert outbox(env) == []
    assert scalar(env.admin, "SELECT count(*) FROM interlock.outbox_state") == 0
    assert scalar(env.admin, "SELECT count(*) FROM interlock.stages") == 0
    assert scalar(env.admin, "SELECT status FROM orders WHERE id = 500") == "open"


def reinstall(env: Pg, sinks: Any = TEST_SINKS, **kwargs: Any) -> None:
    with psycopg.connect(env.admin, autocommit=True) as conn:
        install(conn, specs(*OBSERVED), stage_roles=[env.role], sinks=sinks, **kwargs)


@contextmanager
def role(env: Pg, prefix: str) -> Iterator[str]:
    name = f"{prefix}_{uuid.uuid4().hex[:8]}"
    create_role(env.cluster, name)
    try:
        yield name
    finally:
        drop_role(env.cluster, env.admin, name)


# --------------------------------------------------------------------------
# installation
# --------------------------------------------------------------------------


def test_install_mirrors_the_registry_without_endpoints_or_credentials(pg: Pg) -> None:
    installed = rows(pg.admin, "SELECT * FROM interlock.sinks ORDER BY name")
    assert installed == [
        {
            "name": sink.name,
            "kind": sink.kind,
            "operations": [op.name for op in sink.operations],
            "cost_per_call": str(sink.cost_per_call),
            "idempotency": sink.idempotency,
            "max_payload_bytes": sink.max_payload_bytes,
            "not_after_seconds": int(sink.not_after.total_seconds()),
            "max_attempts": sink.max_attempts,
            "backoff_base_ms": int(sink.backoff_base / timedelta(milliseconds=1)),
            "backoff_cap_ms": int(sink.backoff_cap / timedelta(milliseconds=1)),
            "unknown_outcome": sink.unknown_outcome,
            "config_hash": sink.config_hash(),
            "enabled": True,
        }
        for sink in TEST_SINKS
    ]
    assert scalar(pg.admin, "SELECT DISTINCT version FROM interlock.installation") == (
        INSTALL_VERSION
    )


def test_a_sink_no_longer_listed_is_disabled_not_deleted(pg: Pg) -> None:
    reinstall(pg, sinks=TEST_SINKS[:1])
    state = rows(pg.admin, "SELECT name, enabled FROM interlock.sinks ORDER BY name")
    assert state == [{"name": "mail", "enabled": True}, {"name": "payments", "enabled": False}]
    reinstall(pg)
    assert scalar(pg.admin, "SELECT bool_and(enabled) FROM interlock.sinks") is True


TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
OUTBOX_TABLES = ("sinks", "outbox", "outbox_state", "outbox_attempts", "outbox_epochs", "stages")


def privileges(env: Pg, grantee: str) -> dict[str, set[str]]:
    held: dict[str, set[str]] = {}
    with psycopg.connect(env.admin) as conn:
        for table in OUTBOX_TABLES:
            held[table] = {
                p
                for p in TABLE_PRIVILEGES
                if conn.execute(
                    "SELECT has_table_privilege(%s, %s, %s)", (grantee, f"interlock.{table}", p)
                ).fetchone()
                == (True,)
            }
    return held


def may_execute(env: Pg, grantee: str, signature: str) -> bool:
    return bool(
        scalar(env.admin, "SELECT has_function_privilege(%s, %s, 'EXECUTE')", grantee, signature)
    )


ENQUEUE = (
    "interlock.enqueue(bytea, uuid, text, integer, text[], text, text, text, text, text, "
    "text, text, integer, text)"
)
RELAY_CALLS = (
    "interlock.relay_claim(text, double precision, integer, text[])",
    "interlock.relay_sending(uuid, text, bigint, text)",
    "interlock.relay_outcome(uuid, text, bigint, integer, text, integer, text, text, bigint, text, "
    "text)",
    "interlock.relay_hold(uuid, text, bigint, text)",
    "interlock.relay_defer(uuid, text, bigint, text, bigint)",
    "interlock.relay_refuse(uuid, text, bigint, text)",
)
OPERATOR_CALLS = (
    "interlock.outbox_release(uuid, text, text, text)",
    "interlock.outbox_cancel(uuid, text, text, text, text)",
    "interlock.outbox_requeue(uuid, text, text, text)",
    "interlock.outbox_compensate(uuid, text, text, text, uuid, text, text, text)",
)


def test_each_role_holds_exactly_its_part(pg: Pg) -> None:
    with role(pg, "il_relay") as relay, role(pg, "il_audit") as audit:
        reinstall(pg, relay_roles=[relay], audit_roles=[audit])
        # The stage writes the outbox only through enqueue(), with its token.
        assert privileges(pg, pg.role) == {t: set() for t in OUTBOX_TABLES}
        assert may_execute(pg, pg.role, ENQUEUE)
        assert may_execute(pg, pg.role, "interlock.stage_outbox(bigint)")
        assert not any(may_execute(pg, pg.role, f) for f in RELAY_CALLS + OPERATOR_CALLS)
        # The relay reads the outbox, and changes delivery state only through
        # the relay functions, which check its lease and log every change.
        assert privileges(pg, relay) == {
            "sinks": {"SELECT"},
            "outbox": {"SELECT"},
            "outbox_state": {"SELECT"},
            "outbox_attempts": {"SELECT"},
            "outbox_epochs": {"SELECT"},
            "stages": set(),
        }
        assert all(may_execute(pg, relay, f) for f in RELAY_CALLS)
        assert not any(may_execute(pg, relay, f) for f in OPERATOR_CALLS)
        assert not may_execute(pg, relay, ENQUEUE)
        assert not may_execute(pg, relay, "interlock.begin_stage(uuid, text, jsonb, bytea)")
        # The auditor reads everything and writes nothing.
        assert privileges(pg, audit) == {t: {"SELECT"} for t in OUTBOX_TABLES}
        assert not any(may_execute(pg, audit, f) for f in (ENQUEUE, *RELAY_CALLS))
        # Nobody else, through PUBLIC: no interlock function at all.
        public = scalar(
            pg.admin,
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'interlock' AND has_function_privilege('public', p.oid, 'EXECUTE')",
        )
        assert public == 0


def test_a_stage_role_that_can_write_the_outbox_cannot_stage(pg: Pg) -> None:
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(f"GRANT INSERT ON interlock.outbox TO {pg.role}")
    with pytest.raises(SubstrateConfigurationError, match=r"interlock\.outbox"):
        engine(pg).execute(ship().build())


def downgrade_to_version_1(env: Pg) -> None:
    """Put the database back as version 1 installed it: no outbox, no token
    column, and the three-argument ``begin_stage``."""
    with psycopg.connect(env.admin, autocommit=True) as conn:
        conn.execute(
            "DROP TABLE interlock.outbox_settlements, interlock.outbox_legacy, "
            "interlock.outbox_epochs, interlock.outbox_attempts, interlock.outbox_state, "
            "interlock.outbox, interlock.sinks"
        )
        conn.execute(f"DROP FUNCTION interlock.enqueue{ENQUEUE.removeprefix('interlock.enqueue')}")
        conn.execute("DROP FUNCTION interlock.stage_outbox(bigint)")
        conn.execute("DROP FUNCTION interlock.outbox_append_only()")
        conn.execute("DROP FUNCTION interlock.begin_stage(uuid, text, jsonb, bytea)")
        conn.execute("ALTER TABLE interlock.stages DROP COLUMN enqueue_hash")
        conn.execute(
            "CREATE FUNCTION interlock.begin_stage(p_stage uuid, p_plan text, p_gates jsonb) "
            "RETURNS xid8 LANGUAGE plpgsql SECURITY DEFINER AS $$ "
            "BEGIN RAISE EXCEPTION 'version 1'; END $$"
        )
        conn.execute("UPDATE interlock.installation SET version = '1'")


def test_installing_over_version_1_upgrades_in_place(pg: Pg) -> None:
    downgrade_to_version_1(pg)
    with pytest.raises(SubstrateConfigurationError, match="older version"):
        engine(pg).execute(ship().build())
    reinstall(pg)
    assert scalar(pg.admin, "SELECT DISTINCT version FROM interlock.installation") == (
        INSTALL_VERSION
    )
    overloads = scalar(
        pg.admin,
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'interlock' AND p.proname = 'begin_stage'",
    )
    assert overloads == 1
    assert engine(pg).execute(ship().build()).committed
    assert len(outbox(pg)) == 1


# --------------------------------------------------------------------------
# staging
# --------------------------------------------------------------------------


def test_a_committed_plan_leaves_its_request_in_the_outbox(pg: Pg) -> None:
    eng = engine(pg, chain=EscrowChain())
    plan = ship().build()
    result = eng.execute(plan)
    assert result.committed
    request = plan.effects[1].request
    assert request is not None

    (row,) = outbox(pg)
    stage = rows(pg.admin, "SELECT stage_id, plan_id FROM interlock.stages")
    assert stage == [{"stage_id": row["stage_id"], "plan_id": plan.plan_id}]
    assert {
        k: row[k] for k in row if k not in ("message_id", "stage_id", "not_after", "enqueued_at")
    } == {
        "plan_id": plan.plan_id,
        "effect_id": "notify",
        "seq": 1,
        "depends_on": [],
        "sink": "mail",
        "operation": "send",
        "scope_id": "agent",
        "tenant_id": "acme",
        "payload": MAIL,
        "payload_hash": request.payload_hash,
        "idempotency_key": outbound_key(plan.plan_id, EffectId("notify")),
        "cost": "0.002",
        "compensation": None,
        "compensates": None,
    }
    # The sink's default: fifteen minutes from staging.
    assert row["not_after"] - row["enqueued_at"] == timedelta(minutes=15)
    state = rows(pg.admin, "SELECT * FROM interlock.outbox_state")
    assert [(s["message_id"], s["state"], s["attempts"]) for s in state] == [
        (row["message_id"], "pending", 0)
    ]
    assert scalar(pg.admin, "SELECT status FROM orders WHERE id = 500") == "shipped"

    # The diff the checkers saw is what committed.
    assert result.diff is not None
    (staged,) = result.diff.outbound
    assert (staged.message_id, staged.effect_id, staged.payload, staged.payload_hash) == (
        row["message_id"],
        "notify",
        request.payload,
        request.payload_hash,
    )
    assert staged.idempotency_key == row["idempotency_key"]
    assert len(result.diff.deltas) == 1

    intent = [r for r in eng.chain.records() if r.record_type is RecordType.COMMIT_INTENT]
    assert len(intent) == 1 and "; outbound 1" in intent[0].note


def test_a_request_with_a_compensation_and_its_own_deadline(pg: Pg) -> None:
    reverse = OutboundRequest("payments", "refund.reverse", {"order": 500, "amount": "3.00"})
    plan = (
        PlanBuilder("agent")
        .enqueue(
            sink="payments",
            operation="refund",
            payload={"order": 500, "amount": "3.00"},
            compensation=reverse,
            not_after=timedelta(minutes=5),
        )
        .build()
    )
    assert engine(pg, BlastRadius(0)).execute(plan).committed
    (row,) = outbox(pg)
    assert row["compensation"] == reverse.to_json()
    assert canonical_bytes(row["compensation"]["payload"]) == reverse.canonical_payload
    assert row["not_after"] - row["enqueued_at"] == timedelta(minutes=5)
    assert row["tenant_id"] is None


def test_a_refused_plan_leaves_no_request(pg: Pg) -> None:
    result = engine(pg, BlastRadius(0)).execute(ship().build())
    assert not result.committed
    assert result.state is StageState.ABORTED
    # Staged, measured and refused: the checkers saw the request.
    assert result.diff is not None and len(result.diff.outbound) == 1
    untouched(pg)


def test_a_plan_that_fails_after_its_request_leaves_none(pg: Pg) -> None:
    plan = (
        ship()
        .update(table="orders", statement="UPDATE orders SET total = total / 0 WHERE id = 500")
        .build()
    )
    with pytest.raises(StageError):
        engine(pg).execute(plan)
    untouched(pg)


def test_a_database_that_does_not_install_the_sink_refuses_the_request(pg: Pg) -> None:
    """The engine's registry and the database's are configured separately;
    the database's is the one the stage cannot get past."""
    wider = SinkRegistry(
        [
            SinkSpec(
                "mail",
                (OperationSpec("send"), OperationSpec("digest")),
                max_payload_bytes=1 << 20,
            ),
            TEST_SINKS[1],
            SinkSpec("sms", (OperationSpec("send"),)),
        ]
    )
    reinstall(pg, sinks=TEST_SINKS[:1])  # payments: disabled
    cases = [
        (
            PlanBuilder("agent").enqueue(sink="sms", operation="send", payload={"n": 1}),
            "unregistered_sink",
        ),
        (
            PlanBuilder("agent").enqueue(
                sink="payments",
                operation="refund",
                payload={"order": 1},
                compensation=OutboundRequest("payments", "refund.reverse", {"order": 1}),
            ),
            "unregistered_sink",
        ),
        (
            PlanBuilder("agent").enqueue(sink="mail", operation="digest", payload={}),
            "unregistered_operation",
        ),
        (ship(to="a@b.c", subject="s", body="x" * 5000), "payload_size"),
    ]
    for builder, reason in cases:
        with pytest.raises(OutboundRequestError) as caught:
            engine(pg, sinks=wider).execute(builder.build())
        assert caught.value.reason == reason, caught.value
        assert caught.value.feedback is not None
        untouched(pg)


def test_a_plan_of_requests_alone_commits(pg: Pg) -> None:
    plan = (
        PlanBuilder("agent")
        .enqueue(sink="mail", operation="send", payload=MAIL)
        .enqueue(sink="mail", operation="send", payload=MAIL | {"subject": "Again"})
        .build()
    )
    result = engine(pg, BlastRadius(0)).execute(plan)
    assert result.committed
    assert [r["seq"] for r in outbox(pg)] == [1, 2]
    assert scalar(pg.admin, "SELECT count(*) FROM interlock.stages") == 1


def test_delivery_order_follows_the_plan_through_its_statements(pg: Pg) -> None:
    """A request waits for every request it depends on, directly or through
    the statements between them; an independent one waits for nothing."""
    first, second, third, last = (EffectId(n) for n in ("first", "second", "third", "last"))
    plan = (
        PlanBuilder("agent")
        .enqueue(sink="mail", operation="send", payload=MAIL, effect_id=first)
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'held' WHERE id = 500",
            effect_id=EffectId("hold"),
        )
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'held' WHERE id = 501",
            effect_id=EffectId("hold_too"),
        )
        .enqueue(sink="mail", operation="send", payload=MAIL, effect_id=second)
        .enqueue(sink="mail", operation="send", payload=MAIL, effect_id=third, independent=True)
        .enqueue(sink="mail", operation="send", payload=MAIL, effect_id=last, after=[second, third])
        .build()
    )
    assert engine(pg).execute(plan).committed
    order = {r["effect_id"]: (r["seq"], r["depends_on"]) for r in outbox(pg)}
    assert {e: d for e, (_, d) in order.items()} == {
        "first": [],
        "second": ["first"],
        "third": [],
        "last": ["second", "third"],
    }
    applied = [e.effect_id for e in plan.topological_order() if e.request is not None]
    assert sorted(order, key=lambda e: order[e][0]) == applied


def test_a_request_commits_at_most_once(pg: Pg) -> None:
    plan = ship().build()
    assert engine(pg).execute(plan).committed
    with pytest.raises(OutboundRequestError) as caught:
        engine(pg).execute(plan)
    assert caught.value.reason == "duplicate"
    assert len(outbox(pg)) == 1
    assert scalar(pg.admin, "SELECT count(*) FROM interlock.stages") == 1


def test_a_payload_round_trips_through_jsonb_to_its_canonical_bytes(pg: Pg) -> None:
    """The relay sends ``canonical_bytes`` of what ``jsonb`` gives back; that
    must be the byte string the plan hashed, for anything the domain allows."""
    reinstall(pg, sinks=[*TEST_SINKS, HOOK])
    payload = {
        "text": 'é ✓ 😀 \u2028 \t \u001f "q" \\ /',
        "big": 2**53 - 1,
        "small": -(2**53 - 1),
        "zero": 0,
        "nested": {"b": [True, False, None, {"z": 1, "a": 2}], "": "empty key"},
        "order": {"B": 1, "a": 2, "é": 3, "😀": 4, "\uffff": 5},
    }
    plan = PlanBuilder("agent").enqueue(sink="hook", operation="post", payload=payload).build()
    result = engine(pg, BlastRadius(0), sinks=SinkRegistry([*TEST_SINKS, HOOK])).execute(plan)
    assert result.committed
    request = plan.effects[0].request
    assert request is not None
    stored = scalar(pg.admin, "SELECT payload::text FROM interlock.outbox")
    assert canonical_bytes(loads_strict(stored)) == request.canonical_payload
    assert result.diff is not None
    assert canonical_bytes(result.diff.outbound[0].payload) == request.canonical_payload
    assert hashlib.sha256(request.canonical_payload).hexdigest() == outbox(pg)[0]["payload_hash"]


# --------------------------------------------------------------------------
# the boundary: the agent's SQL shares the stage's transaction and role
# --------------------------------------------------------------------------


class Unvetted(PostgresSubstrate):
    """Passes every statement's text, leaving only what the database enforces."""

    __slots__ = ()

    def reject_reason(self, effect: Any) -> str | None:
        return None


FORGED = (
    "SELECT interlock.enqueue('\\x00'::bytea, gen_random_uuid(), 'x', 1, '{}', 'mail', "
    "'send', NULL, '{}', encode(sha256('{}'), 'hex'), 'forged', NULL, NULL, 'agent')"
)


@pytest.mark.parametrize(
    ("statement", "match"),
    [
        (FORGED, "did not authorize an enqueue"),
        (
            "INSERT INTO interlock.outbox (message_id) VALUES (gen_random_uuid())",
            "refused by the database",
        ),
        ("UPDATE interlock.outbox_state SET state = 'delivered'", "refused by the database"),
        ("SELECT enqueue_hash FROM interlock.stages", "refused by the database"),
        ("SELECT payload FROM interlock.outbox", "refused by the database"),
        ("UPDATE interlock.sinks SET max_payload_bytes = 1 << 30", "refused by the database"),
    ],
)
def test_the_agents_sql_cannot_reach_the_outbox(pg: Pg, statement: str, match: str) -> None:
    plan = (
        ship()
        .update(table="orders", statement=statement)
        .update(table="orders", statement="UPDATE orders SET status = 'after' WHERE id = 501")
        .build()
    )
    eng = EscrowEngine(
        Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[BlastRadius(10)], sinks=REGISTRY
    )
    with pytest.raises(ForbiddenStatementError, match=match):
        eng.execute(plan)
    untouched(pg)


def test_the_agents_sql_cannot_mint_its_own_token(pg: Pg) -> None:
    """A second begin_stage in the stage's transaction would record a token
    hash the agent chose. It fails, and the stage with it."""
    plan = (
        PlanBuilder("agent")
        .update(
            table="orders",
            statement="SELECT interlock.begin_stage(gen_random_uuid(), 'forged', '{}'::jsonb, "
            "sha256('chosen'))",
        )
        .build()
    )
    eng = EscrowEngine(Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[], sinks=REGISTRY)
    with pytest.raises(StageError):
        eng.execute(plan)
    untouched(pg)


# --------------------------------------------------------------------------
# interlock.enqueue on its own
# --------------------------------------------------------------------------


@contextmanager
def raw_stage(env: Pg) -> Iterator[tuple[Any, bytes]]:
    """A stage opened by hand as the stage role, and rolled back after."""
    token = secrets.token_bytes(32)
    with psycopg.connect(env.agent, autocommit=True) as conn:
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        conn.execute(
            "SELECT interlock.begin_stage(gen_random_uuid(), 'plan-raw', '{}'::jsonb, %s)",
            (hashlib.sha256(token).digest(),),
        )
        try:
            yield conn, token
        finally:
            conn.execute("ROLLBACK")


def call_enqueue(conn: Any, stage_token: bytes, **overrides: Any) -> None:
    payload = overrides.pop("payload", '{"subject":"s","to":"a@b.c"}')
    args: dict[str, Any] = {
        "token": stage_token,
        "message": uuid.uuid4(),
        "effect": "e",
        "seq": 1,
        "depends": [],
        "sink": "mail",
        "operation": "send",
        "tenant": None,
        "payload": payload,
        "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
        "key": f"key-{uuid.uuid4()}",
        "compensation": None,
        "seconds": None,
        "scope": "agent",
    } | overrides
    conn.execute(
        "SELECT interlock.enqueue(%(token)s, %(message)s, %(effect)s, %(seq)s, "
        "%(depends)s::text[], %(sink)s, %(operation)s, %(tenant)s, %(payload)s, "
        "%(payload_hash)s, %(key)s, %(compensation)s, %(seconds)s, %(scope)s)",
        args,
    )


@pytest.mark.parametrize(
    ("overrides", "sqlstate", "reason"),
    [
        ({"token": b"\x00" * 32}, "IL002", None),
        ({"token": b""}, "IL002", None),
        ({"sink": "sms"}, "IL004", "unregistered_sink"),
        ({"sink": "payments", "operation": "send"}, "IL004", "unregistered_operation"),
        ({"payload": '{"body":"' + "x" * 4096 + '"}'}, "IL004", "payload_size"),
        ({"payload_hash": "0" * 64}, "IL004", "payload_hash"),
        ({"scope": ""}, "IL002", None),
        # The hash is over the bytes sent, so a re-encoding is a mismatch.
        (
            {
                "payload": '{"to": "a@b.c", "subject": "s"}',
                "payload_hash": hashlib.sha256(b'{"subject":"s","to":"a@b.c"}').hexdigest(),
            },
            "IL004",
            "payload_hash",
        ),
    ],
)
def test_enqueue_refuses_on_its_own(
    pg: Pg, overrides: dict[str, Any], sqlstate: str, reason: str | None
) -> None:
    with raw_stage(pg) as (conn, token):
        with pytest.raises(psycopg.Error) as caught:
            call_enqueue(conn, token, **overrides)
        assert caught.value.sqlstate == sqlstate
        if reason is not None:
            assert f'"reason" : "{reason}"' in (caught.value.diag.message_detail or "")


def test_enqueue_writes_with_the_right_token(pg: Pg) -> None:
    with raw_stage(pg) as (conn, token):
        call_enqueue(conn, token, effect="one")
        call_enqueue(conn, token, effect="two", seq=2)
        staged = conn.execute("SELECT out_effect FROM interlock.stage_outbox(10)").fetchall()
        assert staged == [("one",), ("two",)]
        # One request per effect per stage.
        with pytest.raises(psycopg.errors.UniqueViolation):
            call_enqueue(conn, token, effect="one", seq=3)
    # Rolled back with the stage.
    assert outbox(pg) == []


def test_enqueue_outside_a_stage_is_refused(pg: Pg) -> None:
    with psycopg.connect(pg.agent) as conn, pytest.raises(psycopg.Error) as caught:
        call_enqueue(conn, secrets.token_bytes(32))
    assert caught.value.sqlstate == "IL002"


def test_a_role_without_the_grant_cannot_call_enqueue(pg: Pg) -> None:
    with role(pg, "il_outsider") as outsider:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {outsider}")
        dsn = make_conninfo(pg.admin, user=outsider, password=PASSWORD)
        with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            call_enqueue(conn, secrets.token_bytes(32))


# --------------------------------------------------------------------------
# append-only
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        'UPDATE interlock.outbox SET payload = \'{"to": "attacker@evil.test"}\'',
        "UPDATE interlock.outbox SET sink = 'payments'",
        "DELETE FROM interlock.outbox",
        "TRUNCATE interlock.outbox CASCADE",
        "UPDATE interlock.outbox_attempts SET event = 'delivered'",
        "DELETE FROM interlock.outbox_attempts",
        "TRUNCATE interlock.outbox_attempts",
    ],
)
def test_the_outbox_is_append_only_even_for_its_owner(pg: Pg, statement: str) -> None:
    assert engine(pg).execute(ship().build()).committed
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO interlock.outbox_attempts (message_id, seq, event, actor, at, "
            "prev_hash, event_hash, state_after) SELECT message_id, 1, 'held', 'owner', now(), "
            "'', '', 'held' FROM interlock.outbox"
        )
        before = conn.execute(
            "SELECT o.*, a.* FROM interlock.outbox o JOIN interlock.outbox_attempts a "
            "USING (message_id)"
        ).fetchall()
        with pytest.raises(psycopg.Error) as caught:
            conn.execute(statement)
        assert caught.value.sqlstate == "IL002"
        after = conn.execute(
            "SELECT o.*, a.* FROM interlock.outbox o JOIN interlock.outbox_attempts a "
            "USING (message_id)"
        ).fetchall()
    assert after == before


@pytest.mark.parametrize(
    "tamper",
    [
        "ALTER TABLE interlock.outbox DISABLE TRIGGER outbox_append_only",
        "ALTER TABLE interlock.outbox ENABLE REPLICA TRIGGER outbox_append_only_truncate",
        "DROP TRIGGER attempts_append_only ON interlock.outbox_attempts",
        "ALTER TABLE interlock.outbox_attempts DISABLE TRIGGER outbox_log_link",
    ],
)
def test_a_stage_will_not_open_over_an_outbox_that_can_be_rewritten(pg: Pg, tamper: str) -> None:
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(tamper)
    with pytest.raises(SubstrateConfigurationError, match="could be rewritten"):
        engine(pg).execute(ship().build())
    untouched(pg)
    reinstall(pg)
    assert engine(pg).execute(ship().build()).committed


def test_delivery_state_is_the_part_that_moves(pg: Pg) -> None:
    assert engine(pg).execute(ship().build()).committed
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute("UPDATE interlock.outbox_state SET state = 'held', reason = 'scope halted'")
    assert scalar(pg.admin, "SELECT state FROM interlock.outbox_state") == "held"


# --------------------------------------------------------------------------
# receipts and repair
# --------------------------------------------------------------------------


def test_the_receipt_commits_to_the_request(pg: Pg) -> None:
    key = HmacKey.generate()
    log = ReceiptLog("interlock-receipts", key)
    plan = ship().build()
    result = engine(pg, receipts=ReceiptIssuer(log)).execute(plan)
    assert result.committed
    receipt = result.receipt
    assert receipt is not None
    effect = receipt.effect
    assert effect.row_count == 2
    assert (effect.summary.inserted, effect.summary.updated) == (1, 1)
    assert set(effect.summary.tables) == {"orders", "interlock.outbox"}
    assert effect.summary.tenants == ("acme",)
    assert any(
        g.startswith("1 outbound request(s): delivered at least once")
        for g in receipt.coverage.known_gaps
    )
    index = log.index_of(receipt.receipt_id)
    assert index is not None
    report = verify_bundle(log.bundle(index, log.checkpoint()), issuer_key=key)
    assert report.passed, report.to_json()


def test_repair_keeps_the_request_the_admissible_part_needs(pg: Pg) -> None:
    """The search stages the request in every candidate, in savepoints, and
    commits none of them; the proposal enqueues it under its own plan id."""
    plan = (
        ship()
        .update(
            table="orders",
            statement="UPDATE orders SET status = 'cancelled'",
            effect_id=EffectId("everything"),
            independent=True,
        )
        .build()
    )
    eng = engine(pg, BlastRadius(1))
    repair = eng.repair(plan)
    untouched(pg)
    assert repair.proposal is not None
    assert set(repair.kept) == {"ship", "notify"}
    result = eng.execute(repair.proposal)
    assert result.committed
    (row,) = outbox(pg)
    assert row["plan_id"] == repair.proposal.plan_id
    assert row["idempotency_key"] == outbound_key(repair.proposal.plan_id, EffectId("notify"))


def test_repair_drops_a_request_no_sink_admits(pg: Pg) -> None:
    plan: EffectPlan = (
        ship()
        .enqueue(sink="sms", operation="send", payload={"n": 1}, effect_id=EffectId("sms"))
        .build()
    )
    repair = engine(pg).repair(plan)
    assert repair.proposal is not None
    assert set(repair.kept) == {"ship", "notify"}
    (dropped,) = repair.dropped
    assert (dropped.effect_id, dropped.cause) == ("sms", "inadmissible")
    untouched(pg)


def test_an_outbox_from_a_pre_release_build_is_refused_not_reshaped(pg_back_office: str) -> None:
    """Phases 0 and 1 kept a different delivery log. Installing over it would
    leave functions reading columns that do not exist: refused, saying what
    to do."""
    with psycopg.connect(pg_back_office, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA interlock")
        conn.execute("CREATE TABLE interlock.outbox_attempts (attempt_hash text)")
        with pytest.raises(psycopg.Error, match="pre-release build") as caught:
            install(conn, specs("orders"))
        assert caught.value.sqlstate == "IL005"
