"""Outbound requests (Epic 2, phases 0 and 1), everything short of a database.

The PostgreSQL half, where a request is written to the outbox in the stage's
transaction, is ``test_outbox_postgres.py``. What is checked here:

- An :class:`OutboundRequest` is canonical, hashed over the bytes the outbox
  stores, and frozen; the domain ARC1 refuses, and NUL, are refused.
- An ``ENQUEUE`` effect carries a request and nothing else, and adding one
  leaves every hash that existed before unchanged (vectors pinned from the
  release before outbound requests).
- The sink registry: allowlisted operations, payload bounds, credential-like
  fields, the JSON Schema subset, and the compensation rule (E4-3).
- Admission refuses a request before any stage opens, and tells the agent
  which rule it broke without echoing the payload.
- ``[[sinks]]`` in the configuration file.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts.canonical import canonical_bytes

from interlock import AgentFeedback, EscrowEngine, PlanBuilder, PostgresSubstrate, SqliteSubstrate
from interlock.config import ConfigError, load_config
from interlock.exceptions import OutboundRequestError, PlanError
from interlock.feedback import Guidance
from interlock.outbound import (
    NONE_POSSIBLE,
    OperationSpec,
    SinkRegistry,
    SinkSpec,
    schema_problems,
)
from interlock.types import (
    MAX_NOT_AFTER,
    OUTBOX_TARGET,
    Compensation,
    Effect,
    EffectDiff,
    EffectId,
    EffectKind,
    EffectPlan,
    OutboundDelta,
    OutboundRequest,
    PlanId,
    RowDelta,
    outbound_key,
)
from tests.schemas import MAIL_SEND_SCHEMA, TEST_SINKS, specs

MAIL = {"to": "ann@acme.test", "subject": "Your refund", "body": "We refunded 3.00."}
LEAKY = {"password": "hunter2"}
"""A payload field the relay supplies, never the agent."""


def mail(**payload: Any) -> OutboundRequest:
    return OutboundRequest("mail", "send", payload or MAIL)


def refund(amount: str = "3.00", **kwargs: Any) -> OutboundRequest:
    return OutboundRequest("payments", "refund", {"order": 1, "amount": amount}, **kwargs)


def reverse(amount: str = "3.00") -> OutboundRequest:
    return OutboundRequest("payments", "refund.reverse", {"order": 1, "amount": amount})


REGISTRY = SinkRegistry(TEST_SINKS)


# --------------------------------------------------------------------------
# the request
# --------------------------------------------------------------------------


def test_a_request_is_hashed_over_its_canonical_bytes() -> None:
    request = OutboundRequest("mail", "send", {"subject": "é ✓", "to": "a@b.c", "n": 2**53 - 1})
    assert request.canonical_payload == canonical_bytes(
        {"n": 2**53 - 1, "subject": "é ✓", "to": "a@b.c"}
    )
    assert request.payload_hash == hashlib.sha256(request.canonical_payload).hexdigest()
    reordered = OutboundRequest("mail", "send", {"n": 2**53 - 1, "to": "a@b.c", "subject": "é ✓"})
    assert reordered.payload_hash == request.payload_hash
    assert reordered == request


def test_a_request_payload_is_frozen_and_detached_from_the_caller() -> None:
    body: dict[str, Any] = {"to": "a@b.c", "subject": "s", "tags": ["x", {"k": "v"}]}
    request = OutboundRequest("mail", "send", body)
    body["to"] = "attacker@evil.test"
    body["tags"].append("y")
    assert request.payload["to"] == "a@b.c"
    assert request.payload["tags"] == ("x", {"k": "v"})
    with pytest.raises(TypeError):
        request.payload["to"] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        request.payload["tags"][1]["k"] = "w"
    assert request.canonical_payload == canonical_bytes(
        {"subject": "s", "tags": ["x", {"k": "v"}], "to": "a@b.c"}
    )


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({"amount": 1.5}, "float"),
        ({"n": 2**53}, "2\\^53|range|integer"),
        ({"note": "a\x00b"}, "NUL"),
        ({"a\x00": "b"}, "NUL"),
        ({"deep": [{"x": "\x00"}]}, "NUL"),
        ({1: "x"}, "key|string"),
    ],
)
def test_a_payload_outside_the_canonical_domain_is_refused(
    payload: dict[Any, Any], match: str
) -> None:
    with pytest.raises(PlanError, match=match):
        OutboundRequest("mail", "send", payload)


def test_a_payload_is_a_json_object() -> None:
    with pytest.raises(PlanError, match="JSON object"):
        OutboundRequest("mail", "send", ["not", "an", "object"])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "not_after", [timedelta(0), timedelta(seconds=-1), MAX_NOT_AFTER + timedelta(seconds=1)]
)
def test_not_after_is_positive_and_bounded(not_after: timedelta) -> None:
    with pytest.raises(PlanError, match="not_after"):
        OutboundRequest("mail", "send", MAIL, not_after=not_after)
    assert OutboundRequest("mail", "send", MAIL, not_after=MAX_NOT_AFTER).not_after == MAX_NOT_AFTER


def test_the_content_hash_covers_everything_the_request_does() -> None:
    base = refund(compensation=reverse())
    variants = [
        refund("3.01", compensation=reverse()),
        refund(compensation=reverse("3.01")),
        refund(compensation=reverse(), not_after=timedelta(minutes=5)),
        replace(base, operation="refund.reverse"),
        OutboundRequest("mail", "refund", base.payload, compensation=reverse()),
    ]
    hashes = {base.content_hash(), *(v.content_hash() for v in variants)}
    assert len(hashes) == len(variants) + 1


def test_to_json_carries_the_canonical_payload_and_its_hash() -> None:
    request = refund(not_after=timedelta(minutes=5))
    document = request.to_json()
    assert document == {
        "sink": "payments",
        "operation": "refund",
        "payload_hash": request.payload_hash,
        "payload": {"amount": "3.00", "order": 1},
        "not_after_seconds": 300,
    }
    assert canonical_bytes(document["payload"]) == request.canonical_payload


def test_the_idempotency_key_is_per_plan_and_effect_and_reproducible() -> None:
    key = outbound_key(PlanId("plan-a"), EffectId("e1"))
    assert key == outbound_key(PlanId("plan-a"), EffectId("e1"))
    assert (
        len(
            {
                key,
                outbound_key(PlanId("plan-b"), EffectId("e1")),
                outbound_key(PlanId("plan-a"), EffectId("e2")),
            }
        )
        == 3
    )
    # Not a concatenation: ("plan-a", "e1x") and ("plan-ae", "1x") differ.
    assert outbound_key(PlanId("a"), EffectId("bc")) != outbound_key(PlanId("ab"), EffectId("c"))


# --------------------------------------------------------------------------
# the effect, and every hash that existed before it
# --------------------------------------------------------------------------


def enqueue_effect(**overrides: Any) -> Effect:
    fields: dict[str, Any] = {
        "effect_id": EffectId("notify"),
        "kind": EffectKind.ENQUEUE,
        "target": OUTBOX_TARGET,
        "statement": "",
        "reversible": False,
        "request": mail(),
    }
    return Effect(**(fields | overrides))


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"request": None}, "no outbound request"),
        ({"statement": "UPDATE orders SET total = 0"}, "a statement"),
        ({"parameters": {"id": 1}}, "statement parameters"),
        ({"compensation": Compensation(statement="SELECT 1")}, "SQL compensation"),
        ({"target": "orders"}, "target other than"),
        ({"stated_rows": 1}, "stated_rows"),
    ],
)
def test_an_enqueue_effect_carries_a_request_and_nothing_else(
    overrides: dict[str, Any], match: str
) -> None:
    with pytest.raises(PlanError, match=match):
        enqueue_effect(**overrides)


def test_only_an_enqueue_effect_carries_a_request() -> None:
    with pytest.raises(PlanError, match="request"):
        Effect(
            effect_id=EffectId("e"),
            kind=EffectKind.UPDATE,
            target="orders",
            statement="UPDATE orders SET total = 0",
            request=mail(),
        )


def test_the_builder_enqueues_through_enqueue_only() -> None:
    with pytest.raises(PlanError, match="enqueue"):
        PlanBuilder("agent").add(EffectKind.ENQUEUE, table=OUTBOX_TARGET, statement="")
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET total = 0", stated_rows=2)
        .enqueue(sink="mail", operation="send", payload=MAIL, tenant_id="acme")
        .build()
    )
    order, notify = plan.effects
    assert notify.kind is EffectKind.ENQUEUE
    assert notify.target == OUTBOX_TARGET
    assert notify.depends_on == (order.effect_id,)
    assert notify.tenant_id == "acme"
    assert not notify.reversible
    assert notify.request == mail()
    # The request states no rows, and does not blind StatedFootprint.
    assert plan.stated_rows == 2


def test_the_builder_refuses_a_bad_payload_where_it_is_written() -> None:
    with pytest.raises(PlanError, match="float"):
        PlanBuilder("agent").enqueue(sink="mail", operation="send", payload={"x": 0.1})


def test_the_request_is_part_of_the_effect_and_plan_hash() -> None:
    def plan(request: OutboundRequest) -> EffectPlan:
        return EffectPlan(
            plan_id=PlanId("p"),
            scope_id="agent",
            trajectory_id="t",
            created_at=datetime(2026, 9, 30, tzinfo=UTC),
            effects=(enqueue_effect(request=request),),
        )

    a, b = plan(mail()), plan(mail(to="b@acme.test", subject="s"))
    assert a.effects[0].content_hash() != b.effects[0].content_hash()
    assert a.content_hash() != b.content_hash()


# Computed by the release before outbound requests existed, for the same plan
# and diff. Outbound fields enter a hash only when present, so none moves.
PINNED_PLAN = "b855d358d4cc6541a224975440e81e5acdff31a89e5f83e40b6eb84a6926c1c6"
PINNED_E1 = "e888e5869581018f047e6e6830235dbc7307685a97821ee2a17a955f993c712a"
PINNED_E2 = "abeed95da0c27e29a2e64fd009f4947d193ed8f1416d4812abbc48bfdc8ac907"
PINNED_DIFF = "802ceada81074ef190e227b5015eed4abed4db57c0f5e6f8a2933b6f4d689476"


def pinned_plan() -> EffectPlan:
    return EffectPlan(
        plan_id=PlanId("plan-vector"),
        scope_id="support-agent",
        trajectory_id="traj-vector",
        created_at=datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        effects=(
            Effect(
                effect_id=EffectId("e1"),
                kind=EffectKind.UPDATE,
                target="orders",
                statement="UPDATE orders SET total = :total WHERE id = :id",
                parameters={"total": Decimal("10.50"), "id": 1},
                tenant_id="acme",
                stated_rows=1,
            ),
            Effect(
                effect_id=EffectId("e2"),
                kind=EffectKind.INSERT,
                target="refunds",
                statement="INSERT INTO refunds (id, amount) VALUES (:id, :amount)",
                parameters={"id": 7, "amount": "1.00"},
                depends_on=(EffectId("e1"),),
                reversible=False,
                compensation=Compensation(
                    statement="DELETE FROM refunds WHERE id = :id", parameters={"id": 7}
                ),
            ),
        ),
        intent="vector",
    )


def pinned_diff(outbound: tuple[OutboundDelta, ...] = ()) -> EffectDiff:
    return EffectDiff(
        plan_id=PlanId("plan-vector"),
        stage_id=uuid.UUID(int=7),
        substrate_id="postgres:back_office",
        computed_at=datetime(2026, 9, 30, 12, 0, 1, tzinfo=UTC),
        deltas=(
            RowDelta(
                "orders",
                "1",
                {"id": 1, "total": Decimal("9.00")},
                {"id": 1, "total": Decimal("10.50")},
                "acme",
            ),
            RowDelta("refunds", "7", None, {"id": 7, "amount": Decimal("1.00")}),
        ),
        outbound=outbound,
    )


def test_hashes_from_before_outbound_requests_are_unchanged() -> None:
    plan = pinned_plan()
    assert plan.effects[0].content_hash() == PINNED_E1
    assert plan.effects[1].content_hash() == PINNED_E2
    assert plan.content_hash() == PINNED_PLAN
    assert pinned_diff().content_hash() == PINNED_DIFF


def delta(effect: str, *, message: uuid.UUID | None = None, **overrides: Any) -> OutboundDelta:
    request = mail()
    fields: dict[str, Any] = {
        "message_id": message or uuid.uuid4(),
        "effect_id": EffectId(effect),
        "sink": "mail",
        "operation": "send",
        "tenant_id": "acme",
        "payload": request.payload,
        "payload_hash": request.payload_hash,
        "idempotency_key": outbound_key(PlanId("plan-vector"), EffectId(effect)),
    }
    return OutboundDelta(**(fields | overrides))


def test_the_diff_hash_covers_the_outbox_but_not_the_message_ids() -> None:
    one, two = delta("n1"), delta("n2")
    staged = pinned_diff((one, two))
    assert staged.content_hash() != PINNED_DIFF
    # A replay mints fresh message ids and reads the rows back in any order.
    replayed = pinned_diff(
        (replace(two, message_id=uuid.uuid4()), replace(one, message_id=uuid.uuid4()))
    )
    assert replayed.content_hash() == staged.content_hash()
    for changed in (
        replace(one, payload_hash="0" * 64),
        replace(one, sink="payments"),
        replace(one, operation="refund"),
        replace(one, tenant_id="globex"),
        replace(one, idempotency_key="k"),
        replace(one, depends_on=(EffectId("n2"),)),
    ):
        assert pinned_diff((changed, two)).content_hash() != staged.content_hash()


# --------------------------------------------------------------------------
# the registry
# --------------------------------------------------------------------------


def refused(request: OutboundRequest, registry: SinkRegistry = REGISTRY) -> OutboundRequestError:
    with pytest.raises(OutboundRequestError) as caught:
        registry.check(request)
    return caught.value


def test_a_registered_request_is_admitted() -> None:
    assert REGISTRY.check(mail()).name == "mail"
    assert REGISTRY.check(refund(compensation=reverse())).name == "payments"
    assert [s.name for s in REGISTRY] == ["mail", "payments"]
    assert len(REGISTRY) == 2
    assert REGISTRY.get("sms") is None


def test_an_unregistered_sink_or_operation_is_refused() -> None:
    assert refused(OutboundRequest("sms", "send", MAIL)).reason == "unregistered_sink"
    error = refused(OutboundRequest("mail", "delete_all", MAIL))
    assert (error.reason, error.sink) == ("unregistered_operation", "mail")


def test_a_payload_over_the_sinks_bound_is_refused() -> None:
    error = refused(mail(to="a@b.c", subject="s", body="x" * 5000))
    assert error.reason == "payload_size"
    tight = SinkRegistry(
        [
            SinkSpec(
                "mail", (OperationSpec("send"),), max_payload_bytes=len(mail().canonical_payload)
            )
        ]
    )
    assert tight.check(mail()).name == "mail"
    assert refused(mail(**MAIL, extra="y"), tight).reason == "payload_size"


@pytest.mark.parametrize(
    "payload",
    [
        {"api_key": "k"},
        {"API-Key": "k"},
        {"password": "p"},
        {"nested": {"clientSecret": "s"}},
        {"list": [{"Authorization": "Bearer x"}]},
        {"token": "t"},
        {"refresh_token": "t"},
        {"private_key": "k"},
        {"auth": "a"},
    ],
)
def test_a_credential_like_field_is_refused(payload: dict[str, Any]) -> None:
    open_sink = SinkRegistry([SinkSpec("hook", (OperationSpec("post"),))])
    error = refused(OutboundRequest("hook", "post", payload), open_sink)
    assert error.reason == "credential_field"


@pytest.mark.parametrize(
    "payload",
    [{"key": "k"}, {"monkey": 1}, {"tokens_used": 3}, {"author": "a"}, {"idempotency": "x"}],
)
def test_an_ordinary_field_is_not_mistaken_for_a_credential(payload: dict[str, Any]) -> None:
    open_sink = SinkRegistry([SinkSpec("hook", (OperationSpec("post"),))])
    assert open_sink.check(OutboundRequest("hook", "post", payload)).name == "hook"


@pytest.mark.parametrize(
    ("payload", "problem"),
    [
        ({"subject": "s"}, "required"),
        ({"to": "not-an-address", "subject": "s"}, "pattern"),
        ({"to": "a@b.c", "subject": "s" * 201}, "long"),
        ({"to": "a@b.c", "subject": "s", "bcc": "x@y.z"}, "not an allowed field"),
        ({"to": "a@b.c", "subject": 3}, "string"),
    ],
)
def test_a_payload_that_breaks_its_schema_is_refused(payload: dict[str, Any], problem: str) -> None:
    error = refused(OutboundRequest("mail", "send", payload))
    assert error.reason == "payload_schema"
    assert problem in str(error)


def test_the_compensation_rule() -> None:
    """An operation with an undo needs it written down before the do; one
    declared impossible to undo may not pretend otherwise."""
    assert refused(refund()).reason == "compensation"
    assert refused(OutboundRequest("mail", "send", MAIL, compensation=mail())).reason == (
        "compensation"
    )
    wrong = OutboundRequest("payments", "refund", {"order": 1})
    assert "not payments.refund" in str(refused(refund(compensation=wrong)))
    nested = replace(reverse(), compensation=reverse())
    assert "of its own" in str(refused(refund(compensation=nested)))
    # The compensation is itself a request, held to the same rules.
    leaky = OutboundRequest("payments", "refund.reverse", {"order": 1, "password": "p"})
    assert refused(refund(compensation=leaky)).reason == "credential_field"


# -- registration ----------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "match"),
    [
        (lambda: SinkSpec("Mail", (OperationSpec("send"),)), "lowercase"),
        (lambda: SinkSpec("mail", ()), "no operations"),
        (lambda: SinkSpec("mail", (OperationSpec("send"), OperationSpec("send"))), "twice"),
        (lambda: SinkSpec("mail", (OperationSpec("send", compensation="unsend"),)), "unsend"),
        (lambda: SinkSpec("mail", (OperationSpec("send"),), cost_per_call=Decimal(-1)), "negative"),
        (lambda: SinkSpec("mail", (OperationSpec("send"),), idempotency="maybe"), "idempotency"),
        (lambda: SinkSpec("mail", (OperationSpec("send"),), max_payload_bytes=0), "positive"),
        (lambda: SinkSpec("mail", (OperationSpec("send"),), not_after=timedelta(0)), "not_after"),
        (lambda: OperationSpec("Send"), "identifier"),
        (lambda: OperationSpec("send", compensation="Un Send"), "compensation"),
        (lambda: OperationSpec("send", schema={"$ref": "#/x"}), r"\$ref"),
        (lambda: OperationSpec("send", schema={"type": "object", "oneOf": []}), "oneOf"),
        # A float is outside the canonical domain, so "number" is too.
        (lambda: OperationSpec("send", schema={"type": "number"}), "type must be one of"),
        (lambda: OperationSpec("send", schema={"additionalProperties": {}}), "additional"),
        (lambda: OperationSpec("send", schema={"pattern": "("}), "pattern"),
        (lambda: SinkRegistry([TEST_SINKS[0], TEST_SINKS[0]]), "twice"),
    ],
)
def test_a_registration_the_registry_could_not_enforce_is_refused(build: Any, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        build()


def test_the_config_hash_covers_what_the_sink_permits() -> None:
    base = TEST_SINKS[0]
    variants = [
        replace(base, cost_per_call=Decimal("0.003")),
        replace(base, max_payload_bytes=4097),
        replace(base, not_after=timedelta(minutes=16)),
        replace(base, idempotency="none"),
        replace(base, operations=(OperationSpec("send"),)),
    ]
    assert len({base.config_hash(), *(v.config_hash() for v in variants)}) == len(variants) + 1


# -- the schema subset -------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "schema", "ok"),
    [
        ("5.00", {"type": "string", "minimum": 0, "maximum": "10"}, True),
        ("10.01", {"type": "string", "maximum": "10"}, False),
        (-1, {"type": "integer", "minimum": 0}, False),
        ("abc", {"type": "string", "minimum": 0}, False),
        (True, {"type": "integer"}, False),
        ("b", {"enum": ["a", "b"]}, True),
        ("c", {"enum": ["a", "b"]}, False),
        ("x", {"const": "x"}, True),
        ([1, 2], {"type": "array", "items": {"type": "integer"}, "maxItems": 2}, True),
        ([1, "2"], {"type": "array", "items": {"type": "integer"}}, False),
        ([], {"type": "array", "minItems": 1}, False),
        ("", {"type": "string", "minLength": 1}, False),
        (None, {"type": "null"}, True),
        ({"a": {"b": 1}}, {"properties": {"a": {"properties": {"b": {"type": "string"}}}}}, False),
    ],
)
def test_the_schema_subset(value: Any, schema: dict[str, Any], ok: bool) -> None:
    assert (schema_problems(value, schema) == []) is ok


def test_a_schema_problem_names_where_it_is() -> None:
    problems = schema_problems({"to": 3, "subject": "s"}, MAIL_SEND_SCHEMA)
    assert problems and problems[0].startswith("$.to")


# --------------------------------------------------------------------------
# admission
# --------------------------------------------------------------------------


def notify(**payload: Any) -> EffectPlan:
    return (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET total = 0")
        .enqueue(sink="mail", operation="send", payload=payload or MAIL)
        .build()
    )


def unreachable() -> PostgresSubstrate:
    """A substrate that fails loudly if anything tries to open a stage."""
    return PostgresSubstrate(
        "postgresql://nobody@127.0.0.1:1/none?connect_timeout=1", tables=specs("orders")
    )


def test_sqlite_has_no_outbox(back_office: str) -> None:
    engine = EscrowEngine(SqliteSubstrate(back_office, tables=specs("orders")), checkers=[])
    with pytest.raises(OutboundRequestError, match="outbox") as caught:
        engine.execute(notify())
    assert caught.value.reason == "substrate"
    feedback = caught.value.feedback
    assert isinstance(feedback, AgentFeedback)
    assert feedback.constraints[0].guidance is Guidance.OUTBOUND_REQUEST


def test_sqlite_refuses_to_apply_a_request_directly(back_office: str) -> None:
    substrate = SqliteSubstrate(back_office, tables=specs("orders"))
    plan = notify()
    handle = substrate.open(plan)
    try:
        with pytest.raises(OutboundRequestError) as caught:
            substrate.apply(handle, plan.effects[1])
        assert caught.value.reason == "substrate"
    finally:
        substrate.abort(handle)
        substrate.close(handle)


def test_an_engine_without_a_registry_admits_no_request() -> None:
    engine = EscrowEngine(unreachable(), checkers=[])
    with pytest.raises(OutboundRequestError) as caught:
        engine.admit(notify())
    assert caught.value.reason == "no_registry"


def test_admission_checks_the_registry_before_a_stage_opens() -> None:
    engine = EscrowEngine(unreachable(), checkers=[], sinks=REGISTRY)
    engine.admit(notify())
    for plan, reason in (
        (notify(to="a@b.c", subject="s", **LEAKY), "credential_field"),
        (notify(to="nobody", subject="s"), "payload_schema"),
        (
            PlanBuilder("agent").enqueue(sink="sms", operation="send", payload=MAIL).build(),
            "unregistered_sink",
        ),
    ):
        # execute(), not admit(): the refusal arrives before the substrate is
        # asked for a stage, or it would be SubstrateUnavailableError.
        with pytest.raises(OutboundRequestError) as caught:
            engine.execute(plan)
        assert caught.value.reason == reason


def test_the_agent_is_told_the_rule_and_not_its_own_payload_back() -> None:
    engine = EscrowEngine(unreachable(), checkers=[], sinks=REGISTRY)
    with pytest.raises(OutboundRequestError) as caught:
        engine.execute(notify(to="a@b.c", subject="s", **LEAKY))
    feedback = caught.value.feedback
    assert isinstance(feedback, AgentFeedback)
    text = feedback.render() + json.dumps(feedback.to_json())
    assert "outbound request" in text
    assert "hunter2" not in text
    assert "password" not in text
    assert [c.guidance for c in feedback.constraints] == [Guidance.OUTBOUND_REQUEST]


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

CONFIG = """
substrate = "postgres"
database = "postgresql://agent@db/app"
relay_roles = ["interlock_relay"]

[[tables]]
name = "orders"
columns = ["id", "total"]

[[sinks]]
name = "mail"
cost_per_call = "0.002"
max_payload_bytes = 4096
not_after_seconds = 600

[[sinks.operations]]
name = "send"
schema = "schemas/mail-send.json"

[[sinks]]
name = "payments"
idempotency = "none"

[[sinks.operations]]
name = "refund"
compensation = "refund.reverse"

[[sinks.operations]]
name = "refund.reverse"
"""


def write_config(tmp_path: Path, text: str = CONFIG) -> Path:
    (tmp_path / "schemas").mkdir(exist_ok=True)
    (tmp_path / "schemas" / "mail-send.json").write_text(json.dumps(MAIL_SEND_SCHEMA))
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    return path


def test_sinks_are_read_from_the_config_file(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path))
    assert config.relay_roles == ("interlock_relay",)
    mail_sink, payments = config.sinks
    assert mail_sink == SinkSpec(
        "mail",
        (OperationSpec("send", schema=MAIL_SEND_SCHEMA),),
        cost_per_call=Decimal("0.002"),
        max_payload_bytes=4096,
        not_after=timedelta(minutes=10),
    )
    assert payments.idempotency == "none"
    assert payments.operation("refund") == OperationSpec("refund", compensation="refund.reverse")
    assert payments.operation("refund.reverse") == OperationSpec("refund.reverse", NONE_POSSIBLE)
    assert config.sink_registry().check(mail()).name == "mail"
    moved = config.with_database("postgresql://other/app")
    assert (moved.database, moved.sinks, moved.relay_roles) == (
        "postgresql://other/app",
        config.sinks,
        config.relay_roles,
    )


@pytest.mark.parametrize(
    ("edit", "match"),
    [
        (lambda t: t.replace('cost_per_call = "0.002"', "cost_per_call = 0.002"), "decimal string"),
        (
            lambda t: t.replace('cost_per_call = "0.002"', 'cost_per_call = "cheap"'),
            "not a decimal",
        ),
        (lambda t: t.replace("max_payload_bytes = 4096", 'max_payload_bytes = "4k"'), "integer"),
        (lambda t: t.replace("mail-send.json", "missing.json"), "cannot read schema"),
        (lambda t: t.replace('substrate = "postgres"', 'substrate = "sqlite"'), "postgres"),
        (lambda t: t.replace('name = "payments"', 'name = "mail"'), "twice"),
        (lambda t: t.replace('compensation = "refund.reverse"', 'compensation = "undo"'), "undo"),
        (lambda t: t + '\n[[sinks]]\nname = "empty"\n', r"sinks\[2\].*operations"),
        (
            lambda t: t.replace('[[sinks.operations]]\nname = "send"', "[[sinks.operations]]"),
            "name",
        ),
    ],
)
def test_a_malformed_sink_is_named(tmp_path: Path, edit: Any, match: str) -> None:
    path = write_config(tmp_path, edit(CONFIG))
    with pytest.raises(ConfigError, match=match):
        load_config(path)


def test_a_schema_file_must_be_a_json_object(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    (tmp_path / "schemas" / "mail-send.json").write_text("[1, 2]")
    with pytest.raises(ConfigError, match="not a JSON object"):
        load_config(path)
    (tmp_path / "schemas" / "mail-send.json").write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(path)


# --------------------------------------------------------------------------
# the relay's configuration and retry policy
# --------------------------------------------------------------------------

RELAY = """
[relay]
database = "postgresql://relay@db/app"
ledger = "/var/lib/agentgov/ledger.db"
lease_seconds = 30
timeout_seconds = 5
workers = 4

[[relay.endpoints]]
sink = "mail"
url = "https://mail.example"
routes = { send = "POST /v3/send" }
header_env = { Authorization = "MAIL_AUTHORIZATION" }

[[relay.endpoints]]
sink = "payments"
url = "https://pay.example"
routes = { refund = "POST /refunds", "refund.reverse" = "POST /refunds/reverse" }
"""


def test_the_relay_section_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTERLOCK_RELAY_DATABASE", raising=False)
    config = load_config(write_config(tmp_path, CONFIG + RELAY))
    relay = config.relay
    assert relay is not None
    assert (relay.database, relay.ledger, relay.breaker, relay.workers) == (
        "postgresql://relay@db/app",
        "/var/lib/agentgov/ledger.db",
        "agentgov",
        4,
    )
    assert (relay.lease, relay.timeout) == (timedelta(seconds=30), timedelta(seconds=5))
    mail_endpoint, payments = relay.endpoints
    assert mail_endpoint.header_env == {"Authorization": "MAIL_AUTHORIZATION"}
    assert payments.routes == {"refund": "POST /refunds", "refund.reverse": "POST /refunds/reverse"}
    monkeypatch.setenv("INTERLOCK_RELAY_DATABASE", "postgresql://other@db/app")
    moved = load_config(write_config(tmp_path, CONFIG + RELAY)).relay
    assert moved is not None and moved.database == "postgresql://other@db/app"


@pytest.mark.parametrize(
    ("edit", "match"),
    [
        (lambda t: t.replace('ledger = "/var/lib/agentgov/ledger.db"\n', ""), "ledger"),
        (lambda t: t.replace("lease_seconds = 30", "lease_seconds = 9"), "twice"),
        (lambda t: t.replace('sink = "payments"', 'sink = "sms"'), "no \\[\\[sinks\\]\\]"),
        (lambda t: t.replace(', "refund.reverse" = "POST /refunds/reverse"', ""), "missing"),
        (
            lambda t: t.replace(
                '{ send = "POST /v3/send" }', '{ send = "POST /v3/send", x = "y" }'
            ),
            "unknown",
        ),
        (
            lambda t: (
                t
                + '\n[[relay.endpoints]]\nsink = "mail"\nurl = "https://b.example"\n'
                + 'routes = { send = "POST /send" }\n'
            ),
            "same sink",
        ),
        (lambda t: t.replace("[[relay.endpoints]]", "[[relay.nothing]]"), "endpoints"),
        (lambda t: t.replace("timeout_seconds = 5", "timeout_seconds = 0"), "positive"),
    ],
)
def test_a_malformed_relay_section_is_named(tmp_path: Path, edit: Any, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(write_config(tmp_path, edit(CONFIG + RELAY)))


def test_no_breaker_is_said_out_loud(tmp_path: Path) -> None:
    text = (CONFIG + RELAY).replace(
        'ledger = "/var/lib/agentgov/ledger.db"\n', 'breaker = "none"\n'
    )
    relay = load_config(write_config(tmp_path, text)).relay
    assert relay is not None and (relay.breaker, relay.ledger) == ("none", None)
    with pytest.raises(ConfigError, match="'agentgov' or 'none'"):
        load_config(write_config(tmp_path, text.replace('breaker = "none"', 'breaker = "off"')))


def test_a_relay_host_needs_no_stage_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    text = (CONFIG + RELAY).replace('database = "postgresql://agent@db/app"\n', "", 1)
    with pytest.raises(ConfigError, match="no database"):
        load_config(write_config(tmp_path, text))
    assert load_config(write_config(tmp_path, text), require_database=False).relay is not None


@pytest.mark.parametrize(
    ("edit", "match"),
    [
        (
            lambda t: t.replace(
                "not_after_seconds = 600", "not_after_seconds = 600\nmax_attempts = 0"
            ),
            "max_attempts",
        ),
        (
            lambda t: t.replace(
                "not_after_seconds = 600", "not_after_seconds = 600\nbackoff_base_seconds = 0"
            ),
            "positive",
        ),
        (
            lambda t: t.replace(
                "not_after_seconds = 600", "not_after_seconds = 600\nbackoff_base_seconds = 900"
            ),
            "backoff_cap",
        ),
        (
            lambda t: t.replace(
                "not_after_seconds = 600", 'not_after_seconds = 600\nunknown_outcome = "maybe"'
            ),
            "unknown_outcome",
        ),
    ],
)
def test_a_malformed_retry_policy_is_named(tmp_path: Path, edit: Any, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load_config(write_config(tmp_path, edit(CONFIG)))


def test_the_retry_policy_is_read_and_hashed(tmp_path: Path) -> None:
    text = CONFIG.replace(
        "not_after_seconds = 600",
        "not_after_seconds = 600\nmax_attempts = 3\nbackoff_base_seconds = 0.5\n"
        'backoff_cap_seconds = 30\nunknown_outcome = "dead-letter"',
    )
    sink = load_config(write_config(tmp_path, text)).sinks[0]
    assert (sink.max_attempts, sink.backoff_base, sink.backoff_cap, sink.unknown_outcome) == (
        3,
        timedelta(milliseconds=500),
        timedelta(seconds=30),
        "dead-letter",
    )
    assert sink.config_hash() != load_config(write_config(tmp_path, CONFIG)).sinks[0].config_hash()
