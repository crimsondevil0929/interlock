"""The horizontal primitives (1.2): partitions, guards both ways, units, meters,
honest measurement, sink and source kinds of a package's own, held operations,
and MCP tools as a sink.

Each is additive: a configuration that uses none of it keeps every hash,
digest, verdict and receipt it had.
"""

from __future__ import annotations

import importlib.metadata
import sqlite3
import sys
import textwrap
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager, Unit
from agentgov.receipts import ReceiptLog
from agentgov.receipts.signing import HmacKey

import interlock.inbox as inbox_module
import interlock.outbound as outbound_module
from interlock import EscrowEngine, PlanBuilder, SqliteSubstrate, TableSpec
from interlock.config import ConfigError, Endpoint, load_config
from interlock.exceptions import MeterExhaustedError, PlanError
from interlock.feedback import AgentFeedback, FeedbackHint, Guidance, agent_feedback, sanitize
from interlock.inbox import (
    FieldSpec,
    InboundSource,
    Parsed,
    parse_events,
    register_source_kind,
    source_kinds,
)
from interlock.invariants import ColumnValueGuard, TenantDrawdownGuard, TenantIsolation
from interlock.mcp import (
    McpAdapter,
    McpCallError,
    McpRefusedError,
    StdioServer,
    classify,
    mcp_sink,
    relay_adapter,
)
from interlock.meters import Meter
from interlock.outbound import (
    DEAD_LETTER,
    REDELIVER,
    OperationSpec,
    SinkSpec,
    register_sink_kind,
    sink_kinds,
    typed_sink,
)
from interlock.outbound_checks import PayloadAmountCap
from interlock.receipts import _config, measurement_of, schema_hash
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery
from interlock.types import (
    Effect,
    EffectDiff,
    EffectId,
    EffectKind,
    EffectPlan,
    OutboundDelta,
    PlanId,
    RowDelta,
    SubstrateCapabilities,
    canonical_hash,
)
from interlock.windows import RateWindow, RateWindowCheck, Requests, RowSum
from tests.outbox_env import BACKENDS, SCOPE, Outbox, build_either

MED_ORDERS = TableSpec(
    "med_orders",
    columns=["id", "facility_id", "patient_id", "drug", "mme_per_day", "status"],
    partitions={"tenant": "facility_id", "patient": "patient_id"},
)


# --------------------------------------------------------------------------
# partitions
# --------------------------------------------------------------------------


def test_a_table_names_its_partitions_beside_its_tenant() -> None:
    assert MED_ORDERS.tenant_column == "facility_id"
    assert dict(MED_ORDERS.partitions) == {"patient": "patient_id"}
    assert MED_ORDERS.labels({"facility_id": "f-1", "patient_id": 7}) == ("f-1", {"patient": "7"})
    assert TableSpec("t", columns=["id"]).partitions == {}
    with pytest.raises(ValueError, match="must also be listed in columns"):
        TableSpec("t", columns=["id"], partitions={"patient": "patient_id"})
    with pytest.raises(ValueError, match="not a partition dimension"):
        TableSpec("t", columns=["id", "p"], partitions={"Patient": "p"})
    with pytest.raises(ValueError, match="as the tenant column"):
        TableSpec("t", columns=["id", "a", "b"], tenant_column="a", partitions={"tenant": "b"})


def _row(pk: str, before: Any, after: Any, *, tenant: str, patient: str | None) -> RowDelta:
    return RowDelta(
        "med_orders",
        pk,
        before,
        after,
        tenant_id=tenant,
        partitions={"patient": patient} if patient else {},
    )


def _diff(*rows: RowDelta, outbound: tuple[OutboundDelta, ...] = ()) -> EffectDiff:
    return EffectDiff(
        plan_id=PlanId("p"),
        stage_id=uuid.UUID(int=1),
        substrate_id="sqlite",
        computed_at=datetime(2026, 10, 30, tzinfo=UTC),
        deltas=rows,
        outbound=outbound,
    )


def test_a_diff_of_tenant_only_rows_keeps_its_hash() -> None:
    row = _row("1", {"x": 1}, {"x": 2}, tenant="f-1", patient=None)
    legacy = canonical_hash(
        ["p", "sqlite", False, [["med_orders", "1", "update", {"x": 1}, {"x": 2}, "f-1"]]]
    )
    assert _diff(row).content_hash() == legacy
    labeled = _row("1", {"x": 1}, {"x": 2}, tenant="f-1", patient="p-1")
    assert _diff(labeled).content_hash() != legacy
    assert _diff(labeled).partition_ids("patient") == {"p-1"}
    assert _diff(labeled).partition_ids("tenant") == {"f-1"}


def test_an_effect_hashes_its_partitions_only_when_it_declares_some() -> None:
    def effect(**partitions: str) -> Effect:
        return Effect(
            EffectId("e"),
            EffectKind.UPDATE,
            "sqlite:med_orders",
            "UPDATE med_orders SET status = 'x'",
            partitions=partitions,
        )

    assert effect().content_hash() == canonical_hash(
        [
            "e",
            "update",
            "sqlite:med_orders",
            "UPDATE med_orders SET status = 'x'",
            [],
            [],
            None,
            True,
        ]
    )
    assert effect(patient="p-1").content_hash() != effect().content_hash()
    assert effect(patient="p-1").partition("patient") == "p-1"
    with pytest.raises(PlanError, match="tenant is tenant_id"):
        effect(tenant="t")


def test_a_schema_with_no_partitions_keeps_its_digest() -> None:
    class Substrate:
        table_specs = (TableSpec("orders", columns=["id", "tenant"], tenant_column="tenant"),)

    legacy = canonical_hash(["schema", [["orders", "id", ["id", "tenant"], "tenant"]], []])
    assert schema_hash(Substrate()) == legacy

    class Partitioned:
        table_specs = (MED_ORDERS,)

    assert schema_hash(Partitioned()) != schema_hash(Substrate())


def _plan(*patients: str, tenant: str = "f-1") -> EffectPlan:
    builder = PlanBuilder("med-rec")
    for n, patient in enumerate(patients):
        builder.update(
            table="med_orders",
            statement="UPDATE med_orders SET status = 'held' WHERE id = :i",
            parameters={"i": n},
            tenant_id=tenant,
            partitions={"patient": patient},
            independent=True,
        )
    return builder.build()


def test_isolation_holds_a_plan_to_one_patients_chart() -> None:
    check = TenantIsolation(1, declared=True, dimension="patient")
    assert check.name == "partition_isolation:patient"
    plan = _plan("p-1")
    rows = (
        _row("1", {"s": "a"}, {"s": "b"}, tenant="f-1", patient="p-1"),
        _row("2", {"s": "a"}, {"s": "b"}, tenant="f-1", patient="p-2"),
    )
    spans, undeclared = check.check(plan, _diff(*rows))
    assert spans.message == "plan spans 2 patient partitions, limit is 1"
    assert "1 patient partition(s) its effects do not declare: p-2" in undeclared.message
    feedback = sanitize(
        check.hint(plan, _diff(*rows), undeclared), plan, blocking=True, trusted=True
    )
    assert feedback.tenants == ("p-1",) and feedback.withheld_tenants
    assert feedback.render() == (
        "tenant_isolation: the plan changed rows of a patient it does not declare; its "
        "declared patient is p-1. Confine every statement to its declared patient."
    )
    assert check.check(plan, _diff(rows[0])) == ()


def test_the_tenant_dimension_is_unchanged_and_so_is_its_digest() -> None:
    check = TenantIsolation(1)
    assert check.name == "tenant_isolation"
    assert [k for k, _ in _config(check)] == [
        "TenantIsolation",
        "_declared",
        "_max_tenants",
    ], "an option left unset is left out of the configuration's digest"
    assert ("_dimension", "'patient'") in _config(TenantIsolation(1, dimension="patient"))
    rows = (
        _row("1", {}, {}, tenant="a", patient=None),
        _row("2", {}, {}, tenant="b", patient=None),
    )
    (violation,) = check.check(_plan("p-1"), _diff(*rows))
    assert violation.message == "plan spans 2 tenants, limit is 1"
    with pytest.raises(ValueError, match="not a partition dimension"):
        TenantIsolation(1, dimension="Patient")


# --------------------------------------------------------------------------
# value guards, both ways
# --------------------------------------------------------------------------


def _dose(before: str, after: str, *, patient: str = "p-1", pk: str = "88123") -> RowDelta:
    return _row(
        pk,
        {"mme_per_day": Decimal(before)},
        {"mme_per_day": Decimal(after)},
        tenant="f-1",
        patient=patient,
    )


def test_a_guard_on_a_rise_catches_a_dose_read_in_micrograms() -> None:
    guard = ColumnValueGuard("med_orders", "mme_per_day", max_rise_fraction=0)
    (violation,) = guard.check(_plan("p-1"), _diff(_dose("0.125", "125")))
    assert violation.message == (
        "med_orders.mme_per_day rises 99900.0% (0.125 to 125), limit is 0%"
    )
    assert violation.evidence["before_total"] == "0.125"
    assert guard.check(_plan("p-1"), _diff(_dose("5", "5"))) == ()
    assert guard.check(_plan("p-1"), _diff(_dose("5", "2"))) == (), "a fall is not a rise"
    feedback = sanitize(
        guard.hint(_plan("p-1"), _diff(), violation), _plan("p-1"), blocking=True, trusted=True
    )
    assert feedback.guidance is Guidance.VALUE_RISE
    assert feedback.render() == (
        "column_value_guard: the plan raises med_orders.mme_per_day by more than the 0% allowed."
    )


def test_a_guard_configured_as_before_reaches_the_verdict_it_always_did() -> None:
    guard = ColumnValueGuard("med_orders", "mme_per_day", max_drop_fraction=0.25)
    (violation,) = guard.check(_plan("p-1"), _diff(_dose("100", "70")))
    assert violation.message == (
        "med_orders.mme_per_day falls 30.0% (100.00 to 70.00), limit is 25%"
    )
    assert violation.evidence == {
        "before_total": "100.00",
        "after_total": "70.00",
        "drop_fraction": "0.3000",
    }
    assert "_max_rise" not in dict(_config(guard))
    both = ColumnValueGuard(
        "med_orders", "mme_per_day", max_drop_fraction=0.25, max_rise_fraction=0.5
    )
    (exact,) = both.check(_plan("p-1"), _diff(_dose("100", "70")))
    assert exact.message == "med_orders.mme_per_day falls 30.0% (100 to 70), limit is 25%"
    with pytest.raises(ValueError, match="a drop, a rise, or both"):
        ColumnValueGuard("t", "c")
    with pytest.raises(ValueError, match="at least 0"):
        ColumnValueGuard("t", "c", max_rise_fraction=-1)


def test_a_partition_guard_bounds_each_patients_total() -> None:
    guard = TenantDrawdownGuard(
        "med_orders", "mme_per_day", max_rise_fraction=0.5, dimension="patient"
    )
    assert guard.name == "partition_value_guard:patient:med_orders.mme_per_day"
    rows = (_dose("10", "30", patient="p-1"), _dose("40", "41", patient="p-2", pk="88124"))
    (violation,) = guard.check(_plan("p-1"), _diff(*rows))
    assert violation.message == (
        "patient 'p-1' med_orders.mme_per_day rises 200.0% (10 to 30), limit is 50%"
    )
    assert violation.evidence["label"] == "p-1"
    feedback = sanitize(
        guard.hint(_plan("p-1"), _diff(*rows), violation),
        _plan("p-1"),
        blocking=True,
        trusted=True,
    )
    assert feedback.render() == (
        "column_value_guard: the plan raises med_orders.mme_per_day by more than the 50% "
        "allowed for patient p-1."
    )
    legacy = TenantDrawdownGuard("med_orders", "mme_per_day", max_drop_fraction=0.3)
    assert legacy.name == "tenant_drawdown_guard:med_orders.mme_per_day"
    assert [k for k, _ in _config(legacy)] == [
        "TenantDrawdownGuard",
        "_column",
        "_max_drop",
        "_table",
    ]


# --------------------------------------------------------------------------
# windows per partition, caps by unit
# --------------------------------------------------------------------------


def test_a_window_keeps_each_patients_history() -> None:
    window = RateWindow(
        "mme_per_patient_day",
        timedelta(days=1),
        "90",
        RowSum("med_orders", "mme_per_day"),
        per="partition:patient",
    )
    assert window.dimension == "patient"
    rows = (
        _row("1", None, {"mme_per_day": Decimal(30)}, tenant="f-1", patient="p-1"),
        _row("2", None, {"mme_per_day": Decimal(45)}, tenant="f-1", patient="p-2"),
    )
    amounts, problems = window.amounts(_plan("p-1", "p-2"), _diff(*rows))
    assert amounts == {"p-1": Decimal(30), "p-2": Decimal(45)} and problems == ()
    assert window.whose("p-1") == "patient p-1" and window.whose("") == "what names no patient"
    (violation,) = RateWindowCheck(window).check(_plan("p-1"), _diff(rows[0]))
    hint = RateWindowCheck(window).hint(_plan("p-1"), _diff(rows[0]), violation)
    assert hint.dimension == "patient" and hint.tenants == ("p-1",)
    for per in ("partition:tenant", "partition:", "partition:Bad"):
        with pytest.raises(ValueError, match="per is one of"):
            RateWindow("w", timedelta(days=1), "1", RowSum("t", "c"), per=per)


def test_a_request_counts_toward_the_partition_its_effect_declares() -> None:
    window = RateWindow(
        "orders_per_patient", timedelta(hours=1), 1, Requests("fhir"), per="partition:patient"
    )
    plan = (
        PlanBuilder("med-rec")
        .enqueue(
            sink="fhir",
            operation="medicationrequest.create",
            payload={"dose": "5"},
            partitions={"patient": "p-9"},
            effect_id=EffectId("order"),
        )
        .build()
    )
    request = OutboundDelta(
        message_id=uuid.uuid4(),
        effect_id=EffectId("order"),
        sink="fhir",
        operation="medicationrequest.create",
        tenant_id=None,
        payload={"dose": "5"},
        payload_hash="0" * 64,
        idempotency_key="k",
    )
    assert window.amounts(plan, _diff(outbound=(request,))) == ({"p-9": Decimal(1)}, ())


def test_a_cap_by_unit_reads_its_unit_where_it_is_named() -> None:
    cap = PayloadAmountCap(
        "fhir", "order", field="dose", maximum={"mg": "5", "mcg": "5000"}, unit_field="unit"
    )

    def request(dose: str, unit: str) -> OutboundDelta:
        return OutboundDelta(
            message_id=uuid.uuid4(),
            effect_id=EffectId("o"),
            sink="fhir",
            operation="order",
            tenant_id=None,
            payload={"dose": dose, "unit": unit},
            payload_hash="0" * 64,
            idempotency_key=str(uuid.uuid4()),
        )

    assert cap.check(_plan("p-1"), _diff(outbound=(request("5", "mg"),))) == ()
    (over,) = cap.check(_plan("p-1"), _diff(outbound=(request("50", "mg"),)))
    assert "asks for 50 at dose, over the cap" in over.message
    (unnamed,) = cap.check(_plan("p-1"), _diff(outbound=(request("1", "ml"),)))
    assert unnamed.message.endswith("names no unit this cap covers")
    legacy = PayloadAmountCap("p", "o", field="amount", maximum={"usd": 1}, currency_field="c")
    assert "_units" not in dict(_config(legacy)), "a cap by currency keeps its digest"
    with pytest.raises(ValueError, match="not both"):
        PayloadAmountCap("p", "o", field="a", maximum={"mg": 1}, currency_field="c", unit_field="u")


# --------------------------------------------------------------------------
# sink kinds, held operations, MCP
# --------------------------------------------------------------------------


def test_an_mcp_sink_takes_its_tools_from_configuration_and_is_at_most_once() -> None:
    sink = mcp_sink("crm", {"close_ticket": {"type": "object"}}, held=["close_ticket"])
    assert sink.kind == "mcp" and sink.idempotency == "none"
    assert sink.unknown_outcome == DEAD_LETTER and sink.held == ("close_ticket",)
    assert sink.mirror_kind == "http", "the database applies no rule of its own to it"
    with pytest.raises(ValueError, match="a call made twice acts twice"):
        mcp_sink("crm", {"close_ticket": None}, unknown_outcome=REDELIVER)
    with pytest.raises(ValueError, match="does not list"):
        mcp_sink("crm", {"close_ticket": None}, held=["delete_account"])
    assert "mcp" in sink_kinds()


def test_holding_an_operation_changes_its_sinks_hash_and_nothing_else() -> None:
    plain = SinkSpec("mail", (OperationSpec("send"),))
    held = SinkSpec("mail", (OperationSpec("send", hold=True),))
    assert plain.config_hash() == canonical_hash(
        [
            "sink",
            "mail",
            "0",
            "header",
            16384,
            900,
            10,
            1000,
            600000,
            "redeliver",
            [["send", "none-possible", None]],
        ]
    )
    assert held.config_hash() != plain.config_hash() and plain.held == ()
    stripe = typed_sink("stripe")
    charge = stripe.CATALOG["payment_intents.create"]
    refund = stripe.CATALOG["refunds.create"]
    from dataclasses import replace

    SinkSpec("pay", (replace(charge, hold=True), refund), kind="stripe")


def test_a_package_registers_a_sink_kind_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    class Fhir:
        CATALOG = None
        IDEMPOTENCY = "header"
        UNKNOWN_OUTCOME = REDELIVER

        @staticmethod
        def payload_problem(operation: str, payload: Mapping[str, Any]) -> str | None:
            return None if "resourceType" in payload else "a FHIR resource names its type"

        @staticmethod
        def compensation_problem(*_: Any) -> str | None:
            return None

    monkeypatch.setattr(outbound_module, "_REGISTERED", {})
    monkeypatch.setattr(outbound_module, "_PLUGINS_LOADED", True)
    register_sink_kind("fhir", Fhir)
    sink = SinkSpec("ehr", (OperationSpec("medicationrequest.create"),), kind="fhir")
    assert typed_sink("fhir") is Fhir and sink.mirror_kind == "http"
    from interlock.exceptions import OutboundRequestError
    from interlock.outbound import SinkRegistry
    from interlock.types import OutboundRequest

    with pytest.raises(OutboundRequestError, match="names its type"):
        SinkRegistry([sink]).check(OutboundRequest("ehr", "medicationrequest.create", {"x": 1}))
    for kind in ("stripe", "Bad"):
        with pytest.raises(ValueError, match="may register"):
            register_sink_kind(kind, Fhir)
    with pytest.raises(ValueError, match="is registered"):
        register_sink_kind("fhir", type("Other", (Fhir,), {}))
    with pytest.raises(ValueError, match="defines no CATALOG"):
        register_sink_kind("odd", object)

    class Point:
        name = "servicenow"

        @staticmethod
        def load() -> Any:
            return Fhir

    monkeypatch.setattr(outbound_module, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: [Point()])
    assert "servicenow" in sink_kinds()


def test_the_configuration_file_names_mcp_sinks_and_held_operations(tmp_path: Path) -> None:
    (tmp_path / "close.json").write_text('{"type": "object"}')
    (tmp_path / "interlock.toml").write_text(
        textwrap.dedent(
            """
            substrate = "sqlite"
            database = "app.db"

            [[tables]]
            name = "med_orders"
            columns = ["id", "facility_id", "patient_id"]
            tenant_column = "facility_id"
            partitions = { patient = "patient_id" }

            [[sinks]]
            name = "crm"
            type = "mcp"

            [[sinks.operations]]
            name = "close_ticket"
            schema = "close.json"
            hold = true

            [[sinks]]
            name = "payments"
            type = "stripe"

            [[sinks.operations]]
            name = "payment_intents.create"
            hold = true

            [[sinks.operations]]
            name = "refunds.create"

            [relay]
            database = "app.db"
            breaker = "none"
            key = "relay.key"

            [[relay.endpoints]]
            sink = "crm"
            command = ["crm-mcp", "--stdio"]
            tools = { close_ticket = "closeTicket" }

            [[relay.endpoints]]
            sink = "payments"
            secret_env = "STRIPE_KEY"
            """
        )
    )
    config = load_config(tmp_path / "interlock.toml")
    (table,) = config.tables
    assert dict(table.partitions) == {"patient": "patient_id"}
    crm, payments = config.sinks
    assert crm.kind == "mcp" and crm.held == ("close_ticket",)
    assert payments.held == ("payment_intents.create",)
    assert config.relay is not None
    endpoint = config.relay.endpoints[0]
    assert endpoint.settings == {
        "command": ["crm-mcp", "--stdio"],
        "tools": {"close_ticket": "closeTicket"},
    }
    adapter = relay_adapter(endpoint)
    assert isinstance(adapter, McpAdapter)
    bad = tmp_path / "bad.toml"
    bad.write_text(
        (tmp_path / "interlock.toml").read_text().replace("hold = true", 'hold = "yes"', 1)
    )
    with pytest.raises(ConfigError, match="'hold' is true or false"):
        load_config(bad)


def _delivery(operation: str, payload: Mapping[str, Any]) -> Delivery:
    from agentgov.receipts.canonical import canonical_bytes

    body = canonical_bytes(dict(payload))
    return Delivery(
        message_id=uuid.uuid4(),
        sink="crm",
        operation=operation,
        idempotency_key="k",
        payload=body,
        payload_hash="0" * 64,
        attempt=1,
        tenant_id=None,
        timeout=2.0,
    )


def test_the_mcp_adapter_classifies_each_way_a_call_can_end() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def answering(result: Mapping[str, Any] | None = None, error: Exception | None = None) -> Any:
        def call(tool: str, arguments: Mapping[str, Any], timeout: float) -> Mapping[str, Any]:
            calls.append((tool, dict(arguments)))
            if error is not None:
                raise error
            assert result is not None
            return result

        return call

    send = _delivery("close_ticket", {"ticket": "INC-7"})
    done = McpAdapter(
        answering({"content": [], "structuredContent": {"id": "INC-7"}}),
        tools={"close_ticket": "closeTicket"},
    ).send(send)
    assert done.outcome == DELIVERED and done.remote_ref == "INC-7"
    assert calls == [("closeTicket", {"ticket": "INC-7"})]
    assert McpAdapter(answering({"isError": True})).send(send).outcome == PERMANENT
    assert McpAdapter(answering(error=McpRefusedError("no such tool"))).send(send).outcome == (
        PERMANENT
    )
    assert McpAdapter(answering(error=McpCallError("down", sent=False))).send(send).outcome == (
        RETRYABLE
    )
    silent = McpAdapter(answering(error=McpCallError("timeout", sent=True))).send(send)
    assert silent.outcome == UNKNOWN, "it may have acted: the sink dead-letters it"
    assert McpAdapter(answering(error=RuntimeError("?"))).send(send).outcome == UNKNOWN
    unbound = McpAdapter(answering({})).send(_delivery("x", {"id": {"$bind": "delivered.id"}}))
    assert unbound.outcome == PERMANENT
    assert classify({"structuredContent": {"id": True}}).remote_ref is None


_FAKE_SERVER = """
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}}
    elif message["params"]["name"] == "refuse":
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                          "error": {"code": -32602, "message": "unknown tool"}}), flush=True)
        continue
    elif message["params"]["name"] == "hang":
        continue
    else:
        result = {"content": [{"type": "text", "text": "ok"}],
                  "structuredContent": {"id": message["params"]["arguments"]["ticket"]}}
    print("a stray line", flush=True)
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


def test_a_stdio_server_answers_tools_call(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    script.write_text(_FAKE_SERVER)
    server = StdioServer([sys.executable, str(script)])
    try:
        adapter = McpAdapter(server)
        result = adapter.send(_delivery("close_ticket", {"ticket": "INC-9"}))
        assert result.outcome == DELIVERED and result.remote_ref == "INC-9"
        assert adapter.send(_delivery("refuse", {"ticket": "x"})).outcome == PERMANENT
        hung = server
        with pytest.raises(McpCallError) as raised:
            hung("hang", {}, 0.3)
        assert raised.value.sent, "the call was made: its outcome is unknown"
        again = adapter.send(_delivery("close_ticket", {"ticket": "INC-10"}))
        assert again.remote_ref == "INC-10", "a server that stopped answering is started again"
    finally:
        server.close()
    missing = StdioServer([str(tmp_path / "no-such-server")])
    with pytest.raises(McpCallError) as raised:
        missing("close_ticket", {}, 1.0)
    assert not raised.value.sent
    with pytest.raises(ValueError, match="non-empty list"):
        StdioServer([])
    endpoint = Endpoint(
        sink="crm", url="", routes={}, header_env={}, kind="mcp", settings={"command": "crm"}
    )
    with pytest.raises(ValueError, match="'command'"):
        relay_adapter(endpoint)


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


def test_a_held_operation_enters_the_outbox_held_and_only_a_release_sends_it(
    outbox: Outbox,
) -> None:
    from tests.outbox_env import REGISTRY, RELAY_SINKS, page

    held = tuple(
        SinkSpec(
            s.name,
            (OperationSpec("page", hold=True),),
            idempotency="none",
            unknown_outcome=DEAD_LETTER,
            backoff_base=s.backoff_base,
            backoff_cap=s.backoff_cap,
        )
        if s.name == "pager"
        else s
        for s in RELAY_SINKS
    )
    from interlock.outbound import SinkRegistry

    outbox.reinstall(held)
    registry = SinkRegistry(held)
    builder = PlanBuilder(SCOPE)
    builder.enqueue(
        sink="pager", operation="page", payload=page(1).payload, effect_id=EffectId("p0")
    )
    plan = builder.build()
    result = outbox.engine(sinks=registry, checkers=[]).execute(plan)
    assert result.committed, result.feedback
    (message,) = outbox.messages(plan.plan_id)
    assert outbox.state(message) == "held"
    assert outbox.events(message) == [("held", None)]
    relay = outbox.relay()
    outbox.drain(relay)
    assert outbox.state(message) == "held", "the breaker is closed, and it still waits"
    assert outbox.sink("pager").calls == []
    assert outbox.release(message, actor="alice")
    outbox.drain(relay)
    assert outbox.state(message) == "delivered"
    assert [e for e, _ in outbox.events(message)][:2] == ["held", "released"]
    outbox.verify_logs()
    assert REGISTRY.get("pager") is not None


def test_an_engine_that_holds_what_its_outbox_does_not_refuses_to_run(outbox: Outbox) -> None:
    from interlock.exceptions import SubstrateConfigurationError
    from interlock.outbound import SinkRegistry
    from tests.outbox_env import RELAY_SINKS

    held = SinkRegistry(
        SinkSpec(
            s.name,
            (OperationSpec("page", hold=True),),
            idempotency="none",
            unknown_outcome=DEAD_LETTER,
        )
        if s.name == "pager"
        else s
        for s in RELAY_SINKS
    )
    with pytest.raises(SubstrateConfigurationError, match=r"holds pager\.page for a warrant"):
        outbox.engine(sinks=held)
    outbox.reinstall(tuple(held))
    outbox.engine(sinks=held)


# --------------------------------------------------------------------------
# inbox source kinds
# --------------------------------------------------------------------------


def test_a_package_registers_a_source_kind_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    class Epic:
        CREDENTIAL = "secret"
        SIGNATURE_HEADERS = ("X-Epic-Signature",)
        FIELDS = (FieldSpec("status", "status", "code"),)

        @staticmethod
        def verify(*_: Any) -> tuple[str | None, datetime]:
            return "evt-1", datetime(2026, 10, 30, tzinfo=UTC)

        @staticmethod
        def parse(document: Any, header_id: str | None) -> list[Parsed]:
            return [Parsed(header_id or "x", "order.verified", 0, ("ord-1",), {}, ())]

    monkeypatch.setattr(inbox_module, "_REGISTERED", {})
    monkeypatch.setattr(inbox_module, "_PLUGINS_LOADED", True)
    register_source_kind("epic", Epic)
    assert "epic" in source_kinds()
    source = InboundSource("pharmacy", "epic", secret_env="EPIC_SECRET")
    assert source.projection() == Epic.FIELDS and source.mirror_kind == "http"
    (event,) = parse_events(source, {}, header_id="evt-1")
    assert event.refs == ("ord-1",)
    with pytest.raises(ValueError, match="needs its secret_env"):
        InboundSource("pharmacy", "epic")
    with pytest.raises(ValueError, match="defines no SIGNATURE_HEADERS"):
        register_source_kind("odd", type("Odd", (), {"CREDENTIAL": "key"}))
    with pytest.raises(ValueError, match="'secret' or 'key'"):
        register_source_kind("odd", type("Odd", (Epic,), {"CREDENTIAL": "token"}))
    with pytest.raises(ValueError, match="may register"):
        register_source_kind("stripe", Epic)


# --------------------------------------------------------------------------
# measurement, and meters
# --------------------------------------------------------------------------


def test_a_receipt_says_how_strongly_its_action_was_measured() -> None:
    request = OutboundDelta(
        message_id=uuid.uuid4(),
        effect_id=EffectId("o"),
        sink="crm",
        operation="close_ticket",
        tenant_id=None,
        payload={},
        payload_hash="0" * 64,
        idempotency_key="k",
    )
    assert measurement_of(object(), _diff(outbound=(request,))) == "request-only"
    row = _row("1", {}, {}, tenant="f-1", patient=None)
    assert measurement_of(object(), _diff(row, outbound=(request,))) == "transactional"

    class Planned:
        capabilities = SubstrateCapabilities(
            transactional=False,
            row_level_diff=True,
            snapshot_isolation=False,
            requires_compensation=True,
            measurement="plan-bound",
        )

    assert measurement_of(Planned(), _diff(row)) == "plan-bound"


_SCHEMA = """
CREATE TABLE med_orders (
    id INTEGER PRIMARY KEY, facility_id TEXT, patient_id TEXT, drug TEXT,
    mme_per_day NUMERIC, status TEXT
);
INSERT INTO med_orders VALUES (1, 'f-1', 'p-1', 'oxycodone', 20, 'active');
"""


@pytest.fixture
def ward(tmp_path: Path) -> Iterator[tuple[str, BudgetManager]]:
    path = str(tmp_path / "ward.db")
    with sqlite3.connect(path) as conn:
        conn.executescript(_SCHEMA)
    mme = BudgetManager(unit=Unit("mme"))
    mme.open_root("pharmacy", Decimal(900))
    mme.delegate("pharmacy", "med-rec", Decimal(100))
    yield path, mme
    mme.close()


def _order(mme_per_day: int, *, scope: str = "med-rec") -> EffectPlan:
    return (
        PlanBuilder(scope, intent="order")
        .insert(
            table="med_orders",
            statement="INSERT INTO med_orders (facility_id, patient_id, drug, mme_per_day, "
            "status) VALUES ('f-1', 'p-1', 'oxycodone', :d, 'draft')",
            parameters={"d": mme_per_day},
            tenant_id="f-1",
            partitions={"patient": "p-1"},
        )
        .build()
    )


def _engine(
    path: str, mme: BudgetManager, tmp_path: Path, *, log: str = "r", **kwargs: Any
) -> EscrowEngine:
    from interlock.receipts import ReceiptIssuer

    receipts = ReceiptLog("ward", HmacKey(b"k" * 32, key_id="ward"), path=tmp_path / f"{log}.jsonl")
    return EscrowEngine(
        SqliteSubstrate(path, tables=[MED_ORDERS]),
        checkers=[TenantIsolation(1, declared=True, dimension="patient")],
        meters=[Meter(mme, RowSum("med_orders", "mme_per_day"), 60)],
        receipts=ReceiptIssuer(receipts),
        **kwargs,
    )


def test_a_meter_holds_what_a_plan_may_consume_and_settles_what_it_did(
    ward: tuple[str, BudgetManager], tmp_path: Path
) -> None:
    path, mme = ward
    engine = _engine(path, mme, tmp_path)
    result = engine.execute(_order(30))
    assert result.committed, result.feedback
    assert mme.available("med-rec") == 70, "30 consumed; the rest of the hold of 60 returned"
    assert result.receipt is not None
    (quantity,) = result.receipt.cost.quantities
    assert (quantity.unit, quantity.amount) == ("mme", Decimal(30))
    (txn,) = quantity.ledger_txn_ids
    spends = [e for e in mme.audit_trail() if str(e.transaction_id) == txn]
    assert [e.amount for e in spends if e.entry_type.value == "spend"] == [Decimal(30)]
    assert result.receipt.coverage.measurement == "transactional"
    over = engine.execute(_order(61))
    assert not over.committed and "meter:mme" in over.blocked_by
    assert over.feedback is not None and "consumes more mme than one plan may" in (
        over.feedback.render()
    )
    assert mme.available("med-rec") == 70, "a refused plan's hold is released"


def test_an_envelope_that_cannot_hold_a_plan_refuses_it_before_it_stages(
    ward: tuple[str, BudgetManager], tmp_path: Path
) -> None:
    path, mme = ward
    engine = _engine(path, mme, tmp_path)
    assert engine.execute(_order(10)).committed
    assert mme.available("med-rec") == 90
    engine.execute(_order(10))
    engine.execute(_order(10))
    assert mme.available("med-rec") == 70
    mme.delegate("pharmacy", "other", Decimal(5))
    stranger = _engine(path, mme, tmp_path, log="stranger")
    with pytest.raises(MeterExhaustedError) as raised:
        stranger.execute(_order(1, scope="other"))
    assert raised.value.unit == "mme"
    assert not mme.is_halted("other"), "a hold too big to place is refused, not an overdraft"
    feedback = raised.value.feedback
    assert isinstance(feedback, AgentFeedback)
    assert feedback.render().endswith(
        "meter: the agent's mme budget cannot cover another plan; nothing was staged."
    )
    with pytest.raises(MeterExhaustedError):
        stranger.execute(_order(1, scope="nobody"))
    with pytest.raises(ValueError, match="share a unit"):
        EscrowEngine(
            SqliteSubstrate(path, tables=[MED_ORDERS]),
            checkers=[],
            meters=[Meter(mme, RowSum("med_orders", "mme_per_day"), 1)] * 2,
        )
    with pytest.raises(ValueError, match="more than zero"):
        Meter(mme, RowSum("med_orders", "mme_per_day"), 0)


def test_recovery_settles_a_committed_plans_hold_whole(
    ward: tuple[str, BudgetManager], tmp_path: Path
) -> None:
    _, mme = ward
    meter = Meter(mme, RowSum("med_orders", "mme_per_day"), 30)
    plan, lost = _order(5), _order(5)
    meter.hold(plan)
    meter.hold(lost)
    assert mme.available("med-rec") == 40
    assert meter.recover([plan.plan_id], [lost.plan_id]) == 2
    assert mme.available("med-rec") == 70, "captured whole, which never under-counts"
    meter.hold(_order(5))
    assert meter.recover([], []) == 0, "a plan that may still commit keeps its hold"


def test_a_meters_check_is_digested_by_its_policy_never_its_ledger() -> None:
    from interlock.meters import MeterCheck
    from interlock.receipts import checker_records

    def record(ledger: BudgetManager) -> Any:
        return checker_records([MeterCheck(Meter(ledger, RowSum("t", "c"), 60))])

    one, other = BudgetManager(unit=Unit("mme")), BudgetManager(unit=Unit("mme"))
    assert record(one) == record(other), "two ledgers, one policy, one digest"
    assert "object at" not in repr(Meter(one, RowSum("t", "c"), 60))
    assert record(one) != record(BudgetManager(unit=Unit("vcpu")))


def test_feedback_for_a_meter_names_the_unit_only() -> None:
    plan = _order(1)
    feedback = sanitize(
        FeedbackHint(kind=Guidance.METER, window="mme"), plan, blocking=True, trusted=True
    )
    assert (
        feedback.render() == "meter: the plan consumes more mme than one plan may. Split the work."
    )
    untrusted = sanitize(
        FeedbackHint(kind=Guidance.METER, window="mme"), plan, blocking=True, trusted=False
    )
    assert "of a metered unit" in untrusted.render()
    assert agent_feedback(plan, [], committed=True).outcome == "committed"


def test_the_mcp_kind_leaves_arguments_and_undoes_to_the_operator() -> None:
    from interlock import mcp

    assert mcp.payload_problem("close_ticket", {"anything": 1}) is None
    assert mcp.compensation_problem("close_ticket", {}, None) is None
    for settings, match in (
        ({"command": ["x"], "url": "http://x"}, "not url"),
        ({"command": ["x"], "tools": {"a": 1}}, "maps an operation"),
    ):
        endpoint = Endpoint(
            sink="crm", url="", routes={}, header_env={}, kind="mcp", settings=settings
        )
        with pytest.raises(ValueError, match=match):
            relay_adapter(endpoint)


_CLOSING_SERVER = """
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {}}), flush=True)
    elif message.get("method") == "tools/call":
        sys.stdout.write("{partial")
        sys.stdout.flush()
        sys.exit(0)
"""


def test_a_server_that_dies_mid_call_leaves_the_outcome_unknown(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    script.write_text(_CLOSING_SERVER)
    server = StdioServer([sys.executable, str(script)])
    try:
        result = McpAdapter(server).send(_delivery("close_ticket", {"ticket": "INC-1"}))
        assert result.outcome == UNKNOWN, "sent, then nothing: it may have acted"
    finally:
        server.close()


def test_a_meter_releases_the_hold_of_a_plan_that_consumed_nothing(
    ward: tuple[str, BudgetManager],
) -> None:
    _, mme = ward
    meter = Meter(mme, RowSum("med_orders", "mme_per_day"), 30)
    held = meter.hold(_order(5))
    assert meter.settle(held, Decimal(0), "committed") is None
    assert mme.available("med-rec") == 100
    meter.release(held)  # released already: nothing happens
    assert mme.available("med-rec") == 100


def test_a_meter_may_hold_on_one_scope_whatever_scope_a_plan_bills(
    ward: tuple[str, BudgetManager],
) -> None:
    _, mme = ward
    meter = Meter(mme, RowSum("med_orders", "mme_per_day"), 30, scope="med-rec")
    meter.hold(_order(5, scope="med-rec/ext-1"))
    assert mme.available("med-rec") == 70
    assert repr(meter) == repr(Meter(mme, RowSum("med_orders", "mme_per_day"), 30))


def test_a_receipt_may_name_only_the_tenants_a_plan_declares(
    ward: tuple[str, BudgetManager], tmp_path: Path
) -> None:
    from interlock.receipts import ReceiptIssuer

    path, _ = ward
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO med_orders VALUES (2, 'f-2', 'p-2', 'oxycodone', 10, 'active')")
        conn.execute("INSERT INTO med_orders VALUES (3, 'f-3', 'p-3', 'oxycodone', 10, 'active')")
    plan = (
        PlanBuilder("med-rec", intent="pause every order")
        .update(
            table="med_orders",
            statement="UPDATE med_orders SET status = 'paused'",
            tenant_id="f-1",
        )
        .build()
    )
    found = {}
    for tenants in ("touched", "declared"):
        log = ReceiptLog(
            "ward", HmacKey(b"k" * 32, key_id="ward"), path=tmp_path / f"{tenants}.jsonl"
        )
        engine = EscrowEngine(
            SqliteSubstrate(path, tables=[MED_ORDERS]),
            checkers=[TenantIsolation(1, declared=True)],
            receipts=ReceiptIssuer(log, tenants=tenants),
        )
        result = engine.execute(plan)
        assert not result.committed and result.receipt is not None
        found[tenants] = result.receipt.effect.summary
    assert (found["touched"].tenants, found["touched"].other_tenants) == (("f-1", "f-2", "f-3"), 0)
    assert (found["declared"].tenants, found["declared"].other_tenants) == (("f-1",), 2)
    with pytest.raises(ValueError, match="touched or declared"):
        ReceiptIssuer(log, tenants="own")
