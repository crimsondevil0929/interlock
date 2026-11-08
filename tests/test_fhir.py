"""The FHIR substrate (1.4.0): class V staging on a loopback FHIR R4 server.

A change is predicted from what was read, judged, written on the version read,
and read back: a server rule that changes more than the plan did is caught,
and everything the write changed is put back."""

from __future__ import annotations

import json
import sqlite3
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts import ActionReceipt, HmacKey, OutcomeStatus, ReceiptLog
from agentgov.reconciliation import parse_fhir_audit, reconcile_actions

from interlock import (
    BlastRadius,
    CompensatedError,
    EscrowChain,
    EscrowEngine,
    FhirSubstrate,
    FhirType,
    PlanBuilder,
    TenantIsolation,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.feedback import AgentFeedback
from interlock.fhir import (
    STAGE_TAG,
    fhir_tables,
    fingerprint,
    parse_compensation,
    parse_statement,
    path_value,
)
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.planbound import UndoJournal
from interlock.predicted import PREDICTED
from interlock.receipts import ReceiptIssuer
from interlock.sim.fhir import RULES_ACTOR, Change, LoopbackFhirServer, RuleContext, values
from interlock.sqlite_outbox import install_sqlite_outbox
from interlock.types import Compensation, EffectDiff, EffectKind, StageState

TOKEN = "agent-token"
AGENT = "Device/med-rec-agent"
CHART = "ch-7f3a91"
OTHER = "ch-2c8e04"
MME = "https://fiduciary.dev/fhir/StructureDefinition/mme-per-day"

ORDERS = FhirType(
    "medicationrequests",
    "MedicationRequest",
    columns={
        "status": "status",
        "drug": "medicationCodeableConcept.text",
        "dose_mg": "dosageInstruction.0.doseAndRate.0.doseQuantity.value",
        "mme_per_day": f"extension('{MME}').valueInteger",
        "encounter": "encounter.reference",
    },
    partitions={"facility": "dispenseRequest.performer.reference"},
)
TASKS = FhirType(
    "tasks",
    "Task",
    columns={"status": "status", "code": "code.coding.0.code", "focus": "focus.reference"},
    tenant="for.reference",
)
TYPES = (ORDERS, TASKS)


def encounter_stop(ctx: RuleContext, change: Change) -> None:
    """The EHR's rule: stopping one order of an encounter stops the rest, and
    opens a pharmacy task."""
    after, before = change.after, change.before or {}
    if change.resource_type != "MedicationRequest" or after.get("status") != "stopped":
        return
    if before.get("status") == "stopped":
        return
    encounter = str(after["encounter"]["reference"]).split("/")[1]
    for other in ctx.search("MedicationRequest", encounter=encounter, status="active"):
        other["status"] = "stopped"
        ctx.write(other)
    ctx.write(
        {
            "resourceType": "Task",
            "status": "requested",
            "intent": "order",
            "code": {"coding": [{"code": "encounter-stop"}]},
            "for": after["subject"],
            "focus": {"reference": f"MedicationRequest/{after['id']}"},
        }
    )


def order(order_id: str, patient: str, drug: str, dose: int, encounter: str) -> dict[str, Any]:
    return {
        "resourceType": "MedicationRequest",
        "id": order_id,
        "status": "active",
        "intent": "order",
        "subject": {"reference": f"Patient/{patient}"},
        "encounter": {"reference": f"Encounter/{encounter}"},
        "medicationCodeableConcept": {"text": drug},
        "dosageInstruction": [{"doseAndRate": [{"doseQuantity": {"value": dose, "unit": "mg"}}]}],
        "extension": [{"url": MME, "valueInteger": 0}],
        "dispenseRequest": {"performer": {"reference": "Organization/fac-north"}},
    }


@pytest.fixture
def server() -> Iterator[LoopbackFhirServer]:
    found = LoopbackFhirServer(
        tokens={TOKEN: AGENT, "nurse-token": "Practitioner/rn-04"}, rules=[encounter_stop]
    )
    found.start()
    found.seed({"resourceType": "Organization", "id": "fac-north"})
    for patient, bed, encounter in ((CHART, "4A", "enc-1"), (OTHER, "4B", "enc-2")):
        found.seed({"resourceType": "Patient", "id": patient, "name": [{"text": patient}]})
        found.seed({"resourceType": "Location", "id": bed})
        found.seed(
            {
                "resourceType": "Encounter",
                "id": encounter,
                "status": "in-progress",
                "subject": {"reference": f"Patient/{patient}"},
                "location": [{"location": {"reference": f"Location/{bed}"}}],
                "serviceProvider": {"reference": "Organization/fac-north"},
            }
        )
    for n, drug in enumerate(("lisinopril", "metformin", "atorvastatin"), 1):
        found.seed(order(str(n), CHART, drug, 10, "enc-1"))
    found.seed(order("4", OTHER, "lisinopril", 10, "enc-2"))
    yield found
    found.stop()


class _Fhir(FhirSubstrate):
    """The substrate, its methods replaceable for a test (no ``__slots__``)."""


def substrate(server: LoopbackFhirServer, tmp_path: Path, **kwargs: Any) -> FhirSubstrate:
    return _Fhir(server.url, types=TYPES, journal=tmp_path / "journal", token=TOKEN, **kwargs)


TEMPLATE = {
    "resourceType": "MedicationRequest",
    "status": "active",
    "intent": "order",
    "subject": {"reference": "Patient?_has:Encounter:subject:location=:bed"},
    "encounter": {"reference": "Encounter?location=:bed&status=in-progress"},
    "medicationCodeableConcept": {"text": ":drug"},
    "dosageInstruction": [{"doseAndRate": [{"doseQuantity": {"value": ":dose", "unit": "mg"}}]}],
    "extension": [{"url": MME, "valueInteger": ":mme"}],
    "dispenseRequest": {
        "performer": {"reference": "Organization?_has:Encounter:service-provider:location=:bed"}
    },
}


def literal(document: Any) -> str:
    return "'" + json.dumps(document).replace("'", "''") + "'"


def create(bed: str = "4A", drug: str = "acetaminophen", dose: int = 650) -> tuple[Any, ...]:
    return (
        EffectKind.INSERT,
        f"create medicationrequests {literal(TEMPLATE)} :bed :drug :dose :mme",
        {"bed": bed, "drug": drug, "dose": dose, "mme": 0},
        "medicationrequests",
        "void medicationrequests",
    )


def patch(order_id: str, change: dict[str, Any], **parameters: Any) -> tuple[Any, ...]:
    listed = "".join(f" :{name}" for name in sorted(parameters))
    return (
        EffectKind.UPDATE,
        f"patch medicationrequests :id {literal(change)}{listed}",
        {"id": order_id, **parameters},
        "medicationrequests",
        "restore medicationrequests",
    )


def stop(order_id: str) -> tuple[Any, ...]:
    return patch(order_id, {"status": "stopped"})


def plan(*effects: tuple[Any, ...], tenant: str = CHART) -> Any:
    builder = PlanBuilder("med-rec-agent", intent="reconcile")
    for kind, statement, parameters, table, undo in effects:
        builder.add(
            kind,
            table=f"fhir:{table}",
            statement=statement,
            parameters=parameters,
            tenant_id=tenant,
            compensation=Compensation(undo) if undo else None,
        )
    return builder.build()


def engine(sub: FhirSubstrate, tmp_path: Path, *checkers: Any, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        sub,
        checkers=list(checkers) or [BlastRadius(10)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
        **kwargs,
    )


def receipts(tmp_path: Path) -> tuple[ReceiptLog, ReceiptIssuer]:
    log = ReceiptLog("fhir", HmacKey(b"k" * 32), path=tmp_path / "receipts.jsonl")
    return log, ReceiptIssuer(log, row_secret=b"r" * 32)


def measured(result: Any) -> EffectDiff:
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def statuses(server: LoopbackFhirServer, patient: str = CHART) -> dict[str, str]:
    return {r["id"]: r["status"] for r in server.search("MedicationRequest", patient=patient)}


# -- the statement language, paths and images ---------------------------------------------


def test_statements_parse_each_verb_and_refuse_anything_else() -> None:
    found = parse_statement('patch medicationrequests :id \'{"status": "stopped"}\'')
    assert (found.verb, found.table) == ("patch", "medicationrequests")
    assert found.bind({"id": "7"}) == {"id": "7", "patch": '{"status": "stopped"}'}
    assert parse_statement("create tasks :resource").verb == "create"
    assert parse_statement("expect-version tasks :a 'it''s'").arguments[1] == ("'", "it's")
    assert parse_statement("create tasks '{}' :a :b").binds == ("a", "b")
    for bad, message in [
        ("delete medicationrequests :id", "verbs"),
        ("patch", "verb, a table"),
        ("patch medicationrequests :id", "takes"),
        ("patch medicationrequests :id word", "argument"),
        ("patch medicationrequests :id 'open", "not closed"),
        ("patch medicationrequests : :b", "parameter"),
        ("patch medicationrequests ;", "unexpected"),
        ("create tasks '{}' 'x'", "lists the :parameters"),
        ("expect-version tasks :a :b :c", "takes"),
    ]:
        with pytest.raises(ValueError, match=message):
            parse_statement(bad)
    with pytest.raises(ValueError, match="not bound"):
        parse_statement("patch tasks :id :p").bind({"id": "1"})
    assert parse_compensation("void tasks") == ("void", "tasks")
    for bad, message in [
        ("delete tasks", "never 'delete'"),
        ("void", "is 'void <table>'"),
        ("void tasks :x", "is 'void <table>'"),
    ]:
        with pytest.raises(ValueError, match=message):
            parse_compensation(bad)


def test_paths_read_lists_indexes_and_extensions() -> None:
    resource = order("1", CHART, "lisinopril", 10, "enc-1")
    assert path_value(resource, "dosageInstruction.0.doseAndRate.0.doseQuantity.value") == (
        True,
        10,
    )
    assert path_value(resource, f"extension('{MME}').valueInteger") == (True, 0)
    assert path_value(resource, "extension('https://elsewhere').valueInteger") == (False, None)
    assert path_value(resource, "status('x')") == (False, None)
    assert path_value(resource, "dosageInstruction.9") == (False, None)
    assert path_value(resource, "status.0") == (False, None)
    assert path_value(resource, "nothing.here") == (False, None)
    for bad in ("a..b", "a.", "a b", "a(b)"):
        with pytest.raises(ValueError, match="not a path"):
            path_value(resource, bad)
    image = ORDERS.image(resource)
    assert image["patient"] == CHART and image["facility"] == "fac-north"
    assert image["encounter"] == "Encounter/enc-1" and image["dose_mg"] == 10
    assert ORDERS.image({"resourceType": "MedicationRequest"})["patient"] is None
    assert (
        TASKS.image({"code": {"coding": [{"code": "x"}]}, "for": {"reference": "Patient/p"}})[
            "patient"
        ]
        == "p"
    )
    listed = FhirType("tasks", "Task", columns={"inputs": "input"}, tenant="for.reference")
    assert listed.image({"input": [{"a": 1}]})["inputs"] == '[{"a":1}]'
    assert [t.name for t in fhir_tables(TYPES)] == ["medicationrequests", "tasks"]


def test_the_fingerprint_ignores_bookkeeping_and_nothing_else() -> None:
    resource = order("1", CHART, "lisinopril", 10, "enc-1")
    kept = {
        **resource,
        "meta": {"versionId": "9", "lastUpdated": "x", "tag": [{"system": STAGE_TAG, "code": "s"}]},
    }
    assert fingerprint(kept) == fingerprint(resource)
    assert fingerprint({**resource, "text": {"div": "<div/>"}}) == fingerprint(resource)
    tagged = {**resource, "meta": {"tag": [{"system": "other", "code": "c"}]}}
    assert fingerprint(tagged) != fingerprint(resource)
    assert fingerprint({**resource, "status": "stopped"}) != fingerprint(resource)
    assert fingerprint({"n": 1.5, "big": 2**60}) == fingerprint({"n": 1.5, "big": 2**60})


def test_a_type_names_identifiers_and_its_own_columns_once() -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({"table": "Bad"}, "lowercase identifier"),
        ({"resource_type": "lower"}, "not a FHIR resource type"),
        ({"columns": {"patient": "x"}}, "every type's own"),
        ({"columns": {"a": "x"}, "partitions": {"a": "y"}}, "share a name"),
        ({"columns": {"a": "x..y"}}, "not a path"),
    ]
    for kwargs, message in cases:
        arguments: dict[str, Any] = {"table": "tasks", "resource_type": "Task", **kwargs}
        with pytest.raises(ValueError, match=message):
            FhirType(**arguments)


def test_the_substrate_says_what_it_is(server: LoopbackFhirServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    caps = sub.capabilities
    assert caps.predicted and caps.requires_compensation and caps.measurement == PREDICTED
    assert not caps.transactional and not caps.plan_bound and not caps.outbound
    assert sub.substrate_id == "fhir" and sub.commit_markers
    assert sub.observed_tables == frozenset({"medicationrequests", "tasks"})
    assert [t.name for t in sub.table_specs] == ["medicationrequests", "tasks"]
    assert sub.server == server.url and sub.control is None and sub.held_operations() == {}
    with pytest.raises(SubstrateConfigurationError, match="HTTPS"):
        FhirSubstrate("http://ehr.example.org/fhir", types=TYPES, journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="at least one type"):
        FhirSubstrate(server.url, types=(), journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="its own table"):
        FhirSubstrate(server.url, types=(ORDERS, ORDERS), journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="one table"):
        FhirSubstrate(
            server.url, types=(ORDERS, FhirType("other", "MedicationRequest")), journal=tmp_path
        )
    FhirSubstrate("https://ehr.example.org/fhir", types=TYPES, journal=tmp_path)


def test_each_effect_declares_the_undo_its_verb_takes(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)

    def why(*effect: tuple[Any, ...]) -> str | None:
        return sub.reject_reason(plan(*effect).effects[0])

    assert why(create()) is None and why(stop("1")) is None
    kind, statement, parameters, table, _ = stop("1")
    assert "declares its undo: 'restore medicationrequests'" in str(
        why((kind, statement, parameters, table, None))
    )
    assert "never deleted" in str(why((*create()[:4], "restore medicationrequests")))
    assert "not 'void tasks'" in str(why((*stop("1")[:4], "void tasks")))
    assert "never 'drop'" in str(why((*stop("1")[:4], "drop medicationrequests")))
    assert "no type" in str(why((kind, "patch pods :id '{}'", parameters, "pods", "restore pods")))
    assert "not a statement" in str(why((kind, "patch tasks", {}, "tasks", "restore tasks")))
    assert "targets" in str(
        sub.reject_reason(
            PlanBuilder("s")
            .add(
                kind,
                table="fhir:tasks",
                statement=statement,
                parameters=parameters,
                compensation=Compensation("restore medicationrequests"),
            )
            .build()
            .effects[0]
        )
    )
    template = f"create medicationrequests {literal({'resourceType': 'Task'})}"
    assert "not a MedicationRequest" in str(
        why((EffectKind.INSERT, template, {}, table, "void medicationrequests"))
    )
    for document, message in [
        ({"id": "x"}, "may not set id"),
        ({"status": ":missing"}, "does not list after it"),
        ([1], "a JSON object"),
    ]:
        assert message in str(
            why(
                (
                    EffectKind.INSERT,
                    f"create medicationrequests {literal(document)}",
                    {},
                    table,
                    "void medicationrequests",
                )
            )
        )
    assert "may not change meta" in str(why(patch("1", {"meta": {"tag": []}})))
    assert "a JSON merge patch" in str(why(patch("1", [1])))  # type: ignore[arg-type]
    kind, statement, parameters, table, undo = patch("1", {"status": ":gone"}, gone=None)
    parameters.pop("gone")
    assert "not bound" in str(why((kind, statement, parameters, table, undo)))
    kind, statement, parameters, table, undo = patch("1", {"status": "on-hold"})
    assert "which its template does not bind" in str(
        why((kind, statement + " :extra", {**parameters, "extra": 1}, table, undo))
    )
    assert "not a FHIR resource id" in str(why(patch("bad id!", {"status": "x"})))
    assert "text or a whole number" in str(why(patch(True, {"status": "x"})))  # type: ignore[arg-type]
    enqueue = PlanBuilder("s").enqueue(sink="pharmacy", operation="x", payload={}).build()
    assert sub.reject_reason(enqueue.effects[0]) is None


def test_the_engine_refuses_an_effect_with_no_undo(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    kind, statement, parameters, table, _ = stop("1")
    with pytest.raises(ForbiddenStatementError, match="declares its undo"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan((kind, statement, parameters, table, None))
        )
    assert not [m for m, _ in server.requests if m == "PUT"]


# -- predicted, written, read back -----------------------------------------------------


def test_a_create_is_predicted_from_its_template_and_reads_back_as_predicted(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    log, issuer = receipts(tmp_path)
    result = engine(substrate(server, tmp_path), tmp_path, receipts=issuer).execute(plan(create()))
    assert result.committed
    (delta,) = measured(result).deltas
    after = dict(delta.after or {})
    assert delta.before is None and delta.tenant_id == CHART
    assert delta.partitions == {"facility": "fac-north"}
    assert (after["drug"], after["dose_mg"], after["encounter"]) == (
        "acetaminophen",
        650,
        "Encounter/enc-1",
    )
    stored = server.get("MedicationRequest", delta.primary_key)
    assert stored is not None and stored["subject"] == {"reference": f"Patient/{CHART}"}
    tags = stored["meta"]["tag"]
    assert [t["system"] for t in tags] == [STAGE_TAG]
    assert result.receipt is not None
    assert result.receipt.coverage.measurement == PREDICTED
    txid = result.receipt.outcome.substrate_txid
    assert txid == f"fhir:{tags[0]['code']}"
    events = parse_fhir_audit(server.audit_log())
    report = reconcile_actions(log.receipts(), events, actors=[AGENT], substrates=["fhir"])
    assert report.passed and len(report.matched) == 1 and report.unobserved == ()


def test_a_patch_writes_on_the_version_read(server: LoopbackFhirServer, tmp_path: Path) -> None:
    result = engine(substrate(server, tmp_path), tmp_path).execute(
        plan(
            patch(
                "2",
                {
                    "dosageInstruction": [
                        {"doseAndRate": [{"doseQuantity": {"value": ":d", "unit": "mg"}}]}
                    ]
                },
                d=20,
            )
        )
    )
    assert result.committed
    (delta,) = measured(result).deltas
    assert (dict(delta.before or {})["dose_mg"], dict(delta.after or {})["dose_mg"]) == (10, 20)
    assert server.history("MedicationRequest", "2")[-1]["meta"]["versionId"] == "2"
    put = [p for m, p in server.requests if m == "PUT"]
    assert put == ["/fhir/MedicationRequest/2"]


def test_a_plan_that_changes_nothing_writes_nothing(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    result = engine(sub, tmp_path).execute(plan(patch("1", {"status": "active"})))
    assert result.committed and measured(result).deltas == ()
    assert not [m for m, _ in server.requests if m == "PUT"]
    handle = sub.open(plan(stop("1")))
    assert sub.transaction_id(handle) is None
    sub.close(handle)


def test_a_wrong_patient_order_is_refused_before_the_server_sees_it(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    result = engine(substrate(server, tmp_path), tmp_path, TenantIsolation(declared=True)).execute(
        plan(create(bed="4B"))
    )
    assert not result.committed
    (delta,) = measured(result).deltas
    assert delta.tenant_id == OTHER
    assert not [m for m, _ in server.requests if m == "PUT"]


def test_a_rule_that_changes_more_than_the_plan_is_put_back(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    log, issuer = receipts(tmp_path)
    run = engine(substrate(server, tmp_path), tmp_path, receipts=issuer)
    with pytest.raises(CompensatedError) as caught:
        run.execute(plan(stop("1")))
    found = caught.value
    assert found.applied == 1 and found.restored == 4
    assert len(found.discrepancies) == 3
    assert any("Task/" in d and "created" in d for d in found.discrepancies)
    assert any(
        "MedicationRequest/2: status 'active' -> 'stopped'" in d for d in found.discrepancies
    )
    assert statuses(server) == {"1": "active", "2": "active", "3": "active"}
    (task,) = server.search("Task", patient=CHART)
    assert task["status"] == "entered-in-error", "a record the rule created is voided, not deleted"
    assert statuses(server, OTHER) == {"4": "active"}, "another chart is never touched"
    kinds = [r.record_type for r in run.chain.records()]
    assert kinds[-1] is RecordType.COMPENSATED
    result = found.result
    assert result is not None and result.state is StageState.COMPENSATED  # type: ignore[attr-defined]
    told = found.feedback.render() if isinstance(found.feedback, AgentFeedback) else ""
    assert told.startswith("The plan was admitted and written, then put back")
    assert "put_back: the EHR changed 2-9 records the plan did not touch" in told
    assert "ch-2c8e04" not in told and "lisinopril" not in told, "counts, never values"
    assert "read-back not as predicted (3 discrepancies" in run.chain.records()[-1].note
    receipt = found.receipt
    assert isinstance(receipt, ActionReceipt)
    assert receipt.outcome.status is OutcomeStatus.COMPENSATED
    assert receipt.outcome.substrate_txid is not None
    events = parse_fhir_audit(server.audit_log())
    report = reconcile_actions(log.receipts(), events, actors=[AGENT])
    assert report.passed and report.unobserved == ()
    assert {m.receipt_id for m in report.matched} == {receipt.receipt_id}
    assert len(report.matched) == 5, "the write and its four put-backs"
    rules = reconcile_actions(log.receipts(), events, actors=[RULES_ACTOR])
    assert len(rules.matched) == 3, "the rule's writes carry the request that set them off"


def test_a_value_the_server_rewrites_is_not_as_predicted(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    def cap(ctx: RuleContext, change: Change) -> None:
        dose = change.after["dosageInstruction"][0]["doseAndRate"][0]["doseQuantity"]
        if change.resource_type == "MedicationRequest" and dose["value"] > 500:
            dose["value"] = 500
            ctx.write(change.after)

    server.add_rule(cap)
    with pytest.raises(CompensatedError) as caught:
        engine(substrate(server, tmp_path), tmp_path).execute(plan(create(dose=650)))
    (said,) = caught.value.discrepancies
    assert "dose_mg 650 -> 500, not as predicted" in said
    created = [r for r in server.search("MedicationRequest", patient=CHART) if r["id"] not in "123"]
    assert [r["status"] for r in created] == ["entered-in-error"]


def test_a_chart_edited_while_the_plan_waited_is_not_written(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    original = sub.write_undo

    def nurse_edits(handle: Any) -> str:
        edited = server.get("MedicationRequest", "3")
        assert edited is not None
        edited["note"] = [{"text": "held by the nurse"}]
        server.write(edited, actor="Practitioner/rn-04")
        return original(handle)

    sub.write_undo = nurse_edits  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="the chart changed after the stage read it"):
        engine(sub, tmp_path).execute(plan(create()))
    assert not [m for m, _ in server.requests if m == "PUT"]
    assert sub.resolve_intent(uuid.uuid4()) is None


def test_a_write_whose_version_is_gone_answers_412_and_nothing_lands(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    original = sub.write_undo

    def nurse_edits_the_same_order(handle: Any) -> str:
        edited = server.get("MedicationRequest", "2")
        assert edited is not None
        edited["note"] = [{"text": "dose questioned"}]
        server.write(edited, actor="Practitioner/rn-04")
        return original(handle)

    sub.write_undo = nurse_edits_the_same_order  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="HTTP 412"):
        engine(sub, tmp_path).execute(plan(patch("2", {"status": "on-hold"})))
    stored = server.get("MedicationRequest", "2")
    assert stored is not None and stored["status"] == "active"
    assert stored["note"] == [{"text": "dose questioned"}], "the nurse's edit stands"
    refused = [e for e in server.audit_events() if e["outcome"] == "4"]
    assert len(refused) == 1 and parse_fhir_audit(json.dumps(refused)) == ()


def test_someone_elses_change_is_named_and_never_put_back(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    original = sub._discrepancies

    def nurse_edits_meanwhile(stage: Any) -> list[str]:
        edited = server.get("MedicationRequest", "3")
        assert edited is not None
        edited["note"] = [{"text": "patient refused"}]
        server.write(edited, actor="Practitioner/rn-04", request_id="bedside-17")
        sub._discrepancies = original  # type: ignore[method-assign]
        return original(stage)

    sub._discrepancies = nurse_edits_meanwhile  # type: ignore[method-assign]
    with pytest.raises(CompensatedError, match="left as it is, for a person") as caught:
        engine(sub, tmp_path).execute(plan(patch("2", {"status": "on-hold"})))
    assert "MedicationRequest/3" in str(caught.value)
    assert statuses(server)["2"] == "active", "the plan's own write is put back"
    kept = server.get("MedicationRequest", "3")
    assert kept is not None and kept["note"] == [{"text": "patient refused"}]
    assert kept["meta"]["source"] == "#bedside-17"


def test_a_write_someone_else_wrote_again_is_left_for_an_operator(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    original = sub._discrepancies

    def nurse_edits_the_written_order(stage: Any) -> list[str]:
        edited = server.get("MedicationRequest", "2")
        assert edited is not None
        edited["note"] = [{"text": "held at the bedside"}]
        server.write(edited, actor="Practitioner/rn-04", request_id="bedside-18")
        sub._discrepancies = original  # type: ignore[method-assign]
        return original(stage)

    sub._discrepancies = nurse_edits_the_written_order  # type: ignore[method-assign]
    run = engine(sub, tmp_path)
    with pytest.raises(CommitUnsettledError, match="written again by another request"):
        run.execute(plan(patch("2", {"status": "on-hold"})))
    kept = server.get("MedicationRequest", "2")
    assert kept is not None and kept["note"] == [{"text": "held at the bedside"}]
    assert run.chain.records()[-1].record_type is RecordType.COMMIT_INTENT


def test_a_later_write_that_fails_puts_the_earlier_ones_back(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    server.fail_next("MedicationRequest", "3", 500)
    sub = substrate(server, tmp_path)
    with pytest.raises(CompensatedError, match="writing MedicationRequest/3 failed") as caught:
        engine(sub, tmp_path).execute(
            plan(patch("2", {"status": "on-hold"}), patch("3", {"status": "on-hold"}))
        )
    assert caught.value.discrepancies == ()
    feedback = caught.value.feedback
    told = feedback.render() if isinstance(feedback, AgentFeedback) else ""
    assert "a write failed part way" in told
    assert statuses(server) == {"1": "active", "2": "active", "3": "active"}


def test_a_refused_write_is_never_put_back_over_someone_elses(tmp_path: Path) -> None:
    """On a server that does not say which request wrote a version (HAPI's
    default), the first write lands; a pharmacist then edits the second
    resource, and the stage's write to it is refused on its version. Only
    the first is put back: the pharmacist's edit stands. (Found on HAPI FHIR:
    the put-back once restored every planned write, landed or not.)"""
    server = LoopbackFhirServer(tokens={TOKEN: AGENT}, sources=False)
    server.start()
    try:
        server.seed({"resourceType": "Patient", "id": CHART})
        for n in ("2", "3"):
            server.seed(order(n, CHART, "metformin", 10, "enc-1"))
        sub = substrate(server, tmp_path)
        inner = sub._api
        edits: list[str] = []

        class _Pharmacist:
            def __getattr__(self, name: str) -> Any:
                return getattr(inner, name)

            def call(self, method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
                found = inner.call(method, path, body, **kwargs)
                if method == "PUT" and path.endswith("/2") and not edits:
                    edits.append(path)
                    edited = server.get("MedicationRequest", "3")
                    assert edited is not None
                    edited["note"] = [{"text": "held by the pharmacist"}]
                    server.write(edited, actor="Practitioner/rph-1")
                return found

            def read(self, resource_type: str, resource_id: str) -> Any:
                return inner.read(resource_type, resource_id)

            def search(self, query: str, *, limit: int) -> Any:
                return inner.search(query, limit=limit)

        sub._api = _Pharmacist()  # type: ignore[assignment]
        with pytest.raises(CompensatedError, match="writing MedicationRequest/3 failed"):
            engine(sub, tmp_path).execute(
                plan(patch("2", {"status": "on-hold"}), patch("3", {"status": "on-hold"}))
            )
        assert statuses(server) == {"2": "active", "3": "active"}
        kept = server.get("MedicationRequest", "3")
        assert kept is not None and kept["note"] == [{"text": "held by the pharmacist"}]
        assert "source" not in kept["meta"] and kept["meta"]["versionId"] == "2"
    finally:
        server.stop()


def test_a_put_back_that_fails_leaves_the_intent_open(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    def refuse_the_undo(ctx: RuleContext, change: Change) -> None:
        if change.after.get("status") == "stopped" and change.actor == AGENT:
            server.fail_next("MedicationRequest", "2", 503)

    server.add_rule(refuse_the_undo)
    run = engine(substrate(server, tmp_path), tmp_path)
    with pytest.raises(CommitUnsettledError, match="could not put everything back"):
        run.execute(plan(stop("1")))
    assert run.chain.records()[-1].record_type is RecordType.COMMIT_INTENT
    assert list((tmp_path / "journal").glob("*.undo.json"))


def test_expect_version_pins_the_plan_to_what_was_approved(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    pinned = (
        EffectKind.UPDATE,
        "expect-version medicationrequests :id :v",
        {"id": "2", "v": "1"},
        "medicationrequests",
        "restore medicationrequests",
    )
    result = engine(substrate(server, tmp_path), tmp_path).execute(
        plan(pinned, patch("2", {"status": "on-hold"}))
    )
    assert result.committed
    with pytest.raises(StageConflictError, match="the state it was approved on is gone"):
        engine(substrate(server, tmp_path / "again"), tmp_path / "again").execute(plan(pinned))


def test_a_conditional_reference_must_find_exactly_one(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    server.seed(
        {
            "resourceType": "Encounter",
            "id": "enc-3",
            "status": "in-progress",
            "subject": {"reference": f"Patient/{OTHER}"},
            "location": [{"location": {"reference": "Location/4B"}}],
            "serviceProvider": {"reference": "Organization/fac-north"},
        }
    )
    for bed, message in (("9Z", "matches 0 resources"), ("4B", "matches 2 resources")):
        with pytest.raises(StageError, match=message):
            engine(substrate(server, tmp_path), tmp_path).execute(plan(create(bed=bed)))
    odd = dict(TEMPLATE, subject={"reference": "Patient?unknown=1"})
    statement = f"create medicationrequests {literal(odd)} :bed :drug :dose :mme"
    with pytest.raises(StageError, match="cannot search"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan(
                (
                    EffectKind.INSERT,
                    statement,
                    create()[2],
                    "medicationrequests",
                    "void medicationrequests",
                )
            )
        )
    lowered = dict(TEMPLATE, subject={"reference": "patient?x=1"})
    statement = f"create medicationrequests {literal(lowered)} :bed :drug :dose :mme"
    with pytest.raises(StageError, match="not a conditional reference"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan(
                (
                    EffectKind.INSERT,
                    statement,
                    create()[2],
                    "medicationrequests",
                    "void medicationrequests",
                )
            )
        )


def test_what_a_stage_may_reach(server: LoopbackFhirServer, tmp_path: Path) -> None:
    with pytest.raises(StageError, match="there is no MedicationRequest/99"):
        engine(substrate(server, tmp_path), tmp_path).execute(plan(stop("99")))
    with pytest.raises(StageError, match="is not one a plan may write"):
        engine(substrate(server, tmp_path, patients=[OTHER]), tmp_path).execute(plan(stop("1")))
    orphan = dict(TEMPLATE)
    orphan.pop("subject")
    statement = f"create medicationrequests {literal(orphan)} :bed :drug :dose :mme"
    with pytest.raises(StageError, match="names no patient"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan(
                (
                    EffectKind.INSERT,
                    statement,
                    create()[2],
                    "medicationrequests",
                    "void medicationrequests",
                )
            )
        )
    sub = substrate(server, tmp_path)
    handle = sub.open(plan(create()))
    effect = plan(create()).effects[0]
    sub.apply(handle, effect)
    with pytest.raises(StageError, match="created twice"):
        sub.apply(handle, effect)
    with pytest.raises(StageConflictError, match="already has stage"):
        sub.open(plan(create()))
    with pytest.raises(ForbiddenStatementError, match="refused"):
        sub.apply(handle, plan((*stop("1")[:4], "void medicationrequests")).effects[0])
    with pytest.raises(StageError, match="before it is measured"):
        sub.commit(handle)
    sub.diff(handle)
    with pytest.raises(StageError, match="undo written first"):
        sub.commit(handle)
    sub.close(handle)
    with pytest.raises(StageError, match="not open"):
        sub.diff(handle)


def test_an_unreachable_server_is_unavailable(tmp_path: Path) -> None:
    sub = FhirSubstrate("http://127.0.0.1:9/fhir", types=TYPES, journal=tmp_path, timeout=2)
    handle = sub.open(plan(stop("1")))
    with pytest.raises(SubstrateUnavailableError, match="cannot reach"):
        sub.apply(handle, plan(stop("1")).effects[0])
    sub.close(handle)


def test_a_stage_expires(server: LoopbackFhirServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path, max_stage_seconds=0.0)
    handle = sub.open(plan(stop("1")))
    with pytest.raises(Exception, match="expired"):
        sub.apply(handle, plan(stop("1")).effects[0])
    sub.close(handle)


# -- recovery -----------------------------------------------------------------------


class _Crashing:
    """The server's API, dying after ``count`` writes."""

    def __init__(self, inner: Any, count: int) -> None:
        self._inner = inner
        self._left = count

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def call(self, method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
        if method == "PUT":
            if self._left == 0:
                raise SystemExit("crash")
            self._left -= 1
        return self._inner.call(method, path, body, **kwargs)

    def read(self, resource_type: str, resource_id: str) -> Any:
        return self._inner.read(resource_type, resource_id)

    def search(self, query: str, *, limit: int) -> Any:
        return self._inner.search(query, limit=limit)


def _crash_after_writes(sub: FhirSubstrate, count: int) -> None:
    sub._api = _Crashing(sub._api, count)  # type: ignore[assignment]


def test_recovery_reads_each_resource_back(server: LoopbackFhirServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    original = sub._discrepancies

    def crash(stage: Any) -> list[str]:
        raise SystemExit("crash after every write, before the read-back")

    sub._discrepancies = crash  # type: ignore[method-assign]
    run = engine(sub, tmp_path)
    with pytest.raises(SystemExit):
        run.execute(plan(patch("2", {"status": "on-hold"})))
    run.chain.close()
    del original
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED


def test_recovery_puts_a_partial_write_back(server: LoopbackFhirServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path)
    _crash_after_writes(sub, 1)
    run = engine(sub, tmp_path)
    with pytest.raises(SystemExit):
        run.execute(plan(patch("2", {"status": "on-hold"}), patch("3", {"status": "on-hold"})))
    run.chain.close()
    assert statuses(server)["2"] == "on-hold"
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED
    assert statuses(server) == {"1": "active", "2": "active", "3": "active"}


def test_recovery_of_nothing_written_is_a_rollback(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    _crash_after_writes(sub, 0)
    run = engine(sub, tmp_path)
    with pytest.raises(SystemExit):
        run.execute(plan(create()))
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.ABORTED


def test_recovery_cannot_say_what_someone_else_wrote(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    journal = UndoJournal(tmp_path / "journal")
    stage = uuid.uuid4()
    before = server.get("MedicationRequest", "2")
    journal.write(
        stage,
        {
            "writes": [
                {
                    "table": "medicationrequests",
                    "id": "2",
                    "action": "update",
                    "before": before,
                    "after": {"fingerprint": "x"},
                }
            ]
        },
    )
    edited = dict(before or {}, status="on-hold")
    server.write(edited, actor="Practitioner/rn-04")
    assert sub.resolve_intent(stage) is None
    journal.write(stage, {"writes": [{"table": "pods", "id": "x"}]})
    assert sub.resolve_intent(stage) is None
    journal.write(
        stage,
        {
            "writes": [
                {"table": "medicationrequests", "id": "77", "action": "update", "before": None}
            ]
        },
    )
    assert sub.resolve_intent(stage) is None
    assert sub.compensated(stage) is None


# -- the control database: an outbox, windows, facts -----------------------------------------


SINKS = (SinkSpec("pharmacy", (OperationSpec("dispense.create"),)),)


def _control(tmp_path: Path) -> Path:
    path = tmp_path / "control.db"
    install_sqlite_outbox(str(path), SINKS)
    return path


def test_a_request_commits_with_the_write(server: LoopbackFhirServer, tmp_path: Path) -> None:
    control = _control(tmp_path)
    sub = substrate(server, tmp_path, control=control)
    assert sub.capabilities.outbound and sub.control == str(control)
    builder = PlanBuilder("med-rec-agent", intent="order and dispense")
    kind, statement, parameters, table, undo = create()
    builder.add(
        kind,
        table=f"fhir:{table}",
        statement=statement,
        parameters=parameters,
        tenant_id=CHART,
        compensation=Compensation(undo),
    )
    builder.enqueue(
        sink="pharmacy", operation="dispense.create", payload={"dose_mg": 650}, tenant_id=CHART
    )
    result = engine(sub, tmp_path, sinks=SinkRegistry(SINKS)).execute(builder.build())
    assert result.committed and len(measured(result).outbound) == 1
    with sqlite3.connect(control) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone() == (1,)
    only = (
        PlanBuilder("med-rec-agent")
        .enqueue(
            sink="pharmacy", operation="dispense.create", payload={"dose_mg": 5}, tenant_id=CHART
        )
        .build()
    )
    sub = substrate(server, tmp_path, control=control)
    handle = sub.open(only)
    sub.apply(handle, only.effects[0])
    assert sub.transaction_id(handle) is None
    sub.close(handle)


def test_a_request_without_a_control_database_is_refused(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    handle = sub.open(plan(stop("1")))
    enqueue = PlanBuilder("s").enqueue(sink="pharmacy", operation="x", payload={"a": 1}).build()
    with pytest.raises(OutboundRequestError, match="no control database"):
        sub.apply(handle, enqueue.effects[0])
    with pytest.raises(Exception, match="control database"):
        sub.measure_windows(handle, ())
    with pytest.raises(Exception, match="no inbox"):
        sub.consume_facts(handle, (), "s")
    assert sub.pending_facts("s") == ()
    sub.close(handle)


def test_the_control_half_is_redone_after_a_crash(
    server: LoopbackFhirServer, tmp_path: Path
) -> None:
    control = _control(tmp_path)
    sub = substrate(server, tmp_path, control=control)
    builder = PlanBuilder("med-rec-agent", intent="order and dispense")
    kind, statement, parameters, table, undo = create()
    builder.add(
        kind,
        table=f"fhir:{table}",
        statement=statement,
        parameters=parameters,
        tenant_id=CHART,
        compensation=Compensation(undo),
    )
    builder.enqueue(
        sink="pharmacy", operation="dispense.create", payload={"dose_mg": 650}, tenant_id=CHART
    )
    original = sub._apply_all

    def crash(stage: Any, writes: Any) -> None:
        original(stage, writes)
        raise SystemExit("crash after the server, before the control database")

    sub._apply_all = crash  # type: ignore[method-assign]
    run = engine(sub, tmp_path, sinks=SinkRegistry(SINKS))
    with pytest.raises(SystemExit):
        run.execute(builder.build())
    run.chain.close()
    (record,) = engine(
        substrate(server, tmp_path, control=control), tmp_path, sinks=SinkRegistry(SINKS)
    ).recover()
    assert record.record_type is RecordType.COMMITTED
    with sqlite3.connect(control) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone() == (1,)
    sub = substrate(server, tmp_path, control=control)
    handle = sub.open(plan(create()))
    assert sub.measure_windows(handle, ()) == ()
    sub.consume_facts(handle, (), "med-rec-agent")
    sub.close(handle)


# -- savepoints ----------------------------------------------------------------------


def test_savepoints_roll_the_stage_back(server: LoopbackFhirServer, tmp_path: Path) -> None:
    sub = substrate(server, tmp_path, control=_control(tmp_path))
    first, second = plan(
        patch("2", {"status": "on-hold"}), patch("3", {"status": "on-hold"})
    ).effects
    handle = sub.open(plan(stop("1")))
    sub.apply(handle, first)
    sub.savepoint(handle, "one")
    sub.apply(handle, second)
    assert len(sub.diff(handle).deltas) == 2
    sub.rollback_to(handle, "one")
    assert [d.primary_key for d in sub.diff(handle).deltas] == ["2"]
    sub.release_savepoint(handle, "one")
    with pytest.raises(StageError, match="no savepoint"):
        sub.rollback_to(handle, "one")
    with pytest.raises(ValueError, match="unsafe"):
        sub.savepoint(handle, "1; drop")
    sub.abort(handle)
    sub.abort(handle)
    sub.close(handle)
    sub.close(handle)


# -- the loopback server itself ---------------------------------------------------------


def _http(
    server: LoopbackFhirServer, method: str, path: str, body: Any = None, **headers: str
) -> tuple[int, Any]:
    data = (
        None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    )
    request = urllib.request.Request(server.url + path, data=data, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:  # noqa: S310 - loopback
            return reply.status, json.loads(reply.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_the_server_speaks_enough_fhir(server: LoopbackFhirServer) -> None:
    auth = {"Authorization": f"Bearer {TOKEN}"}
    assert _http(server, "GET", "/Patient/x")[0] == 401
    assert _http(server, "GET", "/Patient/nobody", **auth)[0] == 404
    assert _http(server, "GET", "/Nothing", **auth)[0] == 404
    assert _http(server, "DELETE", "/MedicationRequest/1", **auth)[0] == 405
    assert _http(server, "PATCH", "/MedicationRequest/1", {}, **auth)[0] == 405
    assert (
        _http(
            server, "POST", "/MedicationRequest/1", {"resourceType": "MedicationRequest"}, **auth
        )[0]
        == 405
    )
    assert _http(server, "PUT", "/MedicationRequest/1", b"{oops", **auth)[0] == 400
    assert _http(server, "PUT", "/MedicationRequest/1", {"resourceType": "Task"}, **auth)[0] == 400
    assert (
        _http(
            server,
            "PUT",
            "/MedicationRequest/1",
            {"resourceType": "MedicationRequest", "id": "2"},
            **auth,
        )[0]
        == 400
    )
    code, created = _http(
        server,
        "POST",
        "/Task",
        {"resourceType": "Task", "id": "ignored", "status": "requested"},
        **auth,
    )
    assert code == 201 and created["id"] != "ignored" and created["meta"]["versionId"] == "1"
    stale = {**created, "status": "ready"}
    assert (
        _http(server, "PUT", f"/Task/{created['id']}", stale, **{**auth, "If-Match": 'W/"7"'})[0]
        == 412
    )
    assert (
        _http(server, "PUT", f"/Task/{created['id']}", stale, **{**auth, "If-Match": 'W/"1"'})[0]
        == 200
    )
    code, bundle = _http(server, "GET", "/Encounter?location=4A&_count=5", **auth)
    assert code == 200 and bundle["total"] == 1
    assert _http(server, "GET", "/Encounter?bogus=1", **auth)[0] == 400
    assert (
        _http(server, "GET", "/Patient?_has:Encounter:subject:location=Location/4B", **auth)[1][
            "total"
        ]
        == 1
    )
    assert _http(server, "GET", "/Patient?_has:Nope:subject:location=4B", **auth)[0] == 400
    assert _http(server, "GET", "/Patient?_has:Encounter:nope:location=4B", **auth)[0] == 400
    assert _http(server, "GET", "/Patient?_id=ch-7f3a91,x", **auth)[1]["total"] == 1
    assert len(server.history("Task", created["id"])) == 2
    assert server.search("MedicationRequest", patient=CHART, status="active")
    assert values({"a": [{"b": [1, 2]}, {"b": 3}]}, "a.b") == [1, 2, 3]
    assert values({"a": [{"b": 1}]}, "a.5.b") == []
    with pytest.raises(ValueError, match="seed a served type"):
        server.seed({"resourceType": "Observation", "id": "o"})
    strict = LoopbackFhirServer(require_if_match=True)
    with strict:
        strict.seed({"resourceType": "Task", "id": "t"})
        assert _http(strict, "PUT", "/Task/t", {"resourceType": "Task", "id": "t"})[0] == 428
        assert _http(strict, "PUT", "/Task/new", {"resourceType": "Task", "id": "new"})[0] == 201
        with pytest.raises(Exception, match="does not hold"):
            strict._store({"resourceType": "Observation"}, actor="x", request_id=None, rules=False)
    with pytest.raises(RuntimeError, match="not started"):
        _ = strict.url
    assert any(
        e["agent"][0]["who"]["identifier"]["value"] == "anonymous" for e in strict.audit_events()
    )
