"""The FHIR substrate against a real FHIR R4 server (HAPI FHIR,
``INTERLOCK_TEST_FHIR_URL``).

Every test seeds its own chart (patients, beds, encounters and orders whose
ids carry a fresh suffix), so tests share one server without meeting. What is
the server's own here: ``meta.versionId`` and the ``ETag``, writes on
``If-Match`` and the conflict a stale version gets (HAPI answers ``409``
where the specification says ``412``; the substrate takes either), searches
with ``_has`` resolving the template's conditional references, and the
resources as the server stores and returns them, read back and compared.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    BlastRadius,
    CompensatedError,
    EscrowChain,
    EscrowEngine,
    FhirSubstrate,
    FhirType,
    PlanBuilder,
)
from interlock.chain import RecordType
from interlock.exceptions import StageConflictError, StageError
from interlock.fhir import STAGE_TAG
from interlock.predicted import PREDICTED
from interlock.types import Compensation, EffectDiff, EffectKind

from .real_systems import need

ORDERS = FhirType(
    "medicationrequests",
    "MedicationRequest",
    columns={
        "status": "status",
        "drug": "medicationCodeableConcept.text",
        "dose_mg": "dosageInstruction.0.doseAndRate.0.doseQuantity.value",
        "encounter": "encounter.reference",
    },
)


class _Server:
    """The FHIR server, as the test's own client."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        request = urllib.request.Request(  # noqa: S310 - the test's own server URL
            f"{self.base}/{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Content-Type": "application/fhir+json", "Accept": "application/fhir+json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as reply:  # noqa: S310
                return reply.status, json.loads(reply.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"null")

    def put(self, resource: dict[str, Any]) -> dict[str, Any]:
        status, found = self.call("PUT", f"{resource['resourceType']}/{resource['id']}", resource)
        assert status in (200, 201), found
        return dict(found)

    def get(self, resource_type: str, resource_id: str) -> dict[str, Any]:
        status, found = self.call("GET", f"{resource_type}/{resource_id}")
        assert status == 200, found
        return dict(found)


@pytest.fixture
def server() -> _Server:
    return _Server(need("INTERLOCK_TEST_FHIR_URL")[0])


@pytest.fixture
def chart(server: _Server) -> dict[str, str]:
    """A patient in bed 4A of an encounter at a facility, with two active
    orders, every id fresh."""
    sfx = uuid.uuid4().hex[:8]
    ids = {
        "patient": f"pt-{sfx}",
        "bed": f"bed-{sfx}",
        "encounter": f"enc-{sfx}",
        "facility": f"fac-{sfx}",
        "order1": f"ord1-{sfx}",
        "order2": f"ord2-{sfx}",
        "other_bed": f"bed2-{sfx}",
    }
    server.put({"resourceType": "Organization", "id": ids["facility"]})
    server.put({"resourceType": "Patient", "id": ids["patient"], "name": [{"text": "test"}]})
    for bed in (ids["bed"], ids["other_bed"]):
        server.put({"resourceType": "Location", "id": bed})
    server.put(
        {
            "resourceType": "Encounter",
            "id": ids["encounter"],
            "status": "in-progress",
            "class": {"code": "IMP"},
            "subject": {"reference": f"Patient/{ids['patient']}"},
            "location": [{"location": {"reference": f"Location/{ids['bed']}"}}],
            "serviceProvider": {"reference": f"Organization/{ids['facility']}"},
        }
    )
    for key, drug in (("order1", "lisinopril"), ("order2", "metformin")):
        server.put(order(ids[key], ids["patient"], ids["encounter"], drug, 10))
    return ids


def order(order_id: str, patient: str, encounter: str, drug: str, dose: int) -> dict[str, Any]:
    return {
        "resourceType": "MedicationRequest",
        "id": order_id,
        "status": "active",
        "intent": "order",
        "subject": {"reference": f"Patient/{patient}"},
        "encounter": {"reference": f"Encounter/{encounter}"},
        "medicationCodeableConcept": {"text": drug},
        "dosageInstruction": [{"doseAndRate": [{"doseQuantity": {"value": dose, "unit": "mg"}}]}],
    }


TEMPLATE = {
    "resourceType": "MedicationRequest",
    "status": "active",
    "intent": "order",
    "subject": {"reference": "Patient?_has:Encounter:subject:location=:bed"},
    "encounter": {"reference": "Encounter?location=:bed&status=in-progress"},
    "medicationCodeableConcept": {"text": ":drug"},
    "dosageInstruction": [{"doseAndRate": [{"doseQuantity": {"value": ":dose", "unit": "mg"}}]}],
}


def literal(document: Any) -> str:
    return "'" + json.dumps(document).replace("'", "''") + "'"


def create(bed: str, drug: str = "acetaminophen", dose: int = 650) -> tuple[Any, ...]:
    return (
        EffectKind.INSERT,
        f"create medicationrequests {literal(TEMPLATE)} :bed :drug :dose",
        {"bed": bed, "drug": drug, "dose": dose},
        "void medicationrequests",
    )


def patch(order_id: str, change: dict[str, Any]) -> tuple[Any, ...]:
    return (
        EffectKind.UPDATE,
        f"patch medicationrequests :id {literal(change)}",
        {"id": order_id},
        "restore medicationrequests",
    )


def plan(patient: str, *effects: tuple[Any, ...]) -> Any:
    builder = PlanBuilder("med-rec-agent", intent="reconcile")
    for kind, statement, parameters, undo in effects:
        builder.add(
            kind,
            table="fhir:medicationrequests",
            statement=statement,
            parameters=parameters,
            tenant_id=patient,
            compensation=Compensation(undo),
        )
    return builder.build()


class _Fhir(FhirSubstrate):
    """The substrate, its methods replaceable for a test."""


class _AfterWrites:
    """The substrate's API, calling ``then`` after its ``count``-th PUT."""

    def __init__(self, inner: Any, count: int, then: Any) -> None:
        self._inner, self._left, self._then = inner, count, then

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def call(self, method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
        found = self._inner.call(method, path, body, **kwargs)
        if method == "PUT":
            self._left -= 1
            if self._left == 0:
                self._then()
        return found

    def read(self, resource_type: str, resource_id: str) -> Any:
        return self._inner.read(resource_type, resource_id)

    def search(self, query: str, *, limit: int) -> Any:
        return self._inner.search(query, limit=limit)


def substrate(server: _Server, tmp_path: Path) -> FhirSubstrate:
    return _Fhir(server.base, types=(ORDERS,), journal=tmp_path / "journal", timeout=30)


def engine(sub: FhirSubstrate, tmp_path: Path) -> EscrowEngine:
    return EscrowEngine(sub, checkers=[BlastRadius(10)], chain=EscrowChain(tmp_path / "c.ilok1"))


def diff(result: Any) -> EffectDiff:
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def test_a_create_resolves_its_references_and_reads_back_as_predicted(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    result = engine(substrate(server, tmp_path), tmp_path).execute(
        plan(chart["patient"], create(chart["bed"]))
    )
    assert result.committed
    (delta,) = diff(result).deltas
    assert delta.before is None and delta.tenant_id == chart["patient"]
    after = dict(delta.after or {})
    assert (after["drug"], after["dose_mg"], after["encounter"]) == (
        "acetaminophen",
        650,
        f"Encounter/{chart['encounter']}",
    )
    stored = server.get("MedicationRequest", delta.primary_key)
    assert stored["subject"] == {"reference": f"Patient/{chart['patient']}"}
    assert stored["meta"]["versionId"] == "1"
    assert [t["code"] for t in stored["meta"]["tag"] if t["system"] == STAGE_TAG] == [
        str(diff(result).stage_id)
    ]
    assert substrate(server, tmp_path).capabilities.measurement == PREDICTED


def test_a_patch_writes_on_the_version_read(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    dose = {"doseQuantity": {"value": 20, "unit": "mg"}}
    change = {"dosageInstruction": [{"doseAndRate": [dose]}]}
    result = engine(substrate(server, tmp_path), tmp_path).execute(
        plan(chart["patient"], patch(chart["order1"], change))
    )
    assert result.committed
    (delta,) = diff(result).deltas
    assert (dict(delta.before or {})["dose_mg"], dict(delta.after or {})["dose_mg"]) == (10, 20)
    stored = server.get("MedicationRequest", chart["order1"])
    assert stored["meta"]["versionId"] == "2"
    status, history = server.call("GET", f"MedicationRequest/{chart['order1']}/_history")
    assert status == 200 and history["total"] == 2


def test_a_version_gone_before_the_write_is_a_conflict(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    original = sub.write_undo

    def nurse_edits(handle: Any) -> str:
        edited = server.get("MedicationRequest", chart["order1"])
        edited["note"] = [{"text": "dose questioned"}]
        server.put(edited)
        return original(handle)

    sub.write_undo = nurse_edits  # type: ignore[method-assign]
    with pytest.raises(StageConflictError):
        engine(sub, tmp_path).execute(
            plan(chart["patient"], patch(chart["order1"], {"status": "on-hold"}))
        )
    stored = server.get("MedicationRequest", chart["order1"])
    assert stored["status"] == "active" and stored["note"] == [{"text": "dose questioned"}]


def test_a_write_refused_on_its_version_puts_the_earlier_ones_back(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    """The create lands; the patch after it meets a version someone else just
    wrote, and the server refuses it. The create is voided
    (``entered-in-error``), never deleted, and the chart is as it was."""
    sub = substrate(server, tmp_path)

    def pharmacist_edits() -> None:
        edited = server.get("MedicationRequest", chart["order2"])
        edited["note"] = [{"text": "held by the pharmacist"}]
        server.put(edited)

    sub._api = _AfterWrites(sub._api, 1, pharmacist_edits)  # type: ignore[assignment]
    with pytest.raises(CompensatedError) as caught:
        engine(sub, tmp_path).execute(
            plan(
                chart["patient"],
                create(chart["bed"]),
                patch(chart["order2"], {"status": "on-hold"}),
            )
        )
    assert "every resource written before it was put back" in str(caught.value)
    status, found = server.call(
        "GET", f"MedicationRequest?subject=Patient/{chart['patient']}&_count=50"
    )
    assert status == 200
    by_id = {e["resource"]["id"]: e["resource"] for e in found.get("entry") or ()}
    created = [r for i, r in by_id.items() if i not in (chart["order1"], chart["order2"])]
    assert [r["status"] for r in created] == ["entered-in-error"]
    assert by_id[chart["order2"]]["status"] == "active"
    assert by_id[chart["order2"]]["note"] == [{"text": "held by the pharmacist"}], (
        "the pharmacist's edit stands: the stage's refused write is never put back over it"
    )
    assert by_id[chart["order2"]]["meta"]["versionId"] == "2"
    records = EscrowChain.load(tmp_path / "c.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED


def test_a_conditional_reference_must_find_exactly_one(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    server.put(
        {
            "resourceType": "Encounter",
            "id": f"{chart['encounter']}-b",
            "status": "in-progress",
            "class": {"code": "IMP"},
            "subject": {"reference": f"Patient/{chart['patient']}"},
            "location": [{"location": {"reference": f"Location/{chart['other_bed']}"}}],
        }
    )
    server.put(
        {
            "resourceType": "Encounter",
            "id": f"{chart['encounter']}-c",
            "status": "in-progress",
            "class": {"code": "IMP"},
            "subject": {"reference": f"Patient/{chart['patient']}"},
            "location": [{"location": {"reference": f"Location/{chart['other_bed']}"}}],
        }
    )
    with pytest.raises(StageError, match="matches 0 resources"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan(chart["patient"], create(f"nowhere-{uuid.uuid4().hex[:6]}"))
        )
    with pytest.raises(StageError, match="matches 2 resources"):
        engine(substrate(server, tmp_path), tmp_path).execute(
            plan(chart["patient"], create(chart["other_bed"]))
        )


def test_recovery_reads_each_resource_back(
    server: _Server, chart: dict[str, str], tmp_path: Path
) -> None:
    sub = substrate(server, tmp_path)
    run = engine(sub, tmp_path)

    def crash() -> None:
        raise SystemExit("crash after the write")

    sub._api = _AfterWrites(sub._api, 1, crash)  # type: ignore[assignment]
    with pytest.raises(SystemExit):
        run.execute(plan(chart["patient"], patch(chart["order1"], {"status": "on-hold"})))
    run.chain.close()
    (record,) = engine(substrate(server, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED
    assert server.get("MedicationRequest", chart["order1"])["status"] == "on-hold"
