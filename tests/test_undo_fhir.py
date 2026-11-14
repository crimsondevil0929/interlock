"""Undo on a FHIR server (1.10.0): each changed resource kept whole beside the undo journal,
and patched back, its bookkeeping left alone, only while it is as the plan left it. A record
the plan created is voided, never deleted, so its undo is refused in words."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from interlock.exceptions import UndoError
from interlock.sim.fhir import LoopbackFhirServer
from interlock.undo import UNDO_EXACT, digest_problems
from tests.test_fhir import (
    create,
    patch,
    server,  # noqa: F401 - the loopback FHIR server, as a fixture
)
from tests.test_fhir import engine as fhir_engine
from tests.test_fhir import plan as fhir_plan
from tests.test_fhir import substrate as fhir_substrate

WEEK = timedelta(days=7)
DOSE = [{"doseAndRate": [{"doseQuantity": {"value": 20, "unit": "mg"}}]}]


def dose(fhir: LoopbackFhirServer, order_id: str) -> int:
    found = fhir.get("MedicationRequest", order_id)
    assert found is not None
    value: int = found["dosageInstruction"][0]["doseAndRate"][0]["doseQuantity"]["value"]
    return value


def test_a_fhir_undo_patches_each_order_back(
    server: LoopbackFhirServer,  # noqa: F811 - the fixture imported above
    tmp_path: Path,
) -> None:
    sub = fhir_substrate(server, tmp_path, undo=WEEK)
    done = fhir_engine(sub, tmp_path).execute(fhir_plan(patch("1", {"dosageInstruction": DOSE})))
    assert done.committed and dose(server, "1") == 20 and len(done.changes) == 1
    assert (tmp_path / "journal" / "kept" / f"{done.plan.plan_id}.json").is_file()

    undone = fhir_engine(sub, tmp_path / "u").undo(done.plan.plan_id, scope_id="med-rec-agent")
    assert undone.committed, undone.blocked_by
    assert dose(server, "1") == 10
    assert digest_problems(undone.undid, undone.changes) == []

    # a nurse's edit since: the undo is refused, naming the order, and writes nothing
    again = fhir_engine(sub, tmp_path / "a").execute(
        fhir_plan(patch("2", {"dosageInstruction": DOSE}))
    )
    assert again.committed
    found = server.get("MedicationRequest", "2")
    assert found is not None
    server.write({**found, "note": [{"text": "held by the nurse"}]}, actor="Practitioner/rn-04")
    refused = fhir_engine(sub, tmp_path / "r").undo(again.plan.plan_id, scope_id="med-rec-agent")
    assert not refused.committed and refused.blocked_by == (UNDO_EXACT,)
    assert "medicationrequests 2 was not put back" in refused.verdict.blocking[0].message  # type: ignore[union-attr]
    assert dose(server, "2") == 20

    # an order the plan created is voided, never deleted: its undo is said, not staged
    made = fhir_engine(sub, tmp_path / "c").execute(fhir_plan(create()))
    assert made.committed
    with pytest.raises(UndoError, match="voided, never deleted"):
        fhir_engine(sub, tmp_path / "d").undo(made.plan.plan_id, scope_id="med-rec-agent")
