"""Sensor facts (1.3.0): an analyzer's signed result on the exact diff a stage
measured, required by a pure checker."""

from __future__ import annotations

import dataclasses
import json
import sys
import textwrap
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts import HmacKey
from agentgov.receipts.signing import Ed25519Signer

from interlock import (
    BlastRadius,
    CommandSensor,
    EscrowEngine,
    FunctionSensor,
    PlanBuilder,
    SensorAttestation,
    SensorFact,
    SqliteSubstrate,
    TableSpec,
    sign_fact,
)
from interlock.exceptions import StageError
from interlock.receipts import checker_records
from interlock.sensors import diff_document, sense
from interlock.types import EffectDiff, PlanId, RowDelta, UnknownValue, Verdict

KEY = HmacKey(b"s" * 32)


def measured(result: Any) -> EffectDiff:
    """A result's diff, which every staged plan has."""
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def judged(result: Any) -> Verdict:
    """A result's verdict, which every staged plan has."""
    assert result.verdict is not None
    found: Verdict = result.verdict
    return found


def image(row: Any) -> dict[str, Any]:
    """A row image, present."""
    assert row is not None
    return dict(row)


def _diff(**changes: Any) -> EffectDiff:
    base = EffectDiff(
        plan_id=PlanId("p-1"),
        stage_id=uuid.uuid4(),
        substrate_id="kubernetes",
        computed_at=datetime.now(UTC),
        deltas=(
            RowDelta(
                "deployments",
                "prod/api",
                {"replicas": 4, "image": "reg/api:1"},
                {"replicas": 6, "image": "reg/api:latest"},
                tenant_id="prod",
            ),
        ),
    )
    return dataclasses.replace(base, **changes)


def _plan() -> Any:
    return (
        PlanBuilder("sre", intent="scale").update(table="t", statement="UPDATE t SET a = 1").build()
    )


def _fact(diff: EffectDiff, verdict: str = "pass", signer: Any = KEY, **fields: Any) -> SensorFact:
    fact = sign_fact(
        signer,
        sensor="policy-check",
        subject=diff.measured_hash(),
        verdict=verdict,
        findings=0 if verdict == "pass" else 2,
        report=b"report",
    )
    return dataclasses.replace(fact, **fields) if fields else fact


def test_a_clean_signed_result_on_this_diff_passes() -> None:
    diff = _diff()
    attested = dataclasses.replace(diff, sensors=(_fact(diff),))
    checker = SensorAttestation("policy-check", [KEY.spec()])
    assert checker.check(_plan(), attested) == ()
    assert checker.name == "sensor_attestation:policy-check"
    assert checker.sensor == "policy-check" and checker.keys == (KEY.spec(),)


def test_an_ed25519_key_works_as_well() -> None:
    signer = Ed25519Signer.generate()
    diff = _diff()
    attested = dataclasses.replace(diff, sensors=(_fact(diff, signer=signer),))
    assert SensorAttestation("policy-check", [signer.public_key()]).check(_plan(), attested) == ()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"subject": "0" * 64}, "another diff"),
        ({"key_id": "nobody"}, "not one the mandate pins"),
        ({"alg": "ed25519"}, "the fact says"),
        ({"signature": "zz"}, "not hex"),
        ({"signature": "00" * 32}, "does not verify"),
        ({"findings": 5}, "does not verify"),
    ],
)
def test_a_result_that_is_no_fact_about_this_diff_blocks(
    change: dict[str, Any], message: str
) -> None:
    diff = _diff()
    attested = dataclasses.replace(diff, sensors=(_fact(diff, **change),))
    (violation,) = SensorAttestation("policy-check", [KEY.spec()]).check(_plan(), attested)
    assert message in violation.message
    assert violation.evidence["sensor"] == "policy-check"


def test_a_fail_blocks_and_no_fact_blocks() -> None:
    diff = _diff()
    failed = dataclasses.replace(diff, sensors=(_fact(diff, verdict="fail"),))
    (violation,) = SensorAttestation("policy-check", [KEY.spec()]).check(_plan(), failed)
    assert "found 2 problems" in violation.message
    assert violation.evidence["verdict"] == "fail" and violation.evidence["findings"] == "2"
    (none,) = SensorAttestation("policy-check", [KEY.spec()]).check(_plan(), diff)
    assert "attested nothing" in none.message
    other = dataclasses.replace(
        diff, sensors=(dataclasses.replace(_fact(diff), sensor="kubeconform"),)
    )
    assert SensorAttestation("policy-check", [KEY.spec()]).check(_plan(), other)


def test_a_fact_replayed_after_the_diff_changed_is_none() -> None:
    diff = _diff()
    fact = _fact(diff)
    later = _diff(deltas=diff.deltas + diff.deltas, sensors=(fact,))
    (violation,) = SensorAttestation("policy-check", [KEY.spec()]).check(_plan(), later)
    assert "another diff" in violation.message


def test_the_checker_is_configured_and_digested_stably() -> None:
    with pytest.raises(ValueError, match="names its sensor"):
        SensorAttestation("", [KEY.spec()])
    with pytest.raises(ValueError, match="at least one key"):
        SensorAttestation("x", [])
    one = SensorAttestation("x", [KEY.spec(), HmacKey(b"t" * 32).spec()])
    two = SensorAttestation("x", [HmacKey(b"t" * 32).spec(), KEY.spec()])
    assert checker_records([one]) == checker_records([two])


def test_a_diff_hashes_its_facts_and_unknowns_only_when_it_has_them() -> None:
    diff = _diff()
    fact = _fact(diff)
    attested = dataclasses.replace(diff, sensors=(fact,))
    unknown = dataclasses.replace(diff, unknowns=(UnknownValue("t", "k", "c"),))
    assert attested.content_hash() != diff.content_hash()
    assert attested.measured_hash() == diff.content_hash() == diff.measured_hash()
    assert unknown.content_hash() != diff.content_hash()
    assert fact.digest() != dataclasses.replace(fact, signature="00").digest()


def test_a_fact_reads_back_from_json() -> None:
    fact = _fact(_diff())
    assert SensorFact.from_json(json.loads(json.dumps(fact.to_json()))) == fact
    raw = fact.to_json()
    for broken, message in [
        ({**raw, "extra": 1}, "an object of"),
        ("text", "an object of"),
        ({**raw, "findings": -1}, "a count"),
        ({**raw, "findings": True}, "a count"),
        ({**raw, "sensor": ""}, "are text"),
        ({**raw, "verdict": "maybe"}, "pass or fail"),
        ({**raw, "subject": "abc"}, "SHA-256"),
    ]:
        with pytest.raises(ValueError, match=message):
            SensorFact.from_json(broken)
    with pytest.raises(ValueError, match="pass or fail"):
        sign_fact(KEY, sensor="x", subject="0" * 64, verdict="ok", findings=0, report=b"")


def test_the_document_a_sensor_reads() -> None:
    diff = _diff(unknowns=(UnknownValue("deployments", "prod/api", "endpoint"),))
    document = json.loads(diff_document(_plan(), diff))
    assert document["subject"] == diff.measured_hash()
    assert document["rows"][0]["after"]["image"] == "reg/api:latest"
    assert document["unknowns"] == [
        {"table": "deployments", "key": "prod/api", "column": "endpoint"}
    ]
    assert document["intent"] == "scale"


def _analyze(document: bytes) -> tuple[str, int, bytes]:
    rows = json.loads(document)["rows"]
    latest = sum(
        1 for r in rows if r["after"] and str(r["after"].get("value", "")).endswith(":latest")
    )
    return ("fail" if latest else "pass", latest, document)


def test_the_engine_shows_each_diff_to_its_sensors(tmp_path: Path) -> None:
    db = tmp_path / "app.db"
    import sqlite3

    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE images (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO images VALUES (1, 'reg/api:1')")
    substrate = SqliteSubstrate(str(db), tables=[TableSpec("images", columns=["id", "value"])])
    sensor = FunctionSensor("policy-check", _analyze, KEY)
    engine = EscrowEngine(
        substrate,
        checkers=[BlastRadius(5), SensorAttestation("policy-check", [KEY.spec()])],
        sensors=[sensor],
    )

    def set_image(value: str) -> Any:
        return (
            PlanBuilder("sre", intent="image")
            .update(
                table="images",
                statement="UPDATE images SET value = :v WHERE id = 1",
                parameters={"v": value},
            )
            .build()
        )

    clean = engine.execute(set_image("reg/api:2"))
    assert clean.committed and len(measured(clean).sensors) == 1
    assert judged(clean).diff_hash == measured(clean).content_hash()
    dirty = engine.execute(set_image("reg/api:latest"))
    assert not dirty.committed
    assert judged(dirty).blocking[0].invariant == "sensor_attestation:policy-check"
    with pytest.raises(ValueError, match="share a name"):
        EscrowEngine(substrate, checkers=[], sensors=[sensor, sensor])
    plain = _diff()
    assert sense((), _plan(), plain) is plain


ANALYZER = textwrap.dedent(
    """
    import hashlib, json, sys
    from agentgov.receipts import HmacKey
    from interlock.sensors import sign_fact
    document = sys.stdin.buffer.read()
    rows = json.loads(document)["rows"]
    bad = sum(1 for r in rows if (r["after"] or {}).get("replicas", 0) > 20)
    fact = sign_fact(
        HmacKey(b"s" * 32),
        sensor="policy-check",
        subject=json.loads(document)["subject"],
        verdict="fail" if bad else "pass",
        findings=bad,
        report=document,
    )
    print(json.dumps(fact.to_json()))
    """
)


def test_a_command_sensor_runs_the_analyzer_as_its_own_process(tmp_path: Path) -> None:
    script = tmp_path / "analyzer.py"
    script.write_text(ANALYZER)
    sensor = CommandSensor(
        "policy-check", [sys.executable, str(script)], env={"PYTHONPATH": ":".join(sys.path)}
    )
    diff = _diff()
    fact = sensor.examine(diff_document(_plan(), diff), diff.measured_hash())
    assert fact.verdict == "pass" and fact.subject == diff.measured_hash()
    big = _diff(
        deltas=(
            RowDelta(
                "deployments", "prod/api", {"replicas": 4}, {"replicas": 60}, tenant_id="prod"
            ),
        )
    )
    failed = sensor.examine(diff_document(_plan(), big), big.measured_hash())
    assert (failed.verdict, failed.findings) == ("fail", 1)
    assert sensor.name == "policy-check"


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([sys.executable, "-c", "import sys; sys.exit(3)"], r"failed \(3\)"),
        ([sys.executable, "-c", "print('nothing')"], "answered no fact"),
        (["/no/such/analyzer"], "could not run"),
        ([sys.executable, "-c", "import time; time.sleep(5)"], "ran past"),
    ],
)
def test_a_command_sensor_that_answers_nothing_refuses_the_stage(
    argv: list[str], message: str
) -> None:
    sensor = CommandSensor("policy-check", argv, timeout=1.0)
    with pytest.raises(StageError, match=message):
        sensor.examine(b"{}", "0" * 64)


def test_a_command_sensor_must_answer_about_this_diff(tmp_path: Path) -> None:
    fact = _fact(_diff())
    script = tmp_path / "liar.py"
    script.write_text(f"print({json.dumps(json.dumps(fact.to_json()))})")
    with pytest.raises(StageError, match="on another diff"):
        CommandSensor("policy-check", [sys.executable, str(script)]).examine(b"{}", "1" * 64)
    with pytest.raises(ValueError, match="names the command"):
        CommandSensor("x", [])


def test_a_receipt_names_the_commit_a_substrate_made(tmp_path: Path) -> None:
    """A substrate that names its commit only once it is made (Git's new
    commit) has it written in the receipt (1.3.0)."""
    import sqlite3

    from agentgov.receipts import ReceiptLog

    from interlock.receipts import ReceiptIssuer
    from interlock.types import CommitReceipt

    class Named(SqliteSubstrate):
        def commit(self, handle: Any) -> CommitReceipt:
            done = super().commit(handle)
            return dataclasses.replace(done, substrate_txn_id="c0ffee")

    db = tmp_path / "app.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE images (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO images VALUES (1, 'a')")
    log = ReceiptLog("t", HmacKey(b"k" * 32), path=tmp_path / "r.jsonl")
    engine = EscrowEngine(
        Named(str(db), tables=[TableSpec("images", columns=["id", "value"])]),
        checkers=[BlastRadius(5)],
        receipts=ReceiptIssuer(log, row_secret=b"r" * 32),
    )
    result = engine.execute(
        PlanBuilder("s").update(table="images", statement="UPDATE images SET value = 'b'").build()
    )
    assert result.receipt is not None and result.receipt.outcome.substrate_txid == "c0ffee"
