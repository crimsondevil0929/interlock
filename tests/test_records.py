"""ILOK1 records: signed, linked, resumable, and pinned by the ledger's anchors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.receipts import HmacKey

from interlock.exceptions import AnchorError, ChainInUseError, RecordIntegrityError
from interlock.records import (
    GENESIS,
    RECORD_DOMAIN,
    RecordKind,
    RecordLog,
    SignedRecord,
    anchor_memo,
    check_anchors,
    verify_records,
)

KIND = RecordKind.RECOVERY_STEP


def filled(log: RecordLog, n: int = 3) -> list[SignedRecord]:
    return [
        log.append(KIND, scope="support-agent", body={"step": i, "cost": "0.10"})
        for i in range(1, n + 1)
    ]


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_records_are_signed_linked_and_verify() -> None:
    key = HmacKey.generate()
    log = RecordLog(key, log_id="support")
    first, second, third = filled(log)
    assert (first.seq, first.prev) == (1, GENESIS)
    assert second.prev == first.record_hash and third.prev == second.record_hash
    assert log.head == third.record_hash and len(log) == 3
    assert first.signing_input().startswith(RECORD_DOMAIN)
    assert first.body == {"step": 1, "cost": "0.10"}
    log.verify()
    with pytest.raises(RecordIntegrityError, match="signed by key"):
        log.verify(HmacKey.generate())


def test_a_body_that_canonical_json_cannot_carry_is_refused() -> None:
    log = RecordLog(HmacKey.generate())
    with pytest.raises(ValueError, match="canonical JSON"):
        log.append(KIND, scope="s", body={"cost": 0.1})
    with pytest.raises(ValueError, match="log id"):
        RecordLog(HmacKey.generate(), log_id="has space")
    log.close()
    with pytest.raises(AnchorError, match="closed"):
        log.append(KIND, scope="s", body={})


def test_a_log_file_resumes_and_loads(tmp_path: Path) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, log_id="support", path=path) as log:
        written = filled(log)
    with RecordLog(key, log_id="support", path=path) as log:
        assert log.records() == tuple(written)
        fourth = log.append(KIND, scope="support-agent", body={"step": 4})
    assert fourth.prev == written[-1].record_hash
    assert [r.seq for r in RecordLog.load(path, key)] == [1, 2, 3, 4]


def test_one_log_file_has_one_writer(tmp_path: Path) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, path=path), pytest.raises(ChainInUseError, match="record log"):
        RecordLog(key, path=path)


def test_a_torn_last_line_is_cut_off_on_resume_and_skipped_on_load(tmp_path: Path) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, path=path) as log:
        filled(log, 2)
    with path.open("ab") as handle:
        handle.write(b'{"v": "ILOK1", "seq": 3')
    assert len(RecordLog.load(path, key)) == 2
    with RecordLog(key, path=path) as log:
        assert len(log) == 2
        assert log.append(KIND, scope="s", body={}).seq == 3


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        (lambda rows: rows[1]["body"].update(cost="0.01"), "does not verify"),
        (lambda rows: rows.insert(0, rows.pop(1)), "sequence"),
        (lambda rows: rows.pop(0), "sequence"),
        (lambda rows: rows[2].update(prev=rows[0]["prev"]), "re-linked"),
        (lambda rows: rows[1].update(log="other"), "spliced"),
        (lambda rows: rows[1]["sig"].update(signature="ab" * 32), "does not verify"),
        (lambda rows: rows[1]["sig"].update(signature="ab" * 8), "32 bytes"),
        (lambda rows: rows[1]["sig"].update(alg="ed25519", signature="ab" * 64), "algorithm"),
        (lambda rows: rows[1].update(extra=1), "fields"),
        (lambda rows: rows[1].update(v="ILOK2"), "v must be"),
        (lambda rows: rows[1].update(seq=True), "seq"),
        (lambda rows: rows[1]["sig"].pop("alg"), "sig is"),
    ],
)
def test_any_edit_to_the_file_fails_verification(tmp_path: Path, tamper: Any, message: str) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, path=path) as log:
        filled(log)
    rows = lines(path)
    tamper(rows)
    write(path, rows)
    with pytest.raises(RecordIntegrityError, match=message):
        RecordLog.load(path, key)
    with pytest.raises(RecordIntegrityError):
        RecordLog(key, path=path)


def test_a_float_in_a_stored_body_is_refused(tmp_path: Path) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, path=path) as log:
        filled(log, 1)
    path.write_text(path.read_text().replace('"0.10"', "0.1"))
    with pytest.raises(RecordIntegrityError, match="line 1"):
        RecordLog.load(path, key)


def test_a_log_resumed_under_another_id_is_refused(tmp_path: Path) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    with RecordLog(key, log_id="one", path=path) as log:
        filled(log, 1)
    with pytest.raises(RecordIntegrityError, match="holds log 'one'"):
        RecordLog(key, log_id="two", path=path)


def test_the_ledger_anchors_catch_a_truncated_or_rewritten_log(tmp_path: Path) -> None:
    gov = BudgetManager.open_sqlite(str(tmp_path / "gov.db"))
    gov.open_root("support-agent", "5")
    key = HmacKey.generate()
    log = RecordLog(key, log_id="support")
    records = filled(log)
    for record in records:
        gov.anchor("support-agent", anchor_memo(record))
    gov.anchor("support-agent", "ILOK1 another-log 1 " + "0" * 64)
    gov.anchor("support-agent", "an escrow chain head")
    trail = gov.audit_trail()

    assert check_anchors(records, trail) == 3
    assert check_anchors([], trail) == 0
    with pytest.raises(RecordIntegrityError, match="truncated"):
        check_anchors(records[:2], trail)

    forged = RecordLog(key, log_id="support")
    rewritten = [
        forged.append(KIND, scope="support-agent", body={"step": i, "cost": "0.00"})
        for i in range(1, 4)
    ]
    verify_records(rewritten, key)  # a forger with the key can make it verify alone
    with pytest.raises(RecordIntegrityError, match="rewritten"):
        check_anchors(rewritten, trail)
    gov.close()


def test_from_json_rejects_what_is_not_a_record() -> None:
    with pytest.raises(RecordIntegrityError, match="fields"):
        SignedRecord.from_json([1, 2])
    log = RecordLog(HmacKey.generate())
    record = filled(log, 1)[0]
    assert SignedRecord.from_json(record.to_json()) == record
    raw = record.to_json()
    raw["sig"]["signature"] = "XYZ"
    with pytest.raises(RecordIntegrityError, match="not hex"):
        SignedRecord.from_json(raw)
    raw = record.to_json()
    raw["body"]["cost"] = 0.1
    with pytest.raises(RecordIntegrityError, match="float"):
        SignedRecord.from_json(raw)


def test_a_record_that_cannot_be_written_leaves_the_log_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = HmacKey.generate()
    path = tmp_path / "records.jsonl"
    log = RecordLog(key, log_id="support", path=path)
    assert (log.log_id, log.path, log.signer) == ("support", path, key)
    filled(log, 1)
    size = path.stat().st_size

    def fail(fd: int) -> None:
        raise OSError("disk gone")

    monkeypatch.setattr("interlock.records.os.fsync", fail)
    with pytest.raises(OSError, match="disk gone"):
        log.append(KIND, scope="s", body={})
    monkeypatch.undo()
    assert path.stat().st_size == size and len(log) == 1
    assert log.append(KIND, scope="s", body={}).seq == 2
    log.close()
    assert len(RecordLog.load(path, key)) == 2
