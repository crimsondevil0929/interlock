"""The plan-bound undo journal and the control database's redo (1.3.0)."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from interlock.control import capture, durable_write, replay
from interlock.exceptions import StageError, SubstrateUnavailableError
from interlock.planbound import UndoJournal
from interlock.sqlite_outbox import install_sqlite_outbox
from interlock.substrate import _MARKER_TABLE


def test_the_journal_writes_reads_and_forgets(tmp_path: Path) -> None:
    journal = UndoJournal(tmp_path / "undo")
    stage = uuid.uuid4()
    assert journal.read(stage) is None
    digest = journal.write(stage, {"objects": [{"name": "api"}]})
    document, found = journal.read(stage)  # type: ignore[misc]
    assert document == {"objects": [{"name": "api"}]} and found == digest
    journal.discard(stage)
    journal.discard(stage)
    assert journal.read(stage) is None
    assert journal.directory == tmp_path / "undo"


def test_the_journal_fails_closed(tmp_path: Path) -> None:
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    with pytest.raises(SubstrateUnavailableError, match="nothing was applied"):
        UndoJournal(blocked).write(uuid.uuid4(), {})
    journal = UndoJournal(tmp_path / "undo")
    stage = uuid.uuid4()
    journal.path(stage).parent.mkdir(parents=True)
    journal.path(stage).write_text("[1]")
    with pytest.raises(SubstrateUnavailableError, match="not an object"):
        journal.read(stage)
    journal.path(stage).unlink()
    journal.path(stage).mkdir()
    with pytest.raises(SubstrateUnavailableError, match="cannot read"):
        journal.read(stage)


def test_a_redo_writes_once(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    install_sqlite_outbox(str(db), ())
    stage = str(uuid.uuid4())
    with sqlite3.connect(db) as conn:
        assert capture(conn, uuid.UUID(stage)) == {}
    record = {_MARKER_TABLE: [{"stage_id": stage, "plan_id": "p", "committed_at": "now"}]}
    replay(str(db), stage, record, timeout=5)
    replay(str(db), stage, record, timeout=5)
    with sqlite3.connect(db) as conn:
        assert conn.execute(f"SELECT count(*) FROM {_MARKER_TABLE}").fetchone() == (1,)
        assert capture(conn, uuid.UUID(stage)) == {_MARKER_TABLE: record[_MARKER_TABLE]}


def test_a_redo_that_cannot_be_written_says_so(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    install_sqlite_outbox(str(db), ())
    bad = {_MARKER_TABLE: [{"stage_id": "s", "no_such_column": 1}]}
    with pytest.raises(StageError, match="could not be written again"):
        replay(str(db), "s", bad, timeout=5)
    with pytest.raises(SubstrateUnavailableError, match="cannot open"):
        replay(str(tmp_path / "missing" / "x.db"), "s", {}, timeout=5)
    target = tmp_path / "redo.json"
    durable_write(target, b"{}")
    assert target.read_bytes() == b"{}"
