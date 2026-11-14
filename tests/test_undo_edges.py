"""Undo's edges (1.10.0): what each substrate says it cannot write back, before anything is
staged; kept records that lapse, that a stage left behind, or that cannot be read."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import SqliteSubstrate, TableSpec
from interlock.exceptions import UndoError
from interlock.sim.fhir import LoopbackFhirServer
from interlock.sim.rest import LoopbackRestServer
from interlock.types import Change
from interlock.undo import Kept, KeptRecords, change_digests, template_literal
from tests.test_fhir import server as fhir_server  # noqa: F401 - the FHIR stand-in, a fixture
from tests.test_rest import server  # noqa: F401 - the REST stand-in, a fixture

WEEK = timedelta(days=7)
NOW = datetime.now(UTC)


def kept(*changes: Change, payload: dict[str, Any] | None = None, plan: str = "p") -> Kept:
    return Kept(
        plan_id=plan,
        substrate_id="x",
        changes=changes,
        key=b"k" * 32,
        committed_at=NOW,
        expires_at=NOW + WEEK,
        payload=payload or {},
    )


def test_kept_records_lapse_and_a_stages_leftovers_are_purged(tmp_path: Path) -> None:
    records = KeptRecords(tmp_path / "kept")
    assert records.read("nothing") is None
    pending = records.pending("stage-1", {"plan_id": "plan/odd id", "changes": []})
    records.commit(pending, "plan/odd id", NOW, WEEK)
    assert records.read("plan/odd id") is not None  # a name no file can hold: its digest
    lapsed = records.pending("stage-2", {"plan_id": "old"})
    records.commit(lapsed, "old", NOW - 2 * WEEK, WEEK)
    assert records.read("old") is None
    stale = records.pending("stage-3", {})
    hour_ago = time.time() - 7200
    os.utime(stale, (hour_ago, hour_ago))
    (tmp_path / "kept" / "broken.json").write_text("not json")
    records.pending("stage-4", {})  # writing purges what is past its window, and leftovers
    odd = hashlib.sha256(b"plan/odd id").hexdigest()
    assert {p.name for p in (tmp_path / "kept").iterdir()} == {".stage-4.json", f"{odd}.json"}
    with pytest.raises(ValueError, match="read as a parameter"):
        template_literal({"note": ":name"})
    digests = change_digests(
        b"k" * 32, [Change(kind="t", id="1", before=None, after={"v": Decimal("1.50")})]
    )
    assert digests[0][3] is not None


def test_sql_says_what_it_cannot_put_back(tmp_path: Path) -> None:
    from interlock.substrate import sql_inverse

    table = TableSpec("orders", columns=["id", "total"])
    with pytest.raises(UndoError, match="no table observed here"):
        sql_inverse("sqlite", kept(Change(kind="other", id="1", before=None, after={})), {})
    db = tmp_path / "app.db"
    db.write_bytes(b"")
    assert SqliteSubstrate(str(db), tables=[table]).kept("p") is None  # keeps no undo
    assert SqliteSubstrate(str(db), tables=[table], undo=WEEK).kept("p") is None  # no table yet


def test_a_directory_says_what_it_cannot_write_back(tmp_path: Path) -> None:
    from interlock.filesystem import FilesystemSubstrate, _entry
    from tests.test_filesystem import make_workspace

    root = make_workspace(tmp_path / "billing")
    sub = FilesystemSubstrate(root, undo=WEEK)
    found = _entry(root / "docs/runbook.md")
    assert found is not None
    now = {"sha256": found.sha256, "mode": found.mode, "bytes": found.size}

    def change(before: dict[str, Any]) -> Change:
        return Change(kind="docs", id="docs/runbook.md", before=before, after=now)

    blobs = {"blobs": str(tmp_path / "nowhere")}
    with pytest.raises(UndoError, match="symbolic link"):
        sub.inverse(kept(change({**now, "mode": "link"}), payload=blobs))
    with pytest.raises(UndoError, match="mode 664"):
        sub.inverse(kept(change({**now, "mode": "664"}), payload=blobs))
    with pytest.raises(UndoError, match="cannot be read"):
        sub.inverse(kept(change({**now, "sha256": "0" * 64}), payload=blobs))
    moved = Change(kind="docs", id="docs/runbook.md", before=now, after={**now, "bytes": 1})
    assert sub.inverse(kept(moved, payload=blobs)) == []  # not as left: no statement for it
    # kept records that lapsed, that cannot be read, and a stage's leftovers
    undo = sub.state / "undo"
    (undo / "lapsed").mkdir(parents=True)
    (undo / "lapsed" / "kept.json").write_text(
        json.dumps({"expires_at": (NOW - WEEK).isoformat(), "committed_at": NOW.isoformat()})
    )
    (undo / "broken").mkdir()
    (undo / "broken" / "kept.json").write_text("not json")
    assert sub.kept("lapsed") is None and sub.kept("broken") is None
    stale = undo / ".stage-left"
    stale.mkdir()
    hour_ago = time.time() - 7200
    os.utime(stale, (hour_ago, hour_ago))
    sub._purge_undo(undo)
    assert sorted(p.name for p in undo.iterdir()) == ["broken"]
    assert FilesystemSubstrate(root).kept("anything") is None


def test_git_says_what_it_cannot_write_back(tmp_path: Path) -> None:
    from tests.test_git_substrate import Repo, git
    from tests.test_git_substrate import substrate as git_substrate

    repo = Repo(tmp_path)
    sub = git_substrate(repo, hooks=(), undo=WEEK)
    blob, mode = sub._at_head("README.md") or ("", "")
    now = {"blob_sha": blob, "mode": mode}
    binary = (
        subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],  # noqa: S607 - git, as the tests run it
            cwd=repo.origin,
            input=b"\xff\xfe\x00binary",
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    with pytest.raises(UndoError, match="a link or a submodule"):
        sub.inverse(
            kept(Change(kind="docs", id="README.md", before={**now, "mode": "120000"}, after=now))
        )
    with pytest.raises(UndoError, match="not UTF-8 text"):
        sub.inverse(
            kept(Change(kind="docs", id="README.md", before={**now, "blob_sha": binary}, after=now))
        )
    exe = Change(kind="docs", id="README.md", before={**now, "mode": "100755"}, after=now)
    (statement,) = [e.statement for e in sub.inverse(kept(exe))]
    assert statement == "mode :path :mode"
    directory = Path(sub._common) / "interlock" / "undo"
    directory.mkdir(parents=True)
    (directory / "lapsed.json").write_text(json.dumps({"expires_at": (NOW - WEEK).isoformat()}))
    (directory / "broken.json").write_text("not json")
    assert sub.kept("lapsed") is None and sub.kept("broken") is None
    assert git_substrate(repo, hooks=()).kept("anything") is None
    assert git(repo.origin, "rev-parse", "main")


def test_a_rest_api_says_what_it_cannot_write_back(
    server: LoopbackRestServer,  # noqa: F811 - the fixture imported above
    tmp_path: Path,
) -> None:
    from interlock.rest import FINGERPRINT, fingerprint
    from tests.test_rest import substrate as rest_substrate
    from tests.test_rest import ticket

    sub = rest_substrate(server, tmp_path, undo=WEEK)
    kind = sub._types["tickets"]
    now = ticket(server, 1)
    after = {FINGERPRINT: fingerprint(now, kind.ignored)}

    def change(ident: str = "tkt-1", table: str = "tickets") -> Change:
        return Change(kind=table, id=ident, before={"x": 1}, after=after)

    with pytest.raises(UndoError, match="no resource type"):
        sub.inverse(kept(change(table="other"), payload={"bodies": {}}))
    gone = kept(change("tkt-404"), payload={"bodies": {}})
    assert sub.inverse(gone) == []
    with pytest.raises(UndoError, match="null field"):
        sub.inverse(kept(change(), payload={"bodies": {"tickets/tkt-1": {**now, "note": None}}}))
    with pytest.raises(UndoError, match="read as a parameter"):
        sub.inverse(
            kept(change(), payload={"bodies": {"tickets/tkt-1": {**now, "status": ":open"}}})
        )
    assert rest_substrate(server, tmp_path / "plain").kept("anything") is None


def test_a_fhir_server_says_what_it_cannot_write_back(
    fhir_server: LoopbackFhirServer,  # noqa: F811 - the fixture imported above
    tmp_path: Path,
) -> None:
    from interlock.fhir import FINGERPRINT, fingerprint
    from tests.test_fhir import substrate as fhir_substrate

    sub = fhir_substrate(fhir_server, tmp_path, undo=WEEK)
    now = fhir_server.get("MedicationRequest", "1")
    assert now is not None
    after = {FINGERPRINT: fingerprint(now)}

    def change(ident: str = "1", table: str = "medicationrequests") -> Change:
        return Change(kind=table, id=ident, before={"x": 1}, after=after)

    with pytest.raises(UndoError, match="no resource type"):
        sub.inverse(kept(change(table="other"), payload={"bodies": {}}))
    assert sub.inverse(kept(change("404"), payload={"bodies": {}})) == []
    body = "medicationrequests/1"
    with pytest.raises(UndoError, match="null field"):
        sub.inverse(kept(change(), payload={"bodies": {body: {**now, "note": None}}}))
    with pytest.raises(UndoError, match="read as a parameter"):
        sub.inverse(kept(change(), payload={"bodies": {body: {**now, "status": ":active"}}}))
    assert fhir_substrate(fhir_server, tmp_path / "plain").kept("anything") is None
