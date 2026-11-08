"""The edges of the directory and REST substrates (1.5.0): what each refuses, and each path a
stage takes that the scenario tests do not."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import EscrowEngine, PlanBuilder
from interlock.exceptions import (
    CompensatedError,
    InboundFactError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
)
from interlock.filesystem import FilesystemSubstrate, prepare_swap
from interlock.git_substrate import GitHook
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.rest import RestResource, RestSubstrate, merge_diff
from interlock.sim.rest import Collection, LoopbackRestServer, field_value
from interlock.sqlite_outbox import install_sqlite_outbox
from interlock.text import noun, tally
from interlock.types import Compensation, EffectKind
from interlock.windows import RateWindow, RowSum

# -- the words ---------------------------------------------------------------------------


def test_counts_take_the_form_their_number_takes() -> None:
    assert [tally(n, "row") for n in (0, 1, 2)] == ["0 rows", "1 row", "2 rows"]
    assert tally(2, "discrepancy") == "2 discrepancies" and tally(3, "key") == "3 keys"
    assert tally(2, "match") == "2 matches" and tally(2, "child") == "2 children"
    assert noun("1", "file") == "file" and noun("10-99", "file") == "files"
    assert tally(2, "datum", "data") == "2 data"


# -- the directory --------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "svc"
    (root / "config").mkdir(parents=True)
    (root / "config/app.toml").write_text("timeout_ms = 2500\n")
    (root / "docs").mkdir()
    (root / "docs/a.md").write_text("# a\n")
    return root


def edit(statement: str, **parameters: str) -> Any:
    return PlanBuilder("agent").update(table="config", statement=statement, parameters=parameters)


def test_a_workspace_too_big_to_copy_is_refused(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace, max_files=1)
    with pytest.raises(SubstrateConfigurationError, match="past what a stage copies"):
        sub.open(edit("write 'x' 'y'").build())


def test_a_file_too_big_to_write_is_refused(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace, max_file_bytes=4)
    with pytest.raises(StageError, match="past the 4 a stage writes"):
        EscrowEngine(sub, checkers=[]).execute(edit("write 'docs/b.md' 'too long'").build())


def test_a_replace_in_binary_text_and_a_mode_on_nothing(workspace: Path) -> None:
    (workspace / "docs/blob.bin").write_bytes(b"\xff\xfe\x00")
    sub = FilesystemSubstrate(workspace)
    with pytest.raises(StageError, match="not UTF-8"):
        EscrowEngine(sub, checkers=[]).execute(edit("replace 'docs/blob.bin' 'a' 'b'").build())
    result = EscrowEngine(sub, checkers=[]).execute(edit("append 'docs/new.md' 'hi'").build())
    assert result.committed and (workspace / "docs/new.md").read_text() == "hi"


def test_a_special_file_in_the_workspace_is_refused(workspace: Path) -> None:
    os.mkfifo(workspace / "pipe")
    sub = FilesystemSubstrate(workspace)
    with pytest.raises(StageError, match="neither a file nor a symbolic link"):
        sub.files()
    with pytest.raises(StageError, match="neither a file nor a symbolic link"):
        sub.open(edit("write 'x' 'y'").build())
    (workspace / "pipe").unlink()
    short_base = "/tmp" if Path("/tmp").is_dir() else None  # noqa: S108 - AF_UNIX sun_path cap
    with tempfile.TemporaryDirectory(dir=short_base) as raw:
        short_ws = Path(raw) / "svc"
        short_ws.mkdir()
        (short_ws / "a.txt").write_text("ok\n")
        with closing(socket.socket(socket.AF_UNIX)) as sock:
            sock.bind(str(short_ws / "sock"))
            sock_sub = FilesystemSubstrate(short_ws)
            with pytest.raises(StageError, match="neither a file nor a symbolic link"):
                sock_sub.open(edit("write 'x' 'y'").build())


def test_a_link_in_the_workspace_is_measured_and_may_be_deleted(workspace: Path) -> None:
    (workspace / "current").symlink_to("config/app.toml")
    sub = FilesystemSubstrate(workspace)
    assert "current" in sub.files()
    result = EscrowEngine(sub, checkers=[]).execute(
        PlanBuilder("agent").delete(table="other", statement="delete 'current'").build()
    )
    assert result.committed and not (workspace / "current").is_symlink()
    assert result.diff is not None and result.diff.deltas[0].before is not None
    assert result.diff.deltas[0].before["mode"] == "link"


def test_a_hook_that_fails_or_hangs_fails_the_stage(workspace: Path) -> None:
    failing = GitHook("fail", (sys.executable, "-c", "import sys; sys.exit(3)"))
    with pytest.raises(StageError, match="hook fail failed"):
        EscrowEngine(FilesystemSubstrate(workspace, hooks=(failing,)), checkers=[]).execute(
            edit("write 'docs/b.md' 'x'").build()
        )
    slow = GitHook("slow", (sys.executable, "-c", "import time; time.sleep(5)"), timeout=0.2)
    with pytest.raises(StageError, match="ran past"):
        EscrowEngine(FilesystemSubstrate(workspace, hooks=(slow,)), checkers=[]).execute(
            edit("write 'docs/b.md' 'x'").build()
        )
    missing = GitHook("gone", ("/no/such/program",))
    with pytest.raises(StageError, match="could not run"):
        EscrowEngine(FilesystemSubstrate(workspace, hooks=(missing,)), checkers=[]).execute(
            edit("write 'docs/b.md' 'x'").build()
        )
    with pytest.raises(SubstrateConfigurationError, match="named once each"):
        FilesystemSubstrate(workspace, hooks=(failing, failing))


def test_a_stage_that_outlives_its_bound_commits_nothing(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace, max_stage_seconds=0.01)
    plan = edit("write 'docs/b.md' 'x'").build()
    handle = sub.open(plan)
    try:
        import time

        time.sleep(0.05)
        with pytest.raises(StageExpiredError):
            sub.apply(handle, plan.effects[0])
    finally:
        sub.close(handle)
    with pytest.raises(StageError, match="not open"):
        sub.diff(handle)


def test_a_commit_before_a_measure_is_refused(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = edit("write 'docs/b.md' 'x'").build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        with pytest.raises(StageError, match="before it is measured"):
            sub.commit(handle)
    finally:
        sub.close(handle)


def test_without_a_control_database_no_facts_and_no_windows(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = edit("write 'docs/b.md' 'x'").build()
    assert sub.pending_facts("agent") == () and sub.held_operations() == {}
    assert sub.control is None and sub.version() is None
    handle = sub.open(plan)
    try:
        with pytest.raises(InboundFactError):
            sub.consume_facts(handle, [], "agent")
        with pytest.raises(SubstrateConfigurationError, match="control database"):
            sub.measure_windows(handle, [])
        with pytest.raises(OutboundRequestError, match="no control database"):
            sub.apply(
                handle,
                PlanBuilder("agent")
                .enqueue(sink="notify", operation="send", payload={})
                .build()
                .effects[0],
            )
    finally:
        sub.close(handle)


NOTIFY = SinkSpec("notify", (OperationSpec("send"),), cost_per_call=Decimal("0"))


def test_windows_and_savepoints_with_a_control_database(workspace: Path, tmp_path: Path) -> None:
    control = tmp_path / "control.db"
    install_sqlite_outbox(control, (NOTIFY,), ())
    sub = FilesystemSubstrate(workspace, control=control)
    lines = RowSum("config", "lines_added", rows="net")
    window = RateWindow("lines", timedelta(hours=1), Decimal(100), lines)
    engine = EscrowEngine(sub, checkers=[], windows=[window], sinks=SinkRegistry((NOTIFY,)))
    result = engine.execute(
        edit("replace 'config/app.toml' '2500' '4000'")
        .enqueue(sink="notify", operation="send", payload={"to": "ops"})
        .build()
    )
    assert result.committed and result.diff is not None and result.diff.windows
    assert sub.resolve_intent(result.diff.stage_id) is True
    plan = edit("write 'docs/b.md' 'x'").build()
    handle = sub.open(plan)
    try:
        sub.savepoint(handle, "first")
        sub.apply(handle, plan.effects[0])
        sub.rollback_to(handle, "first")
        assert not sub.diff(handle).deltas
        sub.release_savepoint(handle, "first")
    finally:
        sub.close(handle)
    with closing(sqlite3.connect(control)) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone()[0] == 1


def test_swap_needs_a_link_and_one_file_system(workspace: Path, tmp_path: Path) -> None:
    plain = tmp_path / "plain.txt"
    plain.write_text("x")
    with pytest.raises(SubstrateConfigurationError, match="not a directory"):
        prepare_swap(plain)
    first = prepare_swap(workspace, versions=tmp_path / "vs")
    assert first.parent == tmp_path / "vs"
    (tmp_path / "vs2" / "v0-initial").mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(SubstrateConfigurationError, match="already exists"):
        prepare_swap(other, versions=tmp_path / "vs2")
    sub = FilesystemSubstrate(workspace, mode="swap", versions=tmp_path / "vs")
    assert sub.mode == "swap" and sub.root == workspace.absolute() and sub.version() == "v0-initial"
    assert set(sub.files()) == {"config/app.toml", "docs/a.md"}


def test_a_journal_from_a_crash_in_swap_mode_is_settled(workspace: Path) -> None:
    prepare_swap(workspace)
    sub = FilesystemSubstrate(workspace, mode="swap")
    plan = edit("write 'docs/b.md' 'x'").build()
    handle = sub.open(plan)
    sub.apply(handle, plan.effects[0])
    sub.diff(handle)
    stage = sub._stage
    assert stage is not None
    sub._write_journal(stage, [], None, version=f"v-{handle.stage_id}")
    # the process dies before the rename: nothing committed
    fresh = FilesystemSubstrate(workspace, mode="swap")
    assert fresh.resolve_intent(handle.stage_id) is False
    assert not (workspace / "docs/b.md").exists()


def test_an_in_place_commit_onto_a_path_turned_into_a_link_is_refused(
    workspace: Path, tmp_path: Path
) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = edit("write 'docs/sub/b.md' 'x'").build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        sub.diff(handle)
        outside = tmp_path / "outside"
        outside.mkdir()
        (workspace / "docs/sub").symlink_to(outside, target_is_directory=True)
        with pytest.raises(StageConflictError):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert list((tmp_path / "outside").iterdir()) == []


# -- the REST API --------------------------------------------------------------------------

TICKETS = RestResource(
    "tickets",
    "/tickets",
    columns={"status": "status"},
    tenant="account_id",
    managed=("updated_at", "updated_by", "version"),
    source="last_request",
)


@pytest.fixture
def api() -> Iterator[LoopbackRestServer]:
    server = LoopbackRestServer(
        (Collection("tickets", filters=("account_id",)), Collection("notes")),
        tokens={"t": "agent"},
        require_if_match=True,
    )
    server.start()
    server.seed("tickets", {"id": "t1", "account_id": "a", "status": "open"})
    server.seed("notes", {"id": "n1", "text": "hello"})
    yield server
    server.stop()


def call(
    server: LoopbackRestServer, method: str, path: str, body: Any = None, **headers: str
) -> tuple[int, Any]:
    data = (
        None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    )
    request = urllib.request.Request(server.url + path, data=data, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:  # noqa: S310
            raw = reply.read()
            return reply.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def test_the_loopback_api_follows_rest_conventions(api: LoopbackRestServer) -> None:
    auth = {"Authorization": "Bearer t"}
    assert call(api, "GET", "/tickets/t1")[0] == 401
    status, body = call(api, "POST", "/tickets", {"account_id": "a", "status": "new"}, **auth)
    assert status == 201 and body["version"] == 1
    assert call(api, "POST", "/tickets/x", {}, **auth)[0] == 405
    assert call(api, "PATCH", "/tickets", {}, **auth)[0] == 405
    assert call(api, "PATCH", "/tickets/t1", {"status": "x"}, **auth)[0] == 428
    assert (
        call(api, "PATCH", "/tickets/t1", {"status": "x"}, **{**auth, "If-Match": '"9"'})[0] == 412
    )
    assert call(api, "PATCH", "/tickets/t1", b"{nope", **{**auth, "If-Match": '"1"'})[0] == 400
    assert call(api, "PATCH", "/tickets/t1", [1], **{**auth, "If-Match": '"1"'})[0] == 400
    assert call(api, "PATCH", "/tickets/zz", {}, **{**auth, "If-Match": "*"})[0] == 412
    assert call(api, "PUT", "/tickets/t1", {"id": "t2"}, **{**auth, "If-Match": '"1"'})[0] == 400
    stale = call(
        api, "PUT", "/tickets/t1", {"version": 7, "status": "x"}, **{**auth, "If-Match": '"1"'}
    )
    assert stale[0] == 409
    assert (
        call(api, "PUT", "/tickets/t1", {"status": "x"}, **{**auth, "If-None-Match": "*"})[0] == 412
    )
    assert (
        call(api, "PUT", "/tickets/t9", {"account_id": "a"}, **{**auth, "If-None-Match": "*"})[0]
        == 201
    )
    assert call(api, "DELETE", "/tickets", **auth)[0] == 405
    assert call(api, "DELETE", "/tickets/t9", **{**auth, "If-Match": '"1"'})[0] == 204
    assert call(api, "DELETE", "/tickets/t9", **{**auth, "If-Match": "*"})[0] == 412
    assert call(api, "GET", "/tickets/t9", **auth)[0] == 404
    assert call(api, "GET", "/tickets?colour=red", **auth)[0] == 400
    assert call(api, "GET", "/nothing", **auth)[0] == 404
    api.fail_next("notes", "n1", 503)
    assert call(api, "PATCH", "/notes/n1", {"text": "x"}, **{**auth, "If-Match": '"1"'})[0] == 503
    assert api.history("tickets", "t1")[0]["version"] == 1
    assert field_value({"a": [{"b": 2}]}, "a.0.b") == 2 and field_value({}, "a.b") is None
    log = [json.loads(line) for line in api.audit_log().splitlines()]
    assert {e["status"] for e in log} >= {201, 412, 409, 204}


def substrate(api: LoopbackRestServer, tmp_path: Path, **kwargs: Any) -> RestSubstrate:
    kwargs.setdefault("resources", (TICKETS,))
    return RestSubstrate(api.url, journal=tmp_path / "j", token="t", **kwargs)


def patch_plan(ticket: str, change: dict[str, Any], *, tenant: str = "a") -> Any:
    return (
        PlanBuilder("agent")
        .add(
            EffectKind.UPDATE,
            table="rest:tickets",
            statement="patch tickets :id '" + json.dumps(change) + "'",
            parameters={"id": ticket},
            tenant_id=tenant,
            compensation=Compensation("restore tickets"),
        )
        .build()
    )


def test_a_whole_resource_write_and_a_delete_as_a_creates_undo(
    api: LoopbackRestServer, tmp_path: Path
) -> None:
    put = RestResource(
        "tickets",
        "/tickets",
        columns={"status": "status"},
        tenant="account_id",
        managed=TICKETS.managed,
        source="last_request",
        write="put",
    )
    sub = substrate(api, tmp_path, resources=(put,))
    assert EscrowEngine(sub, checkers=[]).execute(patch_plan("t1", {"status": "pending"})).committed
    created = (
        PlanBuilder("agent")
        .add(
            EffectKind.INSERT,
            table="rest:tickets",
            statement='create tickets \'{"account_id": "a", "status": "new"}\'',
            parameters={},
            tenant_id="a",
            compensation=Compensation("void tickets"),
        )
        .build()
    )

    class Forced(RestSubstrate):
        def _discrepancies(self, stage: Any) -> list[str]:
            return ["forced"]

    forced = Forced(api.url, resources=(put,), journal=tmp_path / "j2", token="t")
    with pytest.raises(CompensatedError):
        EscrowEngine(forced, checkers=[]).execute(created)
    assert [t["status"] for t in api.find("tickets", account_id="a")] == ["pending"]


def test_the_rest_substrate_reports_what_it_is(api: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(api, tmp_path)
    assert sub.server == api.url and sub.control is None and sub.held_operations() == {}
    assert [s.name for s in sub.table_specs] == ["tickets"] and sub.pending_facts("x") == ()
    plan = patch_plan("t1", {"status": "x"})
    handle = sub.open(plan)
    try:
        with pytest.raises(StageConflictError, match="already has stage"):
            sub.open(plan)
        with pytest.raises(InboundFactError):
            sub.consume_facts(handle, [], "agent")
        with pytest.raises(SubstrateConfigurationError):
            sub.measure_windows(handle, [])
        assert sub.transaction_id(handle) is None
        sub.apply(handle, plan.effects[0])
        assert sub.transaction_id(handle) == f"rest:{handle.stage_id}"
        sub.savepoint(handle, "s")
        sub.rollback_to(handle, "s")
        sub.release_savepoint(handle, "s")
        with pytest.raises(StageError, match="no savepoint"):
            sub.rollback_to(handle, "s")
        with pytest.raises(ValueError, match="unsafe"):
            sub.savepoint(handle, "1x")
        with pytest.raises(StageError, match="undo written first"):
            sub.diff(handle)
            sub.commit(handle)
    finally:
        sub.close(handle)


@pytest.mark.parametrize(
    ("statement", "parameters", "why"),
    [
        ("create tickets '[1]'", {}, "a JSON object"),
        ("patch tickets :id '[1]'", {"id": "t1"}, "a JSON merge patch"),
        ("patch tickets :id '{}'", {"id": True}, "text or a whole number"),
        ('patch tickets :id \'{"a": ":x"}\' :x', {"id": "t1"}, "not bound"),
        ("expect-version tickets :id :v", {"id": "t1"}, "not bound"),
    ],
)
def test_more_that_the_rest_substrate_refuses(
    api: LoopbackRestServer, tmp_path: Path, statement: str, parameters: dict[str, Any], why: str
) -> None:
    undo = "void tickets" if statement.startswith("create") else "restore tickets"
    plan = (
        PlanBuilder("agent")
        .add(
            EffectKind.UPDATE,
            table="rest:tickets",
            statement=statement,
            parameters=parameters,
            tenant_id="a",
            compensation=Compensation(undo),
        )
        .build()
    )
    found = substrate(api, tmp_path).reject_reason(plan.effects[0])
    assert found is not None and why in found


def test_a_missing_resource_and_an_unreadable_api(api: LoopbackRestServer, tmp_path: Path) -> None:
    sub = substrate(api, tmp_path)
    with pytest.raises(StageError, match="there is no tickets/zz"):
        EscrowEngine(sub, checkers=[]).execute(patch_plan("zz", {"status": "x"}))
    bad = RestResource("tickets", "/tickets", tenant="account_id", items="results")
    with pytest.raises(StageError, match="holds no 'results'"):
        EscrowEngine(substrate(api, tmp_path, resources=(bad,)), checkers=[]).execute(
            patch_plan("t1", {"status": "x"})
        )
    assert merge_diff([1], {"a": 1}) == {"a": 1}
    gone = RestSubstrate("http://127.0.0.1:9/api", resources=(TICKETS,), journal=tmp_path / "g")
    with pytest.raises(Exception, match="cannot reach"):
        EscrowEngine(gone, checkers=[]).execute(patch_plan("t1", {"status": "x"}))
    with pytest.raises(SubstrateConfigurationError, match="not a header name"):
        RestSubstrate(api.url, resources=(TICKETS,), journal=tmp_path, request_header="X Bad")
    assert os.environ.get("NO_SUCH_VARIABLE_FOR_INTERLOCK") is None
