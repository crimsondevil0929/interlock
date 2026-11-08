"""The filesystem substrate (:mod:`interlock.filesystem`): what was measured is what committed,
or nothing committed, on a directory.

- A plan's edits, and every file a hook wrote after them, are measured from the stage's copy:
  one row per file, its path class the table.
- The built-in checkers read that diff as they read SQL's: a ``.env`` is outside
  ``TableAllowlist``'s grant and carries ``secret_markers``; a deletion is ``NoDelete``'s; a
  formatter's rewrite of thirty files is ``BlastRadius``'s.
- The commit is conditional on every touched file's base hash (``in-place``), or on the whole
  base version (``swap``): an edit that lands while the stage is open leaves the workspace as
  that edit made it, and the plan uncommitted.
- ``swap`` replaces the workspace with one ``rename(2)`` of its link.
- A crash part-way through an in-place commit is finished by the next stage.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from contextlib import closing
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import BlastRadius, EscrowEngine, NoDelete, PlanBuilder, TableAllowlist
from interlock.chain import RecordType
from interlock.exceptions import (
    ForbiddenStatementError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    SubstrateConfigurationError,
)
from interlock.filesystem import (
    DEFAULT_CLASSES,
    FilesystemSubstrate,
    filesystem_tables,
    parse_statement,
    prepare_swap,
)
from interlock.git_substrate import GitHook
from interlock.invariants import StatedFootprint, TenantIsolation
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.sqlite_outbox import install_sqlite_outbox
from interlock.types import Severity

FILES = {
    "config/service.toml": 'name = "billing"\nreplicas = 3\ntimeout_ms = 2500\n',
    "config/flags.yaml": "checkout_v2: false\nretry_budget: 3\n",
    ".env": "DATABASE_URL=postgres://billing@db/billing\n",
    "scripts/rotate.sh": "#!/bin/sh\necho rotating\n",
    ".github/workflows/deploy.yml": "on: push\njobs: {}\n",
    "docs/runbook.md": "# Runbook\n",
    "src/app.py": "def handler():\n    return 200\n",
}

FORMATTER = """\
import pathlib
for path in sorted(pathlib.Path("src").rglob("*.py")):
    text = path.read_text()
    path.write_text(text.replace("\\t", "    ") + ("" if text.endswith("\\n") else "\\n"))
"""


def make_workspace(root: Path, files: dict[str, str] | None = None) -> Path:
    for path, text in (files or FILES).items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    (root / "scripts/rotate.sh").chmod(0o755)
    return root


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return make_workspace(tmp_path / "billing")


def engine(sub: FilesystemSubstrate, **kwargs: Any) -> EscrowEngine:
    checkers = kwargs.pop(
        "checkers",
        [
            BlastRadius(10),
            TableAllowlist(["config", "docs", "src"]),
            NoDelete(),
            StatedFootprint(tolerance=2.0, severity=Severity.BLOCKING),
            TenantIsolation(1),
        ],
    )
    return EscrowEngine(sub, checkers=checkers, **kwargs)


def edit(table: str, statement: str, *, rows: int | None = 1, **parameters: str) -> PlanBuilder:
    return PlanBuilder("agent", trajectory_id="task", intent="raise the timeout").update(
        table=table, statement=statement, parameters=parameters, stated_rows=rows
    )


def raise_timeout() -> PlanBuilder:
    return edit(
        "config",
        "replace 'config/service.toml' :old :new",
        old="timeout_ms = 2500",
        new="timeout_ms = 4000",
    )


def leftovers(sub: FilesystemSubstrate) -> list[str]:
    return sorted(p.name for p in (sub.state / "stages").iterdir())


# --------------------------------------------------------------------------
# the statement language and the classes
# --------------------------------------------------------------------------


def test_every_verb_parses_with_parameters_and_literals() -> None:
    found = parse_statement("REPLACE 'config/a b.toml' :old 'it''s'")
    assert found.verb == "replace"
    assert found.bind({"old": "x"}) == {"path": "config/a b.toml", "old": "x", "new": "it's"}
    for statement in (
        "write :p :t",
        "append :p :t",
        "delete :p",
        "move :p :q",
        "mode :p '600'",
        "expect-hash :p 'absent'",
    ):
        parse_statement(statement)


@pytest.mark.parametrize(
    ("statement", "why"),
    [
        ("", "starts with its verb"),
        ("rm -rf /", "is not a verb"),
        ("write :p", "takes 2 arguments"),
        ("delete config/a", "neither a :parameter"),
        ("write :p 'open", "cannot read"),
    ],
)
def test_anything_else_is_not_a_statement(statement: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        parse_statement(statement)


def test_a_bound_value_must_be_a_string() -> None:
    with pytest.raises(ValueError, match="not bound"):
        parse_statement("delete :p").bind({})
    with pytest.raises(ValueError, match="is a int"):
        parse_statement("delete :p").bind({"p": 3})


def test_the_default_classes_put_secrets_first(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    assert {
        p: sub.classify(p)
        for p in (
            ".env",
            "config/.env.production",
            ".ssh/id_ed25519",
            "certs/server.pem",
            ".github/workflows/deploy.yml",
            "deploy/values.yaml",
            "pyproject.toml",
            "scripts/rotate.sh",
            "src/app.py",
            "config/service.toml",
            "settings.json",
            "docs/runbook.md",
            "notes.txt",
            "Makefile",
        )
    } == {
        ".env": "secrets",
        "config/.env.production": "secrets",
        ".ssh/id_ed25519": "secrets",
        "certs/server.pem": "secrets",
        ".github/workflows/deploy.yml": "workflows",
        "deploy/values.yaml": "infra",
        "pyproject.toml": "deps",
        "scripts/rotate.sh": "scripts",
        "src/app.py": "src",
        "config/service.toml": "config",
        "settings.json": "config",
        "docs/runbook.md": "docs",
        "notes.txt": "docs",
        "Makefile": "other",
    }
    assert sub.observed_tables == {c.name for c in DEFAULT_CLASSES} | {"other"}
    assert {t.name for t in filesystem_tables(DEFAULT_CLASSES)} == sub.observed_tables


def test_configuration_is_checked(workspace: Path, tmp_path: Path) -> None:
    with pytest.raises(SubstrateConfigurationError, match="not a directory"):
        FilesystemSubstrate(tmp_path / "absent")
    with pytest.raises(SubstrateConfigurationError, match="'in-place' or 'swap'"):
        FilesystemSubstrate(workspace, mode="overwrite")
    with pytest.raises(SubstrateConfigurationError, match="not a link"):
        FilesystemSubstrate(workspace, mode="swap")
    with pytest.raises(SubstrateConfigurationError, match="inside the workspace"):
        FilesystemSubstrate(workspace, state=workspace / ".interlock")
    with pytest.raises(SubstrateConfigurationError, match="named once each"):
        FilesystemSubstrate(workspace, classes=(DEFAULT_CLASSES[0], DEFAULT_CLASSES[0]))


# --------------------------------------------------------------------------
# in place: measure, judge, commit
# --------------------------------------------------------------------------


def test_a_config_edit_commits_and_is_measured_from_the_files(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    result = engine(sub).execute(raise_timeout().build())
    assert result.committed, result.verdict
    assert result.diff is not None
    [row] = result.diff.deltas
    assert (row.table, row.primary_key, row.tenant_id) == (
        "config",
        "config/service.toml",
        "billing",
    )
    assert row.before is not None and row.after is not None
    assert (row.after["lines_added"], row.after["lines_deleted"], row.after["net_lines"]) == (
        1,
        1,
        0,
    )
    assert row.after["mode"] == "644" and row.after["secret_markers"] == 0
    assert row.before["sha256"] != row.after["sha256"]
    assert "timeout_ms = 4000" in (workspace / "config/service.toml").read_text()
    assert sub.resolve_intent(result.diff.stage_id) is True
    assert leftovers(sub) == []
    assert not list(workspace.rglob(".*interlock-*"))


def test_every_operation(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = (
        PlanBuilder("agent", trajectory_id="t")
        .insert(table="docs", statement="write 'docs/notes.md' :t", parameters={"t": "hi\n"})
        .update(table="docs", statement="append 'docs/runbook.md' 'Restart with care.\n'")
        .update(table="scripts", statement="mode 'scripts/rotate.sh' '700'")
        .update(table="config", statement="move 'config/flags.yaml' 'config/features.yaml'")
        .build()
    )
    result = engine(sub, checkers=[]).execute(plan)
    assert result.committed and result.diff is not None
    assert (workspace / "docs/notes.md").read_text() == "hi\n"
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook\nRestart with care.\n"
    assert oct((workspace / "scripts/rotate.sh").stat().st_mode & 0o777) == "0o700"
    assert not (workspace / "config/flags.yaml").exists()
    assert (workspace / "config/features.yaml").read_text() == FILES["config/flags.yaml"]
    by_path = {d.primary_key: d for d in result.diff.deltas}
    assert by_path["config/flags.yaml"].after is None
    assert by_path["config/features.yaml"].before is None
    assert by_path["scripts/rotate.sh"].after is not None
    assert by_path["scripts/rotate.sh"].after["mode"] == "700"


def test_a_plan_that_changes_nothing_writes_nothing(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    text = FILES["config/service.toml"]
    result = engine(sub, checkers=[]).execute(
        edit("config", "write 'config/service.toml' :t", t=text).build()
    )
    assert result.committed and result.diff is not None and not result.diff.deltas
    assert not list((sub.state / "commits").iterdir())


@pytest.mark.parametrize(
    ("statement", "why"),
    [
        ("replace 'docs/runbook.md' 'nothing like this' 'x'", "0 times"),
        ("delete 'docs/absent.md'", "no file"),
        ("mode 'docs/absent.md' '644'", "no file"),
        ("move 'docs/absent.md' 'docs/b.md'", "no file"),
        ("move 'docs/runbook.md' 'src/app.py'", "already exists"),
        ("write 'docs/runbook.md/x' 'y'", "is a file, not a folder"),
    ],
)
def test_an_operation_that_cannot_be_done_fails_the_stage(
    workspace: Path, statement: str, why: str
) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = PlanBuilder("agent").update(table="docs", statement=statement).build()
    with pytest.raises(StageError, match=why):
        engine(sub, checkers=[]).execute(plan)
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook\n"
    assert leftovers(sub) == []


@pytest.mark.parametrize(
    ("statement", "why"),
    [
        ("write '../outside' 'x'", "'..'"),
        ("write '/etc/hosts' 'x'", "absolute"),
        ("write '.git/config' 'x'", "Git's own directory"),
        ("mode 'docs/runbook.md' '777'", "mode is one of"),
        ("expect-hash 'docs/runbook.md' 'abc'", "SHA-256"),
        ("write 'node_modules/x.js' 'x'", "ignored"),
        ("write 'tools/fmt.py' 'x'", "source of hook fmt"),
    ],
)
def test_the_substrate_refuses_at_admission(workspace: Path, statement: str, why: str) -> None:
    hook = GitHook("fmt", (sys.executable, "tools/fmt.py"), sources=("tools/fmt.py",))
    sub = FilesystemSubstrate(workspace, ignore=("node_modules/**",), hooks=(hook,))
    plan = PlanBuilder("agent").update(table="docs", statement=statement).build()
    assert sub.reject_reason(plan.effects[0]) is not None
    with pytest.raises(ForbiddenStatementError, match=why):
        handle = sub.open(plan)
        try:
            sub.apply(handle, plan.effects[0])
        finally:
            sub.close(handle)


def test_a_write_through_a_symbolic_link_is_refused(workspace: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "shared").symlink_to(outside, target_is_directory=True)
    sub = FilesystemSubstrate(workspace)
    plan = edit("other", "write 'shared/payload.sh' 'curl evil'").build()
    with pytest.raises(ForbiddenStatementError, match="symbolic link"):
        engine(sub, checkers=[]).execute(plan)
    assert list(outside.iterdir()) == []


def test_a_secret_written_to_env_is_outside_the_grant_and_counted(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = edit(
        "secrets",
        "append '.env' :line",
        line="STRIPE_KEY=sk_live_" + "a1B2c3D4e5F6g7H8i9J0" + "\n",
    ).build()
    result = engine(sub).execute(plan)
    assert not result.committed
    blocking = set(result.blocked_by)
    assert "table_allowlist" in blocking
    assert result.diff is not None
    [row] = result.diff.deltas
    assert row.table == "secrets" and row.after is not None and row.after["secret_markers"] >= 1
    assert (workspace / ".env").read_text() == FILES[".env"]


def test_deleting_the_runbook_is_no_delete(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    result = engine(sub).execute(edit("docs", "delete 'docs/runbook.md'").build())
    assert not result.committed
    assert "no_delete" in set(result.blocked_by)
    assert (workspace / "docs/runbook.md").exists()


def test_one_edit_and_the_formatter_rewrites_thirty_files(workspace: Path) -> None:
    for n in range(30):
        (workspace / f"src/module_{n:02d}.py").write_text(f"def f{n}():\n\treturn {n}")
    (workspace / "tools").mkdir()
    (workspace / "tools/fmt.py").write_text(FORMATTER)
    hook = GitHook("fmt", (sys.executable, "tools/fmt.py"), sources=("tools/fmt.py",))
    sub = FilesystemSubstrate(workspace, hooks=(hook,))
    plan = edit("src", "replace 'src/app.py' 'return 200' 'return 204'").build()
    result = engine(sub).execute(plan)
    assert not result.committed
    assert result.diff is not None and len(result.diff.deltas) == 31
    assert "blast_radius" in set(result.blocked_by)
    assert (workspace / "src/module_00.py").read_text() == "def f0():\n\treturn 0"


def test_owners_partition_paths(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace, owners=(("src/**", "app-team"),), workspace="ops")
    assert sub.owner("src/app.py") == "app-team" and sub.owner("config/service.toml") == "ops"


def test_ignored_paths_are_neither_copied_nor_measured(workspace: Path) -> None:
    (workspace / "node_modules/pkg").mkdir(parents=True)
    (workspace / "node_modules/pkg/index.js").write_text("module.exports = 1\n")
    sub = FilesystemSubstrate(workspace, ignore=("node_modules/**",))
    assert "node_modules/pkg/index.js" not in sub.files()
    result = engine(sub).execute(raise_timeout().build())
    assert result.committed
    assert (workspace / "node_modules/pkg/index.js").exists()


# --------------------------------------------------------------------------
# races: the commit is conditional on the files the stage read
# --------------------------------------------------------------------------


def test_an_edit_while_the_stage_is_open_commits_nothing(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        for effect in plan.topological_order():
            sub.apply(handle, effect)
        sub.diff(handle)
        (workspace / "config/service.toml").write_text("name = 'billing'\nreplicas = 5\n")
        with pytest.raises(StageConflictError, match="1 file changed in the workspace"):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert (workspace / "config/service.toml").read_text() == "name = 'billing'\nreplicas = 5\n"


def test_an_edit_to_a_file_the_plan_does_not_touch_does_not_block_it(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        for effect in plan.topological_order():
            sub.apply(handle, effect)
        sub.diff(handle)
        (workspace / "docs/runbook.md").write_text("# Runbook\nedited\n")
        sub.commit(handle)
    finally:
        sub.close(handle)
    assert "4000" in (workspace / "config/service.toml").read_text()
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook\nedited\n"


def test_a_file_created_while_the_stage_is_open_blocks_a_plan_creating_it(
    workspace: Path,
) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = edit("docs", "write 'docs/new.md' 'mine'").build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        sub.diff(handle)
        (workspace / "docs/new.md").write_text("theirs")
        with pytest.raises(StageConflictError):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert (workspace / "docs/new.md").read_text() == "theirs"


def test_the_engine_records_a_lost_race_as_aborted(workspace: Path) -> None:
    class Racing(FilesystemSubstrate):
        def diff(self, handle: Any) -> Any:
            measured = super().diff(handle)
            (workspace / "config/service.toml").write_text("changed by a person\n")
            return measured

    built = engine(Racing(workspace))
    with pytest.raises(StageConflictError):
        built.execute(raise_timeout().build())
    kinds = [r.record_type for r in built.chain.records()]
    assert kinds[-2:] == [RecordType.COMMIT_INTENT, RecordType.ABORTED]


def test_expect_hash_pins_a_plan_to_the_file_its_approvers_saw(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    seen = sub.files()["config/service.toml"]
    pinned = raise_timeout().update(
        table="config", statement="expect-hash 'config/service.toml' :sha", parameters={"sha": seen}
    )
    assert engine(sub, checkers=[]).execute(pinned.build()).committed
    stale = edit("config", "expect-hash 'config/service.toml' :sha", rows=0, sha=seen)
    with pytest.raises(StageConflictError, match="the state it was approved on is gone"):
        engine(sub, checkers=[]).execute(stale.build())
    absent = edit("docs", "expect-hash 'docs/new.md' 'absent'", rows=0)
    assert engine(sub, checkers=[]).execute(absent.build()).committed


def test_commit_refuses_a_copy_changed_after_it_was_measured(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        sub.diff(handle)
        stage = sub._stage
        assert stage is not None
        (stage.tree / "config/extra.toml").write_text("x = 1\n")
        with pytest.raises(StageError, match="changed after it was measured"):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert not (workspace / "config/extra.toml").exists()


def test_one_stage_at_a_time(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        with pytest.raises(StageConflictError, match="already has stage"):
            sub.open(plan)
    finally:
        sub.close(handle)


def test_repair_and_savepoints(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        sub.savepoint(handle, "edited")
        extra = edit("docs", "write 'docs/extra.md' 'x'").build().effects[0]
        sub.apply(handle, extra)
        assert len(sub.diff(handle).deltas) == 2
        sub.rollback_to(handle, "edited")
        assert [d.primary_key for d in sub.diff(handle).deltas] == ["config/service.toml"]
        sub.release_savepoint(handle, "edited")
        with pytest.raises(StageError, match="no savepoint"):
            sub.rollback_to(handle, "edited")
        with pytest.raises(ValueError, match="unsafe"):
            sub.savepoint(handle, "x; rm")
    finally:
        sub.close(handle)


# --------------------------------------------------------------------------
# swap: the whole workspace replaced by one rename
# --------------------------------------------------------------------------


def test_swap_replaces_the_workspace_with_one_rename(workspace: Path) -> None:
    first = prepare_swap(workspace)
    assert workspace.is_symlink() and first.name == "v0-initial"
    assert (workspace / "config/service.toml").read_text() == FILES["config/service.toml"]
    sub = FilesystemSubstrate(workspace, mode="swap", keep_versions=2)
    assert sub.capabilities.snapshot_isolation
    held = (workspace / "config/service.toml").open()
    result = engine(sub).execute(raise_timeout().build())
    assert result.committed, result.verdict
    assert result.diff is not None
    assert "4000" in (workspace / "config/service.toml").read_text()
    assert "2500" in held.read()  # a reader already inside the old version keeps it whole
    held.close()
    assert sub.version() == f"v-{result.diff.stage_id}"
    assert sub.resolve_intent(result.diff.stage_id) is True
    for n in range(3):
        engine(sub, checkers=[]).execute(
            edit("docs", "write 'docs/runbook.md' :t", t=f"# Runbook {n}\n").build()
        )
    versions = sorted(p.name for p in (workspace.parent / ".billing.versions").iterdir())
    assert len(versions) == 2 and sub.version() in versions
    assert sub.resolve_intent(result.diff.stage_id) is True  # its marker outlives its version


def test_swap_refuses_when_the_version_was_edited_in_place(workspace: Path) -> None:
    prepare_swap(workspace)
    sub = FilesystemSubstrate(workspace, mode="swap")
    plan = raise_timeout().build()
    handle = sub.open(plan)
    try:
        sub.apply(handle, plan.effects[0])
        sub.diff(handle)
        (workspace / "docs/runbook.md").write_text("edited where it stands\n")
        with pytest.raises(StageConflictError, match="changed in the workspace"):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert sub.version() == "v0-initial"


def test_swap_refuses_when_another_version_landed(workspace: Path) -> None:
    prepare_swap(workspace)
    first = FilesystemSubstrate(workspace, mode="swap")
    second = FilesystemSubstrate(workspace, mode="swap")
    plan = raise_timeout().build()
    handle = first.open(plan)
    try:
        first.apply(handle, plan.effects[0])
        first.diff(handle)
        assert engine(second, checkers=[]).execute(edit("docs", "write 'docs/b.md' 'b'").build())
        with pytest.raises(StageConflictError, match="moved to version"):
            first.commit(handle)
    finally:
        first.close(handle)
    assert "2500" in (workspace / "config/service.toml").read_text()


def test_swap_configuration(workspace: Path, tmp_path: Path) -> None:
    prepare_swap(workspace)
    with pytest.raises(SubstrateConfigurationError, match="already a link"):
        prepare_swap(workspace)
    with pytest.raises(SubstrateConfigurationError, match="ignores none"):
        FilesystemSubstrate(workspace, mode="swap", ignore=("x/**",))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.replace(workspace, tmp_path / "old-link")
    workspace.symlink_to(elsewhere, target_is_directory=True)
    sub = FilesystemSubstrate(workspace, mode="swap")
    with pytest.raises(SubstrateConfigurationError, match="not to a version directory"):
        sub.open(raise_timeout().build())


# --------------------------------------------------------------------------
# crashes: an in-place commit is finished by the next stage
# --------------------------------------------------------------------------

CRASH = """\
import os, sys
from interlock import EscrowEngine, PlanBuilder
from interlock.filesystem import FilesystemSubstrate
root = sys.argv[1]
sub = FilesystemSubstrate(root)
landed = []
real = FilesystemSubstrate._land
def land(self, tree, path, entry):
    if landed:
        os._exit(9)
    landed.append(path)
    real(self, tree, path, entry)
FilesystemSubstrate._land = land
plan = (
    PlanBuilder("agent", trajectory_id="t")
    .update(table="config", statement="replace 'config/service.toml' 'replicas = 3' 'replicas = 4'")
    .update(table="docs", statement="write 'docs/runbook.md' '# Runbook v2\\n'")
    .build()
)
EscrowEngine(sub, checkers=[]).execute(plan)
"""


def test_a_crash_part_way_is_finished_by_the_next_stage(workspace: Path, tmp_path: Path) -> None:
    script = tmp_path / "crash.py"
    script.write_text(CRASH)
    done = subprocess.run(
        [sys.executable, str(script), str(workspace)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 9, done.stderr
    assert "replicas = 4" in (workspace / "config/service.toml").read_text()
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook\n"  # not yet
    [journal] = (workspace.parent / ".billing.interlock/journal").iterdir()
    sub = FilesystemSubstrate(workspace)
    assert sub.resolve_intent(uuid.UUID(journal.stem)) is True
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook v2\n"
    assert not journal.exists() and leftovers(sub) == []


def test_a_half_done_commit_a_person_edited_since_is_left_for_them(
    workspace: Path, tmp_path: Path
) -> None:
    script = tmp_path / "crash.py"
    script.write_text(CRASH)
    subprocess.run([sys.executable, str(script), str(workspace)], check=False)
    (workspace / "docs/runbook.md").write_text("a person's edit\n")
    [journal] = (workspace.parent / ".billing.interlock/journal").iterdir()
    sub = FilesystemSubstrate(workspace)
    assert sub.resolve_intent(uuid.UUID(journal.stem)) is None
    assert journal.exists()
    assert (workspace / "docs/runbook.md").read_text() == "a person's edit\n"


def test_a_failed_write_while_alive_puts_back_what_it_wrote(workspace: Path) -> None:
    class Failing(FilesystemSubstrate):
        writes = 0

        def _land(self, tree: Path, path: str, entry: Any) -> None:
            if entry is not None and tree.name == "tree":
                Failing.writes += 1
                if Failing.writes == 2:
                    raise OSError("disk full")
            super()._land(tree, path, entry)

    sub = Failing(workspace)
    plan = (
        PlanBuilder("agent", trajectory_id="t")
        .update(
            table="config", statement="replace 'config/service.toml' 'replicas = 3' 'replicas = 4'"
        )
        .update(table="docs", statement="write 'docs/runbook.md' 'v2'")
        .build()
    )
    with pytest.raises(StageError, match="put back"):
        engine(sub, checkers=[]).execute(plan)
    assert (workspace / "config/service.toml").read_text() == FILES["config/service.toml"]
    assert (workspace / "docs/runbook.md").read_text() == "# Runbook\n"
    assert not list((sub.state / "journal").iterdir())


# --------------------------------------------------------------------------
# the control database: a request commits with the files
# --------------------------------------------------------------------------

NOTIFY = SinkSpec(
    "notify", (OperationSpec("send"),), cost_per_call=Decimal("0"), idempotency="header"
)


@pytest.fixture
def control(tmp_path: Path) -> str:
    path = tmp_path / "control.db"
    install_sqlite_outbox(path, (NOTIFY,), ())
    return str(path)


def outbox(control: str) -> list[str]:
    with closing(sqlite3.connect(control)) as conn:
        return [str(r[0]) for r in conn.execute("SELECT payload FROM _interlock_outbox")]


def test_a_request_commits_with_the_files(workspace: Path, control: str) -> None:
    sub = FilesystemSubstrate(workspace, control=control)
    assert sub.capabilities.outbound and sub.control == control
    plan = raise_timeout().enqueue(sink="notify", operation="send", payload={"to": "#ops"})
    result = engine(sub, checkers=[], sinks=SinkRegistry((NOTIFY,))).execute(plan.build())
    assert result.committed
    assert [json.loads(p) for p in outbox(control)] == [{"to": "#ops"}]
    assert "4000" in (workspace / "config/service.toml").read_text()


def test_a_lost_race_rolls_the_request_back_too(workspace: Path, control: str) -> None:
    class Racing(FilesystemSubstrate):
        def diff(self, handle: Any) -> Any:
            measured = super().diff(handle)
            (workspace / "config/service.toml").write_text("changed by a person\n")
            return measured

    sub = Racing(workspace, control=control)
    plan = raise_timeout().enqueue(sink="notify", operation="send", payload={"to": "#ops"})
    with pytest.raises(StageConflictError):
        engine(sub, checkers=[], sinks=SinkRegistry((NOTIFY,))).execute(plan.build())
    assert outbox(control) == []


def test_without_a_control_database_there_is_no_outbox(workspace: Path) -> None:
    sub = FilesystemSubstrate(workspace)
    plan = raise_timeout().enqueue(sink="notify", operation="send", payload={"to": "#ops"})
    with pytest.raises(OutboundRequestError, match="no transactional outbox"):
        engine(sub, checkers=[], sinks=SinkRegistry((NOTIFY,))).execute(plan.build())
