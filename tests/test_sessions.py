"""Coding sessions (1.7.0): a stage an agent works in for as long as the work takes, then
promoted as one plan (``interlock.session``, ``interlock.sandbox``, ``interlock.hooks``).
"""

from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from interlock.chain import EscrowChain, RecordType
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.engine import EscrowEngine
from interlock.filesystem import FilesystemSubstrate
from interlock.git_substrate import GitSubstrate
from interlock.hooks import HookContext, claude_code, settings
from interlock.invariants import ChangeLimit, KindAllowlist
from interlock.sandbox import Sandbox, SandboxUnavailableError, available, choose
from interlock.session import (
    Session,
    SessionError,
    find_session,
    list_sessions,
    promote,
    run_command,
    verify_receipt,
)

CONFINED = [k for k in available() if k != "none"]
needs_sandbox = pytest.mark.skipif(not CONFINED, reason="no OS sandbox on this machine")
SANDBOX = CONFINED[0] if CONFINED else "none"


def _workspace(root: Path) -> Path:
    ws = root / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "docs").mkdir()
    (ws / "src" / "app.py").write_text("print('hi')\n")
    (ws / "docs" / "README.md").write_text("# readme\n")
    return ws


def _fs(root: Path) -> FilesystemSubstrate:
    return FilesystemSubstrate(_workspace(root), state=root / ".ws.interlock")


def _engine(substrate: Any, root: Path, *checkers: Any) -> EscrowEngine:
    return EscrowEngine(substrate, checkers=list(checkers), chain=EscrowChain(root / "p.chain"))


def _write(session: Session, path: str, text: str) -> None:
    target = session.tree / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


# --------------------------------------------------------------------------
# a directory
# --------------------------------------------------------------------------


def test_a_directory_session_is_promoted_as_one_plan(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    engine = _engine(substrate, tmp_path, KindAllowlist(["src", "tests"]), ChangeLimit(5))
    session = substrate.open_session(name="fix-1")
    assert session.tree.is_dir() and (session.tree / "src" / "app.py").is_file()
    assert session.base == session.input_tree and session.base.startswith("sha256:")
    _write(session, "src/app.py", "print('fixed')\n")
    _write(session, "tests/test_app.py", "def test(): pass\n")
    workspace = tmp_path / "ws"
    assert (workspace / "src" / "app.py").read_text() == "print('hi')\n"  # untouched until promoted

    checked = promote(engine, session, scope_id="s", check=True)
    assert checked.outcome == "would-commit" and checked.changes == 2
    assert not [r for r in engine.chain.records() if r.record_type is RecordType.COMMITTED]

    done = promote(engine, session, scope_id="s")
    assert done.committed and done.receipt is not None
    assert (workspace / "src" / "app.py").read_text() == "print('fixed')\n"
    assert (workspace / "tests" / "test_app.py").is_file()
    assert done.receipt["v"] == "ILPR1" and done.receipt["outcome"] == "committed"
    assert done.receipt["input_tree"] == session.input_tree
    assert done.receipt["output_tree"] != session.input_tree
    assert done.receipt["commit"] == f"fs:{session.session_id}"
    assert "signature" not in done.receipt
    reloaded = Session.load(session.directory)
    assert reloaded.state == "promoted" and not reloaded.tree.exists()
    admitted = [r for r in engine.chain.records() if r.record_type is RecordType.PLAN_ADMITTED]
    assert admitted[-1].note.startswith("interlock promote fix-1: 2 files changed")
    with pytest.raises(SessionError, match="promoted"):
        promote(engine, reloaded, scope_id="s")


def test_a_refused_session_keeps_its_copy_for_the_agent_to_fix(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    engine = _engine(substrate, tmp_path, KindAllowlist(["src", "tests"]))
    session = substrate.open_session(name="docs")
    _write(session, "src/app.py", "print(2)\n")
    _write(session, "docs/README.md", "# rewritten\n")
    refused = promote(engine, session, scope_id="s")
    assert refused.outcome == "refused" and not refused.committed
    assert "docs" in refused.feedback
    assert (tmp_path / "ws" / "docs" / "README.md").read_text() == "# readme\n"
    assert (tmp_path / "ws" / "src" / "app.py").read_text() == "print('hi')\n"
    assert session.tree.is_dir() and Session.load(session.directory).state == "open"
    # The agent puts the docs back; the same session now commits.
    _write(session, "docs/README.md", "# readme\n")
    assert promote(engine, session, scope_id="s").committed
    assert (tmp_path / "ws" / "src" / "app.py").read_text() == "print(2)\n"


def test_a_file_changed_in_the_workspace_meanwhile_refuses_the_commit(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    engine = _engine(substrate, tmp_path)
    session = substrate.open_session(name="race")
    _write(session, "src/app.py", "print('session')\n")
    (tmp_path / "ws" / "src" / "app.py").write_text("print('a person')\n")
    done = promote(engine, session, scope_id="s")
    assert done.outcome == "conflict" and "changed the same files" in done.feedback
    assert (tmp_path / "ws" / "src" / "app.py").read_text() == "print('a person')\n"


def test_a_session_that_changed_nothing_is_closed_empty(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    session = substrate.open_session()
    done = promote(_engine(substrate, tmp_path), session, scope_id="s")
    assert done.outcome == "empty" and done.changes == 0
    assert Session.load(session.directory).state == "promoted" and not session.tree.exists()


def test_sessions_are_found_by_name_and_by_the_directory_a_command_runs_in(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    one = substrate.open_session(name="one")
    (one.tree / "src" / "deep").mkdir()
    assert find_session(one.tree / "src" / "deep") is not None
    assert find_session(one.tree / "src" / "deep").name == "one"  # type: ignore[union-attr]
    assert find_session(tmp_path / "ws") is None
    substrate.open_session(name="two")
    assert [s.name for s in list_sessions(substrate)] == ["one", "two"]
    with pytest.raises(SessionError, match="exists"):
        substrate.open_session(name="one")
    with pytest.raises(SessionError, match="lower-case"):
        substrate.open_session(name="Bad Name")


def test_a_signed_receipt_verifies_and_an_edit_breaks_it(tmp_path: Path) -> None:
    from agentgov.receipts.signing import Ed25519Signer, verifier_of

    signer = Ed25519Signer.generate()
    substrate = _fs(tmp_path)
    session = substrate.open_session(name="signed")
    _write(session, "src/app.py", "print(3)\n")
    done = promote(_engine(substrate, tmp_path), session, scope_id="s", signer=signer)
    receipt = done.receipt
    assert receipt is not None and receipt["signature"]["key_id"] == signer.key_id
    assert verify_receipt(receipt, verifier_of(signer))
    assert not verify_receipt({**receipt, "outcome": "refused"}, verifier_of(signer))
    assert not verify_receipt(receipt, verifier_of(Ed25519Signer.generate()))
    on_disk = json.loads((session.directory / "promotion.json").read_text())
    assert verify_receipt(on_disk, verifier_of(signer))


# --------------------------------------------------------------------------
# commands, under the sandbox
# --------------------------------------------------------------------------


@needs_sandbox
def test_a_command_writes_only_in_the_session_and_reaches_no_network(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    session = substrate.open_session(name="sbx")
    outside = tmp_path / "outside.txt"
    assert run_command(session, ["sh", "-c", "echo ok > src/new.py"], sandbox=SANDBOX) == 0
    assert (session.tree / "src" / "new.py").read_text() == "ok\n"
    assert run_command(session, ["sh", "-c", f"echo no > {outside}"], sandbox=SANDBOX) != 0
    assert not outside.exists()
    # The workspace itself is outside the session, and so are the session's own records.
    target = tmp_path / "ws" / "src" / "app.py"
    assert run_command(session, ["sh", "-c", f"echo no > {target}"], sandbox=SANDBOX) != 0
    record = session.directory / "session.json"
    assert run_command(session, ["cat", str(record)], sandbox=SANDBOX) != 0
    network = "import socket; socket.create_connection(('1.1.1.1', 53), 3)"
    assert run_command(session, ["python3", "-c", network], sandbox=SANDBOX) != 0
    log = session.commands()
    assert [c["exit"] == 0 for c in log] == [True, False, False, False, False]
    assert {c["sandbox"] for c in log} == {SANDBOX}
    assert all(c["profile"].startswith("sha256:") for c in log)


def test_a_command_runs_unconfined_only_when_asked_and_the_log_says_so(tmp_path: Path) -> None:
    substrate = _fs(tmp_path)
    session = substrate.open_session(name="open")
    assert run_command(session, ["sh", "-c", "echo $INTERLOCK_SESSION > who"], sandbox="none") == 0
    assert (session.tree / "who").read_text() == "open\n"
    assert session.commands()[-1]["sandbox"] == "none"
    with pytest.raises(SessionError, match="outside"):
        run_command(session, ["true"], sandbox="none", cwd=tmp_path)
    with pytest.raises(SandboxUnavailableError):
        choose("chroot")


def test_the_profiles_say_what_they_confine(tmp_path: Path) -> None:
    seatbelt = Sandbox("seatbelt", writable=(tmp_path / "t",), hidden=(tmp_path,))
    text = seatbelt.profile()
    assert "(deny network*)" in text and "(deny file-write*)" in text
    assert f'(allow file-write* (subpath "{tmp_path / "t"}")' in text
    assert seatbelt.digest().startswith("sha256:")
    bwrap = Sandbox("bwrap", writable=(tmp_path / "t",), hidden=(tmp_path,)).argv(
        ["make"], tmp_path
    )
    assert bwrap[:1] == ["bwrap"] and "--unshare-net" in bwrap and bwrap[-2:] == ["--", "make"]
    assert bwrap.index("--tmpfs", bwrap.index("--unshare-net")) < bwrap.index("--bind")
    assert Sandbox("none", writable=()).argv(["make"], tmp_path) == ["make"]
    with pytest.raises(ValueError):
        Sandbox("jail", writable=())


# --------------------------------------------------------------------------
# a Git branch
# --------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@x",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@x",
    }
    return subprocess.run(
        ["git", "-c", "init.defaultBranch=main", *args], cwd=cwd, env=env, check=True,
        capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


def _checkout(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('hi')\n")
    (repo / "README.md").write_text("# readme\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    return repo


def test_a_git_session_moves_a_checked_out_branch_by_fast_forward(tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    base = _git(repo, "rev-parse", "HEAD")
    with pytest.raises(Exception, match="checked out"):
        GitSubstrate(repo, branch="main").open_session()
    substrate = GitSubstrate(repo, branch="main", checked_out="follow")
    engine = _engine(substrate, tmp_path, KindAllowlist(["src", "tests"]))
    session = substrate.open_session(name="feature")
    assert session.base == base and session.input_tree == _git(repo, "rev-parse", "HEAD^{tree}")
    _write(session, "src/app.py", "print('feature')\n")
    _write(session, "tests/test_app.py", "def test(): pass\n")
    done = promote(engine, session, scope_id="s")
    assert done.committed
    head = _git(repo, "rev-parse", "HEAD")
    assert head == done.receipt["commit"] and _git(repo, "rev-parse", "HEAD^") == base  # type: ignore[index]
    assert (repo / "src" / "app.py").read_text() == "print('feature')\n"  # the checkout followed
    assert _git(repo, "status", "--porcelain") == ""
    assert "Interlock-Stage:" in _git(repo, "log", "-1", "--format=%B")
    assert done.receipt["output_tree"] == _git(repo, "rev-parse", "HEAD^{tree}")  # type: ignore[index]
    assert not session.tree.exists()


def test_a_git_session_is_refused_when_the_branch_moved(tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    substrate = GitSubstrate(repo, branch="main", checked_out="follow")
    engine = _engine(substrate, tmp_path)
    session = substrate.open_session(name="late")
    _write(session, "src/app.py", "print('late')\n")
    (repo / "README.md").write_text("# moved\n")
    _git(repo, "commit", "-qam", "someone else")
    moved = _git(repo, "rev-parse", "HEAD")
    done = promote(engine, session, scope_id="s")
    assert done.outcome == "conflict" and _git(repo, "rev-parse", "HEAD") == moved
    assert session.tree.is_dir()


def test_a_refused_git_session_moves_nothing(tmp_path: Path) -> None:
    repo = _checkout(tmp_path)
    substrate = GitSubstrate(repo, branch="main", checked_out="follow")
    engine = _engine(substrate, tmp_path, KindAllowlist(["src"]))
    session = substrate.open_session(name="readme")
    _write(session, "README.md", "# changed\n")
    before = _git(repo, "rev-parse", "HEAD")
    done = promote(engine, session, scope_id="s")
    assert done.outcome == "refused" and _git(repo, "rev-parse", "HEAD") == before
    assert (session.tree / "README.md").read_text() == "# changed\n"


# --------------------------------------------------------------------------
# configuration and the command line
# --------------------------------------------------------------------------


def _config(root: Path, sessions: str = "") -> Path:
    _workspace(root)
    path = root / "interlock.toml"
    path.write_text(
        'substrate = "filesystem"\n[filesystem]\nroot = "ws"\nstate = ".ws.interlock"\n' + sessions
    )
    return path


def test_the_sessions_section_is_read_and_checked(tmp_path: Path) -> None:
    path = _config(tmp_path, '[sessions]\nkinds = ["src"]\nmax_changes = 2\nlifetime_hours = 1\n')
    config = load_config(path)
    assert config.sessions.kinds == ("src",) and config.sessions.max_changes == 2
    assert [type(c).__name__ for c in config.sessions.checkers()] == [
        "KindAllowlist",
        "ChangeLimit",
    ]
    for bad, said in (
        ("sandbox = 'jail'", "sandbox"),
        ("max_changes = 0", "max_changes"),
        ("lifetime_hours = -1", "lifetime_hours"),
        ("color = 1", "unknown"),
    ):
        path.write_text(path.read_text().split("[sessions]")[0] + f"[sessions]\n{bad}\n")
        with pytest.raises(ConfigError, match=said):
            load_config(path)
    sql = tmp_path / "sql.toml"
    sql.write_text('database = "x.db"\n[[tables]]\nname = "t"\ncolumns = ["id"]\n[sessions]\n')
    with pytest.raises(ConfigError, match="directory"):
        load_config(sql)


def test_the_command_line_opens_runs_checks_and_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _config(tmp_path, '[sessions]\nkinds = ["src", "tests"]\nsandbox = "none"\n')
    assert main(["install", "--config", str(path)], out=io.StringIO()) == 0
    out = io.StringIO()
    assert main(["stage", "open", "--config", str(path), "--name", "cli"], out=out) == 0
    tree = Path(out.getvalue().strip().splitlines()[-1])
    (tree / "src" / "app.py").write_text("print('cli')\n")
    monkeypatch.chdir(tree)
    assert main(["run", "--config", str(path), "--", "sh", "-c", "exit 3"], out=io.StringIO()) == 3
    out = io.StringIO()
    assert main(["promote", "--config", str(path), "--check", "--json"], out=out) == 0
    assert json.loads(out.getvalue())["outcome"] == "would-commit"
    out = io.StringIO()
    assert main(["stage", "show", "--config", str(path)], out=out) == 0
    assert json.loads(out.getvalue())["command_log"][0]["exit"] == 3
    out = io.StringIO()
    assert main(["promote", "--config", str(path), "--json"], out=out) == 0
    promoted = json.loads(out.getvalue())
    assert promoted["outcome"] == "committed" and promoted["receipt"]["commands"]["exits"] == [3]
    assert (tmp_path / "ws" / "src" / "app.py").read_text() == "print('cli')\n"
    out = io.StringIO()
    assert main(["stage", "list", "--config", str(path)], out=out) == 0
    assert "cli" in out.getvalue() and "promoted" in out.getvalue()


# --------------------------------------------------------------------------
# Claude Code's hooks
# --------------------------------------------------------------------------


def _hook(context: HookContext, **payload: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = claude_code(payload, context, out, err)
    return code, out.getvalue(), err.getvalue()


def test_claude_codes_hooks_open_check_and_promote_a_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    substrate = _fs(tmp_path)
    project = tmp_path / "ws"
    (project / ".claude").mkdir()
    (project / ".claude" / "settings.local.json").write_text("{}")
    engine = _engine(substrate, tmp_path, KindAllowlist(["src", "tests"]))
    context = HookContext(
        substrate=lambda: substrate,
        promote=lambda session, check: promote(engine, session, scope_id="s", check=check),
        lifetime=3600,
        target="the workspace",
    )
    code, out, _ = _hook(
        context, hook_event_name="WorktreeCreate", name="Bold Oak", cwd=str(project)
    )
    tree = Path(out.strip().splitlines()[-1])
    assert code == 0 and tree.is_dir() and tree.parent.name == "bold-oak"
    assert (tree / ".claude" / "settings.local.json").is_file()

    env_file = tmp_path / "claude.env"
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
    code, out, _ = _hook(context, hook_event_name="SessionStart", cwd=str(tree), source="startup")
    said = json.loads(out)["hookSpecificOutput"]["additionalContext"]
    assert "staged session (bold-oak)" in said and "the workspace" in said
    assert env_file.read_text() == "export INTERLOCK_SESSION=bold-oak\n"

    edit = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(tree)}
    code, out, _ = _hook(context, **edit, tool_input={"file_path": str(project / "src/app.py")})
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    code, out, _ = _hook(context, **edit, tool_input={"file_path": str(tree / "src/app.py")})
    assert out == ""
    code, out, _ = _hook(context, **{**edit, "cwd": str(project)}, tool_input={"file_path": "x"})
    assert "EnterWorktree" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    code, out, _ = _hook(context, **{**edit, "tool_name": "Bash"}, tool_input={"command": "ls"})
    assert out == ""

    (tree / "docs" / "README.md").write_text("# not allowed\n")
    code, out, _ = _hook(context, hook_event_name="Stop", cwd=str(tree), stop_hook_active=False)
    blocked = json.loads(out)
    assert blocked["decision"] == "block" and "would be refused" in blocked["reason"]
    code, out, _ = _hook(context, hook_event_name="Stop", cwd=str(tree), stop_hook_active=True)
    assert out == ""  # once per stop: the agent is not held in a loop

    code, _, err = _hook(context, hook_event_name="WorktreeRemove", worktree_path=str(tree))
    assert code == 1 and "not promoted" in err and tree.is_dir()

    (tree / "docs" / "README.md").write_text("# readme\n")
    (tree / "src" / "app.py").write_text("print('agent')\n")
    code, out, _ = _hook(context, hook_event_name="Stop", cwd=str(tree), stop_hook_active=False)
    assert out == ""
    code, _, _ = _hook(context, hook_event_name="SessionEnd", cwd=str(tree), reason="clear")
    assert Session.load(tree.parent).state == "open"  # /clear goes on working
    code, _, err = _hook(context, hook_event_name="SessionEnd", cwd=str(tree), reason="other")
    assert code == 0 and "promoted to the workspace" in err
    assert (project / "src" / "app.py").read_text() == "print('agent')\n"
    code, _, _ = _hook(context, hook_event_name="WorktreeRemove", worktree_path=str(tree))
    assert code == 0 and not tree.exists()


def test_the_settings_send_every_event_to_one_command() -> None:
    hooks = settings("interlock hook claude-code --config /x/interlock.toml")
    assert set(hooks) == {
        "WorktreeCreate", "SessionStart", "PreToolUse", "Stop", "SessionEnd", "WorktreeRemove"
    }  # fmt: skip
    assert hooks["PreToolUse"][0]["matcher"] == "Edit|MultiEdit|NotebookEdit|Write"
    assert hooks["SessionEnd"][0]["matcher"] == "prompt_input_exit|logout|other"
    commands = {h["command"] for e in hooks.values() for g in e for h in g["hooks"]}
    assert commands == {"interlock hook claude-code --config /x/interlock.toml"}
