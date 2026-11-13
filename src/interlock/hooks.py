"""Claude Code's hooks, answered for a coding session (1.7.0).

One command answers every hook a session needs, reading the event Claude Code sends on stdin
(``interlock hook claude-code``, and ``fiduciary hook claude-code`` for a mandate's
deployment). Nothing rewrites a tool call's input: the session's tree is the directory Claude
Code works in, so its own Edit, Write and Bash tools act there unchanged.

- ``WorktreeCreate`` (``claude --worktree``, or the EnterWorktree tool): opens a session and
  prints its tree, which Claude Code then works in.
- ``SessionStart``: tells the agent it works in a stage, and how it ends; puts the session's
  name in the environment of every command (``INTERLOCK_SESSION``).
- ``PreToolUse`` on Edit, Write, MultiEdit and NotebookEdit: refuses a file outside the
  session's tree, and any edit when the session is not in one. Bash is not checked call by
  call: Claude Code's sandbox confines its writes to the working directory, which is the tree.
- ``Stop``: measures and checks the session as it stands, and when the plan would be refused
  keeps the agent working with the refusal in its words, once per stop.
- ``SessionEnd`` (on exit, not on ``/clear``) and ``WorktreeRemove``: promote the session. A
  refused session keeps its tree, and WorktreeRemove fails, so Claude Code keeps the directory.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TextIO

from interlock.session import (
    OPEN,
    Promotion,
    Session,
    SessionError,
    find_session,
    sessions_of,
)

__all__ = ["EDIT_TOOLS", "HookContext", "claude_code"]

EDIT_TOOLS: Final = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_SKIPPED_ENDS: Final = frozenset({"clear", "resume"})


@dataclass
class HookContext:
    """What a hook needs from the deployment.

    :ivar substrate: Opens the substrate sessions live on.
    :ivar promote: Promotes a session, or with ``check`` measures and judges it only: through
        the engine and checks the deployment holds (:func:`interlock.session.promote`, or a
        mandate's engine). Called only by the events that promote, so an edit's check opens
        nothing.
    :ivar lifetime: How long a session lasts, in seconds.
    :ivar target: What a promotion lands on, in words: "main", "the workspace".
    :ivar copies: Files beside the project copied into a new session's tree (Claude Code's
        local settings), each relative to the project.
    """

    substrate: Callable[[], Any]
    promote: Callable[[Session, bool], Promotion]
    lifetime: float
    target: str = "the branch"
    copies: tuple[str, ...] = (".claude/settings.local.json",)


def _slug(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "-" for c in name.lower()).strip("-.")
    return (cleaned or "session")[:64]


def claude_code(payload: Mapping[str, Any], context: HookContext, out: TextIO, err: TextIO) -> int:
    """Answer one Claude Code hook event; the exit code Claude Code reads."""
    event = str(payload.get("hook_event_name", ""))
    cwd = Path(str(payload.get("cwd") or "."))
    handler = _HANDLERS.get(event)
    if handler is None:
        return 0
    try:
        return handler(payload, cwd, context, out, err)
    except SessionError as exc:
        print(f"interlock: {exc}", file=err)
        return 2 if event in ("PreToolUse", "Stop") else 1


def _worktree_create(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    substrate = sessions_of(context.substrate())
    session = substrate.open_session(
        name=_slug(str(payload.get("name") or "")), lifetime=context.lifetime
    )
    for relative in context.copies:
        source = cwd / relative
        if source.is_file():
            target = session.tree / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
    print(f"session {session.name} opened at {session.tree}", file=err)
    print(str(session.tree), file=out)
    return 0


def _session_start(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    session = find_session(cwd)
    if session is None:
        text = (
            "This repository's edits go through a staged session, and this session is not in "
            "one: edits here are refused. Call EnterWorktree to open one (or restart with "
            "claude --worktree), then work there."
        )
    else:
        env_file = os.environ.get("CLAUDE_ENV_FILE")
        if env_file:
            with open(env_file, "a", encoding="utf-8") as handle:
                handle.write(f"export INTERLOCK_SESSION={session.name}\n")
        text = (
            f"You are working in a staged session ({session.name}): a copy of the project at "
            f"{session.tree}. Your edits and commands change only this copy. Commands run in a "
            f"sandbox that can write only here and reaches no network. When the session ends, "
            f"everything you changed is measured as one change and checked against the limits "
            f"set for this project. If it passes it is committed to {context.target} once; if "
            f"not, it stays here and you are told why. Before you finish, a check tells you "
            f"whether it would pass."
        )
    answer = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}}
    print(json.dumps(answer), file=out)
    return 0


def _deny(reason: str, out: TextIO) -> int:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        ),
        file=out,
    )
    return 0


def _pre_tool_use(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    if payload.get("tool_name") not in EDIT_TOOLS:
        return 0
    arguments = payload.get("tool_input") or {}
    target = arguments.get("file_path") or arguments.get("notebook_path")
    session = find_session(cwd)
    if session is None:
        return _deny(
            "Edits go through a staged session, and this one is not in one. Call EnterWorktree "
            "to open a session, then make the edit there.",
            out,
        )
    if not target:
        return 0
    path = Path(str(target))
    full = Path(os.path.realpath(path if path.is_absolute() else cwd / path))
    tree = Path(os.path.realpath(session.tree))
    if full != tree and tree not in full.parents:
        return _deny(
            f"{path} is outside this session's copy ({tree}). Edit the file at the same place "
            f"inside the copy: everything there is promoted together when the session ends.",
            out,
        )
    return 0


def _stop(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    session = find_session(cwd)
    if session is None or session.state != OPEN or payload.get("stop_hook_active"):
        return 0
    checked = context.promote(session, True)
    if checked.outcome != "would-refuse":
        return 0
    reason = (
        "Before this session ends: as it stands, its change would be refused when it is "
        "promoted, and nothing would be committed.\n\n"
        + checked.feedback
        + "\n\nChange the work so that it passes, or tell the user why it needs an exception."
    )
    print(json.dumps({"decision": "block", "reason": reason}), file=out)
    return 0


def _promote(session: Session, context: HookContext, err: TextIO) -> Promotion:
    done = context.promote(session, False)
    if done.outcome == "committed":
        commit = (done.receipt or {}).get("commit")
        print(
            f"session {session.name}: {done.changes} files promoted to {context.target}"
            + (f" as {str(commit)[:12]}" if commit else ""),
            file=err,
        )
    elif done.outcome in ("refused", "conflict"):
        print(
            f"session {session.name} was not promoted, and its copy is kept at {session.tree}:\n"
            + done.feedback,
            file=err,
        )
    return done


def _session_end(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    if str(payload.get("reason", "")) in _SKIPPED_ENDS:
        return 0
    session = find_session(cwd)
    if session is None or session.state != OPEN:
        return 0
    _promote(session, context, err)
    return 0


def _worktree_remove(
    payload: Mapping[str, Any], cwd: Path, context: HookContext, out: TextIO, err: TextIO
) -> int:
    where = Path(str(payload.get("worktree_path") or cwd))
    session = find_session(where)
    if session is None:
        return 0
    substrate = sessions_of(context.substrate())
    if session.state == OPEN:
        done = _promote(session, context, err)
        if done.outcome in ("refused", "conflict"):
            return 1
    substrate.discard_session(session)
    return 0


_HANDLERS: Final[
    Mapping[str, Callable[[Mapping[str, Any], Path, HookContext, TextIO, TextIO], int]]
] = {
    "WorktreeCreate": _worktree_create,
    "SessionStart": _session_start,
    "PreToolUse": _pre_tool_use,
    "Stop": _stop,
    "SessionEnd": _session_end,
    "WorktreeRemove": _worktree_remove,
}


def settings(command: str, *, ends: str = "prompt_input_exit|logout|other") -> dict[str, Any]:
    """The ``hooks`` of a Claude Code settings file that send every event a session needs to
    ``command`` (``interlock hook claude-code --config ...``)."""

    def one(timeout: int | None = None) -> list[dict[str, Any]]:
        hook: dict[str, Any] = {"type": "command", "command": command}
        if timeout is not None:
            hook["timeout"] = timeout
        return [{"hooks": [hook]}]

    return {
        "WorktreeCreate": one(120),
        "SessionStart": one(30),
        "PreToolUse": [
            {"matcher": "|".join(sorted(EDIT_TOOLS)), "hooks": one(30)[0]["hooks"]},
        ],
        "Stop": one(120),
        "SessionEnd": [{"matcher": ends, "hooks": one(60)[0]["hooks"]}],
        "WorktreeRemove": one(60),
    }
