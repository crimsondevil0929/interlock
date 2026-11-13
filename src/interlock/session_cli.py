"""``interlock stage``, ``interlock run``, ``interlock promote`` and ``interlock hook``: coding
sessions from the command line (1.7.0, :mod:`interlock.session`).

    interlock stage open --config interlock.toml [--name NAME]      # prints the tree's path last
    interlock run --config interlock.toml [--session NAME] -- pytest -q
    interlock promote --config interlock.toml [--session NAME] [--check]
    interlock stage list | show | discard --config interlock.toml
    interlock hook claude-code --config interlock.toml               # Claude Code's hooks, on stdin

A command without ``--session`` acts on the session whose tree it runs in, or the one
``INTERLOCK_SESSION`` names, or the only open one.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from interlock.config import InterlockConfig
from interlock.text import tally

__all__ = ["add_commands", "dispatch", "promotion_engine"]

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def add_commands(commands: Any, common: Callable[[argparse.ArgumentParser, str], None]) -> None:
    """Add the session commands to ``interlock``'s parser."""
    database = "overrides the file's database, as does INTERLOCK_DATABASE"
    stage = commands.add_parser(
        "stage",
        help="open, list, show or discard a coding session's stage",
        description="A coding session: a stage an agent works in for as long as the work "
        "takes, promoted as one change at the end (Git or filesystem substrates).",
    )
    actions = stage.add_subparsers(dest="action", required=True)
    for name, text in (
        ("open", "open a session: copy the workspace, or check out a worktree; print its path"),
        ("list", "list the sessions"),
        ("show", "show a session: its base, its commands, its last promotion"),
        ("discard", "discard a session's copy without promoting it"),
    ):
        action = actions.add_parser(name, help=text, description=text)
        common(action, database)
        if name == "open":
            action.add_argument("--name", help="the session's name: lower case, digits, . _ -")
        else:
            action.add_argument("--session", help="the session's name")
        action.add_argument("--json", action="store_true", help="print JSON")
    run = commands.add_parser(
        "run",
        help="run a command in a session's stage, under the OS sandbox",
        description="Run a command in a session's stage under the operating system's sandbox: "
        "it writes only inside the stage and reaches no network. Logged with its exit code.",
    )
    common(run, database)
    run.add_argument("--session", help="the session's name")
    run.add_argument(
        "--sandbox",
        choices=("auto", "seatbelt", "bwrap", "none"),
        help="overrides [sessions] sandbox; none runs unconfined, and the receipt says so",
    )
    run.add_argument("argv", nargs=argparse.REMAINDER, help="-- and the command")
    promote = commands.add_parser(
        "promote",
        help="measure a session's whole change, check it, and commit it or refuse it",
        description="Measure everything a session changed as one plan, check it, and commit "
        "it on the base the session started from, or refuse it and keep the session. Writes a "
        "promotion receipt (signed with --key, --signer or [receipts]'s key).",
    )
    common(promote, database)
    promote.add_argument("--session", help="the session's name")
    promote.add_argument("--check", action="store_true", help="measure and check; commit nothing")
    promote.add_argument("--scope", help="overrides [sessions] scope")
    promote.add_argument("--app", help="module:callable: an application whose checkers apply too")
    promote.add_argument("--key", help="an Ed25519 key file that signs the receipt")
    promote.add_argument("--signer", help="in place of --key: a [signers.<name>]")
    promote.add_argument("--json", action="store_true", help="print the outcome as JSON")
    hook = commands.add_parser(
        "hook",
        help="answer a coding agent's hook (Claude Code), the event on stdin",
        description="Answer one of Claude Code's hook events, read as JSON on stdin: "
        "WorktreeCreate opens a session, Stop checks it, SessionEnd and WorktreeRemove "
        "promote it (interlock.hooks).",
    )
    hook.add_argument("agent", choices=("claude-code",))
    common(hook, database)
    hook.add_argument("--app", help="module:callable: an application whose checkers apply too")


def _substrate(config: InterlockConfig) -> Any:
    from interlock.session import sessions_of
    from interlock.wiring import open_substrate

    return sessions_of(open_substrate(config))


def promotion_engine(config: InterlockConfig, app: str | None = None) -> Any:
    """An engine for promotions: the substrate, ``[sessions]``'s checks and the application's,
    the ledger, receipts, and an escrow chain beside the sessions."""
    from interlock.chain import EscrowChain
    from interlock.engine import EscrowEngine
    from interlock.session import sessions_of
    from interlock.wiring import (
        open_anchor,
        open_governor,
        open_receipts,
        open_sensors,
        open_substrate,
    )

    substrate = open_substrate(config)
    sessions = sessions_of(substrate)
    checkers = list(config.sessions.checkers())
    if app:
        from interlock.daemon import load_application

        checkers += list(load_application(app, config).checkers)
    path = config.engine.chain_for(0, 1)
    if path is None:
        path = sessions.sessions.parent / "promotions.chain"
    path.parent.mkdir(parents=True, exist_ok=True)
    return EscrowEngine(
        substrate,
        checkers=checkers,
        chain=EscrowChain(path),
        anchor=open_anchor(config, open_governor(config)),
        receipts=open_receipts(config),
        windows=config.windows,
        sensors=open_sensors(config),
    )


def _receipt_signer(config: InterlockConfig, key: str | None, signer: str | None) -> Any:
    from interlock.wiring import open_signer

    if key or signer:
        return open_signer(config, signer, key)
    if config.receipts is not None:
        return open_signer(config, config.receipts.signer, config.receipts.key)
    return None


def _describe(session: Any) -> dict[str, Any]:
    commands = session.commands()
    return {
        "name": session.name,
        "state": session.state,
        "substrate": session.substrate,
        "tree": str(session.tree),
        "base": session.base,
        "input_tree": session.input_tree,
        "opened_at": session.opened_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "commands": len(commands),
        "failed": sum(1 for c in commands if c.get("exit") != 0),
        "last": session.last,
    }


def dispatch(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.session import current_session, list_sessions, run_command

    lifetime = config.sessions.lifetime_hours * 3600
    if args.command == "hook":
        return _hook(config, args, out)
    if args.command == "stage":
        substrate = _substrate(config)
        if args.action == "open":
            session = substrate.open_session(name=args.name, lifetime=lifetime)
            if args.json:
                print(json.dumps(_describe(session), indent=2), file=out)
            else:
                print(f"session {session.name} opened on {session.base[:12]}; work in:", file=out)
                print(str(session.tree), file=out)
            return EXIT_OK
        if args.action == "list":
            found = [_describe(s) for s in list_sessions(substrate)]
            if args.json:
                print(json.dumps(found, indent=2), file=out)
            for s in [] if args.json else found:
                print(
                    f"{s['name']:<24} {s['state']:<10} {tally(s['commands'], 'command')}, "
                    f"opened {s['opened_at'][:16]}  {s['tree']}",
                    file=out,
                )
            if not found and not args.json:
                print("no sessions", file=out)
            return EXIT_OK
        session = current_session(substrate, args.session, Path.cwd())
        if args.action == "show":
            described = _describe(session)
            described["command_log"] = session.commands()
            print(json.dumps(described, indent=2), file=out)
            return EXIT_OK
        substrate.discard_session(session)
        session.state = "discarded"
        session.save()
        print(f"session {session.name} discarded; its records are kept", file=out)
        return EXIT_OK
    if args.command == "run":
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv = argv[1:]
        if not argv:
            print("interlock: run needs a command: interlock run -- <command>", file=sys.stderr)
            return EXIT_USAGE
        session = current_session(_substrate(config), args.session, Path.cwd())
        cwd = Path.cwd()
        inside = session.tree.resolve()
        where = cwd if (cwd.resolve() == inside or inside in cwd.resolve().parents) else None
        return run_command(
            session,
            argv,
            sandbox=args.sandbox or config.sessions.sandbox,
            cwd=where,
            hidden=config.sessions.hidden,
        )
    return _promote(config, args, out)


def _promote(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.session import current_session, promote

    engine = promotion_engine(config, args.app)
    session = current_session(engine._substrate, args.session, Path.cwd())
    signer = None if args.check else _receipt_signer(config, args.key, args.signer)
    done = promote(
        engine,
        session,
        scope_id=args.scope or config.sessions.scope,
        check=args.check,
        signer=signer,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "session": session.name,
                    "outcome": done.outcome,
                    "changes": done.changes,
                    "feedback": None if done.outcome in ("committed", "empty") else done.feedback,
                    "receipt": done.receipt,
                },
                indent=2,
            ),
            file=out,
        )
    else:
        print(f"session {session.name}: {done.outcome}, {tally(done.changes, 'file')}", file=out)
        if done.outcome in ("refused", "would-refuse", "conflict"):
            print(done.feedback, file=out)
        if done.receipt is not None:
            signed = "signed" if "signature" in done.receipt else "unsigned"
            print(f"receipt ({signed}): {session.directory / 'promotion.json'}", file=out)
    return EXIT_FINDINGS if done.outcome in ("refused", "would-refuse", "conflict") else EXIT_OK


def _hook(config: InterlockConfig, args: argparse.Namespace, out: TextIO) -> int:
    from interlock.hooks import HookContext, claude_code

    try:
        payload = json.load(sys.stdin)
    except ValueError as exc:
        print(f"interlock: the hook's input is not JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    target = config.git.branch if config.git is not None else "the workspace"

    def promote(session: Any, check: bool) -> Any:
        from interlock.session import promote as run

        return run(
            promotion_engine(config, args.app),
            session,
            scope_id=config.sessions.scope,
            check=check,
            signer=None if check else _receipt_signer(config, None, None),
        )

    context = HookContext(
        substrate=lambda: _substrate(config),
        promote=promote,
        lifetime=config.sessions.lifetime_hours * 3600,
        target=target,
    )
    return claude_code(payload, context, out, sys.stderr)
