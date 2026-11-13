"""Sessions: a stage a coding agent works in for as long as the work takes, promoted at the end
(1.7.0).

A plan is usually short: an agent's tool call stages its writes, the stage is measured, and the
plan commits or is refused within seconds. A coding agent works differently. It edits files
with its own tools and runs builds and tests for an hour, and only the result matters. A
session gives that work one stage for its whole length:

- ``interlock stage open`` copies the workspace (a directory) or checks out a worktree (a Git
  branch) into a session of its own, and records the state it started from: the *base*, and
  a digest of the files in it, the *input tree*.
- The agent works there with its own tools. ``interlock run -- <command>`` runs each command
  in the session under the operating system's sandbox (:mod:`interlock.sandbox`): it can write
  only inside the session, and it reaches no network. Every command is logged with its exit
  code and the digest of the sandbox profile it ran under.
- ``interlock promote`` measures everything the session changed against its base, as one plan,
  checks it, and commits it on the exact base the session started from, or refuses it and
  leaves the session as it is for the agent to fix. A file someone else changed in the
  workspace meanwhile refuses the commit (the substrate's compare-and-swap). ``--check``
  measures and checks without committing.
- Each promotion writes a receipt (``ILPR1``): the input and output trees, the command log's
  digest, each command's exit code and sandbox, the diff and verdict hashes the escrow chain
  holds, and the commit. With a key it is signed (:func:`verify_receipt`).

The plan a promotion runs states what it may land on: for a directory, an ``expect-hash`` of
each file it changes, at the hash the session started from; for Git, an ``expect-head`` of
the base commit. The diff is measured from the files, never from the plan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol

from interlock.exceptions import InterlockError
from interlock.text import tally

if TYPE_CHECKING:
    from interlock.engine import EscrowEngine, StageResult
    from interlock.types import EffectPlan, StageHandle

__all__ = [
    "COMMANDS",
    "RECEIPT",
    "SESSION_FILE",
    "Promotion",
    "Session",
    "SessionError",
    "SessionSubstrate",
    "find_session",
    "manifest_digest",
    "promote",
    "run_command",
    "sign_receipt",
    "verify_receipt",
]

SESSION_FILE: Final = "session.json"
COMMANDS: Final = "commands.jsonl"
RECEIPT: Final = "promotion.json"
RECEIPT_VERSION: Final = "ILPR1"
INTENT: Final = "interlock promote "
"""How a promotion's plan begins its intent: the escrow chain's record of it, and what a
verifier reading the chain (fiduciary's V7) knows it by."""

_NAME: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
OPEN, PROMOTED, DISCARDED = "open", "promoted", "discarded"


class SessionError(InterlockError):
    """A session cannot do what was asked: it is missing, expired, already promoted, or its
    substrate cannot hold one."""


def manifest_digest(entries: Mapping[str, Sequence[object]]) -> str:
    """``sha256:`` over a tree's files, each its path, SHA-256 and mode, sorted: the digest of
    a directory's tree."""
    digest = hashlib.sha256()
    for path in sorted(entries):
        sha, mode = entries[path][0], entries[path][1]
        digest.update(f"{path}\0{sha}\0{mode}\n".encode("utf-8", "surrogateescape"))
    return "sha256:" + digest.hexdigest()


def session_name(name: str | None) -> str:
    """A session's name: the one given, checked, or a fresh one."""
    if name is None:
        return "s-" + uuid.uuid4().hex[:12]
    if not _NAME.fullmatch(name):
        raise SessionError(
            f"a session's name is lower-case letters, digits, '.', '_' and '-', at most 64, "
            f"not {name!r}"
        )
    return name


@dataclass
class Session:
    """A session, as its ``session.json`` records it."""

    directory: Path
    session_id: uuid.UUID
    name: str
    substrate: str
    tree: Path
    base: str
    input_tree: str
    opened_at: datetime
    expires_at: datetime
    state: str = OPEN
    version: str | None = None
    last: dict[str, Any] = field(default_factory=dict)
    """What the last promotion or check said: its outcome, plan and commit."""

    @classmethod
    def load(cls, directory: Path) -> Session:
        try:
            raw = json.loads((directory / SESSION_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SessionError(f"{directory} holds no session: {exc}") from exc
        return cls(
            directory=directory,
            session_id=uuid.UUID(raw["session_id"]),
            name=raw["name"],
            substrate=raw["substrate"],
            tree=Path(raw["tree"]),
            base=raw["base"],
            input_tree=raw["input_tree"],
            opened_at=datetime.fromisoformat(raw["opened_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            state=raw.get("state", OPEN),
            version=raw.get("version"),
            last=dict(raw.get("last") or {}),
        )

    def save(self) -> None:
        record = {
            "v": 1,
            "session_id": str(self.session_id),
            "name": self.name,
            "substrate": self.substrate,
            "tree": str(self.tree),
            "base": self.base,
            "input_tree": self.input_tree,
            "opened_at": self.opened_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "state": self.state,
            "version": self.version,
            "last": self.last,
        }
        temporary = self.directory / f".{SESSION_FILE}.{uuid.uuid4().hex[:8]}"
        temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, self.directory / SESSION_FILE)

    @property
    def home(self) -> Path:
        """The session's own home and temporary directory: what a command may write besides the
        tree."""
        return self.directory / "home"

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    def commands(self) -> list[dict[str, Any]]:
        """Every command run in the session, in order."""
        path = self.directory / COMMANDS
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def require_open(self) -> None:
        if self.state != OPEN:
            raise SessionError(f"session {self.name} is {self.state}")
        if self.expired:
            raise SessionError(
                f"session {self.name} expired at {self.expires_at:%Y-%m-%d %H:%M} UTC: open a new "
                f"one (its tree is still at {self.tree})"
            )


def new_session(
    directory: Path,
    *,
    session_id: uuid.UUID,
    name: str,
    substrate: str,
    tree: Path,
    base: str,
    input_tree: str,
    lifetime: float,
    version: str | None = None,
) -> Session:
    """Write a new session's record into ``directory``, which the substrate made."""
    opened = datetime.now(UTC)
    session = Session(
        directory=directory,
        session_id=session_id,
        name=name,
        substrate=substrate,
        tree=tree,
        base=base,
        input_tree=input_tree,
        opened_at=opened,
        expires_at=opened + timedelta(seconds=lifetime),
        version=version,
    )
    session.home.mkdir(parents=True, exist_ok=True)
    session.save()
    return session


class SessionSubstrate(Protocol):
    """What a substrate offers to hold sessions: the filesystem and Git substrates."""

    @property
    def substrate_id(self) -> str: ...

    @property
    def sessions(self) -> Path: ...

    def open_session(self, *, name: str | None = None, lifetime: float = 86400.0) -> Session: ...

    def session_changes(self, session: Session) -> list[tuple[str, str]]: ...

    def session_plan(self, session: Session, scope_id: str, intent: str) -> EffectPlan: ...

    def adopt(self, session: Session, plan: EffectPlan) -> StageHandle: ...

    def output_tree(self, session: Session) -> str: ...

    def landed(self, session: Session) -> str: ...

    def discard_session(self, session: Session) -> None: ...


def sessions_of(substrate: object) -> SessionSubstrate:
    """``substrate``, when it holds sessions.

    :raises SessionError: When it does not: a database or an API commits in seconds, and a
        session's long stage is for a directory or a repository.
    """
    if not callable(getattr(substrate, "open_session", None)):
        raise SessionError(
            f"a {getattr(substrate, 'substrate_id', 'this')} substrate holds no sessions: they "
            f"are for a directory (filesystem) or a repository (git)"
        )
    return substrate  # type: ignore[return-value]


def list_sessions(substrate: object) -> list[Session]:
    """Every session the substrate holds, oldest first."""
    root = sessions_of(substrate).sessions
    if not root.is_dir():
        return []
    found = [Session.load(d) for d in root.iterdir() if (d / SESSION_FILE).is_file()]
    return sorted(found, key=lambda s: s.opened_at)


def load_session(substrate: object, name: str) -> Session:
    """The session called ``name``.

    :raises SessionError: When there is none.
    """
    directory = sessions_of(substrate).sessions / session_name(name)
    if not (directory / SESSION_FILE).is_file():
        raise SessionError(f"no session {name} in {directory.parent}")
    return Session.load(directory)


def find_session(start: Path) -> Session | None:
    """The session whose tree holds ``start`` (a working directory inside it), if any: the
    directory a command or a hook runs in says which session it belongs to."""
    current = Path(os.path.realpath(start))
    for candidate in (current, *current.parents):
        record = candidate.parent / SESSION_FILE
        if record.is_file():
            try:
                session = Session.load(candidate.parent)
            except SessionError:
                continue
            if Path(os.path.realpath(session.tree)) == candidate:
                return session
    return None


def current_session(substrate: object, name: str | None, cwd: Path) -> Session:
    """The session named, or else the one ``INTERLOCK_SESSION`` names, or else the one the
    working directory is in; when the substrate holds exactly one open session, that one.

    :raises SessionError: When none of them says.
    """
    chosen = name or os.environ.get("INTERLOCK_SESSION") or None
    if chosen:
        return load_session(substrate, chosen)
    here = find_session(cwd)
    if here is not None:
        return here
    open_ones = [s for s in list_sessions(substrate) if s.state == OPEN]
    if len(open_ones) == 1:
        return open_ones[0]
    raise SessionError(
        f"{tally(len(open_ones), 'session')} open: name one with --session, or run from inside "
        f"its tree"
    )


# --------------------------------------------------------------------------
# running a command
# --------------------------------------------------------------------------


def run_command(
    session: Session,
    command: Sequence[str],
    *,
    sandbox: str = "auto",
    cwd: Path | None = None,
    hidden: Sequence[Path] = (),
    extra_writable: Sequence[Path] = (),
    env: Mapping[str, str] | None = None,
) -> int:
    """Run ``command`` inside the session's tree under the sandbox, log it, and return its exit
    code.

    :param cwd: Where in the tree to run it: the tree itself by default. A directory outside
        the tree is refused.
    :param hidden: Directories the command may not read (beside the session's own records,
        which are always hidden).
    :raises SessionError: When the session is not open, or ``cwd`` is outside its tree.
    :raises SandboxUnavailableError: When the sandbox cannot run here.
    """
    from interlock.sandbox import Sandbox, choose, real

    session.require_open()
    if not command:
        raise SessionError("there is no command to run: interlock run -- <command>")
    tree = real(session.tree)
    where = real(cwd) if cwd is not None else tree
    if where != tree and tree not in where.parents:
        raise SessionError(f"{where} is outside session {session.name}'s tree {tree}")
    kind = choose(sandbox)
    session.home.mkdir(parents=True, exist_ok=True)
    temporary = session.home / "tmp"
    temporary.mkdir(exist_ok=True)
    writable = (tree, real(session.home), *(real(p) for p in extra_writable))
    confined = Sandbox(
        kind,
        writable=writable,
        hidden=tuple(dict.fromkeys(real(p) for p in (session.directory.parent, *hidden))),
    )
    environment = dict(os.environ if env is None else env)
    environment.update(
        {
            "INTERLOCK_SESSION": session.name,
            "TMPDIR": str(real(temporary)),
            "XDG_CACHE_HOME": str(real(session.home) / "cache"),
        }
    )
    started = datetime.now(UTC)
    try:
        code = confined.run(command, cwd=where, env=environment)
    except FileNotFoundError:
        code = 127
    entry = {
        "n": len(session.commands()) + 1,
        "argv": list(command),
        "cwd": "." if where == tree else where.relative_to(tree).as_posix(),
        "sandbox": kind,
        "profile": confined.digest(),
        "started_at": started.isoformat(),
        "ended_at": datetime.now(UTC).isoformat(),
        "exit": code,
    }
    with (session.directory / COMMANDS).open("a", encoding="utf-8") as log:
        log.write(json.dumps(entry, sort_keys=True) + "\n")
    return code


# --------------------------------------------------------------------------
# promotion
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Promotion:
    """What a promotion, or a check, found.

    :ivar outcome: ``committed``, ``refused``, ``conflict`` (what the session changed was
        changed in the workspace too, and nothing was written), ``empty`` (nothing changed), or
        for a check ``would-commit`` and ``would-refuse``.
    """

    session: Session
    outcome: str
    changes: int
    result: StageResult | None = None
    receipt: dict[str, Any] | None = None
    detail: str = ""

    @property
    def committed(self) -> bool:
        return self.outcome == "committed"

    @property
    def feedback(self) -> str:
        """What the agent is told: the verdict's own words when refused."""
        if self.result is not None and self.result.feedback is not None:
            return str(self.result.feedback.render())
        if self.outcome == "empty":
            return f"session {self.session.name} changed nothing: there is nothing to promote"
        if self.outcome == "conflict":
            return (
                f"session {self.session.name} was not promoted: {self.detail}. Someone changed "
                f"the same files since the session opened; open a new session on the new state"
            )
        return f"session {self.session.name}: {self.outcome}"


def promote(
    engine: EscrowEngine,
    session: Session,
    *,
    scope_id: str,
    check: bool = False,
    signer: Any | None = None,
    intent: str | None = None,
) -> Promotion:
    """Measure everything ``session`` changed, as one plan on ``engine``, and commit it or
    refuse it (module docstring). With ``check``, measure and judge only: nothing is recorded
    and nothing commits.

    :param signer: Signs the receipt (``alg``, ``key_id`` and ``sign``); unsigned without.
    :raises SessionError: When the session is not open.
    """
    substrate = sessions_of(engine._substrate)
    session.require_open()
    changes = substrate.session_changes(session)
    if not changes:
        if not check:
            session.state = PROMOTED
            session.last = {"outcome": "empty", "at": datetime.now(UTC).isoformat()}
            session.save()
            substrate.discard_session(session)
        return Promotion(session, "empty", 0)
    commands = session.commands()
    said = intent or (
        f"{INTENT}{session.name}: {tally(len(changes), 'file')} changed, "
        f"{tally(len(commands), 'command')} run"
    )
    plan = substrate.session_plan(session, scope_id, said)
    handle = substrate.adopt(session, plan)
    if check:
        result = engine.preview(plan, handle=handle)
        admitted = result.verdict is not None and result.verdict.admitted
        outcome = "would-commit" if admitted else "would-refuse"
        session.last = {"outcome": outcome, "at": datetime.now(UTC).isoformat()}
        session.save()
        return Promotion(session, outcome, len(changes), result)
    from interlock.engine import _Opened
    from interlock.exceptions import StageConflictError

    output_tree = substrate.output_tree(session)
    try:
        result = engine.execute(plan, _opened=_Opened(handle, ()))
    except StageConflictError as exc:
        # Someone else changed what the session changed, since it opened: nothing was
        # written, and the session stays for the agent to start again from the new state.
        session.last = {"outcome": "conflict", "at": datetime.now(UTC).isoformat()}
        session.save()
        return Promotion(session, "conflict", len(changes), detail=str(exc))
    outcome = "committed" if result.committed else "refused"
    commit = substrate.landed(session) if result.committed else None
    receipt = _receipt(session, plan, result, outcome, output_tree, commit, commands, signer)
    (session.directory / RECEIPT).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    session.last = {
        "outcome": outcome,
        "plan_id": str(plan.plan_id),
        "commit": commit,
        "at": receipt["promoted_at"],
    }
    if result.committed:
        session.state = PROMOTED
    session.save()
    return Promotion(session, outcome, len(changes), result, receipt)


def _receipt(
    session: Session,
    plan: EffectPlan,
    result: StageResult,
    outcome: str,
    output_tree: str,
    commit: str | None,
    commands: Sequence[Mapping[str, Any]],
    signer: Any | None,
) -> dict[str, Any]:
    log = session.directory / COMMANDS
    log_digest = "sha256:" + hashlib.sha256(log.read_bytes() if log.is_file() else b"").hexdigest()
    verdict = result.verdict
    record: dict[str, Any] = {
        "v": RECEIPT_VERSION,
        "session": {"id": str(session.session_id), "name": session.name},
        "substrate": session.substrate,
        "scope": plan.scope_id,
        "plan_id": str(plan.plan_id),
        "plan_hash": plan.content_hash(),
        "base": session.base,
        "input_tree": session.input_tree,
        "output_tree": output_tree,
        "outcome": outcome,
        "commit": commit,
        "diff_hash": result.diff.content_hash() if result.diff is not None else None,
        "verdict_hash": verdict.content_hash() if verdict is not None else None,
        "blocked_by": sorted({v.invariant for v in verdict.blocking}) if verdict else [],
        "chain_head": result.chain_head,
        "action_receipt": getattr(result.receipt, "receipt_id", None),
        "commands": {
            "count": len(commands),
            "log": log_digest,
            "exits": [c.get("exit") for c in commands],
            "sandboxes": sorted({str(c.get("sandbox")) for c in commands}),
            "profiles": sorted({str(c.get("profile")) for c in commands}),
        },
        "opened_at": session.opened_at.isoformat(),
        "promoted_at": datetime.now(UTC).isoformat(),
    }
    return sign_receipt(record, signer) if signer is not None else record


def _payload(record: Mapping[str, Any]) -> bytes:
    from agentgov.receipts.canonical import canonical_bytes

    return bytes(canonical_bytes({k: v for k, v in record.items() if k != "signature"}))


def sign_receipt(record: Mapping[str, Any], signer: Any) -> dict[str, Any]:
    """``record`` with a ``signature`` over its canonical bytes (every field but the signature)."""
    signature = signer.sign(_payload(record))
    return {
        **record,
        "signature": {
            "alg": signer.alg,
            "key_id": signer.key_id,
            "sig": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_receipt(record: Mapping[str, Any], verifier: Any) -> bool:
    """Whether ``record`` is signed by ``verifier``'s key and unchanged since."""
    signed = record.get("signature")
    if not isinstance(signed, Mapping) or signed.get("key_id") != verifier.key_id:
        return False
    try:
        signature = base64.b64decode(str(signed.get("sig", "")), validate=True)
    except ValueError:
        return False
    return bool(verifier.verify(_payload(record), signature))


def remove_tree(path: Path) -> None:
    """Remove a session's copy, quietly when it is gone already."""
    shutil.rmtree(path, ignore_errors=True)
