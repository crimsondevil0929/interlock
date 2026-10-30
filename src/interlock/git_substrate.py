"""Git as a transactional substrate: stage a change in a worktree of its own,
measure it with Git, and commit it with a compare-and-swap on the branch.

The guarantee is the one :class:`~interlock.substrate.SqliteSubstrate` gives,
on a repository: what was measured is exactly what committed, or nothing
committed. Git supplies the three things a substrate owes the engine:

- **A diff read from the system.** Each stage has a detached worktree at the
  branch's head (its *base*). Effects edit files there, and the repository's
  own hooks run after each one, as triggers run after a statement: a code
  generator, a formatter, a lockfile refresh. The diff is
  ``git diff-index --cached`` of everything in the worktree against the base,
  so a file a hook wrote is measured like a file the plan wrote.
- **A head the commit is conditional on.** The commit is
  ``git update-ref <branch> <new> <base>``: it moves the branch only if the
  branch is still at the base the stage measured against. If anyone else
  moved it meanwhile (a push, another stage, a merge), nothing moves and the
  stage fails, so a measurement or a warrant never commits onto a state it did
  not see.
- **A marker recovery can read.** The commit carries the trailer
  ``Interlock-Stage: <stage_id>``. :meth:`GitSubstrate.resolve_intent` reads
  the branch's history for it.

Each changed path is one :class:`~interlock.types.RowDelta`, so every built-in
checker reads a Git diff as it reads a SQL one:

- **table**: the path's *class*, from glob rules (:class:`PathClass`):
  ``workflows``, ``governance``, ``infra``, ``deps``, ``tests``, ``src``,
  ``docs``, and ``other`` for any path no rule names. ``TableAllowlist``
  keeps a plan out of the classes its mandate does not grant, ``NoDelete``
  out of deletions.
- **primary key**: the path.
- **partition** (``tenant_id``): the workspace, or the owner a rule names for
  the path, so ``TenantIsolation`` keeps a plan to one package.
- **columns** (:data:`COLUMNS`): ``path``, ``blob_sha``, ``mode``,
  ``lines_added``, ``lines_deleted``, ``net_lines`` and ``secret_markers``.
  The before image holds the base's blob and mode with zero counts; the
  after image holds the new blob and mode with the change's counts. A
  deletion has no after image. ``secret_markers`` counts the credential
  patterns (:data:`SECRET_PATTERNS`) the change adds; only the count is kept,
  never the text.

A statement is one operation in the substrate's own small language, with
arguments that are ``:parameters`` or ``'quoted'`` literals (``''`` escapes a
quote), so a FIDU1 tool binding can pin it as it pins SQL::

    write :path :text              create or replace a file
    replace :path :old :new        replace the one occurrence of old in a file
    delete :path                   remove a file
    mode :path :mode               100644 or 100755
    patch :diff                    apply a unified diff (git apply)
    expect-head :commit            refuse unless the branch is at that commit

``expect-head`` pins a plan to the head its approvers saw: a warrant over a
plan that names it can only commit onto that exact commit.

**The control database.** Rate windows, the outbox and the inbox need a
transactional home that Git does not have. With ``control`` naming a SQLite
file that ``interlock install`` set up, a stage also opens a stage there: its
requests, the facts it consumes and its window history are written in that
transaction, and the Git commit happens inside it, just before ``COMMIT``. If
the process dies between the two, a redo record written before the
compare-and-swap lets the next stage, or recovery, finish the control
database's half: exactly when the Git commit landed.

What a stage does not contain: a hook is operator code, run in the stage's
worktree with a scrubbed environment and a timeout, and it can reach whatever
the process can. A hook that executes a file a plan can write runs that plan's
code; name such files in :attr:`GitHook.sources` and a plan may not write
them. Point the substrate at a bare repository, or at a branch no worktree has
checked out: moving a checked-out branch leaves that worktree behind, so the
substrate refuses to.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import subprocess
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from interlock.chain import EscrowRecord
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    InboundFactError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.inbox_sql import SQLITE_CONSUMED
from interlock.reconcile import Reconciliation, UnmediatedWrite, _stage_findings
from interlock.sqlite_outbox import OUTBOX, STATE, TRACES, WINDOWS_TABLE
from interlock.substrate import _MARKER_TABLE, STAGE_JOURNAL_TABLE, SqliteSubstrate
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectKind,
    EffectOutcome,
    EffectPlan,
    InboundFact,
    OutboundDelta,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
    WindowMeasure,
)
from interlock.windows import WindowCharge

__all__ = [
    "COLUMNS",
    "DEFAULT_CLASSES",
    "PLAN_TRAILER",
    "SECRET_PATTERNS",
    "STAGE_TRAILER",
    "VERBS",
    "GitHook",
    "GitStatement",
    "GitSubstrate",
    "PathClass",
    "parse_statement",
    "reconcile_git",
    "secret_markers",
]

logger = logging.getLogger("interlock.git_substrate")

STAGE_TRAILER: Final = "Interlock-Stage"
"""The commit trailer naming the stage a commit is: the substrate's marker."""
PLAN_TRAILER: Final = "Interlock-Plan"

COLUMNS: Final = (
    "path",
    "blob_sha",
    "mode",
    "lines_added",
    "lines_deleted",
    "net_lines",
    "secret_markers",
)
"""The columns of every path's before and after image."""

FALLBACK_CLASS: Final = "other"

VERBS: Final[Mapping[str, tuple[str, ...]]] = {
    "write": ("path", "text"),
    "replace": ("path", "old", "new"),
    "delete": ("path",),
    "mode": ("path", "mode"),
    "patch": ("diff",),
    "expect-head": ("commit",),
}
"""Each verb of the statement language, and its arguments in order."""

_PARAMETER: Final = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_TOKEN: Final = re.compile(r"\s*(?:'((?:[^']|'')*)'|(:[A-Za-z_][A-Za-z0-9_]*)|([^\s']+))", re.S)
_COMMIT: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_NAME: Final = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_CLASS_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,62}")
_MODES: Final = {"100644": 0o644, "100755": 0o755}
_ZERO: Final = re.compile(r"0+")
_EMPTY_BLOB: Final = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("stripe_live_key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("ci_secret_reference", re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
        ),
    ),
)
"""Credential patterns a change is scanned for, by name. A CI secret reference
(``${{ secrets.X }}``) counts: it is how a workflow reads a credential."""

_HIGH_ENTROPY: Final = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_ENTROPY_BITS: Final = 4.5
"""Bits per character above which a 32-character token reads as a secret.
Hex (a commit, a lockfile hash, a UUID) tops out at 4."""


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PathClass:
    """A class of paths: a table name for every path its globs match.

    Globs are anchored at the repository's root and match whole paths:
    ``*`` and ``?`` stay within one directory, ``**`` crosses any number,
    and ``dir/**`` matches everything under ``dir``.
    """

    name: str
    patterns: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _CLASS_NAME.fullmatch(self.name):
            raise ValueError(f"a path class is named as a table is: {self.name!r}")
        if not self.patterns:
            raise ValueError(f"path class {self.name} matches no path")

    def matches(self, path: str) -> bool:
        return any(glob_match(pattern, path) for pattern in self.patterns)


DEFAULT_CLASSES: Final = (
    PathClass("workflows", (".github/workflows/**", ".gitlab-ci.yml", ".circleci/**")),
    PathClass(
        "governance",
        (
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "docs/CODEOWNERS",
            "SECURITY.md",
            "LICENSE",
            "LICENSE.*",
            ".github/dependabot.yml",
        ),
    ),
    PathClass(
        "infra",
        (
            "infra/**",
            "terraform/**",
            "**/*.tf",
            "Dockerfile",
            "**/Dockerfile",
            "docker-compose*.yml",
            "k8s/**",
            "helm/**",
        ),
    ),
    PathClass(
        "deps",
        (
            "**/pyproject.toml",
            "**/uv.lock",
            "**/poetry.lock",
            "**/requirements*.txt",
            "**/package.json",
            "**/package-lock.json",
            "**/yarn.lock",
            "**/pnpm-lock.yaml",
            "**/go.mod",
            "**/go.sum",
            "**/Cargo.toml",
            "**/Cargo.lock",
        ),
    ),
    PathClass("tests", ("tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/*_test.go")),
    PathClass("src", ("src/**", "lib/**", "app/**")),
    PathClass("docs", ("docs/**", "**/*.md", "**/*.rst")),
)
"""The classes a substrate uses unless told otherwise, first match wins."""


@dataclass(frozen=True, slots=True)
class GitHook:
    """A program the stage runs after each effect, as a trigger runs after a
    statement: a code generator, a formatter, a lockfile refresh.

    :ivar argv: The command, run in the stage's worktree. No shell.
    :ivar when: Globs of the paths that make it run; it runs after every
        effect when empty.
    :ivar sources: Paths it executes or reads as code. A plan may not write
        them, or the hook would run code the plan wrote.
    :ivar env: Variables it gets beyond ``PATH``, ``LANG`` and a ``HOME`` of
        the stage's own: nothing else of the process's environment reaches it.
    :ivar timeout: Seconds it may run before the effect fails.
    """

    name: str
    argv: tuple[str, ...]
    when: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    timeout: float = 60.0

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError(f"a hook's name is a lowercase identifier: {self.name!r}")
        if not self.argv or not all(isinstance(a, str) and a for a in self.argv):
            raise ValueError(f"hook {self.name}: argv names a program and its arguments")
        for source in self.sources:
            problem = path_problem(source)
            if problem is not None:
                raise ValueError(f"hook {self.name}: source {source!r} {problem}")
        if not 0 < self.timeout <= 3600:
            raise ValueError(f"hook {self.name}: timeout is between 0 and 3600 seconds")


# --------------------------------------------------------------------------
# paths and globs
# --------------------------------------------------------------------------

_GLOBS: dict[str, re.Pattern[str]] = {}


def glob_match(pattern: str, path: str) -> bool:
    """Whether ``path`` matches ``pattern`` (see :class:`PathClass`)."""
    compiled = _GLOBS.get(pattern)
    if compiled is None:
        compiled = re.compile(_glob_regex(pattern), re.S)
        _GLOBS[pattern] = compiled
    return compiled.fullmatch(path) is not None


def _glob_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


def path_problem(path: str) -> str | None:
    """Why ``path`` cannot be written by a stage, or ``None``.

    A path is relative, POSIX, within the repository and outside Git's own
    directory: no empty, ``.`` or ``..`` component, no ``.git`` anywhere, no
    backslash or control character.
    """
    if not isinstance(path, str) or not path:
        return "is empty"
    if len(path.encode("utf-8")) > 4096:
        return "is longer than 4096 bytes"
    if path.startswith("/"):
        return "is absolute: paths are relative to the repository's root"
    if "\\" in path or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return "holds a backslash or a control character"
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "has an empty, '.' or '..' component"
    if any(p.lower() == ".git" for p in parts):
        return "reaches into Git's own directory"
    return None


# --------------------------------------------------------------------------
# the statement language
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GitStatement:
    """A statement, parsed: its verb, and each argument as a literal or a
    ``:parameter``."""

    verb: str
    arguments: tuple[tuple[str, str], ...]
    """``("literal", text)`` or ``("parameter", name)``, in order."""

    def bind(self, parameters: Mapping[str, object]) -> dict[str, str]:
        """Each argument by name, its value bound.

        :raises ValueError: On a parameter missing or not a string.
        """
        bound: dict[str, str] = {}
        for name, (kind, value) in zip(VERBS[self.verb], self.arguments, strict=True):
            if kind == "literal":
                bound[name] = value
                continue
            if value not in parameters:
                raise ValueError(f"parameter :{value} is not bound")
            found = parameters[value]
            if not isinstance(found, str):
                raise ValueError(f"parameter :{value} is a {type(found).__name__}, not a string")
            bound[name] = found
        return bound


def parse_statement(statement: str) -> GitStatement:
    """Read one statement of the language (module docstring).

    :raises ValueError: On anything else, naming what is wrong.
    """
    tokens: list[tuple[str, str]] = []
    position = 0
    text = statement.rstrip()
    while position < len(text):
        found = _TOKEN.match(text, position)
        if found is None or found.end() == position:
            raise ValueError(f"cannot read the statement at character {position}")
        quoted, parameter, bare = found.groups()
        if quoted is not None:
            tokens.append(("literal", quoted.replace("''", "'")))
        elif parameter is not None:
            tokens.append(("parameter", parameter[1:]))
        else:
            tokens.append(("bare", bare))
        position = found.end()
    if not tokens or tokens[0][0] != "bare":
        raise ValueError("a statement starts with its verb: " + ", ".join(VERBS))
    verb = tokens[0][1].lower()
    if verb not in VERBS:
        raise ValueError(f"{verb!r} is not a verb of this substrate: one of {', '.join(VERBS)}")
    arguments = tokens[1:]
    wanted = VERBS[verb]
    if len(arguments) != len(wanted):
        raise ValueError(f"{verb} takes {len(wanted)} argument(s): {' '.join(wanted)}")
    for index, (kind, value) in enumerate(arguments, 1):
        if kind == "bare":
            raise ValueError(
                f"argument {index} ({value[:40]!r}) is neither a :parameter nor a 'quoted' literal"
            )
    return GitStatement(verb, tuple(arguments))


# --------------------------------------------------------------------------
# secrets
# --------------------------------------------------------------------------


def _entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def _hits(text: str) -> Counter[tuple[str, str]]:
    found: Counter[tuple[str, str]] = Counter()
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            found[(name, match.group(0))] += 1
    for match in _HIGH_ENTROPY.finditer(text):
        token = match.group(0)
        if _entropy(token) >= _ENTROPY_BITS:
            found[("high_entropy", token)] += 1
    return found


def secret_markers(before: str, after: str) -> int:
    """How many credential-shaped strings ``after`` holds that ``before``
    did not: each pattern of :data:`SECRET_PATTERNS`, and any 32-character
    token of high entropy. Counted as multisets, so a secret moved within a
    file adds nothing and a second copy adds one."""
    return sum((_hits(after) - _hits(before)).values())


# --------------------------------------------------------------------------
# running git
# --------------------------------------------------------------------------

_DROP_ENV: Final = re.compile(r"GIT_.*")


class _Git:
    """``git``, run with argument lists, a timeout and a fixed configuration.

    Every call disables hooks (``core.hooksPath``) and the file-system
    monitor, and reads no system configuration: only the stage's own hooks
    run, and only where the substrate runs them.
    """

    __slots__ = ("_env", "executable", "timeout")

    def __init__(self, executable: str, timeout: float) -> None:
        self.executable = executable
        self.timeout = timeout
        env = {k: v for k, v in os.environ.items() if not _DROP_ENV.fullmatch(k)}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
        self._env = env

    def run(
        self,
        cwd: Path,
        *args: str,
        stdin: bytes | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        argv = [
            self.executable,
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.quotePath=false",
            *args,
        ]
        try:
            done = subprocess.run(  # noqa: S603 - an argument list, never a shell
                argv,
                cwd=cwd,
                input=stdin,
                capture_output=True,
                env={**self._env, **(env or {})},
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SubstrateUnavailableError(
                f"git {args[0]} did not finish within {self.timeout}s"
            ) from exc
        except OSError as exc:
            raise SubstrateUnavailableError(f"cannot run git: {exc}") from exc
        if check and done.returncode != 0:
            raise StageError(
                f"git {args[0]} failed ({done.returncode}): "
                + done.stderr.decode("utf-8", "replace").strip()[:500]
            )
        return done

    def text(self, cwd: Path, *args: str, stdin: bytes | None = None) -> str:
        return self.run(cwd, *args, stdin=stdin).stdout.decode("utf-8", "surrogateescape").strip()


# --------------------------------------------------------------------------
# the substrate
# --------------------------------------------------------------------------


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    base: str
    root: Path
    worktree: Path
    home: Path
    savepoints: list[tuple[str, str]] = field(default_factory=list)
    measured: str | None = None
    """The tree :meth:`GitSubstrate.diff` measured, once it has."""
    control: StageHandle | None = None
    done: bool = False


class GitSubstrate:
    """Transactional staging over a Git branch (module docstring).

    :param repository: The repository: a bare one, or one whose working tree
        does not have ``branch`` checked out.
    :param branch: The branch a commit moves: ``main`` or ``refs/heads/main``.
    :param classes: Path classes, first match wins; a path none matches is
        :data:`FALLBACK_CLASS`.
    :param workspace: The partition of every path no ``owners`` rule names.
        The repository's directory name by default.
    :param owners: ``(glob, owner)`` rules, first match wins: a path's owner
        is its partition.
    :param hooks: What runs after each effect, in order.
    :param control: A SQLite file ``interlock install`` set up: the home of
        the outbox, the inbox and rate windows' history (module docstring).
    :param stage_root: Where stages' worktrees live: in the repository's Git
        directory by default, beside the redo records.
    :param author: The ``(name, email)`` each commit is written by.
    :param git: The ``git`` executable.
    :param max_file_bytes: The largest file a ``write``, ``replace`` or
        ``patch`` may leave.
    :param max_scan_bytes: How much of a file the secret scan reads.
    :raises SubstrateConfigurationError: If ``git`` cannot be found, the
        repository cannot be read, or the branch is not a branch.
    """

    __slots__ = (
        "_author",
        "_by_name",
        "_classes",
        "_common",
        "_control",
        "_git",
        "_hooks",
        "_max_file",
        "_max_rows",
        "_max_scan",
        "_owners",
        "_protected",
        "_ref",
        "_repository",
        "_stage",
        "_stage_root",
        "_stage_seconds",
        "_workspace",
    )

    def __init__(
        self,
        repository: str | os.PathLike[str],
        *,
        branch: str = "main",
        classes: Sequence[PathClass] = DEFAULT_CLASSES,
        workspace: str | None = None,
        owners: Sequence[tuple[str, str]] = (),
        hooks: Sequence[GitHook] = (),
        control: str | os.PathLike[str] | None = None,
        stage_root: str | os.PathLike[str] | None = None,
        author: tuple[str, str] = ("interlock", "interlock@localhost"),
        git: str = "git",
        max_stage_seconds: float = 120.0,
        max_diff_rows: int = 50_000,
        max_file_bytes: int = 4 * 1024 * 1024,
        max_scan_bytes: int = 1024 * 1024,
    ) -> None:
        executable = shutil.which(git)
        if executable is None:
            raise SubstrateConfigurationError(f"cannot find the git executable {git!r}")
        self._git = _Git(executable, timeout=max(30.0, max_stage_seconds))
        self._repository = Path(repository).resolve()
        names = [c.name for c in classes]
        if len(set(names)) != len(names) or FALLBACK_CLASS in names:
            raise ValueError(
                f"path classes are named once each, and none is {FALLBACK_CLASS!r}, the class of "
                f"every path no rule names"
            )
        self._classes = tuple(classes)
        self._by_name = frozenset((*names, FALLBACK_CLASS))
        hook_names = [h.name for h in hooks]
        if len(set(hook_names)) != len(hook_names):
            raise ValueError("hooks are named once each")
        self._hooks = tuple(hooks)
        self._protected = {s: h.name for h in self._hooks for s in h.sources}
        self._owners = tuple(owners)
        self._workspace = workspace or self._repository.name.removesuffix(".git")
        self._author = author
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._max_file = max_file_bytes
        self._max_scan = max_scan_bytes
        ref = branch if branch.startswith("refs/") else f"refs/heads/{branch}"
        try:
            self._git.run(self._repository, "check-ref-format", ref)
            common = self._git.text(
                self._repository, "rev-parse", "--path-format=absolute", "--git-common-dir"
            )
        except StageError as exc:
            raise SubstrateConfigurationError(
                f"{self._repository} is not a repository with a branch {ref}: {exc}"
            ) from exc
        self._ref = ref
        self._common = Path(common)
        self._stage_root = (
            Path(stage_root) if stage_root is not None else self._common / "interlock" / "stages"
        )
        self._control = (
            SqliteSubstrate(str(control), tables=(), max_stage_seconds=max_stage_seconds)
            if control is not None
            else None
        )
        self._stage: _Stage | None = None

    # -- what it is ---------------------------------------------------------

    @property
    def substrate_id(self) -> str:
        return "git"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=True,
            row_level_diff=True,
            snapshot_isolation=True,
            requires_compensation=False,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            outbound=self._control is not None and self._control.capabilities.outbound,
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        """Every path class. Every path falls in one, so nothing a stage
        writes in the repository goes unmeasured."""
        return self._by_name

    @property
    def commit_markers(self) -> bool:
        """Always: the trailer is part of the commit."""
        return True

    @property
    def repository(self) -> Path:
        return self._repository

    @property
    def ref(self) -> str:
        """The branch a commit moves, as a full ref."""
        return self._ref

    @property
    def control(self) -> str | None:
        """The control database's path, when there is one."""
        return None if self._control is None else self._control.path

    def head(self) -> str:
        """The commit the branch is at now.

        :raises SubstrateUnavailableError: If the branch does not exist.
        """
        done = self._git.run(
            self._repository, "rev-parse", "--verify", "--quiet", f"{self._ref}^{{commit}}"
        )
        sha = done.stdout.decode().strip()
        if not _COMMIT.fullmatch(sha):  # pragma: no cover - rev-parse --verify said yes
            raise SubstrateUnavailableError(f"{self._ref} does not name a commit")
        return sha

    def classify(self, path: str) -> str:
        """The class of ``path``: its table."""
        for path_class in self._classes:
            if path_class.matches(path):
                return path_class.name
        return FALLBACK_CLASS

    def owner(self, path: str) -> str:
        """The partition of ``path``."""
        for pattern, owner in self._owners:
            if glob_match(pattern, path):
                return owner
        return self._workspace

    # -- vetting --------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from its statement: one of
        :data:`VERBS`, its arguments literals or bound strings, each path one a
        stage may write (:func:`path_problem`) and no hook's source."""
        try:
            statement = parse_statement(effect.statement)
            bound = statement.bind(effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        if "path" in bound:
            problem = self._write_problem(bound["path"])
            if problem is not None:
                return problem
        if statement.verb == "mode" and bound["mode"] not in _MODES:
            return f"mode is {' or '.join(_MODES)}"
        if statement.verb == "expect-head" and not _COMMIT.fullmatch(bound["commit"]):
            return "expect-head names a whole commit id, in lowercase hex"
        return None

    def _write_problem(self, path: str) -> str | None:
        problem = path_problem(path)
        if problem is not None:
            return f"path {path[:120]!r} {problem}"
        hook = self._protected.get(path)
        if hook is not None:
            return (
                f"path {path!r} is a source of hook {hook}: a plan may not write code a hook runs"
            )
        return None

    # -- lifecycle ----------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Record the branch's head as the stage's base, and check a worktree
        out at it. With a control database, first finish any commit a crashed
        process left half-done there.

        :raises StageConflictError: If a stage is already open here.
        :raises SubstrateConfigurationError: If the branch is checked out in a
            worktree, which moving it would leave behind.
        """
        if self._stage is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage "
                f"{self._stage.handle.stage_id} open"
            )
        self._settle_redo()
        self._refuse_checked_out()
        base = self.head()
        stage_id = uuid.uuid4()
        root = self._stage_root / str(stage_id)
        worktree, home = root / "worktree", root / "home"
        try:
            home.mkdir(parents=True)
        except OSError as exc:
            raise SubstrateUnavailableError(f"cannot create {root}: {exc}") from exc
        try:
            self._git.run(self._repository, "worktree", "prune")
            self._git.run(self._repository, "worktree", "add", "--detach", str(worktree), base)
        except StageError:
            shutil.rmtree(root, ignore_errors=True)
            raise
        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=stage_id,
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        self._stage = _Stage(handle, plan, base, root, worktree, home)
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Apply one effect in the stage's worktree, then run the hooks it
        sets off. Never commits.

        :raises ForbiddenStatementError: On a statement :meth:`reject_reason`
            refuses.
        :raises StageConflictError: On ``expect-head`` naming a commit other
            than the stage's base.
        :raises StageError: On an operation that cannot be done (a
            ``replace`` whose text occurs other than once, a ``delete`` of a
            file that is not there, a patch that does not apply) or a hook
            that fails.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            if self._control is None:
                raise OutboundRequestError(
                    f"effect {effect.effect_id!r} is an outbound request, and this Git "
                    f"substrate has no control database to hold an outbox",
                    reason="substrate",
                    sink=effect.request.sink if effect.request is not None else None,
                )
            return self._control.apply(self._control_stage(stage), effect)
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(
                f"effect {effect.effect_id!r} refused: {refusal}", reason="statement_kind"
            )
        statement = parse_statement(effect.statement)
        bound = statement.bind(effect.parameters)
        touched = self._operate(stage, effect, statement.verb, bound)
        self._run_hooks(stage, touched)
        if self._control is not None and stage.control is not None:
            self._control.applied_elsewhere(stage.control, effect)
        stage.measured = None
        return EffectOutcome(
            effect_id=effect.effect_id, rows_affected=len(touched), applied_at=datetime.now(UTC)
        )

    def _operate(
        self, stage: _Stage, effect: Effect, verb: str, bound: Mapping[str, str]
    ) -> list[str]:
        """Do one operation; the paths it wrote."""
        where = f"effect {effect.effect_id!r}"
        if verb == "expect-head":
            if bound["commit"] != stage.base:
                raise StageConflictError(
                    f"{where}: {self._ref} is at {stage.base[:12]}, not at "
                    f"{bound['commit'][:12]}, the commit the plan names: the state it was "
                    f"approved on is gone"
                )
            return []
        if verb == "patch":
            return self._patch(stage, where, bound["diff"])
        path = bound["path"]
        target = self._inside(stage, where, path)
        if verb == "write":
            data = bound["text"].encode("utf-8")
            self._bounded(where, path, len(data))
            target.parent.mkdir(parents=True, exist_ok=True)
            fresh = not target.exists()
            target.write_bytes(data)
            if fresh:
                target.chmod(0o644)
        elif verb == "replace":
            text = self._read_text(where, target, path)
            count = text.count(bound["old"])
            if count != 1:
                raise StageError(
                    f"{where}: replace finds its text {count} times in {path}; it replaces "
                    f"exactly one occurrence"
                )
            data = text.replace(bound["old"], bound["new"], 1).encode("utf-8")
            self._bounded(where, path, len(data))
            target.write_bytes(data)
        elif verb == "delete":
            if not target.is_file():
                raise StageError(f"{where}: there is no file {path} to delete")
            target.unlink()
        else:  # mode
            if not target.is_file():
                raise StageError(f"{where}: there is no file {path} to change the mode of")
            target.chmod(_MODES[bound["mode"]])
        return [path]

    def _inside(self, stage: _Stage, where: str, path: str) -> Path:
        """``path`` in the worktree, through no symbolic link."""
        current = stage.worktree
        for part in path.split("/"):
            current = current / part
            if current.is_symlink():
                raise ForbiddenStatementError(
                    f"{where} refused: {path} passes through a symbolic link, which could lead "
                    f"outside the repository",
                    reason="statement_kind",
                )
        return current

    def _read_text(self, where: str, target: Path, path: str) -> str:
        if not target.is_file():
            raise StageError(f"{where}: there is no file {path} to edit")
        try:
            return target.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StageError(f"{where}: {path} is not UTF-8 text") from exc

    def _bounded(self, where: str, path: str, size: int) -> None:
        if size > self._max_file:
            raise StageError(
                f"{where}: {path} would be {size} bytes, past the {self._max_file} a stage writes"
            )

    def _patch(self, stage: _Stage, where: str, diff: str) -> list[str]:
        data = diff.encode("utf-8")
        listed = self._git.run(stage.worktree, "apply", "--numstat", "-z", "-", stdin=data)
        paths = [p for p in _numstat_paths(listed.stdout) if p]
        summary = self._git.text(stage.worktree, "apply", "--summary", "-", stdin=data)
        if re.search(r"mode (?:120000|160000)", summary):
            raise ForbiddenStatementError(
                f"{where} refused: the patch creates a symbolic link or a submodule",
                reason="statement_kind",
            )
        if re.search(r"^\s*(?:rename|copy) ", summary, re.M):
            raise ForbiddenStatementError(
                f"{where} refused: the patch renames or copies a file; write the new path and "
                f"delete the old one",
                reason="statement_kind",
            )
        for path in paths:
            problem = self._write_problem(path)
            if problem is not None:
                raise ForbiddenStatementError(
                    f"{where} refused: {problem}", reason="statement_kind"
                )
            self._inside(stage, where, path)
        self._git.run(stage.worktree, "apply", "--whitespace=nowarn", "-", stdin=data)
        for path in paths:
            target = stage.worktree / path
            if target.is_file():
                self._bounded(where, path, target.stat().st_size)
        return paths

    def _run_hooks(self, stage: _Stage, touched: Sequence[str]) -> None:
        for hook in self._hooks:
            if hook.when and not any(glob_match(g, p) for g in hook.when for p in touched):
                continue
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": str(stage.home),
                "TMPDIR": str(stage.home),
                "PYTHONDONTWRITEBYTECODE": "1",
                **hook.env,
            }
            try:
                done = subprocess.run(  # noqa: S603 - operator-configured argv, no shell
                    list(hook.argv),
                    cwd=stage.worktree,
                    env=env,
                    capture_output=True,
                    timeout=hook.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise StageError(f"hook {hook.name} ran past its {hook.timeout}s") from exc
            except OSError as exc:
                raise StageError(f"hook {hook.name} could not run: {exc}") from exc
            if done.returncode != 0:
                raise StageError(
                    f"hook {hook.name} failed ({done.returncode}): "
                    + done.stderr.decode("utf-8", "replace").strip()[:500]
                )

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Measure the worktree against the base: every path any effect or
        hook changed, added or removed, ignored files apart. Not from the
        plan: from Git's own index of the worktree."""
        stage = self._require(handle)
        tree = self._stage_tree(stage)
        stage.measured = tree
        changes = _raw_changes(
            self._git.run(
                stage.worktree,
                "diff-index",
                "--cached",
                "--raw",
                "-z",
                "--no-renames",
                "--no-abbrev",
                stage.base,
            ).stdout
        )
        counts = _numstat(
            self._git.run(
                stage.worktree,
                "diff-index",
                "--cached",
                "--numstat",
                "-z",
                "--no-renames",
                stage.base,
            ).stdout
        )
        truncated = len(changes) > self._max_rows
        changes = changes[: self._max_rows]
        blobs = self._blobs(
            stage.worktree,
            {sha for c in changes for sha in (c.old_sha, c.new_sha) if not _ZERO.fullmatch(sha)},
        )
        deltas = []
        for change in changes:
            added, deleted = counts.get(change.path, (0, 0))
            before = None
            if change.status != "A":
                before = self._image(change.path, change.old_sha, change.old_mode, 0, 0, 0)
            after = None
            if change.status != "D":
                old = "" if change.status == "A" else blobs.get(change.old_sha, "")
                markers = secret_markers(old, blobs.get(change.new_sha, ""))
                after = self._image(
                    change.path, change.new_sha, change.new_mode, added, deleted, markers
                )
            deltas.append(
                RowDelta(
                    table=self.classify(change.path),
                    primary_key=change.path,
                    before=before,
                    after=after,
                    tenant_id=self.owner(change.path),
                )
            )
        outbound: tuple[OutboundDelta, ...] = ()
        facts: tuple[InboundFact, ...] = ()
        if self._control is not None and stage.control is not None:
            control = self._control.diff(stage.control)
            outbound, facts = control.outbound, control.facts
            truncated = truncated or control.truncated
        return EffectDiff(
            plan_id=handle.plan_id,
            stage_id=handle.stage_id,
            substrate_id=self.substrate_id,
            computed_at=datetime.now(UTC),
            deltas=tuple(deltas),
            truncated=truncated,
            outbound=outbound,
            facts=facts,
        )

    @staticmethod
    def _image(
        path: str, blob: str, mode: str, added: int, deleted: int, markers: int
    ) -> dict[str, Any]:
        return {
            "path": path,
            "blob_sha": blob,
            "mode": mode,
            "lines_added": added,
            "lines_deleted": deleted,
            "net_lines": added - deleted,
            "secret_markers": markers,
        }

    def _stage_tree(self, stage: _Stage) -> str:
        """Index everything in the worktree, ignored files apart, and the tree
        that makes."""
        self._git.run(stage.worktree, "add", "--all")
        return self._git.text(stage.worktree, "write-tree")

    def _blobs(self, cwd: Path, shas: set[str]) -> dict[str, str]:
        """Each blob's text, as far as the secret scan reads; binary files as
        empty."""
        if not shas:
            return {}
        ordered = sorted(shas)
        done = self._git.run(
            cwd, "cat-file", "--batch", stdin="".join(f"{s}\n" for s in ordered).encode()
        )
        out, found, position = done.stdout, {}, 0
        for sha in ordered:
            end = out.index(b"\n", position)
            header = out[position:end].split()
            if len(header) != 3:  # "<sha> missing": no body follows
                position = end + 1
                continue
            size = int(header[2])
            body = out[end + 1 : end + 1 + size]
            position = end + 1 + size + 1
            sample = body[: self._max_scan]
            found[sha] = "" if b"\x00" in sample else sample.decode("utf-8", "replace")
        return found

    # -- the control database -------------------------------------------------

    def _control_stage(self, stage: _Stage) -> StageHandle:
        """The stage's stage in the control database, opened on first need,
        under the same id."""
        assert self._control is not None
        if stage.control is None:
            stage.control = self._control.open(stage.plan, stage_id=stage.handle.stage_id)
        return stage.control

    def pending_facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        """The facts pending for ``scope_id`` in the control database's inbox;
        none without one."""
        if self._control is None:
            return ()
        return self._control.pending_facts(scope_id)

    def consume_facts(
        self, handle: StageHandle, fact_ids: Sequence[uuid.UUID], scope_id: str
    ) -> None:
        """Consume the plan's facts in the control database's stage.

        :raises InboundFactError: Without a control database.
        """
        stage = self._require(handle)
        if self._control is None:
            raise InboundFactError(
                "this Git substrate has no control database, so no inbox to consume a fact from"
            )
        self._control.consume_facts(self._control_stage(stage), fact_ids, scope_id)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        """What each window holds, read in the control database's stage, which
        holds its write lock from here to the commit.

        :raises SubstrateConfigurationError: Without a control database.
        """
        stage = self._require(handle)
        if self._control is None:
            raise SubstrateConfigurationError(
                "rate windows keep their history in a control database, and this Git "
                "substrate has none"
            )
        return self._control.measure_windows(self._control_stage(stage), charges)

    # -- commit and recovery ----------------------------------------------------

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Write the measured tree as a commit on the base, with the stage's
        trailer, and move the branch to it only if it is still at the base.

        With a control database the move happens inside the control stage's
        transaction, just before its ``COMMIT``, after a redo record of that
        transaction is on disk.

        :raises StageError: If the worktree no longer holds what was measured.
        :raises StageConflictError: If the branch moved since the stage opened:
            nothing is committed, in Git or in the control database.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if stage.measured is None:
            raise StageError(f"stage {handle.stage_id} is committed before it is measured")
        if self._stage_tree(stage) != stage.measured:
            raise StageError(
                f"stage {handle.stage_id}: the worktree changed after it was measured; what "
                f"would commit is not what was judged"
            )
        changed = self._tree_of(stage.base) != stage.measured
        committed_at = datetime.now(UTC)
        new = self._commit_object(stage, committed_at) if changed else None

        attempted = False

        def move(conn: sqlite3.Connection | None) -> None:
            nonlocal attempted
            if new is None:
                return
            redo = self._write_redo(stage, new, conn) if conn is not None else None
            attempted = True
            try:
                self._swap(stage, new)
            except StageConflictError:
                # Git said no: the branch did not move, so there is nothing
                # for a redo to finish.
                if redo is not None:
                    redo.unlink(missing_ok=True)
                raise

        try:
            if self._control is None:
                move(None)
            else:
                self._control.commit(self._control_stage(stage), prepare=move)
        except StageConflictError:
            raise
        except Exception as exc:
            if not attempted:
                raise
            # The swap was attempted and did not report a refusal: the branch
            # may have moved. The control database's half is in the redo
            # record; roll its open transaction back so recovery can write it,
            # and let recovery read the branch for what happened.
            if self._control is not None and stage.control is not None:
                self._control.abort(stage.control)
            raise CommitUnsettledError(
                f"stage {handle.stage_id}: whether {self._ref} moved, and the control "
                f"database's half committed, is for recovery to settle: {exc}"
            ) from exc
        if self._control is not None:
            self._redo_path(handle.stage_id).unlink(missing_ok=True)
        stage.done = True
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=committed_at,
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=new,
        )

    def _tree_of(self, commit: str) -> str:
        return self._git.text(self._repository, "rev-parse", f"{commit}^{{tree}}")

    def _commit_object(self, stage: _Stage, at: datetime) -> str:
        subject = re.sub(r"\s+", " ", stage.plan.intent).strip()[:72] or "a staged plan"
        plan = re.sub(r"[^A-Za-z0-9._:-]", "_", str(stage.plan.plan_id))[:128]
        message = (
            f"interlock: {subject}\n\n"
            f"{PLAN_TRAILER}: {plan}\n"
            f"{STAGE_TRAILER}: {stage.handle.stage_id}\n"
        )
        name, email = self._author
        stamp = f"{int(at.timestamp())} +0000"
        identity = {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_COMMITTER_DATE": stamp,
        }
        done = self._git.run(
            stage.worktree,
            "commit-tree",
            str(stage.measured),
            "-p",
            stage.base,
            "-F",
            "-",
            stdin=message.encode("utf-8"),
            env=identity,
        )
        return done.stdout.decode().strip()

    def _swap(self, stage: _Stage, new: str) -> None:
        done = self._git.run(
            self._repository,
            "update-ref",
            "--create-reflog",
            "-m",
            f"interlock: stage {stage.handle.stage_id}",
            self._ref,
            new,
            stage.base,
            check=False,
        )
        if done.returncode != 0:
            raise StageConflictError(
                f"stage {stage.handle.stage_id}: {self._ref} moved since the stage measured it "
                f"at {stage.base[:12]}; nothing was committed. "
                + done.stderr.decode("utf-8", "replace").strip()[:300]
            )

    def resolve_intent(self, stage_id: uuid.UUID) -> bool | None:
        """Whether a stage committed, read from Git and the control database.

        A commit carrying the stage's trailer in the branch's history means
        it did. So does a control-database marker, for a stage that changed no
        file. A redo record left by a crash is settled first: the branch
        holding its commit means the stage committed, and the control
        database's half is written now; otherwise the record is dropped.

        A commit a force-push later removed from the branch reads as not
        committed: :func:`reconcile_git` names the rewrite.

        :raises SubstrateUnavailableError: If the repository cannot be read.
        """
        settled = self._settle_redo(only=stage_id)
        if settled is not None:
            return settled
        if self._commit_of(stage_id) is not None:
            return True
        if self._control is not None:
            found = self._control.resolve_intent(stage_id)
            return bool(found)
        return False

    def _commit_of(self, stage_id: uuid.UUID) -> str | None:
        """The commit on the branch carrying ``stage_id``'s trailer."""
        done = self._git.run(
            self._repository,
            "log",
            "-z",
            "--fixed-strings",
            f"--grep={STAGE_TRAILER}: {stage_id}",
            f"--format=%H%x1f%(trailers:key={STAGE_TRAILER},valueonly,separator=%x1f)",
            self._ref,
            "--",
        )
        for record in done.stdout.decode("utf-8", "replace").split("\0"):
            sha, _, values = record.strip("\n").partition("\x1f")
            if str(stage_id) in (v.strip() for v in values.split("\x1f")):
                return sha
        return None

    def _contains(self, commit: str) -> bool:
        done = self._git.run(
            self._repository, "merge-base", "--is-ancestor", commit, self._ref, check=False
        )
        return done.returncode == 0

    # -- the redo record ------------------------------------------------------

    _REDO_TABLES: Final = (
        (_MARKER_TABLE, "stage_id = :stage"),
        (OUTBOX, "stage_id = :stage"),
        (STATE, f"message_id IN (SELECT message_id FROM {OUTBOX} WHERE stage_id = :stage)"),
        (TRACES, f"message_id IN (SELECT message_id FROM {OUTBOX} WHERE stage_id = :stage)"),
        (SQLITE_CONSUMED, "stage_id = :stage"),
        (WINDOWS_TABLE, "stage_id = :stage"),
        (STAGE_JOURNAL_TABLE, "stage_id = :stage"),
    )
    """What a control stage writes, in the order a redo writes it again."""

    def _redo_path(self, stage_id: uuid.UUID) -> Path:
        return self._common / "interlock" / "redo" / f"{stage_id}.json"

    def _write_redo(self, stage: _Stage, new: str, conn: sqlite3.Connection) -> Path:
        """Every row the control stage holds, on disk before the branch moves."""
        tables: dict[str, list[dict[str, Any]]] = {}
        for table, where in self._REDO_TABLES:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            if exists is None:
                continue
            cursor = conn.execute(
                f"SELECT * FROM main.{table} WHERE {where}",
                {"stage": str(stage.handle.stage_id)},
            )
            columns = [c[0] for c in cursor.description]
            rows = [dict(zip(columns, map(_jsonable, row), strict=True)) for row in cursor]
            if rows:
                tables[table] = rows
        record = {
            "stage_id": str(stage.handle.stage_id),
            "ref": self._ref,
            "base": stage.base,
            "commit": new,
            "tables": tables,
        }
        path = self._redo_path(stage.handle.stage_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _durable_write(path, json.dumps(record, sort_keys=True).encode("utf-8"))
        return path

    def _settle_redo(self, *, only: uuid.UUID | None = None) -> bool | None:
        """Finish or drop each redo record a crash left: the commit it names
        on the branch means the control database's half is written now.

        :returns: For ``only``, whether that stage committed, or ``None`` when
            there was no record of it.
        """
        directory = self._common / "interlock" / "redo"
        if self._control is None or not directory.is_dir():
            return None
        answer: bool | None = None
        for path in sorted(directory.glob("*.json")):
            if only is not None and path.stem != str(only):
                continue
            record = json.loads(path.read_bytes())
            if record.get("ref") != self._ref:
                continue
            landed = self._contains(str(record["commit"]))
            if landed:
                self._redo(record)
            path.unlink(missing_ok=True)
            logger.warning(
                "stage %s: a redo record from a crash was %s",
                record["stage_id"],
                "replayed: its commit is on the branch"
                if landed
                else "dropped: its commit never reached the branch",
            )
            if only is not None:
                answer = landed
        return answer

    def _redo(self, record: Mapping[str, Any]) -> None:
        """Write a redo record's rows, once: nothing, when its marker is there."""
        assert self._control is not None
        path = self._control.path
        try:
            conn = sqlite3.connect(path, isolation_level=None, timeout=self._stage_seconds)
        except sqlite3.Error as exc:
            raise SubstrateUnavailableError(f"cannot open {path}: {exc}") from exc
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            present = conn.execute(
                f"SELECT 1 FROM main.{_MARKER_TABLE} WHERE stage_id = ?",
                (str(record["stage_id"]),),
            ).fetchone()
            if present is None:
                for table, _ in self._REDO_TABLES:
                    for row in record["tables"].get(table, ()):
                        columns = sorted(row)
                        conn.execute(
                            f"INSERT INTO main.{table} ({', '.join(columns)}) "
                            f"VALUES ({', '.join('?' for _ in columns)})",
                            [_from_json(row[c]) for c in columns],
                        )
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise StageError(
                f"stage {record['stage_id']}: its commit is on the branch and its control "
                f"rows could not be written again: {exc}"
            ) from exc
        finally:
            conn.close()

    # -- savepoints -----------------------------------------------------------

    def savepoint(self, handle: StageHandle, name: str) -> None:
        """Mark the worktree's state now (as a tree), and the control stage's,
        to return to with :meth:`rollback_to`."""
        stage = self._require(handle)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise ValueError(f"unsafe savepoint name: {name!r}")
        stage.savepoints.append((name, self._stage_tree(stage)))
        if self._control is not None:
            self._control.savepoint(self._control_stage(stage), name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        """Put the worktree back as it was at savepoint ``name``, files any
        hook wrote since included; the mark stays."""
        stage = self._require(handle)
        tree = self._savepoint(stage, name)
        self._git.run(stage.worktree, "read-tree", "--reset", "-u", tree)
        self._git.run(stage.worktree, "clean", "-ffdxq")
        stage.measured = None
        if self._control is not None:
            self._control.rollback_to(self._control_stage(stage), name)

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        """Forget mark ``name`` and every mark after it, keeping the work."""
        stage = self._require(handle)
        self._savepoint(stage, name)
        index = max(i for i, (n, _) in enumerate(stage.savepoints) if n == name)
        del stage.savepoints[index:]
        if self._control is not None:
            self._control.release_savepoint(self._control_stage(stage), name)

    def _savepoint(self, stage: _Stage, name: str) -> str:
        for found, tree in reversed(stage.savepoints):
            if found == name:
                return tree
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage -------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        """Discard the stage's work: the control stage rolls back, and the
        worktree goes with :meth:`close`. Safe in any state, including after a
        commit."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        stage.done = True
        if self._control is not None and stage.control is not None:
            self._control.abort(stage.control)

    def close(self, handle: StageHandle) -> None:
        """Remove the stage's worktree, rolling back first if still open."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        self.abort(handle)
        if self._control is not None and stage.control is not None:
            self._control.close(stage.control)
        with contextlib.suppress(StageError, SubstrateUnavailableError):
            self._git.run(
                self._repository, "worktree", "remove", "--force", str(stage.worktree), check=False
            )
        shutil.rmtree(stage.root, ignore_errors=True)
        with contextlib.suppress(StageError, SubstrateUnavailableError):
            self._git.run(self._repository, "worktree", "prune", check=False)
        self._stage = None

    # -- internals ------------------------------------------------------------

    def _require(self, handle: StageHandle) -> _Stage:
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id or stage.done:
            raise StageError(f"stage {handle.stage_id} is not open on this substrate")
        return stage

    def _assert_live(self, handle: StageHandle) -> None:
        if datetime.now(UTC) > handle.expires_at:
            raise StageExpiredError(
                f"stage {handle.stage_id} exceeded its {self._stage_seconds}s bound"
            )

    def _refuse_checked_out(self) -> None:
        listing = self._git.text(self._repository, "worktree", "list", "--porcelain")
        current: str | None = None
        for line in listing.splitlines():
            if line.startswith("worktree "):
                current = line[len("worktree ") :]
            elif line == f"branch {self._ref}":
                raise SubstrateConfigurationError(
                    f"{self._ref} is checked out at {current}: moving it would leave that "
                    f"worktree behind. Point the substrate at a bare repository, or at a branch "
                    f"no worktree has checked out"
                )


# --------------------------------------------------------------------------
# reading git's output
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Change:
    old_mode: str
    new_mode: str
    old_sha: str
    new_sha: str
    status: str
    path: str


def _raw_changes(output: bytes) -> list[_Change]:
    """``diff-index --raw -z``: ``:old new old_sha new_sha status NUL path NUL``."""
    fields = output.split(b"\0")
    changes = []
    i = 0
    while i < len(fields) - 1:
        meta = fields[i].decode()
        if not meta.startswith(":"):
            i += 1
            continue
        old_mode, new_mode, old_sha, new_sha, status = meta[1:].split()
        path = fields[i + 1].decode("utf-8", "surrogateescape")
        changes.append(_Change(old_mode, new_mode, old_sha, new_sha, status[0], path))
        i += 2
    return sorted(changes, key=lambda c: c.path)


def _numstat(output: bytes) -> dict[str, tuple[int, int]]:
    """``--numstat -z``: ``added TAB deleted TAB path NUL``; binary as 0, 0."""
    found: dict[str, tuple[int, int]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        added, deleted, path = record.decode("utf-8", "surrogateescape").split("\t", 2)
        found[path] = (
            int(added) if added.isdigit() else 0,
            int(deleted) if deleted.isdigit() else 0,
        )
    return found


def _numstat_paths(output: bytes) -> list[str]:
    return [
        record.decode("utf-8", "surrogateescape").split("\t", 2)[2]
        for record in output.split(b"\0")
        if record.count(b"\t") >= 2
    ]


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode("ascii")}
    return value


def _from_json(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"b64"}:
        return base64.b64decode(str(value["b64"]))
    return value


def _durable_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` so it is on disk, whole, when this returns."""
    temporary = path.with_suffix(".tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# --------------------------------------------------------------------------
# reconciliation
# --------------------------------------------------------------------------


def reconcile_git(
    substrate: GitSubstrate, records: Iterable[EscrowRecord], *, since: str
) -> Reconciliation:
    """Every commit on the branch since ``since`` has a stage the chains
    record as committed, or is named (the Git twin of
    :func:`~interlock.reconcile.reconcile_sqlite`).

    - **An unmediated commit**: one with no stage trailer. A push, a merge
      in a web interface, or anyone's credentials used directly.
    - **A rewrite**: ``since`` is no longer in the branch's history, so a
      force-push replaced what was there; every stage committed since is in
      doubt.
    - **A stage the chains do not account for**: unrecorded, recorded as
      aborted or under another plan, or holding only its commit intent.

    :param since: The commit the branch was at when the substrate took it
        over, or when it was last reconciled clean.
    """
    git = substrate._git
    repository = substrate.repository
    head = substrate.head()
    unmediated: list[UnmediatedWrite] = []
    if not substrate._contains(since):
        unmediated.append(
            UnmediatedWrite(
                entry=0,
                table=substrate.ref,
                primary_key=since,
                operation="rewrite",
                at=datetime.now(UTC).isoformat(),
                transaction=head,
            )
        )
        span = head
    else:
        span = f"{since}..{head}"
    log = git.run(
        repository,
        "log",
        "-z",
        "--reverse",
        "--format=%H%x1f%aI%x1f%an <%ae>%x1f"
        f"%(trailers:key={STAGE_TRAILER},valueonly,separator=%x1f)%x1e"
        f"%(trailers:key={PLAN_TRAILER},valueonly,separator=%x1f)",
        span,
        "--",
    ).stdout.decode("utf-8", "replace")
    committed: list[tuple[str, str]] = []
    commits = [r for r in log.split("\0") if r.strip()]
    for index, record in enumerate(commits, 1):
        head_part, _, plans = record.strip("\n").partition("\x1e")
        sha, at, actor, stages = [*head_part.split("\x1f", 3), "", "", ""][:4]
        stage_ids = [s.strip() for s in stages.split("\x1f") if s.strip()]
        plan_ids = [p.strip() for p in plans.split("\x1f") if p.strip()]
        if len(stage_ids) != 1:
            unmediated.append(
                UnmediatedWrite(
                    entry=index,
                    table=substrate.ref,
                    primary_key=sha,
                    operation="commit" if not stage_ids else "commit naming several stages",
                    at=at,
                    actor=actor,
                )
            )
            continue
        committed.append((stage_ids[0], plan_ids[0] if plan_ids else ""))
    return Reconciliation(
        substrate=f"git {repository} {substrate.ref}",
        stages_checked=len(committed),
        writes_checked=len(commits),
        unmediated=tuple(unmediated),
        stages=_stage_findings(committed, records),
        unjournaled=(),
        last_entry=len(commits),
    )
