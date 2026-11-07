"""A directory as a transactional substrate (class T, 1.5.0): stage an agent's file changes in a
private copy, measure the copy, and commit only onto the exact files that were measured.

This is the substrate for agents that edit a workspace rather than a database: a coding agent
working in a checkout, an ops agent changing a service's ``config/`` directory, a release agent
rewriting ``deploy/``. The guarantee is the one :class:`~interlock.substrate.SqliteSubstrate`
gives: what was measured is exactly what commits, or nothing commits.

**How a stage works.**

- ``open`` copies the workspace into a stage directory of its own and hashes every file in it.
  Those hashes are the stage's *base*: the state a measurement, a check and a warrant refer to.
- Each effect edits the copy, never the workspace. Hooks you configure (a formatter, a code
  generator) run in the copy after each effect, the way triggers run after a statement.
- ``diff`` walks the copy and compares every file with the base. Nothing is taken from the plan:
  a file a hook wrote is measured like a file the plan wrote.
- ``commit`` takes the workspace's commit lock and checks that every file the diff touches is
  still at its base hash. If anything moved (a person's edit, another agent), nothing is written
  and the stage fails. Otherwise the change lands in one of two ways.

**Two commit modes.**

- ``swap``: the workspace is a symbolic link to a version directory. The stage's copy becomes the
  next version, and the commit renames a new link over the old one. ``rename(2)`` is atomic, so a
  reader sees the old tree or the new tree and never a mix. Before swapping, the whole base
  version is re-hashed, so an edit made in place is caught too. Old versions are kept
  (``keep_versions``) for rollback. :func:`prepare_swap` converts a plain directory.
- ``in-place`` (the default): an ordinary directory. Each changed file is written to a temporary
  file beside it and renamed over it, so no file is ever half-written. The set of changes is
  journaled first: if the process dies part-way, the next stage (or recovery) finishes the
  commit. If the commit fails while the process is alive, the files already replaced are put
  back. Readers may see some files new and others old for the moment the commit takes; use
  ``swap`` when that matters.

**What a diff holds.** Each changed file is one :class:`~interlock.types.RowDelta`, so every
built-in checker reads a workspace diff as it reads a SQL one:

- **table**: the file's *path class* (:class:`~interlock.git_substrate.PathClass`), first match
  wins: ``secrets`` (``.env``, ``.ssh/``, keys and credential files), ``workflows``,
  ``governance``, ``infra``, ``deps``, ``scripts``, ``tests``, ``src``, ``config``, ``docs``, and
  ``other`` for any path no rule names. ``TableAllowlist`` keeps a plan out of classes its
  mandate does not grant, ``NoDelete`` out of deletions, ``BlastRadius`` to a number of files.
- **primary key**: the path, relative to the workspace.
- **partition** (``tenant_id``): the workspace's name, or the owner an ``owners`` rule names.
- **columns** (:data:`COLUMNS`): ``path``, ``sha256``, ``mode``, ``bytes``, ``lines_added``,
  ``lines_deleted``, ``net_lines`` and ``secret_markers``. The before image holds the base
  file's hash, mode and size with zero counts. The after image holds the new file's, with the
  change's line counts and the number of credential-shaped strings it adds
  (:func:`~interlock.git_substrate.secret_markers`). Only the count is kept, never the text.
  A deleted file has no after image.

**Statements.** One operation each, with arguments that are ``:parameters`` or ``'quoted'``
literals (``''`` escapes a quote), so a FIDU1 tool binding can pin a statement as it pins SQL::

    write :path :text              create or replace a file
    append :path :text             add text to the end of a file (creating it if absent)
    replace :path :old :new        replace the one occurrence of old in a file
    delete :path                   remove a file
    move :path :to                 rename a file; nothing may be at the new path
    mode :path :mode               600, 640, 644, 700, 750 or 755
    expect-hash :path :sha256      refuse unless the base holds the file at that SHA-256
                                   ('absent': refuse unless there is no such file)

``expect-hash`` pins a plan to the file its approvers saw, as ``expect-head`` does on Git.

**What is refused outright:** a path that is absolute, holds ``..``, a backslash or a control
character, reaches into ``.git``, passes through a symbolic link, matches an ``ignore`` rule, or
is a source a hook runs. Writing through a link could leave the workspace; writing an ignored
path would go unmeasured.

**The control database.** Rate windows, the outbox and the inbox need a transactional home a
directory does not have. With ``control`` naming a SQLite file that ``interlock install`` set
up, they are kept there, and the file commit happens inside that database's transaction, just
before its ``COMMIT``, after a redo record of it is on disk (:mod:`interlock.control`).

**What a stage does not contain:** a hook is operator code. It runs in the stage's copy with a
scrubbed environment and a timeout, and it can reach whatever the process can.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, NamedTuple

from interlock.control import capture, durable_write, replay
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
from interlock.git_substrate import GitHook, PathClass, glob_match, path_problem, secret_markers
from interlock.substrate import SqliteSubstrate, TableSpec
from interlock.text import tally
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

try:  # POSIX: the commit lock is an advisory flock on the state directory's lock file
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "COLUMNS",
    "DEFAULT_CLASSES",
    "FALLBACK_CLASS",
    "MODES",
    "VERBS",
    "FilesystemStatement",
    "FilesystemSubstrate",
    "filesystem_tables",
    "parse_statement",
    "prepare_swap",
]

logger = logging.getLogger("interlock.filesystem")

COLUMNS: Final = (
    "path",
    "sha256",
    "mode",
    "bytes",
    "lines_added",
    "lines_deleted",
    "net_lines",
    "secret_markers",
)
"""The columns of every file's before and after image."""

FALLBACK_CLASS: Final = "other"

VERBS: Final[Mapping[str, tuple[str, ...]]] = {
    "write": ("path", "text"),
    "append": ("path", "text"),
    "replace": ("path", "old", "new"),
    "delete": ("path",),
    "move": ("path", "to"),
    "mode": ("path", "mode"),
    "expect-hash": ("path", "sha256"),
}
"""Each verb of the statement language, and its arguments in order."""

MODES: Final = frozenset({"600", "640", "644", "700", "750", "755"})
"""The permissions ``mode`` may set."""

ABSENT: Final = "absent"
"""What ``expect-hash`` names for a file that must not exist."""

LINK: Final = "link"
"""The ``mode`` of a symbolic link in an image: its ``sha256`` is of the link's target text."""

COMMIT_MODES: Final = ("in-place", "swap")

DEFAULT_CLASSES: Final = (
    PathClass(
        "secrets",
        (
            ".env",
            ".env.*",
            "**/.env",
            "**/.env.*",
            ".ssh/**",
            "**/.ssh/**",
            "**/*.pem",
            "**/*.key",
            "**/*.p12",
            "**/id_rsa",
            "**/id_rsa.*",
            "**/id_ed25519",
            "**/id_ed25519.*",
            "**/.netrc",
            "**/.npmrc",
            "**/.pypirc",
            "**/credentials",
            "**/credentials.*",
            "**/secrets/**",
        ),
    ),
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
            "deploy/**",
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
    PathClass("scripts", ("scripts/**", "bin/**", "**/*.sh")),
    PathClass("tests", ("tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/*_test.go")),
    PathClass("src", ("src/**", "lib/**", "app/**")),
    PathClass(
        "config",
        (
            "config/**",
            "etc/**",
            "**/*.toml",
            "**/*.yaml",
            "**/*.yml",
            "**/*.json",
            "**/*.ini",
            "**/*.cfg",
            "**/*.conf",
        ),
    ),
    PathClass("docs", ("docs/**", "**/*.md", "**/*.rst", "**/*.txt")),
)
"""The classes a workspace uses unless told otherwise, first match wins. Secrets come first, so a
``.env`` under ``config/`` is a secret, not configuration."""

_PARAMETER_TOKEN: Final = re.compile(
    r"\s*(?:'((?:[^']|'')*)'|(:[A-Za-z_][A-Za-z0-9_]*)|([^\s']+))", re.S
)
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_JOURNAL: Final = "journal"
_COMMITS: Final = "commits"
_STAGES: Final = "stages"
_LOCK: Final = "lock"
_PARENTS: Final = "parents"


# --------------------------------------------------------------------------
# the statement language
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FilesystemStatement:
    """A statement, parsed: its verb, and each argument as a literal or a ``:parameter``."""

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


def parse_statement(statement: str) -> FilesystemStatement:
    """Read one statement of the language (module docstring).

    :raises ValueError: On anything else, naming what is wrong.
    """
    tokens: list[tuple[str, str]] = []
    position = 0
    text = statement.rstrip()
    while position < len(text):
        found = _PARAMETER_TOKEN.match(text, position)
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
        raise ValueError(f"{verb} takes {tally(len(wanted), 'argument')}: {' '.join(wanted)}")
    for index, (kind, value) in enumerate(arguments, 1):
        if kind == "bare":
            raise ValueError(
                f"argument {index} ({value[:40]!r}) is neither a :parameter nor a 'quoted' literal"
            )
    return FilesystemStatement(verb, tuple(arguments))


def filesystem_tables(classes: Sequence[PathClass]) -> tuple[TableSpec, ...]:
    """A workspace's tables: one per path class and the fallback, keyed by path, with the columns
    every file's image has."""
    return tuple(
        TableSpec(name, primary_key="path", columns=list(COLUMNS))
        for name in (*(c.name for c in classes), FALLBACK_CLASS)
    )


# --------------------------------------------------------------------------
# files, hashes and manifests
# --------------------------------------------------------------------------


class _File(NamedTuple):
    """One file of a tree, as a manifest records it."""

    sha256: str
    mode: str
    """The permissions in octal (``644``), or :data:`LINK`."""
    size: int


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _entry(path: Path) -> _File | None:
    """``path`` as a manifest records it, or ``None`` when nothing is there.

    :raises StageError: On something that is neither a file nor a symbolic link.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path).encode("utf-8", "surrogateescape")
        return _File(hashlib.sha256(target).hexdigest(), LINK, len(target))
    if stat.S_ISREG(info.st_mode):
        return _File(_hash_file(path), format(stat.S_IMODE(info.st_mode), "o"), info.st_size)
    if stat.S_ISDIR(info.st_mode):
        raise StageError(f"{path.name} is a directory where a file was expected")
    raise StageError(f"{path.name} is neither a file nor a symbolic link")


@dataclass(frozen=True, slots=True)
class _Limits:
    files: int
    bytes: int


def _manifest(
    root: Path, ignore: Sequence[str], limits: _Limits, *, skip: Sequence[Path] = ()
) -> dict[str, _File]:
    """Every file under ``root`` (links not followed), by relative POSIX path, ignored paths and
    ``skip`` apart.

    :raises SubstrateConfigurationError: Past the limits.
    :raises StageError: On a special file (a socket, a device, a pipe).
    """
    found: dict[str, _File] = {}
    total = 0
    skipped = {p.resolve() for p in skip}
    for directory, folders, files in os.walk(root, followlinks=False):
        here = Path(directory)
        relative = here.relative_to(root).as_posix()
        prefix = "" if relative == "." else relative + "/"
        kept = []
        for name in sorted(folders):
            full = here / name
            path = prefix + name
            if full.is_symlink():
                files.append(name)
                continue
            if full.resolve() in skipped or _ignored(path, ignore, directory=True):
                continue
            kept.append(name)
        folders[:] = kept
        for name in sorted(files):
            path = prefix + name
            if _ignored(path, ignore):
                continue
            entry = _entry(here / name)
            assert entry is not None
            found[path] = entry
            total += entry.size
            if len(found) > limits.files or total > limits.bytes:
                raise SubstrateConfigurationError(
                    f"{root} holds more than {tally(limits.files, 'file')} or "
                    f"{limits.bytes} bytes: past what a stage copies (max_files, max_bytes)"
                )
    return found


def _ignored(path: str, ignore: Sequence[str], *, directory: bool = False) -> bool:
    if any(glob_match(pattern, path) for pattern in ignore):
        return True
    return directory and any(glob_match(pattern, path + "/") for pattern in ignore)


def _copy_tree(source: Path, target: Path, ignore: Sequence[str]) -> None:
    """``source`` copied to ``target`` (which must not exist), links as links, permissions kept,
    ignored paths left out."""

    def skip(directory: str, names: list[str]) -> list[str]:
        relative = Path(directory).relative_to(source).as_posix()
        prefix = "" if relative == "." else relative + "/"
        return [
            n for n in names if _ignored(prefix + n, ignore, directory=Path(directory, n).is_dir())
        ]

    shutil.copytree(source, target, symlinks=True, ignore=skip if ignore else None)


def _text(path: Path, limit: int) -> str:
    """A file's text as far as the scan reads; a binary file, or a link, as empty."""
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        with path.open("rb") as handle:
            sample = handle.read(limit)
    except OSError:
        return ""
    return "" if b"\x00" in sample else sample.decode("utf-8", "replace")


def _line_counts(before: str, after: str) -> tuple[int, int]:
    """Lines added and deleted between two texts, as a diff counts them."""
    old, new = before.splitlines(), after.splitlines()
    added = deleted = 0
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if op in ("replace", "delete"):
            deleted += i2 - i1
        if op in ("replace", "insert"):
            added += j2 - j1
    return added, deleted


def _fsync_directory(path: Path) -> None:
    with contextlib.suppress(OSError):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def prepare_swap(
    root: str | os.PathLike[str], *, versions: str | os.PathLike[str] | None = None
) -> Path:
    """Turn the plain directory ``root`` into the layout ``mode = "swap"`` commits on: its files
    move to a first version directory, and ``root`` becomes a link to it. Readers that open
    ``root/...`` see the same files before and after.

    :param versions: Where versions are kept: ``.<name>.versions`` beside ``root`` by default.
    :returns: The first version's directory.
    :raises SubstrateConfigurationError: If ``root`` is already a link, or is not a directory.
    """
    workspace = Path(root)
    if workspace.is_symlink():
        raise SubstrateConfigurationError(f"{workspace} is already a link: nothing to prepare")
    if not workspace.is_dir():
        raise SubstrateConfigurationError(f"{workspace} is not a directory")
    store = Path(versions) if versions is not None else _default_versions(workspace)
    store.mkdir(parents=True, exist_ok=True)
    first = store / "v0-initial"
    if first.exists():
        raise SubstrateConfigurationError(f"{first} already exists")
    workspace.rename(first)
    _swap_link(workspace, first)
    return first


def _default_versions(workspace: Path) -> Path:
    return workspace.absolute().parent / f".{workspace.name}.versions"


def _swap_link(link: Path, target: Path) -> None:
    """Point ``link`` at ``target`` with one ``rename(2)``: a reader sees one or the other."""
    temporary = link.parent / f".{link.name}.{uuid.uuid4().hex[:12]}.link"
    relative = os.path.relpath(target, link.parent)
    os.symlink(relative, temporary, target_is_directory=True)
    try:
        os.replace(temporary, link)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(link.parent)


# --------------------------------------------------------------------------
# the substrate
# --------------------------------------------------------------------------


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    directory: Path
    """Everything of the stage's: its copy (``tree``), its base copy, its home, savepoints."""
    tree: Path
    base_tree: Path
    """The base as it was copied: the before side of every line count."""
    base: dict[str, _File]
    version: str | None
    """For ``swap``: the version directory the link pointed at when the stage opened."""
    home: Path
    savepoints: list[tuple[str, Path]] = field(default_factory=list)
    measured: dict[str, _File] | None = None
    control: StageHandle | None = None
    done: bool = False
    unsettled: bool = False


class FilesystemSubstrate:
    """Transactional staging over a directory (module docstring).

    :param root: The workspace. For ``mode = "swap"``, a link to a version directory
        (:func:`prepare_swap` makes one).
    :param mode: ``"in-place"`` or ``"swap"``.
    :param classes: Path classes, first match wins; a path none matches is :data:`FALLBACK_CLASS`.
    :param workspace: The partition of every path no ``owners`` rule names: the directory's name
        by default.
    :param owners: ``(glob, owner)`` rules, first match wins: a path's owner is its partition.
    :param ignore: Globs of paths a stage neither copies nor measures, and a plan may not write
        (``node_modules/**``, ``.venv/**``). ``in-place`` only: a swapped version must hold every
        file.
    :param hooks: What runs in the stage's copy after each effect, in order.
    :param control: A SQLite file ``interlock install`` set up: the outbox, the inbox and rate
        windows' history.
    :param state: Where stages, the commit lock, journals and commit markers live:
        ``.<name>.interlock`` beside the workspace by default. Never inside it.
    :param versions: For ``swap``: where version directories are kept.
    :param keep_versions: For ``swap``: how many versions to keep, the current one included.
    :raises SubstrateConfigurationError: On a workspace that is missing or of the wrong kind for
        the mode, a state directory inside it, or versions on another file system.
    """

    __slots__ = (
        "_by_name",
        "_classes",
        "_control",
        "_hooks",
        "_ignore",
        "_keep",
        "_limits",
        "_max_file",
        "_max_rows",
        "_max_scan",
        "_mode",
        "_owners",
        "_protected",
        "_root",
        "_stage",
        "_stage_seconds",
        "_state",
        "_versions",
        "_workspace",
    )

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        mode: str = "in-place",
        classes: Sequence[PathClass] = DEFAULT_CLASSES,
        workspace: str | None = None,
        owners: Sequence[tuple[str, str]] = (),
        ignore: Sequence[str] = (),
        hooks: Sequence[GitHook] = (),
        control: str | os.PathLike[str] | None = None,
        state: str | os.PathLike[str] | None = None,
        versions: str | os.PathLike[str] | None = None,
        keep_versions: int = 10,
        max_stage_seconds: float = 120.0,
        max_diff_rows: int = 50_000,
        max_files: int = 50_000,
        max_bytes: int = 256 * 1024 * 1024,
        max_file_bytes: int = 4 * 1024 * 1024,
        max_scan_bytes: int = 1024 * 1024,
    ) -> None:
        if fcntl is None:  # pragma: no cover - Windows
            raise SubstrateConfigurationError(
                "the filesystem substrate needs POSIX file locks (fcntl), which this platform "
                "does not have"
            )
        if mode not in COMMIT_MODES:
            raise SubstrateConfigurationError(f"mode is 'in-place' or 'swap', not {mode!r}")
        self._mode = mode
        self._root = Path(root).absolute()
        if mode == "swap":
            if not self._root.is_symlink():
                raise SubstrateConfigurationError(
                    f"{self._root} is not a link to a version directory, which mode 'swap' "
                    f"commits by replacing. Run interlock.filesystem.prepare_swap on it once"
                )
            if ignore:
                raise SubstrateConfigurationError(
                    "mode 'swap' copies every file into the next version, so it ignores none"
                )
        elif not self._root.is_dir() or self._root.is_symlink():
            raise SubstrateConfigurationError(f"{self._root} is not a directory")
        names = [c.name for c in classes]
        if len(set(names)) != len(names) or FALLBACK_CLASS in names:
            raise SubstrateConfigurationError(
                f"path classes are named once each, and none is {FALLBACK_CLASS!r}, the class of "
                f"every path no rule names"
            )
        self._classes = tuple(classes)
        self._by_name = frozenset((*names, FALLBACK_CLASS))
        hook_names = [h.name for h in hooks]
        if len(set(hook_names)) != len(hook_names):
            raise SubstrateConfigurationError("hooks are named once each")
        self._hooks = tuple(hooks)
        self._protected = {s: h.name for h in self._hooks for s in h.sources}
        self._owners = tuple(owners)
        self._ignore = tuple(ignore)
        self._workspace = workspace or self._root.name
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._limits = _Limits(max_files, max_bytes)
        self._max_file = max_file_bytes
        self._max_scan = max_scan_bytes
        self._keep = max(2, keep_versions)
        self._state = (
            Path(state).absolute()
            if state is not None
            else self._root.parent / f".{self._root.name}.interlock"
        )
        real_root = self._root.resolve()
        if self._state.resolve() == real_root or real_root in self._state.resolve().parents:
            raise SubstrateConfigurationError(
                f"the state directory {self._state} is inside the workspace, where a stage would "
                f"copy and measure it"
            )
        self._versions = (
            Path(versions).absolute() if versions is not None else _default_versions(self._root)
        )
        for sub in (_STAGES, _JOURNAL, _COMMITS, _PARENTS):
            (self._state / sub).mkdir(parents=True, exist_ok=True)
        if mode == "swap":
            self._versions.mkdir(parents=True, exist_ok=True)
            if os.stat(self._versions).st_dev != os.stat(self._state).st_dev:
                raise SubstrateConfigurationError(
                    f"{self._versions} and {self._state} are on different file systems: a "
                    f"stage's copy becomes a version by a rename, which cannot cross them"
                )
        self._control = (
            SqliteSubstrate(str(control), tables=(), max_stage_seconds=max_stage_seconds)
            if control is not None
            else None
        )
        self._stage: _Stage | None = None

    # -- what it is -----------------------------------------------------------

    @property
    def substrate_id(self) -> str:
        return "filesystem"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=True,
            row_level_diff=True,
            snapshot_isolation=self._mode == "swap",
            requires_compensation=False,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            outbound=self._control is not None and self._control.capabilities.outbound,
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        """Every path class. Every path falls in one, so nothing a stage writes goes unmeasured."""
        return self._by_name

    @property
    def commit_markers(self) -> bool:
        """Always: every commit leaves a marker in the state directory."""
        return True

    @property
    def root(self) -> Path:
        return self._root

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def state(self) -> Path:
        return self._state

    @property
    def control(self) -> str | None:
        """The control database's path, when there is one."""
        return None if self._control is None else self._control.path

    def held_operations(self) -> dict[str, tuple[str, ...]]:
        """The control database's held operations (its outbox's)."""
        return {} if self._control is None else self._control.held_operations()

    def version(self) -> str | None:
        """For ``swap``: the version directory the workspace's link points at now."""
        if self._mode != "swap":
            return None
        return Path(os.readlink(self._root)).name

    def _current_version(self) -> Path:
        """For ``swap``: the version directory itself.

        :raises SubstrateConfigurationError: If the link leads anywhere but a version directory.
        """
        target = self._root.resolve()
        if target.parent != self._versions.resolve() or not target.is_dir():
            raise SubstrateConfigurationError(
                f"{self._root} leads to {target}, not to a version directory in {self._versions}"
            )
        return target

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

    def files(self) -> dict[str, str]:
        """Every file of the workspace now and its SHA-256: what a plan may name in
        ``expect-hash``."""
        return {p: f.sha256 for p, f in self._live_manifest().items()}

    # -- vetting ----------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from its statement: one of :data:`VERBS`, its
        arguments literals or bound strings, each path one a stage may write."""
        if effect.kind is EffectKind.ENQUEUE:
            return None
        try:
            statement = parse_statement(effect.statement)
            bound = statement.bind(effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        for key in ("path", "to"):
            if key in bound:
                problem = self._write_problem(bound[key])
                if problem is not None:
                    return problem
        if statement.verb == "mode" and bound["mode"] not in MODES:
            return f"mode is one of {', '.join(sorted(MODES))}"
        if statement.verb == "expect-hash" and not (
            bound["sha256"] == ABSENT or _SHA256.fullmatch(bound["sha256"])
        ):
            return "expect-hash names a SHA-256 in lowercase hex, or 'absent'"
        return None

    def _write_problem(self, path: str) -> str | None:
        problem = path_problem(path)
        if problem is not None:
            return f"path {path[:120]!r} {problem}"
        if _ignored(path, self._ignore):
            return (
                f"path {path!r} is ignored: a stage does not measure it, so a plan may not write it"
            )
        hook = self._protected.get(path)
        if hook is not None:
            return (
                f"path {path!r} is a source of hook {hook}: a plan may not write code a hook runs"
            )
        return None

    # -- lifecycle --------------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Copy the workspace into a stage of its own and hash it: the stage's base. Any commit a
        crashed process left half-done is finished first.

        :raises StageConflictError: If a stage is already open here.
        """
        if self._stage is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage "
                f"{self._stage.handle.stage_id} open"
            )
        self._settle()
        stage_id = uuid.uuid4()
        directory = self._state / _STAGES / str(stage_id)
        tree, home = directory / "tree", directory / "home"
        try:
            home.mkdir(parents=True)
        except OSError as exc:
            raise SubstrateUnavailableError(f"cannot create {directory}: {exc}") from exc
        try:
            with self._lock(exclusive=False):
                if self._mode == "swap":
                    source = self._current_version()
                    version = source.name
                    base_tree = source
                else:
                    version = None
                    source = self._root
                    base_tree = directory / "base"
                    _copy_tree(source, base_tree, self._ignore)
                _copy_tree(base_tree, tree, self._ignore)
            base = _manifest(tree, self._ignore, self._limits)
        except BaseException:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=stage_id,
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        self._stage = _Stage(handle, plan, directory, tree, base_tree, base, version, home)
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Apply one effect to the stage's copy, then run the hooks it sets off. Never touches the
        workspace.

        :raises ForbiddenStatementError: On a statement :meth:`reject_reason` refuses.
        :raises StageConflictError: On ``expect-hash`` naming a state the base does not hold.
        :raises StageError: On an operation that cannot be done (a ``replace`` whose text occurs
            other than once, a ``delete`` of a file that is not there) or a hook that fails.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            if self._control is None:
                raise OutboundRequestError(
                    f"effect {effect.effect_id!r} is an outbound request, and this workspace has "
                    f"no control database to hold an outbox",
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
        """Do one operation in the stage's copy; the paths it wrote."""
        where = f"effect {effect.effect_id!r}"
        path = bound["path"]
        if verb == "expect-hash":
            held = stage.base.get(path)
            want = bound["sha256"]
            have = ABSENT if held is None else held.sha256
            if have != want:
                raise StageConflictError(
                    f"{where}: {path} is "
                    + ("absent" if held is None else f"at {have[:12]}")
                    + f", not {'absent' if want == ABSENT else 'at ' + want[:12]} as the plan "
                    f"names: the state it was approved on is gone"
                )
            return []
        target = self._inside(stage, where, path, final=verb == "delete")
        if verb in ("write", "append"):
            data = bound["text"].encode("utf-8")
            if verb == "append" and target.exists():
                self._regular(where, target, path)
                data = target.read_bytes() + data
            self._bounded(where, path, len(data))
            self._replace_file(target, data, None if target.exists() else 0o644)
        elif verb == "replace":
            text = self._read_text(where, target, path)
            count = text.count(bound["old"])
            if count != 1:
                raise StageError(
                    f"{where}: replace finds its text {tally(count, 'time')} in {path}; it "
                    f"replaces exactly one occurrence"
                )
            data = text.replace(bound["old"], bound["new"], 1).encode("utf-8")
            self._bounded(where, path, len(data))
            self._replace_file(target, data, None)
        elif verb == "delete":
            if not (target.is_file() or target.is_symlink()):
                raise StageError(f"{where}: there is no file {path} to delete")
            target.unlink()
            self._prune_empty(stage.tree, target.parent)
        elif verb == "move":
            if not target.is_file() or target.is_symlink():
                raise StageError(f"{where}: there is no file {path} to move")
            destination = self._inside(stage, where, bound["to"])
            if destination.exists() or destination.is_symlink():
                raise StageError(
                    f"{where}: {bound['to']} already exists; a move does not overwrite"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(target, destination)
            self._prune_empty(stage.tree, target.parent)
            return [path, bound["to"]]
        else:  # mode
            self._regular(where, target, path)
            target.chmod(int(bound["mode"], 8))
        return [path]

    def _inside(self, stage: _Stage, where: str, path: str, *, final: bool = False) -> Path:
        """``path`` in the stage's copy, through no symbolic link (the last component may be one
        when ``final``: a link may be deleted, never written through)."""
        current = stage.tree
        parts = path.split("/")
        for index, part in enumerate(parts):
            current = current / part
            last = index == len(parts) - 1
            if current.is_symlink() and not (last and final):
                raise ForbiddenStatementError(
                    f"{where} refused: {path} passes through a symbolic link, which could lead "
                    f"outside the workspace",
                    reason="statement_kind",
                )
            if not last and current.exists() and not current.is_dir():
                raise StageError(f"{where}: {'/'.join(parts[: index + 1])} is a file, not a folder")
        return current

    def _regular(self, where: str, target: Path, path: str) -> None:
        if not target.is_file():
            raise StageError(f"{where}: there is no file {path}")

    def _read_text(self, where: str, target: Path, path: str) -> str:
        self._regular(where, target, path)
        try:
            return target.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StageError(f"{where}: {path} is not UTF-8 text") from exc

    def _bounded(self, where: str, path: str, size: int) -> None:
        if size > self._max_file:
            raise StageError(
                f"{where}: {path} would be {size} bytes, past the {self._max_file} a stage writes"
            )

    @staticmethod
    def _replace_file(target: Path, data: bytes, mode: int | None) -> None:
        """Write ``data`` at ``target`` in the stage's copy, keeping its permissions."""
        target.parent.mkdir(parents=True, exist_ok=True)
        keep = stat.S_IMODE(target.stat().st_mode) if mode is None else mode
        target.write_bytes(data)
        target.chmod(keep)

    @staticmethod
    def _prune_empty(tree: Path, directory: Path) -> None:
        """Remove folders a deletion emptied, up to the copy's root."""
        while directory != tree and tree in directory.parents:
            try:
                directory.rmdir()
            except OSError:
                return
            directory = directory.parent

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
                    cwd=stage.tree,
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

    # -- measuring ----------------------------------------------------------------

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Measure the stage's copy against the base: every file any effect or hook created,
        changed or removed. Read from the files, never from the plan."""
        stage = self._require(handle)
        now = _manifest(stage.tree, self._ignore, self._limits)
        for path in now:
            problem = path_problem(path)
            if problem is not None:
                raise StageError(f"the stage's copy holds {path!r}, which {problem}")
        stage.measured = now
        changed = sorted(p for p in set(stage.base) | set(now) if stage.base.get(p) != now.get(p))
        truncated = len(changed) > self._max_rows
        deltas = [self._delta(stage, path, now) for path in changed[: self._max_rows]]
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

    def _delta(self, stage: _Stage, path: str, now: Mapping[str, _File]) -> RowDelta:
        old, new = stage.base.get(path), now.get(path)
        before = None if old is None else self._image(path, old, 0, 0, 0)
        after = None
        if new is not None:
            old_text = "" if old is None else _text(stage.base_tree / path, self._max_scan)
            new_text = _text(stage.tree / path, self._max_scan)
            added, deleted = _line_counts(old_text, new_text)
            after = self._image(path, new, added, deleted, secret_markers(old_text, new_text))
        return RowDelta(
            table=self.classify(path),
            primary_key=path,
            before=before,
            after=after,
            tenant_id=self.owner(path),
        )

    @staticmethod
    def _image(path: str, entry: _File, added: int, deleted: int, markers: int) -> dict[str, Any]:
        return {
            "path": path,
            "sha256": entry.sha256,
            "mode": entry.mode,
            "bytes": entry.size,
            "lines_added": added,
            "lines_deleted": deleted,
            "net_lines": added - deleted,
            "secret_markers": markers,
        }

    # -- the control database -------------------------------------------------------

    def _control_stage(self, stage: _Stage) -> StageHandle:
        assert self._control is not None
        if stage.control is None:
            stage.control = self._control._open(stage.plan, stage.handle.stage_id)
        return stage.control

    def pending_facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        return () if self._control is None else self._control.pending_facts(scope_id)

    def consume_facts(
        self, handle: StageHandle, fact_ids: Sequence[uuid.UUID], scope_id: str
    ) -> None:
        stage = self._require(handle)
        if self._control is None:
            raise InboundFactError(
                "this workspace has no control database, so no inbox to consume a fact from"
            )
        self._control.consume_facts(self._control_stage(stage), fact_ids, scope_id)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        stage = self._require(handle)
        if self._control is None:
            raise SubstrateConfigurationError(
                "rate windows keep their history in a control database, and this workspace has none"
            )
        return self._control.measure_windows(self._control_stage(stage), charges)

    # -- commit -----------------------------------------------------------------------

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Write what was measured onto the workspace, only if every file it touches is still at
        its base hash (``swap``: only if the whole base version is unchanged and still current).

        With a control database the write happens inside its stage's transaction, just before its
        ``COMMIT``, after a redo record of that transaction is on disk.

        :raises StageError: If the stage's copy changed after it was measured.
        :raises StageConflictError: If the workspace moved since the stage read it: nothing is
            written, to the workspace or the control database.
        :raises CommitUnsettledError: If the process cannot tell whether the write completed.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if stage.measured is None:
            raise StageError(f"stage {handle.stage_id} is committed before it is measured")
        if _manifest(stage.tree, self._ignore, self._limits) != stage.measured:
            raise StageError(
                f"stage {handle.stage_id}: the stage's copy changed after it was measured; what "
                f"would commit is not what was judged"
            )
        changes = sorted(
            p
            for p in set(stage.base) | set(stage.measured)
            if stage.base.get(p) != stage.measured.get(p)
        )
        committed_at = datetime.now(UTC)
        attempted = False

        def write(conn: sqlite3.Connection | None) -> None:
            nonlocal attempted
            if not changes:
                return
            tables = capture(conn, handle.stage_id) if conn is not None else None
            with self._lock(exclusive=True):
                self._verify(stage, changes)
                attempted = True
                if self._mode == "swap":
                    self._swap(stage, tables)
                else:
                    self._write_in_place(stage, changes, tables)

        try:
            if self._control is None:
                write(None)
            else:
                self._control._commit(self._control_stage(stage), write)
        except StageConflictError:
            raise
        except CommitUnsettledError:
            stage.unsettled = True
            raise
        except Exception as exc:
            journal = self._journal_path(handle.stage_id)
            if not attempted or not journal.exists():
                raise
            if self._mode == "swap" and not self._committed_version(handle.stage_id):
                # The link never moved: nothing committed.
                journal.unlink(missing_ok=True)
                raise
            # The files landed, and what failed came after (the marker, or the control
            # database's COMMIT): the journal holds the control rows for recovery to replay.
            stage.unsettled = True
            if self._control is not None and stage.control is not None:
                self._control.abort(stage.control)
            raise CommitUnsettledError(
                f"stage {handle.stage_id}: the workspace holds the commit, and whether the control "
                f"database does too is for recovery to settle: {exc}"
            ) from exc
        self._journal_path(handle.stage_id).unlink(missing_ok=True)
        stage.done = True
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=committed_at,
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=f"fs:{handle.stage_id}" if changes else None,
        )

    def _verify(self, stage: _Stage, changes: Sequence[str]) -> None:
        """Refuse unless the workspace still holds the base for everything the commit touches."""
        if self._mode == "swap":
            current = self.version()
            if current != stage.version:
                raise StageConflictError(
                    f"stage {stage.handle.stage_id}: the workspace moved to version {current} "
                    f"since the stage read version {stage.version}; nothing was written"
                )
            assert stage.version is not None
            held = _manifest(self._current_version(), (), self._limits)
            moved = sorted(
                p for p in set(held) | set(stage.base) if held.get(p) != stage.base.get(p)
            )
        else:
            moved = []
            for path in changes:
                live = self._root / path
                parts = path.split("/")
                if any(self._root.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts))):
                    moved.append(path)
                    continue
                try:
                    found = _entry(live)
                except StageError:
                    moved.append(path)
                    continue
                if found != stage.base.get(path):
                    moved.append(path)
        if moved:
            shown = ", ".join(moved[:8]) + (f" and {len(moved) - 8} more" if len(moved) > 8 else "")
            raise StageConflictError(
                f"stage {stage.handle.stage_id}: {tally(len(moved), 'file')} changed in the "
                f"workspace since the stage read {'it' if len(moved) == 1 else 'them'} ({shown}); "
                f"nothing was written"
            )

    def _swap(self, stage: _Stage, tables: Mapping[str, Any] | None) -> None:
        """Make the stage's copy the next version, and point the workspace at it."""
        name = f"v-{stage.handle.stage_id}"
        target = self._versions / name
        self._write_journal(stage, [], tables, version=name)
        os.replace(stage.tree, target)
        (self._state / _PARENTS / f"{name}.json").write_text(
            json.dumps({"parent": stage.version, "stage_id": str(stage.handle.stage_id)})
        )
        _swap_link(self._root, target)
        self._mark(stage, [], version=name)
        self._prune_versions(keep={name, str(stage.version)})

    def _history(self) -> list[str]:
        """For ``swap``: the current version, its parent, and so on back."""
        chain: list[str] = []
        name = self.version()
        while name is not None and name not in chain:
            chain.append(name)
            parent = self._state / _PARENTS / f"{name}.json"
            name = json.loads(parent.read_text()).get("parent") if parent.is_file() else None
        return chain

    def _prune_versions(self, keep: set[str]) -> None:
        """Remove versions past the newest ``keep_versions`` of the history (and any a crash
        left that the history never reached)."""
        kept = set(self._history()[: self._keep]) | keep
        for directory in self._versions.iterdir():
            if directory.is_dir() and directory.name not in kept:
                shutil.rmtree(directory, ignore_errors=True)
                (self._state / _PARENTS / f"{directory.name}.json").unlink(missing_ok=True)

    def _write_in_place(
        self, stage: _Stage, changes: Sequence[str], tables: Mapping[str, Any] | None
    ) -> None:
        """Replace each changed file atomically, the set journaled first; on a failure while
        alive, put back what was replaced."""
        assert stage.measured is not None
        backup = stage.directory / "backup"
        for path in changes:
            if stage.base.get(path) is not None:
                (backup / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self._root / path, backup / path, follow_symlinks=False)
        self._write_journal(stage, list(changes), tables)
        done: list[str] = []
        try:
            for path in changes:
                self._land(stage.tree, path, stage.measured.get(path))
                done.append(path)
        except BaseException as exc:
            problems = self._put_back(stage, done)
            if problems:
                raise CommitUnsettledError(
                    f"stage {stage.handle.stage_id}: writing the workspace failed ({exc}), and "
                    f"putting back what was written failed too: {'; '.join(problems)}. The "
                    f"journal stays for recovery"
                ) from exc
            self._journal_path(stage.handle.stage_id).unlink(missing_ok=True)
            raise StageError(
                f"stage {stage.handle.stage_id}: writing the workspace failed ({exc}); every "
                f"file written before the failure was put back"
            ) from exc
        self._mark(stage, list(changes))

    def _land(self, tree: Path, path: str, entry: _File | None) -> None:
        """Make ``path`` in the workspace what it is in ``tree``: replaced by a rename, or
        removed."""
        live = self._root / path
        if entry is None:
            with contextlib.suppress(FileNotFoundError):
                live.unlink()
            self._prune_empty(self._root, live.parent)
            return
        live.parent.mkdir(parents=True, exist_ok=True)
        temporary = live.parent / f".{live.name}.interlock-{uuid.uuid4().hex[:12]}"
        source = tree / path
        try:
            if entry.mode == LINK:
                os.symlink(os.readlink(source), temporary)
            else:
                shutil.copyfile(source, temporary)
                os.chmod(temporary, int(entry.mode, 8))
                with temporary.open("rb") as handle:
                    os.fsync(handle.fileno())
            os.replace(temporary, live)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        _fsync_directory(live.parent)

    def _put_back(self, stage: _Stage, written: Sequence[str]) -> list[str]:
        """Restore each written path from the stage's backup; the problems."""
        backup = stage.directory / "backup"
        problems = []
        for path in reversed(written):
            try:
                self._land(backup, path, stage.base.get(path))
            except OSError as exc:
                problems.append(f"{path}: {exc}")
        return problems

    # -- journal, markers and recovery -------------------------------------------------

    def _journal_path(self, stage_id: uuid.UUID) -> Path:
        return self._state / _JOURNAL / f"{stage_id}.json"

    def _marker_path(self, stage_id: uuid.UUID) -> Path:
        return self._state / _COMMITS / f"{stage_id}.json"

    def _write_journal(
        self,
        stage: _Stage,
        changes: list[str],
        tables: Mapping[str, Any] | None,
        *,
        version: str | None = None,
    ) -> None:
        assert stage.measured is not None
        record = {
            "stage_id": str(stage.handle.stage_id),
            "plan_id": str(stage.plan.plan_id),
            "mode": self._mode,
            "stage": str(stage.directory),
            "version": version,
            "changes": [
                {
                    "path": p,
                    "before": None if stage.base.get(p) is None else list(stage.base[p]),
                    "after": None if stage.measured.get(p) is None else list(stage.measured[p]),
                }
                for p in changes
            ],
            "tables": tables,
        }
        durable_write(
            self._journal_path(stage.handle.stage_id),
            json.dumps(record, sort_keys=True).encode("utf-8"),
        )

    def _mark(self, stage: _Stage, changes: list[str], *, version: str | None = None) -> None:
        durable_write(
            self._marker_path(stage.handle.stage_id),
            json.dumps(
                {
                    "stage_id": str(stage.handle.stage_id),
                    "plan_id": str(stage.plan.plan_id),
                    "committed_at": datetime.now(UTC).isoformat(),
                    "files": changes,
                    "version": version,
                },
                sort_keys=True,
            ).encode("utf-8"),
        )

    def _committed_version(self, stage_id: uuid.UUID) -> bool:
        """For ``swap``: whether the stage's version is the current one or an ancestor of it."""
        return self._mode == "swap" and f"v-{stage_id}" in self._history()

    def _settle(self, *, only: uuid.UUID | None = None) -> bool | None:
        """Finish or drop each commit a crash left half-done.

        In place, a journal means the commit was decided: every file at its after state or its
        before state is brought to its after state. A file at neither (edited since the crash)
        leaves the journal for a person. For ``swap``, the link says: pointing at the stage's
        version (or a descendant of it), the stage committed. The control database's half is
        replayed when the files landed.

        :returns: For ``only``, whether that stage committed, ``None`` when unsettled or when
            there was no journal of it.
        """
        directory = self._state / _JOURNAL
        answer: bool | None = None
        for path in sorted(directory.glob("*.json")):
            if only is not None and path.stem != str(only):
                continue
            record = json.loads(path.read_bytes())
            stage_id = uuid.UUID(str(record["stage_id"]))
            if record.get("mode") == "swap":
                landed: bool | None = self._committed_version(stage_id)
            else:
                landed = self._roll_forward(record)
            if landed is None:
                logger.warning(
                    "stage %s: a half-done commit could not be finished: a file it writes is at "
                    "neither its before nor its after state; the journal %s is left for a person",
                    stage_id,
                    path,
                )
                continue
            if landed:
                if record.get("tables") and self._control is not None:
                    replay(
                        self._control.path,
                        str(stage_id),
                        record["tables"],
                        timeout=self._stage_seconds,
                    )
                if not self._marker_path(stage_id).exists():
                    durable_write(
                        self._marker_path(stage_id),
                        json.dumps(
                            {
                                "stage_id": str(stage_id),
                                "plan_id": record.get("plan_id"),
                                "committed_at": datetime.now(UTC).isoformat(),
                                "files": [c["path"] for c in record.get("changes", ())],
                                "version": record.get("version"),
                                "recovered": True,
                            },
                            sort_keys=True,
                        ).encode("utf-8"),
                    )
            path.unlink(missing_ok=True)
            shutil.rmtree(Path(str(record.get("stage", ""))), ignore_errors=True)
            logger.warning(
                "stage %s: a half-done commit was %s",
                stage_id,
                "finished: its files are in the workspace" if landed else "dropped",
            )
            if only is not None:
                answer = landed
        return answer

    def _roll_forward(self, record: Mapping[str, Any]) -> bool | None:
        tree = Path(str(record["stage"])) / "tree"
        pending: list[tuple[str, _File | None]] = []
        for change in record.get("changes", ()):
            path = str(change["path"])
            before = None if change["before"] is None else _File(*change["before"])
            after = None if change["after"] is None else _File(*change["after"])
            try:
                live = _entry(self._root / path)
            except StageError:
                return None
            if live == after:
                continue
            if live != before:
                return None
            if after is not None and _entry(tree / path) != after:
                return None
            pending.append((path, after))
        with self._lock(exclusive=True):
            for path, after in pending:
                self._land(tree, path, after)
        return True

    def resolve_intent(self, stage_id: uuid.UUID) -> bool | None:
        """Whether a stage committed: a half-done commit is settled first; then its marker says
        so, or (``swap``) the workspace's version history does, or (a stage that wrote no file)
        the control database does.

        :returns: ``None`` when a half-done commit cannot be finished without a person.
        """
        if self._journal_path(stage_id).exists():
            return self._settle(only=stage_id)
        if self._marker_path(stage_id).exists() or self._committed_version(stage_id):
            return True
        if self._control is not None:
            return bool(self._control.resolve_intent(stage_id))
        return False

    def _live_manifest(self) -> dict[str, _File]:
        source = self._versions / str(self.version()) if self._mode == "swap" else self._root
        with self._lock(exclusive=False):
            return _manifest(source, self._ignore, self._limits)

    @contextlib.contextmanager
    def _lock(self, *, exclusive: bool) -> Iterator[None]:
        """The workspace's commit lock: shared to read a consistent copy, exclusive to commit."""
        path = self._state / _LOCK
        with path.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    # -- savepoints -------------------------------------------------------------------

    def savepoint(self, handle: StageHandle, name: str) -> None:
        """Copy the stage's copy as it is now (and mark the control stage), to return to with
        :meth:`rollback_to`."""
        stage = self._require(handle)
        if not _NAME.fullmatch(name):
            raise ValueError(f"unsafe savepoint name: {name!r}")
        target = stage.directory / "savepoints" / f"{len(stage.savepoints)}-{name}"
        _copy_tree(stage.tree, target, ())
        stage.savepoints.append((name, target))
        if self._control is not None:
            self._control.savepoint(self._control_stage(stage), name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        """Put the stage's copy back as it was at savepoint ``name``; the mark stays."""
        stage = self._require(handle)
        saved = self._savepoint(stage, name)
        shutil.rmtree(stage.tree)
        _copy_tree(saved, stage.tree, ())
        stage.measured = None
        if self._control is not None:
            self._control.rollback_to(self._control_stage(stage), name)

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        """Forget mark ``name`` and every mark after it, keeping the work."""
        stage = self._require(handle)
        self._savepoint(stage, name)
        index = max(i for i, (n, _) in enumerate(stage.savepoints) if n == name)
        for _, copy in stage.savepoints[index:]:
            shutil.rmtree(copy, ignore_errors=True)
        del stage.savepoints[index:]
        if self._control is not None:
            self._control.release_savepoint(self._control_stage(stage), name)

    @staticmethod
    def _savepoint(stage: _Stage, name: str) -> Path:
        for found, copy in reversed(stage.savepoints):
            if found == name:
                return copy
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage -----------------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        """Discard the stage: the workspace was never written, and the control stage rolls back.
        Safe in any state, including after a commit."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        stage.done = True
        if self._control is not None and stage.control is not None:
            self._control.abort(stage.control)

    def close(self, handle: StageHandle) -> None:
        """Remove the stage's copy, rolling back first if still open. A stage whose commit is
        unsettled keeps its copy: recovery finishes the commit from it."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        self.abort(handle)
        if self._control is not None and stage.control is not None:
            self._control.close(stage.control)
        if not stage.unsettled and not self._journal_path(handle.stage_id).exists():
            shutil.rmtree(stage.directory, ignore_errors=True)
        self._stage = None

    # -- internals ------------------------------------------------------------------------

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
