"""Run a command so that it can write only inside a stage, and reach no network (1.7.0).

``interlock run`` runs a coding agent's commands in a session's stage (:mod:`interlock.session`)
under the operating system's own sandbox:

- **seatbelt** (macOS): ``sandbox-exec`` with a profile that denies every file write outside the
  writable directories, and every network operation.
- **bwrap** (Linux): bubblewrap, with the root file system mounted read-only, the writable
  directories bound read-write over it, and a network namespace of its own with no route out.
  The command's ``/tmp`` is a private, empty directory: what it writes there is discarded
  when it exits (its ``TMPDIR`` is the session's own temporary directory, which is kept).
- **none**: no sandbox. Only when asked for by name; the command log and the promotion receipt
  record it, so a reader knows the commands ran unconfined.

Reads are not confined, as in Claude Code's own sandbox: a build reads the toolchain, the
package caches and the rest of the file system. ``hidden`` directories are the exception: a
command cannot list or read them (the stage's own records, a deployment's keys).

What the sandbox does not do: it does not limit CPU, memory or time, and it does not stop a
command from reading a secret elsewhere on the machine that is not hidden. What it changes is
where a write can land, which is what a promotion measures.
"""

from __future__ import annotations

import functools
import hashlib
import os
import platform
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from interlock.exceptions import InterlockError

__all__ = [
    "KINDS",
    "Sandbox",
    "SandboxUnavailableError",
    "available",
    "choose",
]

KINDS: Final = ("seatbelt", "bwrap", "none")
"""The sandboxes a command can run under; ``auto`` picks the first this machine has."""

_DEVICES: Final = ("/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper", "/dev/random")


class SandboxUnavailableError(InterlockError):
    """The sandbox asked for cannot run here."""


def _quote(path: Path) -> str:
    """A path as a quoted string of a Seatbelt profile."""
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True, slots=True)
class Sandbox:
    """How one command is confined.

    :ivar kind: One of :data:`KINDS`.
    :ivar writable: The directories a command may write in (the stage, its temporary
        directory), as real paths.
    :ivar hidden: Directories a command may not read at all, unless a writable one is inside.
    :ivar network: Whether the command may use the network; ``False`` for every promotion.
    """

    kind: str
    writable: tuple[Path, ...]
    hidden: tuple[Path, ...] = ()
    network: bool = False
    _devices: tuple[str, ...] = field(default=_DEVICES, repr=False)

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"a sandbox is one of {', '.join(KINDS)}, not {self.kind!r}")

    def profile(self) -> str:
        """The confinement, as text: the Seatbelt profile, the bubblewrap arguments, or
        ``none``. Its SHA-256 is what the command log records (:meth:`digest`)."""
        if self.kind == "seatbelt":
            lines = ["(version 1)", "(allow default)"]
            if not self.network:
                lines.append("(deny network*)")
            for hidden in self.hidden:
                lines.append(f"(deny file-read* file-write* (subpath {_quote(hidden)}))")
            lines.append("(deny file-write*)")
            allowed = [f"(subpath {_quote(p)})" for p in self.writable]
            allowed += [f'(literal "{d}")' for d in self._devices]
            allowed.append('(regex #"^/dev/fd/")')
            lines.append("(allow file-write* " + " ".join(allowed) + ")")
            if self.hidden:
                readable = " ".join(f"(subpath {_quote(p)})" for p in self.writable)
                lines.append(f"(allow file-read* {readable})")
            return "\n".join(lines) + "\n"
        if self.kind == "bwrap":
            return " ".join(self._bwrap_options()) + "\n"
        return "none\n"

    def digest(self) -> str:
        """``sha256:`` and the hex digest of :meth:`profile`."""
        return "sha256:" + hashlib.sha256(self.profile().encode("utf-8")).hexdigest()

    def _bwrap_options(self) -> list[str]:
        options = ["--die-with-parent", "--new-session", "--ro-bind", "/", "/"]
        # A private, empty /tmp: the session's own temporary directory is TMPDIR.
        options += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]  # noqa: S108
        if not self.network:
            options += ["--unshare-net"]
        options += ["--unshare-ipc"]
        for hidden in self.hidden:
            options += ["--tmpfs", str(hidden)]
        for path in self.writable:
            options += ["--bind", str(path), str(path)]
        return options

    def argv(self, command: Sequence[str], cwd: Path) -> list[str]:
        """The argument vector that runs ``command`` in ``cwd`` under this sandbox."""
        if not command:
            raise ValueError("there is no command to run")
        if self.kind == "seatbelt":
            return ["sandbox-exec", "-p", self.profile(), *command]
        if self.kind == "bwrap":
            return ["bwrap", *self._bwrap_options(), "--chdir", str(cwd), "--", *command]
        return list(command)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> int:
        """Run ``command`` under the sandbox, its output on this process's own; its exit code.

        :raises FileNotFoundError: If the command cannot be found.
        """
        done = subprocess.run(  # noqa: S603 - the command is the caller's, run without a shell
            self.argv(command, cwd),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            check=False,
            timeout=timeout,
        )
        return done.returncode


@functools.cache
def _works(kind: str) -> bool:
    """Whether ``kind`` can confine a command here: tried once, on ``true``."""
    true = shutil.which("true") or "/usr/bin/true"
    if kind == "seatbelt":
        if platform.system() != "Darwin" or shutil.which("sandbox-exec") is None:
            return False
        argv = ["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", true]
    elif kind == "bwrap":
        if platform.system() != "Linux" or shutil.which("bwrap") is None:
            return False
        argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-net", true]
    else:
        return kind == "none"
    try:
        return subprocess.run(argv, capture_output=True, timeout=20, check=False).returncode == 0  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return False


def available() -> tuple[str, ...]:
    """The sandboxes that work on this machine, ``none`` last."""
    return tuple(k for k in KINDS if _works(k))


def choose(requested: str = "auto") -> str:
    """The sandbox to run under: ``requested``, or for ``auto`` the one this machine has.

    :raises SandboxUnavailableError: When ``requested`` cannot run here, or ``auto`` finds no
        sandbox: then a command runs only with ``none`` asked for by name.
    """
    if requested == "auto":
        for kind in ("seatbelt", "bwrap"):
            if _works(kind):
                return kind
        raise SandboxUnavailableError(
            "no sandbox works on this machine: on Linux install bubblewrap (bwrap) and allow "
            "unprivileged user namespaces; on macOS sandbox-exec is part of the system. To run "
            "the command unconfined, ask for it: --sandbox none. The command log and the "
            "promotion receipt then say so"
        )
    if requested not in KINDS:
        raise SandboxUnavailableError(f"--sandbox is auto, {', '.join(KINDS)}; not {requested!r}")
    if not _works(requested):
        raise SandboxUnavailableError(f"the {requested} sandbox does not work on this machine")
    return requested


def real(path: Path) -> Path:
    """``path`` with every link resolved, as the sandbox sees it (``/tmp`` is
    ``/private/tmp`` on macOS)."""
    return Path(os.path.realpath(path))
