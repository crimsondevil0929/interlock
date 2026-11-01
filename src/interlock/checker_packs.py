"""Pinned checker packs: a domain's own checkers, run only as the code pinned (1.3.0).

The built-in checkers compose most of what a domain needs. A domain whose
invariant cannot be composed from them (a dose ceiling read off a formulary, a
change-window calendar) ships its checkers as a *pack*: an importable module
that names itself and its checkers::

    PACK_NAME = "acme-dose-checkers"
    PACK_VERSION = "1.0.0"
    CHECKERS = {"dose_ceiling": DoseCeiling}   # each called with its config

A policy pins a pack by module, version and :func:`pack_digest`, as a mandate
pins a tool binding by its document's digest. :func:`load_pack` refuses the
pack unless exactly that code is installed, so a verdict, and its offline
replay, run the checker the approvers pinned, or none:

- not installed: the module cannot be imported;
- another version: its ``PACK_VERSION`` is not the one pinned;
- tampered: its digest is not the one pinned.

The digest is SHA-256 over every ``.py`` file of the pack's package (or its
one module), each as its path relative to the package and the SHA-256 of its
bytes, sorted: an edit to any file, a file added or removed, changes it. It is
computed from the files installed, not from a wheel's ``RECORD``, which a
tamperer could edit too.

A pack's checkers must be what every checker is: deterministic functions of
the plan and the diff, reading nothing else.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final

from agentgov.receipts.canonical import canonical_bytes

from interlock.exceptions import InterlockError
from interlock.invariants import InvariantChecker

__all__ = ["CheckerPack", "CheckerPackError", "PackPin", "load_pack", "pack_digest"]

_MODULE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")


class CheckerPackError(InterlockError):
    """A pinned checker pack is not installed as pinned.

    :ivar reason: ``missing``, ``version``, ``digest`` or ``checker``.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class PackPin:
    """A pack as a policy pins it: its module, version and digest."""

    module: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        if not _MODULE.fullmatch(self.module):
            raise ValueError(f"{self.module!r} is not a module name")
        if not self.version:
            raise ValueError(f"pack {self.module}: the version is named")
        if not _DIGEST.fullmatch(self.digest):
            raise ValueError(f"pack {self.module}: the digest is SHA-256, 64 lowercase hex")


def _files(module: ModuleType) -> tuple[Path, list[Path]]:
    origin = getattr(module, "__file__", None)
    if origin is None:
        raise CheckerPackError(
            f"checker pack {module.__name__} has no files to digest", reason="missing"
        )
    path = Path(origin).resolve()
    if path.name == "__init__.py":
        root = path.parent
        return root, sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)
    return path.parent, [path]


def pack_digest(module: ModuleType) -> str:
    """The digest of an imported pack's code (module docstring)."""
    root, files = _files(module)
    listing = [
        [p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()] for p in files
    ]
    return hashlib.sha256(canonical_bytes(listing)).hexdigest()


@dataclass(frozen=True, slots=True)
class CheckerPack:
    """A pack loaded as pinned."""

    pin: PackPin
    name: str
    checkers: Mapping[str, Callable[..., InvariantChecker]]

    def checker(self, name: str, config: Mapping[str, Any]) -> InvariantChecker:
        """Checker ``name`` of the pack, built with ``config``.

        :raises CheckerPackError: If the pack has no such checker, or it
            refuses the configuration.
        """
        factory = self.checkers.get(name)
        if factory is None:
            raise CheckerPackError(
                f"checker pack {self.pin.module} {self.pin.version} has no checker {name!r}; it "
                f"has {', '.join(sorted(self.checkers)) or 'none'}",
                reason="checker",
            )
        try:
            built = factory(**dict(config))
        except (TypeError, ValueError) as exc:
            raise CheckerPackError(
                f"checker {self.pin.module}.{name} refuses its configuration: {exc}",
                reason="checker",
            ) from exc
        if not callable(getattr(built, "check", None)) or not isinstance(
            getattr(built, "name", None), str
        ):
            raise CheckerPackError(
                f"checker {self.pin.module}.{name} is not a checker (a name and a check)",
                reason="checker",
            )
        return built


def load_pack(pin: PackPin) -> CheckerPack:
    """The pack ``pin`` names, if exactly that code is installed.

    :raises CheckerPackError: If it is not installed, is another version, or
        its code does not match the pinned digest.
    """
    if importlib.util.find_spec(pin.module.split(".")[0]) is None:
        raise CheckerPackError(
            f"checker pack {pin.module} {pin.version} is not installed: install it (digest "
            f"{pin.digest[:16]}) to run, or replay, this policy",
            reason="missing",
        )
    try:
        module = importlib.import_module(pin.module)
    except ImportError as exc:
        raise CheckerPackError(
            f"checker pack {pin.module} {pin.version} cannot be imported: {exc}",
            reason="missing",
        ) from exc
    version = getattr(module, "PACK_VERSION", None)
    if version != pin.version:
        raise CheckerPackError(
            f"checker pack {pin.module} is version {version}, and the policy pins {pin.version}",
            reason="version",
        )
    found = pack_digest(module)
    if found != pin.digest:
        raise CheckerPackError(
            f"checker pack {pin.module} {pin.version} is not the code pinned: its digest is "
            f"{found[:16]}, the policy pins {pin.digest[:16]}. Reinstall the pinned release",
            reason="digest",
        )
    checkers = getattr(module, "CHECKERS", None)
    if not isinstance(checkers, Mapping) or not all(callable(c) for c in checkers.values()):
        raise CheckerPackError(
            f"checker pack {pin.module} names no CHECKERS mapping", reason="checker"
        )
    return CheckerPack(pin, str(getattr(module, "PACK_NAME", pin.module)), dict(checkers))
