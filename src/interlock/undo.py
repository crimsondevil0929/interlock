"""Undo (1.10.0): a committed plan put back exactly, as a plan of its own.

**What is kept, and where.** A substrate built with ``undo=timedelta(days=7)`` keeps, at each
commit, every resource's net before and after image: the state before the plan, and the state
it left. They stay in the system they came from, under that system's own access control, for
the window, and are then deleted:

- SQLite: a table, ``_interlock_undo``, in the same database, written in the stage's own
  transaction; PostgreSQL: ``interlock.undo_images``, written and read only through the
  install's ``SECURITY DEFINER`` functions, also in the stage's transaction;
- a directory: the before content of each file, in a directory beside the workspace;
- Git: nothing but a small record under the repository's common directory: the content is
  the repository's own objects;
- a REST API or FHIR server: the before resources, beside the undo journal.

Never in the chain, and never in an audit bundle. The chain gets a digest of the plan's
*change digests* (:func:`change_digests`): for each resource, an HMAC of its before image and
of its after image under a key kept beside the images. An auditor compares an undo's digests
with the plan's, so swapping before and after is caught, without seeing any data.

**What an undo is.** :meth:`~interlock.engine.EscrowEngine.undo` builds the inverse from what
was kept (each substrate's ``inverse``): every resource the plan changed, set back from its
after image to its before image. It is staged, measured and judged like any plan
(``EffectPlan.undoes`` names the plan it undoes). It commits only if what was measured is
exactly the inverse (:func:`inverse_problems`): the same resources, each found as the plan left
it and put back as it was, and nothing else. A resource someone changed since makes the
measurement differ, and the whole undo is refused, naming it; nothing changes. An exact
inverse waives the size bounds (:data:`WAIVED`), which would otherwise refuse undoing a large
mistake; every other check still applies.

**What it is not.** It does not unsend a request a relay delivered, and it does not see a
change it was never asked to measure (a column a table's spec leaves out, a field an API
manages itself). Deleted rows come back with the columns Interlock observes, and the table's
defaults for any others.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from agentgov.receipts.canonical import canonical_bytes

from interlock.types import (
    Change,
    EffectDiff,
    EffectPlan,
    InvariantViolation,
    Severity,
)

__all__ = [
    "UNDO_EXACT",
    "WAIVED",
    "ChangeDigest",
    "Kept",
    "KeptRecords",
    "UndoExact",
    "change_digests",
    "changes_hash",
    "digest_problems",
    "identity",
    "inverse_problems",
    "net",
    "waived",
]

UNDO_EXACT: Final = "undo_exact"
"""The check an undo is always held to, in shadow mode too: :class:`UndoExact`."""

WAIVED: Final = frozenset(
    {
        "change_limit",
        "blast_radius",
        "no_delete",
        "value_guard",
        "column_value_guard",
        "tenant_drawdown_guard",
        "partition_value_guard",
        "stated_footprint",
    }
)
"""The size bounds an exact inverse is not held to: undoing a large mistake is as large as
the mistake, and an insert's undo is a delete. Isolation, allowlists, truncation, schema and
provenance checks still apply. A checker named ``value_guard:orders.total`` is waived by
the part before the colon."""


def waived(name: str) -> bool:
    """Whether the checker ``name`` is a size bound an exact inverse is not held to."""
    return name.split(":", 1)[0] in WAIVED


ChangeDigest = tuple[str, str, str | None, str | None]
"""``(kind, id, before, after)``: one resource's change, its images as HMAC-SHA256 hex
(``None`` where the resource did not exist)."""


@dataclass(frozen=True, slots=True)
class Kept:
    """What a substrate kept of one committed plan, to undo it.

    :ivar changes: The plan's net changes, one per resource, in the order each was first
        changed (:func:`net`).
    :ivar key: The key its change digests are made under. An undo of this plan digests its
        own changes under it too, so the two can be compared.
    :ivar fields: For each kind, the fields that are the resource's state: what an undo must
        find and put back. A kind not named compares every field. A file's line counts, say,
        describe a change, not a file, and are left out.
    :ivar payload: What the substrate needs beyond the images to write the before state back:
        a file's content, a resource's whole body. Never digested, never recorded.
    """

    plan_id: str
    substrate_id: str
    changes: tuple[Change, ...]
    key: bytes
    committed_at: datetime
    expires_at: datetime
    fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)

    def digests(self) -> tuple[ChangeDigest, ...]:
        """This plan's change digests (:func:`change_digests`)."""
        return change_digests(self.key, self.changes, self.fields)


def net(changes: Iterable[Change]) -> tuple[Change, ...]:
    """One change per resource: its image before the first change, and after the last, in the
    order each resource was first changed. A resource left as it was (created and deleted in
    the same plan, or set and set back) is dropped."""
    first: dict[tuple[str, str], Change] = {}
    last: dict[tuple[str, str], Change] = {}
    for change in changes:
        key = (change.kind, change.id)
        first.setdefault(key, change)
        last[key] = change
    out = []
    for key, change in first.items():
        after = last[key]
        if change.before == after.after:
            continue
        out.append(
            Change(
                kind=change.kind,
                id=change.id,
                before=change.before,
                after=after.after,
                tenant_id=after.tenant_id if after.tenant_id is not None else change.tenant_id,
                partitions=dict(after.partitions or change.partitions),
            )
        )
    return tuple(out)


def identity(image: Mapping[str, Any] | None, fields: Sequence[str] | None) -> Any:
    """The part of an image that is the resource's state: ``fields`` of it, or all of it."""
    if image is None:
        return None
    if fields is None:
        return {k: image[k] for k in sorted(image)}
    return {k: image.get(k) for k in fields}


def _digest(key: bytes, kind: str, ident: str, image: Any) -> str | None:
    if image is None:
        return None
    message = canonical_bytes([kind, ident, _plain(image)])
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _plain(value: Any) -> Any:
    """``value`` as canonical JSON takes it: numbers that are not integers as strings."""
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, int | str):
        return value
    return str(value)


def change_digests(
    key: bytes, changes: Iterable[Change], fields: Mapping[str, tuple[str, ...]] | None = None
) -> tuple[ChangeDigest, ...]:
    """Each change as ``(kind, id, before, after)``, its images' state (:func:`identity`) as
    HMAC-SHA256 under ``key``, sorted by kind and id."""
    fields = fields or {}
    return tuple(
        sorted(
            (
                c.kind,
                c.id,
                _digest(key, c.kind, c.id, identity(c.before, fields.get(c.kind))),
                _digest(key, c.kind, c.id, identity(c.after, fields.get(c.kind))),
            )
            for c in changes
        )
    )


def changes_hash(digests: Sequence[ChangeDigest]) -> str:
    """The SHA-256 a commit's chain record names its change digests by."""
    return hashlib.sha256(canonical_bytes([list(d) for d in digests])).hexdigest()


def inverse_problems(kept: Kept, diff: EffectDiff) -> list[str]:
    """What keeps ``diff`` from being exactly the inverse of ``kept``: each resource the plan
    changed must be measured going from its after image back to its before image, and
    nothing else may change. Empty when it is exact."""
    measured = {(c.kind, c.id): c for c in net(diff.deltas)}
    problems: list[str] = []
    if diff.truncated:
        problems.append("the measurement was cut short, so it cannot be shown to be exact")
    for change in kept.changes:
        fields = kept.fields.get(change.kind)
        found = measured.pop((change.kind, change.id), None)
        where = f"{change.kind} {change.id}"
        if found is None:
            problems.append(f"{where} was not put back: it changed since the plan committed")
            continue
        if identity(found.before, fields) != identity(change.after, fields):
            problems.append(f"{where} changed since the plan committed")
        elif identity(found.after, fields) != identity(change.before, fields):
            problems.append(f"{where} would not be put back as it was")
    problems.extend(f"{kind} {ident} is not one the plan changed" for kind, ident in measured)
    return problems


def digest_problems(original: Sequence[Sequence[Any]], undo: Sequence[Sequence[Any]]) -> list[str]:
    """What keeps the change digests ``undo`` from being exactly the inverse of ``original``:
    the same resources, each undo's before the original's after and its after the original's
    before. What an auditor checks (V14), without the data."""
    want = {(str(d[0]), str(d[1])): (d[3], d[2]) for d in original}
    got = {(str(d[0]), str(d[1])): (d[2], d[3]) for d in undo}
    problems = []
    for where, images in sorted(want.items()):
        if where not in got:
            problems.append(f"{where[0]} {where[1]} is not put back")
        elif got[where] != images:
            problems.append(f"{where[0]} {where[1]} is not put back exactly as it was")
    problems.extend(
        f"{kind} {ident} is changed and the plan never changed it"
        for kind, ident in sorted(set(got) - set(want))
    )
    return problems


class UndoExact:
    """Hold an undo to being exactly the inverse of the plan it undoes (:func:`inverse_problems`).
    Enforced in shadow mode too: an undo that is not exact is no undo."""

    __slots__ = ("_kept",)

    def __init__(self, kept: Kept) -> None:
        self._kept = kept

    @property
    def name(self) -> str:
        return UNDO_EXACT

    def check(self, plan: EffectPlan, diff: EffectDiff) -> tuple[InvariantViolation, ...]:
        problems = inverse_problems(self._kept, diff)
        if not problems:
            return ()
        shown = "; ".join(problems[:10]) + (
            f"; and {len(problems) - 10} more" if len(problems) > 10 else ""
        )
        return (
            InvariantViolation(
                invariant=UNDO_EXACT,
                severity=Severity.BLOCKING,
                message=f"the undo of plan {self._kept.plan_id} is not exact: {shown}",
                evidence={"undoes": self._kept.plan_id, "problems": str(len(problems))},
            ),
        )


class KeptRecords:
    """Kept undo records as files in one directory (1.10.0): what an API substrate keeps
    beside its undo journal. A stage's record is written before its commit, under a name only
    that stage uses, and becomes the plan's once the commit is made; a record past its window,
    or one a stage that never committed left an hour ago, is deleted at the next write."""

    __slots__ = ("_directory",)

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._directory = Path(directory)

    def pending(self, stage_id: str, record: Mapping[str, Any]) -> Path:
        self._purge()
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._directory / f".{stage_id}.json"
        path.write_text(json.dumps(dict(record), sort_keys=True), encoding="utf-8")
        return path

    def commit(
        self, pending: Path, plan_id: str, committed_at: datetime, window: timedelta
    ) -> None:
        record = json.loads(pending.read_text(encoding="utf-8"))
        record["committed_at"] = committed_at.isoformat()
        record["expires_at"] = (committed_at + window).isoformat()
        pending.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.replace(pending, self._directory / f"{_file_name(plan_id)}.json")

    def read(self, plan_id: str) -> dict[str, Any] | None:
        """The plan's record, while it is within its window."""
        try:
            record: dict[str, Any] = json.loads(
                (self._directory / f"{_file_name(plan_id)}.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return None
        if datetime.fromisoformat(record["expires_at"]) <= datetime.now(UTC):
            return None
        return record

    def _purge(self) -> None:
        if not self._directory.is_dir():
            return
        now = datetime.now(UTC)
        for path in self._directory.glob("*.json"):
            gone = False
            try:
                if path.name.startswith("."):
                    born = datetime.fromtimestamp(path.stat().st_mtime, UTC)
                    gone = now - born > timedelta(hours=1)
                else:
                    record = json.loads(path.read_text(encoding="utf-8"))
                    gone = datetime.fromisoformat(record["expires_at"]) <= now
            except (OSError, ValueError, KeyError):
                gone = True
            if gone:
                with contextlib.suppress(OSError):
                    path.unlink()


def _file_name(plan_id: str) -> str:
    """A plan's file name: its id, or its digest when the id is no file name."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", plan_id):
        return plan_id
    return hashlib.sha256(plan_id.encode("utf-8")).hexdigest()


def template_literal(document: Any) -> str:
    """``document`` as a statement's quoted JSON literal (a quote doubled).

    :raises ValueError: When a string in it would be read as a parameter (``":name"``).
    """

    def walk(value: Any) -> None:
        if isinstance(value, str) and re.fullmatch(r":[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError(f"the value {value!r} would be read as a parameter")
        if isinstance(value, Mapping):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return "'" + json.dumps(document, sort_keys=True).replace("'", "''") + "'"
