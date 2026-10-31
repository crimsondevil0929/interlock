"""Class P, plan-bound substrates: what they owe the engine, and the undo
journal they share (1.3.0).

A plan-bound substrate (:mod:`interlock.kubernetes`, :mod:`interlock.terraform`)
measures the plan it will apply, not a transaction it will commit. The
measurement is the system's own: a Kubernetes API server's dry run, with every
admission webhook and default applied, or Terraform's saved plan. The commit
applies exactly what was measured, conditional on the system not having moved
since (a ``resourceVersion``, a state serial), so a measurement or a warrant
never lands on a state it did not see.

What such a system cannot do is roll back. An apply across several objects is
not atomic: if the third write fails, the first two stay written. So the
substrate works out the undo from the before images it measured, and writes it
down before applying anything (the undo before the do, as for an outbound
request's compensation):

1. :meth:`write_undo` (the substrate's) writes the undo to an
   :class:`UndoJournal`, durably, and returns its SHA-256. The engine names
   the digest in the stage's ``COMMIT_INTENT`` record, so the chain says which
   undo was armed before the first write went out.
2. ``commit`` applies. A partial failure is put back from the journal, and
   raises :class:`~interlock.exceptions.CompensatedError`; the engine records
   the stage ``COMPENSATED``.
3. After a crash, ``resolve_intent`` reads each object's stage marker: every
   object marked is a commit, none is a rollback, and a part is put back from
   the journal first (then ``compensated`` says so, and the engine records
   ``COMPENSATED``).

Every receipt of such a substrate's plans says ``coverage.measurement =
"plan-bound"``: what was measured is the plan that was applied, and a partial
failure was covered by an undo written down first. It never claims
``transactional``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from agentgov.receipts.canonical import canonical_bytes

from interlock.exceptions import SubstrateUnavailableError

__all__ = ["PLAN_BOUND", "STAGE_ANNOTATION", "UndoJournal"]

PLAN_BOUND: Final = "plan-bound"
"""ARC1 1.3's ``coverage.measurement`` for a plan-bound substrate."""

STAGE_ANNOTATION: Final = "interlock.io/stage-id"
"""The marker a plan-bound substrate leaves on every object it writes: the
stage's id. Recovery reads it, and a system of record's audit log echoes it,
which is how ``agentgov reconcile-actions`` ties the write to its receipt."""


class UndoJournal:
    """The undo of each stage, one file per stage, written before its apply.

    A file is ``<stage_id>.undo.json``: canonical JSON, fsynced with its
    directory before :meth:`write` returns, so a crash after the first write
    to the system still finds the undo.
    """

    __slots__ = ("_directory",)

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._directory = Path(directory)

    @property
    def directory(self) -> Path:
        return self._directory

    def path(self, stage_id: uuid.UUID) -> Path:
        return self._directory / f"{stage_id}.undo.json"

    def write(self, stage_id: uuid.UUID, document: Mapping[str, Any]) -> str:
        """Write ``document`` as the stage's undo; its SHA-256.

        :raises SubstrateUnavailableError: If it cannot be made durable, so the
            apply must not start.
        """
        data = canonical_bytes(dict(document))
        target = self.path(stage_id)
        try:
            self._directory.mkdir(parents=True, exist_ok=True)
            partial = target.with_suffix(".partial")
            with open(partial, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial, target)
            directory = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise SubstrateUnavailableError(
                f"cannot write the undo of stage {stage_id} to {target}: {exc}; nothing was applied"
            ) from exc
        return hashlib.sha256(data).hexdigest()

    def read(self, stage_id: uuid.UUID) -> tuple[dict[str, Any], str] | None:
        """The stage's undo and its SHA-256, or ``None`` when there is none."""
        try:
            data = self.path(stage_id).read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SubstrateUnavailableError(
                f"cannot read the undo of stage {stage_id}: {exc}"
            ) from exc
        document = json.loads(data)
        if not isinstance(document, dict):
            raise SubstrateUnavailableError(f"the undo of stage {stage_id} is not an object")
        return document, hashlib.sha256(data).hexdigest()

    def discard(self, stage_id: uuid.UUID) -> None:
        """Forget the stage's undo, once its outcome is settled."""
        with contextlib.suppress(FileNotFoundError):
            self.path(stage_id).unlink()
