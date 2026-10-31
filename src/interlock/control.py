"""A control database's half of a stage, redone after a crash (1.3.0).

A substrate with no transactions of its own (Git, a Kubernetes cluster,
Terraform) keeps what must commit with a plan in a *control database*: a
SQLite file holding the outbox, the inbox and the rate windows' history. Its
stage commits in that database's transaction, around the system's own write:
the system is written just before the control database's ``COMMIT``.

If the process dies between the two, the system holds the plan and the control
database does not. So, just before writing the system, the substrate writes a
*redo record*: every row the control stage holds (:func:`capture`), durably.
Recovery, finding the system written (by the substrate's own marker), writes
those rows again (:func:`replay`), once: not at all when the control
database's commit marker shows they committed.

:class:`~interlock.git_substrate.GitSubstrate` and
:class:`~interlock.kubernetes.KubernetesSubstrate` both use this.
"""

from __future__ import annotations

import base64
import contextlib
import os
import sqlite3
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from interlock.exceptions import StageError, SubstrateUnavailableError
from interlock.inbox_sql import SQLITE_CONSUMED
from interlock.sqlite_outbox import OUTBOX, STATE, TRACES, WINDOWS_TABLE
from interlock.substrate import _MARKER_TABLE, STAGE_JOURNAL_TABLE

__all__ = ["REDO_TABLES", "capture", "durable_write", "replay"]

REDO_TABLES: Final = (
    (_MARKER_TABLE, "stage_id = :stage"),
    (OUTBOX, "stage_id = :stage"),
    (STATE, f"message_id IN (SELECT message_id FROM {OUTBOX} WHERE stage_id = :stage)"),
    (TRACES, f"message_id IN (SELECT message_id FROM {OUTBOX} WHERE stage_id = :stage)"),
    (SQLITE_CONSUMED, "stage_id = :stage"),
    (WINDOWS_TABLE, "stage_id = :stage"),
    (STAGE_JOURNAL_TABLE, "stage_id = :stage"),
)
"""What a control stage writes, in the order a redo writes it again."""


def capture(conn: sqlite3.Connection, stage_id: uuid.UUID) -> dict[str, list[dict[str, Any]]]:
    """Every row the control stage on ``conn`` holds, by table, as JSON."""
    tables: dict[str, list[dict[str, Any]]] = {}
    for table, where in REDO_TABLES:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        if exists is None:
            continue
        cursor = conn.execute(f"SELECT * FROM main.{table} WHERE {where}", {"stage": str(stage_id)})
        columns = [c[0] for c in cursor.description]
        rows = [dict(zip(columns, map(_jsonable, row), strict=True)) for row in cursor]
        if rows:
            tables[table] = rows
    return tables


def replay(
    path: str,
    stage_id: str,
    tables: Mapping[str, Any],
    *,
    timeout: float,
) -> None:
    """Write a redo record's rows into the control database at ``path``, once:
    nothing when its commit marker is there already.

    :raises StageError: If they cannot be written.
    """
    try:
        conn = sqlite3.connect(path, isolation_level=None, timeout=timeout)
    except sqlite3.Error as exc:
        raise SubstrateUnavailableError(f"cannot open {path}: {exc}") from exc
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE")
        present = conn.execute(
            f"SELECT 1 FROM main.{_MARKER_TABLE} WHERE stage_id = ?", (stage_id,)
        ).fetchone()
        if present is None:
            for table, _ in REDO_TABLES:
                for row in tables.get(table, ()):
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
            f"stage {stage_id}: its effects are written and its control rows could not be "
            f"written again: {exc}"
        ) from exc
    finally:
        conn.close()


def durable_write(path: Path, data: bytes) -> None:
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


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode("ascii")}
    return value


def _from_json(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"b64"}:
        return base64.b64decode(str(value["b64"]))
    return value
