"""Unrecorded writes: every change to an observed table has a record, or fails.

The reference monitor only sees what goes through it. A cron job, a migration,
a DBA at a prompt, or the agent's own credentials used directly: each writes
an observed table and leaves nothing in the escrow chain. Reconciliation is the
check that closes the loop, the database-side twin of AgentGov's
unauthorized-charge check: nothing spent without an authorization, nothing
changed without a record.

It fails on four things:

- **An unmediated write.** A row change in an observed table that no stage
  made. PostgreSQL logs each to ``interlock.unmediated`` from the trigger
  ``interlock install`` puts on the table; SQLite journals every row change
  to ``_interlock_journal`` from permanent triggers, and each committed stage
  records the range of journal rows it produced, exact because
  ``BEGIN IMMEDIATE`` admits one writer at a time.
- **An unrecorded stage.** A stage the database committed that no escrow chain
  records at all: opened outside an engine, or by one whose chain was lost.
- **A contradicted stage.** One the chain records as aborted, or under
  another plan, that the database committed.
- **An unresolved stage.** One the database committed while the chain holds
  only its commit intent: a crash in the commit window. Run recovery
  (``EscrowEngine.recover``, which ``EscrowRuntime`` runs at startup).

And, on SQLite, on an observed table with no journal trigger, since its
writes cannot be reconciled at all.

What it cannot see: anyone able to disable the triggers or edit the logs,
which on PostgreSQL means the tables' owner or a superuser, and on SQLite
means anyone who can write the file. Logical decoding would close the first;
nothing in the file closes the second.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from interlock.chain import EscrowRecord, RecordType
from interlock.exceptions import SubstrateConfigurationError, SubstrateUnavailableError
from interlock.substrate import (
    _MARKER_TABLE,
    JOURNAL_TABLE,
    STAGE_JOURNAL_TABLE,
    TableSpec,
)

if TYPE_CHECKING:
    import psycopg

__all__ = [
    "Reconciliation",
    "StageFinding",
    "UnmediatedWrite",
    "chain_outcomes",
    "format_reconciliation",
    "install_sqlite_journal",
    "reconcile_postgres",
    "reconcile_sqlite",
]

_TERMINAL = frozenset(
    {RecordType.COMMITTED, RecordType.ABORTED, RecordType.ORPHANED, RecordType.COMPENSATED}
)


@dataclass(frozen=True, slots=True)
class UnmediatedWrite:
    """One row change no stage made.

    :ivar entry: Its id in the log (``interlock.unmediated.id`` or the
        journal's ``seq``), for ``--after``.
    :ivar primary_key: ``None`` for a ``TRUNCATE``, which names no row.
    :ivar actor: Who wrote it, where the database knows: the PostgreSQL
        session user and ``application_name``.
    """

    entry: int
    table: str
    primary_key: str | None
    operation: str
    at: str
    transaction: str | None = None
    actor: str | None = None

    def describe(self) -> str:
        row = f"{self.table} pk={self.primary_key}" if self.primary_key else self.table
        who = f" by {self.actor}" if self.actor else ""
        txid = f" xid {self.transaction}" if self.transaction else ""
        return f"#{self.entry} {self.operation} {row} at {self.at}{who}{txid}"


@dataclass(frozen=True, slots=True)
class StageFinding:
    """A committed stage the chain does not account for.

    :ivar problem: ``"unrecorded"``, ``"aborted"``, ``"plan"`` (the chain
        records it under another plan) or ``"unresolved"``.
    """

    stage_id: str
    plan_id: str
    problem: str

    def describe(self) -> str:
        what = {
            "unrecorded": "committed in the database, absent from every chain",
            "aborted": "committed in the database, recorded as aborted",
            "plan": "committed in the database under another plan than the chain records",
            "unresolved": "committed in the database; the chain holds only its commit "
            "intent. Run recovery",
        }[self.problem]
        return f"stage {self.stage_id} (plan {self.plan_id}): {what}"


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """What reconciling one database against its chains found."""

    substrate: str
    stages_checked: int
    writes_checked: int
    unmediated: tuple[UnmediatedWrite, ...]
    stages: tuple[StageFinding, ...]
    unjournaled: tuple[str, ...]
    last_entry: int

    @property
    def clean(self) -> bool:
        return not (self.unmediated or self.stages or self.unjournaled)

    @property
    def findings(self) -> int:
        return len(self.unmediated) + len(self.stages) + len(self.unjournaled)


def chain_outcomes(records: Iterable[EscrowRecord]) -> dict[str, tuple[RecordType, str]]:
    """Each stage's standing in the chain(s): its terminal record, else its
    commit intent, with the plan it was recorded under."""
    outcomes: dict[str, tuple[RecordType, str]] = {}
    for record in records:
        if record.stage_id is None:
            continue
        key = str(record.stage_id)
        if record.record_type in _TERMINAL:
            outcomes[key] = (record.record_type, str(record.plan_id))
        elif record.record_type is RecordType.COMMIT_INTENT and key not in outcomes:
            outcomes[key] = (RecordType.COMMIT_INTENT, str(record.plan_id))
    return outcomes


def _stage_findings(
    committed: Sequence[tuple[str, str]], records: Iterable[EscrowRecord]
) -> tuple[StageFinding, ...]:
    outcomes = chain_outcomes(records)
    findings: list[StageFinding] = []
    for stage_id, plan_id in committed:
        outcome = outcomes.get(stage_id)
        if outcome is None:
            findings.append(StageFinding(stage_id, plan_id, "unrecorded"))
        elif outcome[1] != plan_id:
            findings.append(StageFinding(stage_id, plan_id, "plan"))
        elif outcome[0] is RecordType.COMMIT_INTENT:
            findings.append(StageFinding(stage_id, plan_id, "unresolved"))
        elif outcome[0] is not RecordType.COMMITTED:
            findings.append(StageFinding(stage_id, plan_id, "aborted"))
    return tuple(findings)


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------


def install_sqlite_journal(path: str, tables: Sequence[TableSpec]) -> None:
    """Put the journal and its permanent triggers into a SQLite database.

    Idempotent; a table the journal covered before and ``tables`` no longer
    lists loses its triggers. The triggers fire for every connection, staged
    or not, which is the point.

    :raises SubstrateUnavailableError: If the database cannot be written.
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=rw", uri=True, isolation_level=None)
    except sqlite3.Error as exc:
        raise SubstrateUnavailableError(f"cannot open {path}: {exc}") from exc
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS main.{JOURNAL_TABLE} ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, tbl TEXT NOT NULL, pk TEXT, "
            "op TEXT NOT NULL, "
            "at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))"
        )
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS main.{STAGE_JOURNAL_TABLE} ("
            "stage_id TEXT PRIMARY KEY, first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL)"
        )
        wanted = {f"ilok_journal_{t.name}_{op}" for t in tables for op in ("i", "u", "d")}
        existing = [
            str(r[0])
            for r in conn.execute(
                "SELECT name FROM main.sqlite_master WHERE type = 'trigger' "
                "AND name LIKE 'ilok\\_journal\\_%' ESCAPE '\\'"
            )
        ]
        for name in existing:
            if name not in wanted:
                conn.execute(f'DROP TRIGGER main."{name}"')
        for spec in tables:
            # Identifiers validated by TableSpec; see SqliteSubstrate.
            for op, suffix, row in (
                ("INSERT", "i", "NEW"),
                ("UPDATE", "u", "NEW"),
                ("DELETE", "d", "OLD"),
            ):
                name = f"ilok_journal_{spec.name}_{suffix}"
                conn.execute(f"DROP TRIGGER IF EXISTS main.{name}")
                conn.execute(
                    f"CREATE TRIGGER main.{name} AFTER {op} ON {spec.name} BEGIN "
                    f"INSERT INTO {JOURNAL_TABLE} (tbl, pk, op) VALUES "
                    f"('{spec.name}', CAST({row}.{spec.primary_key} AS TEXT), '{op.lower()}'); "
                    f"END"
                )
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        raise SubstrateUnavailableError(f"cannot install the journal into {path}: {exc}") from exc
    finally:
        conn.close()


def reconcile_sqlite(
    path: str,
    tables: Sequence[TableSpec],
    records: Iterable[EscrowRecord],
    *,
    after: int = 0,
) -> Reconciliation:
    """Reconcile a SQLite database's journal and commit markers against chains.

    :param records: Every record of every chain that stages against ``path``.
    :param after: Only journal entries numbered above this, the ``last_entry``
        of a previous run. Committed stages are always all checked.
    :raises SubstrateConfigurationError: If the journal is not installed.
    :raises SubstrateUnavailableError: If the database cannot be read.
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise SubstrateUnavailableError(f"cannot open {path}: {exc}") from exc
    try:
        names = {
            str(r[0]): str(r[1]) for r in conn.execute("SELECT name, type FROM main.sqlite_master")
        }
        if names.get(JOURNAL_TABLE) != "table" or names.get(STAGE_JOURNAL_TABLE) != "table":
            raise SubstrateConfigurationError(
                f"{path} has no Interlock journal, so its writes cannot be reconciled. "
                f"Run `interlock install`"
            )
        unjournaled = tuple(
            sorted(
                t.name
                for t in tables
                if any(
                    names.get(f"ilok_journal_{t.name}_{op}") != "trigger" for op in ("i", "u", "d")
                )
            )
        )
        ranges = [
            (int(r[0]), int(r[1]))
            for r in conn.execute(f"SELECT first_seq, last_seq FROM main.{STAGE_JOURNAL_TABLE}")
        ]
        rows = conn.execute(
            f"SELECT seq, tbl, pk, op, at FROM main.{JOURNAL_TABLE} WHERE seq > ? ORDER BY seq",
            (after,),
        ).fetchall()
        committed: list[tuple[str, str]] = []
        if names.get(_MARKER_TABLE) == "table":
            committed = [
                (str(r[0]), str(r[1]))
                for r in conn.execute(
                    f"SELECT stage_id, plan_id FROM main.{_MARKER_TABLE} ORDER BY committed_at"
                )
            ]
    except sqlite3.Error as exc:
        raise SubstrateUnavailableError(f"cannot read {path}: {exc}") from exc
    finally:
        conn.close()

    unmediated = tuple(
        UnmediatedWrite(
            entry=int(seq),
            table=str(table),
            primary_key=None if pk is None else str(pk),
            operation=str(op),
            at=str(at),
        )
        for seq, table, pk, op, at in rows
        if not any(first <= int(seq) <= last for first, last in ranges)
    )
    return Reconciliation(
        substrate="sqlite",
        stages_checked=len(committed),
        writes_checked=len(rows),
        unmediated=unmediated,
        stages=_stage_findings(committed, records),
        unjournaled=unjournaled,
        last_entry=max([after, *(int(r[0]) for r in rows)]),
    )


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------


def reconcile_postgres(
    conn: psycopg.Connection[Any],
    records: Iterable[EscrowRecord],
    *,
    after: int = 0,
) -> Reconciliation:
    """Reconcile ``interlock.unmediated`` and ``interlock.stages`` against chains.

    Run as a role granted ``audit_roles`` at install (or the installer).

    :raises SubstrateConfigurationError: If Interlock is not installed, or the
        role may not read its tables.
    :raises SubstrateUnavailableError: On any other database error.
    """
    import psycopg

    try:
        with conn.transaction():
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            rows = conn.execute(
                "SELECT id, xid::text, tbl, pk, op, at::text, db_user::text, application "
                "FROM interlock.unmediated WHERE id > %s ORDER BY id",
                (after,),
            ).fetchall()
            committed = [
                (str(r[0]), str(r[1]))
                for r in conn.execute(
                    "SELECT stage_id::text, plan_id FROM interlock.stages ORDER BY opened_at"
                ).fetchall()
            ]
    except psycopg.Error as exc:
        if exc.sqlstate in ("42P01", "3F000", "42501"):
            raise SubstrateConfigurationError(
                f"cannot read Interlock's logs: {exc}. Run `interlock install`, and grant "
                f"this role with audit_roles"
            ) from exc
        raise SubstrateUnavailableError(f"cannot reconcile: {exc}") from exc
    unmediated = tuple(
        UnmediatedWrite(
            entry=int(entry),
            table=str(table),
            primary_key=None if pk is None else str(pk),
            operation=str(op),
            at=str(at),
            transaction=str(xid),
            actor=f"{user} ({application})" if application else str(user),
        )
        for entry, xid, table, pk, op, at, user, application in rows
    )
    return Reconciliation(
        substrate="postgres",
        stages_checked=len(committed),
        writes_checked=len(rows),
        unmediated=unmediated,
        stages=_stage_findings(committed, records),
        unjournaled=(),
        last_entry=max([after, *(int(r[0]) for r in rows)]),
    )


def format_reconciliation(result: Reconciliation) -> list[str]:
    """Human-readable lines, one per finding, then a verdict."""
    lines = [
        f"reconcile-effects: {result.substrate}, {result.stages_checked} committed stage(s), "
        f"{result.writes_checked} logged write(s) checked"
    ]
    lines += [f"UNJOURNALED  {table}: no journal trigger" for table in result.unjournaled]
    lines += [f"UNMEDIATED   {write.describe()}" for write in result.unmediated]
    lines += [f"{f.problem.upper():<12} {f.describe()}" for f in result.stages]
    lines.append(f"last entry: {result.last_entry}")
    lines.append("result: clean" if result.clean else f"result: FAIL, {result.findings} finding(s)")
    return lines
