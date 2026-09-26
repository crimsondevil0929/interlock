"""Foreign-key reach: the tables a statement mutates without naming them.

A ``DELETE`` on ``orders`` whose foreign key from ``order_notes`` says
``ON DELETE CASCADE`` deletes notes too. The statement never names
``order_notes``, the agent may not know it exists, and when ``order_notes`` is
not an observed table the substrate's measurement cannot see those rows go.
The diff would then report a one-row delete that was really a many-row one,
and every checker reading it would pass on less than what happened.

This module reads the schema's foreign-key graph and works out, for every
observed table, which unobserved tables a ``DELETE`` or ``UPDATE`` on it can
reach through a referential action (``CASCADE``, ``SET NULL``,
``SET DEFAULT``). ``RESTRICT`` and ``NO ACTION`` mutate nothing; they refuse
the parent's statement instead, so they reach nothing.

Every reach is one of two things:

- **Gated.** The substrate refuses the parent operation before a row changes.
  This is the default for every reach into an unobserved table.
- **Acknowledged.** The operator named the unobserved table in
  ``acknowledge_cascades``: the cascade may run, unmeasured, and the gap is
  recorded on every stage that runs with it. Acknowledgment is the only way to
  lift a gate.

A reach into an *observed* table is neither: the capture triggers measure it,
which is the case the diff exists for.

The analysis is column-precise for updates. An ``UPDATE`` only fires
``ON UPDATE`` actions when it changes a referenced (parent key) column, and a
cascaded update only changes the child's foreign-key columns, so an update of
``orders.total`` is never gated because of a foreign key on ``orders.id``.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

__all__ = [
    "CascadeGate",
    "CascadeReach",
    "CascadeReport",
    "CascadeStep",
    "ForeignKey",
    "analyze_cascades",
    "log_report",
    "read_postgres_foreign_keys",
    "read_sqlite_foreign_keys",
]

Operation = Literal["delete", "update"]

CASCADE: Final = "CASCADE"
SET_NULL: Final = "SET NULL"
SET_DEFAULT: Final = "SET DEFAULT"
RESTRICT: Final = "RESTRICT"
NO_ACTION: Final = "NO ACTION"

_MUTATING: Final = frozenset({CASCADE, SET_NULL, SET_DEFAULT})
"""Referential actions that write the child row. The rest only refuse."""

_PG_ACTIONS: Final[Mapping[str, str]] = {
    "a": NO_ACTION,
    "r": RESTRICT,
    "c": CASCADE,
    "n": SET_NULL,
    "d": SET_DEFAULT,
}
"""``pg_constraint.confdeltype`` / ``confupdtype`` codes."""


@dataclass(frozen=True, slots=True)
class ForeignKey:
    """One foreign-key constraint, child to parent.

    :ivar parent_columns: The referenced columns. Empty when they could not be
        resolved, which the analysis treats as "any column of the parent".
    :ivar set_columns: The columns ``ON DELETE SET NULL (cols)`` or
        ``SET DEFAULT (cols)`` writes (PostgreSQL 15+). Empty means all of
        ``child_columns``.
    """

    child: str
    child_columns: tuple[str, ...]
    parent: str
    parent_columns: tuple[str, ...]
    on_delete: str
    on_update: str
    name: str = ""
    set_columns: tuple[str, ...] = ()

    def action(self, operation: Operation) -> str:
        return self.on_delete if operation == "delete" else self.on_update

    def label(self, operation: Operation) -> str:
        """``orders -[ON DELETE CASCADE]-> order_notes``."""
        return f"{self.parent} -[ON {operation.upper()} {self.action(operation)}]-> {self.child}"


@dataclass(frozen=True, slots=True)
class CascadeStep:
    """One edge of a reach path: the parent-side operation that fired it."""

    foreign_key: ForeignKey
    fired_by: Operation

    @property
    def effect(self) -> Operation:
        """What the edge does to the child row: a cascade delete deletes it,
        every other mutating action updates it."""
        if self.fired_by == "delete" and self.foreign_key.on_delete == CASCADE:
            return "delete"
        return "update"


@dataclass(frozen=True, slots=True)
class CascadeReach:
    """An operation on an observed table that can mutate an unobserved one.

    :ivar parent: The observed table the statement writes.
    :ivar operation: ``"delete"``, or ``"update"`` of ``columns``.
    :ivar columns: For an update, the parent columns whose change sets the
        cascade off. Empty for a delete, and for an update whose referenced
        columns could not be resolved (any column then counts).
    :ivar table: The unobserved table reached.
    :ivar path: The shortest chain of referential actions from ``parent`` to
        ``table``.
    :ivar acknowledged: Whether the operator accepted this gap.
    """

    parent: str
    operation: Operation
    columns: tuple[str, ...]
    table: str
    path: tuple[CascadeStep, ...]
    acknowledged: bool

    def describe(self) -> str:
        """``DELETE on orders reaches order_notes: orders -[...]-> order_notes``."""
        what = self.operation.upper()
        if self.operation == "update":
            what += f" of {', '.join(self.columns)}" if self.columns else " of any column"
        chain = ", then ".join(step.foreign_key.label(step.fired_by) for step in self.path)
        return f"{what} on {self.parent} reaches {self.table}: {chain}"


@dataclass(frozen=True, slots=True)
class CascadeGate:
    """What the substrate refuses on one observed table.

    :ivar delete: Refuse any statement that deletes from the table.
    :ivar update_columns: Refuse an update that changes any of these columns.
    :ivar update_any: Refuse every update of the table, because a gated
        foreign key's referenced columns could not be resolved.
    """

    table: str
    delete: bool
    update_columns: frozenset[str]
    update_any: bool

    def blocks_update_of(self, column: str) -> bool:
        return self.update_any or column in self.update_columns


@dataclass(frozen=True, slots=True)
class CascadeReport:
    """The cascade check's result for one schema and one observed-table set."""

    observed: frozenset[str]
    acknowledged: frozenset[str]
    foreign_keys: tuple[ForeignKey, ...]
    reaches: tuple[CascadeReach, ...]

    @property
    def gated(self) -> tuple[CascadeReach, ...]:
        """Reaches the substrate refuses: nobody acknowledged the gap."""
        return tuple(r for r in self.reaches if not r.acknowledged)

    @property
    def gaps(self) -> tuple[CascadeReach, ...]:
        """Reaches the operator accepted. Each one runs unmeasured."""
        return tuple(r for r in self.reaches if r.acknowledged)

    @property
    def closed(self) -> bool:
        """Every row a stage can mutate lands in an observed table.

        True when there is no acknowledged gap: every other reach into an
        unobserved table is refused before it happens.
        """
        return not self.gaps

    @property
    def unreached_acknowledgments(self) -> frozenset[str]:
        """Acknowledged tables no cascade reaches: stale or mistyped config."""
        return self.acknowledged - {_fold(r.table) for r in self.reaches}

    def gates(self) -> dict[str, CascadeGate]:
        """The refusals to enforce, keyed by lowercased observed table name.

        Column names are lowercased too: both engines compare identifiers
        case-insensitively where a ``TableSpec`` can name them.
        """
        delete: set[str] = set()
        columns: dict[str, set[str]] = defaultdict(set)
        any_column: set[str] = set()
        for reach in self.gated:
            parent = _fold(reach.parent)
            if reach.operation == "delete":
                delete.add(parent)
            elif reach.columns:
                columns[parent].update(_fold(c) for c in reach.columns)
            else:
                any_column.add(parent)
        tables = sorted(delete | set(columns) | any_column)
        return {
            table: CascadeGate(
                table=table,
                delete=table in delete,
                update_columns=frozenset(columns.get(table, ())),
                update_any=table in any_column,
            )
            for table in tables
        }

    def unmonitored_tables(self) -> frozenset[str]:
        """Unobserved tables a gated reach would mutate, as the schema names them."""
        return frozenset(r.table for r in self.gated)

    def refusal(self, table: str, operation: Operation, column: str | None = None) -> str:
        """Why an operation on ``table`` is refused, naming every gated path."""
        key = _fold(table)
        wanted = None if column is None else _fold(column)
        paths = [
            r.describe()
            for r in self.gated
            if _fold(r.parent) == key
            and r.operation == operation
            and (wanted is None or not r.columns or wanted in {_fold(c) for c in r.columns})
        ]
        what = operation.upper() if column is None else f"{operation.upper()} of {column}"
        found = "; ".join(paths) if paths else f"a foreign-key action from {table}"
        unobserved = sorted({r.table for r in self.gated if _fold(r.parent) == key})
        return (
            f"{what} on {table!r} is refused: a foreign-key action carries it into "
            f"unobserved table(s) where it would execute without being measured ({found}). "
            f"Observe {', '.join(unobserved) or 'the reached table'} with a TableSpec, or "
            f"accept the unmeasured write with acknowledge_cascades"
        )

    def describe_gaps(self) -> str:
        """One line naming every acknowledged gap, for the audit record."""
        return "; ".join(sorted({f"{r.operation} {r.parent}->{r.table}" for r in self.gaps}))


def log_report(
    logger: logging.Logger, previous: CascadeReport | None, report: CascadeReport
) -> None:
    """Warn about every gated reach, acknowledged gap and stale acknowledgment.

    Only when what is gated changed since ``previous``: a substrate re-runs the
    check every stage, and the answer rarely moves.
    """
    if previous is not None and previous.reaches == report.reaches:
        return
    for reach in report.gated:
        logger.warning("cascade check: refusing %s", reach.describe())
    for reach in report.gaps:
        logger.warning("cascade check: acknowledged, unmeasured: %s", reach.describe())
    for table in sorted(report.unreached_acknowledgments):
        logger.warning(
            "cascade check: acknowledge_cascades names %r, which no foreign-key "
            "action from an observed table reaches",
            table,
        )


def _fold(name: str) -> str:
    return name.lower()


def analyze_cascades(
    foreign_keys: Iterable[ForeignKey],
    observed: Collection[str],
    acknowledged: Collection[str] = (),
) -> CascadeReport:
    """Work out every reach from an observed table into an unobserved one.

    Names compare case-insensitively: SQLite folds identifiers, and PostgreSQL
    folds the unquoted identifiers a ``TableSpec`` is written in.

    :param foreign_keys: The schema's constraints, from a reader below.
    :param observed: Table names the substrate captures.
    :param acknowledged: Unobserved table names the operator accepts cascades
        into, unmeasured.
    :returns: The report. Paths are shortest-first and deterministic.
    """
    keys = tuple(foreign_keys)
    seen = frozenset(_fold(t) for t in observed)
    accepted = frozenset(_fold(t) for t in acknowledged)
    by_parent: dict[str, list[ForeignKey]] = defaultdict(list)
    for fk in sorted(keys, key=lambda k: (k.parent, k.child, k.name, k.child_columns)):
        by_parent[_fold(fk.parent)].append(fk)

    reaches: list[CascadeReach] = []
    for parent in sorted({_fold(t) for t in observed}):
        name = _display(parent, keys)
        for table, path in _walk(by_parent, parent, "delete", None, ()):
            if _fold(table) not in seen:
                reaches.append(
                    CascadeReach(name, "delete", (), table, path, _fold(table) in accepted)
                )
        for fk in by_parent.get(parent, ()):
            if fk.on_update not in _MUTATING:
                continue
            first = (CascadeStep(fk, "update"),)
            for table, path in _walk(by_parent, _fold(fk.child), "update", fk.child_columns, first):
                if _fold(table) not in seen:
                    reaches.append(
                        CascadeReach(
                            name,
                            "update",
                            fk.parent_columns,
                            table,
                            path,
                            _fold(table) in accepted,
                        )
                    )
    return CascadeReport(
        observed=seen,
        acknowledged=accepted,
        foreign_keys=keys,
        reaches=_dedupe(reaches),
    )


def _display(folded: str, keys: Sequence[ForeignKey]) -> str:
    """The table's name as the schema spells it, when a key mentions it."""
    for fk in keys:
        for name in (fk.parent, fk.child):
            if _fold(name) == folded:
                return name
    return folded


_State = tuple[str, Operation, frozenset[str] | None]
"""A traversal state: table, what happens to its rows, which columns changed."""


def _walk(
    by_parent: Mapping[str, Sequence[ForeignKey]],
    start: str,
    operation: Operation,
    columns: tuple[str, ...] | None,
    prefix: tuple[CascadeStep, ...],
) -> Iterator[tuple[str, tuple[CascadeStep, ...]]]:
    """Breadth-first over (table, operation, changed columns) states.

    Yields every table reached with its shortest path. When ``prefix`` is
    non-empty, ``start`` was itself reached by the prefix's last edge and is
    yielded first. ``columns=None`` means any column may have changed, which
    is the case for the statement's own update.
    """
    begin: _State = (
        start,
        operation,
        None if columns is None else frozenset(_fold(c) for c in columns),
    )
    queue: deque[tuple[_State, tuple[CascadeStep, ...]]] = deque([(begin, prefix)])
    visited: set[_State] = {begin}
    reached: set[str] = set()
    if prefix:
        reached.add(start)
        yield prefix[-1].foreign_key.child, prefix
    while queue:
        (table, op, changed), path = queue.popleft()
        for fk in by_parent.get(table, ()):
            if op == "update":
                if changed is not None and fk.parent_columns:
                    if not changed & {_fold(c) for c in fk.parent_columns}:
                        continue
            if fk.action(op) not in _MUTATING:
                continue
            step = CascadeStep(fk, op)
            child = _fold(fk.child)
            if step.effect == "delete":
                nxt: _State = (child, "delete", None)
            else:
                written = fk.set_columns if op == "delete" and fk.set_columns else fk.child_columns
                nxt = (child, "update", frozenset(_fold(c) for c in written))
            if nxt in visited:
                continue
            visited.add(nxt)
            here = (*path, step)
            if child not in reached:
                reached.add(child)
                yield fk.child, here
            queue.append((nxt, here))


def _dedupe(reaches: Sequence[CascadeReach]) -> tuple[CascadeReach, ...]:
    """One reach per (parent, operation, columns, table): the shortest path."""
    best: dict[tuple[str, str, tuple[str, ...], str], CascadeReach] = {}
    for reach in reaches:
        key = (reach.parent, reach.operation, reach.columns, reach.table)
        if key not in best or len(reach.path) < len(best[key].path):
            best[key] = reach
    return tuple(best[k] for k in sorted(best))


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------


def read_sqlite_foreign_keys(conn: Any) -> tuple[ForeignKey, ...]:
    """Every foreign key in a SQLite database's main schema.

    Uses the ``pragma_foreign_key_list`` table-valued function, so no table
    name is interpolated into SQL. A key that names no parent columns refers
    to the parent's primary key, which is resolved from ``pragma_table_info``.

    :param conn: A ``sqlite3.Connection``.
    """
    tables = [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM main.sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name"
        )
    ]
    keys: list[ForeignKey] = []
    for child in tables:
        rows = conn.execute(
            'SELECT id, seq, "table", "from", "to", on_update, on_delete '
            "FROM pragma_foreign_key_list(?) ORDER BY id, seq",
            (child,),
        ).fetchall()
        grouped: dict[int, list[Any]] = defaultdict(list)
        for row in rows:
            grouped[int(row[0])].append(row)
        for key_id in sorted(grouped):
            members = grouped[key_id]
            parent = str(members[0][2])
            targets = [m[4] for m in members]
            if any(t is None for t in targets):
                parent_columns = _sqlite_primary_key(conn, parent)
            else:
                parent_columns = tuple(str(t) for t in targets)
            keys.append(
                ForeignKey(
                    child=child,
                    child_columns=tuple(str(m[3]) for m in members),
                    parent=_sqlite_table_name(tables, parent),
                    parent_columns=parent_columns,
                    on_delete=str(members[0][6]).upper(),
                    on_update=str(members[0][5]).upper(),
                    name=f"{child}#{key_id}",
                )
            )
    return tuple(keys)


def _sqlite_table_name(tables: Sequence[str], name: str) -> str:
    """The parent as ``sqlite_master`` spells it; the clause may differ in case."""
    for table in tables:
        if _fold(table) == _fold(name):
            return table
    return name


def _sqlite_primary_key(conn: Any, table: str) -> tuple[str, ...]:
    rows = conn.execute(
        "SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk", (table,)
    ).fetchall()
    return tuple(str(r[0]) for r in rows)


_PG_FOREIGN_KEYS: Final = """
SELECT c.conname,
       cn.nspname, cc.relname,
       pn.nspname, pc.relname,
       c.confdeltype, c.confupdtype,
       ARRAY(SELECT a.attname::text
               FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_catalog.pg_attribute a
                 ON a.attrelid = c.conrelid AND a.attnum = k.attnum
              ORDER BY k.ord),
       ARRAY(SELECT a.attname::text
               FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_catalog.pg_attribute a
                 ON a.attrelid = c.confrelid AND a.attnum = k.attnum
              ORDER BY k.ord),
       {set_columns}
  FROM pg_catalog.pg_constraint c
  JOIN pg_catalog.pg_class cc ON cc.oid = c.conrelid
  JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace
  JOIN pg_catalog.pg_class pc ON pc.oid = c.confrelid
  JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
 WHERE c.contype = 'f' AND c.conparentid = 0
 ORDER BY cn.nspname, cc.relname, c.conname
"""

_PG_SET_COLUMNS: Final = """ARRAY(SELECT a.attname::text
               FROM unnest(c.confdelsetcols) WITH ORDINALITY AS k(attnum, ord)
               JOIN pg_catalog.pg_attribute a
                 ON a.attrelid = c.conrelid AND a.attnum = k.attnum
              ORDER BY k.ord)"""


def read_postgres_foreign_keys(conn: Any, schema: str = "public") -> tuple[ForeignKey, ...]:
    """Every foreign key in a PostgreSQL database, from ``pg_constraint``.

    Tables in ``schema`` are named bare, as a ``TableSpec`` names them; a table
    in any other schema is named ``schema.table``, so it can never be mistaken
    for an observed one. Constraints cloned onto partitions are skipped: the
    partitioned table's own constraint is the one that describes the reach.

    :param conn: A ``psycopg.Connection``.
    :param schema: The schema the observed tables live in.
    """
    version = int(conn.execute("SHOW server_version_num").fetchone()[0])
    set_columns = _PG_SET_COLUMNS if version >= 150000 else "ARRAY[]::text[]"
    rows = conn.execute(_PG_FOREIGN_KEYS.format(set_columns=set_columns)).fetchall()
    return tuple(
        ForeignKey(
            child=_pg_name(row[1], row[2], schema),
            child_columns=tuple(row[7]),
            parent=_pg_name(row[3], row[4], schema),
            parent_columns=tuple(row[8]),
            on_delete=_PG_ACTIONS.get(row[5], NO_ACTION),
            on_update=_PG_ACTIONS.get(row[6], NO_ACTION),
            name=str(row[0]),
            set_columns=tuple(row[9]),
        )
        for row in rows
    )


def _pg_name(namespace: str, relation: str, home: str) -> str:
    return relation if namespace == home else f"{namespace}.{relation}"
