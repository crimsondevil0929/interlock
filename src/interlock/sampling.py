"""What only the database knows, sampled for the metrics (``docs/EPIC7_DESIGN.md``
§2.4): the outbox's depth by state and its oldest message still due,
settlement's backlog, the inbox's pending facts and unmatched events, and the
fullest key of each rate window.

Read in one snapshot, read-only, every ``[metrics] every_seconds``, on a
connection of the sampler's own: a scrape touches no database. On
PostgreSQL the role must read the window ledger and the outbox's and inbox's
tables, as an ``audit_roles`` role may.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from interlock.windows import RateWindow

__all__ = ["STATES", "Sample", "sample_postgres", "sample_sqlite"]

STATES: Final = ("pending", "leased", "held", "delivered", "dead", "cancelled")
"""Every delivery state: a gauge for each, zero when no message is in it."""


@dataclass(frozen=True, slots=True)
class Sample:
    """One reading of the database.

    :ivar states: Messages in the outbox, for every state in :data:`STATES`.
    :ivar oldest_due: Seconds the oldest pending or leased message has been
        in the outbox; ``None`` when none is.
    :ivar backlog: Messages delivered and not settled yet.
    :ivar oldest_unsettled: Seconds the oldest of those has been delivered.
    :ivar facts_pending: Facts no plan has consumed yet.
    :ivar events_unmatched: Inbound events bound to no delivery yet.
    :ivar windows: For each configured window, the fullest key's total within
        its span, and how many keys hold anything there.
    """

    states: Mapping[str, int]
    oldest_due: float | None = None
    backlog: int = 0
    oldest_unsettled: float | None = None
    facts_pending: int = 0
    events_unmatched: int = 0
    windows: Mapping[str, tuple[Decimal, int]] = field(default_factory=dict)


def _states(rows: Sequence[Any]) -> dict[str, int]:
    found = {str(state): int(count) for state, count in rows}
    return {state: found.get(state, 0) for state in STATES}


def _fullest(totals: Mapping[str, Decimal]) -> tuple[Decimal, int]:
    return (max(totals.values(), default=Decimal(0)), len(totals))


def sample_sqlite(path: str, windows: Sequence[RateWindow], *, now_us: int) -> Sample:
    """Read a SQLite file's outbox, inbox and windows, opened read-only, in one
    read transaction. ``now_us`` is the reading's instant, microseconds since
    the epoch, as the file keeps its own."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        conn.execute("BEGIN")
        tables = {
            str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        states: dict[str, int] = dict.fromkeys(STATES, 0)
        oldest_due = oldest_unsettled = None
        backlog = 0
        if {"_interlock_outbox", "_interlock_outbox_state"} <= tables:
            states = _states(
                conn.execute(
                    "SELECT state, count(*) FROM _interlock_outbox_state GROUP BY state"
                ).fetchall()
            )
            (first,) = conn.execute(
                "SELECT min(o.enqueued_at) FROM _interlock_outbox_state AS s "
                "JOIN _interlock_outbox AS o ON o.message_id = s.message_id "
                "WHERE s.state IN ('pending', 'leased')"
            ).fetchone()
            oldest_due = None if first is None else max(0.0, (now_us - int(first)) / 1e6)
        if "_interlock_outbox_settlements" in tables:
            backlog, since = conn.execute(
                "SELECT count(*), min(s.updated_at) FROM _interlock_outbox_state AS s "
                "WHERE s.state = 'delivered' AND NOT EXISTS ("
                "SELECT 1 FROM _interlock_outbox_settlements AS t "
                "WHERE t.message_id = s.message_id)"
            ).fetchone()
            oldest_unsettled = None if since is None else max(0.0, (now_us - int(since)) / 1e6)
        facts = events = 0
        if {"_interlock_inbox_facts", "_interlock_inbox_consumed"} <= tables:
            (facts,) = conn.execute(
                "SELECT count(*) FROM _interlock_inbox_facts AS f WHERE NOT EXISTS ("
                "SELECT 1 FROM _interlock_inbox_consumed AS c WHERE c.fact_id = f.fact_id)"
            ).fetchone()
            (events,) = conn.execute(
                "SELECT count(*) FROM _interlock_inbox_events AS e WHERE NOT EXISTS ("
                "SELECT 1 FROM _interlock_inbox_facts AS f "
                "WHERE f.source = e.source AND f.event_seq = e.seq)"
            ).fetchone()
        held: dict[str, tuple[Decimal, int]] = {}
        for window in windows:
            totals: dict[str, Decimal] = {}
            if "_interlock_windows" in tables:
                since_us = now_us - window.span // timedelta(microseconds=1)
                for key, amount in conn.execute(
                    "SELECT key, amount FROM _interlock_windows WHERE window_name = ? AND at > ?",
                    (window.name, since_us),
                ):
                    totals[str(key)] = totals.get(str(key), Decimal(0)) + Decimal(str(amount))
            held[window.name] = _fullest(totals)
        return Sample(
            states=states,
            oldest_due=oldest_due,
            backlog=int(backlog),
            oldest_unsettled=oldest_unsettled,
            facts_pending=int(facts),
            events_unmatched=int(events),
            windows=held,
        )
    finally:
        conn.close()


def sample_postgres(
    dsn: str,
    windows: Sequence[RateWindow],
    *,
    timeout: float,
    application_name: str = "interlock-metrics",
) -> Sample:
    """Read PostgreSQL's outbox, inbox and window ledger in one ``REPEATABLE
    READ READ ONLY`` transaction, bounded by ``timeout`` seconds, as the role
    ``dsn`` names: one that may read them all. The connection is called
    ``application_name`` in ``pg_stat_activity``."""
    import psycopg

    milliseconds = max(1, int(timeout * 1000))
    with psycopg.connect(
        dsn,
        autocommit=True,
        prepare_threshold=None,
        application_name=application_name,
        connect_timeout=max(2, int(timeout)),
    ) as conn:
        conn.execute(
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; "
            f"SET LOCAL statement_timeout = {milliseconds}"
        )
        states = _states(
            conn.execute(
                "SELECT state, count(*) FROM interlock.outbox_state GROUP BY state"
            ).fetchall()
        )
        row = conn.execute(
            "SELECT extract(epoch FROM pg_catalog.clock_timestamp() - min(o.enqueued_at)) "
            "FROM interlock.outbox_state AS s "
            "JOIN interlock.outbox AS o ON o.message_id = s.message_id "
            "WHERE s.state IN ('pending', 'leased')"
        ).fetchone()
        oldest_due = None if row is None or row[0] is None else max(0.0, float(row[0]))
        row = conn.execute(
            "SELECT count(*), "
            "extract(epoch FROM pg_catalog.clock_timestamp() - min(s.updated_at)) "
            "FROM interlock.outbox_state AS s WHERE s.state = 'delivered' AND NOT EXISTS ("
            "SELECT 1 FROM interlock.outbox_settlements AS t WHERE t.message_id = s.message_id)"
        ).fetchone()
        backlog = 0 if row is None else int(row[0])
        oldest_unsettled = None if row is None or row[1] is None else max(0.0, float(row[1]))
        row = conn.execute(
            "SELECT (SELECT count(*) FROM interlock.inbox_facts AS f WHERE NOT EXISTS ("
            "        SELECT 1 FROM interlock.inbox_consumed AS c WHERE c.fact_id = f.fact_id)), "
            "       (SELECT count(*) FROM interlock.inbox_events AS e WHERE NOT EXISTS ("
            "        SELECT 1 FROM interlock.inbox_facts AS f "
            "        WHERE f.source = e.source AND f.event_seq = e.seq))"
        ).fetchone()
        facts, events = (0, 0) if row is None else (int(row[0]), int(row[1]))
        held: dict[str, tuple[Decimal, int]] = {}
        for window in windows:
            totals = {
                str(key): Decimal(str(total))
                for key, total in conn.execute(
                    "SELECT key, sum(amount) FROM interlock.window_ledger "
                    "WHERE window_name = %s AND at > pg_catalog.clock_timestamp() "
                    "- %s * interval '1 microsecond' GROUP BY key",
                    (window.name, window.span // timedelta(microseconds=1)),
                ).fetchall()
            }
            held[window.name] = _fullest(totals)
        conn.execute("COMMIT")
    return Sample(
        states=states,
        oldest_due=oldest_due,
        backlog=backlog,
        oldest_unsettled=oldest_unsettled,
        facts_pending=facts,
        events_unmatched=events,
        windows=held,
    )
