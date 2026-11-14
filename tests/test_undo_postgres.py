"""Undo on PostgreSQL (1.10.0), against a real server: each commit's images kept in
``interlock.undo_images``, in the stage's own transaction, under the database's own access
control, and put back exactly, ``NUMERIC`` as ``Decimal``."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")

from interlock import (  # noqa: E402
    BlastRadius,
    EffectKind,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
)
from interlock.exceptions import SubstrateConfigurationError  # noqa: E402
from interlock.undo import UNDO_EXACT, digest_problems  # noqa: E402
from tests.conftest import OBSERVED, Pg  # noqa: E402
from tests.schemas import specs  # noqa: E402

WEEK = timedelta(days=7)


def rows(dsn: str) -> list[tuple[Any, ...]]:
    with psycopg.connect(dsn) as conn:
        return list(conn.execute("SELECT * FROM orders ORDER BY id")) + list(
            conn.execute("SELECT * FROM order_items ORDER BY id")
        )


def mistake() -> Any:
    return (
        PlanBuilder("agent")
        .add(
            EffectKind.UPDATE,
            table="orders",
            statement="UPDATE orders SET total = 99.99 WHERE id = 500",
        )
        .add(
            EffectKind.INSERT,
            table="orders",
            statement="INSERT INTO orders VALUES (777, 10, 'acme', 'open', 12.34)",
        )
        .build()
    )


def test_a_postgres_undo_puts_back_exact_numerics(pg: Pg) -> None:
    sub = PostgresSubstrate(pg.agent, tables=specs(*OBSERVED), undo=WEEK)
    before = rows(pg.admin)
    done = EscrowEngine(sub, checkers=[]).execute(mistake())
    assert done.committed and len(done.changes) == 2
    with psycopg.connect(pg.admin) as conn:
        kept = conn.execute("SELECT count(*) FROM interlock.undo_images").fetchone()
    assert kept is not None and kept[0] == 2
    # the stage's role reads them only through the install's function
    with psycopg.connect(pg.agent) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT * FROM interlock.undo_images")

    undone = EscrowEngine(sub, checkers=[BlastRadius(1)]).undo(done.plan.plan_id, scope_id="agent")
    assert undone.committed, undone.blocked_by
    assert rows(pg.admin) == before
    assert digest_problems(undone.undid, undone.changes) == []


def test_a_row_changed_since_refuses_the_postgres_undo(pg: Pg) -> None:
    sub = PostgresSubstrate(pg.agent, tables=specs(*OBSERVED), undo=WEEK)
    done = EscrowEngine(sub, checkers=[]).execute(mistake())
    assert done.committed
    with psycopg.connect(pg.admin) as conn:
        conn.execute("UPDATE orders SET status = 'held' WHERE id = 777")
    edited = rows(pg.admin)
    undone = EscrowEngine(sub, checkers=[]).undo(done.plan.plan_id, scope_id="agent")
    assert not undone.committed and undone.blocked_by == (UNDO_EXACT,)
    assert "orders 777 was not put back" in undone.verdict.blocking[0].message  # type: ignore[union-attr]
    assert rows(pg.admin) == edited


def test_an_installation_before_undo_is_named(pg: Pg) -> None:
    with psycopg.connect(pg.admin) as conn:
        conn.execute("DROP FUNCTION interlock.undo_keep(bytea, text, text, bytea, bigint)")
    sub = PostgresSubstrate(pg.agent, tables=specs(*OBSERVED), undo=WEEK)
    before = rows(pg.admin)
    with pytest.raises(SubstrateConfigurationError, match="run `interlock install`"):
        EscrowEngine(sub, checkers=[]).execute(mistake())
    assert rows(pg.admin) == before
    assert PostgresSubstrate(pg.agent, tables=specs(*OBSERVED), undo=WEEK).kept("x") is None
