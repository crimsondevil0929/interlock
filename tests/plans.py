"""Realistic plans and engines on the back-office schema, shared by the tests.

The plans are written once with a placeholder function, so the same batch runs
on SQLite (``:name``) and PostgreSQL (``%(name)s``).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from interlock import (
    BlastRadius,
    EscrowEngine,
    PlanBuilder,
    SqliteSubstrate,
    TenantDrawdownGuard,
    TenantIsolation,
)
from interlock.types import EffectId, EffectPlan
from tests.conftest import OBSERVED, Pg
from tests.schemas import specs


def pg_placeholder(name: str) -> str:
    return f"%({name})s"


def snapshot(path: str) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows: list[tuple[Any, ...]] = []
        for table in ("orders", "order_items", "accounts", "refunds", "shipments"):
            rows += [(table, *r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
        return rows
    finally:
        conn.close()


def support_batch(placeholder: Callable[[str], str] = lambda n: f":{n}") -> EffectPlan:
    """Four corrections for tenant acme, and one that reaches globex."""
    p = placeholder
    return (
        PlanBuilder("support-agent", intent="apply ticket 9001 corrections")
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = 'held' WHERE id = {p('a')}",
            parameters={"a": 500},
            tenant_id="acme",
            effect_id=EffectId("hold_500"),
            independent=True,
        )
        .update(
            table="orders",
            statement=f"UPDATE orders SET total = {p('t')} WHERE id = {p('a')}",
            parameters={"t": 30, "a": 501},
            tenant_id="acme",
            effect_id=EffectId("reprice_501"),
            independent=True,
        )
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = 'held' WHERE id = {p('a')}",
            parameters={"a": 600},
            tenant_id="acme",
            effect_id=EffectId("hold_600"),
            independent=True,
        )
        .update(
            table="order_items",
            statement=f"UPDATE order_items SET qty = qty + 1 WHERE order_id = {p('a')}",
            parameters={"a": 500},
            tenant_id="acme",
            effect_id=EffectId("bump_items_500"),
            after=[EffectId("hold_500")],
        )
        .build()
    )


def transfer(placeholder: Callable[[str], str] = lambda n: f":{n}") -> EffectPlan:
    """A debit and its balancing credit within acme, and a globex write."""
    p = placeholder
    return (
        PlanBuilder("treasury-agent", intent="rebalance acme accounts")
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance - {p('x')} WHERE id = 100",
            parameters={"x": 400},
            tenant_id="acme",
            effect_id=EffectId("debit"),
            independent=True,
        )
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance + {p('x')} WHERE id = 101",
            parameters={"x": 400},
            tenant_id="acme",
            effect_id=EffectId("credit"),
            independent=True,
        )
        .update(
            table="accounts",
            statement=f"UPDATE accounts SET balance = balance + {p('x')} WHERE id = 200",
            parameters={"x": 1},
            tenant_id="acme",
            effect_id=EffectId("globex_touch"),
            independent=True,
        )
        .build()
    )


def sqlite_engine(path: str, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        SqliteSubstrate(
            path,
            tables=specs("orders", "order_items", "refunds", "shipments", "accounts"),
            acknowledge_cascades=["stock_reservations", "ledger_entries"],
        ),
        checkers=[
            TenantIsolation(1),
            BlastRadius(10),
            TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
        ],
        **kwargs,
    )


def pg_engine(env: Pg, **kwargs: Any) -> EscrowEngine:
    from interlock import PostgresSubstrate

    return EscrowEngine(
        PostgresSubstrate(
            env.agent,
            tables=specs(*OBSERVED),
            acknowledge_cascades=["shipment_events", "ledger_entries"],
        ),
        checkers=[
            TenantIsolation(1),
            BlastRadius(10),
            TenantDrawdownGuard("accounts", "balance", max_drop_fraction=0.3),
        ],
        **kwargs,
    )


def pg_snapshot(env: Pg) -> list[tuple[Any, ...]]:
    import psycopg

    with psycopg.connect(env.admin) as conn:
        rows: list[tuple[Any, ...]] = []
        for table in ("orders", "order_items", "accounts", "refunds", "shipments"):
            rows += [
                (table, *r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            ]
        return rows
