"""``EscrowRuntime``, configured whole (``docs/EPIC6_DESIGN.md`` §1), on both stores.

- Any substrate, in place of the SQLite path, with every engine option passed
  through: rate windows refuse a plan past a limit, inbound facts are offered
  and consumed, outbound requests are enqueued.
- The claim-and-settle anchor, passed in, settles each plan with its commit.
- ``from_config`` builds the runtime ``interlock.toml`` describes, ledger,
  chain and receipt log included, and closes what it opened.
- Misconfiguration is refused at construction, plainly.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov import BudgetManager
from agentgov.core import EntryType

from interlock import BlastRadius, EscrowRuntime, LedgerAnchor, PlanBuilder, TableSpec
from interlock.config import load_config
from interlock.exceptions import InboundFactError
from interlock.operators import generate_key
from interlock.windows import Plans, RateWindow
from tests.conftest import OBSERVED, Pg, build_sqlite_back_office
from tests.crash_child import ACKNOWLEDGED
from tests.inbox_env import INBOX_KEYS, InboxSite, inbox_site, refund_event, stripe_webhook
from tests.outbox_env import BACKENDS, REGISTRY, SCOPE, Outbox, build_either
from tests.schemas import specs


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _status(outbox: Outbox, value: str) -> Any:
    named = outbox.named("status")
    return (
        PlanBuilder(SCOPE)
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = {named} WHERE id = 500",
            parameters={"status": value},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )


def test_a_runtime_on_any_substrate_passes_every_option_through(site: InboxSite) -> None:
    outbox = site.outbox
    window = RateWindow("plans_per_agent", timedelta(minutes=5), 2, Plans())
    runtime = EscrowRuntime(
        substrate=outbox.substrate(),
        scope_id=SCOPE,
        checkers=[BlastRadius(10)],
        sinks=REGISTRY,
        windows=[window],
        inbox=INBOX_KEYS,
    )
    try:
        # Facts are offered through the runtime, and consumed in its plans.
        site.deliver("re_1")
        site.receive(site.inbox(), "stripe", stripe_webhook(refund_event("re_1")))
        (fact,) = runtime.facts()
        assert runtime.facts("nobody") == ()
        plan = (
            runtime.plan(intent="the refund went through")
            .consume(fact)
            .update(
                table="orders",
                statement=f"UPDATE orders SET status = {outbox.named('s')} WHERE id = 500",
                parameters={"s": "refunded"},
                tenant_id="acme",
                stated_rows=1,
            )
            .build()
        )
        assert runtime.execute(plan).committed
        assert runtime.facts() == ()
        # The window counts plans: the delivery's plan (another engine) does
        # not share this runtime's history, so two more commit and a third
        # is refused.
        assert runtime.execute(_status(outbox, "open")).committed
        refused = runtime.execute(_status(outbox, "shipped"))
        assert not refused.committed
        assert refused.blocked_by == ("rate_window:plans_per_agent",)
        assert runtime.cascade_report is not None
    finally:
        runtime.close()


def test_a_runtime_settles_each_plan_with_its_commit(pg: Pg) -> None:
    from agentgov.postgres import PostgresStore

    from interlock import PostgresSubstrate

    governor = BudgetManager.open_postgres(pg.admin)
    try:
        governor.open_root(SCOPE, "10.00")
        store = governor.store
        assert isinstance(store, PostgresStore)
        store.grant_join(pg.role)
        anchor = LedgerAnchor(governed=governor, same_transaction=True)
        runtime = EscrowRuntime(
            substrate=PostgresSubstrate(
                pg.agent, tables=specs(*OBSERVED), acknowledge_cascades=ACKNOWLEDGED
            ),
            scope_id=SCOPE,
            checkers=[BlastRadius(10)],
            anchor=anchor,
            settle_cost="0.25",
        )
        with runtime:
            result = runtime.execute_sql(
                "UPDATE orders SET status = %(s)s WHERE id = 500",
                {"s": "paid"},
                table="orders",
                tenant_id="acme",
                stated_rows=1,
            )
            assert result.committed
        # The caller's anchor and governor are the caller's: still open.
        governor.refresh()
        spends = [e for e in governor.audit_trail(SCOPE) if e.entry_type is EntryType.SPEND]
        assert [s.amount for s in spends] == [Decimal("0.25")]
        governor.verify_integrity()
    finally:
        governor.close()


def test_misconfiguration_is_refused_plainly(tmp_path: Path) -> None:
    db = build_sqlite_back_office(tmp_path / "db.sqlite")
    from interlock import SqliteSubstrate

    substrate = SqliteSubstrate(db, tables=specs("orders"))
    with pytest.raises(ValueError, match="db_path or a substrate: one"):
        EscrowRuntime(db, substrate=substrate, scope_id=SCOPE)
    with pytest.raises(ValueError, match="db_path or a substrate: one"):
        EscrowRuntime(scope_id=SCOPE)
    with pytest.raises(ValueError, match="configured already"):
        EscrowRuntime(substrate=substrate, tables=specs("orders"), scope_id=SCOPE)
    with pytest.raises(ValueError, match="configured already"):
        EscrowRuntime(substrate=substrate, max_stage_seconds=3, scope_id=SCOPE)
    governor = BudgetManager()
    with pytest.raises(ValueError, match="not both"):
        EscrowRuntime(
            db,
            tables=specs("orders"),
            scope_id=SCOPE,
            anchor=LedgerAnchor(governed=governor),
            governed=governor,
        )
    runtime = EscrowRuntime(substrate=substrate, scope_id=SCOPE)
    with pytest.raises(InboundFactError, match="inbox"):
        runtime.facts()
    runtime.close()


CONFIG = """
substrate = "sqlite"
database = "{database}"

[[tables]]
name = "orders"
columns = ["id", "customer_id", "tenant", "status", "total"]
tenant_column = "tenant"

[[windows]]
name = "plans_per_agent"
span_seconds = 300
limit = 1
measure = "plans"

[engine]
chain = "escrow.chain"
settle_cost = "0.05"
ledger = "governor.db"

[receipts]
log = "receipts.jsonl"
key = "receipts.key"
log_id = "runtime-receipts"
"""


def test_from_config_builds_the_runtime_the_file_describes(tmp_path: Path) -> None:
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    generate_key(tmp_path / "receipts.key")
    with BudgetManager.open_sqlite(str(tmp_path / "governor.db")) as governor:
        governor.open_root(SCOPE, "1.00")
    path = tmp_path / "interlock.toml"
    path.write_text(CONFIG.format(database=database))
    config = load_config(path)
    runtime = EscrowRuntime.from_config(config, scope_id=SCOPE, checkers=[BlastRadius(10)])
    try:
        sql = "UPDATE orders SET status = :s WHERE id = 500"
        assert runtime.execute_sql(sql, {"s": "a"}, tenant_id="acme", stated_rows=1).committed
        refused = runtime.execute_sql(sql, {"s": "b"}, tenant_id="acme", stated_rows=1)
        assert refused.blocked_by == ("rate_window:plans_per_agent",)
        receipts = runtime.engine.receipts
        assert receipts is not None and receipts.log.log_id == "runtime-receipts"
        assert len(receipts.log) == 2
        runtime.verify()
    finally:
        runtime.close()
    # Closed: the chain file, the receipt log and the ledger are free again.
    assert (tmp_path / "escrow.chain").stat().st_size > 0
    reopened = EscrowRuntime.from_config(config, scope_id=SCOPE, checkers=[BlastRadius(10)])
    try:
        assert len(reopened.chain) > 0
    finally:
        reopened.close()
    with BudgetManager.open_sqlite(str(tmp_path / "governor.db")) as governor:
        spent = sum(
            (e.amount for e in governor.audit_trail(SCOPE) if e.entry_type is EntryType.SPEND),
            Decimal(0),
        )
        assert spent == Decimal("0.10")
        governor.verify_integrity()


def test_from_config_on_postgresql_settles_with_the_commit(pg: Pg, tmp_path: Path) -> None:
    from agentgov.postgres import PostgresStore

    with BudgetManager.open_postgres(pg.admin) as governor:
        governor.open_root(SCOPE, "5.00")
        store = governor.store
        assert isinstance(store, PostgresStore)
        store.grant_join(pg.role)
    path = tmp_path / "interlock.toml"
    tables = "".join(
        f'[[tables]]\nname = "{t.name}"\nprimary_key = "{t.primary_key}"\n'
        f"columns = {list(t.columns)!r}\n"
        + (f'tenant_column = "{t.tenant_column}"\n' if t.tenant_column else "")
        for t in specs(*OBSERVED)
    ).replace("'", '"')
    path.write_text(
        f'substrate = "postgres"\ndatabase = "{pg.admin}"\n'
        f"acknowledge_cascades = {list(ACKNOWLEDGED)!r}\n".replace("'", '"')
        + tables
        + f'[engine]\ndatabase = "{pg.agent}"\nledger = "{pg.admin}"\nsame_transaction = true\n'
        f'settle_cost = "0.10"\n'
    )
    runtime = EscrowRuntime.from_config(
        load_config(path), scope_id=SCOPE, checkers=[BlastRadius(10)]
    )
    with runtime:
        result = runtime.execute_sql(
            "UPDATE orders SET status = %(s)s WHERE id = 500",
            {"s": "paid"},
            table="orders",
            tenant_id="acme",
            stated_rows=1,
        )
        assert result.committed
        assert runtime.anchor is not None and runtime.anchor.joins_transaction
    with BudgetManager.open_postgres(pg.admin) as governor:
        spends = [e for e in governor.audit_trail(SCOPE) if e.entry_type is EntryType.SPEND]
        assert [s.amount for s in spends] == [Decimal("0.10")]


def test_a_runtime_over_an_outbox_enqueues(outbox: Outbox) -> None:
    runtime = EscrowRuntime(
        substrate=outbox.substrate(), scope_id=SCOPE, checkers=[BlastRadius(0)], sinks=REGISTRY
    )
    with runtime:
        plan = (
            runtime.plan()
            .enqueue(sink="mail", operation="send", payload={"to": "a@acme.test", "subject": "x"})
            .build()
        )
        assert runtime.execute(plan).committed
    assert outbox.requests() == 1


def test_the_tables_of_a_passed_substrate_bound_the_default_checkers(tmp_path: Path) -> None:
    from interlock import SqliteSubstrate

    db = build_sqlite_back_office(tmp_path / "db.sqlite")
    runtime = EscrowRuntime(
        substrate=SqliteSubstrate(db, tables=[TableSpec("orders", columns=["id", "status"])]),
        scope_id=SCOPE,
    )
    with runtime:
        names = {c.name for c in runtime.engine._checkers}
        assert "table_allowlist" in names
