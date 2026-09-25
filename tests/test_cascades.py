"""The cascade check (2.1): no foreign-key action writes a table nobody measures.

A ``DELETE`` on an observed table whose foreign keys cascade into an
unobserved one used to destroy those rows unmeasured: the diff reported the
parent's rows, every checker passed on them, and the rest went unrecorded.
The check reads the foreign-key graph and refuses the operation before a row
changes, unless the operator acknowledged the unobserved table, in which case
the gap is written into the chain for every stage that runs with it.

Everything here runs against the fifteen-table back-office schema in
``tests/schemas.py``, on files, never ``:memory:``. The graph readers are also
checked against a real PostgreSQL, where the same schema must produce the same
report.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest

from interlock import (
    BlastRadius,
    EffectKind,
    EscrowEngine,
    EscrowRuntime,
    PlanBuilder,
    SqliteSubstrate,
    StageState,
    TableSpec,
)
from interlock.cascade import (
    CASCADE,
    NO_ACTION,
    RESTRICT,
    SET_DEFAULT,
    SET_NULL,
    CascadeReach,
    CascadeReport,
    ForeignKey,
    analyze_cascades,
    read_postgres_foreign_keys,
    read_sqlite_foreign_keys,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    ForbiddenStatementError,
    StageError,
    SubstrateUnavailableError,
)
from interlock.types import Effect, EffectPlan
from tests.schemas import specs

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def graph(path: str) -> tuple[ForeignKey, ...]:
    conn = sqlite3.connect(path)
    try:
        return read_sqlite_foreign_keys(conn)
    finally:
        conn.close()


def report(path: str, *observed: str, acknowledged: tuple[str, ...] = ()) -> CascadeReport:
    return analyze_cascades(graph(path), observed, acknowledged)


def reached(rep: CascadeReport, parent: str, operation: str) -> dict[str, list[str]]:
    """Unobserved table -> the path of tables leading to it."""
    return {
        r.table: [r.parent, *(s.foreign_key.child for s in r.path)]
        for r in rep.reaches
        if r.parent == parent and r.operation == operation
    }


def count(path: str, table: str) -> int:
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
    finally:
        conn.close()


def one(table: str, statement: str, kind: EffectKind = EffectKind.DELETE) -> EffectPlan:
    return PlanBuilder("agent").add(kind, table=table, statement=statement).build()


def engine(path: str, *observed: str, **kwargs: object) -> EscrowEngine:
    substrate = SqliteSubstrate(path, tables=specs(*observed), **kwargs)  # type: ignore[arg-type]
    return EscrowEngine(substrate, checkers=[BlastRadius(1000)])


def edges(keys: tuple[ForeignKey, ...]) -> set[tuple[object, ...]]:
    return {
        (k.child, k.child_columns, k.parent, k.parent_columns, k.on_delete, k.on_update)
        for k in keys
    }


EXPECTED_EDGES = {
    ("customers", ("tenant_id",), "tenants", ("id",), CASCADE, NO_ACTION),
    ("accounts", ("customer_id",), "customers", ("id",), CASCADE, NO_ACTION),
    ("ledger_entries", ("account_id",), "accounts", ("id",), CASCADE, CASCADE),
    ("orders", ("customer_id",), "customers", ("id",), CASCADE, NO_ACTION),
    ("order_items", ("order_id",), "orders", ("id",), CASCADE, NO_ACTION),
    ("order_items", ("sku",), "products", ("sku",), RESTRICT, CASCADE),
    ("refunds", ("order_item_id",), "order_items", ("id",), CASCADE, NO_ACTION),
    ("shipments", ("order_id",), "orders", ("id",), SET_NULL, NO_ACTION),
    ("shipment_events", ("shipment_id",), "shipments", ("id",), CASCADE, NO_ACTION),
    ("invoices", ("order_id",), "orders", ("id",), RESTRICT, NO_ACTION),
    ("payments", ("invoice_id",), "invoices", ("id",), CASCADE, NO_ACTION),
    ("stock_reservations", ("order_id",), "orders", ("id",), SET_DEFAULT, NO_ACTION),
    (
        "stock_reservations",
        ("warehouse", "sku"),
        "warehouse_stock",
        ("warehouse", "sku"),
        CASCADE,
        CASCADE,
    ),
    ("categories", ("parent_id",), "categories", ("id",), CASCADE, NO_ACTION),
    ("employees", ("manager_id",), "employees", ("id",), SET_NULL, NO_ACTION),
}


# --------------------------------------------------------------------------
# reading the graph
# --------------------------------------------------------------------------


def test_the_sqlite_reader_reads_every_constraint(back_office: str) -> None:
    """Including the implicit primary-key reference and the composite key."""
    assert edges(graph(back_office)) == EXPECTED_EDGES


def test_a_parent_named_in_another_case_resolves_to_the_table(tmp_path: Path) -> None:
    path = str(tmp_path / "case.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE Orders (id INTEGER PRIMARY KEY)")
    conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, "
        "order_id INTEGER REFERENCES ORDERS ON DELETE CASCADE)"
    )
    conn.close()
    (key,) = graph(path)
    assert (key.parent, key.parent_columns) == ("Orders", ("id",))
    rep = report(path, "orders")
    assert [r.table for r in rep.gated] == ["notes"]


# --------------------------------------------------------------------------
# the analysis
# --------------------------------------------------------------------------


def test_a_delete_reaches_four_deep_by_the_shortest_path(back_office: str) -> None:
    """customers -> orders -> order_items -> refunds, and every branch beside it."""
    rep = report(back_office, "customers")
    assert reached(rep, "customers", "delete") == {
        "accounts": ["customers", "accounts"],
        "ledger_entries": ["customers", "accounts", "ledger_entries"],
        "orders": ["customers", "orders"],
        "order_items": ["customers", "orders", "order_items"],
        "refunds": ["customers", "orders", "order_items", "refunds"],
        "shipments": ["customers", "orders", "shipments"],
        "stock_reservations": ["customers", "orders", "stock_reservations"],
    }
    refunds = next(r for r in rep.reaches if r.table == "refunds")
    assert refunds.describe() == (
        "DELETE on customers reaches refunds: "
        "customers -[ON DELETE CASCADE]-> orders, then "
        "orders -[ON DELETE CASCADE]-> order_items, then "
        "order_items -[ON DELETE CASCADE]-> refunds"
    )


def test_set_null_updates_the_child_and_goes_no_further(back_office: str) -> None:
    """``shipments.order_id`` is set to NULL; nothing references that column,
    so ``shipment_events`` is never reached, though it cascades from shipments."""
    rep = report(back_office, "orders", "order_items")
    assert reached(rep, "orders", "delete") == {
        "refunds": ["orders", "order_items", "refunds"],
        "shipments": ["orders", "shipments"],
        "stock_reservations": ["orders", "stock_reservations"],
    }
    shipments = next(r for r in rep.reaches if r.table == "shipments")
    assert shipments.path[0].effect == "update"


def test_restrict_and_no_action_reach_nothing(back_office: str) -> None:
    """``invoices`` RESTRICTs deleting an order, so neither it nor ``payments``
    is reached; ``order_items`` RESTRICTs deleting a product."""
    rep = report(back_office, "orders", "order_items", "shipments", "stock_reservations")
    assert reached(rep, "orders", "delete") == {"refunds": ["orders", "order_items", "refunds"]}
    assert not {"invoices", "payments"} & {r.table for r in rep.reaches}
    # shipments is observed now, so its own deletes are the ones that reach
    # shipment_events; the order's SET NULL still does not.
    assert reached(rep, "shipments", "delete") == {
        "shipment_events": ["shipments", "shipment_events"]
    }
    assert reached(report(back_office, "products"), "products", "delete") == {}


def test_updates_are_gated_only_on_the_referenced_columns(back_office: str) -> None:
    rep = report(back_office, "products")
    assert [(r.operation, r.columns, r.table) for r in rep.reaches] == [
        ("update", ("sku",), "order_items")
    ]
    gate = rep.gates()["products"]
    assert not gate.delete
    assert gate.blocks_update_of("sku")
    assert not gate.blocks_update_of("price")


def test_an_update_cascade_follows_only_the_columns_it_writes(back_office: str) -> None:
    """``products.sku`` cascades into ``order_items.sku``. ``refunds`` hangs off
    ``order_items.id``, which the cascade does not touch."""
    rep = report(back_office, "products")
    assert "refunds" not in {r.table for r in rep.reaches}


def test_a_composite_key_is_one_edge(back_office: str) -> None:
    rep = report(back_office, "stock_reservations")
    assert rep.reaches == ()
    # warehouse_stock has no single-column key, so it is analysed directly.
    rep = analyze_cascades(graph(back_office), ["warehouse_stock"])
    assert {(r.operation, r.columns, r.table) for r in rep.reaches} == {
        ("delete", (), "stock_reservations"),
        ("update", ("warehouse", "sku"), "stock_reservations"),
    }


def test_self_references_terminate(back_office: str) -> None:
    assert report(back_office, "categories").reaches == ()
    assert report(back_office, "employees").reaches == ()
    rep = report(back_office, "shipment_events")
    assert rep.reaches == ()


def test_a_cycle_through_unobserved_tables_terminates() -> None:
    a_to_b = ForeignKey("b", ("a_id",), "a", ("id",), CASCADE, CASCADE)
    b_to_a = ForeignKey("a", ("b_id",), "b", ("id",), CASCADE, CASCADE)
    rep = analyze_cascades([a_to_b, b_to_a], ["a"])
    assert {(r.operation, r.table) for r in rep.reaches} == {("delete", "b"), ("update", "b")}


def test_unresolved_parent_columns_gate_every_update() -> None:
    key = ForeignKey("child", ("p",), "parent", (), CASCADE, CASCADE)
    rep = analyze_cascades([key], ["parent"])
    gate = rep.gates()["parent"]
    assert gate.update_any and gate.blocks_update_of("anything")
    update = next(r for r in rep.reaches if r.operation == "update")
    assert "of any column" in update.describe()


def test_on_delete_set_null_with_a_column_list_writes_only_those() -> None:
    """PostgreSQL 15 ``ON DELETE SET NULL (col)``: the rest of a composite key
    stays, so a key hanging off another column is not reached."""
    child = ForeignKey(
        "child",
        ("tenant", "parent_id"),
        "parent",
        ("tenant", "id"),
        SET_NULL,
        NO_ACTION,
        set_columns=("parent_id",),
    )
    grandchild = ForeignKey("grand", ("tenant",), "child", ("tenant",), CASCADE, CASCADE)
    rep = analyze_cascades([child, grandchild], ["parent"])
    assert [(r.table, r.path[-1].effect) for r in rep.reaches] == [("child", "update")]
    widened = ForeignKey(
        "child", ("tenant", "parent_id"), "parent", ("tenant", "id"), SET_NULL, NO_ACTION
    )
    rep = analyze_cascades([widened, grandchild], ["parent"])
    assert {r.table for r in rep.reaches} == {"child", "grand"}


def test_acknowledgment_lifts_exactly_the_named_table(back_office: str) -> None:
    rep = report(back_office, "orders", "order_items", acknowledged=("shipments",))
    assert {r.table for r in rep.gaps} == {"shipments"}
    assert {r.table for r in rep.gated} == {"refunds", "stock_reservations"}
    assert rep.gates()["orders"].delete  # still refused: two gaps remain
    assert not rep.closed
    rep = report(
        back_office,
        "orders",
        "order_items",
        acknowledged=("shipments", "refunds", "stock_reservations"),
    )
    assert rep.gated == ()
    assert rep.gates() == {}
    assert rep.describe_gaps() == (
        "delete order_items->refunds; delete orders->refunds; "
        "delete orders->shipments; delete orders->stock_reservations"
    )


def test_a_fully_observed_closure_is_closed(back_office: str) -> None:
    rep = report(
        back_office,
        "tenants",
        "customers",
        "accounts",
        "ledger_entries",
        "orders",
        "order_items",
        "refunds",
        "shipments",
        "shipment_events",
        "stock_reservations",
    )
    assert rep.reaches == () and rep.closed and rep.gates() == {}


def test_an_acknowledgment_nothing_reaches_is_reported(back_office: str) -> None:
    rep = report(back_office, "orders", acknowledged=("payments", "Refunds"))
    assert rep.unreached_acknowledgments == frozenset({"payments"})


# --------------------------------------------------------------------------
# enforcement on SQLite
# --------------------------------------------------------------------------


def test_a_gated_delete_is_refused_before_any_row_changes(back_office: str) -> None:
    before = {t: count(back_office, t) for t in ("orders", "order_items", "refunds", "shipments")}
    eng = engine(back_office, "orders", "order_items")
    with pytest.raises(ForbiddenStatementError) as caught:
        eng.execute(one("orders", "DELETE FROM orders WHERE id = 500"))
    message = str(caught.value)
    assert "DELETE on 'orders' is refused" in message
    assert "orders -[ON DELETE CASCADE]-> order_items, then" in message
    assert "order_items -[ON DELETE CASCADE]-> refunds" in message
    assert "acknowledge_cascades" in message
    after = {t: count(back_office, t) for t in before}
    assert after == before
    assert eng.chain.records()[-1].record_type is RecordType.ABORTED


def test_a_delete_that_matches_no_row_is_still_refused(back_office: str) -> None:
    """The refusal is made when SQLite prepares the statement, not per row."""
    with pytest.raises(ForbiddenStatementError, match="DELETE on 'orders'"):
        engine(back_office, "orders").execute(one("orders", "DELETE FROM orders WHERE id = -1"))


def test_updates_of_other_columns_on_a_gated_parent_commit(back_office: str) -> None:
    result = engine(back_office, "orders").execute(
        one("orders", "UPDATE orders SET status = 'held' WHERE id = 500", EffectKind.UPDATE)
    )
    assert result.committed
    assert result.diff is not None and result.diff.blast_radius == 1


def test_an_update_of_a_referenced_column_is_refused(back_office: str) -> None:
    eng = engine(back_office, "products")
    with pytest.raises(ForbiddenStatementError, match="UPDATE of sku on 'products'"):
        eng.execute(
            one("products", "UPDATE products SET sku = 'SKU-9' WHERE id = 1", EffectKind.UPDATE)
        )
    assert (
        engine(back_office, "products")
        .execute(one("products", "UPDATE products SET price = 11 WHERE id = 1", EffectKind.UPDATE))
        .committed
    )


def test_updating_the_rowid_of_a_gated_key_is_refused(back_office: str) -> None:
    """``orders.id`` is an INTEGER PRIMARY KEY, so ``rowid`` is another name
    for it. ``accounts`` references ``ledger_entries`` ON UPDATE CASCADE."""
    eng = engine(back_office, "accounts")
    for column in ("rowid", "_rowid_", "oid", "id"):
        with pytest.raises(ForbiddenStatementError, match="on 'accounts' is refused"):
            eng.execute(
                one(
                    "accounts",
                    f"UPDATE accounts SET {column} = 999 WHERE id = 100",
                    EffectKind.UPDATE,
                )
            )
    assert count(back_office, "ledger_entries") == 3


def test_inserting_into_a_gated_parent_is_allowed(back_office: str) -> None:
    result = engine(back_office, "orders").execute(
        one(
            "orders",
            "INSERT INTO orders VALUES (502, 10, 'acme', 'open', '5.00')",
            EffectKind.INSERT,
        )
    )
    assert result.committed


def test_insert_or_replace_cannot_delete_through_a_cascade(back_office: str) -> None:
    """REPLACE deletes the conflicting row, and the delete cascades; SQLite
    reports the statement as an INSERT, so the parent gate alone would miss
    it. The authorizer sees the foreign-key action SQLite compiles for it."""
    eng = engine(back_office, "orders")
    with pytest.raises(ForbiddenStatementError, match="foreign-key action"):
        eng.execute(
            one(
                "orders",
                "INSERT OR REPLACE INTO orders VALUES (500, 10, 'acme', 'open', '1.00')",
                EffectKind.INSERT,
            )
        )
    assert count(back_office, "order_items") == 4
    assert count(back_office, "refunds") == 1


def test_a_schema_level_replace_conflict_clause_is_caught_too(tmp_path: Path) -> None:
    path = str(tmp_path / "replace.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE plans (id INTEGER PRIMARY KEY, code TEXT UNIQUE ON CONFLICT REPLACE);
        CREATE TABLE seats (id INTEGER PRIMARY KEY,
                            plan_code TEXT REFERENCES plans(code) ON DELETE CASCADE);
        INSERT INTO plans VALUES (1, 'pro');
        INSERT INTO seats VALUES (10, 'pro');
        """
    )
    conn.close()
    substrate = SqliteSubstrate(path, tables=[TableSpec("plans", columns=["id", "code"])])
    eng = EscrowEngine(substrate, checkers=[])
    with pytest.raises(ForbiddenStatementError, match="seats"):
        eng.execute(one("plans", "INSERT INTO plans VALUES (2, 'pro')", EffectKind.INSERT))
    assert count(path, "seats") == 1


def test_an_acknowledged_cascade_runs_and_the_chain_says_so(back_office: str) -> None:
    eng = engine(
        back_office,
        "orders",
        "order_items",
        acknowledge_cascades=["shipments", "refunds", "stock_reservations"],
    )
    result = eng.execute(one("orders", "DELETE FROM orders WHERE id = 500"))
    assert result.committed
    assert result.diff is not None
    # Measured: the order and its two items. Unmeasured, as acknowledged: the
    # refund deleted, the shipment and the reservation re-pointed.
    assert sorted((d.table, d.primary_key, d.operation) for d in result.diff.deltas) == [
        ("order_items", "5000", "delete"),
        ("order_items", "5001", "delete"),
        ("orders", "500", "delete"),
    ]
    assert count(back_office, "refunds") == 0
    opened = next(r for r in eng.chain.records() if r.record_type is RecordType.STAGE_OPENED)
    assert opened.note == (
        "unmeasured cascades acknowledged: delete order_items->refunds; "
        "delete orders->refunds; delete orders->shipments; "
        "delete orders->stock_reservations"
    )
    eng.chain.verify()


def test_a_closed_stage_notes_nothing(back_office: str) -> None:
    eng = engine(back_office, "orders")
    eng.execute(one("orders", "UPDATE orders SET status = 'x' WHERE id = 501", EffectKind.UPDATE))
    opened = next(r for r in eng.chain.records() if r.record_type is RecordType.STAGE_OPENED)
    assert opened.note == ""


def test_a_fully_observed_cascade_is_measured_four_deep(back_office: str) -> None:
    """The case the diff exists for: delete a tenant, measure all of it."""
    observed = (
        "tenants",
        "customers",
        "accounts",
        "ledger_entries",
        "orders",
        "order_items",
        "refunds",
        "shipments",
        "stock_reservations",
    )
    eng = engine(back_office, *observed)
    result = eng.execute(one("tenants", "DELETE FROM tenants WHERE id = 1"))
    assert result.committed and result.diff is not None
    by_table: dict[str, list[str]] = {}
    for delta in result.diff.deltas:
        by_table.setdefault(delta.table, []).append(delta.operation)
    assert by_table == {
        "tenants": ["delete"],
        "customers": ["delete", "delete"],
        "accounts": ["delete", "delete"],
        "ledger_entries": ["delete", "delete"],
        "orders": ["delete", "delete"],
        "order_items": ["delete", "delete", "delete"],
        "refunds": ["delete"],
        "shipments": ["update"],
        "stock_reservations": ["update", "update"],
    }
    shipment = next(d for d in result.diff.deltas if d.table == "shipments")
    assert shipment.before is not None and shipment.after is not None
    assert (shipment.before["order_id"], shipment.after["order_id"]) == (500, None)
    assert result.diff.tenant_ids == frozenset({"acme"})


def test_a_foreign_key_added_after_setup_is_enforced_next_stage(back_office: str) -> None:
    eng = engine(back_office, "payments")
    eng.execute(one("payments", "DELETE FROM payments WHERE id = 8000"))
    conn = sqlite3.connect(back_office)
    conn.execute(
        "CREATE TABLE receipts (id INTEGER PRIMARY KEY, "
        "payment_id INTEGER REFERENCES payments(id) ON DELETE CASCADE)"
    )
    conn.close()
    with pytest.raises(ForbiddenStatementError, match="payments -\\[ON DELETE CASCADE\\]"):
        eng.execute(one("payments", "DELETE FROM payments WHERE id = 1"))


def test_sentinels_hold_when_the_authorizer_does_not(back_office: str) -> None:
    """The third layer: take the authorizer away, as a SQLite build that did
    not report foreign-key actions would, and the gated table still refuses."""
    substrate = SqliteSubstrate(back_office, tables=specs("orders", "order_items"))
    plan = one("orders", "DELETE FROM orders WHERE id = 501")
    handle = substrate.open(plan)
    try:
        conn = substrate._conn
        assert conn is not None
        conn.set_authorizer(None)
        with pytest.raises(ForbiddenStatementError, match="unobserved table refunds") as caught:
            substrate.apply(
                handle, one("orders", "DELETE FROM order_items WHERE id = 5001").effects[0]
            )
        assert "before the row changed" in str(caught.value)
    finally:
        substrate.close(handle)
    assert count(back_office, "refunds") == 1


def test_a_trigger_cannot_carry_a_gated_delete(back_office: str) -> None:
    """A schema trigger on an observed table that deletes from a gated parent
    is refused like the statement itself would be."""
    conn = sqlite3.connect(back_office)
    conn.execute(
        "CREATE TRIGGER purge AFTER UPDATE OF status ON orders WHEN NEW.status = 'purge' "
        "BEGIN DELETE FROM order_items WHERE order_id = NEW.id; END"
    )
    conn.close()
    eng = engine(back_office, "orders", "order_items")
    with pytest.raises(ForbiddenStatementError, match="DELETE on 'order_items'"):
        eng.execute(
            one("orders", "UPDATE orders SET status = 'purge' WHERE id = 500", EffectKind.UPDATE)
        )
    assert count(back_office, "refunds") == 1


def test_disabling_table_enforcement_does_not_lift_a_gate(back_office: str) -> None:
    eng = engine(back_office, "orders", enforce_table_access=False)
    with pytest.raises(ForbiddenStatementError, match="DELETE on 'orders'"):
        eng.execute(one("orders", "DELETE FROM orders WHERE id = 500"))
    # The unobserved-table rule is off: a direct write elsewhere commits.
    assert eng.execute(one("orders", "DELETE FROM payments WHERE id = 8000")).committed


def test_acknowledging_an_observed_table_is_a_configuration_error(back_office: str) -> None:
    with pytest.raises(ValueError, match="observed table"):
        SqliteSubstrate(back_office, tables=specs("orders"), acknowledge_cascades=["ORDERS"])


def test_the_runtime_runs_the_check_at_setup(
    back_office: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="interlock.substrate"):
        runtime = EscrowRuntime(
            back_office,
            tables=specs("orders", "order_items"),
            scope_id="agent",
            acknowledge_cascades=["shipments", "invoices"],
        )
    rep = runtime.cascade_report
    assert rep is not None
    assert {r.table for r in rep.gated} == {"refunds", "stock_reservations"}
    assert {r.table for r in rep.gaps} == {"shipments"}
    logged = caplog.text
    # Logged once, though the first stage recomputes after creating the
    # commit-marker table changed the schema version.
    assert logged.count("refusing DELETE on orders reaches refunds") == 1
    assert "acknowledged, unmeasured: DELETE on orders reaches shipments" in logged
    assert "names 'invoices', which no foreign-key action" in logged
    result = runtime.execute_sql("UPDATE orders SET status = 'held' WHERE id = 501", table="orders")
    assert result.committed and result.state is StageState.COMMITTED
    assert caplog.text.count("refusing DELETE on orders reaches refunds") == 1
    runtime.close()

    with pytest.raises(SubstrateUnavailableError):
        EscrowRuntime(str(tmp_path / "missing.db"), tables=specs("orders"), scope_id="agent")


def test_a_database_that_cannot_be_read_is_unavailable(tmp_path: Path) -> None:
    path = tmp_path / "not-a-database.db"
    path.write_bytes(b"this is not sqlite" * 100)
    substrate = SqliteSubstrate(str(path), tables=specs("orders"))
    with pytest.raises(SubstrateUnavailableError, match="foreign-key graph"):
        substrate.check_cascades()


# --------------------------------------------------------------------------
# holes in the measurement the cascade work exposed
# --------------------------------------------------------------------------


class Unvetted(SqliteSubstrate):
    """A substrate whose statement-text check passes everything, so what is
    left is the authorizer: the layer that reads what SQLite will do."""

    __slots__ = ()

    def reject_reason(self, effect: Effect) -> str | None:
        return None


def test_a_statement_cannot_erase_the_measurement(back_office: str) -> None:
    """Deleting the capture table's rows used to empty the diff, and a plan
    that zeroed every order committed past a one-row blast radius."""
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET total = 0")
        .delete(table="orders", statement="DELETE FROM _interlock_capture")
        .build()
    )
    for enforce in (True, False):
        eng = EscrowEngine(
            SqliteSubstrate(back_office, tables=specs("orders"), enforce_table_access=enforce),
            checkers=[BlastRadius(1)],
        )
        with pytest.raises(ForbiddenStatementError, match="capture table"):
            eng.execute(plan)
    conn = sqlite3.connect(back_office)
    assert conn.execute("SELECT sum(total) FROM orders").fetchone()[0] == 80
    conn.close()


@pytest.mark.parametrize(
    "statement",
    ["COMMIT", "END TRANSACTION", "ROLLBACK", "BEGIN", "SAVEPOINT s", "RELEASE s", "commit;"],
)
def test_transaction_control_is_refused_at_admission(back_office: str, statement: str) -> None:
    with pytest.raises(ForbiddenStatementError, match="is not stageable"):
        engine(back_office, "orders").admit(one("orders", statement, EffectKind.UPDATE))


@pytest.mark.parametrize("statement", ["COMMIT", "SAVEPOINT s", "ROLLBACK"])
def test_the_authorizer_refuses_transaction_control_on_its_own(
    back_office: str, statement: str
) -> None:
    """A COMMIT mid-stage made every effect before it durable before any
    checker ran, and every effect after it autocommitted. Refused by SQLite
    itself, whatever the statement-text check says."""
    eng = EscrowEngine(Unvetted(back_office, tables=specs("orders")), checkers=[BlastRadius(0)])
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET total = 1")
        .update(table="orders", statement=statement)
        .build()
    )
    with pytest.raises(ForbiddenStatementError, match="transaction control"):
        eng.execute(plan)
    conn = sqlite3.connect(back_office)
    assert conn.execute("SELECT sum(total) FROM orders").fetchone()[0] == 80
    conn.close()


def test_the_substrate_still_commits_its_own_transaction(back_office: str) -> None:
    result = EscrowEngine(Unvetted(back_office, tables=specs("orders")), checkers=[]).execute(
        one("orders", "UPDATE orders SET status = 'ok' WHERE id = 500", EffectKind.UPDATE)
    )
    assert result.committed


# --------------------------------------------------------------------------
# the same graph from PostgreSQL
# --------------------------------------------------------------------------


def pg_graph(dsn: str) -> tuple[ForeignKey, ...]:
    import psycopg

    with psycopg.connect(dsn) as conn:
        return read_postgres_foreign_keys(conn)


def shape(rep: CascadeReport) -> list[tuple[object, ...]]:
    return [
        (r.parent, r.operation, r.columns, r.table, tuple(s.foreign_key.child for s in r.path))
        for r in rep.reaches
    ]


def test_the_postgres_reader_reads_every_constraint(pg_back_office: str) -> None:
    assert edges(pg_graph(pg_back_office)) == EXPECTED_EDGES


@pytest.mark.parametrize(
    "observed",
    [
        ("customers",),
        ("orders", "order_items"),
        ("products",),
        ("warehouse_stock",),
        ("categories", "employees"),
        ("tenants", "customers", "accounts", "orders", "order_items"),
    ],
)
def test_postgres_and_sqlite_agree_on_every_reach(
    back_office: str, pg_back_office: str, observed: tuple[str, ...]
) -> None:
    sqlite_report = analyze_cascades(graph(back_office), observed)
    postgres_report = analyze_cascades(pg_graph(pg_back_office), observed)
    assert shape(postgres_report) == shape(sqlite_report)


def test_postgres_names_other_schemas_and_reads_set_null_column_lists(
    pg_database: str,
) -> None:
    import psycopg

    with psycopg.connect(pg_database) as conn:
        conn.execute(
            """
            CREATE SCHEMA archive;
            CREATE TABLE parent (tenant TEXT, id INTEGER, PRIMARY KEY (tenant, id));
            CREATE TABLE child (
                id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, parent_id INTEGER,
                FOREIGN KEY (tenant, parent_id) REFERENCES parent (tenant, id)
                    ON DELETE SET NULL (parent_id)
            );
            CREATE TABLE archive.copies (
                id INTEGER PRIMARY KEY, child_id INTEGER REFERENCES child(id) ON DELETE CASCADE
            );
            """
        )
    keys = {k.child: k for k in pg_graph(pg_database)}
    assert keys["child"].set_columns == ("parent_id",)
    assert keys["archive.copies"].parent == "child"
    rep = analyze_cascades(keys.values(), ["parent", "child"])
    assert [(r.parent, r.table) for r in rep.reaches] == [("child", "archive.copies")]
    reach: CascadeReach = rep.reaches[0]
    assert reach.describe().startswith("DELETE on child reaches archive.copies")


def test_a_substrate_failure_is_a_stage_error(back_office: str) -> None:
    """A statement that fails for its own reasons is not reported as a gate."""
    with pytest.raises(StageError) as caught:
        engine(back_office, "orders").execute(
            one("orders", "UPDATE orders SET no_such_column = 1", EffectKind.UPDATE)
        )
    assert not isinstance(caught.value, ForbiddenStatementError)


def test_the_authorizer_refuses_attach_on_its_own(back_office: str, tmp_path: Path) -> None:
    other = str(tmp_path / "elsewhere.db")
    eng = EscrowEngine(Unvetted(back_office, tables=specs("orders")), checkers=[])
    with pytest.raises(ForbiddenStatementError, match=r"ATTACH .* outside the database"):
        eng.execute(one("orders", f"ATTACH DATABASE '{other}' AS elsewhere", EffectKind.UPDATE))
