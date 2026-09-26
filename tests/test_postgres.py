"""PostgresSubstrate (2.2), against a real PostgreSQL server.

Every test gets a fresh database holding the back-office schema, Interlock
installed as the tables' owner, and a dedicated stage role granted DML on the
observed tables and SELECT on the rest: the production shape. Nothing here
uses an in-memory or mocked database.

What is checked, in the order the file goes:

- A stage measures what the database did, exactly (``NUMERIC`` as
  ``Decimal``), including cascades, and commits with its own marker row.
- ``REPEATABLE READ`` and the lock and statement bounds hold.
- The cascade check refuses what reaches an unobserved table.
- Nothing a statement can do reaches the capture, the stage marker, the
  gates or the transaction: each attempt is refused and nothing commits.
- The installation and the role's grants are verified, not trusted.
- A crashed commit is resolved exactly, including while the server still has
  the dead client's transaction open.
- ``interlock install`` and ``interlock check``.
"""

from __future__ import annotations

import io
import subprocess
import sys
import time
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import make_conninfo  # noqa: E402

from interlock import (  # noqa: E402
    BlastRadius,
    ColumnValueGuard,
    EffectKind,
    EscrowChain,
    EscrowEngine,
    PlanBuilder,
    PostgresSubstrate,
    StageState,
    TableSpec,
)
from interlock.chain import RecordType  # noqa: E402
from interlock.cli import main  # noqa: E402
from interlock.exceptions import (  # noqa: E402
    ForbiddenStatementError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.postgres import install  # noqa: E402
from interlock.types import Effect, EffectPlan  # noqa: E402
from tests.conftest import OBSERVED, PASSWORD, Pg, create_role, drop_role  # noqa: E402
from tests.schemas import specs  # noqa: E402


def substrate(env: Pg, **kwargs: Any) -> PostgresSubstrate:
    return PostgresSubstrate(env.agent, tables=specs(*OBSERVED), **kwargs)


def engine(env: Pg, *checkers: Any, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(substrate(env, **kwargs), checkers=list(checkers) or [BlastRadius(100)])


def one(
    table: str,
    statement: str,
    parameters: dict[str, object] | None = None,
    kind: EffectKind = EffectKind.UPDATE,
) -> EffectPlan:
    return (
        PlanBuilder("agent")
        .add(kind, table=table, statement=statement, parameters=parameters)
        .build()
    )


def scalar(dsn: str, query: str, *params: object) -> Any:
    with psycopg.connect(dsn) as conn:
        row = conn.execute(query, params or None).fetchone()
        return None if row is None else row[0]


def stages(env: Pg) -> int:
    return int(scalar(env.admin, "SELECT count(*) FROM interlock.stages"))


class Unvetted(PostgresSubstrate):
    """Passes every statement's text, leaving only what the database enforces."""

    __slots__ = ()

    def reject_reason(self, effect: Effect) -> str | None:
        return None


# --------------------------------------------------------------------------
# measuring and committing
# --------------------------------------------------------------------------


def test_a_stage_measures_exact_numerics_and_commits_its_marker(pg: Pg) -> None:
    eng = engine(pg, ColumnValueGuard("orders", "total", max_drop_fraction=0.5))
    result = eng.execute(
        one("orders", "UPDATE orders SET total = total * 2 WHERE tenant = %(t)s", {"t": "acme"})
    )
    assert result.committed and result.state is StageState.COMMITTED
    assert result.diff is not None

    def image(order: int, customer: int, total: str) -> dict[str, object]:
        return {
            "id": order,
            "customer_id": customer,
            "tenant": "acme",
            "status": "open",
            "total": Decimal(total),
        }

    assert [(d.primary_key, d.before, d.after) for d in result.diff.deltas] == [
        ("500", image(500, 10, "45.00"), image(500, 10, "90.00")),
        ("501", image(501, 11, "25.00"), image(501, 11, "50.00")),
    ]
    assert result.diff.column_total("orders", "total") == (Decimal("70.00"), Decimal("140.00"))
    assert result.diff.tenant_ids == frozenset({"acme"})
    assert result.outcomes[0].rows_affected == 2
    assert scalar(pg.admin, "SELECT sum(total) FROM orders") == Decimal("150.00")

    intent = next(r for r in eng.chain.records() if r.record_type is RecordType.COMMIT_INTENT)
    assert intent.note.endswith("; commit marker armed")
    txid = intent.note.split("; txid ")[1].split(";")[0]
    marker = scalar(
        pg.admin, "SELECT xid::text FROM interlock.stages WHERE stage_id = %s", intent.stage_id
    )
    assert marker == txid


def test_a_refused_plan_leaves_nothing_behind(pg: Pg) -> None:
    eng = engine(pg, BlastRadius(1))
    result = eng.execute(one("orders", "UPDATE orders SET total = 0"))
    assert not result.committed and result.blocked_by == ("blast_radius",)
    assert result.diff is not None and result.diff.blast_radius == 3
    assert scalar(pg.admin, "SELECT sum(total) FROM orders") == Decimal("80.00")
    assert stages(pg) == 0


def test_cascades_into_observed_tables_are_measured(pg: Pg) -> None:
    result = engine(pg).execute(
        one("orders", "DELETE FROM orders WHERE id = 500", kind=EffectKind.DELETE)
    )
    assert result.committed and result.diff is not None
    assert sorted((d.table, d.primary_key, d.operation) for d in result.diff.deltas) == [
        ("order_items", "5000", "delete"),
        ("order_items", "5001", "delete"),
        ("orders", "500", "delete"),
        ("refunds", "9000", "delete"),
        ("shipments", "700", "update"),
        ("stock_reservations", "40", "update"),
    ]
    shipment = next(d for d in result.diff.deltas if d.table == "shipments")
    assert shipment.changed_columns() == ("order_id",)


def test_writable_ctes_and_merge_are_measured(pg: Pg) -> None:
    plan = (
        PlanBuilder("agent")
        .update(
            table="order_items",
            statement=(
                "WITH gone AS (DELETE FROM refunds RETURNING order_item_id) "
                "UPDATE order_items SET qty = 0 WHERE id IN (SELECT order_item_id FROM gone)"
            ),
        )
        .update(
            table="orders",
            statement=(
                "MERGE INTO orders o USING (VALUES (500, 'held'), (502, 'new')) AS v(id, s) "
                "ON o.id = v.id "
                "WHEN MATCHED THEN UPDATE SET status = v.s "
                "WHEN NOT MATCHED THEN INSERT VALUES (v.id, 10, 'acme', v.s, 0)"
            ),
        )
        .build()
    )
    result = engine(pg).execute(plan)
    assert result.committed and result.diff is not None
    assert sorted((d.table, d.primary_key, d.operation) for d in result.diff.deltas) == [
        ("order_items", "5001", "update"),
        ("orders", "500", "update"),
        ("orders", "502", "insert"),
        ("refunds", "9000", "delete"),
    ]


def test_the_diff_is_capped_and_says_so(pg: Pg) -> None:
    sub = substrate(pg, max_diff_rows=2)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        sub.apply(handle, one("orders", "UPDATE orders SET status = 'x'").effects[0])
        diff = sub.diff(handle)
        assert diff.truncated and len(diff.deltas) == 2
        assert sub.diff(handle).content_hash() == diff.content_hash()
    finally:
        sub.close(handle)


def test_the_stage_marker_setting_is_visible_inside_the_stage(pg: Pg) -> None:
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        assert sub._conn is not None
        row = sub._conn.execute("SELECT current_setting('interlock.stage_id')").fetchone()
        assert row is not None and row[0] == str(handle.stage_id)
        assert sub.transaction_id(handle) is not None
    finally:
        sub.close(handle)
    assert sub.transaction_id(handle) is None


def test_writes_outside_a_stage_pass_through_untouched(pg: Pg) -> None:
    with psycopg.connect(pg.agent) as conn:
        conn.execute("UPDATE orders SET status = 'direct' WHERE id = 500")
    assert scalar(pg.admin, "SELECT status FROM orders WHERE id = 500") == "direct"
    assert stages(pg) == 0


# --------------------------------------------------------------------------
# isolation and bounds
# --------------------------------------------------------------------------


def test_the_stage_reads_a_repeatable_snapshot_and_loses_a_write_race(pg: Pg) -> None:
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        with psycopg.connect(pg.admin, autocommit=True) as other:
            other.execute("UPDATE orders SET total = 1 WHERE id = 500")
        assert sub._conn is not None
        seen = sub._conn.execute("SELECT total FROM orders WHERE id = 500").fetchone()
        assert seen is not None and seen[0] == Decimal("45.00")
        with pytest.raises(StageConflictError, match="concurrent"):
            sub.apply(
                handle, one("orders", "UPDATE orders SET total = 2 WHERE id = 500").effects[0]
            )
    finally:
        sub.close(handle)
    assert scalar(pg.admin, "SELECT total FROM orders WHERE id = 500") == Decimal("1.00")


def test_a_stage_that_cannot_lock_in_time_is_a_conflict(pg: Pg) -> None:
    with psycopg.connect(pg.admin) as holder:
        holder.execute("LOCK TABLE orders IN SHARE MODE")
        start = time.monotonic()
        with pytest.raises(StageConflictError, match="could not lock"):
            engine(pg, lock_timeout_seconds=0.2).execute(one("orders", "SELECT 1"))
        assert time.monotonic() - start < 5


def test_a_statement_cannot_lift_the_stage_bound(pg: Pg) -> None:
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="SELECT set_config('statement_timeout', '0', true)")
        .update(table="orders", statement="SELECT pg_sleep(5)")
        .build()
    )
    start = time.monotonic()
    with pytest.raises(StageExpiredError, match="bound"):
        engine(pg, max_stage_seconds=1).execute(plan)
    assert time.monotonic() - start < 4


# --------------------------------------------------------------------------
# the cascade check on PostgreSQL
# --------------------------------------------------------------------------


def test_a_gated_delete_is_refused_and_rolled_back(pg: Pg) -> None:
    eng = engine(pg)
    with pytest.raises(ForbiddenStatementError) as caught:
        eng.execute(
            one("shipments", "DELETE FROM shipments WHERE id = 700", kind=EffectKind.DELETE)
        )
    message = str(caught.value)
    assert "DELETE on 'shipments' is refused" in message
    assert "shipments -[ON DELETE CASCADE]-> shipment_events" in message
    assert "rolled the statement back" in message
    assert scalar(pg.admin, "SELECT count(*) FROM shipment_events") == 3
    assert scalar(pg.admin, "SELECT count(*) FROM shipments") == 2
    assert stages(pg) == 0
    assert eng.execute(one("shipments", "UPDATE shipments SET carrier = 'fedex'")).committed


def test_an_update_of_a_referenced_key_is_refused(pg: Pg) -> None:
    eng = engine(pg)
    with pytest.raises(ForbiddenStatementError, match="UPDATE of id on 'accounts'"):
        eng.execute(one("accounts", "UPDATE accounts SET id = 109 WHERE id = 100"))
    assert scalar(pg.admin, "SELECT count(*) FROM ledger_entries WHERE account_id = 100") == 1
    # A key "updated" to itself fires no ON UPDATE action, and is allowed.
    assert eng.execute(one("accounts", "UPDATE accounts SET id = id, balance = 1")).committed


def test_an_acknowledged_cascade_runs_and_is_recorded(pg: Pg) -> None:
    eng = engine(pg, acknowledge_cascades=["shipment_events", "ledger_entries"])
    result = eng.execute(
        one("shipments", "DELETE FROM shipments WHERE id = 700", kind=EffectKind.DELETE)
    )
    assert result.committed
    assert scalar(pg.admin, "SELECT count(*) FROM shipment_events") == 1
    opened = next(r for r in eng.chain.records() if r.record_type is RecordType.STAGE_OPENED)
    assert opened.note == (
        "unmeasured cascades acknowledged: delete accounts->ledger_entries; "
        "delete shipments->shipment_events; update accounts->ledger_entries"
    )
    rep = eng_report(eng)
    assert not rep.closed


def eng_report(eng: EscrowEngine) -> Any:
    return getattr(eng, "_substrate").cascade_report  # noqa: B009


# --------------------------------------------------------------------------
# what a statement cannot reach
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT s",
        "SET interlock.stage_id = ''",
        "RESET ALL",
        "DO $$ BEGIN END $$",
        "CALL anything()",
        "COPY orders FROM STDIN",
        "LOCK TABLE orders",
        "TRUNCATE refunds",
        "ALTER TABLE orders DISABLE TRIGGER interlock_capture",
        "CREATE TABLE x (id int)",
        "PREPARE p AS SELECT 1",
        "",
    ],
)
def test_anything_but_a_row_statement_is_refused_at_admission(pg: Pg, statement: str) -> None:
    with pytest.raises(ForbiddenStatementError, match="not stageable on PostgreSQL"):
        engine(pg).admit(one("orders", statement))


def test_a_smuggled_commit_is_refused_by_the_server(pg: Pg) -> None:
    eng = EscrowEngine(Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[BlastRadius(0)])
    with pytest.raises(ForbiddenStatementError, match="carries several"):
        eng.execute(one("orders", "UPDATE orders SET total = 0; COMMIT"))
    assert scalar(pg.admin, "SELECT sum(total) FROM orders") == Decimal("80.00")


@pytest.mark.parametrize(
    ("statement", "match"),
    [
        ("DELETE FROM pg_temp.interlock_capture", "refused by the database"),
        ("UPDATE pg_temp.interlock_capture SET after = NULL", "refused by the database"),
        ("DELETE FROM interlock.stages", "refused by the database"),
        ("UPDATE interlock.stages SET gates = '{}'", "refused by the database"),
        ("INSERT INTO customers VALUES (99, 1, 'acme', 'x@acme.test')", "refused by the database"),
        ("TRUNCATE refunds", "refused by the database"),
        ("SELECT set_config('interlock.stage_id', '', true)", "stage marker"),
    ],
)
def test_a_statement_cannot_touch_the_measurement(pg: Pg, statement: str, match: str) -> None:
    """Each would, if it worked, hide rows from the diff, lift a gate, or
    write where nothing measures. The database refuses every one."""
    plan = (
        PlanBuilder("agent")
        .update(table="orders", statement="UPDATE orders SET total = 0")
        .update(table="orders", statement=statement)
        .update(table="orders", statement="UPDATE orders SET status = 'after'")
        .build()
    )
    eng = EscrowEngine(Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[BlastRadius(1)])
    with pytest.raises(ForbiddenStatementError, match=match):
        eng.execute(plan)
    assert scalar(pg.admin, "SELECT sum(total) FROM orders") == Decimal("80.00")
    assert stages(pg) == 0


def test_a_second_begin_stage_in_one_transaction_fails(pg: Pg) -> None:
    eng = EscrowEngine(Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[])
    with pytest.raises(StageError):
        eng.execute(
            one(
                "orders",
                "SELECT interlock.begin_stage(gen_random_uuid(), 'forged', '{}'::jsonb)",
            )
        )
    assert stages(pg) == 0


def test_an_out_of_band_writer_cannot_forge_a_stage_marker(pg: Pg) -> None:
    with psycopg.connect(pg.agent) as conn:
        conn.execute("SET interlock.stage_id = '00000000-0000-0000-0000-000000000000'")
        with pytest.raises(psycopg.Error, match="opened no stage"):
            conn.execute("UPDATE orders SET status = 'forged' WHERE id = 500")


def test_an_out_of_band_writer_cannot_open_a_stage(pg: Pg, pg_admin_dsn: str) -> None:
    """Only the stage role may call begin_stage; anyone else who could would
    have their writes captured into their own session instead of logged."""
    outsider = f"il_outsider_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, outsider)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {outsider}")
            conn.execute(f"GRANT UPDATE, SELECT ON orders TO {outsider}")
        dsn = make_conninfo(pg.admin, user=outsider, password=PASSWORD)
        with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT interlock.begin_stage(gen_random_uuid(), 'x', '{}'::jsonb)")
    finally:
        drop_role(pg_admin_dsn, pg.admin, outsider)


def test_a_schema_trigger_cannot_write_where_the_role_may_not(pg: Pg) -> None:
    """Triggers run as the statement's role, so the grant boundary holds
    through them too."""
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(
            """
            CREATE FUNCTION note_it() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN INSERT INTO payments VALUES (8001, 800, 1); RETURN NULL; END $$;
            CREATE TRIGGER note_it AFTER UPDATE ON orders
                FOR EACH ROW EXECUTE FUNCTION note_it();
            """
        )
    with pytest.raises(ForbiddenStatementError, match="payments"):
        engine(pg).execute(one("orders", "UPDATE orders SET status = 'x' WHERE id = 500"))
    assert scalar(pg.admin, "SELECT count(*) FROM payments") == 1


def test_truncate_inside_a_stage_is_refused_by_the_trigger(pg: Pg) -> None:
    """With the role's TRUNCATE grant and the text check both out of the way,
    the statement-level trigger still refuses."""
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(f"GRANT TRUNCATE ON refunds TO {pg.role}")
    eng = EscrowEngine(Unvetted(pg.agent, tables=specs(*OBSERVED)), checkers=[])
    with pytest.raises(ForbiddenStatementError, match="TRUNCATE on 'refunds'"):
        eng.execute(one("refunds", "TRUNCATE refunds"))
    assert scalar(pg.admin, "SELECT count(*) FROM refunds") == 1


# --------------------------------------------------------------------------
# the installation and the grants, verified
# --------------------------------------------------------------------------


def test_install_is_idempotent_and_drops_what_it_no_longer_covers(pg: Pg) -> None:
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        install(conn, specs(*OBSERVED), stage_roles=[pg.role])
        install(conn, specs("orders"), stage_roles=[pg.role])
        triggers = conn.execute(
            "SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE t.tgname LIKE 'interlock%%' ORDER BY 1, 2"
        ).fetchall()
        installed = conn.execute("SELECT tbl FROM interlock.installation").fetchall()
    assert triggers == [("orders", "interlock_capture"), ("orders", "interlock_truncate")]
    assert installed == [("orders",)]


def test_a_database_without_interlock_is_a_configuration_error(pg_back_office: str) -> None:
    sub = PostgresSubstrate(pg_back_office, tables=specs("orders"), enforce_table_access=False)
    with pytest.raises(SubstrateConfigurationError, match="interlock install"):
        sub.check_cascades()
    with pytest.raises(SubstrateConfigurationError, match="interlock install"):
        EscrowEngine(sub, checkers=[]).execute(one("orders", "SELECT 1"))


@pytest.mark.parametrize(
    ("tamper", "match"),
    [
        ("ALTER TABLE orders DISABLE TRIGGER interlock_capture", "not ENABLE ALWAYS"),
        ("ALTER TABLE orders ENABLE TRIGGER interlock_capture", "not ENABLE ALWAYS"),
        ("ALTER TABLE orders DISABLE TRIGGER interlock_truncate", "interlock_truncate"),
        ("DROP TRIGGER interlock_capture ON orders", "no interlock_capture trigger"),
        (
            "DROP TRIGGER interlock_capture ON orders; "
            "CREATE TRIGGER interlock_capture AFTER INSERT OR UPDATE OR DELETE ON orders "
            "FOR EACH ROW EXECUTE FUNCTION interlock.capture('id', 'id'); "
            "ALTER TABLE orders ENABLE ALWAYS TRIGGER interlock_capture",
            "the TableSpec says",
        ),
    ],
)
def test_a_tampered_installation_refuses_to_stage(pg: Pg, tamper: str, match: str) -> None:
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(tamper)
    with pytest.raises(SubstrateConfigurationError, match=match):
        engine(pg).execute(one("orders", "UPDATE orders SET status = 'x'"))
    assert scalar(pg.admin, "SELECT count(*) FROM orders WHERE status = 'x'") == 0


@pytest.mark.parametrize(
    "child",
    [
        "CREATE TABLE orders_archive (archived_at timestamptz) INHERITS (orders)",
        "CREATE TABLE refunds_2026 (LIKE refunds); ALTER TABLE refunds_2026 INHERIT refunds",
    ],
)
def test_an_observed_table_with_inheritance_children_refuses_to_stage(pg: Pg, child: str) -> None:
    """UPDATE orders writes orders_archive's rows too, through no trigger and
    past no grant: PostgreSQL checks privileges on the parent alone."""
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(child)
    with pytest.raises(SubstrateConfigurationError, match="inheritance children"):
        engine(pg).execute(one("orders", "UPDATE orders SET status = 'x'"))


def test_gates_match_mixed_case_columns_exactly(pg: Pg, pg_admin_dsn: str) -> None:
    """A quoted, mixed-case key column: a gate on its lowercased name would
    match nothing in the row image and let the update through."""
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(
            """
            ALTER TABLE accounts ADD COLUMN "ExternalRef" text UNIQUE;
            UPDATE accounts SET "ExternalRef" = 'ext-' || id;
            CREATE TABLE statements (
                id integer PRIMARY KEY,
                account_ref text REFERENCES accounts ("ExternalRef") ON UPDATE CASCADE
            );
            INSERT INTO statements VALUES (1, 'ext-100');
            """
        )
        conn.execute(f"GRANT SELECT ON statements TO {pg.role}")
    with pytest.raises(ForbiddenStatementError, match="UPDATE of ExternalRef on 'accounts'"):
        engine(pg).execute(
            one("accounts", """UPDATE accounts SET "ExternalRef" = 'moved' WHERE id = 100""")
        )
    assert scalar(pg.admin, "SELECT account_ref FROM statements") == "ext-100"


@pytest.mark.parametrize(
    "grant",
    [
        "GRANT INSERT ON customers TO {role}",
        "GRANT UPDATE (email) ON customers TO {role}",
        "GRANT TRUNCATE ON payments TO {role}",
    ],
)
def test_a_role_that_can_write_elsewhere_cannot_stage(pg: Pg, grant: str) -> None:
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute(grant.format(role=pg.role))
    with pytest.raises(SubstrateConfigurationError, match="outside the observed set"):
        substrate(pg).check_cascades()
    # Trusted instead of checked, on the operator's say-so.
    assert substrate(pg, enforce_table_access=False).check_cascades() is not None


def test_a_write_grant_through_a_group_role_counts(pg: Pg, pg_admin_dsn: str) -> None:
    group = f"il_group_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE {group} NOLOGIN")
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute(f"GRANT DELETE ON invoices TO {group}")
            conn.execute(f"GRANT {group} TO {pg.role}")
        with pytest.raises(SubstrateConfigurationError, match="invoices"):
            engine(pg).execute(one("orders", "SELECT 1"))
    finally:
        drop_role(pg_admin_dsn, pg.admin, group)


def test_a_superuser_or_an_owner_cannot_stage(pg: Pg, pg_admin_dsn: str) -> None:
    with pytest.raises(SubstrateConfigurationError, match="superuser"):
        PostgresSubstrate(pg.admin, tables=specs(*OBSERVED)).check_cascades()
    owner = f"il_owner_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, owner)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute(f"GRANT USAGE ON SCHEMA interlock TO {owner}")
            conn.execute(f"ALTER TABLE refunds OWNER TO {owner}")
        dsn = make_conninfo(pg.admin, user=owner, password=PASSWORD)
        with pytest.raises(SubstrateConfigurationError, match="owns observed table"):
            PostgresSubstrate(dsn, tables=specs("refunds")).check_cascades()
    finally:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute("ALTER TABLE refunds OWNER TO CURRENT_USER")
        drop_role(pg_admin_dsn, pg.admin, owner)


def test_a_role_without_stage_grants_is_told_what_to_grant(pg: Pg, pg_admin_dsn: str) -> None:
    bare = f"il_bare_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, bare)
    try:
        dsn = make_conninfo(pg.admin, user=bare, password=PASSWORD)
        with pytest.raises(SubstrateConfigurationError, match="lacks a privilege"):
            EscrowEngine(PostgresSubstrate(dsn, tables=specs("orders")), checkers=[]).execute(
                one("orders", "SELECT 1")
            )
    finally:
        drop_role(pg_admin_dsn, pg.admin, bare)


def test_an_unreachable_server_is_unavailable() -> None:
    sub = PostgresSubstrate(
        "postgresql://nobody@127.0.0.1:1/none", tables=specs("orders"), max_stage_seconds=1
    )
    with pytest.raises(SubstrateUnavailableError):
        sub.check_cascades()
    with pytest.raises(SubstrateUnavailableError):
        sub.resolve_intent(uuid.uuid4(), txid="1")


def test_acknowledging_an_observed_table_is_refused() -> None:
    with pytest.raises(ValueError, match="observed table"):
        PostgresSubstrate("", tables=specs("orders"), acknowledge_cascades=["orders"])


def test_one_stage_at_a_time_per_substrate(pg: Pg) -> None:
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        with pytest.raises(StageConflictError, match="already has stage"):
            sub.open(one("orders", "SELECT 1"))
        with pytest.raises(StageError, match="not open"):
            sub.apply(
                type(handle)(
                    stage_id=uuid.uuid4(),
                    plan_id=handle.plan_id,
                    substrate_id="postgres",
                    opened_at=handle.opened_at,
                    expires_at=handle.expires_at,
                ),
                one("orders", "SELECT 1").effects[0],
            )
    finally:
        sub.close(handle)
    sub.close(handle)
    sub.abort(handle)


def test_a_stage_past_its_bound_does_not_commit(pg: Pg) -> None:
    sub = substrate(pg, max_stage_seconds=0.5)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        sub.apply(handle, one("orders", "UPDATE orders SET status = 'late'").effects[0])
        time.sleep(0.6)
        with pytest.raises(StageExpiredError):
            sub.commit(handle)
    finally:
        sub.close(handle)
    assert scalar(pg.admin, "SELECT count(*) FROM orders WHERE status = 'late'") == 0


def test_a_failed_transaction_cannot_be_committed(pg: Pg) -> None:
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    try:
        with pytest.raises(StageError):
            sub.apply(handle, one("orders", "UPDATE orders SET nope = 1").effects[0])
        with pytest.raises(StageError, match="cannot commit"):
            sub.commit(handle)
    finally:
        sub.close(handle)


# --------------------------------------------------------------------------
# crash recovery
# --------------------------------------------------------------------------


_CRASHING_COMMIT = r"""
import os, sys
from interlock import BlastRadius, EscrowChain, EscrowEngine, PlanBuilder, PostgresSubstrate
from tests.schemas import specs

dsn, chain_path, when = sys.argv[1], sys.argv[2], sys.argv[3]

class Dying:
    def __init__(self, inner):
        self._inner = inner
    def execute(self, query, *args, **kwargs):
        if query == "COMMIT" and when == "before":
            os._exit(3)
        cursor = self._inner.execute(query, *args, **kwargs)
        if query == "COMMIT" and when == "after":
            os._exit(3)
        return cursor
    def __getattr__(self, name):
        return getattr(self._inner, name)

class Substrate(PostgresSubstrate):
    def commit(self, handle):
        self._conn = Dying(self._conn)
        return super().commit(handle)

tables = specs("orders", "order_items", "refunds", "shipments", "stock_reservations", "accounts")
engine = EscrowEngine(
    Substrate(dsn, tables=tables), checkers=[BlastRadius(8)], chain=EscrowChain(chain_path)
)
statement = "UPDATE orders SET total = 777 WHERE id = 500"
engine.execute(PlanBuilder("agent").update(table="orders", statement=statement).build())
os._exit(0)
"""


def settled(dsn: str, txid: str) -> None:
    """Wait for the server to notice a dead client and end its transaction."""
    for _ in range(100):
        if scalar(dsn, "SELECT pg_xact_status(%s::xid8)", txid) != "in progress":
            return
        time.sleep(0.05)
    raise AssertionError(f"transaction {txid} still running")


@pytest.mark.parametrize(
    ("when", "outcome", "total"),
    [
        ("before", RecordType.ABORTED, Decimal("45.00")),
        ("after", RecordType.COMMITTED, Decimal("777.00")),
    ],
)
def test_a_process_killed_at_commit_is_resolved_exactly(
    pg: Pg, tmp_path: Path, when: str, outcome: RecordType, total: Decimal
) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    root = str(Path(__file__).resolve().parent.parent)
    child = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CRASHING_COMMIT, pg.agent, str(chain_path), when],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    assert child.returncode == 3, child.stderr
    (intent,) = EscrowChain.load(chain_path).unresolved_intents()
    txid = intent.note.split("; txid ")[1].split(";")[0]
    settled(pg.admin, txid)

    with EscrowChain(chain_path) as chain:
        eng = EscrowEngine(substrate(pg), checkers=[], chain=chain)
        (resolution,) = eng.recover()
        assert resolution.record_type is outcome
        assert resolution.stage_id == intent.stage_id
        assert chain.unresolved_intents() == ()
        chain.verify()
    assert scalar(pg.admin, "SELECT total FROM orders WHERE id = 500") == total


def test_a_transaction_still_open_on_the_server_is_not_guessed(pg: Pg) -> None:
    """A dead client can leave its transaction running until the server times
    it out. Absent marker plus running transaction is not "rolled back"."""
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    txid = sub.transaction_id(handle)
    assert txid is not None
    try:
        sub.apply(handle, one("orders", "UPDATE orders SET status = 'pending'").effects[0])
        assert substrate(pg).resolve_intent(handle.stage_id, txid=txid) is None
        assert substrate(pg).resolve_intent(handle.stage_id) is None
        sub.commit(handle)
    finally:
        sub.close(handle)
    assert substrate(pg).resolve_intent(handle.stage_id, txid=txid) is True
    assert substrate(pg).resolve_intent(handle.stage_id) is True


def test_a_rolled_back_stage_resolves_as_rolled_back(pg: Pg) -> None:
    sub = substrate(pg)
    handle = sub.open(one("orders", "SELECT 1"))
    txid = sub.transaction_id(handle)
    sub.close(handle)
    assert substrate(pg).resolve_intent(handle.stage_id, txid=txid) is False


def test_a_deleted_marker_is_not_read_as_a_rollback(pg: Pg) -> None:
    """The server says the transaction committed, and its row is gone: someone
    deleted it. That is not evidence of a rollback."""
    assert engine(pg).execute(one("orders", "UPDATE orders SET status = 'kept'")).committed
    row = scalar(pg.admin, "SELECT stage_id::text || ' ' || xid::text FROM interlock.stages")
    stage, txid = str(row).split()
    with psycopg.connect(pg.admin, autocommit=True) as conn:
        conn.execute("DELETE FROM interlock.stages")
    assert substrate(pg).resolve_intent(uuid.UUID(stage), txid=txid) is None


# --------------------------------------------------------------------------
# the command line
# --------------------------------------------------------------------------


def write_config(path: Path, **overrides: object) -> Path:
    tables = overrides.pop("tables", OBSERVED)
    lines = [f'substrate = "{overrides.pop("substrate", "postgres")}"']
    for key, value in overrides.items():
        rendered = (
            "[" + ", ".join(f'"{v}"' for v in value) + "]"
            if isinstance(value, list | tuple)
            else f'"{value}"'
        )
        lines.append(f"{key} = {rendered}")
    for name in tables:  # type: ignore[attr-defined]
        spec: TableSpec = specs(name)[0]
        lines += [
            "",
            "[[tables]]",
            f'name = "{spec.name}"',
            f'primary_key = "{spec.primary_key}"',
            "columns = [" + ", ".join(f'"{c}"' for c in spec.columns) + "]",
        ]
        if spec.tenant_column:
            lines.append(f'tenant_column = "{spec.tenant_column}"')
    path.write_text("\n".join(lines) + "\n")
    return path


def test_the_cli_installs_and_checks(pg: Pg, tmp_path: Path) -> None:
    config = write_config(
        tmp_path / "interlock.toml",
        stage_roles=[pg.role],
        acknowledge_cascades=["shipment_events"],
    )
    out = io.StringIO()
    assert main(["install", "--config", str(config), "--database", pg.admin], out=out) == 0
    text = out.getvalue()
    assert f"installed: {len(OBSERVED)} table(s) in public" in text
    assert f"granted to stage role: {pg.role}" in text
    assert "acknowledged: DELETE on shipments reaches shipment_events" in text
    assert "refused:      DELETE on accounts reaches ledger_entries" in text
    assert "cascade closure: open, 1 acknowledged gap(s)" in text

    out = io.StringIO()
    assert main(["check", "--config", str(config), "--database", pg.agent], out=out) == 0
    assert out.getvalue().startswith(f"ok: postgres, {len(OBSERVED)} observed table(s)")


def test_the_cli_exit_codes(pg: Pg, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = write_config(tmp_path / "interlock.toml")
    assert main(["check", "--config", str(config), "--database", pg.admin]) == 3
    assert "superuser" in capsys.readouterr().err
    unreachable = "postgresql://nobody@127.0.0.1:1/none?connect_timeout=1"
    assert main(["check", "--config", str(config), "--database", unreachable]) == 4
    assert main(["install", "--config", str(config), "--database", unreachable]) == 4
    assert main(["check", "--config", str(tmp_path / "missing.toml")]) == 2
    bad = write_config(tmp_path / "bad.toml", stage_roles=["not a role"])
    assert main(["install", "--config", str(bad), "--database", pg.admin]) == 3
