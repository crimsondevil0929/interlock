"""Unrecorded writes (2.3): nothing changes an observed table without a record.

Each test stages real plans through an engine with a chain file, then has
something else write the same tables the way it happens in production: a
cron job on its own connection, a cascade from a table nobody observes, the
agent's own credentials used directly, a crash between commit and record.
``interlock reconcile-effects`` has to find exactly those and nothing else.
"""

from __future__ import annotations

import io
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    BlastRadius,
    EffectKind,
    EscrowChain,
    EscrowEngine,
    PlanBuilder,
    SqliteSubstrate,
)
from interlock.chain import RecordType
from interlock.cli import main
from interlock.exceptions import (
    ForbiddenStatementError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.reconcile import (
    format_reconciliation,
    install_sqlite_journal,
    reconcile_postgres,
    reconcile_sqlite,
)
from interlock.types import EffectPlan
from tests.conftest import OBSERVED, PASSWORD, Pg, create_role, drop_role
from tests.schemas import specs

SQLITE_OBSERVED = ("customers", "orders", "order_items", "refunds", "shipments")
"""Enough of the back office that deleting an order is not cascade-gated:
its SET DEFAULT reach into stock_reservations is acknowledged below."""


def plan(table: str, statement: str, kind: EffectKind = EffectKind.UPDATE) -> EffectPlan:
    return PlanBuilder("agent").add(kind, table=table, statement=statement).build()


def sqlite_engine(path: str, chain: EscrowChain) -> EscrowEngine:
    substrate = SqliteSubstrate(
        path,
        tables=specs(*SQLITE_OBSERVED),
        acknowledge_cascades=["stock_reservations", "accounts"],
    )
    return EscrowEngine(substrate, checkers=[BlastRadius(100)], chain=chain)


def reconcile(path: str, *chains: Path, after: int = 0) -> Any:
    records = [r for c in chains for r in EscrowChain.load(c).records()]
    return reconcile_sqlite(path, specs(*SQLITE_OBSERVED), records, after=after)


def out_of_band(path: str, *statements: str) -> None:
    """A cron job: its own connection, foreign keys on, no Interlock."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def journaled(back_office: str) -> str:
    install_sqlite_journal(back_office, specs(*SQLITE_OBSERVED))
    return back_office


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------


def test_staged_writes_reconcile_clean(journaled: str, tmp_path: Path) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        eng = sqlite_engine(journaled, chain)
        assert eng.execute(plan("orders", "UPDATE orders SET status = 'held'")).committed
        assert eng.execute(
            plan("orders", "DELETE FROM orders WHERE id = 501", EffectKind.DELETE)
        ).committed
        refused = eng.execute(
            PlanBuilder("agent").update(table="orders", statement="SELECT 1").build()
        )
        assert refused.committed
    result = reconcile(journaled, chain_path)
    assert result.clean, format_reconciliation(result)
    # Three orders updated, then one order and its item deleted by cascade.
    assert (result.stages_checked, result.writes_checked) == (3, 5)


def test_a_write_outside_a_stage_is_found_exactly(journaled: str, tmp_path: Path) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        eng = sqlite_engine(journaled, chain)
        eng.execute(plan("orders", "UPDATE orders SET status = 'a' WHERE id = 500"))
        out_of_band(journaled, "UPDATE orders SET total = 0 WHERE id = 600")
        eng.execute(plan("orders", "UPDATE orders SET status = 'b' WHERE id = 500"))
    result = reconcile(journaled, chain_path)
    assert not result.clean
    ((write),) = [result.unmediated]
    assert [(w.entry, w.table, w.primary_key, w.operation) for w in write] == [
        (2, "orders", "600", "update")
    ]
    assert result.stages == ()


def test_an_out_of_band_cascade_is_journaled_row_by_row(journaled: str) -> None:
    """Deleting a tenant nobody observes cascades into four observed tables.
    Every row it took is a finding."""
    out_of_band(journaled, "DELETE FROM invoices", "DELETE FROM tenants WHERE id = 2")
    result = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), [])
    assert sorted((w.table, w.primary_key, w.operation) for w in result.unmediated) == [
        ("customers", "20", "delete"),
        ("order_items", "6000", "delete"),
        ("orders", "600", "delete"),
        ("shipments", "701", "update"),
    ]


def test_the_cursor_skips_what_a_previous_run_reported(journaled: str) -> None:
    out_of_band(journaled, "UPDATE orders SET total = 1 WHERE id = 500")
    first = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), [])
    assert first.last_entry == 1 and len(first.unmediated) == 1
    out_of_band(journaled, "UPDATE orders SET total = 2 WHERE id = 500")
    second = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), [], after=first.last_entry)
    assert [w.entry for w in second.unmediated] == [2]
    third = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), [], after=second.last_entry)
    assert third.clean and third.last_entry == 2


def test_a_stage_committed_with_no_chain_is_unrecorded(journaled: str, tmp_path: Path) -> None:
    """An engine on the default in-memory chain: the writes are mediated, and
    the record of them died with the process."""
    forgetful = EscrowEngine(
        SqliteSubstrate(journaled, tables=specs(*SQLITE_OBSERVED)), checkers=[]
    )
    result = forgetful.execute(plan("orders", "UPDATE orders SET status = 'x' WHERE id = 500"))
    assert result.committed
    findings = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), []).stages
    assert [(f.plan_id, f.problem) for f in findings] == [(result.plan.plan_id, "unrecorded")]
    assert "absent from every chain" in findings[0].describe()


def test_a_chain_that_says_aborted_is_contradicted(journaled: str, tmp_path: Path) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        result = sqlite_engine(journaled, chain).execute(
            plan("orders", "UPDATE orders SET status = 'x' WHERE id = 500")
        )
        committed = next(r for r in chain.records() if r.record_type is RecordType.COMMITTED)
        chain.append(
            RecordType.ABORTED,
            plan_id=result.plan.plan_id,
            payload_hash=committed.payload_hash,
            stage_id=committed.stage_id,
            note="a later, wrong record",
        )
    (finding,) = reconcile(journaled, chain_path).stages
    assert finding.problem == "aborted"


def test_a_stage_recorded_under_another_plan_is_contradicted(
    journaled: str, tmp_path: Path
) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        sqlite_engine(journaled, chain).execute(plan("orders", "UPDATE orders SET status = 'x'"))
    conn = sqlite3.connect(journaled)
    conn.execute("UPDATE _interlock_commits SET plan_id = 'plan-forged'")
    conn.commit()
    conn.close()
    (finding,) = reconcile(journaled, chain_path).stages
    assert (finding.plan_id, finding.problem) == ("plan-forged", "plan")


def test_a_statement_cannot_rewrite_the_journal(journaled: str) -> None:
    for statement in (
        "DELETE FROM _interlock_journal",
        "UPDATE _interlock_journal SET tbl = 'x'",
        "INSERT INTO _interlock_stage_journal VALUES ('s', 1, 999)",
        "DELETE FROM _interlock_stage_journal",
    ):
        eng = EscrowEngine(SqliteSubstrate(journaled, tables=specs(*SQLITE_OBSERVED)), checkers=[])
        with pytest.raises(ForbiddenStatementError, match="only the"):
            eng.execute(plan("orders", statement))


def test_a_missing_journal_trigger_fails_reconciliation(journaled: str) -> None:
    conn = sqlite3.connect(journaled)
    conn.execute("DROP TRIGGER ilok_journal_refunds_d")
    conn.close()
    result = reconcile_sqlite(journaled, specs(*SQLITE_OBSERVED), [])
    assert result.unjournaled == ("refunds",) and not result.clean
    assert "UNJOURNALED  refunds: no journal trigger" in format_reconciliation(result)


def test_reinstalling_drops_triggers_for_tables_no_longer_observed(journaled: str) -> None:
    install_sqlite_journal(journaled, specs("orders"))
    conn = sqlite3.connect(journaled)
    names = sorted(
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    )
    conn.close()
    assert names == ["ilok_journal_orders_d", "ilok_journal_orders_i", "ilok_journal_orders_u"]


def test_an_uninstalled_or_unreadable_database_is_reported(
    back_office: str, tmp_path: Path
) -> None:
    with pytest.raises(SubstrateConfigurationError, match="no Interlock journal"):
        reconcile_sqlite(back_office, specs("orders"), [])
    with pytest.raises(SubstrateUnavailableError):
        reconcile_sqlite(str(tmp_path / "absent.db"), specs("orders"), [])
    with pytest.raises(SubstrateUnavailableError):
        install_sqlite_journal(str(tmp_path / "absent.db"), specs("orders"))


def config_file(tmp_path: Path, database: str) -> Path:
    path = tmp_path / "interlock.toml"
    lines = [
        'substrate = "sqlite"',
        f'database = "{database}"',
        'acknowledge_cascades = ["stock_reservations", "accounts"]',
    ]
    for name in SQLITE_OBSERVED:
        spec = specs(name)[0]
        lines += ["[[tables]]", f'name = "{name}"', f"columns = {list(spec.columns)!r}"]
    path.write_text("\n".join(lines).replace("'", '"') + "\n")
    return path


def test_the_cli_reconciles_sqlite(back_office: str, tmp_path: Path) -> None:
    config = config_file(tmp_path, back_office)
    assert main(["install", "--config", str(config)], out=io.StringIO()) == 0
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        sqlite_engine(back_office, chain).execute(plan("orders", "UPDATE orders SET status = 'x'"))
    out = io.StringIO()
    args = ["reconcile-effects", "--config", str(config), "--chain", str(chain_path)]
    assert main(args, out=out) == 0
    assert out.getvalue().splitlines()[-1] == "result: clean"

    out_of_band(back_office, "UPDATE orders SET total = 0 WHERE id = 600")
    out = io.StringIO()
    assert main(args, out=out) == 1
    lines = out.getvalue().splitlines()
    assert lines[1].startswith("UNMEDIATED   #4 update orders pk=600 at ")
    assert lines[-2:] == ["last entry: 4", "result: FAIL, 1 finding(s)"]
    assert main([*args, "--after", "4"], out=io.StringIO()) == 0


def test_the_cli_refuses_a_chain_that_does_not_verify(
    back_office: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = config_file(tmp_path, back_office)
    main(["install", "--config", str(config)], out=io.StringIO())
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        sqlite_engine(back_office, chain).execute(plan("orders", "UPDATE orders SET status = 'x'"))
    text = chain_path.read_text().replace('"status', '"STATUS').replace("rows", "ROWS", 1)
    chain_path.write_text(text)
    args = ["reconcile-effects", "--config", str(config), "--chain", str(chain_path)]
    assert main(args) == 5
    missing = ["reconcile-effects", "--config", str(config), "--chain", str(tmp_path / "no")]
    assert main(missing) == 5
    assert "cannot read escrow chain" in capsys.readouterr().err


# --------------------------------------------------------------------------
# PostgreSQL
# --------------------------------------------------------------------------


def pg_engine(env: Pg, chain: EscrowChain) -> EscrowEngine:
    from interlock import PostgresSubstrate

    return EscrowEngine(
        PostgresSubstrate(env.agent, tables=specs(*OBSERVED)),
        checkers=[BlastRadius(100)],
        chain=chain,
    )


def eng_substrate(env: Pg) -> Any:
    from interlock import PostgresSubstrate

    return PostgresSubstrate(env.agent, tables=specs(*OBSERVED))


def pg_reconcile(env: Pg, *chains: Path, after: int = 0) -> Any:
    import psycopg

    records = [r for c in chains for r in EscrowChain.load(c).records()]
    with psycopg.connect(env.admin, autocommit=True) as conn:
        return reconcile_postgres(conn, records, after=after)


def test_postgres_staged_writes_reconcile_clean(pg: Pg, tmp_path: Path) -> None:
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        eng = pg_engine(pg, chain)
        assert eng.execute(plan("orders", "UPDATE orders SET status = 'held'")).committed
        assert eng.execute(
            plan("orders", "DELETE FROM orders WHERE id = 501", EffectKind.DELETE)
        ).committed
        refusing = EscrowEngine(eng_substrate(pg), checkers=[BlastRadius(0)], chain=chain)
        assert not refusing.execute(plan("orders", "UPDATE orders SET total = 0")).committed
    result = pg_reconcile(pg, chain_path)
    assert result.clean, format_reconciliation(result)
    assert result.writes_checked == 0


def test_postgres_out_of_band_writes_are_logged_with_their_author(
    pg: Pg, pg_admin_dsn: str, tmp_path: Path
) -> None:
    import psycopg
    from psycopg.conninfo import make_conninfo

    cron = f"il_cron_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, cron)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            conn.execute(f"GRANT SELECT, UPDATE, DELETE ON orders, customers, tenants TO {cron}")
        dsn = make_conninfo(pg.admin, user=cron, password=PASSWORD, application_name="nightly")
        with psycopg.connect(dsn) as conn:
            conn.execute("UPDATE orders SET total = 0 WHERE tenant = 'globex'")
        # The owner deleting a tenant nobody observes: the cascade reaches
        # orders, order_items and shipments, which are.
        with psycopg.connect(pg.admin) as conn:
            conn.execute("DELETE FROM invoices")
            conn.execute("DELETE FROM tenants WHERE id = 2")
        with psycopg.connect(pg.admin) as conn:
            conn.execute("TRUNCATE refunds")
        result = pg_reconcile(pg)
    finally:
        drop_role(pg_admin_dsn, pg.admin, cron)
    found = [(w.table, w.primary_key, w.operation, w.actor) for w in result.unmediated]
    first, *cascade, last = found
    assert first == ("orders", "600", "update", f"{cron} (nightly)")
    # The order the cascade's actions run in is the server's business; what
    # they reached is not.
    assert sorted(cascade) == [
        ("accounts", "200", "delete", "interlock_admin"),
        ("order_items", "6000", "delete", "interlock_admin"),
        ("orders", "600", "delete", "interlock_admin"),
        ("shipments", "701", "update", "interlock_admin"),
    ]
    assert last == ("refunds", None, "truncate", "interlock_admin")
    assert all(w.transaction for w in result.unmediated)
    assert "UNMEDIATED   #1 update orders pk=600" in format_reconciliation(result)[1]
    later = pg_reconcile(pg, after=result.last_entry)
    assert later.clean and later.last_entry == result.last_entry


def test_a_rolled_back_out_of_band_write_leaves_no_entry(pg: Pg) -> None:
    import psycopg

    with psycopg.connect(pg.admin) as conn:
        conn.execute("UPDATE orders SET total = 0")
        conn.rollback()
    assert pg_reconcile(pg).clean


def test_the_agents_own_credentials_used_directly_are_found(pg: Pg) -> None:
    """Two ways round the engine with the stage role's own login: write with
    no stage, or open one by hand and commit it. Both are found."""
    import psycopg

    with psycopg.connect(pg.agent) as conn:
        conn.execute("UPDATE orders SET status = 'direct' WHERE id = 500")
    with psycopg.connect(pg.agent) as conn:
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        conn.execute("SELECT interlock.begin_stage(gen_random_uuid(), 'by-hand', '{}'::jsonb)")
        conn.execute("UPDATE orders SET status = 'by hand' WHERE id = 501")
    result = pg_reconcile(pg)
    assert [(w.primary_key, w.operation) for w in result.unmediated] == [("500", "update")]
    assert [(f.plan_id, f.problem) for f in result.stages] == [("by-hand", "unrecorded")]


_CRASH_AFTER_COMMIT = r"""
import os, sys
from interlock import BlastRadius, EscrowChain, EscrowEngine, PlanBuilder, PostgresSubstrate
from tests.schemas import specs

dsn, chain_path = sys.argv[1], sys.argv[2]

class Substrate(PostgresSubstrate):
    def commit(self, handle):
        receipt = super().commit(handle)
        os._exit(3)

tables = specs("orders", "order_items", "refunds", "shipments", "stock_reservations", "accounts")
engine = EscrowEngine(
    Substrate(dsn, tables=tables), checkers=[BlastRadius(8)], chain=EscrowChain(chain_path)
)
statement = "UPDATE orders SET total = 777 WHERE id = 500"
engine.execute(PlanBuilder("agent").update(table="orders", statement=statement).build())
"""


def test_a_crash_in_the_commit_window_is_unresolved_until_recovery(pg: Pg, tmp_path: Path) -> None:
    from interlock import PostgresSubstrate

    chain_path = tmp_path / "escrow.jsonl"
    child = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CRASH_AFTER_COMMIT, pg.agent, str(chain_path)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert child.returncode == 3, child.stderr
    (finding,) = pg_reconcile(pg, chain_path).stages
    assert finding.problem == "unresolved"
    assert "Run recovery" in finding.describe()
    with EscrowChain(chain_path) as chain:
        eng = EscrowEngine(
            PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)), checkers=[], chain=chain
        )
        for _ in range(50):
            if eng.recover():
                break
            time.sleep(0.05)
    assert pg_reconcile(pg, chain_path).clean


def test_postgres_reconcile_needs_an_audit_grant(pg: Pg, pg_admin_dsn: str, tmp_path: Path) -> None:
    import psycopg
    from psycopg.conninfo import make_conninfo

    from interlock.postgres import install

    with (
        psycopg.connect(pg.agent, autocommit=True) as conn,
        pytest.raises(SubstrateConfigurationError, match="audit_roles"),
    ):
        reconcile_postgres(conn, [])
    auditor = f"il_audit_{uuid.uuid4().hex[:8]}"
    create_role(pg_admin_dsn, auditor)
    try:
        with psycopg.connect(pg.admin, autocommit=True) as conn:
            install(conn, specs(*OBSERVED), stage_roles=[pg.role], audit_roles=[auditor])
        dsn = make_conninfo(pg.admin, user=auditor, password=PASSWORD)
        with psycopg.connect(dsn, autocommit=True) as conn:
            assert reconcile_postgres(conn, []).clean
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("DELETE FROM interlock.unmediated")
    finally:
        drop_role(pg_admin_dsn, pg.admin, auditor)


def test_the_cli_reconciles_postgres(pg: Pg, tmp_path: Path) -> None:
    import psycopg

    config = tmp_path / "interlock.toml"
    lines = ['substrate = "postgres"']
    for name in OBSERVED:
        spec = specs(name)[0]
        lines += ["[[tables]]", f'name = "{name}"', f"columns = {list(spec.columns)!r}"]
    config.write_text("\n".join(lines).replace("'", '"') + "\n")
    chain_path = tmp_path / "escrow.jsonl"
    with EscrowChain(chain_path) as chain:
        pg_engine(pg, chain).execute(plan("orders", "UPDATE orders SET status = 'x'"))
    args = ["reconcile-effects", "--config", str(config), "--database", pg.admin]
    assert main([*args, "--chain", str(chain_path)], out=io.StringIO()) == 0
    with psycopg.connect(pg.admin) as conn:
        conn.execute("UPDATE orders SET total = 0 WHERE id = 500")
    out = io.StringIO()
    assert main([*args, "--chain", str(chain_path)], out=out) == 1
    assert "UNMEDIATED   #1 update orders pk=500" in out.getvalue()
    with pytest.raises(SystemExit):
        main(args)  # --chain is required
    unreachable = "postgresql://nobody@127.0.0.1:1/none?connect_timeout=1"
    no_db = ["reconcile-effects", "--config", str(config), "--database", unreachable]
    assert main([*no_db, "--chain", str(chain_path)]) == 4
