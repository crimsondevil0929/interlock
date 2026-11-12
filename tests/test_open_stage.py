"""A stage that opens before its plan is whole (``EscrowEngine.stage``, 1.6.0).

Code that decides what to write from what it reads cannot hand the engine a finished plan.
It opens a stage, applies effects one at a time, reads inside the stage, and settles: the
effects become an ordinary plan, and that plan goes through the same lifecycle as
``execute`` on the stage that is already open. Nothing is on the chain before the settle,
and a stage that is discarded leaves nothing anywhere.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    ChangeLimit,
    EscrowChain,
    EscrowEngine,
    KindAllowlist,
    NoDelete,
    OpenStage,
    PlanBuilder,
    SqliteSubstrate,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    ForbiddenStatementError,
    PlanError,
    StageConflictError,
    StageError,
)
from interlock.filesystem import FilesystemSubstrate
from interlock.types import EffectKind, StageState
from tests.conftest import OBSERVED, Pg
from tests.schemas import specs


def engine(back_office: str, tmp_path: Path, *checkers: Any) -> EscrowEngine:
    return EscrowEngine(
        SqliteSubstrate(back_office, tables=specs("orders", "refunds", "order_items")),
        checkers=list(checkers),
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )


def total(back_office: str, order: int) -> str:
    conn = sqlite3.connect(back_office)
    try:
        return str(conn.execute("SELECT total FROM orders WHERE id = ?", (order,)).fetchone()[0])
    finally:
        conn.close()


UPDATE = "UPDATE orders SET total = :total WHERE id = :id"


def test_a_stage_reads_what_it_wrote_and_settles_as_one_plan(
    back_office: str, tmp_path: Path
) -> None:
    run = engine(back_office, tmp_path, ChangeLimit(5), KindAllowlist(["orders"]))
    stage = run.stage("support-agent", intent="discount order 500")
    assert isinstance(stage, OpenStage) and stage.open
    (before,) = stage.read("SELECT total FROM orders WHERE id = :id", {"id": 500})
    assert str(before["total"]) == "45"
    outcome = stage.add(
        EffectKind.UPDATE,
        table="orders",
        statement=UPDATE,
        parameters={"total": "40.00", "id": 500},
    )
    assert outcome.rows_affected == 1
    # the stage sees its own write; the database does not, and the chain holds nothing yet
    (seen,) = stage.read("SELECT total FROM orders WHERE id = :id", {"id": 500})
    assert str(seen["total"]) == "40"
    assert run.chain.records() == ()
    # what it reads decides what it writes next
    stage.add(
        EffectKind.UPDATE,
        table="orders",
        statement=UPDATE,
        parameters={"total": str(seen["total"] - 5), "id": 501},
    )
    result = stage.settle()
    assert result is not None and result.committed and result.state is StageState.COMMITTED
    assert not stage.open
    assert (total(back_office, 500), total(back_office, 501)) == ("40", "35")
    assert result.diff is not None and result.diff.change_count == 2
    assert [e.statement for e in result.plan.effects] == [UPDATE, UPDATE]
    assert result.plan.plan_id == stage.plan_id
    # the chain reads exactly as a plan staged by execute() reads
    assert [r.record_type for r in run.chain.records()] == [
        RecordType.PLAN_ADMITTED,
        RecordType.STAGE_OPENED,
        RecordType.DIFF_COMPUTED,
        RecordType.VERDICT,
        RecordType.COMMIT_INTENT,
        RecordType.COMMITTED,
    ]
    assert {r.stage_id for r in run.chain.records()[1:]} == {stage.stage_id}
    run.chain.verify()


def test_a_plan_the_checkers_refuse_changes_nothing(back_office: str, tmp_path: Path) -> None:
    run = engine(back_office, tmp_path, ChangeLimit(1))
    with run.stage("support-agent") as stage:
        for order in (500, 501):
            stage.add(
                EffectKind.UPDATE,
                table="orders",
                statement=UPDATE,
                parameters={"total": "1.00", "id": order},
            )
        result = stage.settle()
    assert result is not None and not result.committed
    assert result.blocked_by == ("change_limit",)
    assert result.feedback is not None and "change_limit" in result.feedback.render()
    assert (total(back_office, 500), total(back_office, 501)) == ("45", "25")
    assert run.chain.records()[-1].record_type is RecordType.ABORTED
    # the substrate is free again: the next plan stages
    again = PlanBuilder("support-agent").update(
        table="orders", statement=UPDATE, parameters={"total": "44.00", "id": 500}
    )
    assert run.execute(again.build()).committed


def test_a_discarded_stage_leaves_nothing(back_office: str, tmp_path: Path) -> None:
    run = engine(back_office, tmp_path)
    with run.stage("support-agent") as stage:
        stage.add(
            EffectKind.UPDATE,
            table="orders",
            statement=UPDATE,
            parameters={"total": "0.00", "id": 500},
        )
    assert not stage.open
    assert total(back_office, 500) == "45" and run.chain.records() == ()
    with pytest.raises(StageError, match="settled or discarded"):
        stage.settle()
    with pytest.raises(StageError, match="settled or discarded"):
        stage.read("SELECT 1")
    stage.discard()  # twice is once
    # and a stage that added nothing settles to nothing, recorded nowhere
    assert run.stage("support-agent").settle() is None
    assert run.chain.records() == ()
    assert run.execute(
        PlanBuilder("support-agent")
        .update(table="orders", statement=UPDATE, parameters={"total": "44.00", "id": 500})
        .build()
    ).committed


def test_an_effect_that_is_refused_is_not_part_of_the_plan(
    back_office: str, tmp_path: Path
) -> None:
    run = engine(back_office, tmp_path)
    with run.stage("support-agent") as stage:
        with pytest.raises(PlanError, match="unobserved table") as refused:
            stage.add(
                EffectKind.UPDATE,
                table="customers",
                statement="UPDATE customers SET email = 'x' WHERE id = 10",
            )
        assert refused.value.feedback is not None
        with pytest.raises(ForbiddenStatementError):
            stage.add(EffectKind.UPDATE, table="orders", statement="DROP TABLE orders")
        with pytest.raises(StageError, match="failed"):
            stage.add(EffectKind.UPDATE, table="orders", statement="UPDATE orders SET nope = 1")
        assert stage.effects == ()
        stage.add(
            EffectKind.UPDATE,
            table="orders",
            statement=UPDATE,
            parameters={"total": "44.00", "id": 500},
        )
        result = stage.settle()
    assert result is not None and result.committed
    assert len(result.plan.effects) == 1 and total(back_office, 500) == "44"


def test_a_read_keeps_nothing_it_changes(back_office: str, tmp_path: Path) -> None:
    """A read runs inside a savepoint that is rolled back: a statement passed to it that
    writes is undone before the read returns, so it is never in the diff, and never commits."""
    run = engine(back_office, tmp_path, ChangeLimit(1))
    with run.stage("support-agent") as stage:
        assert stage.read("UPDATE orders SET total = 0 WHERE id = 501") == []
        (row,) = stage.read("SELECT total FROM orders WHERE id = 501")
        assert str(row["total"]) == "25"
        with pytest.raises(StageError, match="read failed"):
            stage.read("SELECT nope FROM orders")
        with pytest.raises(ForbiddenStatementError, match="transaction control"):
            stage.read("COMMIT")
        stage.add(
            EffectKind.UPDATE,
            table="orders",
            statement=UPDATE,
            parameters={"total": "44.00", "id": 500},
        )
        result = stage.settle()
    assert result is not None and result.committed
    assert result.diff is not None and result.diff.change_count == 1
    assert total(back_office, 501) == "25"


def test_one_stage_at_a_time(back_office: str, tmp_path: Path) -> None:
    run = engine(back_office, tmp_path)
    with run.stage("support-agent"):
        with pytest.raises(StageConflictError):
            run.stage("support-agent")
    run.stage("support-agent").discard()


def test_a_stage_on_a_directory_reads_its_own_files(tmp_path: Path) -> None:
    workspace = tmp_path / "notes"
    workspace.mkdir()
    (workspace / "todo.md").write_text("- ship\n")
    substrate = FilesystemSubstrate(workspace, ignore=[".git/**"])
    run = EscrowEngine(
        substrate,
        checkers=[KindAllowlist(["docs"]), NoDelete(), ChangeLimit(3)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )
    with run.stage("notes-agent", intent="add a note") as stage:
        assert stage.read("todo.md") == b"- ship\n"
        assert stage.read("missing.md") is None
        text = stage.read("todo.md").decode() + "- test\n"
        stage.add(
            EffectKind.APPLY,
            table="docs",
            statement="write 'todo.md' :text",
            parameters={"text": text},
        )
        stage.add(
            EffectKind.APPLY,
            table="docs",
            statement="write 'done.md' :text",
            parameters={"text": "nothing yet\n"},
        )
        assert stage.read("todo.md") == b"- ship\n- test\n"
        assert stage.substrate is substrate
        assert substrate.paths(stage.handle) == ["done.md", "todo.md"]
        assert (workspace / "todo.md").read_text() == "- ship\n"
        with pytest.raises(ForbiddenStatementError, match="read refused"):
            stage.read("../outside.txt")
        with pytest.raises(ForbiddenStatementError, match="is ignored"):
            stage.read(".git/config")
        result = stage.settle()
    assert result is not None and result.committed
    assert (workspace / "todo.md").read_text() == "- ship\n- test\n"
    assert (workspace / "done.md").read_text() == "nothing yet\n"
    # a second stage whose plan reaches a path class the engine does not grant
    with run.stage("notes-agent") as stage:
        stage.add(
            EffectKind.APPLY,
            table="secrets",
            statement="write '.env' :text",
            parameters={"text": "TOKEN=1\n"},
        )
        refused = stage.settle()
    assert refused is not None and refused.blocked_by == ("kind_allowlist",)
    assert not (workspace / ".env").exists()


def test_a_plan_refused_before_it_is_staged_gives_the_stage_back(
    back_office: str, tmp_path: Path
) -> None:
    """Admission can still refuse at the settle (here, a negative cost). The stage was
    already open, so the engine gives it back: the next plan must be able to stage."""
    run = engine(back_office, tmp_path)
    stage = run.stage("support-agent")
    stage.add(
        EffectKind.UPDATE, table="orders", statement=UPDATE, parameters={"total": "1", "id": 500}
    )
    with pytest.raises(PlanError, match="negative"):
        stage.settle(settle_cost="-1")
    assert total(back_office, 500) == "45"
    run.stage("support-agent").discard()


def test_a_stage_reads_and_settles_on_postgres(pg: Pg, tmp_path: Path) -> None:
    from interlock.postgres import PostgresSubstrate

    run = EscrowEngine(
        PostgresSubstrate(pg.agent, tables=specs(*OBSERVED)),
        checkers=[ChangeLimit(2)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )
    with run.stage("support-agent") as stage:
        stage.add(
            EffectKind.UPDATE,
            table="orders",
            statement="UPDATE orders SET total = %(total)s WHERE id = %(id)s",
            parameters={"total": "40.00", "id": 500},
        )
        (seen,) = stage.read("SELECT total FROM orders WHERE id = %(id)s", {"id": 500})
        assert str(seen["total"]) == "40.00"
        # a read that fails does not end the stage, and one that writes keeps nothing
        with pytest.raises(StageError, match="read failed"):
            stage.read("SELECT nope FROM orders")
        assert stage.read("UPDATE orders SET total = 0 WHERE id = 501") == []
        (other,) = stage.read("SELECT total FROM orders WHERE id = 501")
        assert str(other["total"]) == "25.00"
        result = stage.settle()
    assert result is not None and result.committed
    assert result.diff is not None and result.diff.change_count == 1
