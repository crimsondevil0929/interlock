"""An engine that watches and does not refuse (``observe_only``, 1.6.0).

A policy is tried on real work before it is enforced: every plan is staged, measured and
judged exactly as it would be, and a violation that would have refused it is recorded as
``observed``. The plan commits. The verdict, its hash and the chain say what was observed,
so "what would this policy have refused last week" is answered from signed records.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from interlock import (
    ChangeLimit,
    EscrowChain,
    EscrowEngine,
    KindAllowlist,
    NoDelete,
    PlanBuilder,
    SqliteSubstrate,
    StatedFootprint,
)
from interlock.chain import RecordType
from interlock.exceptions import ForbiddenStatementError
from interlock.filesystem import FilesystemSubstrate
from interlock.types import EffectPlan, Severity
from tests.schemas import specs


def engine(back_office: str, tmp_path: Path, **options: object) -> EscrowEngine:
    return EscrowEngine(
        SqliteSubstrate(back_office, tables=specs("orders", "refunds", "order_items")),
        checkers=[ChangeLimit(1), KindAllowlist(["refunds"]), StatedFootprint()],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
        **options,  # type: ignore[arg-type]
    )


def zero_two_orders() -> EffectPlan:
    return (
        PlanBuilder("support-agent", intent="zero two orders")
        .update(table="orders", statement="UPDATE orders SET total = 0 WHERE tenant = 'acme'")
        .build()
    )


def totals(back_office: str) -> list[str]:
    conn = sqlite3.connect(back_office)
    try:
        return [str(r[0]) for r in conn.execute("SELECT total FROM orders ORDER BY id")]
    finally:
        conn.close()


def test_an_enforcing_engine_refuses_the_plan(back_office: str, tmp_path: Path) -> None:
    result = engine(back_office, tmp_path).execute(zero_two_orders())
    assert not result.committed
    assert result.blocked_by == ("change_limit", "kind_allowlist")
    assert result.would_refuse == ()
    assert totals(back_office) == ["45", "25", "10"]


def test_an_observing_engine_commits_it_and_records_what_would_have_refused(
    back_office: str, tmp_path: Path
) -> None:
    run = engine(back_office, tmp_path, observe_only=True)
    result = run.execute(zero_two_orders())
    assert result.committed and result.blocked_by == ()
    assert result.would_refuse == ("change_limit", "kind_allowlist")
    assert totals(back_office) == ["0", "0", "10"]
    assert result.verdict is not None and result.verdict.admitted
    assert [(v.invariant, v.severity) for v in result.verdict.violations] == [
        ("change_limit", Severity.OBSERVED),
        ("kind_allowlist", Severity.OBSERVED),
    ]
    assert [v.message for v in result.verdict.observed] == [
        "plan would mutate 2 rows, limit is 1",
        "plan touched tables outside the allowlist: orders",
    ]
    # the chain says so, and the verdict it hashes is not the enforcing engine's
    notes = {r.record_type: r.note for r in run.chain.records()}
    assert notes[RecordType.VERDICT] == (
        "admitted; observed, not enforced: change_limit,kind_allowlist"
    )
    assert notes[RecordType.COMMITTED].startswith("2 rows committed")
    run.chain.verify()
    # the agent is told, in the same words a refusal would use
    assert result.feedback is not None
    told = result.feedback.render()
    assert told.startswith("The plan committed.")
    assert told.count("Observed, not enforced: the plan was not refused for it.") == 2
    assert "change_limit: the plan changed 2-9 rows; the limit is 1." in told
    constraints = result.feedback.to_json()["constraints"]
    assert [(c["constraint"], c["blocking"], c["observed"]) for c in constraints] == [
        ("change_limit", False, True),
        ("kind_allowlist", False, True),
    ]


def test_the_two_engines_hash_different_verdicts(back_office: str, tmp_path: Path) -> None:
    """Observed is on the verdict and in its hash: a record of a plan that committed under
    observation cannot be passed off as one an enforcing engine admitted clean."""
    enforcing = engine(back_office, tmp_path).execute(zero_two_orders())
    (tmp_path / "second").mkdir()
    observing = engine(back_office, tmp_path / "second", observe_only=True).execute(
        zero_two_orders()
    )
    assert enforcing.verdict is not None and observing.verdict is not None
    assert enforcing.verdict.content_hash() != observing.verdict.content_hash()


def test_a_checker_named_always_enforced_still_refuses(back_office: str, tmp_path: Path) -> None:
    run = engine(back_office, tmp_path, observe_only=True, always_enforce=["kind_allowlist"])
    result = run.execute(zero_two_orders())
    assert not result.committed
    assert result.blocked_by == ("kind_allowlist",)
    assert result.would_refuse == ("change_limit",)
    assert totals(back_office) == ["45", "25", "10"]
    assert run.chain.records()[-1].record_type is RecordType.ABORTED


def test_a_plan_inside_the_policy_reads_the_same_either_way(
    back_office: str, tmp_path: Path
) -> None:
    refund = (
        PlanBuilder("support-agent")
        .insert(
            table="refunds",
            statement="INSERT INTO refunds (id, order_item_id, amount) VALUES (9001, 5000, 5)",
        )
        .build()
    )
    run = engine(back_office, tmp_path, observe_only=True)
    result = run.execute(refund)
    assert result.committed and result.would_refuse == ()
    assert result.verdict is not None and result.verdict.violations == ()
    assert run.chain.records()[3].note == "admitted"


def test_what_the_stage_cannot_do_still_fails(tmp_path: Path) -> None:
    """Observing turns verdicts into observations. It does not make the substrate stage what
    it cannot measure: a path that leaves the workspace is refused as it always is."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.txt").write_text("a\n")
    run = EscrowEngine(
        FilesystemSubstrate(workspace),
        checkers=[NoDelete(), KindAllowlist(["config"])],
        observe_only=True,
    )
    removed = run.execute(
        PlanBuilder("agent").delete(table="other", statement="delete 'a.txt'").build()
    )
    assert removed.committed and removed.would_refuse == ("no_delete", "kind_allowlist")
    assert not (workspace / "a.txt").exists()
    with pytest.raises(ForbiddenStatementError):
        run.execute(
            PlanBuilder("agent").update(table="other", statement="write '../x' 'x'").build()
        )
