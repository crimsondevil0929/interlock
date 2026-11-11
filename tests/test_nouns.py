"""Each system's own nouns in what a refusal and a chain record say (1.5.2).

Every substrate measures a diff of ``RowDelta``s keyed by ``table``: the engine's model, and
SQL's words. A person who works on files, cluster objects or API records reads a refusal in
theirs. Checker names (``table_allowlist``, ``no_delete``) are identifiers that receipts and
mandates carry, and do not change.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from interlock import BlastRadius, EscrowChain, EscrowEngine, NoDelete, PlanBuilder, TableAllowlist
from interlock.chain import RecordType
from interlock.feedback import ConstraintFeedback, Guidance
from interlock.filesystem import FilesystemSubstrate
from interlock.invariants import StatedFootprint, TenantIsolation
from interlock.text import Nouns, nouns
from interlock.types import EffectDiff, EffectKind, PlanId, RowDelta

SYSTEMS = {
    "sqlite": ("row", "table"),
    "postgres": ("row", "table"),
    "git": ("file", "path class"),
    "filesystem": ("file", "path class"),
    "kubernetes": ("object", "kind"),
    "terraform": ("resource", "resource type"),
    "fhir": ("resource", "resource type"),
    "rest": ("record", "resource type"),
}


def test_every_shipped_substrate_has_its_nouns_and_an_unknown_one_has_sqls() -> None:
    for system, (row, table) in SYSTEMS.items():
        assert nouns(system) == Nouns(row, table)
    assert nouns("a-plugin") == Nouns("row", "table")


def diff(system: str) -> EffectDiff:
    """Two deleted things in ``scripts`` and one changed in ``config``, of two tenants."""
    deltas = (
        RowDelta("scripts", "a", {"v": 1}, None, tenant_id="acme"),
        RowDelta("scripts", "b", {"v": 1}, None, tenant_id="globex"),
        RowDelta("config", "c", {"v": 1}, {"v": 2}, tenant_id="acme"),
    )
    return EffectDiff(
        plan_id=PlanId("plan-1"),
        stage_id=uuid.uuid4(),
        substrate_id=system,
        computed_at=datetime.now(UTC),
        deltas=deltas,
    )


def plan(stated: int | None = None) -> object:
    builder = PlanBuilder("agent", intent="tidy up")
    builder.add(
        EffectKind.DELETE, table="scripts", statement="x", tenant_id="acme", stated_rows=stated
    )
    return builder.build()


@pytest.mark.parametrize("system", SYSTEMS)
def test_a_refusal_speaks_the_systems_nouns(system: str) -> None:
    row, table = SYSTEMS[system]
    rows, tables = (f"{row}s", "path classes" if table == "path class" else f"{table}s")
    measured, built = diff(system), plan(stated=1)

    def said(checker: object) -> list[str]:
        return [str(v.message) for v in checker.check(built, measured)]  # type: ignore[attr-defined]

    assert said(TableAllowlist(["config"])) == [
        f"plan touched {tables} outside the allowlist: scripts"
    ]
    assert said(NoDelete()) == [f"plan deletes 2 {rows} from ungranted {table}: scripts"]
    assert said(BlastRadius(2)) == [f"plan would mutate 3 {rows}, limit is 2"]
    assert said(StatedFootprint()) == [f"agent stated 1 {row}; substrate measured 3 (3.0x)"]
    assert f"plan changes {rows} of 1 tenant its effects do not declare: globex" in said(
        TenantIsolation(2, declared=True)
    )


def test_a_directory_is_told_about_files_and_path_classes(tmp_path: Path) -> None:
    """End to end on the filesystem substrate: the verdict, the agent's feedback and the
    chain's notes. Before 1.5.2 the verdict read "plan touched tables outside the allowlist:
    secrets" and "deletes 1 row from ungranted table"."""
    workspace = tmp_path / "svc"
    (workspace / "scripts").mkdir(parents=True)
    (workspace / "config").mkdir()
    (workspace / "scripts" / "backup.sh").write_text("#!/bin/sh\n")
    (workspace / "config" / "service.toml").write_text("timeout_ms = 2500\n")
    run = EscrowEngine(
        FilesystemSubstrate(workspace),
        checkers=[TableAllowlist(["config"]), NoDelete(), BlastRadius(5)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )
    remove = PlanBuilder("ops-agent", intent="tidy up").delete(
        table="scripts", statement="delete 'scripts/backup.sh'"
    )
    refused = run.execute(remove.build())
    assert not refused.committed and (workspace / "scripts" / "backup.sh").exists()
    assert refused.verdict is not None
    assert sorted(v.message for v in refused.verdict.violations) == [
        "plan deletes 1 file from ungranted path class: scripts",
        "plan touched path classes outside the allowlist: scripts",
    ]
    assert refused.feedback is not None
    told = refused.feedback.render()
    assert "the plan changed files in the scripts path class, which it may not write" in told
    assert "the plan deletes files from the scripts path class" in told
    # The checkers' names stay as receipts and mandates carry them; the sentences are files'.
    sentences = told.replace("table_allowlist:", "").replace("no_delete:", "")
    assert "table" not in sentences and "row" not in sentences
    edit = PlanBuilder("ops-agent", intent="raise the timeout").update(
        table="config",
        statement="replace 'config/service.toml' :old :new",
        parameters={"old": "timeout_ms = 2500", "new": "timeout_ms = 4000"},
    )
    assert run.execute(edit.build()).committed
    notes = {r.record_type: r.note for r in run.chain.records()[-4:]}
    assert notes[RecordType.COMMIT_INTENT].startswith("about to commit 1 file")
    assert notes[RecordType.COMMITTED].startswith("1 file committed")
    assert all("row" not in r.note for r in run.chain.records())


@pytest.mark.parametrize(
    ("system", "things", "kind", "reached"),
    [
        ("kubernetes", "objects", "kind", "the cluster's API server could not be reached."),
        ("terraform", "resources", "resource type", "Terraform, or its state, could not be"),
    ],
)
def test_the_plan_bound_systems_tell_an_agent_in_their_own_words(
    system: str, things: str, kind: str, reached: str
) -> None:
    """Before 1.5.2 a cluster's agent was told to "narrow the statements' WHERE clauses"."""

    def told(guidance: Guidance, **fields: object) -> str:
        return ConstraintFeedback(guidance, True, substrate=system, **fields).render()  # type: ignore[arg-type]

    limit = told(Guidance.ROW_LIMIT, measured="10-99", limit="6")
    assert f"the plan changes 10-99 {things}" in limit and "WHERE" not in limit
    scope = told(Guidance.TABLE_SCOPE, tables=("secrets",))
    assert f"changes {things} of the secrets {kind}" in scope or f"{things} of secrets" in scope
    assert f"deletes {things} from" in told(Guidance.NO_DELETE, tables=("configmaps",))
    assert reached in told(Guidance.UNAVAILABLE)
    for guidance in (
        Guidance.ROW_LIMIT,
        Guidance.TRUNCATED,
        Guidance.STATED_FOOTPRINT,
        Guidance.STATEMENT_KIND,
        Guidance.STATEMENT_FAILED,
        Guidance.CONFLICT,
        Guidance.UNAVAILABLE,
    ):
        sentence = told(guidance, measured="3", limit="1").split(": ", 1)[1]
        assert " row" not in sentence and "database" not in sentence and "SELECT" not in sentence
