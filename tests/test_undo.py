"""Undo (1.10.0): a committed plan put back exactly, as a plan of its own.

The claims, in order of how much they matter:

1. An undo puts every row back exactly as it was, and commits only as exactly the inverse
   of the plan: a row someone changed since refuses the whole undo, naming it, and nothing
   changes.
2. What is kept stays in the database it came from, for the window, and nowhere else: the
   chain names the plan's change digests by hash.
3. An exact inverse is not held to the size bounds (an insert's undo is a delete, a large
   mistake's undo is as large); an inexact one is refused, in shadow mode too.
4. The undo's change digests are exactly the inverse of the plan's, so an auditor can check
   it without the data; an undo of the undo puts the plan's change back.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from interlock import (
    BlastRadius,
    Effect,
    EffectId,
    EffectKind,
    EffectPlan,
    EscrowEngine,
    PlanId,
    SqliteSubstrate,
    TableSpec,
)
from interlock.chain import RecordType
from interlock.exceptions import PlanError, UndoError
from interlock.invariants import NoDelete
from interlock.types import Change, EffectDiff
from interlock.undo import (
    UNDO_EXACT,
    Kept,
    changes_hash,
    digest_problems,
    inverse_problems,
    net,
    waived,
)

SCHEMA = """
CREATE TABLE orders(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, customer INTEGER, total REAL NOT NULL
);
"""
TABLES = [
    TableSpec("orders", columns=["id", "tenant", "customer", "total"], tenant_column="tenant")
]
WEEK = timedelta(days=7)


@pytest.fixture
def db(tmp_path: Path) -> str:
    path = str(tmp_path / "prod.db")
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO orders VALUES (?,?,?,?)",
        [(1, "acme", 42, 100.0), (2, "acme", 42, 200.0), (5, "initech", 12, 500.0)],
    )
    conn.commit()
    conn.close()
    return path


def rows(path: str) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        return list(conn.execute("SELECT * FROM orders ORDER BY id"))
    finally:
        conn.close()


def sql(effect_id: str, kind: EffectKind, statement: str, **parameters: object) -> Effect:
    return Effect(
        effect_id=EffectId(effect_id),
        kind=kind,
        target="sqlite:orders",
        statement=statement,
        parameters=parameters,
        tenant_id="acme",
    )


def plan(*effects: Effect) -> EffectPlan:
    return EffectPlan(
        plan_id=PlanId(f"plan-{uuid.uuid4().hex[:8]}"),
        scope_id="agent",
        trajectory_id="t1",
        created_at=datetime.now(UTC),
        effects=effects,
        intent="a mistake",
    )


def mistake() -> EffectPlan:
    return plan(
        sql("e1", EffectKind.UPDATE, "UPDATE orders SET total = 150.0 WHERE id = 1"),
        sql("e2", EffectKind.INSERT, "INSERT INTO orders VALUES (6, 'acme', 9, 60.0)"),
        sql("e3", EffectKind.DELETE, "DELETE FROM orders WHERE id = 5"),
    )


def engine(path: str, *, undo: timedelta | None = WEEK, **kwargs: object) -> EscrowEngine:
    checkers = kwargs.pop("checkers", [])
    return EscrowEngine(
        SqliteSubstrate(path, tables=TABLES, undo=undo),
        checkers=checkers,  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def test_an_undo_puts_every_row_back_exactly(db: str) -> None:
    before = rows(db)
    first = engine(db)
    done = first.execute(mistake())
    assert done.committed and len(done.changes) == 3
    committed = [r for r in first.chain.records() if r.record_type is RecordType.COMMITTED]
    assert f"changes {changes_hash(done.changes)}" in committed[-1].note
    assert rows(db) != before

    second = engine(db)
    undone = second.undo(done.plan.plan_id, scope_id="agent")
    assert undone.committed, undone.verdict
    assert rows(db) == before
    assert undone.plan.undoes == done.plan.plan_id
    assert undone.undid == done.changes
    assert digest_problems(undone.undid, undone.changes) == []
    # the chain says it is an undo, and names its own change digests
    records = list(second.chain.records())
    admitted = [r for r in records if r.record_type is RecordType.PLAN_ADMITTED]
    assert admitted[-1].note.startswith(f"undo of {done.plan.plan_id}: ")

    # an undo of the undo puts the plan's change back
    redone = engine(db).undo(undone.plan.plan_id, scope_id="agent")
    assert redone.committed and rows(db) != before
    assert digest_problems(redone.undid, redone.changes) == []
    assert sorted(redone.changes) == sorted(done.changes)


def test_kept_images_stay_in_the_database_and_lapse_with_the_window(db: str) -> None:
    done = engine(db).execute(mistake())
    conn = sqlite3.connect(db)
    try:
        kept = conn.execute("SELECT tbl, pk, before, after FROM _interlock_undo").fetchall()
        assert len(kept) == 3
        conn.execute("UPDATE _interlock_undo SET expires_at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(UndoError, match="older than the undo window"):
        engine(db).undo(done.plan.plan_id, scope_id="agent")
    # the next commit drops what is past its window
    engine(db).execute(
        plan(sql("e1", EffectKind.UPDATE, "UPDATE orders SET total = 1 WHERE id = 2"))
    )
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM _interlock_undo").fetchone()[0] == 1
    finally:
        conn.close()


def test_a_row_changed_since_refuses_the_whole_undo_and_changes_nothing(db: str) -> None:
    done = engine(db).execute(mistake())
    conn = sqlite3.connect(db)
    conn.execute("UPDATE orders SET total = 175.0 WHERE id = 1")  # a person's edit
    conn.commit()
    conn.close()
    after_edit = rows(db)
    undone = engine(db).undo(done.plan.plan_id, scope_id="agent")
    assert not undone.committed
    assert undone.blocked_by == (UNDO_EXACT,)
    (violation,) = undone.verdict.blocking  # type: ignore[union-attr]
    assert "orders 1 was not put back" in violation.message
    assert rows(db) == after_edit


def test_an_exact_undo_is_not_held_to_the_size_bounds_and_an_inexact_one_is(db: str) -> None:
    done = engine(db).execute(mistake())
    bounded = engine(db, checkers=[BlastRadius(1), NoDelete()])
    # moved first: the bounds hold, and so does the undo's own check
    conn = sqlite3.connect(db)
    conn.execute("UPDATE orders SET customer = 1 WHERE id = 6")
    conn.commit()
    conn.close()
    refused = bounded.undo(done.plan.plan_id, scope_id="agent")
    assert not refused.committed and UNDO_EXACT in refused.blocked_by
    assert "blast_radius" in refused.blocked_by
    conn = sqlite3.connect(db)
    conn.execute("UPDATE orders SET customer = 9 WHERE id = 6")  # put back by hand
    conn.commit()
    conn.close()
    undone = bounded.undo(done.plan.plan_id, scope_id="agent")
    assert undone.committed, undone.blocked_by  # three rows and a delete, waived


def test_shadow_mode_still_refuses_an_inexact_undo(db: str) -> None:
    done = engine(db).execute(mistake())
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM orders WHERE id = 6")
    conn.commit()
    conn.close()
    watching = engine(db, checkers=[BlastRadius(1)], observe_only=True)
    undone = watching.undo(done.plan.plan_id, scope_id="agent")
    assert not undone.committed and undone.blocked_by == (UNDO_EXACT,)


def test_what_cannot_be_undone_is_said(db: str) -> None:
    with pytest.raises(UndoError, match="keeps no undo"):
        engine(db, undo=None).undo("plan-x", scope_id="agent")
    with pytest.raises(UndoError, match="nothing is kept"):
        engine(db).undo("plan-never", scope_id="agent")
    forged = EffectPlan(
        plan_id=PlanId("plan-forged"),
        scope_id="agent",
        trajectory_id="t",
        created_at=datetime.now(UTC),
        effects=(sql("e1", EffectKind.DELETE, "DELETE FROM orders WHERE id = 1"),),
        undoes=PlanId("plan-anything"),
    )
    with pytest.raises(PlanError, match=r"an undo is built by EscrowEngine\.undo"):
        engine(db, checkers=[NoDelete()]).execute(forged)
    with pytest.raises(ValueError, match="positive"):
        SqliteSubstrate(db, tables=TABLES, undo=timedelta(0))
    # a plan that changed nothing kept nothing
    same = engine(db).execute(
        plan(sql("e1", EffectKind.UPDATE, "UPDATE orders SET total = total WHERE id = 1"))
    )
    assert same.committed and same.changes == ()


def test_net_inverse_and_digest_problems_in_words() -> None:
    a = Change(kind="t", id="1", before={"v": 1}, after={"v": 2})
    b = Change(kind="t", id="1", before={"v": 2}, after={"v": 3})
    gone = Change(kind="t", id="2", before=None, after={"v": 1})
    back = Change(kind="t", id="2", before={"v": 1}, after=None)
    (netted,) = net([a, b, gone, back])
    assert netted.before == {"v": 1} and netted.after == {"v": 3}
    kept = Kept(
        plan_id="p",
        substrate_id="sqlite",
        changes=(netted,),
        key=b"k" * 32,
        committed_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + WEEK,
    )

    def diff(*changes: Change, truncated: bool = False) -> EffectDiff:
        return EffectDiff(
            plan_id=PlanId("u"),
            stage_id=uuid.uuid4(),
            substrate_id="sqlite",
            computed_at=datetime.now(UTC),
            deltas=changes,
            truncated=truncated,
        )

    exact = Change(kind="t", id="1", before={"v": 3}, after={"v": 1})
    assert inverse_problems(kept, diff(exact)) == []
    assert inverse_problems(kept, diff(exact, truncated=True))[0].startswith("the measurement")
    assert inverse_problems(kept, diff(Change(kind="t", id="1", before={"v": 4}, after={"v": 1})))
    wrong = Change(kind="t", id="1", before={"v": 3}, after={"v": 9})
    assert inverse_problems(kept, diff(wrong)) == ["t 1 would not be put back as it was"]
    stray = Change(kind="t", id="9", before=None, after={"v": 1})
    assert inverse_problems(kept, diff(exact, stray)) == ["t 9 is not one the plan changed"]
    original = kept.digests()
    (k, i, b0, a0) = original[0]
    assert digest_problems(original, [(k, i, a0, b0)]) == []
    assert digest_problems(original, [(k, i, b0, a0)]) == ["t 1 is not put back exactly as it was"]
    assert digest_problems(original, []) == ["t 1 is not put back"]
    assert digest_problems([], [(k, i, a0, b0)]) == ["t 1 is changed and the plan never changed it"]
    assert waived("value_guard:orders.total") and not waived("tenant_isolation")


# --------------------------------------------------------------------------
# a directory: the content it replaced, kept beside the workspace
# --------------------------------------------------------------------------


def tree(root: Path) -> dict[str, tuple[str, str]]:
    """Every file under ``root``: its text and mode."""
    return {
        p.relative_to(root).as_posix(): (p.read_text(), oct(p.stat().st_mode & 0o777))
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_a_directory_undo_puts_every_file_back(tmp_path: Path) -> None:
    from interlock import PlanBuilder
    from interlock.filesystem import FilesystemSubstrate
    from tests.test_filesystem import make_workspace

    workspace = make_workspace(tmp_path / "billing")
    before = tree(workspace)
    sub = FilesystemSubstrate(workspace, undo=WEEK)
    plan = (
        PlanBuilder("agent", trajectory_id="t")
        .insert(table="docs", statement="write 'docs/notes.md' :t", parameters={"t": "hi\n"})
        .update(table="docs", statement="append 'docs/runbook.md' 'Restart with care.\n'")
        .update(table="scripts", statement="mode 'scripts/rotate.sh' '700'")
        .update(table="config", statement="move 'config/flags.yaml' 'config/features.yaml'")
        .build()
    )
    done = EscrowEngine(sub, checkers=[]).execute(plan)
    assert done.committed and len(done.changes) == 5
    kept = sub.state / "undo" / done.plan.plan_id
    assert (kept / "kept.json").is_file() and len(list((kept / "blobs").iterdir())) == 3
    assert workspace.resolve() not in kept.resolve().parents  # beside it, never in it

    bounded = EscrowEngine(sub, checkers=[BlastRadius(1), NoDelete()])
    undone = bounded.undo(done.plan.plan_id, scope_id="agent")
    assert undone.committed, undone.blocked_by
    assert tree(workspace) == before
    assert digest_problems(undone.undid, undone.changes) == []


def test_a_file_edited_since_refuses_the_directory_undo(tmp_path: Path) -> None:
    from interlock import PlanBuilder
    from interlock.filesystem import FilesystemSubstrate
    from tests.test_filesystem import make_workspace

    workspace = make_workspace(tmp_path / "billing")
    sub = FilesystemSubstrate(workspace, undo=WEEK)
    plan = (
        PlanBuilder("agent", trajectory_id="t")
        .update(table="docs", statement="append 'docs/runbook.md' 'one\n'")
        .update(table="config", statement="append 'config/flags.yaml' 'two: true\n'")
        .build()
    )
    done = EscrowEngine(sub, checkers=[]).execute(plan)
    assert done.committed
    (workspace / "docs/runbook.md").write_text("a person's edit\n")
    edited = tree(workspace)
    undone = EscrowEngine(sub, checkers=[]).undo(done.plan.plan_id, scope_id="agent")
    assert not undone.committed and undone.blocked_by == (UNDO_EXACT,)
    (violation,) = undone.verdict.blocking  # type: ignore[union-attr]
    assert "docs/runbook.md was not put back" in violation.message
    assert tree(workspace) == edited

    # a file the language cannot write back is said, before anything is staged
    (workspace / "docs/runbook.md").write_bytes(b"\xff\xfe binary")
    binary = EscrowEngine(sub, checkers=[]).execute(
        PlanBuilder("agent", trajectory_id="t")
        .update(table="docs", statement="write 'docs/runbook.md' 'text now\n'")
        .build()
    )
    assert binary.committed
    with pytest.raises(UndoError, match="not UTF-8 text"):
        EscrowEngine(sub, checkers=[]).undo(binary.plan.plan_id, scope_id="agent")


# --------------------------------------------------------------------------
# Git: the images recorded beside the repository, the content its own objects
# --------------------------------------------------------------------------


def test_a_git_undo_puts_each_path_back_as_a_new_commit(tmp_path: Path) -> None:
    from interlock import PlanBuilder
    from tests.test_git_substrate import INVOICE, Repo, git
    from tests.test_git_substrate import substrate as git_substrate

    repo = Repo(tmp_path)
    sub = git_substrate(repo, hooks=(), undo=WEEK)
    plan = (
        PlanBuilder("agent", trajectory_id="t")
        .update(table="src", statement=f"replace '{INVOICE}' 'sum(lines)' 'sum(lines) * 2'")
        .insert(table="docs", statement="write 'docs/new.md' 'new\n'")
        .delete(table="docs", statement="delete 'README.md'")
        .build()
    )
    done = EscrowEngine(sub, checkers=[]).execute(plan)
    assert done.committed and len(done.changes) == 3
    record = Path(sub._common) / "interlock" / "undo" / f"{done.plan.plan_id}.json"
    assert record.is_file()
    teammate = repo.push("tests/test_more.py", "def test_more():\n    assert True\n")

    undone = EscrowEngine(sub, checkers=[BlastRadius(1), NoDelete()]).undo(
        done.plan.plan_id, scope_id="agent"
    )
    assert undone.committed, undone.blocked_by
    assert repo.show(INVOICE) == "def total(lines):\n    return sum(lines)\n"
    assert repo.show("README.md") == "# acme\n"
    assert git(repo.origin, "ls-tree", "main", "--", "docs/new.md") == ""
    assert repo.show("tests/test_more.py").startswith("def test_more")  # the teammate's stays
    git(repo.origin, "merge-base", "--is-ancestor", teammate, "main")  # built on top of it
    assert digest_problems(undone.undid, undone.changes) == []


def test_a_path_a_teammate_changed_since_refuses_the_git_undo(tmp_path: Path) -> None:
    from interlock import PlanBuilder
    from tests.test_git_substrate import INVOICE, Repo
    from tests.test_git_substrate import substrate as git_substrate

    repo = Repo(tmp_path)
    sub = git_substrate(repo, hooks=(), undo=WEEK)
    done = EscrowEngine(sub, checkers=[]).execute(
        PlanBuilder("agent", trajectory_id="t")
        .update(table="src", statement=f"replace '{INVOICE}' 'sum(lines)' 'sum(lines) * 2'")
        .build()
    )
    assert done.committed
    repo.push(INVOICE, "def total(lines):\n    return 0\n")
    head = repo.head()
    undone = EscrowEngine(sub, checkers=[]).undo(done.plan.plan_id, scope_id="agent")
    assert not undone.committed and undone.blocked_by == (UNDO_EXACT,)
    assert f"{INVOICE} was not put back" in undone.verdict.blocking[0].message  # type: ignore[union-attr]
    assert repo.head() == head


def test_the_window_is_read_from_the_file_and_given_to_the_substrate(
    db: str, tmp_path: Path
) -> None:
    from interlock.config import ConfigError, load_config
    from interlock.wiring import open_substrate

    def config(extra: str) -> Path:
        path = tmp_path / "interlock.toml"
        path.write_text(
            f'substrate = "sqlite"\ndatabase = "{db}"\n{extra}'
            '[[tables]]\nname = "orders"\nprimary_key = "id"\n'
            'columns = ["id", "tenant", "customer", "total"]\ntenant_column = "tenant"\n'
        )
        return path

    assert load_config(config("")).undo is None
    loaded = load_config(config("[undo]\ndays = 7\n"))
    assert loaded.undo == WEEK
    sub = open_substrate(loaded)
    assert getattr(sub, "keeps_undo", False)
    for bad in (
        "[undo]\ndays = 0\n",
        "[undo]\ndays = 400\n",
        '[undo]\ndays = "7"\n',
        "[undo]\nhours = 1\n",
        "undo = 7\n",
    ):
        with pytest.raises(ConfigError, match="undo"):
            load_config(config(bad))
