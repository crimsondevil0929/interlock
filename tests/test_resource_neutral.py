"""The resource-neutral public model (1.6.0).

A change is a row, a file, a cluster object, a resource or a record. ``Change`` names it the
way every system can (``kind``, ``id``); ``RowDelta``, ``table`` and ``primary_key`` are the
same class and the same values under the names they had. Four built-in checkers have neutral
names beside their SQL ones. Nothing recorded before 1.6.0 changes: the SQL-named checkers
keep the digests their receipts carry, and a diff hashes as it did.
"""

from __future__ import annotations

import dataclasses
import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

import interlock
from interlock import (
    CHECKER_ALIASES,
    BlastRadius,
    Change,
    ChangeLimit,
    ColumnValueGuard,
    EscrowChain,
    EscrowEngine,
    InvariantChecker,
    KindAllowlist,
    NoDelete,
    PartitionIsolation,
    PlanBuilder,
    RowDelta,
    TableAllowlist,
    TenantIsolation,
    ValueGuard,
    checker_family,
)
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.filesystem import FilesystemSubstrate
from interlock.invariants import BUILT_IN_CHECKERS
from interlock.receipts import checker_records
from interlock.types import EffectDiff, EffectKind, EffectPlan, PlanId

# --------------------------------------------------------------------------
# Change
# --------------------------------------------------------------------------


def test_row_delta_is_change_under_the_name_it_had() -> None:
    assert RowDelta is Change
    assert interlock.RowDelta is interlock.Change


def test_a_change_is_built_and_read_in_either_vocabulary() -> None:
    neutral = Change("orders", "500", {"total": "45.00"}, {"total": "40.00"}, tenant_id="acme")
    sql = RowDelta(
        table="orders",
        primary_key="500",
        before={"total": "45.00"},
        after={"total": "40.00"},
        tenant_id="acme",
    )
    keyword = Change(kind="orders", id="500", before={"total": "45.00"}, after={"total": "40.00"})
    assert neutral == sql
    assert keyword == dataclasses.replace(neutral, tenant_id=None)
    for change in (neutral, sql):
        assert (change.kind, change.id) == ("orders", "500")
        assert (change.table, change.primary_key) == ("orders", "500")
        assert change.operation == "update"
        assert change.changed_fields() == change.changed_columns() == ("total",)
        assert change.partition("tenant") == "acme" and change.partition("patient") is None


def test_a_change_names_what_is_missing_and_stays_frozen() -> None:
    with pytest.raises(TypeError, match="missing id, before, after"):
        Change("orders")
    change = Change("docs", "README.md", None, {"bytes": 12})
    assert change.operation == "insert" and change.partitions == {}
    with pytest.raises(dataclasses.FrozenInstanceError):
        change.kind = "src"  # type: ignore[misc]
    # replace() passes the change's own kind beside the SQL name it is given: the name wins
    moved = dataclasses.replace(change, table="src", primary_key="a.py")  # type: ignore[call-arg]
    assert (moved.kind, moved.id, moved.after) == ("src", "a.py", {"bytes": 12})


DIFF_1_5_2 = "1c21578742e0c01f9b4d18422d79534f4171bba21d73633d528cd6c7a9345d3d"


def diff(system: str = "filesystem") -> EffectDiff:
    return EffectDiff(
        plan_id=PlanId("plan-1"),
        stage_id=uuid.UUID(int=1),
        substrate_id=system,
        computed_at=datetime(2026, 11, 12, tzinfo=UTC),
        deltas=(
            Change("scripts", "a.sh", {"bytes": 4}, None, tenant_id="acme"),
            Change("scripts", "b.sh", {"bytes": 4}, None, tenant_id="globex"),
            Change("config", "svc.toml", {"bytes": 10}, {"bytes": 4}, tenant_id="acme"),
        ),
    )


def test_a_diff_reads_in_either_vocabulary_and_hashes_as_it_did() -> None:
    measured = diff()
    assert measured.changes is measured.deltas
    assert measured.change_count == measured.blast_radius == 3
    assert measured.kinds_touched == measured.tables_touched == {"scripts", "config"}
    # the digest of this diff as interlock 1.5.2 computed it: the same values, hashed in the
    # same order, under no names
    assert measured.content_hash() == DIFF_1_5_2
    legacy = EffectDiff(
        plan_id=measured.plan_id,
        stage_id=measured.stage_id,
        substrate_id=measured.substrate_id,
        computed_at=measured.computed_at,
        deltas=tuple(
            RowDelta(
                table=d.kind,
                primary_key=d.id,
                before=d.before,
                after=d.after,
                tenant_id=d.tenant_id,
            )
            for d in measured.deltas
        ),
    )
    assert legacy.content_hash() == measured.content_hash()


# --------------------------------------------------------------------------
# the neutral checkers
# --------------------------------------------------------------------------

DIGESTS_1_5_2 = {
    "blast_radius": "cfd7cd9e040d",
    "tenant_isolation": "f80bd4acce26",
    "partition_isolation:patient": "10276e40a0b9",
    "table_allowlist": "9f4cfa1064e6",
    "column_value_guard:o.t": "2d1d179be8fe",
}


def test_the_sql_named_checkers_keep_the_digests_their_receipts_carry() -> None:
    """Computed on interlock 1.5.2, before the checkers shared a base: a receipt issued then
    still shows the configuration a 1.6.0 verifier computes."""
    checkers: list[InvariantChecker] = [
        BlastRadius(8),
        TenantIsolation(1),
        TenantIsolation(1, dimension="patient"),
        TableAllowlist(["a", "b"]),
        ColumnValueGuard("o", "t", max_drop_fraction="0.3"),
    ]
    found = {r.name: r.config_hash[:12] for c in checkers for r in checker_records([c])}
    assert found == DIGESTS_1_5_2


def test_each_neutral_checker_records_its_own_name_and_configuration() -> None:
    pairs: list[tuple[InvariantChecker, InvariantChecker, str]] = [
        (ChangeLimit(8), BlastRadius(8), "change_limit"),
        (KindAllowlist(["a", "b"]), TableAllowlist(["a", "b"]), "kind_allowlist"),
        (PartitionIsolation(), TenantIsolation(1), "partition_isolation:tenant"),
        (
            PartitionIsolation("patient", max=2, declared=True),
            TenantIsolation(2, declared=True, dimension="patient"),
            "partition_isolation:patient",
        ),
        (
            ValueGuard("orders", "total", max_drop_fraction="0.3"),
            ColumnValueGuard("orders", "total", max_drop_fraction="0.3"),
            "value_guard:orders.total",
        ),
    ]
    for neutral, sql, name in pairs:
        assert neutral.name == name
        assert type(neutral) in BUILT_IN_CHECKERS and type(sql) in BUILT_IN_CHECKERS
        (ours,), (theirs,) = checker_records([neutral]), checker_records([sql])
        assert ours.config_hash != theirs.config_hash
        assert checker_family(neutral.name) == checker_family(sql.name)
    # a different configuration is a different digest, under the neutral name too
    (eight,), (nine,) = checker_records([ChangeLimit(8)]), checker_records([ChangeLimit(9)])
    assert eight.name == nine.name and eight.config_hash != nine.config_hash


def test_checker_family_reads_both_vocabularies() -> None:
    assert set(CHECKER_ALIASES.values()) == {
        "change_limit",
        "kind_allowlist",
        "partition_isolation",
        "value_guard",
    }
    assert checker_family("blast_radius") == checker_family("change_limit") == "change_limit"
    assert checker_family("column_value_guard:orders.total") == "value_guard"
    assert checker_family("tenant_isolation") == "partition_isolation"
    assert checker_family("partition_isolation:patient") == "partition_isolation"
    assert checker_family("no_delete") == "no_delete"
    assert checker_family("rate_window:refunds") == "rate_window"


def plan() -> EffectPlan:
    builder = PlanBuilder("agent", intent="tidy up")
    builder.add(EffectKind.DELETE, table="scripts", statement="x", tenant_id="acme")
    return builder.build()


def test_a_neutral_checker_judges_as_its_sql_twin_does() -> None:
    measured, built = diff(), plan()
    twins: tuple[tuple[InvariantChecker, InvariantChecker], ...] = (
        (ChangeLimit(2), BlastRadius(2)),
        (KindAllowlist(["config"]), TableAllowlist(["config"])),
        (PartitionIsolation(max=1), TenantIsolation(1)),
        (PartitionIsolation(max=2, declared=True), TenantIsolation(2, declared=True)),
        (
            ValueGuard("config", "bytes", max_drop_fraction="0.5"),
            ColumnValueGuard("config", "bytes", max_drop_fraction="0.5"),
        ),
    )
    for neutral, sql in twins:
        ours, theirs = neutral.check(built, measured), sql.check(built, measured)
        assert len(ours) == len(theirs) == 1
        assert ours[0].message.split(" (")[0] == theirs[0].message.split(" (")[0]
        assert ours[0].invariant == neutral.name and theirs[0].invariant == sql.name
    assert ChangeLimit(3).check(built, measured) == ()
    assert KindAllowlist(["config", "scripts"]).check(built, measured) == ()
    assert PartitionIsolation(max=2).check(built, measured) == ()


def test_the_neutral_evidence_carries_no_sql_names() -> None:
    measured, built = diff(), plan()
    (limit,) = ChangeLimit(2).check(built, measured)
    assert dict(limit.evidence) == {"measured": "3", "limit": "2", "kinds": "config,scripts"}
    (legacy,) = BlastRadius(2).check(built, measured)
    assert dict(legacy.evidence) == {
        "measured_rows": "3",
        "limit": "2",
        "tables": "config,scripts",
    }
    (span,) = PartitionIsolation(max=1).check(built, measured)
    assert dict(span.evidence) == {"dimension": "tenant", "labels": "acme,globex"}
    (theirs,) = TenantIsolation(1).check(built, measured)
    assert dict(theirs.evidence) == {"tenants": "acme,globex"}


def test_a_directorys_agent_is_told_the_neutral_names(tmp_path: Path) -> None:
    """End to end: the verdict, the agent's feedback and the receipt-side names all say
    ``kind_allowlist`` and ``change_limit`` when the engine was built with them. Through
    1.5.2 the only names were ``table_allowlist`` and ``blast_radius``, on every system."""
    workspace = tmp_path / "svc"
    (workspace / "scripts").mkdir(parents=True)
    (workspace / "config").mkdir()
    for name in ("a.sh", "b.sh", "c.sh"):
        (workspace / "scripts" / name).write_text("#!/bin/sh\n")
    (workspace / "config" / "service.toml").write_text("timeout_ms = 2500\n")
    run = EscrowEngine(
        FilesystemSubstrate(workspace),
        checkers=[KindAllowlist(["config"]), NoDelete(), ChangeLimit(1)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )
    builder = PlanBuilder("ops-agent", intent="tidy up")
    builder.delete(table="scripts", statement="delete 'scripts/a.sh'")
    builder.delete(table="scripts", statement="delete 'scripts/b.sh'")
    refused = run.execute(builder.build())
    assert not refused.committed and (workspace / "scripts" / "a.sh").exists()
    assert refused.blocked_by == ("kind_allowlist", "no_delete", "change_limit")
    assert refused.feedback is not None
    told = refused.feedback.render()
    assert "kind_allowlist: the plan changed files in the scripts path class" in told
    assert "change_limit: the plan changes 2-9 files" in told
    assert "table_allowlist" not in told and "blast_radius" not in told
    constraints = {c["constraint"] for c in refused.feedback.to_json()["constraints"]}
    assert constraints == {"kind_allowlist", "no_delete", "change_limit"}


def test_a_label_is_kept_only_for_its_own_kind_of_guidance() -> None:
    """A checker's label names the constraint only where it is one of the label's own kinds:
    a custom checker cannot rename a refusal, and a built-in one cannot mislabel another's."""
    from interlock.feedback import FeedbackHint, Guidance, HintedViolation, agent_feedback
    from interlock.types import InvariantViolation, Severity

    broken = InvariantViolation(invariant="x", severity=Severity.BLOCKING, message="m")
    hint = FeedbackHint(kind=Guidance.NO_DELETE, tables=("scripts",))
    for trusted, label in ((True, "change_limit"), (False, "kind_allowlist"), (True, "payroll")):
        told = agent_feedback(
            plan(), [HintedViolation(broken, hint, trusted, label)], committed=False
        )
        assert [c.constraint for c in told.constraints] == ["no_delete"]
    limit = FeedbackHint(kind=Guidance.ROW_LIMIT, measured=12, limit=5)
    (kept,) = agent_feedback(
        plan(), [HintedViolation(broken, limit, True, "change_limit")], committed=False
    ).constraints
    assert kept.constraint == "change_limit"
    (dropped,) = agent_feedback(
        plan(), [HintedViolation(broken, limit, False, "change_limit")], committed=False
    ).constraints
    assert dropped.constraint == "blast_radius"


# --------------------------------------------------------------------------
# state =
# --------------------------------------------------------------------------


def config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    (tmp_path / "ws").mkdir(exist_ok=True)
    return path


FILES = 'substrate = "filesystem"\n[filesystem]\nroot = "ws"\n'


def test_a_directory_needs_no_database_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through 1.5.2 this file was refused: "no database: set 'database'"."""
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    loaded = load_config(config(tmp_path, FILES))
    hidden = (tmp_path / ".interlock").resolve()
    assert loaded.state == str(hidden)
    assert loaded.database == str(hidden / "control.db")
    assert loaded.controlled


def test_state_names_the_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    loaded = load_config(config(tmp_path, 'state = "var/interlock"\n' + FILES))
    assert loaded.state == str((tmp_path / "var" / "interlock").resolve())
    assert loaded.database == str((tmp_path / "var" / "interlock" / "control.db").resolve())


def test_database_still_names_the_control_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    loaded = load_config(config(tmp_path, 'database = "control.db"\n' + FILES))
    assert (loaded.database, loaded.state) == ("control.db", "")
    # and the command line, or the environment, still override the file's state
    over = load_config(config(tmp_path, 'state = "s"\n' + FILES), database="elsewhere.db")
    assert (over.database, over.state) == ("elsewhere.db", "")


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ('state = "s"\ndatabase = "control.db"\n' + FILES, "give one"),
        ('state = ""\n' + FILES, "cannot be empty"),
        (
            'state = "s"\ndatabase = "app.db"\n[[tables]]\nname = "orders"\ncolumns = ["id"]\n',
            "give one",
        ),
        (
            'state = "s"\n[[tables]]\nname = "orders"\ncolumns = ["id"]\n',
            "keeps Interlock's records in the database it stages",
        ),
    ],
)
def test_state_is_refused_where_it_cannot_mean_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, said: str
) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    with pytest.raises(ConfigError, match=said):
        load_config(config(tmp_path, text))


def test_a_sql_database_is_still_named_outright(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    with pytest.raises(ConfigError, match="no database"):
        load_config(config(tmp_path, '[[tables]]\nname = "orders"\ncolumns = ["id"]\n'))


def test_install_makes_the_state_directory_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("INTERLOCK_DATABASE", raising=False)
    path = config(tmp_path, FILES)
    (tmp_path / "ws" / "notes.md").write_text("hello\n")
    assert main(["install", "--config", str(path)]) == 0
    hidden = tmp_path / ".interlock"
    assert (hidden / "control.db").is_file()
    assert stat.S_IMODE(os.stat(hidden).st_mode) == 0o700
    assert f"state: {hidden.resolve()}" in capsys.readouterr().out
    # and a stage on it commits, with the control database it was given
    from interlock.wiring import open_substrate

    substrate = open_substrate(load_config(path))
    run = EscrowEngine(substrate, checkers=[KindAllowlist(["docs", "other"])])
    wrote = PlanBuilder("agent").add(
        EffectKind.APPLY,
        table="other",
        statement="write 'notes.md' :text",
        parameters={"text": "hello, twice\n"},
    )
    assert run.execute(wrote.build()).committed
    assert (tmp_path / "ws" / "notes.md").read_text() == "hello, twice\n"
