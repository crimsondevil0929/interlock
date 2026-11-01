"""The Terraform substrate (1.3.0): plan-bound staging over a saved plan, with
the stand-in CLI (:mod:`interlock.sim.terraform`) in the real formats."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    BlastRadius,
    CompensatedError,
    EscrowChain,
    EscrowEngine,
    NoDelete,
    PlanBuilder,
    TerraformSubstrate,
    TfResource,
    TruncationGuard,
)
from interlock.chain import RecordType
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.sim import terraform as sim
from interlock.terraform import FALLBACK_TABLE, terraform_tables
from interlock.types import EffectDiff, EffectKind, Verdict

TF = (sys.executable, "-m", "interlock.sim.terraform")

MODEL = {
    "variables": {
        "instance_type": {"default": "r7i.2xlarge"},
        "nodes": {"default": 3},
        "interlock_stage_id": {"default": ""},
        "cache": {"default": False},
    },
    "resources": [
        {
            "address": "aws_eks_node_group.data",
            "type": "aws_eks_node_group",
            "attributes": {
                "instance_types": ["${var.instance_type}"],
                "desired_size": "${var.nodes}",
                "tags": {"env": "prod-east"},
                "name": "data-${var.instance_type}",
            },
            "force_new": [],
            "computed": ["arn"],
        },
        {
            "address": "aws_db_instance.orders",
            "type": "aws_db_instance",
            "attributes": {
                "instance_class": "db.${var.instance_type}",
                "allocated_storage": 500,
                "tags": {"env": "prod-east"},
            },
            "force_new": ["instance_class"],
            "computed": ["endpoint"],
        },
    ],
    "outputs": {"interlock_stage_id": "${var.interlock_stage_id}"},
}

RESOURCES = (
    TfResource(
        "node_groups",
        "aws_eks_node_group",
        {"instance_types": "instance_types", "nodes": "desired_size", "arn": "arn"},
        tenant="tags.env",
        partitions={"group": "name"},
    ),
    TfResource(
        "db_instances",
        "aws_db_instance",
        {"instance_class": "instance_class", "endpoint": "endpoint"},
        tenant="tags.env",
    ),
)


def measured(result: Any) -> EffectDiff:
    """A result's diff, which every staged plan has."""
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def judged(result: Any) -> Verdict:
    """A result's verdict, which every staged plan has."""
    assert result.verdict is not None
    found: Verdict = result.verdict
    return found


def image(row: Any) -> dict[str, Any]:
    """A row image, present."""
    assert row is not None
    return dict(row)


def tf(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*TF, *args], cwd=directory, capture_output=True, text=True, check=False)


@pytest.fixture
def infra(tmp_path: Path) -> Path:
    directory = tmp_path / "infra"
    directory.mkdir()
    (directory / "model.json").write_text(json.dumps(MODEL))
    assert tf(directory, "init").returncode == 0
    assert tf(directory, "apply", "-auto-approve").returncode == 0
    return directory


class _Tf(TerraformSubstrate):
    """The substrate, its methods replaceable for a test."""


def substrate(infra: Path, **kwargs: Any) -> TerraformSubstrate:
    return _Tf(
        infra,
        resources=RESOURCES,
        journal=infra.parent / "journal",
        executable=TF,
        variables=("instance_type", "nodes"),
        **kwargs,
    )


def plan(*sets: tuple[str, Any]) -> Any:
    builder = PlanBuilder("sre-remediator", intent="resize")
    for name, value in sets:
        builder.add(
            EffectKind.APPLY,
            table="terraform:node_groups",
            statement="set :name :value",
            parameters={"name": name, "value": value},
            tenant_id="prod-east",
        )
    return builder.build()


def engine(sub: TerraformSubstrate, tmp_path: Path, *checkers: Any) -> EscrowEngine:
    return EscrowEngine(
        sub,
        checkers=list(checkers) or [BlastRadius(10)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )


def state(infra: Path) -> dict[str, Any]:
    found: dict[str, Any] = json.loads((infra / "terraform.tfstate").read_text())
    return found


def test_a_change_commits_on_the_state_measured(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    before = state(infra)["serial"]
    result = engine(sub, tmp_path).execute(plan(("nodes", 4)))
    assert result.committed
    (delta,) = measured(result).deltas
    assert (delta.table, delta.primary_key, delta.tenant_id) == (
        "node_groups",
        "aws_eks_node_group.data",
        "prod-east",
    )
    assert (image(delta.before)["nodes"], image(delta.after)["nodes"]) == (3, 4)
    assert delta.partitions == {"group": "data-r7i.2xlarge"}
    after = state(infra)
    assert after["serial"] == before + 1
    assert after["outputs"]["interlock_stage_id"]["value"] == str(measured(result).stage_id)
    assert json.loads((infra / "interlock.tfvars.json").read_text()) == {"nodes": 4}
    assert not list((infra.parent / "journal").glob("*.undo.json"))
    assert sub.capabilities.measurement == "plan-bound" and sub.capabilities.plan_bound


def test_a_forced_replacement_is_a_deletion(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    guard = TruncationGuard(acknowledged_unknown={"db_instances.endpoint"})
    result = engine(sub, tmp_path, guard, NoDelete(()), BlastRadius(10)).execute(
        plan(("instance_type", "r7i.4xlarge"))
    )
    assert [(d.table, d.operation) for d in measured(result).deltas] == [
        ("node_groups", "update"),
        ("db_instances", "delete"),
        ("db_instances", "insert"),
    ]
    assert [(u.table, u.column) for u in measured(result).unknowns] == [
        ("db_instances", "endpoint")
    ]
    assert [v.invariant for v in judged(result).blocking] == ["no_delete"]
    assert image(measured(result).deltas[2].after)["endpoint"] is None


def test_a_value_known_only_after_the_apply_is_refused(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    result = engine(sub, tmp_path, TruncationGuard(), NoDelete(("db_instances",))).execute(
        plan(("instance_type", "r7i.4xlarge"))
    )
    (refusal,) = judged(result).blocking
    assert refusal.invariant == "truncation_guard"
    assert "known only after the apply" in refusal.message
    assert refusal.evidence == {"unknown": "1", "first": "db_instances.endpoint"}


def test_a_state_that_moved_fails_closed(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    original = sub.commit

    def raced(handle: Any) -> Any:
        assert tf(infra, "apply", "-auto-approve", "-var=nodes=5").returncode == 0
        return original(handle)

    sub.commit = raced  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="state moved"):
        engine(sub, tmp_path).execute(plan(("nodes", 4)))
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.ABORTED


def test_terraform_itself_refuses_a_stale_plan(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    original = sub.state
    calls = {"n": 0}

    def stale() -> dict[str, Any]:
        calls["n"] += 1
        found = original()
        if calls["n"] == 2:  # the check before the apply sees the old state
            tf(infra, "apply", "-auto-approve", "-var=nodes=7")
            return found
        return found

    sub.state = stale  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="refused the saved plan"):
        engine(sub, tmp_path).execute(plan(("nodes", 4)))
    assert state(infra)["resources"][0]["instances"][0]["attributes"]["desired_size"] == "7"


def test_an_apply_that_changes_nothing_and_fails_is_a_conflict(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    original = sub._run

    def failing(*args: str, check: bool = True) -> Any:
        if args[0] == "apply":
            return subprocess.CompletedProcess(args, 1, b"", b"Error: provider crashed")
        return original(*args, check=check)

    sub._run = failing  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="applied nothing"):
        engine(sub, tmp_path).execute(plan(("nodes", 4)))


def test_a_partial_apply_is_put_back(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    (infra / "faults.json").write_text(json.dumps({"fail_apply": ["aws_db_instance.orders"]}))
    with pytest.raises(CompensatedError, match="stopped part way"):
        engine(sub, tmp_path, NoDelete(("db_instances",))).execute(
            plan(("instance_type", "r7i.4xlarge"))
        )
    found = {r["type"]: r["instances"][0]["attributes"] for r in state(infra)["resources"]}
    assert found["aws_eks_node_group"]["instance_types"] == ["r7i.2xlarge"]
    assert found["aws_db_instance"]["instance_class"] == "db.r7i.2xlarge"
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED


def test_an_undo_that_fails_leaves_the_intent_open(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    (infra / "faults.json").write_text(json.dumps({"fail_apply": ["aws_db_instance.orders"]}))
    sub._apply_inputs = lambda root, inputs: False  # type: ignore[method-assign]
    run = engine(sub, tmp_path, NoDelete(("db_instances",)))
    with pytest.raises(CommitUnsettledError, match="undo journal stays"):
        run.execute(plan(("instance_type", "r7i.4xlarge")))
    run.chain.close()
    (record,) = engine(substrate(infra), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED


def _crashed(infra: Path, tmp_path: Path, *, applied: bool) -> uuid.UUID:
    sub = substrate(infra)
    run = engine(sub, tmp_path, NoDelete(("db_instances",)))
    original = sub._run

    def run_once(*args: str, check: bool = True) -> Any:
        if args[0] == "apply":
            if applied:
                original(*args, check=check)
            raise SystemExit("crash")
        return original(*args, check=check)

    sub._run = run_once  # type: ignore[method-assign]
    with pytest.raises(SystemExit):
        run.execute(plan(("nodes", 6)))
    (intent,) = run.chain.unresolved_intents()
    run.chain.close()
    assert intent.stage_id is not None
    return intent.stage_id


def test_recovery_reads_the_marker(infra: Path, tmp_path: Path) -> None:
    _crashed(infra, tmp_path, applied=True)
    (record,) = engine(substrate(infra), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED
    assert json.loads((infra / "interlock.tfvars.json").read_text()) == {"nodes": 6}


def test_recovery_reads_the_serial(infra: Path, tmp_path: Path) -> None:
    _crashed(infra, tmp_path, applied=False)
    (record,) = engine(substrate(infra), tmp_path).recover()
    assert record.record_type is RecordType.ABORTED


def test_recovery_puts_a_partial_apply_back(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    run = engine(sub, tmp_path, NoDelete(("db_instances",)))
    original = sub._run

    def partial(*args: str, check: bool = True) -> Any:
        if args[0] == "apply" and not any(a.startswith("-var-file=") for a in args):
            (infra / "faults.json").write_text(
                json.dumps({"fail_apply": ["aws_db_instance.orders"]})
            )
            original(*args, check=False)
            raise SystemExit("crash mid-apply")
        return original(*args, check=check)

    sub._run = partial  # type: ignore[method-assign]
    with pytest.raises(SystemExit):
        run.execute(plan(("instance_type", "r7i.4xlarge")))
    run.chain.close()
    (record,) = engine(substrate(infra), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED
    found = {r["type"]: r["instances"][0]["attributes"] for r in state(infra)["resources"]}
    assert found["aws_eks_node_group"]["instance_types"] == ["r7i.2xlarge"]


def test_recovery_without_its_undo_or_on_another_lineage(infra: Path, tmp_path: Path) -> None:
    sub = substrate(infra)
    assert sub.resolve_intent(uuid.uuid4()) is None
    stage = _crashed(infra, tmp_path, applied=False)
    current = state(infra)
    current["lineage"] = "another"
    (infra / "terraform.tfstate").write_text(json.dumps(current))
    assert substrate(infra).resolve_intent(stage) is None


def test_vetting_reads_the_statement(infra: Path) -> None:
    sub = substrate(infra)

    def reason(statement: str, parameters: dict[str, Any]) -> str | None:
        builder = PlanBuilder("s").add(
            EffectKind.APPLY,
            table="terraform:node_groups",
            statement=statement,
            parameters=parameters,
        )
        return sub.reject_reason(builder.build().effects[0])

    assert reason("set :n :v", {"n": "nodes", "v": 4}) is None
    assert reason("set 'nodes' :v", {"v": 4}) is None
    assert reason("expect-serial :s", {"s": 3}) is None
    assert reason("expect-serial '3'", {}) is None
    assert "not one a plan" in str(reason("set :n :v", {"n": "region", "v": "x"}))
    assert "stage's own" in str(reason("set :n :v", {"n": "interlock_stage_id", "v": "x"}))
    assert "input variable" in str(reason("set :n :v", {"n": "1x", "v": "x"}))
    assert "whole number" in str(reason("expect-serial :s", {"s": "three"}))
    assert "not a statement" in str(reason("drop :n", {"n": 1}))
    assert "not a statement" in str(reason("set :n", {"n": 1}))
    assert "not a statement" in str(reason("set :n :v", {"n": "nodes"}))
    enqueue = PlanBuilder("s").enqueue(sink="a", operation="b", payload={}).build().effects[0]
    assert "no control database" in str(sub.reject_reason(enqueue))
    handle = sub.open(plan(("nodes", 4)))
    with pytest.raises(OutboundRequestError):
        sub.apply(handle, enqueue)
    with pytest.raises(ForbiddenStatementError):
        sub.apply(handle, plan(("region", "x")).effects[0])
    sub.close(handle)


def test_expect_serial_pins_the_approved_state(infra: Path, tmp_path: Path) -> None:
    serial = state(infra)["serial"]
    builder = PlanBuilder("s").add(
        EffectKind.APPLY,
        table="terraform:node_groups",
        statement="expect-serial :s",
        parameters={"s": serial},
    )
    builder.add(
        EffectKind.APPLY,
        table="terraform:node_groups",
        statement="set 'nodes' :v",
        parameters={"v": 5},
    )
    assert engine(substrate(infra), tmp_path).execute(builder.build()).committed
    (tmp_path / "x").mkdir()
    builder = PlanBuilder("s").add(
        EffectKind.APPLY,
        table="terraform:node_groups",
        statement="expect-serial :s",
        parameters={"s": serial},
    )
    with pytest.raises(StageConflictError, match="approved on is gone"):
        engine(substrate(infra), tmp_path / "x").execute(builder.build())


def test_an_unobserved_type_is_measured_too(infra: Path, tmp_path: Path) -> None:
    model = json.loads((infra / "model.json").read_text())
    model["resources"].append(
        {"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket", "attributes": {"acl": "private"}}
    )
    (infra / "model.json").write_text(json.dumps(model))
    result = engine(substrate(infra), tmp_path, BlastRadius(10)).execute(plan(("nodes", 3)))
    assert [(d.table, d.operation, image(d.after)["type"]) for d in measured(result).deltas] == [
        (FALLBACK_TABLE, "insert", "aws_s3_bucket")
    ]
    assert measured(result).deltas[0].tenant_id == "default"


def test_savepoints_and_the_stages_own_rules(infra: Path) -> None:
    sub = substrate(infra)
    handle = sub.open(plan(("nodes", 4)))
    with pytest.raises(StageConflictError, match="already has stage"):
        sub.open(plan(("nodes", 4)))
    (first,) = plan(("nodes", 4)).effects
    (second,) = plan(("instance_type", "m7i.large")).effects
    sub.apply(handle, first)
    sub.savepoint(handle, "one")
    sub.apply(handle, second)
    sub.rollback_to(handle, "one")
    assert [d.table for d in sub.diff(handle).deltas] == ["node_groups"]
    sub.release_savepoint(handle, "one")
    with pytest.raises(StageError, match="no savepoint"):
        sub.rollback_to(handle, "one")
    with pytest.raises(ValueError, match="unsafe"):
        sub.savepoint(handle, "a b")
    with pytest.raises(StageError, match="undo written first"):
        sub.commit(handle)
    sub.rollback_to = sub.rollback_to  # type: ignore[method-assign]
    sub.apply(handle, second)
    sub.write_undo(handle)
    with pytest.raises(StageError, match="before it is measured"):
        sub.commit(handle)
    assert sub.transaction_id(handle) == f"terraform:{handle.stage_id}"
    sub.abort(handle)
    sub.close(handle)
    sub.close(handle)
    with pytest.raises(StageError, match="not open"):
        sub.apply(handle, first)


def test_the_substrate_is_checked(infra: Path, tmp_path: Path) -> None:
    with pytest.raises(SubstrateConfigurationError, match="not a directory"):
        TerraformSubstrate(tmp_path / "none", resources=RESOURCES, journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="named"):
        TerraformSubstrate(infra, resources=RESOURCES, journal=tmp_path, executable=())
    with pytest.raises(SubstrateConfigurationError, match="own table"):
        TerraformSubstrate(infra, resources=(RESOURCES[0], RESOURCES[0]), journal=tmp_path)
    twice = TfResource("other", RESOURCES[0].type)
    with pytest.raises(SubstrateConfigurationError, match="observed once"):
        TerraformSubstrate(infra, resources=(RESOURCES[0], twice), journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="stage's"):
        TerraformSubstrate(
            infra, resources=RESOURCES, journal=tmp_path, variables=("interlock_stage_id",)
        )
    with pytest.raises(ValueError, match="identifier"):
        TfResource("DB", "aws_db_instance")
    with pytest.raises(ValueError, match="own"):
        TfResource("db", "aws_db_instance", columns={"tenant": "x"})
    assert [t.name for t in terraform_tables(RESOURCES)] == [
        "node_groups",
        "db_instances",
        "resources",
    ]
    missing = TerraformSubstrate(
        infra, resources=RESOURCES, journal=tmp_path, executable=("no-such-terraform",)
    )
    with pytest.raises(SubstrateUnavailableError, match="cannot run"):
        missing.state()
    broken = TerraformSubstrate(
        infra,
        resources=RESOURCES,
        journal=tmp_path,
        executable=(sys.executable, "-c", "print('not json')"),
    )
    with pytest.raises(SubstrateUnavailableError, match="no JSON"):
        broken.state()
    (infra / "interlock.tfvars.json").write_text("not json")
    with pytest.raises(SubstrateUnavailableError, match="cannot read"):
        substrate(infra).open(plan(("nodes", 4)))


def test_the_stand_in_speaks_the_cli(infra: Path) -> None:
    assert tf(infra).returncode == 1
    assert tf(infra, "fly").returncode == 1
    assert tf(infra, "plan").returncode == 1
    assert tf(infra, "show", "plan").returncode == 1
    assert "Value for undeclared variable" in tf(infra, "plan", "-out=p", "-var=region=x").stderr
    assert tf(infra, "plan", "-out=p", "-var=nodes=9").returncode == 0
    shown = json.loads(tf(infra, "show", "-json", "p").stdout)
    assert shown["format_version"] == "1.2"
    (change,) = [c for c in shown["resource_changes"] if c["change"]["actions"] != ["no-op"]]
    assert change["address"] == "aws_eks_node_group.data"
    assert json.loads(tf(infra, "output", "-json").stdout)["interlock_stage_id"]["value"] == ""
    model = json.loads((infra / "model.json").read_text())
    model["resources"] = model["resources"][:1]
    (infra / "model.json").write_text(json.dumps(model))
    assert tf(infra, "apply", "-auto-approve").returncode == 0
    assert [r["type"] for r in state(infra)["resources"]] == ["aws_eks_node_group"]
    assert sim._render("a-${var.x}-b", {"x": 1}) == "a-1-b"


def test_the_stand_in_in_process(
    infra: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(infra)
    assert sim.main([]) == 1
    assert sim.main(["init"]) == 0
    assert sim.main(["plan", "-input=false"]) == 1
    with pytest.raises(SystemExit, match="undeclared"):
        sim.main(["plan", "-out=p", "-var=region=x"])
    (infra / "vars.json").write_text(json.dumps({"instance_type": "m7i.large"}))
    assert sim.main(["plan", "-out=p", "-var-file=vars.json", "-var=nodes=5"]) == 0
    assert "to add" in capsys.readouterr().out
    assert sim.main(["show", "p"]) == 1
    assert sim.main(["show", "-json", "p"]) == 0
    shown = json.loads(capsys.readouterr().out)
    actions = {c["address"]: c["change"]["actions"] for c in shown["resource_changes"]}
    assert actions == {
        "aws_eks_node_group.data": ["update"],
        "aws_db_instance.orders": ["delete", "create"],
    }
    assert sim.main(["apply", "-auto-approve", "p"]) == 0
    capsys.readouterr()
    assert sim.main(["apply", "-auto-approve", "p"]) == 1
    assert "Saved plan is stale" in capsys.readouterr().err
    (infra / "faults.json").write_text(json.dumps({"fail_apply": ["aws_db_instance.orders"]}))
    assert sim.main(["apply", "-auto-approve", "-var=instance_type=c7i.large"]) == 1
    assert json.loads((infra / "faults.json").read_text()) == {"fail_apply": []}
    assert sim.main(["state", "pull"]) == 0
    pulled = json.loads(capsys.readouterr().out)
    assert pulled["serial"] >= 3
    assert sim.main(["output", "-json"]) == 0
    assert sim.main(["fly"]) == 1
    model = json.loads((infra / "model.json").read_text())
    model["resources"] = []
    (infra / "model.json").write_text(json.dumps(model))
    assert sim.main(["plan", "-out=q"]) == 0
    capsys.readouterr()
    assert sim.main(["show", "-json", "q"]) == 0
    gone = json.loads(capsys.readouterr().out)["resource_changes"]
    assert {c["change"]["actions"][0] for c in gone} == {"delete"}
    assert sim.main(["apply", "-auto-approve", "q"]) == 0
    assert json.loads((infra / "terraform.tfstate").read_text())["resources"] == []
