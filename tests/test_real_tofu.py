"""The Terraform substrate against the real OpenTofu CLI (``INTERLOCK_TEST_TOFU``).

The configuration uses only ``terraform_data``, built into the CLI, so no
provider is downloaded and nothing leaves the machine. Its plans are real:
``plan -out``, ``show -json``, values known only after the apply, replacements
that ``triggers_replace`` forces, the state's serial and lineage, a saved plan
the CLI refuses once the state has moved, and an apply a resource
postcondition stops part way, after it has changed other resources.
"""

from __future__ import annotations

import json
import subprocess
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
from interlock.exceptions import StageConflictError
from interlock.types import EffectDiff, EffectKind

from .real_systems import need

CONFIG = """
variable "instance_type" {
  type    = string
  default = "small"
}
variable "nodes" {
  type    = number
  default = 3
}
variable "generation" {
  type    = number
  default = 1
}
variable "fail_apply" {
  type    = bool
  default = false
}
variable "interlock_stage_id" {
  type    = string
  default = ""
}

resource "terraform_data" "node_group" {
  input = { instance_type = var.instance_type, nodes = var.nodes, env = "prod-east" }
}

resource "terraform_data" "database" {
  input            = { instance_class = "db.${var.instance_type}", env = "prod-east" }
  triggers_replace = [var.instance_type]
}

resource "terraform_data" "canary" {
  input            = { generation = var.generation, env = "prod-east" }
  triggers_replace = [var.generation]
  lifecycle {
    postcondition {
      # Known only after the apply, so checked then: the apply has already
      # changed the other resources when it fails.
      condition     = !var.fail_apply || length(self.id) < 0
      error_message = "the canary failed after the apply"
    }
  }
}

output "interlock_stage_id" {
  value = var.interlock_stage_id
}
"""

RESOURCES = (
    TfResource(
        "data",
        "terraform_data",
        {
            "nodes": "input.nodes",
            "instance_type": "input.instance_type",
            "instance_class": "input.instance_class",
            "generation": "input.generation",
            "output": "output",
        },
        tenant="input.env",
    ),
)
VARIABLES = ("instance_type", "nodes", "generation", "fail_apply")


@pytest.fixture
def tofu() -> str:
    return need("INTERLOCK_TEST_TOFU")[0]


def run(tofu: str, directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the operator's own tofu binary
        [tofu, *args, "-input=false", "-no-color"],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def infra(tofu: str, tmp_path: Path) -> Path:
    directory = tmp_path / "infra"
    directory.mkdir()
    (directory / "main.tf").write_text(CONFIG)
    assert run(tofu, directory, "init").returncode == 0
    applied = run(tofu, directory, "apply", "-auto-approve")
    assert applied.returncode == 0, applied.stderr
    return directory


class _Tf(TerraformSubstrate):
    """The substrate, its methods replaceable for a test."""


def substrate(tofu: str, infra: Path) -> TerraformSubstrate:
    return _Tf(
        infra,
        resources=RESOURCES,
        journal=infra.parent / "journal",
        executable=(tofu,),
        variables=VARIABLES,
        timeout=120,
    )


def plan(*sets: tuple[str, Any]) -> Any:
    builder = PlanBuilder("sre-remediator", intent="resize")
    for name, value in sets:
        builder.add(
            EffectKind.APPLY,
            table="terraform:data",
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


def inputs(infra: Path) -> dict[str, Any]:
    return {
        r["name"]: r["instances"][0]["attributes"]["input"]["value"]
        for r in state(infra)["resources"]
    }


def diff(result: Any) -> EffectDiff:
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def test_a_change_commits_on_the_state_measured(tofu: str, infra: Path, tmp_path: Path) -> None:
    serial = state(infra)["serial"]
    result = engine(substrate(tofu, infra), tmp_path).execute(plan(("nodes", 4)))
    assert result.committed
    (delta,) = diff(result).deltas
    assert (delta.table, delta.primary_key, delta.operation, delta.tenant_id) == (
        "data",
        "terraform_data.node_group",
        "update",
        "prod-east",
    )
    assert delta.before is not None and delta.after is not None
    assert (delta.before["nodes"], delta.after["nodes"]) == (3, 4)
    # terraform_data's output is known only after the apply, on every change.
    assert [(u.table, u.column) for u in diff(result).unknowns] == [("data", "output")]
    after = state(infra)
    assert after["serial"] == serial + 1
    assert after["outputs"]["interlock_stage_id"]["value"] == str(diff(result).stage_id)
    assert inputs(infra)["node_group"]["nodes"] == 4


def test_a_forced_replacement_is_a_deletion_and_is_refused(
    tofu: str, infra: Path, tmp_path: Path
) -> None:
    result = engine(
        substrate(tofu, infra),
        tmp_path,
        TruncationGuard(acknowledged_unknown={"data.output"}),
        NoDelete(()),
    ).execute(plan(("instance_type", "large")))
    assert not result.committed
    assert sorted((d.primary_key, d.operation) for d in diff(result).deltas) == [
        ("terraform_data.database", "delete"),
        ("terraform_data.database", "insert"),
        ("terraform_data.node_group", "update"),
    ]
    assert result.verdict is not None
    assert [v.invariant for v in result.verdict.blocking] == ["no_delete"]
    assert inputs(infra)["database"]["instance_class"] == "db.small"


def test_a_value_known_only_after_the_apply_is_refused(
    tofu: str, infra: Path, tmp_path: Path
) -> None:
    result = engine(substrate(tofu, infra), tmp_path, TruncationGuard()).execute(plan(("nodes", 4)))
    assert result.verdict is not None
    (refusal,) = result.verdict.blocking
    assert refusal.invariant == "truncation_guard"
    assert refusal.evidence == {"unknown": "1", "first": "data.output"}
    assert inputs(infra)["node_group"]["nodes"] == 3


def test_a_state_that_moved_fails_closed(tofu: str, infra: Path, tmp_path: Path) -> None:
    sub = substrate(tofu, infra)
    original = sub.commit

    def raced(handle: Any) -> Any:
        moved = run(tofu, infra, "apply", "-auto-approve", "-var=nodes=9")
        assert moved.returncode == 0, moved.stderr
        return original(handle)

    sub.commit = raced  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="state moved"):
        engine(sub, tmp_path).execute(plan(("nodes", 4)))
    assert inputs(infra)["node_group"]["nodes"] == 9
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.ABORTED


def test_the_cli_itself_refuses_a_stale_plan(tofu: str, infra: Path, tmp_path: Path) -> None:
    """The substrate's own check is skipped here, so the saved plan meets a
    moved state: OpenTofu refuses it, and nothing of the plan is applied."""
    sub = substrate(tofu, infra)
    original = sub.state
    calls = {"n": 0}

    def stale() -> dict[str, Any]:
        calls["n"] += 1
        found = original()
        if calls["n"] == 2:  # the check before the apply sees the old state
            moved = run(tofu, infra, "apply", "-auto-approve", "-var=nodes=7")
            assert moved.returncode == 0, moved.stderr
        return found

    sub.state = stale  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="refused the saved plan"):
        engine(sub, tmp_path).execute(plan(("nodes", 4)))
    assert inputs(infra)["node_group"]["nodes"] == 7


def test_a_partial_apply_is_put_back(tofu: str, infra: Path, tmp_path: Path) -> None:
    before = inputs(infra)
    with pytest.raises(CompensatedError, match="stopped part way"):
        engine(substrate(tofu, infra), tmp_path).execute(
            plan(("nodes", 5), ("generation", 2), ("fail_apply", True))
        )
    restored = inputs(infra)
    assert restored["node_group"] == before["node_group"]
    assert restored["canary"]["generation"] == 1
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED


def test_expect_serial_pins_the_approved_state(tofu: str, infra: Path, tmp_path: Path) -> None:
    serial = state(infra)["serial"]
    builder = PlanBuilder("sre-remediator", intent="resize")
    builder.add(
        EffectKind.APPLY,
        table="terraform:data",
        statement="expect-serial :serial",
        parameters={"serial": serial - 1},
        tenant_id="prod-east",
    )
    with pytest.raises(StageConflictError, match=r"not .* the serial the plan names"):
        engine(substrate(tofu, infra), tmp_path).execute(builder.build())


def test_recovery_reads_the_marker(tofu: str, infra: Path, tmp_path: Path) -> None:
    sub = substrate(tofu, infra)
    run_engine = engine(sub, tmp_path)
    original = sub._run

    def crash_after_apply(*args: str, check: bool = True) -> Any:
        if args[0] == "apply":
            original(*args, check=check)
            raise SystemExit("crash")
        return original(*args, check=check)

    sub._run = crash_after_apply  # type: ignore[method-assign]
    with pytest.raises(SystemExit):
        run_engine.execute(plan(("nodes", 6)))
    (intent,) = run_engine.chain.unresolved_intents()
    run_engine.chain.close()
    assert isinstance(intent.stage_id, uuid.UUID)
    (record,) = engine(substrate(tofu, infra), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED
    assert inputs(infra)["node_group"]["nodes"] == 6
