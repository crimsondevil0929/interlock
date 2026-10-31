"""``substrate = "kubernetes"`` and ``"terraform"``, and ``[sensors.<name>]``,
in ``interlock.toml`` (1.3.0)."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from interlock import CommandSensor, KubernetesSubstrate, TerraformSubstrate
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.wiring import open_kubernetes, open_sensors, open_substrate, open_terraform

KUBE = """
substrate = "kubernetes"
database = "control.db"

[kubernetes]
server = "http://127.0.0.1:6443"
token_file = "sa.token"
namespaces = ["prod-east"]
journal = "undo"
timeout_seconds = 5

[[kubernetes.kinds]]
table = "deployments"
plural = "deployments"
kind = "Deployment"
group = "apps"
columns = { replicas = "spec.replicas" }
partitions = { account = "metadata.labels.account" }

[[kubernetes.kinds]]
table = "statefulsets"
plural = "statefulsets"
kind = "StatefulSet"
group = "apps"
replace_on_immutable = true

[sensors.policy-check]
argv = ["python", "-m", "policy_check"]
timeout_seconds = 10
env = { POLICY = "strict" }
"""

TERRAFORM = """
substrate = "terraform"

[terraform]
directory = "infra"
executable = "tofu"
variables = ["nodes"]
workspace = "prod"

[[terraform.resources]]
table = "node_groups"
type = "aws_eks_node_group"
columns = { nodes = "desired_size" }
tenant = "tags.env"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    (tmp_path / "sa.token").write_text("t0k\n")
    (tmp_path / "infra").mkdir(exist_ok=True)
    return path


def test_a_kubernetes_substrate_is_configured(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, KUBE))
    assert config.plan_bound and config.controlled
    settings = config.kubernetes
    assert settings is not None and settings.token() == "t0k"
    assert [k.table for k in settings.kinds] == ["deployments", "statefulsets"]
    assert settings.kinds[1].replace_on_immutable
    assert settings.journal == tmp_path / "undo" and settings.timeout_seconds == 5
    assert [t.name for t in config.tables] == ["deployments", "statefulsets"]
    assert config.engine.max_stage_seconds == 120.0
    substrate = open_substrate(config)
    assert isinstance(substrate, KubernetesSubstrate)
    assert substrate.control == str(tmp_path / "control.db") or substrate.control is not None
    (sensor,) = open_sensors(config)
    assert isinstance(sensor, CommandSensor) and sensor.name == "policy-check"
    assert config.sensors[0].env == {"POLICY": "strict"}


def test_a_terraform_substrate_is_configured(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, TERRAFORM), require_database=False)
    assert config.plan_bound and not config.controlled
    tf = config.terraform
    assert tf is not None and tf.executable == ("tofu",) and tf.workspace == "prod"
    assert [t.name for t in config.tables] == ["node_groups", "resources"]
    assert config.engine.max_stage_seconds == 900.0
    assert isinstance(open_substrate(config), TerraformSubstrate)
    assert isinstance(open_terraform(config), TerraformSubstrate)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('substrate = "kubernetes"\ndatabase = "x.db"\n', r"needs a \[kubernetes\] section"),
        (
            'substrate = "sqlite"\ndatabase = "x.db"\n[kubernetes]\nserver = "x"\n',
            "configures a kubernetes",
        ),
        (KUBE.replace("journal = ", "jornal = "), "unknown key"),
        (
            KUBE.replace(
                '[[kubernetes.kinds]]\ntable = "statefulsets"',
                '[[kubernetes.kinds]]\ntable = "deployments"',
            ),
            "own table",
        ),
        (
            KUBE.replace("replace_on_immutable = true", 'replace_on_immutable = "yes"'),
            "true or false",
        ),
        (
            KUBE.replace('columns = { replicas = "spec.replicas" }', "columns = { replicas = 1 }"),
            "path, as text",
        ),
        (
            KUBE.replace(
                'columns = { replicas = "spec.replicas" }',
                'columns = { Replicas = "spec.replicas" }',
            ),
            "identifier",
        ),
        (KUBE.replace('group = "apps"\ncolumns', 'grup = "apps"\ncolumns'), "unknown key"),
        (KUBE.replace("timeout_seconds = 5", "timeout_seconds = 0"), "positive"),
        (KUBE + '\n[[tables]]\nname = "x"\ncolumns = ["id"]\n', "lists no"),
        (
            KUBE.replace('argv = ["python", "-m", "policy_check"]', "argv = []"),
            "argv is the command",
        ),
        (KUBE.replace("[sensors.policy-check]", "[sensors.Policy]"), "lowercase"),
        (KUBE.replace('env = { POLICY = "strict" }', "env = { POLICY = 1 }"), "env maps"),
        (KUBE.replace('env = { POLICY = "strict" }', 'envs = { POLICY = "x" }'), "unknown key"),
        ('substrate = "terraform"\n[terraform]\ndirectory = "infra"\n', "at least one"),
        (TERRAFORM.replace('executable = "tofu"', "executable = []"), "a command"),
        (TERRAFORM.replace('tenant = "tags.env"', 'tenent = "tags.env"'), "unknown key"),
        (TERRAFORM.replace('workspace = "prod"', 'workspace = "prod"\nextra = 1'), "unknown key"),
        (TERRAFORM.replace('table = "node_groups"', 'table = "resources"'), "own"),
    ],
)
def test_a_malformed_plan_bound_file_names_what_is_wrong(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, text), require_database=False)


def test_kubernetes_and_terraform_cannot_run_several_workers(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="one worker"):
        load_config(write(tmp_path, KUBE + "\n[engine]\nworkers = 2\n"))


def test_wiring_names_a_missing_section(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, TERRAFORM), require_database=False)
    with pytest.raises(Exception, match="no \\[kubernetes\\]"):
        open_kubernetes(config)
    kube = load_config(write(tmp_path, KUBE))
    with pytest.raises(Exception, match="no \\[terraform\\]"):
        open_terraform(kube)


def test_a_token_file_that_cannot_be_read(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, KUBE))
    (tmp_path / "sa.token").unlink()
    with pytest.raises(ConfigError, match="token_file"):
        open_kubernetes(config)


def test_the_command_line_installs_and_checks_a_plan_bound_substrate(tmp_path: Path) -> None:
    path = write(
        tmp_path, KUBE + '\n[[sinks]]\nname = "cloud"\noperations = [{ name = "sg.update" }]\n'
    )
    out = io.StringIO()
    assert main(["install", "--config", str(path)], out=out) == 0
    assert (
        "installed: the outbox" in out.getvalue() and "kind: apps/v1 StatefulSet" in out.getvalue()
    )
    assert "sensor: policy-check" in out.getvalue()
    out = io.StringIO()
    assert main(["check", "--config", str(path)], out=out) == 0
    assert "kubernetes (plan-bound)" in out.getvalue() and "namespaces: prod-east" in out.getvalue()
    err = io.StringIO()
    sys_stderr, sys.stderr = sys.stderr, err
    try:
        assert (
            main(
                ["reconcile-effects", "--config", str(path), "--chain", str(tmp_path / "c")],
                out=out,
            )
            == 2
        )
    finally:
        sys.stderr = sys_stderr
    assert "agentgov reconcile-actions" in err.getvalue() and "k8s-audit-jsonl" in err.getvalue()
    tf = write(tmp_path, TERRAFORM)
    out = io.StringIO()
    assert main(["check", "--config", str(tf)], out=out) == 0
    assert "configuration:" in out.getvalue() and "any other type" in out.getvalue()
    out = io.StringIO()
    assert main(["install", "--config", str(tf)], out=out) == 0


def test_the_terraform_stand_in_is_a_command(tmp_path: Path) -> None:
    (tmp_path / "model.json").write_text(json.dumps({"variables": {}, "resources": []}))
    done = subprocess.run(
        [sys.executable, "-m", "interlock.sim.terraform", "init"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0 and (tmp_path / "terraform.tfstate").exists()
