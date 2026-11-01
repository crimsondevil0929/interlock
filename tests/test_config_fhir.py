"""``substrate = "fhir"`` in ``interlock.toml`` (1.4.0): a FHIR R4 server,
staged predicted and verified."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from interlock import FhirSubstrate
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.wiring import open_fhir, open_substrate

FHIR = """
substrate = "fhir"
database = "control.db"

[fhir]
server = "http://127.0.0.1:8080/fhir"
token_file = "agent.token"
patients = ["ch-7f3a91"]
journal = "undo"
timeout_seconds = 5

[[fhir.types]]
table = "medicationrequests"
type = "MedicationRequest"
columns = { status = "status", dose_mg = "dosageInstruction.0.doseAndRate.0.doseQuantity.value" }
partitions = { facility = "dispenseRequest.performer.reference" }

[[fhir.types]]
table = "tasks"
type = "Task"
columns = { status = "status" }
tenant = "for.reference"
void_status = "cancelled"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    (tmp_path / "agent.token").write_text("token\n")
    return path


def test_a_fhir_substrate_is_configured(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, FHIR))
    settings = config.fhir
    assert settings is not None and config.predicted and not config.plan_bound
    assert config.controlled and config.engine.max_stage_seconds == 120.0
    assert [t.table for t in settings.types] == ["medicationrequests", "tasks"]
    assert (
        settings.types[1].tenant == "for.reference" and settings.types[1].void_status == "cancelled"
    )
    assert settings.journal == tmp_path / "undo" and settings.patients == ("ch-7f3a91",)
    assert settings.token() == "token" and settings.timeout_seconds == 5
    assert [t.name for t in config.tables] == ["medicationrequests", "tasks"]
    found = open_substrate(config)
    assert isinstance(found, FhirSubstrate) and found.control == "control.db"
    assert open_fhir(config, control=str(tmp_path / "other.db")).control == str(
        tmp_path / "other.db"
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('substrate = "fhir"\ndatabase = "x.db"\n', r"needs a \[fhir\] section"),
        (FHIR.replace("timeout_seconds = 5", "retries = 5"), "unknown key"),
        (FHIR.replace('void_status = "cancelled"', "colour = 1"), "unknown key"),
        (FHIR.replace('table = "tasks"', 'table = "medicationrequests"'), "its own table"),
        (FHIR.replace('type = "Task"', 'type = "MedicationRequest"'), "one table"),
        (FHIR.replace('type = "Task"', 'type = "task"'), "not a FHIR resource type"),
        (FHIR.split("[[fhir.types]]")[0], "at least one"),
        (FHIR.replace("[fhir]", '[[tables]]\nname = "x"\ncolumns = ["id"]\n[fhir]'), "lists no"),
    ],
)
def test_a_malformed_fhir_file_names_what_is_wrong(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, text))


def test_a_fhir_types_entry_is_a_table(tmp_path: Path) -> None:
    text = 'substrate = "fhir"\ndatabase = "c.db"\n[fhir]\nserver = "x"\ntypes = [1]\n'
    with pytest.raises(ConfigError, match="a table"):
        load_config(write(tmp_path, text))


def test_a_fhir_substrate_runs_one_worker(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="one worker"):
        load_config(write(tmp_path, FHIR + "\n[engine]\nworkers = 2\n"))


def test_wiring_names_a_missing_fhir_section(tmp_path: Path) -> None:
    config = load_config(
        write(tmp_path, 'database = "x.db"\n[[tables]]\nname = "t"\ncolumns = ["id"]\n')
    )
    with pytest.raises(Exception, match=r"no \[fhir\]"):
        open_fhir(config)
    fhir = load_config(write(tmp_path, FHIR))
    (tmp_path / "agent.token").unlink()
    with pytest.raises(ConfigError, match="token_file"):
        open_fhir(fhir)


def test_the_command_line_installs_and_checks_a_fhir_substrate(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        FHIR + '\n[[sinks]]\nname = "pharmacy"\noperations = [{ name = "dispense.create" }]\n',
    )
    out = io.StringIO()
    assert main(["install", "--config", str(path)], out=out) == 0
    said = out.getvalue()
    assert "installed: the outbox" in said and "type: Task as table tasks" in said
    out = io.StringIO()
    assert main(["check", "--config", str(path)], out=out) == 0
    said = out.getvalue()
    assert "fhir (predicted)" in said and "patients: ch-7f3a91" in said
    assert "FHIR server: http://127.0.0.1:8080/fhir" in said
    err = io.StringIO()
    sys_stderr, sys.stderr = sys.stderr, err
    try:
        command = ["reconcile-effects", "--config", str(path), "--chain", str(tmp_path / "c")]
        assert main(command, out=out) == 2
    finally:
        sys.stderr = sys_stderr
    assert "fhir-auditevent" in err.getvalue()
