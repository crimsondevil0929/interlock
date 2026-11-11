"""``substrate = "filesystem"`` and ``substrate = "rest"`` in ``interlock.toml`` (1.5.0): the
sections are read and checked, ``interlock install`` and ``interlock check`` describe them, and
``EscrowRuntime.from_config`` stages on them."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlock import BlastRadius, PlanBuilder, TableAllowlist
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.filesystem import DEFAULT_CLASSES, FilesystemSubstrate, filesystem_tables
from interlock.rest import RestSubstrate
from interlock.runtime import EscrowRuntime
from interlock.sim.rest import Collection, LoopbackRestServer
from interlock.types import Compensation, EffectKind
from interlock.wiring import open_rest


def workspace_config(tmp_path: Path, extra: str = "") -> Path:
    root = tmp_path / "service"
    (root / "config").mkdir(parents=True)
    (root / "config/app.toml").write_text("timeout_ms = 2500\n")
    (root / ".env").write_text("TOKEN=placeholder\n")
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "filesystem"\n'
        'database = "control.db"\n\n'
        "[filesystem]\n"
        'root = "service"\n'
        'workspace = "payments"\n'
        'owners = [{ glob = "src/**", owner = "app-team" }]\n'
        'ignore = ["node_modules/**"]\n'
        '\n[[filesystem.hooks]]\nname = "noop"\nargv = ["true"]\n' + extra
    )
    return path


def test_a_workspace_is_configured_in_interlock_toml(tmp_path: Path) -> None:
    config = load_config(workspace_config(tmp_path))
    assert config.substrate == "filesystem" and config.filesystem is not None
    assert config.filesystem.root == tmp_path / "service"
    assert config.filesystem.owners == (("src/**", "app-team"),)
    assert config.filesystem.ignore == ("node_modules/**",)
    assert [h.name for h in config.filesystem.hooks] == ["noop"]
    assert [t.name for t in config.tables] == [t.name for t in filesystem_tables(DEFAULT_CLASSES)]
    assert config.controlled and not config.predicted
    assert config.engine.max_stage_seconds == 120.0


def test_the_command_line_installs_checks_and_stages_on_a_workspace(tmp_path: Path) -> None:
    path = workspace_config(tmp_path)
    out = io.StringIO()
    assert main(["install", "--config", str(path)], out=out) == 0
    assert "in the control database" in out.getvalue()
    assert "workspace: " in out.getvalue() and "(in-place)" in out.getvalue()
    out = io.StringIO()
    assert main(["check", "--config", str(path)], out=out) == 0
    text = out.getvalue()
    assert text.startswith("ok: filesystem, 11 path classes")
    assert "files: 2" in text and "ignored: node_modules/**" in text and "hook: noop" in text
    runtime = EscrowRuntime.from_config(
        load_config(path),
        scope_id="agent",
        checkers=[BlastRadius(5), TableAllowlist(["config"])],
        chain_path=tmp_path / "plans.chain",
    )
    try:
        assert isinstance(runtime.engine._substrate, FilesystemSubstrate)
        edit = PlanBuilder("agent").update(
            table="config", statement="replace 'config/app.toml' '2500' '4000'", stated_rows=1
        )
        assert runtime.execute(edit.build()).committed
        secret = PlanBuilder("agent").update(table="secrets", statement="write '.env' 'TOKEN=x'")
        assert not runtime.execute(secret.build()).committed
    finally:
        runtime.close()
    assert (tmp_path / "service/config/app.toml").read_text() == "timeout_ms = 4000\n"
    assert (tmp_path / "service/.env").read_text() == "TOKEN=placeholder\n"


FS = 'substrate = "filesystem"\ndatabase = "c.db"\n[filesystem]\nroot = "r"\n'


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ('substrate = "filesystem"\ndatabase = "c.db"\n', "needs a \\[filesystem\\] section"),
        (
            FS + "x = 1\n",
            "unknown key x",
        ),
        (
            FS + 'mode = "copy"\n',
            "'in-place' or 'swap'",
        ),
        (
            'substrate = "filesystem"\ndatabase = "c.db"\n[filesystem]\nroot = "r"\nmode = "swap"\n'
            'ignore = ["x/**"]\n',
            "ignores none",
        ),
        (
            FS + "max_files = 0\n",
            "positive",
        ),
        (
            'substrate = "filesystem"\ndatabase = "c.db"\n[filesystem]\nroot = "r"\n'
            '[[filesystem.classes]]\nname = "other"\npatterns = ["x"]\n',
            "none is 'other'",
        ),
        (
            FS + "[engine]\nworkers = 2\n",
            "one worker",
        ),
    ],
)
def test_a_workspace_configuration_is_checked(tmp_path: Path, text: str, why: str) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=why):
        load_config(path)


# -- REST -------------------------------------------------------------------------------


@pytest.fixture
def desk() -> Iterator[LoopbackRestServer]:
    server = LoopbackRestServer(
        (Collection("tickets", filters=("account_id",)),), tokens={"t0ken": "agent"}
    )
    server.start()
    server.seed("tickets", {"id": "tkt-1", "account_id": "acme", "status": "open"})
    yield server
    server.stop()


def rest_config(tmp_path: Path, server: LoopbackRestServer, extra: str = "") -> Path:
    (tmp_path / "agent.token").write_text("t0ken\n")
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "rest"\n'
        'database = "control.db"\n\n'
        "[rest]\n"
        f'server = "{server.url}"\n'
        'token_file = "agent.token"\n'
        'tenants = ["acme"]\n'
        'journal = "journal"\n\n'
        "[[rest.resources]]\n"
        'table = "tickets"\n'
        'path = "/tickets"\n'
        'columns = { status = "status" }\n'
        'tenant = "account_id"\n'
        'managed = ["updated_at", "updated_by", "version"]\n'
        'source = "last_request"\n'
        'void = { status = "deleted" }\n' + extra
    )
    return path


def test_an_api_is_configured_in_interlock_toml(tmp_path: Path, desk: LoopbackRestServer) -> None:
    config = load_config(rest_config(tmp_path, desk))
    assert config.substrate == "rest" and config.rest is not None
    [resource] = config.rest.resources
    assert (resource.table, resource.path, resource.tenant) == (
        "tickets",
        "/tickets",
        "acme"[:0] + "account_id",
    )
    assert resource.void == {"status": "deleted"} and resource.source == "last_request"
    assert config.rest.token() == "t0ken" and config.rest.tenants == ("acme",)
    assert config.predicted and config.controlled
    assert [t.name for t in config.tables] == ["tickets"]


def test_the_command_line_installs_checks_and_stages_on_an_api(
    tmp_path: Path, desk: LoopbackRestServer
) -> None:
    path = rest_config(tmp_path, desk)
    out = io.StringIO()
    assert main(["install", "--config", str(path)], out=out) == 0
    assert f"API: {desk.url}" in out.getvalue()
    out = io.StringIO()
    assert main(["check", "--config", str(path)], out=out) == 0
    assert out.getvalue().startswith("ok: rest (predicted), 1 observed table")
    assert "resource: /tickets as table tickets, tenant account_id" in out.getvalue()
    runtime = EscrowRuntime.from_config(
        load_config(path), scope_id="agent", checkers=[BlastRadius(5)], chain_path=tmp_path / "c"
    )
    try:
        assert isinstance(runtime.engine._substrate, RestSubstrate)
        plan = PlanBuilder("agent").add(
            EffectKind.UPDATE,
            table="rest:tickets",
            statement="patch tickets :id '" + json.dumps({"status": "solved"}) + "'",
            parameters={"id": "tkt-1"},
            tenant_id="acme",
            compensation=Compensation("restore tickets"),
        )
        assert runtime.execute(plan.build()).committed
    finally:
        runtime.close()
    ticket = desk.get("tickets", "tkt-1")
    assert ticket is not None and ticket["status"] == "solved" and ticket["updated_by"] == "agent"


@pytest.mark.parametrize(
    ("extra", "why"),
    [
        ("color = 1\n", "unknown key color"),
        ('void = "erase"\n', 'a table \\(a merge patch\\) or \\"delete\\"'),
        ('write = "post"\n', "'patch' or 'put'"),
    ],
)
def test_an_api_configuration_is_checked(
    tmp_path: Path, desk: LoopbackRestServer, extra: str, why: str
) -> None:
    path = rest_config(tmp_path, desk)
    text = path.read_text()
    if extra.startswith("void"):
        text = text.replace('void = { status = "deleted" }\n', extra)
    else:
        text += extra
    path.write_text(text)
    with pytest.raises(ConfigError, match=why):
        load_config(path)


def test_an_apis_answer_and_listing_bounds_are_settings(
    tmp_path: Path, desk: LoopbackRestServer
) -> None:
    """``[rest] max_response_bytes`` and ``max_pages`` (1.5.2): 10 MiB and 1,000 pages unless
    the file says otherwise, and each a whole number of at least 1."""
    path = rest_config(tmp_path, desk)
    config = load_config(path)
    assert config.rest is not None
    assert (config.rest.max_response_bytes, config.rest.max_pages) == (10 * 1024 * 1024, 1000)
    text = path.read_text()
    limits = 'journal = "journal"\nmax_response_bytes = 65536\nmax_pages = 40\n'
    path.write_text(text.replace('journal = "journal"\n', limits))
    config = load_config(path)
    assert config.rest is not None
    sub = open_rest(config)
    assert (sub.max_response_bytes, sub.max_pages) == (65536, 40)
    for bad in ("max_pages = 0", "max_response_bytes = 1.5", "max_pages = true"):
        path.write_text(text.replace('journal = "journal"\n', f'journal = "journal"\n{bad}\n'))
        with pytest.raises(ConfigError, match="is a whole number, at least 1"):
            load_config(path)


def test_a_rest_section_needs_its_resources(tmp_path: Path) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "rest"\ndatabase = "c.db"\n[rest]\nserver = "http://127.0.0.1:1/api"\n'
    )
    with pytest.raises(ConfigError, match="at least one"):
        load_config(path)
