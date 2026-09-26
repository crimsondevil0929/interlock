"""The ``interlock`` command's configuration file, and the SQLite side of the CLI."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from interlock.cli import main
from interlock.config import DATABASE_ENV, ConfigError, load_config

GOOD = """
substrate = "postgres"
database = "postgresql://agent@db/app"
schema = "ops"
stage_roles = ["interlock_agent"]
acknowledge_cascades = ["shipment_events"]

[[tables]]
name = "orders"
columns = ["id", "tenant", "total"]
tenant_column = "tenant"

[[tables]]
name = "refunds"
primary_key = "refund_id"
columns = ["refund_id", "amount"]
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    return path


def test_a_complete_file_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DATABASE_ENV, raising=False)
    config = load_config(write(tmp_path, GOOD))
    assert config.substrate == "postgres"
    assert config.database == "postgresql://agent@db/app"
    assert config.schema == "ops"
    assert config.stage_roles == ("interlock_agent",)
    assert config.acknowledge_cascades == ("shipment_events",)
    orders, refunds = config.tables
    assert (orders.name, orders.primary_key, orders.tenant_column) == ("orders", "id", "tenant")
    assert (refunds.primary_key, refunds.tenant_column) == ("refund_id", None)
    assert config.with_database(None) is config
    assert config.with_database("other").database == "other"


def test_the_database_comes_from_the_flag_then_the_environment_then_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path, GOOD)
    monkeypatch.setenv(DATABASE_ENV, "from-env")
    assert load_config(path).database == "from-env"
    assert load_config(path, database="from-flag").database == "from-flag"


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("substrate = ", "not valid TOML"),
        ('substrate = "mysql"\n' + GOOD.split("\n", 2)[2], "'sqlite' or 'postgres'"),
        ('substrate = "sqlite"\n[[tables]]\nname = "t"\ncolumns = ["id"]\n', "no database"),
        ('database = "x.db"\n', "no \\[\\[tables\\]\\]"),
        ('database = "x.db"\ntables = [1]\n', "tables\\[0\\] is not a table"),
        ('database = "x.db"\n[[tables]]\ncolumns = ["id"]\n', "missing 'name'"),
        ('database = "x.db"\n[[tables]]\nname = "t"\n', "missing 'columns'"),
        ('database = "x.db"\n[[tables]]\nname = 3\ncolumns = ["id"]\n', "'name' must be a string"),
        ('database = "x.db"\n[[tables]]\nname = "t"\ncolumns = "id"\n', "list of strings"),
        ('database = "x.db"\n[[tables]]\nname = "t; drop"\ncolumns = ["id"]\n', "unsafe SQL"),
        (
            'database = "x.db"\n[[tables]]\nname = "t"\ncolumns = ["id"]\ntenant_column = "t"\n',
            "must also be listed",
        ),
    ],
)
def test_a_malformed_file_names_what_is_wrong(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, match: str
) -> None:
    monkeypatch.delenv(DATABASE_ENV, raising=False)
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, text))


def test_a_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "absent.toml")


def test_the_cli_on_sqlite(back_office: str, tmp_path: Path) -> None:
    config = write(
        tmp_path,
        f'substrate = "sqlite"\ndatabase = "{back_office}"\n'
        'acknowledge_cascades = ["refunds"]\n'
        '[[tables]]\nname = "order_items"\ncolumns = ["id", "order_id", "sku", "qty", "price"]\n',
    )
    out = io.StringIO()
    assert main(["install", "--config", str(config)], out=out) == 0
    assert out.getvalue().startswith("installed: journal triggers on 1 table(s): order_items")
    out = io.StringIO()
    assert main(["check", "--config", str(config)], out=out) == 0
    assert out.getvalue().splitlines() == [
        "ok: sqlite, 1 observed table(s)",
        "acknowledged: DELETE on order_items reaches refunds: "
        "order_items -[ON DELETE CASCADE]-> refunds",
        "cascade closure: open, 1 acknowledged gap(s)",
    ]
    missing = write(tmp_path, GOOD.replace('"postgres"', '"sqlite"'))
    assert main(["check", "--config", str(missing), "--database", str(tmp_path / "no.db")]) == 4
