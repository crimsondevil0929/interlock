"""The ``interlock`` command's configuration file, and the SQLite side of the CLI."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from interlock.cli import main
from interlock.config import DATABASE_ENV, ConfigError, MetricsConfig, load_config
from interlock.operators import generate_key

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


DAEMON = (
    GOOD
    + """
[engine]
workers = 4
database = "postgresql://interlock_agent@db/app"
chain = "escrow.chain"
settle_cost = "0.01"
ledger = "host=db dbname=app user=owner"
same_transaction = true
conflict_retries = 8
max_stage_seconds = 5
lock_timeout_seconds = 1.5
pool_timeout_seconds = 0.75

[receipts]
log = "receipts.jsonl"
key = "receipts.key"
log_id = "app-receipts"
policy_epoch = 3

[settler]
database = "postgresql://interlock_settle@db/app"
every_seconds = 2.5

[vacuum]
every_seconds = 600
database = "postgresql://owner@db/app"
key = "vacuum.key"

[daemon]
drain_timeout_seconds = 12
restart_min_seconds = 0.25
restart_max_seconds = 8

[metrics]
listen = "10.0.0.5:9464"
every_seconds = 5
database = "postgresql://interlock_audit@db/app"
"""
)


def test_the_daemons_sections_load(tmp_path: Path) -> None:
    from datetime import timedelta
    from decimal import Decimal

    config = load_config(write(tmp_path, DAEMON))
    engine = config.engine
    assert (engine.workers, engine.settle_cost, engine.conflict_retries) == (4, Decimal("0.01"), 8)
    assert engine.ledger == "host=db dbname=app user=owner" and engine.same_transaction
    assert (engine.max_stage_seconds, engine.lock_timeout_seconds) == (5.0, 1.5)
    assert engine.pool_timeout_seconds == 0.75
    assert engine.chain == tmp_path / "escrow.chain"
    assert engine.chain_for(0) == tmp_path / "escrow-0.chain"
    assert engine.chain_for(3) == tmp_path / "escrow-3.chain"
    assert engine.chain_for(0, 1) == tmp_path / "escrow.chain"
    receipts = config.receipts
    assert receipts is not None
    assert (receipts.log, receipts.key, receipts.log_id, receipts.policy_epoch) == (
        tmp_path / "receipts.jsonl",
        tmp_path / "receipts.key",
        "app-receipts",
        3,
    )
    assert config.settler.every == timedelta(seconds=2.5)
    assert config.vacuum.every == timedelta(minutes=10)
    assert config.vacuum.key == tmp_path / "vacuum.key"
    assert config.vacuum.database == "postgresql://owner@db/app"
    assert config.daemon.drain_timeout == timedelta(seconds=12)
    assert (config.daemon.restart_min, config.daemon.restart_max) == (
        timedelta(milliseconds=250),
        timedelta(seconds=8),
    )
    assert config.metrics == MetricsConfig(
        "10.0.0.5:9464", timedelta(seconds=5), "postgresql://interlock_audit@db/app"
    )
    # Absent, each section has its defaults; a SQLite ledger sits beside the file.
    bare = load_config(write(tmp_path, GOOD))
    assert (bare.engine.workers, bare.receipts, bare.vacuum.every) == (1, None, None)
    assert bare.metrics == MetricsConfig(None, timedelta(seconds=15), "")
    sqlite = load_config(
        write(
            tmp_path,
            GOOD.replace('substrate = "postgres"', 'substrate = "sqlite"').replace(
                'stage_roles = ["interlock_agent"]\n', ""
            )
            + '[engine]\nledger = "governor.db"\n',
        )
    )
    assert sqlite.engine.ledger == str(tmp_path / "governor.db")


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        (("workers = 4", "workers = 0"), "workers is at least 1"),
        (("conflict_retries = 8", "conflict_retries = -1"), "not negative"),
        (('settle_cost = "0.01"', 'settle_cost = "-1"'), "settle_cost is not negative"),
        (("same_transaction = true", 'same_transaction = "yes"'), "true or false"),
        (('ledger = "host=db dbname=app user=owner"', 'ledger = "governor.db"'), "same database"),
        (("workers = 4", "workers = 4\nthreads = 2"), r"\[engine\]: unknown key"),
        (('log_id = "app-receipts"', "log_id = 7"), "must be a string"),
        (("policy_epoch = 3", "policy_epoch = -1"), "policy_epoch is not negative"),
        (('log = "receipts.jsonl"\n', ""), "missing 'log'"),
        (("every_seconds = 2.5", "every_seconds = 0"), "positive number"),
        (("every_seconds = 600", "every_seconds = -1"), "not negative"),
        (("restart_max_seconds = 8", "restart_max_seconds = 0.1"), "at least restart_min"),
        (("drain_timeout_seconds = 12", "drain_after = 12"), r"\[daemon\]: unknown key"),
        (('listen = "10.0.0.5:9464"', 'listen = "9464"'), r"listen is HOST:PORT"),
        (('listen = "10.0.0.5:9464"', 'listen = "10.0.0.5:http"'), r"listen is HOST:PORT"),
        (('listen = "10.0.0.5:9464"', 'listen = "10.0.0.5:70000"'), r"listen is HOST:PORT"),
        (("every_seconds = 5", "every_seconds = 0"), "positive number"),
        (("every_seconds = 5", "every_seconds = 5\nport = 9464"), r"\[metrics\]: unknown key"),
        (('database = "postgresql://interlock_settle@db/app"', "interval = 2"), "unknown key"),
    ],
)
def test_a_misconfigured_daemon_is_refused(
    tmp_path: Path, replace: tuple[str, str], message: str
) -> None:
    assert replace[0] in DAEMON
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, DAEMON.replace(replace[0], replace[1], 1)))


def test_one_sqlite_worker(tmp_path: Path) -> None:
    text = GOOD.replace('substrate = "postgres"', 'substrate = "sqlite"').replace(
        'stage_roles = ["interlock_agent"]\n', ""
    )
    with pytest.raises(ConfigError, match="one worker"):
        load_config(write(tmp_path, text + "[engine]\nworkers = 2\n"))
    with pytest.raises(ConfigError, match="same database"):
        load_config(write(tmp_path, text + '[engine]\nsame_transaction = true\nledger = "g.db"\n'))


def test_an_operators_ledger_may_be_a_keyword_connection_string(tmp_path: Path) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "sqlite"\ndatabase = "app.db"\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id"]\n'
        '[operators]\nlog = "operators.ilok1"\nledger = "host=db dbname=app user=owner"\n'
        "[operators.keys]\n"
        f'ops = "{generate_key(tmp_path / "ops.key").public_key().spec()}"\n'
    )
    operators = load_config(path).operators
    assert operators is not None and operators.ledger == "host=db dbname=app user=owner"


SIGNERS = (
    GOOD
    + """
[signers.relay-kms]
type = "http"
url = "https://kms.internal:8443"
key = "interlock-relay"
token_env = "INTERLOCK_KMS_TOKEN"
timeout_seconds = 2.5
version = 3

[signers.ops]
type = "http"
url = "http://127.0.0.1:9000"
key = "operators"

[relay]
signer = "relay-kms"
breaker = "none"

[[relay.endpoints]]
sink = "mail"
url = "https://api.mail.example"
routes = { send = "POST /v3/mail/send" }

[[sinks]]
name = "mail"
cost_per_call = "0.002"

[[sinks.operations]]
name = "send"

[receipts]
log = "receipts.jsonl"
signer = "ops"

[vacuum]
signer = "ops"
"""
)


def test_keys_at_a_signing_service_load(tmp_path: Path) -> None:
    from interlock.config import SignerConfig

    config = load_config(write(tmp_path, SIGNERS))
    assert config.signers["relay-kms"] == SignerConfig(
        name="relay-kms",
        type="http",
        url="https://kms.internal:8443",
        key="interlock-relay",
        token_env="INTERLOCK_KMS_TOKEN",
        timeout=2.5,
        version=3,
    )
    assert config.signers["ops"].token_env is None and config.signers["ops"].version is None
    assert config.relay is not None and (config.relay.signer, config.relay.key) == (
        "relay-kms",
        None,
    )
    assert config.receipts is not None and (config.receipts.signer, config.receipts.key) == (
        "ops",
        None,
    )
    assert config.vacuum.signer == "ops"
    assert load_config(write(tmp_path, GOOD)).signers == {}


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        (('type = "http"\nurl = "https://kms', 'type = "aws"\nurl = "https://kms'), "'http'"),
        (("https://kms.internal:8443", "ftp://kms.internal"), r"http\(s\)"),
        (("version = 3", "version = 0"), "positive integer"),
        (("version = 3", "version = 3\nregion = 'eu'"), r"\[signers.relay-kms\]: unknown key"),
        (('signer = "relay-kms"', 'signer = "nobody"'), r"names no \[signers.nobody\]"),
        (('signer = "relay-kms"', 'signer = "relay-kms"\nkey = "relay.key"'), "not both"),
        (('log = "receipts.jsonl"\nsigner = "ops"', 'log = "receipts.jsonl"'), "missing 'key'"),
        (("[signers.ops]", "[signers.'no good']"), "letters, digits"),
    ],
)
def test_a_signer_misconfigured_is_refused(
    tmp_path: Path, replace: tuple[str, str], message: str
) -> None:
    assert replace[0] in SIGNERS
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, SIGNERS.replace(replace[0], replace[1], 1)))


def test_a_signer_opens_with_its_credential_from_the_environment_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from interlock.signers import HttpRemoteSigner, SignerUnavailableError
    from tests.fakekms import FakeKms

    with FakeKms(token="the-token") as kms:
        kms.create("interlock-relay")
        kms.rotate("interlock-relay")
        kms.rotate("interlock-relay")
        text = SIGNERS.replace("https://kms.internal:8443", kms.url)
        settings = load_config(write(tmp_path, text)).signers["relay-kms"]
        monkeypatch.delenv("INTERLOCK_KMS_TOKEN", raising=False)
        with pytest.raises(SignerUnavailableError, match="INTERLOCK_KMS_TOKEN is not set"):
            settings.open()
        monkeypatch.setenv("INTERLOCK_KMS_TOKEN", "the-token")
        signer = settings.open()
        assert isinstance(signer, HttpRemoteSigner) and signer.version == 3
        assert signer.key_id == kms.key("interlock-relay", 3).key_id
