"""Typed sinks in ``interlock.toml``, and the relay command delivering to them.

A typed sink names its kind and which of its kind's operations to allow; its
schemas and compensations are the kind's, and configuration may not write
them. Its relay endpoint names the environment variable holding its API key;
the adapter knows the routes and how to present the key.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlock import EscrowEngine, PlanBuilder, SqliteSubstrate
from interlock.cli import main
from interlock.config import ConfigError, load_config
from interlock.outbound import SinkRegistry
from interlock.sendgrid import CATALOG as SENDGRID_CATALOG
from interlock.sendgrid import MAIL_SEND
from interlock.stripe import CATALOG as STRIPE_CATALOG
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.types import OutboundRequest
from tests.conftest import build_sqlite_back_office
from tests.fakesendgrid import KEY as SENDGRID_KEY
from tests.fakesendgrid import FakeSendGrid
from tests.fakestripe import KEY as STRIPE_KEY
from tests.fakestripe import FakeStripe
from tests.schemas import specs

CONFIG = """
substrate = "sqlite"
database = "{database}"

[[tables]]
name = "orders"
columns = ["id", "customer_id", "tenant", "status", "total"]
tenant_column = "tenant"

[[sinks]]
name = "payments"
type = "stripe"
cost_per_call = "0.30"
backoff_base_seconds = 0.02
backoff_cap_seconds = 0.16

[[sinks.operations]]
name = "payment_intents.create"

[[sinks.operations]]
name = "refunds.create"

[[sinks]]
name = "email"
type = "sendgrid"
cost_per_call = "0.001"

[[sinks.operations]]
name = "mail.send"

[relay]
breaker = "none"
lease_seconds = 4
timeout_seconds = 1

[[relay.endpoints]]
sink = "payments"
url = "{stripe}"
secret_env = "TEST_STRIPE_KEY"

[[relay.endpoints]]
sink = "email"
url = "{sendgrid}"
secret_env = "TEST_SENDGRID_KEY"
sandbox = {sandbox}
"""


def write(tmp_path: Path, text: str, **values: object) -> Path:
    path = tmp_path / "interlock.toml"
    defaults: dict[str, object] = {
        "database": tmp_path / "app.sqlite",
        "stripe": "http://127.0.0.1:1",
        "sendgrid": "http://127.0.0.1:2",
        "sandbox": "false",
    }
    path.write_text(text.format(**{**defaults, **values}))
    return path


def test_a_typed_sink_takes_its_kinds_operations(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, CONFIG))
    payments, email = config.sinks
    assert (payments.kind, email.kind) == ("stripe", "sendgrid")
    assert payments.operations == (
        STRIPE_CATALOG[PAYMENT_INTENTS_CREATE],
        STRIPE_CATALOG[REFUNDS_CREATE],
    )
    assert email.operations == (SENDGRID_CATALOG[MAIL_SEND],)
    assert (email.idempotency, email.unknown_outcome) == ("none", "dead-letter")
    assert (payments.idempotency, payments.unknown_outcome) == ("header", "redeliver")
    assert config.relay is not None
    stripe, sendgrid = config.relay.endpoints
    assert (stripe.kind, stripe.secret_env, stripe.routes) == ("stripe", "TEST_STRIPE_KEY", {})
    assert (sendgrid.kind, sendgrid.sandbox) == ("sendgrid", False)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda t: t.replace('type = "stripe"', 'type = "paypal"'), "'type' is one of"),
        (
            lambda t: t.replace('name = "refunds.create"', 'name = "customers.delete"'),
            "stripe has no operation 'customers.delete'",
        ),
        (
            lambda t: t.replace(
                'name = "refunds.create"', 'name = "refunds.create"\nschema = "x.json"'
            ),
            "bring their own schema",
        ),
        (
            lambda t: t.replace('[[sinks.operations]]\nname = "refunds.create"\n', ""),
            "does not register",
        ),
        (
            lambda t: t.replace('type = "sendgrid"', 'type = "sendgrid"\nidempotency = "header"'),
            "idempotency is 'none'",
        ),
        (
            lambda t: t.replace(
                'secret_env = "TEST_STRIPE_KEY"',
                'secret_env = "TEST_STRIPE_KEY"\nroutes = {{ "refunds.create" = "POST /x" }}',
            ),
            "knows its routes",
        ),
        (
            lambda t: t.replace(
                'secret_env = "TEST_STRIPE_KEY"', 'secret_env = "TEST_STRIPE_KEY"\nsandbox = true'
            ),
            "for a sendgrid sink",
        ),
        (
            lambda t: t.replace(
                'secret_env = "TEST_SENDGRID_KEY"',
                'secret_env = "TEST_SENDGRID_KEY"\nstripe_version = "2024-06-20"',
            ),
            "for a stripe sink",
        ),
        (lambda t: t.replace('secret_env = "TEST_STRIPE_KEY"\n', ""), "missing 'secret_env'"),
        (lambda t: t.replace('url = "{stripe}"', 'url = "ftp://x"'), r"http\(s\) URL"),
    ],
)
def test_a_typed_sink_is_configured_as_its_kind_allows(
    tmp_path: Path, change: object, match: str
) -> None:
    assert callable(change)
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, change(CONFIG)))


def test_an_http_endpoint_takes_no_secret_env(tmp_path: Path) -> None:
    text = """
substrate = "sqlite"
database = "x.sqlite"
[[tables]]
name = "orders"
columns = ["id"]
[[sinks]]
name = "mail"
[[sinks.operations]]
name = "send"
[relay]
breaker = "none"
[[relay.endpoints]]
sink = "mail"
url = "http://127.0.0.1:1"
routes = { send = "POST /s" }
secret_env = "KEY"
"""
    path = tmp_path / "interlock.toml"
    path.write_text(text)
    with pytest.raises(ConfigError, match="is for a typed sink"):
        load_config(path)


# --------------------------------------------------------------------------
# the command line, against the fakes
# --------------------------------------------------------------------------


@pytest.fixture
def vendors() -> Iterator[tuple[FakeStripe, FakeSendGrid]]:
    stripe, sendgrid = FakeStripe(), FakeSendGrid()
    try:
        yield stripe, sendgrid
    finally:
        stripe.close()
        sendgrid.close()


def cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def test_the_relay_command_delivers_to_stripe_and_sendgrid(
    tmp_path: Path,
    vendors: tuple[FakeStripe, FakeSendGrid],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stripe, sendgrid = vendors
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = write(tmp_path, CONFIG, database=database, stripe=stripe.url, sendgrid=sendgrid.url)
    code, out = cli("install", "--config", str(path))
    assert code == 0
    assert "registered sink: payments (stripe: payment_intents.create, refunds.create)" in out
    assert "registered sink: email (sendgrid: mail.send)" in out

    config = load_config(path)
    engine = EscrowEngine(
        SqliteSubstrate(database, tables=specs("orders")),
        checkers=[],
        sinks=SinkRegistry(config.sinks),
    )
    plan = (
        PlanBuilder("agent")
        .enqueue(
            sink="payments",
            operation=PAYMENT_INTENTS_CREATE,
            payload={"amount": 1200, "currency": "eur"},
            compensation=OutboundRequest(
                "payments", REFUNDS_CREATE, {"payment_intent": {"$bind": "delivered.id"}}
            ),
        )
        .enqueue(
            sink="email",
            operation=MAIL_SEND,
            payload={
                "to": [{"email": "ann@acme.test"}],
                "from": {"email": "shop@shop.test"},
                "subject": "Paid",
                "text": "Thank you.",
            },
        )
        .build()
    )
    assert engine.execute(plan).committed

    # Without their keys, the relay says which are missing, and sends nothing.
    monkeypatch.delenv("TEST_STRIPE_KEY", raising=False)
    monkeypatch.delenv("TEST_SENDGRID_KEY", raising=False)
    code, _ = cli("relay", "--config", str(path), "--once")
    assert code == 3
    err = capsys.readouterr().err
    assert "TEST_STRIPE_KEY (sink payments, its API key)" in err and "TEST_SENDGRID_KEY" in err
    assert stripe.calls == [] and sendgrid.calls == []

    monkeypatch.setenv("TEST_STRIPE_KEY", STRIPE_KEY)
    monkeypatch.setenv("TEST_SENDGRID_KEY", SENDGRID_KEY)
    code, out = cli("relay", "--config", str(path), "--once")
    assert code == 0 and "claimed 2: delivered 2" in out
    (intent,) = stripe.of("payment_intent")
    assert intent["amount"] == 1200 and len(sendgrid.sent) == 1
    code, out = cli("outbox", "verify", "--config", str(path))
    assert (code, out.strip()) == (0, "every delivery log verifies")
    code, out = cli("outbox", "list", "--state", "delivered", "--config", str(path))
    assert code == 0 and "payments.payment_intents.create" in out and "email.mail.send" in out
