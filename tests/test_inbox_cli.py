"""The inbox's configuration, its commands, and its HTTP server
(``docs/EPIC5_DESIGN.md`` §2): ``[inbox]``, ``[[inbox.sources]]`` and
``[inbox.keys]``; ``interlock keygen --role inbox``; ``interlock inbox serve``
receiving a vendor's webhook over HTTP in a process of its own, ``match``,
``list`` and ``verify``.
"""

from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from interlock import EscrowEngine, PlanBuilder, SqliteSubstrate
from interlock.config import ConfigError, load_config
from interlock.inbox import InboxServer, Response, serve
from interlock.operators import generate_key
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.relay import NoBreaker, Relay
from interlock.sqlite_outbox import SqliteOutboxStore
from tests.conftest import PASSWORD, Pg, build_sqlite_back_office, create_role, drop_role
from tests.inbox_env import (
    HOOKS_SECRET,
    SENDGRID_PUBLIC,
    STRIPE_SECRET,
    InboxSite,
    Referencing,
    inbox_site,
    refund_event,
    stripe_webhook,
)
from tests.outbox_env import BACKENDS, Outbox, build_either, relay_signer, relays_section
from tests.schemas import specs

ROOT = Path(__file__).resolve().parent.parent

CONFIG = """
substrate = "sqlite"
database = "{database}"

[[tables]]
name = "orders"
primary_key = "id"
columns = ["id", "customer_id", "tenant", "status", "total"]
tenant_column = "tenant"

[[sinks]]
name = "payments"
cost_per_call = "0.01"

[[sinks.operations]]
name = "refund"

[inbox]
key = "inbox.key"
listen = "127.0.0.1:0"
match_every_seconds = 0.2
match_window_seconds = 600

[[inbox.sources]]
name = "stripe"
kind = "stripe"
secret_env = "STRIPE_WEBHOOK_SECRET"
tolerance_seconds = 120

[[inbox.sources]]
name = "hooks"
kind = "http"
secret_env = "HOOKS_SECRET"
references = ["data.id"]
fields = [{{ name = "status", path = "data.status", type = "code" }}]

[[inbox.sources]]
name = "sendgrid"
kind = "sendgrid"
verification_key = "{sendgrid}"
"""


def cli(*argv: str) -> tuple[int, str]:
    from interlock.cli import main

    out = io.StringIO()
    return main(list(argv), out=out), out.getvalue()


def _keys(directory: Path) -> str:
    """The inbox's key, written as ``interlock keygen --role inbox`` does, and
    the ``[inbox.keys]`` table registering it."""
    code, out = cli(
        "keygen", "--role", "inbox", "--out", str(directory / "inbox.key"), "--name", "main"
    )
    assert code == 0 and "[inbox.keys]" in out
    return "\n[inbox.keys]\n" + out.strip().splitlines()[-1] + "\n"


@pytest.fixture
def configured(tmp_path: Path) -> Path:
    database = build_sqlite_back_office(tmp_path / "app.sqlite")
    path = tmp_path / "interlock.toml"
    path.write_text(
        CONFIG.format(database=database, sendgrid=SENDGRID_PUBLIC)
        + _keys(tmp_path)
        + relays_section(tmp_path)
    )
    return path


# -- configuration ----------------------------------------------------------------


def test_the_inbox_is_configured(configured: Path) -> None:
    config = load_config(configured)
    inbox = config.inbox
    assert [s.name for s in inbox.sources] == ["stripe", "hooks", "sendgrid"]
    assert inbox.sources[0].tolerance == timedelta(seconds=120)
    assert [(f.name, f.path, f.type) for f in inbox.sources[1].fields] == [
        ("status", "data.status", "code")
    ]
    assert inbox.key == configured.parent / "inbox.key"
    assert (inbox.listen, inbox.match_window, inbox.match_every) == (
        "127.0.0.1:0",
        timedelta(minutes=10),
        timedelta(seconds=0.2),
    )
    keyring = config.inbox_keyring()
    assert keyring is not None and len(keyring) == 1
    # No [inbox]: nothing to receive, no keys to verify under.
    bare = configured.parent / "bare.toml"
    bare.write_text(CONFIG.split("[inbox]")[0].format(database="x.db", sendgrid=""))
    assert load_config(bare).inbox_keyring() is None


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        (("[inbox]\n", "[inbox]\nport = 1\n"), "unknown key"),
        (('listen = "127.0.0.1:0"', 'listen = "nowhere"'), "HOST:PORT"),
        (('listen = "127.0.0.1:0"', 'listen = "h:99999"'), "HOST:PORT"),
        (("match_every_seconds = 0.2", "match_every_seconds = 0"), "positive"),
        (("match_window_seconds = 600", "match_window_seconds = -1"), "not negative"),
        (("tolerance_seconds = 120", "tolerance_seconds = 0"), "positive"),
        (("tolerance_seconds = 120", 'tolerance_seconds = 120\nsecret = "x"'), "unknown key"),
        (('name = "hooks"', 'name = "stripe"'), "configured twice"),
        (('name = "hooks"', 'name = "Hooks"'), "lowercase identifier"),
        (('kind = "http"', 'kind = "paypal"'), "kind is one of"),
        (('references = ["data.id"]', "references = []"), "references"),
        (('type = "code"', 'type = "text"'), "type one of|type is one of"),
        (('path = "data.status", ', ""), "name, path, type"),
        (('verification_key = "', 'verification_key = "x'), "verification_key"),
    ],
)
def test_a_misconfigured_inbox_is_refused(
    configured: Path, replace: tuple[str, str], message: str
) -> None:
    text = configured.read_text()
    assert replace[0] in text
    configured.write_text(text.replace(replace[0], replace[1], 1))
    with pytest.raises(ConfigError, match=message):
        load_config(configured)


def test_inbox_keys_and_roles_are_checked(configured: Path) -> None:
    text = configured.read_text()
    configured.write_text(text.replace('main = "ed25519:', 'main = "rsa:', 1))
    with pytest.raises(ConfigError, match=r"\[inbox.keys\]"):
        load_config(configured)
    configured.write_text('inbox_roles = ["interlock_inbox"]\n' + text)
    with pytest.raises(ConfigError, match="inbox_roles are PostgreSQL roles"):
        load_config(configured)
    configured.write_text(text.replace("[[inbox.sources]]", "[inbox.sources]", 1))
    with pytest.raises((ConfigError, ValueError)):
        load_config(configured)


# -- the commands, on a SQLite file -------------------------------------------------


def _deliver(database: str, ref: str) -> uuid.UUID:
    """Commit and deliver one refund, its call creating ``ref``."""
    registry = SinkRegistry(
        [SinkSpec("payments", (OperationSpec("refund"),), cost_per_call=Decimal("0.01"))]
    )
    engine = EscrowEngine(
        SqliteSubstrate(database, tables=specs("orders")), checkers=[], sinks=registry
    )
    plan = (
        PlanBuilder("agent")
        .enqueue(sink="payments", operation="refund", payload={"ref": ref, "amount": "25.00"})
        .build()
    )
    assert engine.execute(plan).committed
    relay = Relay(
        SqliteOutboxStore(database),
        adapters={"payments": Referencing()},
        breaker=NoBreaker(),
        signer=relay_signer(),
        lease=timedelta(seconds=10),
        timeout=timedelta(seconds=2),
    )
    try:
        assert relay.run_once().delivered == 1
    finally:
        relay.close()
    (message,) = [
        m for m in SqliteOutboxStore(database).snapshot(None)[0] if m.plan_id == plan.plan_id
    ]
    return message.message_id


class Server:
    """``interlock inbox serve`` in a process of its own, stopped with SIGTERM."""

    def __init__(self, config: Path, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-u",
                "-c",
                "import sys; from interlock.cli import main; sys.exit(main(sys.argv[1:]))",
                "inbox",
                "serve",
                "--config",
                str(config),
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        assert "receiving webhooks on 127.0.0.1:" in line, line + self.stderr()
        self.port = int(line.split("127.0.0.1:")[1].split(";")[0])

    def stderr(self) -> str:
        if self.process.poll() is None:
            return ""
        assert self.process.stderr is not None
        return str(self.process.stderr.read())

    def post(self, source: str, webhook: tuple[dict[str, str], bytes]) -> Response:
        headers, body = webhook
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/inbox/{source}", data=body, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as answer:  # noqa: S310
                return Response(answer.status, json.loads(answer.read()))
        except urllib.error.HTTPError as refused:
            return Response(refused.code, json.loads(refused.read()))

    def stop(self) -> int:
        self.process.send_signal(signal.SIGTERM)
        return self.process.wait(timeout=30)


def _environment(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("INTERLOCK_")}
    return {**env, "PYTHONPATH": str(ROOT / "src"), **extra}


def test_the_inbox_receives_a_webhook_over_http_and_proves_it(configured: Path) -> None:
    config = load_config(configured)
    code, out = cli("install", "--config", str(configured))
    assert code == 0, out
    assert "registered inbound source: stripe (stripe)" in out
    assert "registered inbound source: sendgrid (sendgrid)" in out
    message = _deliver(config.database, "re_1")

    server = Server(
        configured,
        _environment(STRIPE_WEBHOOK_SECRET=STRIPE_SECRET, HOOKS_SECRET=HOOKS_SECRET),
    )
    try:
        webhook = stripe_webhook(refund_event("re_1"))
        assert server.post("stripe", webhook) == Response(200, {"recorded": 1, "matched": 1})
        assert server.post("stripe", webhook) == Response(200, {"recorded": 0, "matched": 1})
        forged = stripe_webhook(refund_event("re_1", event_id="evt_2"), secret="whsec_forged")
        assert server.post("stripe", forged).status == 401
        assert server.post("paypal", webhook).status == 404
    finally:
        assert server.stop() == 0, server.stderr()

    code, out = cli("inbox", "list", "--config", str(configured))
    assert code == 0
    (line,) = out.strip().splitlines()
    assert line.startswith("stripe    1 ") and "charge.refund.updated" in line
    assert f"-> message {message} (scope agent), pending" in line
    code, out = cli("inbox", "verify", "--config", str(configured))
    assert (code, out.splitlines()[0]) == (
        0,
        "every inbound log verifies: 1 event(s), each attested by a registered inbox; 1 fact(s) "
        "bound to the deliveries they name, each attested by a registered relay; 0 consumed",
    )
    engine = EscrowEngine(
        SqliteSubstrate(config.database, tables=config.tables),
        checkers=[],
        inbox=config.inbox_keyring(),
    )
    (fact,) = engine.facts("agent")
    assert fact.message_id == message

    # The owner rewrites what the vendor said: verification fails.
    import sqlite3

    raw = sqlite3.connect(config.database)
    try:
        raw.execute("DROP TRIGGER _interlock_inbox_events_no_update")
        raw.execute('UPDATE _interlock_inbox_events SET fields = \'{"status":"failed"}\'')
        raw.commit()
    finally:
        raw.close()
    code, out = cli("inbox", "verify", "--config", str(configured))
    assert code == 1 and "does not hash to what it records" in out


def test_an_event_before_its_delivery_is_bound_by_inbox_match(configured: Path) -> None:
    config = load_config(configured)
    assert cli("install", "--config", str(configured))[0] == 0
    server = Server(configured, _environment(STRIPE_WEBHOOK_SECRET=STRIPE_SECRET, HOOKS_SECRET="x"))
    try:
        answer = server.post("stripe", stripe_webhook(refund_event("re_7")))
    finally:
        assert server.stop() == 0
    assert answer == Response(200, {"recorded": 1, "matched": 0})
    code, out = cli("inbox", "list", "--config", str(configured), "--source", "stripe")
    assert code == 0 and out.strip().endswith("unmatched")
    _deliver(config.database, "re_7")
    code, out = cli("inbox", "match", "--config", str(configured))
    assert (code, out.strip()) == (0, "bound 1 event(s) to their deliveries")
    assert cli("inbox", "match", "--config", str(configured))[1].strip() == (
        "bound 0 event(s) to their deliveries"
    )
    assert cli("inbox", "list", "--config", str(configured), "--source", "hooks")[1] == ""


def test_the_inbox_refuses_to_start_without_what_it_needs(
    configured: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli("install", "--config", str(configured))[0] == 0
    text = configured.read_text()
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", STRIPE_SECRET)
    monkeypatch.delenv("HOOKS_SECRET", raising=False)
    # A secret the environment does not hold.
    assert cli("inbox", "serve", "--config", str(configured))[0] == 3
    assert "HOOKS_SECRET (source hooks)" in capsys.readouterr().err
    # No key.
    configured.write_text(text.replace('key = "inbox.key"\n', "", 1))
    assert cli("inbox", "match", "--config", str(configured))[0] == 2
    assert "attests every event and fact" in capsys.readouterr().err
    # A key no [inbox.keys] registers.
    other = generate_key(configured.parent / "other.key")
    assert (
        cli(
            "inbox",
            "match",
            "--config",
            str(configured),
            "--key",
            str(other_path := configured.parent / "other.key"),
        )[0]
        == 2
    )
    assert f"key {other.key_id} is not registered" in capsys.readouterr().err
    assert other_path.exists()
    # An unreadable key.
    (configured.parent / "bad.key").write_text("not a key")
    assert (
        cli(
            "inbox",
            "match",
            "--config",
            str(configured),
            "--key",
            str(configured.parent / "bad.key"),
        )[0]
        == 2
    )
    assert "cannot open the inbox key" in capsys.readouterr().err
    # No [inbox.keys]; no [relays.keys]; no source.
    configured.write_text(text.split("\n[inbox.keys]")[0] + relays_section(configured.parent))
    assert cli("inbox", "verify", "--config", str(configured))[0] == 2
    configured.write_text(text.split("\n[relays.keys]")[0])
    assert cli("inbox", "match", "--config", str(configured))[0] == 2
    assert "[relays.keys]" in capsys.readouterr().err
    head, _, keys = text.partition("\n[inbox.keys]")
    configured.write_text(head.split("[[inbox.sources]]")[0] + "\n[inbox.keys]" + keys)
    assert cli("inbox", "match", "--config", str(configured))[0] == 2
    assert "configures no source" in capsys.readouterr().err


def test_the_inbox_on_postgresql(pg: Pg, tmp_path: Path) -> None:
    from psycopg.conninfo import make_conninfo

    role = f"il_inbox_{uuid.uuid4().hex[:8]}"
    create_role(pg.cluster, role)
    try:
        path = tmp_path / "interlock.toml"
        text = CONFIG.format(database=pg.admin, sendgrid=SENDGRID_PUBLIC).replace(
            'substrate = "sqlite"',
            f'substrate = "postgres"\nstage_roles = ["{pg.role}"]\ninbox_roles = ["{role}"]',
        )
        path.write_text(text + _keys(tmp_path) + relays_section(tmp_path))
        code, out = cli("install", "--config", str(path))
        assert code == 0, out
        assert f"granted to inbox role: {role}" in out
        assert "registered inbound source: hooks (http)" in out
        dsn = make_conninfo(pg.admin, user=role, password=PASSWORD)
        code, out = cli("inbox", "match", "--config", str(path), "--database", dsn)
        assert (code, out.strip()) == (0, "bound 0 event(s) to their deliveries")
        code, out = cli("inbox", "verify", "--config", str(path))
        assert code == 0 and "0 event(s)" in out
        code, out = cli("inbox", "list", "--config", str(path))
        assert (code, out) == (0, "")
        # A stage role cannot stand in for the inbox's.
        code, _ = cli("inbox", "match", "--config", str(path), "--database", pg.agent)
        assert code == 3
        bad = make_conninfo(pg.admin, port=1)
        assert cli("inbox", "match", "--config", str(path), "--database", bad)[0] == 4
    finally:
        drop_role(pg.cluster, pg.admin, role)


# -- the HTTP server ------------------------------------------------------------------


@pytest.fixture(params=BACKENDS)
def outbox(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Outbox]:
    yield from build_either(request, tmp_path)


@pytest.fixture
def site(outbox: Outbox) -> Iterator[InboxSite]:
    with inbox_site(outbox) as installed:
        yield installed


def _raw(port: int, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, Any]:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest("POST", path)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders()
        if body:
            conn.send(body)
        answer = conn.getresponse()
        return answer.status, json.loads(answer.read())
    finally:
        conn.close()


def test_the_server_binds_without_looking_up_a_name(
    site: InboxSite, monkeypatch: pytest.MonkeyPatch
) -> None:
    # http.server's own bind resolves the address to a name, which nothing
    # reads: half a minute, in every new process, where a resolver times out.
    def lookup(name: str = "") -> str:
        raise AssertionError(f"looked up {name!r}")

    monkeypatch.setattr(socket, "getfqdn", lookup)
    server = InboxServer(site.inbox(), "127.0.0.1", 0)
    try:
        assert server.start() > 0
    finally:
        server.stop()


def test_the_server_answers_each_webhook_as_the_inbox_does(site: InboxSite) -> None:
    site.deliver("re_1")
    inbox = site.inbox()
    stop = threading.Event()
    bound: list[int] = []
    ready = threading.Event()

    def on_ready(port: int) -> None:
        bound.append(port)
        ready.set()

    worker = threading.Thread(
        target=serve,
        args=(inbox, "127.0.0.1", 0),
        kwargs={"stop": stop, "ready": on_ready, "match_every": timedelta(milliseconds=50)},
    )
    worker.start()
    try:
        assert ready.wait(10)
        (port,) = bound
        headers, body = stripe_webhook(refund_event("re_1"))
        sized = {**headers, "Content-Length": str(len(body))}
        assert _raw(port, "/inbox/stripe", body, sized) == (200, {"recorded": 1, "matched": 1})
        assert _raw(port, "/inbox/stripe?x=1", body, sized)[0] == 200
        assert _raw(port, "/inbox/paypal", body, sized)[0] == 404
        assert _raw(port, "/elsewhere", body, sized)[0] == 404
        assert _raw(port, "/inbox/stripe", body, headers)[0] == 411
        too_big = {**headers, "Content-Length": str(10 * 1024 * 1024)}
        assert _raw(port, "/inbox/stripe", b"", too_big)[0] == 413
        forged = stripe_webhook(refund_event("re_1", event_id="evt_9"), secret="whsec_no")
        forged_headers = {**forged[0], "Content-Length": str(len(forged[1]))}
        assert _raw(port, "/inbox/stripe", forged[1], forged_headers)[0] == 401
    finally:
        stop.set()
        worker.join(timeout=30)
    assert not worker.is_alive()
    assert (site.events(), site.facts()) == (1, 1)
