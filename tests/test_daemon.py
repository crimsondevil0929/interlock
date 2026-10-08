"""The daemon (``docs/EPIC6_DESIGN.md`` §2.7, §2.8): the supervisor
``interlock.toml`` describes, with its real parts, on SQLite. On PostgreSQL,
every part runs under load in ``tests/test_soak.py``.

- An agent's charge commits; a relay delivers it to the payment API; the
  vendor's webhook comes back to the inbox and is bound to the delivery; the
  agent consumes the fact; the settler receipts the delivery; the vacuum
  prunes what is settled. Stopped, the daemon leaves nothing for a second one
  to recover.
- ``interlock daemon`` runs until SIGTERM, with an application or without one,
  and reports every part as it stops.
- A part configured but not runnable is refused before anything starts: a
  relay without its credentials or an unregistered key, a vacuum whose key no
  operator holds, or without the ledger its checkpoints are anchored in; and
  an application that cannot be loaded.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, TypeVar

import pytest
from agentgov import BudgetManager

from interlock import BlastRadius
from interlock.cli import main
from interlock.config import InterlockConfig, load_config
from interlock.daemon import Application, build_supervisor, load_application
from interlock.engine import StageResult
from interlock.exceptions import SubstrateConfigurationError
from interlock.operators import generate_key
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.supervisor import AgentContext
from interlock.types import OutboundRequest
from tests.conftest import build_sqlite_back_office
from tests.fakestripe import KEY, FakeStripe
from tests.inbox_env import STRIPE_SECRET, stripe_webhook

ROOT = Path(__file__).resolve().parent.parent
T = TypeVar("T")

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
backoff_base_seconds = 0.05
backoff_cap_seconds = 0.2

[[sinks.operations]]
name = "payment_intents.create"

[[sinks.operations]]
name = "refunds.create"

[relays.keys]
relay = "{relay}"

[relay]
key = "relay.key"
breaker = "none"
poll_seconds = 0.05
lease_seconds = 4
timeout_seconds = 2

[[relay.endpoints]]
sink = "payments"
url = "{url}"
secret_env = "DAEMON_STRIPE_KEY"

[operators]
log = "operators.ilok1"
ledger = "governor.db"

[operators.keys]
vacuum = "{vacuum}"

[inbox]
key = "inbox.key"
listen = "127.0.0.1:0"
match_every_seconds = 0.1

[[inbox.sources]]
name = "stripe"
kind = "stripe"
secret_env = "DAEMON_WEBHOOK_SECRET"

[inbox.keys]
inbox = "{inbox}"

[engine]
chain = "escrow.chain"
settle_cost = "0.01"
ledger = "governor.db"

[receipts]
log = "receipts.jsonl"
key = "receipts.key"

[settler]
every_seconds = 0.1

[vacuum]
every_seconds = 1
retain_seconds = 0
margin_seconds = 0
key = "vacuum.key"

[daemon]
drain_timeout_seconds = 5
restart_min_seconds = 0.05
"""

ENVIRONMENT = {"DAEMON_STRIPE_KEY": KEY, "DAEMON_WEBHOOK_SECRET": STRIPE_SECRET}


@dataclass
class Site:
    path: Path
    stripe: FakeStripe

    @property
    def config(self) -> InterlockConfig:
        return load_config(self.path)

    def rewrite(self, old: str, new: str) -> InterlockConfig:
        """The configuration with ``old`` replaced: one way to misconfigure it."""
        text = self.path.read_text()
        assert old in text, old
        self.path.write_text(text.replace(old, new))
        return self.config


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Site]:
    """A back office with the outbox and the inbox installed, its keys, its
    ledger, and a payment API, as ``interlock.toml`` describes them."""
    for variable in [v for v in os.environ if v.startswith("INTERLOCK_")]:
        monkeypatch.delenv(variable)
    for variable, value in ENVIRONMENT.items():
        monkeypatch.setenv(variable, value)
    database = build_sqlite_back_office(tmp_path / "app.db")
    specs = {
        name: generate_key(tmp_path / f"{name}.key").public_key().spec()
        for name in ("relay", "inbox", "vacuum", "receipts")
    }
    stripe = FakeStripe()
    path = tmp_path / "interlock.toml"
    path.write_text(CONFIG.format(database=database, url=stripe.url, **specs))
    out = io.StringIO()
    assert (
        main(["install", "--config", str(path), "--key", str(tmp_path / "vacuum.key")], out=out)
        == 0
    )
    with BudgetManager.open_sqlite(str(tmp_path / "governor.db")) as governor:
        governor.open_root("agent", "10")
        governor.open_root("interlock-operators", "1")
    try:
        yield Site(path, stripe)
    finally:
        stripe.close()


async def until(check: Callable[[], T], timeout: float = 30.0) -> T:
    """``check()``'s first truthy answer, polled."""
    deadline = time.monotonic() + timeout
    while not (found := check()):
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.02)
    return found


def post(port: int, webhook: tuple[dict[str, str], bytes]) -> tuple[int, dict[str, Any]]:
    headers, body = webhook
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/inbox/stripe", data=body, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:  # noqa: S310 - our server
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as refused:
        return refused.code, json.loads(refused.read())


def charge(ctx: AgentContext) -> Any:
    return (
        ctx.plan("agent", intent="charge order 500")
        .update(
            table="orders",
            statement="UPDATE orders SET status = :s WHERE id = 500",
            parameters={"s": "charging"},
            tenant_id="acme",
            stated_rows=1,
        )
        .enqueue(
            sink="payments",
            operation=PAYMENT_INTENTS_CREATE,
            payload={"amount": 500, "currency": "usd"},
            tenant_id="acme",
            compensation=OutboundRequest(
                "payments", REFUNDS_CREATE, {"payment_intent": {"$bind": "delivered.id"}}
            ),
        )
        .build()
    )


def test_every_part_runs_as_the_configuration_says(site: Site) -> None:
    results: list[StageResult] = []

    async def agent(ctx: AgentContext) -> None:
        results.append(await ctx.execute(charge(ctx)))
        while not ctx.stopping:
            facts = await ctx.facts("agent")
            if facts:
                (fact,) = facts
                plan = (
                    ctx.plan("agent", intent="the payment went through")
                    .consume(fact)
                    .update(
                        table="orders",
                        statement="UPDATE orders SET status = :s WHERE id = 500",
                        parameters={"s": str(fact.fields["status"])},
                        tenant_id="acme",
                        stated_rows=1,
                    )
                    .build()
                )
                results.append(await ctx.execute(plan))
                return
            await ctx.sleep(0.05)

    config = site.config
    supervisor = build_supervisor(config, Application(checkers=[BlastRadius(5)], agents=[agent]))

    async def run() -> None:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        port = supervisor.inbox_port
        assert port is not None
        await until(lambda: supervisor.status()["relay-0"].counters.get("delivered", 0) == 1)
        (intent,) = site.stripe.of("payment_intent")
        event = {
            "id": "evt_1",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {"object": {**intent, "status": "succeeded"}},
        }
        status, answer = await asyncio.to_thread(post, port, stripe_webhook(event))
        assert (status, answer) == (200, {"recorded": 1, "matched": 1})
        await until(lambda: len(results) == 2)
        # Settled, then pruned: the retention is nothing.
        await until(lambda: supervisor.status()["vacuum"].counters.get("messages", 0) > 0)
        health = supervisor.health()
        assert health[0] == 200 and health[1]["status"] == "ok"
        supervisor.stop()
        await running

    asyncio.run(run())
    assert [r.committed for r in results] == [True, True]
    status = supervisor.status()
    assert {name: s.state for name, s in status.items()} == {
        "engines": "stopped",
        "relay-0": "stopped",
        "inbox": "stopped",
        "settler": "stopped",
        "vacuum": "stopped",
        "agent-0": "stopped",
    }
    assert status["engines"].counters["committed"] == 2
    assert status["relay-0"].counters["delivered"] == 1
    assert status["inbox"].counters["answered_200"] == 1
    assert status["settler"].counters["receipts"] == 1
    assert status["vacuum"].counters["applied"] >= 1
    assert all(s.failures == 0 for s in status.values()), status

    # A second daemon over the same files: nothing to recover, and it stops
    # as cleanly.
    again = build_supervisor(config, Application(checkers=[BlastRadius(5)]))

    async def restart() -> None:
        running = asyncio.create_task(again.run())
        await asyncio.wait_for(again.ready(), 30)
        again.stop()
        await running

    asyncio.run(restart())
    second = again.status()
    assert second["engines"].counters.get("recovered", 0) == 0
    assert all(s.failures == 0 and s.state == "stopped" for s in second.values()), second


class Daemon:
    """``interlock daemon`` in a process of its own, stopped with SIGTERM."""

    def __init__(self, path: Path, *extra: str) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("INTERLOCK_")}
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
        self.process = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-u",
                "-c",
                "import sys; from interlock.cli import main; sys.exit(main(sys.argv[1:]))",
                "daemon",
                "--config",
                str(path),
                *extra,
            ],
            cwd=ROOT,
            env={**env, **ENVIRONMENT},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.lines: list[str] = []
        self.errors: list[str] = []
        # Both pipes are read as the daemon writes: one left full would stall it.
        self._readers = [
            threading.Thread(target=_read, args=(self.process.stdout, self.lines), daemon=True),
            threading.Thread(target=_read, args=(self.process.stderr, self.errors), daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def wait_for(self, text: str, timeout: float = 30.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            exited = self.process.poll() is not None
            if exited:  # what it wrote last is read to the end
                for reader in self._readers:
                    reader.join(timeout=5)
            for line in list(self.lines):
                if text in line:
                    return line
            if exited or time.monotonic() > deadline:
                raise AssertionError(f"no {text!r} in {self.lines}; stderr: {self.errors}")
            time.sleep(0.02)

    def stop(self) -> int:
        """SIGTERM, and the exit code. A daemon still running a minute later
        is killed, and the test fails: none is left behind."""
        self.process.send_signal(signal.SIGTERM)
        try:
            code = self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        for reader in self._readers:
            reader.join(timeout=10)
        return code


def _read(stream: IO[str] | None, into: list[str]) -> None:
    assert stream is not None
    for line in stream:
        into.append(line.rstrip("\n"))


@pytest.mark.parametrize(
    ("app", "parts"),
    [
        ("tests.daemon_app:build", ["engines", "inbox", "mark-0", "relay-0", "settler", "vacuum"]),
        (None, ["inbox", "relay-0", "vacuum"]),
    ],
)
def test_interlock_daemon_runs_until_sigterm(site: Site, app: str | None, parts: list[str]) -> None:
    daemon = Daemon(site.path, *(["--app", app] if app else []))
    try:
        running = daemon.wait_for("interlock daemon running:")
        assert running.split(": ", 1)[1].split(";")[0] == ", ".join(parts)
        port = int(daemon.wait_for("receiving webhooks on port").rsplit(" ", 1)[1])
        status, health = post_health(port)
        if app:
            daemon.wait_for("agent: plan committed")
    finally:
        code = daemon.stop()
    assert code == 0, (daemon.lines, daemon.errors)
    assert status == 200 and health["status"] == "ok"
    stopped = [line.split(":", 1)[0] for line in daemon.lines if ": stopped," in line]
    assert stopped == parts


def post_health(port: int) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}/healthz")
    with urllib.request.urlopen(request, timeout=10) as answer:  # noqa: S310 - our server
        return answer.status, json.loads(answer.read())


# --------------------------------------------------------------------------
# refused before anything starts
# --------------------------------------------------------------------------


def test_a_relay_without_its_credentials_is_refused(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DAEMON_STRIPE_KEY")
    with pytest.raises(SubstrateConfigurationError, match="DAEMON_STRIPE_KEY"):
        build_supervisor(site.config)


def test_a_relay_whose_key_is_not_registered_is_refused(site: Site, tmp_path: Path) -> None:
    generate_key(tmp_path / "stranger.key")
    with pytest.raises(SubstrateConfigurationError, match="is not registered"):
        build_supervisor(site.config, relay_key=str(tmp_path / "stranger.key"))


def test_a_vacuum_whose_key_no_operator_holds_is_refused(site: Site, tmp_path: Path) -> None:
    generate_key(tmp_path / "stranger.key")
    config = site.rewrite('key = "vacuum.key"', 'key = "stranger.key"')
    with pytest.raises(SubstrateConfigurationError, match="no registered operator's"):
        build_supervisor(config)


def test_a_vacuum_without_the_operators_ledger_is_refused(site: Site) -> None:
    config = site.rewrite('ledger = "governor.db"\n\n[operators.keys]', "\n[operators.keys]")
    with pytest.raises(SubstrateConfigurationError, match="anchored into AgentGov"):
        build_supervisor(config)


def test_an_inbox_listening_nowhere_is_refused(site: Site) -> None:
    with pytest.raises(SubstrateConfigurationError, match="HOST:PORT"):
        build_supervisor(site.config, listen="8787")


def test_an_application_that_cannot_be_loaded_is_refused(site: Site) -> None:
    config = site.config
    for target, why in (
        ("tests.daemon_app", "module:callable"),
        ("tests.no_such_module:build", "cannot load"),
        ("tests.daemon_app:missing", "cannot load"),
        ("tests.daemon_app:wrong", "not an interlock Application"),
    ):
        with pytest.raises(SubstrateConfigurationError, match=why):
            load_application(target, config)
    assert load_application("tests.daemon_app:build", config).agents
