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
import logging
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
from interlock.config import METRICS_DATABASE_ENV, InterlockConfig, load_config
from interlock.daemon import Application, build_supervisor, load_application
from interlock.engine import StageResult
from interlock.exceptions import SubstrateConfigurationError
from interlock.operators import generate_key
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.supervisor import AgentContext
from interlock.trace import child_traceparent
from interlock.types import OutboundRequest
from tests.conftest import build_sqlite_back_office
from tests.fakestripe import KEY, FakeStripe
from tests.inbox_env import STRIPE_SECRET, stripe_webhook

TRACED = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

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


def test_the_daemon_signs_with_every_key_at_a_signing_service(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The relay, the inbox, the vacuum and the receipt log each sign through a
    key service (docs/EPIC8_DESIGN.md §1): no key file is left to read."""
    from tests.fakekms import FakeKms

    base = site.path.parent
    parts = ("relay", "inbox", "vacuum", "receipts")
    kms = FakeKms(token="daemon-kms-token")
    monkeypatch.setenv("DAEMON_KMS_TOKEN", "daemon-kms-token")
    text = site.path.read_text()
    for name in parts:
        key_file = base / f"{name}.key"
        kms.create(name, bytes.fromhex(key_file.read_text().strip()))
        key_file.unlink()
        text = text.replace(f'key = "{name}.key"', f'signer = "{name}"').replace(
            "[daemon]",
            f'[signers.{name}]\ntype = "http"\nurl = "{kms.url}"\nkey = "{name}"\n'
            f'token_env = "DAEMON_KMS_TOKEN"\n\n[daemon]',
        )
    site.path.write_text(text)
    config = site.config
    assert {config.signers[n].key for n in parts} == set(parts)
    charged: list[StageResult] = []

    async def agent(ctx: AgentContext) -> None:
        charged.append(await ctx.execute(charge(ctx)))
        while not ctx.stopping:
            await ctx.sleep(0.05)

    supervisor = build_supervisor(config, Application(checkers=[BlastRadius(5)], agents=[agent]))

    async def run() -> None:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        inbox = supervisor.inbox_port
        assert inbox is not None
        await until(lambda: supervisor.status()["settler"].counters.get("receipts", 0) == 1)
        (intent,) = site.stripe.of("payment_intent")
        event = {
            "id": "evt_1",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {"object": {**intent, "status": "succeeded"}},
        }
        # Recorded, so attested. (Its fact may not be: the vacuum, every second
        # with no retention, may have pruned the payment by now.)
        status, answer = await asyncio.to_thread(post, inbox, stripe_webhook(event))
        assert status == 200 and answer["recorded"] == 1
        await until(lambda: supervisor.status()["vacuum"].counters.get("applied", 0) >= 1)
        supervisor.stop()
        await running

    try:
        asyncio.run(run())
    finally:
        kms.close()
    assert [r.committed for r in charged] == [True]
    # Every signature came from the service: the outcome, the event, both
    # receipts, and the vacuum's intent and outcome.
    assert kms.signed[("relay", 1)] >= 1
    assert kms.signed[("inbox", 1)] >= 1
    assert kms.signed[("receipts", 1)] >= 2
    assert kms.signed[("vacuum", 1)] >= 2
    assert not [n for n in parts if (base / f"{n}.key").exists()]


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


# The daemon writes every thread's stack to stderr on SIGUSR1: a wait for its
# words that runs out shows where it is.
ENTRY = (
    "import faulthandler, signal, sys; faulthandler.register(signal.SIGUSR1); "
    "from interlock.cli import main; sys.exit(main(sys.argv[1:]))"
)


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
                ENTRY,
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
                if not exited:
                    self._dump()
                raise AssertionError(
                    f"no {text!r} in {self.lines}; exit code {self.process.poll()}; "
                    "stderr:\n" + "\n".join(self.errors)
                )
            time.sleep(0.02)

    def _dump(self) -> None:
        """Every thread's stack, into stderr, as soon as it stops growing."""
        self.process.send_signal(signal.SIGUSR1)
        settled, size = time.monotonic() + 5, -1
        while len(self.errors) != size and time.monotonic() < settled:
            size = len(self.errors)
            time.sleep(0.5)

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


# --------------------------------------------------------------------------
# metrics (docs/EPIC7_DESIGN.md §2)
# --------------------------------------------------------------------------

METRICS = '[metrics]\nlisten = "127.0.0.1:0"\nevery_seconds = 0.1\n\n[daemon]'


def scrape(port: int) -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
    from tests.test_metrics import parse

    request = urllib.request.Request(f"http://127.0.0.1:{port}/metrics")
    with urllib.request.urlopen(request, timeout=10) as answer:  # noqa: S310 - our server
        return parse(answer.read().decode())


def test_the_daemon_serves_what_every_part_measures(site: Site) -> None:
    config = site.rewrite("[daemon]", METRICS)
    charged: list[StageResult] = []

    async def agent(ctx: AgentContext) -> None:
        charged.append(await ctx.execute(charge(ctx)))
        while not ctx.stopping:
            await ctx.sleep(0.05)

    supervisor = build_supervisor(config, Application(checkers=[BlastRadius(5)], agents=[agent]))

    async def run() -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        inbox, port = supervisor.inbox_port, supervisor.metrics_port
        assert inbox is not None and port is not None
        await until(lambda: supervisor.status()["settler"].counters.get("receipts", 0) == 1)
        (intent,) = site.stripe.of("payment_intent")
        event = {
            "id": "evt_1",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {"object": {**intent, "status": "succeeded"}},
        }
        assert (await asyncio.to_thread(post, inbox, stripe_webhook(event)))[0] == 200
        # Webhooks taken, by the trace context they carried: ours, continued;
        # one that is not a context; and, not counted, one whose signature
        # does not verify, since anyone can send that.
        for n, traceparent in ((2, child_traceparent(TRACED)), (3, "00-abc-def-01")):
            headers, body = stripe_webhook({**event, "id": f"evt_{n}"})
            headers["traceparent"] = traceparent
            assert (await asyncio.to_thread(post_to, inbox, "/inbox/stripe", headers, body)) == 200
        headers, body = stripe_webhook({**event, "id": "evt_4"}, secret="whsec_not_the_one")
        headers["traceparent"] = TRACED
        assert (await asyncio.to_thread(post_to, inbox, "/inbox/stripe", headers, body)) == 401
        # A source no one configured: counted, under no name of the sender's choosing.
        headers, body = stripe_webhook(event)
        assert (await asyncio.to_thread(post_to, inbox, "/inbox/whatever", headers, body)) == 404

        def sampled() -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
            # Sampled since the webhook: every state named. (The vacuum, every
            # second with no retention, may have pruned the payment by now.)
            scraped = scrape(port)
            states = {dict(k)["state"] for k in scraped.get("interlock_outbox_messages", {})}
            sampled_at = scraped.get("interlock_metrics_sampled_at_seconds", {}).get((), 0)
            return scraped if len(states) == 6 and sampled_at > began else {}

        began = time.time()

        scraped = await until(sampled)
        supervisor.stop()
        await running
        return scraped

    scraped = asyncio.run(run())
    assert [r.committed for r in charged] == [True]
    import interlock

    assert scraped["interlock_build_info"] == {(("version", interlock.__version__),): 1}
    assert scraped["interlock_plans_total"] == {(("outcome", "committed"),): 1}
    assert scraped["interlock_deliveries_total"] == {
        (("sink", "payments"), ("outcome", "delivered")): 1
    }
    assert scraped["interlock_receipts_issued_total"] == {(): 1}
    assert scraped["interlock_settlement_lag_seconds_count"] == {(): 1}
    assert scraped["interlock_webhooks_total"] == {
        (("source", "stripe"), ("status", "200")): 3,
        (("source", "stripe"), ("status", "401")): 1,
        (("source", "_unknown"), ("status", "404")): 1,
    }
    assert scraped["interlock_webhook_traceparent_total"] == {
        (("source", "stripe"), ("result", "absent")): 1,
        (("source", "stripe"), ("result", "valid")): 1,
        (("source", "stripe"), ("result", "invalid")): 1,
    }
    up = scraped["interlock_service_up"]
    assert {dict(k)["service"] for k in up} == {
        "engines",
        "relay-0",
        "inbox",
        "settler",
        "vacuum",
        "metrics",
    }
    assert set(up.values()) == {1}
    assert scraped["interlock_metrics_sampled_at_seconds"][()] > 0


def post_to(port: int, path: str, headers: dict[str, str], body: bytes) -> int:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:  # noqa: S310 - our server
            return int(answer.status)
    except urllib.error.HTTPError as refused:
        return int(refused.code)


def test_postgresql_is_sampled_only_as_a_role_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "interlock.toml"
    path.write_text(
        'substrate = "postgres"\ndatabase = "postgresql://owner@127.0.0.1:1/app"\n'
        '[[tables]]\nname = "orders"\ncolumns = ["id"]\n'
        "[metrics]\nevery_seconds = 0.05\n"
    )
    config = load_config(path)
    with pytest.raises(SubstrateConfigurationError, match="HOST:PORT"):
        build_supervisor(config, metrics_listen="9464")
    # No role to sample as: served, and said so.
    monkeypatch.delenv(METRICS_DATABASE_ENV, raising=False)
    with caplog.at_level(logging.WARNING, logger="interlock.daemon"):
        build_supervisor(config, metrics_listen="127.0.0.1:0")
    assert "no role to sample the database as" in caplog.text
    # One given by the environment is sampled as: here a server that is not
    # there, so each sample fails, is counted, and the service runs on.
    monkeypatch.setenv(METRICS_DATABASE_ENV, "postgresql://audit@127.0.0.1:1/app")
    supervisor = build_supervisor(config, metrics_listen="127.0.0.1:0")

    async def run() -> None:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        await until(lambda: supervisor.metrics.value("interlock_metrics_sample_errors_total") >= 2)
        assert supervisor.status()["metrics"].state == "running"
        supervisor.stop()
        await running

    asyncio.run(run())


def test_interlock_daemon_serves_metrics_where_asked(site: Site) -> None:
    daemon = Daemon(site.path, "--metrics", "127.0.0.1:0")
    try:
        line = daemon.wait_for("serving metrics on port")
        scraped = scrape(int(line.rsplit(" ", 1)[1]))
    finally:
        code = daemon.stop()
    assert code == 0, (daemon.lines, daemon.errors)
    assert {dict(k)["service"] for k in scraped["interlock_service_up"]} == {
        "inbox",
        "relay-0",
        "vacuum",
        "metrics",
    }


def test_an_operator_signs_through_a_signing_service(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    from interlock.records import read_records
    from tests.fakekms import FakeKms

    base = site.path.parent
    with FakeKms(token="ops-token") as kms:
        key = kms.create("ops", bytes.fromhex((base / "vacuum.key").read_text().strip()))
        monkeypatch.setenv("OPS_KMS_TOKEN", "ops-token")
        site.path.write_text(
            site.path.read_text().replace(
                "[daemon]",
                f'[signers.ops]\ntype = "http"\nurl = "{kms.url}"\nkey = "ops"\n'
                f'token_env = "OPS_KMS_TOKEN"\n\n[daemon]',
            )
        )
        config = str(site.path)
        before = len(read_records(base / "operators.ilok1"))
        assert main(["install", "--config", config, "--signer", "ops"], out=io.StringIO()) == 0
        records = read_records(base / "operators.ilok1")
        assert len(records) == before + 1 and records[-1].key_id == key.key_id
        assert kms.signed[("ops", 1)] == 1
        both = ["install", "--config", config, "--signer", "ops", "--key", str(base / "vacuum.key")]
        assert main(both, out=io.StringIO()) != 0
        assert main(["install", "--config", config, "--signer", "nobody"], out=io.StringIO()) != 0
        assert kms.signed[("ops", 1)] == 1


def test_keys_are_listed_registered_and_revoked_from_the_command_line(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``interlock keys`` (docs/EPIC8_DESIGN.md §2): a relay key rotated, its
    successor's public half read from the key service, and verified after."""
    from tests.fakekms import FakeKms

    base = site.path.parent
    config = str(site.path)
    operator_key = ["--key", str(base / "vacuum.key")]
    old = load_config(site.path).relay_keyring()
    assert old is not None
    (old_id,) = old.ids()

    def run(*argv: str) -> tuple[int, str]:
        out = io.StringIO()
        code = main([*argv, "--config", config], out=out)
        return code, out.getvalue()

    code, listed = run("keys", "list")
    assert code == 0
    assert f"relay     relay                {old_id}  configured; trusted" in listed
    with FakeKms() as kms:
        new = kms.create("relay-2")
        site.path.write_text(
            site.path.read_text().replace(
                "[daemon]",
                f'[signers.relay-2]\ntype = "http"\nurl = "{kms.url}"\nkey = "relay-2"\n\n[daemon]',
            )
        )
        register = ["keys", "register", *operator_key, "--role", "relay", "--name", "relay-2"]
        code, said = run(*register, "--public-of", "relay-2")
        assert code == 0, said
        assert f"relay key {new.key_id} registered as relay-2" in said
        # Once is enough: under any name, for any role.
        assert run(*register, "--public-of", "relay-2")[0] == 1
        again = ["keys", "register", *operator_key, "--role", "inbox", "--name", "x"]
        code, said = run(*again, "--public", new.public_key().spec())
        assert code == 1 and "is a relay key already" in said
        assert run(*register, "--public-of", "nobody")[0] == 2
    revoke = ["keys", "revoke", *operator_key, "--role", "relay", old_id, "--reason", "rotated"]
    code, said = run(*revoke)
    assert code == 0, said
    assert f"relay key {old_id} revoked; 0 rows sealed" in said
    assert run(*revoke)[0] == 1
    # The operator's own key, and the last one: nobody could sign again.
    vacuum = load_config(site.path).operators
    assert vacuum is not None
    (operator_id,) = vacuum.keyring().ids()
    code, said = run("keys", "revoke", *operator_key, "--role", "operator", operator_id)
    assert code == 1 and "does not revoke their own key" in said
    code, listed = run("keys", "list")
    assert code == 0
    assert f"{old_id}  configured; revoked " in listed and "0 rows sealed" in listed
    assert f"relay-2              {new.key_id}  registered by operator record" in listed
    code, verified = run("outbox", "verify")
    assert code == 0, verified
    assert "1 key(s) registered by operators; 1 revoked" in verified


# --------------------------------------------------------------------------
# keys rotated while the daemon runs (docs/EPIC8_DESIGN.md §2.6, §3)
# --------------------------------------------------------------------------

KMS_TOKEN = "daemon-kms-token"


def at_key_service(
    site: Site, kms: Any, parts: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``parts``' keys moved into ``kms``, their files deleted: each part signs
    through a ``[signers.<part>]`` of its own."""
    base = site.path.parent
    monkeypatch.setenv("DAEMON_KMS_TOKEN", KMS_TOKEN)
    text = site.path.read_text()
    for name in parts:
        key_file = base / f"{name}.key"
        kms.create(name, bytes.fromhex(key_file.read_text().strip()))
        key_file.unlink()
        text = text.replace(f'key = "{name}.key"', f'signer = "{name}"').replace(
            "[daemon]",
            f'[signers.{name}]\ntype = "http"\nurl = "{kms.url}"\nkey = "{name}"\n'
            f'token_env = "DAEMON_KMS_TOKEN"\n\n[daemon]',
        )
    site.path.write_text(text)


def cli(site: Site, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main([*argv, "--config", str(site.path)], out=out)
    return code, out.getvalue()


def as_operator(site: Site, *argv: str) -> tuple[int, str]:
    """``interlock keys ...`` signed with the vacuum's key: the site's operator."""
    return cli(site, *argv, "--key", str(site.path.parent / "vacuum.key"))


def payment_succeeded(intent: dict[str, Any], n: int) -> tuple[dict[str, str], bytes]:
    return stripe_webhook(
        {
            "id": f"evt_{n}",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {"object": {**intent, "status": "succeeded"}},
        }
    )


def two_charges(charged: list[StageResult], second: threading.Event) -> Any:
    """An agent charging once, and again once ``second`` is set."""

    async def agent(ctx: AgentContext) -> None:
        charged.append(await ctx.execute(charge(ctx)))
        while not second.is_set() and not ctx.stopping:
            await ctx.sleep(0.02)
        if not ctx.stopping:
            charged.append(await ctx.execute(charge(ctx)))
        while not ctx.stopping:
            await ctx.sleep(0.05)

    return agent


def test_a_reload_rotates_the_relay_and_inbox_keys_while_the_daemon_runs(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The planned rotation (docs/EPIC8_DESIGN.md §2.6): new versions at the key
    service, registered; a reload; the old keys revoked. Nothing is refused,
    nothing stops, and what the old keys attested still verifies."""
    from tests.fakekms import FakeKms

    kms = FakeKms(token=KMS_TOKEN)
    at_key_service(site, kms, ("relay", "inbox"), monkeypatch)
    # The operator acts between the vacuum's runs: one as it starts, none after.
    config = site.rewrite("every_seconds = 1\n", "every_seconds = 3600\n")
    old = {"relay": kms.key("relay").key_id, "inbox": kms.key("inbox").key_id}
    charged: list[StageResult] = []
    second = threading.Event()
    supervisor = build_supervisor(
        config, Application(checkers=[BlastRadius(5)], agents=[two_charges(charged, second)])
    )
    told: dict[str, Any] = {}

    def receipts() -> int:
        return supervisor.status()["settler"].counters.get("receipts", 0)

    async def run() -> None:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        await until(lambda: receipts() == 1)
        # 1. A new version of each key at the service, registered: both trusted.
        for role in ("relay", "inbox"):
            kms.rotate(role)
            register = ("keys", "register", "--role", role, "--name", f"{role}-2")
            code, said = await asyncio.to_thread(as_operator, site, *register, "--public-of", role)
            assert code == 0, said
        # 2. Every part opens again, signing with the new keys; the inbox
        # behind the listener it had, which never closed.
        listening = supervisor._running["inbox"].service._server  # type: ignore[attr-defined]
        told["reload"] = await supervisor.reload()
        assert supervisor._running["inbox"].service._server is listening  # type: ignore[attr-defined]
        # 3. The old keys revoked: what they attested, sealed.
        for role, key_id in old.items():
            revoke = ("keys", "revoke", "--role", role, key_id, "--reason", "rotated")
            code, told[role] = await asyncio.to_thread(as_operator, site, *revoke)
            assert code == 0, told[role]
        second.set()
        await until(lambda: receipts() == 2)
        port = supervisor.inbox_port
        assert port is not None
        for n, intent in enumerate(site.stripe.of("payment_intent")):
            # Bound to its delivery, the first's attested by the revoked key.
            answered = await asyncio.to_thread(post, port, payment_succeeded(intent, n))
            assert answered == (200, {"recorded": 1, "matched": 1}), answered
        supervisor.stop()
        await running

    try:
        asyncio.run(run())
    finally:
        kms.close()
    assert [r.committed for r in charged] == [True, True]
    assert told["reload"] == dict.fromkeys(("relay-0", "inbox", "settler", "vacuum"))
    assert "; 1 rows sealed" in told["relay"] and "; 0 rows sealed" in told["inbox"]
    # Each key signed only before its rotation, or only after.
    assert kms.signed[("relay", 1)] == 1 and kms.signed[("relay", 2)] == 1
    assert kms.signed[("inbox", 1)] == 0 and kms.signed[("inbox", 2)] == 4
    status = supervisor.status()
    assert all(s.failures == 0 for s in status.values()), status
    assert status["relay-0"].counters["reloads"] == 1
    # Everything verifies: the revoked keys' attestations under their seals.
    code, verified = cli(site, "outbox", "verify")
    assert code == 0, verified
    assert "2 key(s) registered by operators; 2 revoked" in verified
    code, verified = cli(site, "inbox", "verify")
    assert code == 0, verified


def test_a_part_whose_key_is_revoked_opens_again_with_the_key_it_is_given_now(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a compromise (docs/EPIC8_DESIGN.md §2.6) the old keys are revoked
    with no reload. The relay's next claim and the inbox's next pass find
    their keys revoked: each fails, and opens again with the key its service
    serves then."""
    from tests.fakekms import FakeKms

    kms = FakeKms(token=KMS_TOKEN)
    at_key_service(site, kms, ("relay", "inbox"), monkeypatch)
    config = site.rewrite("every_seconds = 1\n", "every_seconds = 3600\n")
    old = {"relay": kms.key("relay").key_id, "inbox": kms.key("inbox").key_id}
    charged: list[StageResult] = []
    second = threading.Event()
    supervisor = build_supervisor(
        config, Application(checkers=[BlastRadius(5)], agents=[two_charges(charged, second)])
    )

    def failed(name: str) -> bool:
        status = supervisor.status()[name]
        return status.failures >= 1 and status.state == "running"

    async def run() -> None:
        running = asyncio.create_task(supervisor.run())
        await asyncio.wait_for(supervisor.ready(), 30)
        await until(lambda: supervisor.status()["settler"].counters.get("receipts", 0) == 1)
        for role in ("relay", "inbox"):
            kms.rotate(role)
            register = ("keys", "register", "--role", role, "--name", f"{role}-2")
            code, said = await asyncio.to_thread(as_operator, site, *register, "--public-of", role)
            assert code == 0, said
            revoke = ("keys", "revoke", "--role", role, old[role], "--reason", "compromised")
            code, said = await asyncio.to_thread(as_operator, site, *revoke)
            assert code == 0, said
        await until(lambda: failed("relay-0") and failed("inbox"))
        second.set()
        await until(lambda: supervisor.status()["settler"].counters.get("receipts", 0) == 2)
        port = supervisor.inbox_port
        assert port is not None
        for n, intent in enumerate(site.stripe.of("payment_intent")):
            answered = await asyncio.to_thread(post, port, payment_succeeded(intent, n))
            assert answered == (200, {"recorded": 1, "matched": 1}), answered
        supervisor.stop()
        await running

    try:
        asyncio.run(run())
    finally:
        kms.close()
    assert [r.committed for r in charged] == [True, True]
    status = supervisor.status()
    for name in ("relay-0", "inbox"):
        assert (status[name].last_error or "").startswith("KeyRevokedError"), status[name]
    assert kms.signed[("relay", 2)] == 1 and kms.signed[("inbox", 2)] == 4
    assert cli(site, "outbox", "verify")[0] == 0
    assert cli(site, "inbox", "verify")[0] == 0


def test_interlock_daemon_reloads_on_sighup(site: Site, tmp_path: Path) -> None:
    """A key file replaced, its new key registered, and ``SIGHUP``: the relay
    opens again with it."""
    site.rewrite("every_seconds = 1\n", "every_seconds = 3600\n")
    daemon = Daemon(site.path)
    try:
        daemon.wait_for("interlock daemon running:")
        fresh = generate_key(tmp_path / "relay-2.key")
        os.replace(tmp_path / "relay-2.key", site.path.parent / "relay.key")
        register = ("keys", "register", "--role", "relay", "--name", "relay-2")
        code, said = as_operator(site, *register, "--public", fresh.public_key().spec())
        assert code == 0, said
        daemon.process.send_signal(signal.SIGHUP)
        reloaded = daemon.wait_for("reloaded:")
    finally:
        code = daemon.stop()
    assert code == 0, (daemon.lines, daemon.errors)
    assert reloaded == "reloaded: inbox, relay-0, vacuum"
    (relay,) = [line for line in daemon.lines if line.startswith("relay-0: stopped")]
    assert "0 failure(s)" in relay and "reloads 1" in relay


def test_a_key_registered_while_a_part_runs_is_trusted_at_its_first_use(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    import interlock.wiring
    from interlock.wiring import key_registry, live_keyring

    reads: list[int] = []

    def counted(config: InterlockConfig) -> Any:
        reads.append(1)
        return key_registry(config)

    keyring = live_keyring(site.config, "relay")
    assert keyring is not None
    monkeypatch.setattr(interlock.wiring, "key_registry", counted)
    fresh = generate_key(site.path.parent / "relay-2.key")
    assert fresh.key_id not in keyring and len(reads) == 1
    register = ("keys", "register", "--role", "relay", "--name", "relay-2")
    assert as_operator(site, *register, "--public", fresh.public_key().spec())[0] == 0
    reads.clear()
    assert keyring.verifier(fresh.key_id) is not None
    assert keyring.name(fresh.key_id) == "relay-2"
    # An id no one registered: the log is read again only once it changed.
    assert keyring.verifier("0123456789abcdef") is None
    assert keyring.verifier("fedcba9876543210") is None
    assert len(reads) == 1


def test_a_revoked_key_is_refused_before_anything_starts(site: Site, tmp_path: Path) -> None:
    from interlock.operators import load_key
    from interlock.wiring import RefusedError, operator_signer

    config = site.config
    keyring = config.relay_keyring()
    assert keyring is not None
    (relay_id,) = keyring.ids()
    code, said = as_operator(site, "keys", "revoke", "--role", "relay", relay_id)
    assert code == 0, said
    with pytest.raises(SubstrateConfigurationError, match="was revoked by operator record"):
        build_supervisor(config)
    assert cli(site, "relay", "--once")[0] == 2
    # An operator's key, revoked by another operator.
    ops = generate_key(tmp_path / "ops.key")
    register = ("keys", "register", "--role", "operator", "--name", "ops")
    assert as_operator(site, *register, "--public", ops.public_key().spec())[0] == 0
    vacuum_id = load_key(tmp_path / "vacuum.key").key_id
    revoke = ("keys", "revoke", "--role", "operator", vacuum_id, "--key", str(tmp_path / "ops.key"))
    code, said = cli(site, *revoke)
    assert code == 0, said
    with pytest.raises(RefusedError, match=r"the vacuum.s key .* was revoked by operator record"):
        operator_signer(config, None, tmp_path / "vacuum.key", part="vacuum")
    assert operator_signer(config, None, tmp_path / "ops.key", part="vacuum").key_id == ops.key_id


@pytest.mark.parametrize("part", ["relay", "inbox"])
def test_a_standalone_part_whose_key_is_revoked_stops_and_says_so(
    site: Site, part: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """``interlock relay`` and ``interlock inbox serve``: a key revoked while
    they run stops every worker, with exit status 3."""
    site.rewrite("every_seconds = 1\n", "every_seconds = 3600\n")
    config = site.config
    keys = config.relay_keyring() if part == "relay" else config.inbox_keyring()
    assert keys is not None
    (key_id,) = keys.ids()
    argv = ("relay",) if part == "relay" else ("inbox", "serve")
    exited: list[int] = []
    running = threading.Thread(target=lambda: exited.append(cli(site, *argv)[0]))
    running.start()
    try:
        time.sleep(0.3)  # serving: claiming, or matching
        assert as_operator(site, "keys", "revoke", "--role", part, key_id)[0] == 0
        running.join(timeout=30)
    finally:
        assert not running.is_alive(), f"interlock {' '.join(argv)} did not stop"
    assert exited == [3]
    assert "was revoked" in capsys.readouterr().err
