#!/usr/bin/env python3
"""The soak: the whole Interlock daemon under sustained concurrent load, on a live PostgreSQL.

(``docs/EPIC6_DESIGN.md`` §3.) One :class:`~interlock.supervisor.InterlockSupervisor`
runs every part of Interlock in this process (the engines, the relays, the
inbox, the settler and the vacuum), built by :func:`interlock.daemon.build_supervisor`
from an ``interlock.toml`` the soak writes, each part connecting as its own
role. Around it:

- **A payment API** on localhost, in Stripe's shape. It honours
  ``Idempotency-Key``, replaying a key's first result, and injects faults: a
  500 after it acted, a 429, a reply slower than the relay waits, latency.
- **The vendor's webhooks**, signed as Stripe signs them, for every payment
  and every refund: some duplicated, some sent before the relay has recorded
  the delivery they are about, some about objects Interlock never created,
  and some forged (another secret, a stale timestamp, a rewritten body, no
  signature at all).
- **Agents**, each its own AgentGov scope with several plans in flight:
  checkouts (an order row, and the charge for it carrying the refund that
  undoes it); reconciliations (a fact consumed, and the order updated to say
  what the fact says); notes on a few hot rows every agent contends for;
  and, now and then, a plan that must be refused.
- **An operator** compensating paid orders, every action signed.
- **An auditor** sampling the database throughout: lock waits, the rate
  windows' history, the outbox's size, what the vacuum has yet to prune.

The load runs for ``--minutes``. Then no new work starts, everything in
flight is delivered, settled and consumed, the daemon is stopped, and a
second one is started to find nothing to recover. Then each claim is proven
from the database, the ledger and the logs:

==========================  ====================================================================
Claim                       Measured by
==========================  ====================================================================
no deadlocks                ``pg_stat_database.deadlocks`` unchanged; no error says one happened
lock waits resolve          sampled waits within the stage lock timeout; every lost race retried
                            to an outcome; every plan answered
rate windows hold exactly   every key's history, at every row's commit instant, within the limit
                            over its span: rows the vacuum pruned included
the ledger balances         AgentGov's integrity and conservation; each plan charged once, exactly
                            its price; each refund credited once; no hold left open
exactly once                one object per idempotency key and per order; one receipt per
                            delivery; every event recorded once, every fact consumed once
no forgery accepted         every forged webhook answered 400 or 401, and recorded nowhere
the vacuum compacts         checkpoints throughout; messages, window rows and events pruned;
                            nothing prunable outlives its retention by more than a few runs
everything verifies         delivery logs, attestations, operators, settlements, the inbox, every
                            escrow chain and its anchors, the receipt log
shutdown is graceful        stopped within the drain bound, nothing cut; a second daemon
                            recovers nothing
==========================  ====================================================================

Run::

    uv run python scripts/live_stress_test.py --docker --minutes 5
    uv run python scripts/live_stress_test.py --dsn postgresql://admin:pw@localhost:5432/postgres

``--dsn`` names a server, and a role on it that may create databases and
roles: the soak creates a database and roles of its own, and drops them when
it is done (``--keep`` keeps them, and the run's files). ``--docker`` starts a
``postgres:16`` container for the run instead. Exit status: 0 when every claim
holds, 1 when one does not, 2 when the soak could not run.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import faulthandler
import hashlib
import heapq
import hmac
import http.client
import io
import itertools
import json
import logging
import os
import random
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psycopg
from agentgov import BudgetManager
from agentgov.core import EntryType
from psycopg import sql
from psycopg.conninfo import make_conninfo

from interlock import (
    BlastRadius,
    CrossEffectAgreement,
    EscrowChain,
    FactAgreement,
    OutboundCount,
    SinkAllowlist,
    TenantIsolation,
)
from interlock.config import InterlockConfig, load_config
from interlock.daemon import Application, build_supervisor
from interlock.exceptions import (
    ChainInUseError,
    InboundFactError,
    StageConflictError,
    SupervisorStoppedError,
)
from interlock.operators import Operator, OperatorLog, OperatorRefusedError, generate_key, load_key
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.supervisor import AgentContext, InterlockSupervisor, ServiceStatus
from interlock.types import InboundFact, OutboundRequest

logger = logging.getLogger("soak")

# --------------------------------------------------------------------------
# What the soak runs
# --------------------------------------------------------------------------

SINK = "payments"
SOURCE = "stripe"
API_KEY_ENV = "SOAK_STRIPE_KEY"
WEBHOOK_SECRET_ENV = "SOAK_WEBHOOK_SECRET"  # noqa: S105 - the name of a variable
OPERATORS_SCOPE = "interlock-operators"

SETTLE_COST = Decimal("0.01")
"""What producing a plan costs its scope, committed or refused."""
CALL_COST = Decimal("0.30")
"""What the registry prices a payment at: charged with the plan that
enqueues it, and credited back when it is compensated."""
ENVELOPE = Decimal("1000000.00")

STATUS_KINDS = ("payment_intent.succeeded", "payment_intent.payment_failed")
REFUND_KIND = "charge.refund.updated"
INITIAL = "awaiting_payment"
"""An order's status before any fact: the one value written without one."""

TENANTS = ("acme", "globex", "initech", "umbrella", "hooli", "stark", "wayne", "tyrell")
LOCK_TIMEOUT = 2.0
"""The stages' ``lock_timeout``: no stage waits on a lock longer."""
LEDGER_LOCK_TIMEOUT = 30.0
"""AgentGov's own: the longest any governor waits for the ledger."""

TENANT_WINDOW = "rate_window:plans_per_tenant"
BURST_EVERY = 15.0
BURST_SECONDS = 5.0

OUTCOMES = ("applied", "nothing", "refused", "rejected", "abandoned")
"""What a vacuum run can come to: only the first two are a vacuum keeping up."""

MISBEHAVIOURS = ("overcharge", "unfounded_status", "cross_tenant", "self_refund", "fact_replay")
"""Plans that must never commit: a charge for ten times the order, a status
no fact says, a write across two tenants, a refund the agent issues itself,
and a fact consumed twice."""

EXIT_OK, EXIT_FAILED, EXIT_ERROR = 0, 1, 2


class SoakError(Exception):
    """The soak could not run: no database, no Docker, a part that would not start."""


@dataclass(frozen=True)
class Settings:
    """How hard and how long (``--help``)."""

    minutes: float = 5.0
    agents: int = 4
    concurrency: int = 6
    workers: int = 8
    relays: int = 3
    tenants: int = 6
    seed: int = 2026
    retain: int = 15
    vacuum_every: int = 5
    margin: int = 5
    charge_limit: int = 40_000
    charge_span: float = 10.0
    tenant_limit: int = 25
    tenant_span: float = 5.0
    desk_every: float = 1.5
    quiesce: float = 180.0
    faults: float = 1.0
    quiet: bool = False

    @property
    def scopes(self) -> tuple[str, ...]:
        return tuple(f"soak-agent-{n}" for n in range(self.agents))

    @property
    def tenant_names(self) -> tuple[str, ...]:
        return TENANTS[: self.tenants]

    @property
    def slack(self) -> float:
        """How long past its retention a prunable row may stay: three vacuum
        runs, and the time one takes."""
        return 3 * self.vacuum_every + 10


# --------------------------------------------------------------------------
# PostgreSQL: a container for the run, or a server given by DSN
# --------------------------------------------------------------------------


@dataclass
class Cluster:
    """A PostgreSQL server, and a role on it that may create databases and roles."""

    admin: str
    container: str | None = None

    def logs(self) -> str:
        """The server's log, when the soak started it."""
        if self.container is None:
            return ""
        done = subprocess.run(
            ["docker", "logs", self.container],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        return done.stdout + done.stderr

    def close(self) -> None:
        if self.container is not None:
            subprocess.run(
                ["docker", "rm", "-f", self.container],
                capture_output=True,
                check=False,
                timeout=120,
            )
            self.container = None


def start_docker(image: str) -> Cluster:
    """A fresh ``image`` container, listening on a free port of localhost."""
    if shutil.which("docker") is None:
        raise SoakError("--docker needs docker on the PATH")
    name = f"interlock-soak-{secrets.token_hex(4)}"
    password = secrets.token_hex(16)
    command = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-e",
        f"POSTGRES_PASSWORD={password}",
        "-p",
        "127.0.0.1::5432",
        image,
        "-c",
        "max_connections=200",
        "-c",
        "log_lock_waits=on",
    ]
    started = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
    if started.returncode != 0:
        raise SoakError(f"docker run failed: {started.stderr.strip()}")
    cluster = Cluster("", name)
    try:
        mapped = subprocess.run(
            ["docker", "port", name, "5432/tcp"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.split()[0]
        port = int(mapped.rsplit(":", 1)[1])
        cluster.admin = f"postgresql://postgres:{password}@127.0.0.1:{port}/postgres"
        deadline = time.monotonic() + 120
        while True:
            try:
                with psycopg.connect(cluster.admin, connect_timeout=3) as conn:
                    conn.execute("SELECT 1")
                break
            except psycopg.Error:
                if time.monotonic() > deadline:
                    raise SoakError("the PostgreSQL container did not come up") from None
                time.sleep(0.5)
    except BaseException:
        cluster.close()
        raise
    return cluster


PARTS = ("stage", "relay", "inbox", "settle", "audit")
"""The roles the soak creates: one for each part that connects as its own."""

ORDERS_DDL = """
CREATE TABLE orders (
    id             bigint PRIMARY KEY,
    tenant         text NOT NULL,
    amount_cents   bigint NOT NULL CHECK (amount_cents > 0),
    status         text NOT NULL,
    refund_status  text,
    payment_intent text,
    note           text
)
"""
COLUMNS = ("id", "tenant", "amount_cents", "status", "refund_status", "payment_intent", "note")


@dataclass
class Site:
    """The soak's database on a cluster, its roles, and its files."""

    cluster: Cluster
    name: str
    directory: Path
    roles: dict[str, str]
    password: str
    created: bool = False

    @property
    def owner(self) -> str:
        """The database as the cluster's admin: it owns the tables, installs
        Interlock, owns the AgentGov ledger, and runs the vacuum."""
        return make_conninfo(self.cluster.admin, dbname=self.name)

    def dsn(self, part: str) -> str:
        return make_conninfo(self.owner, user=self.roles[part], password=self.password)

    def drop(self) -> None:
        """The database and the roles, whatever was created of them."""
        with psycopg.connect(self.cluster.admin, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(self.name))
            )
            for role in self.roles.values():
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def new_site(cluster: Cluster, directory: Path) -> Site:
    tag = secrets.token_hex(4)
    return Site(
        cluster,
        f"interlock_soak_{tag}",
        directory,
        {part: f"soak_{tag}_{part}" for part in PARTS},
        secrets.token_hex(16),
    )


def create_site(site: Site, settings: Settings) -> None:
    """A fresh database with the orders table, a role for each part, and the
    AgentGov ledger: a root scope for each agent and one for the operators."""
    cluster = site.cluster
    with psycopg.connect(cluster.admin, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(site.name))
        )
        site.created = True
        for role in site.roles.values():
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(site.password)
                )
            )
    roles = site.roles
    with psycopg.connect(site.owner, autocommit=True) as conn:
        conn.execute(ORDERS_DDL)
        conn.execute(
            sql.SQL("GRANT SELECT, INSERT, UPDATE ON orders TO {}").format(
                sql.Identifier(roles["stage"])
            )
        )
        conn.execute(sql.SQL("GRANT SELECT ON orders TO {}").format(sql.Identifier(roles["audit"])))
    from agentgov.postgres import PostgresStore

    with BudgetManager.open_postgres(site.owner) as governor:
        for scope in settings.scopes:
            governor.open_root(scope, ENVELOPE)
        governor.open_root(OPERATORS_SCOPE, "1.00")
        store = governor.store
        assert isinstance(store, PostgresStore)
        store.grant_join(roles["stage"])
    with psycopg.connect(site.owner, autocommit=True) as conn:
        # The relays' breaker reads the ledger, and writes nothing to it.
        relay = sql.Identifier(roles["relay"])
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA agentgov TO {}").format(relay))
        conn.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA agentgov TO {}").format(relay))


# --------------------------------------------------------------------------
# The configuration the daemon runs from
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Keys:
    """Every key the run signs with, written beside the configuration."""

    relay: Path
    inbox: Path
    desk: Path
    vacuum: Path
    receipts: Path

    @classmethod
    def generate(cls, directory: Path) -> Keys:
        paths = {name: directory / f"{name}.key" for name in cls.__dataclass_fields__}
        for path in paths.values():
            generate_key(path)
        return cls(**paths)

    def spec(self, name: str) -> str:
        return str(load_key(getattr(self, name)).public_key().spec())


def _q(text: str) -> str:
    """A TOML basic string."""
    return json.dumps(text)


def write_config(site: Site, settings: Settings, keys: Keys, api_port: int) -> Path:
    """The ``interlock.toml`` of the run: every part, configured as in production,
    with its times scaled down to seconds."""
    roles = site.roles
    text = f"""
substrate = "postgres"
database = {_q(site.owner)}
schema = "public"
stage_roles = [{_q(roles["stage"])}]
audit_roles = [{_q(roles["audit"])}]
relay_roles = [{_q(roles["relay"])}]
settler_roles = [{_q(roles["settle"])}]
inbox_roles = [{_q(roles["inbox"])}]

[[tables]]
name = "orders"
primary_key = "id"
columns = {json.dumps(list(COLUMNS))}
tenant_column = "tenant"

[[sinks]]
name = {_q(SINK)}
type = "stripe"
cost_per_call = {_q(str(CALL_COST))}
max_attempts = 25
backoff_base_seconds = 0.2
backoff_cap_seconds = 2
not_after_seconds = 3600

[[sinks.operations]]
name = {_q(PAYMENT_INTENTS_CREATE)}

[[sinks.operations]]
name = {_q(REFUNDS_CREATE)}

[[windows]]
name = "charged_per_agent"
span_seconds = {settings.charge_span}
limit = {settings.charge_limit}
per = "scope"
measure = "request_sum"
sink = {_q(SINK)}
operation = {_q(PAYMENT_INTENTS_CREATE)}
field = "amount"

[[windows]]
name = "plans_per_tenant"
span_seconds = {settings.tenant_span}
limit = {settings.tenant_limit}
per = "tenant"
measure = "plans"

[relays.keys]
soak-relay = {_q(keys.spec("relay"))}

[relay]
key = "relay.key"
database = {_q(site.dsn("relay"))}
ledger = {_q(site.dsn("relay"))}
breaker = "agentgov"
lease_seconds = 6
timeout_seconds = 1.5
poll_seconds = 0.2
batch = 4
workers = {settings.relays}

[[relay.endpoints]]
sink = {_q(SINK)}
url = {_q(f"http://127.0.0.1:{api_port}")}
secret_env = {_q(API_KEY_ENV)}

[operators]
log = "operators.ilok1"
ledger = {_q(site.owner)}
scope = {_q(OPERATORS_SCOPE)}

[operators.keys]
desk = {_q(keys.spec("desk"))}
vacuum = {_q(keys.spec("vacuum"))}

[inbox]
key = "inbox.key"
database = {_q(site.dsn("inbox"))}
listen = "127.0.0.1:0"
match_window_seconds = 600
match_every_seconds = 0.5

[[inbox.sources]]
name = {_q(SOURCE)}
kind = "stripe"
secret_env = {_q(WEBHOOK_SECRET_ENV)}
tolerance_seconds = 300

[inbox.keys]
soak-inbox = {_q(keys.spec("inbox"))}

[engine]
workers = {settings.workers}
database = {_q(site.dsn("stage"))}
chain = "escrow.chain"
settle_cost = {_q(str(SETTLE_COST))}
ledger = {_q(site.owner)}
same_transaction = true
conflict_retries = 32
max_stage_seconds = 10
lock_timeout_seconds = {LOCK_TIMEOUT}

[receipts]
log = "receipts.jsonl"
key = "receipts.key"
log_id = "soak-receipts"

[settler]
database = {_q(site.dsn("settle"))}
every_seconds = 1

[vacuum]
every_seconds = {settings.vacuum_every}
retain_seconds = {settings.retain}
margin_seconds = {settings.margin}
database = {_q(site.owner)}
key = "vacuum.key"

[daemon]
drain_timeout_seconds = 30
restart_min_seconds = 0.2
restart_max_seconds = 5
"""
    path = site.directory / "interlock.toml"
    path.write_text(text, encoding="utf-8")
    return path


def install(path: Path, keys: Keys) -> None:
    """``interlock install``, as an operator would run it: the schema, the
    roles' grants, and the sink registry, signed by the desk's key."""
    from interlock.cli import main as interlock

    out = io.StringIO()
    code = interlock(["install", "--config", str(path), "--key", str(keys.desk)], out=out)
    if code != 0:
        raise SoakError(f"interlock install failed ({code}):\n{out.getvalue()}")


def checkers() -> list[Any]:
    """The policy the agents' plans are adjudicated against. The rate windows
    of ``[[windows]]`` are added to it."""
    return [
        BlastRadius(4),
        TenantIsolation(),
        SinkAllowlist({SINK: [PAYMENT_INTENTS_CREATE]}),
        OutboundCount(1),
        CrossEffectAgreement(
            SINK, PAYMENT_INTENTS_CREATE, field="amount", table="orders", column="amount_cents"
        ),
        FactAgreement(
            STATUS_KINDS,
            field="status",
            table="orders",
            column="status",
            key=("id", "payment_intent"),
            exempt=[INITIAL],
        ),
        FactAgreement(
            REFUND_KIND,
            field="status",
            table="orders",
            column="refund_status",
            key=("payment_intent", "payment_intent"),
            exempt=[None],
        ),
    ]


# --------------------------------------------------------------------------
# The payment API: Stripe's shape, its faults, and its webhooks
# --------------------------------------------------------------------------


def parse_form(body: bytes) -> dict[str, Any]:
    """Stripe's bracket notation back into nested objects."""
    root: dict[str, Any] = {}
    for name, value in urllib.parse.parse_qsl(body.decode("ascii"), keep_blank_values=True):
        head, _, rest = name.partition("[")
        keys = [head] + ([part.rstrip("]") for part in ("[" + rest).split("[")[1:]] if rest else [])
        node: Any = root
        for index, key in enumerate(keys):
            if index == len(keys) - 1:
                node[key] = value
            else:
                node = node.setdefault(key, {})
    return root


def stripe_error(kind: str, code: str) -> dict[str, Any]:
    return {"error": {"type": kind, "code": code, "message": f"{kind}: {code}"}}


@dataclass(frozen=True)
class Faults:
    """How often the payment API misbehaves, per call."""

    rate_limited: float = 0.04
    """429, without acting."""
    slow: float = 0.02
    """Acts, then answers after the relay has stopped waiting."""
    error_after: float = 0.04
    """Acts, then answers 500: the outcome is unknown to the relay."""
    declined: float = 0.1
    """A payment that fails: ``requires_payment_method``."""
    slow_seconds: float = 2.5

    def scaled(self, factor: float) -> Faults:
        return Faults(
            self.rate_limited * factor,
            self.slow * factor,
            self.error_after * factor,
            self.declined,
            self.slow_seconds,
        )


class PaymentAPI:
    """Stripe, as far as the relay relies on it, on localhost.

    The first call with an ``Idempotency-Key`` acts, and its result is
    stored: every later call with the key is answered from the store, with
    ``Idempotent-Replayed: true``, and acts on nothing. A call while the key's
    first is still running is answered 409. Each object it creates is handed
    to the vendor, which sends its webhook.
    """

    def __init__(self, key: str, vendor: Vendor, faults: Faults, seed: int) -> None:
        self.key = key
        self._vendor = vendor
        self._faults = faults
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._tag = secrets.token_hex(3)
        self._numbers: Counter[str] = Counter()
        self._stored: dict[str, tuple[str, dict[str, Any], int, dict[str, Any]]] = {}
        self._running: set[str] = set()
        self.objects: dict[str, dict[str, Any]] = {}
        self.executions: Counter[str] = Counter()
        """Calls that acted, by idempotency key."""
        self.answers: Counter[str] = Counter()
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                api._handle(self)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="soak-payment-api", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length)
        if handler.headers.get("Authorization") != f"Bearer {self.key}":
            self._count("unauthorized")
            self._answer(handler, 401, stripe_error("invalid_request_error", "api_key_invalid"))
            return
        key = handler.headers.get("Idempotency-Key") or ""
        if not key:
            self._count("no_key")
            self._answer(handler, 400, stripe_error("invalid_request_error", "idempotency_key"))
            return
        params = parse_form(body)
        path = handler.path
        with self._lock:
            latency = self._rng.uniform(0.002, 0.03)
        time.sleep(latency)
        reply: tuple[int, dict[str, Any], dict[str, str]] | None = None
        mode = "ok"
        with self._lock:
            roll = self._rng.random()
            faults = self._faults
            if key in self._running:
                self.answers["in_use"] += 1
                reply = (409, stripe_error("invalid_request_error", "idempotency_key_in_use"), {})
            elif key in self._stored:
                stored_path, stored_params, status, result = self._stored[key]
                if stored_path != path or stored_params != params:
                    self.answers["key_reused"] += 1
                    reply = (400, stripe_error("idempotency_error", "idempotency_key_reused"), {})
                else:
                    self.answers["replayed"] += 1
                    reply = (status, result, {"Idempotent-Replayed": "true"})
            elif roll < faults.rate_limited:
                self.answers["rate_limited"] += 1
                reply = (429, stripe_error("rate_limit_error", "rate_limit"), {})
            else:
                roll -= faults.rate_limited
                mode = "slow" if roll < faults.slow else "ok"
                if mode == "ok" and roll - faults.slow < faults.error_after:
                    mode = "error_after"
                status, result = self._execute(path, params)
                self._stored[key] = (path, params, status, result)
                self.executions[key] += 1
                self.answers[f"acted_{mode}"] += 1
                if mode == "slow":
                    self._running.add(key)
        if reply is not None:
            self._answer(handler, reply[0], reply[1], reply[2])
            return
        if mode == "slow":
            try:
                time.sleep(self._faults.slow_seconds)
            finally:
                with self._lock:
                    self._running.discard(key)
            self._answer(handler, status, result)
        elif mode == "error_after":
            self._answer(handler, 500, stripe_error("api_error", "after_acting"))
        else:
            self._answer(handler, status, result)

    def _execute(self, path: str, params: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        """Act: under the lock, once per key."""
        now = int(time.time())
        if path == "/v1/payment_intents":
            declined = self._rng.random() < self._faults.declined
            intent: dict[str, Any] = {
                "id": self._id("pi"),
                "object": "payment_intent",
                "amount": int(params["amount"]),
                "amount_refunded": 0,
                "currency": params.get("currency", "usd"),
                "status": "requires_payment_method" if declined else "succeeded",
                "metadata": dict(params.get("metadata") or {}),
                "created": now,
                "livemode": False,
            }
            if declined:
                intent["failure_code"] = "card_declined"
            self.objects[intent["id"]] = intent
            self._vendor.created(dict(intent))
            return 200, dict(intent)
        if path == "/v1/refunds":
            charged = self.objects.get(str(params.get("payment_intent") or ""))
            if charged is None or charged["object"] != "payment_intent":
                return 404, stripe_error("invalid_request_error", "resource_missing")
            if charged["status"] != "succeeded":
                return 400, stripe_error("invalid_request_error", "charge_not_captured")
            left = int(charged["amount"]) - int(charged["amount_refunded"])
            amount = int(params.get("amount") or left)
            if left <= 0 or amount > left:
                return 400, stripe_error("invalid_request_error", "charge_already_refunded")
            charged["amount_refunded"] = int(charged["amount_refunded"]) + amount
            refund: dict[str, Any] = {
                "id": self._id("re"),
                "object": "refund",
                "amount": amount,
                "currency": charged["currency"],
                "payment_intent": charged["id"],
                "status": "succeeded",
                "reason": "requested_by_customer",
                "created": now,
            }
            self.objects[refund["id"]] = refund
            self._vendor.created(dict(refund))
            return 200, dict(refund)
        return 404, stripe_error("invalid_request_error", "unrecognized_url")

    def _id(self, prefix: str) -> str:
        self._numbers[prefix] += 1
        return f"{prefix}_{self._tag}{self._numbers[prefix]:07d}"

    def _count(self, answer: str) -> None:
        with self._lock:
            self.answers[answer] += 1

    @staticmethod
    def _answer(
        handler: BaseHTTPRequestHandler,
        status: int,
        document: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(document).encode()
        try:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                handler.send_header(name, value)
            handler.end_headers()
            handler.wfile.write(body)
        except OSError:  # the relay stopped waiting: nobody reads the reply
            pass

    def of(self, kind: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(o) for o in self.objects.values() if o["object"] == kind]


def stripe_signature(secret: str, body: bytes, at: int) -> str:
    """``Stripe-Signature`` over ``body``, signed at ``at``."""
    signed = hmac.new(secret.encode(), f"{at}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={at},v1={signed}"


@dataclass
class Webhook:
    """One send of an event to the inbox."""

    event: dict[str, Any]
    purpose: str
    """``genuine``, ``duplicate``, ``noise``, or ``forged:<how>``."""
    attempts: int = 0


@dataclass(frozen=True)
class Sent:
    event_id: str
    purpose: str
    status: int
    recorded: int
    matched: int


FORGERIES = ("wrong_secret", "stale", "tampered", "unsigned")


class Vendor:
    """The payment provider's webhooks: each object's event, signed when it is
    sent, retried while the inbox does not answer 2xx, as Stripe retries.

    Some are sent at once, before the relay can have recorded the delivery
    they are about; some twice; and beside them, events about objects nobody
    created, and forgeries of the real ones.
    """

    def __init__(self, secret: str, seed: int, *, senders: int = 4) -> None:
        self._secret = secret
        self._rng = random.Random(seed)
        self._lock = threading.Condition()
        self._heap: list[tuple[float, int, Webhook]] = []
        self._order = itertools.count()
        self._events = itertools.count(1)
        self._tag = secrets.token_hex(3)
        self._busy = 0
        self._stop = False
        self.url: tuple[str, int, str] | None = None
        self.sent: list[Sent] = []
        self.failures: Counter[str] = Counter()
        self.forged: set[str] = set()
        self._threads = [
            threading.Thread(target=self._send_loop, name=f"soak-vendor-{n}", daemon=True)
            for n in range(senders)
        ]

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def target(self, port: int) -> None:
        """Send to the inbox listening on ``port``."""
        with self._lock:
            self.url = ("127.0.0.1", port, f"/inbox/{SOURCE}")
            self._lock.notify_all()

    def close(self) -> None:
        with self._lock:
            self._stop = True
            self._lock.notify_all()
        for thread in self._threads:
            thread.join(timeout=15)

    def backlog(self) -> int:
        with self._lock:
            return len(self._heap) + self._busy

    def created(self, obj: Mapping[str, Any]) -> None:
        """The API created ``obj``: its event goes out, and what rides with it."""
        if obj["object"] == "payment_intent":
            kind = STATUS_KINDS[0] if obj["status"] == "succeeded" else STATUS_KINDS[1]
        else:
            kind = REFUND_KIND
        now = time.monotonic()
        with self._lock:
            rng = self._rng
            event = self._event(kind, obj)
            early = rng.random() < 0.2
            delay = 0.0 if early else rng.uniform(0.05, 1.5)
            self._push(now + delay, Webhook(event, "genuine"))
            if rng.random() < 0.15:
                self._push(now + delay + rng.uniform(0.2, 3.0), Webhook(event, "duplicate"))
            if rng.random() < 0.08:
                how = rng.choice(FORGERIES)
                forged = json.loads(json.dumps(event))
                forged["id"] = f"evt_forged{self._tag}{next(self._events):07d}"
                if kind == REFUND_KIND:
                    forged["data"]["object"]["amount"] = int(obj["amount"]) * 10
                else:
                    forged["type"] = STATUS_KINDS[0]
                    forged["data"]["object"]["status"] = "succeeded"
                self.forged.add(forged["id"])
                self._push(now + rng.uniform(0.0, 2.0), Webhook(forged, f"forged:{how}"))
            if rng.random() < 0.05:
                noise = dict(obj)
                noise["id"] = f"{obj['id'][:3]}noise{self._tag}{next(self._events):07d}"
                noise.pop("payment_intent", None)
                self._push(now + rng.uniform(0.0, 2.0), Webhook(self._event(kind, noise), "noise"))
            self._lock.notify_all()

    def _event(self, kind: str, obj: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": f"evt_{self._tag}{next(self._events):07d}",
            "object": "event",
            "type": kind,
            "api_version": "2024-06-20",
            "created": int(time.time()),
            "livemode": False,
            "data": {"object": dict(obj)},
        }

    def _push(self, at: float, webhook: Webhook) -> None:
        heapq.heappush(self._heap, (at, next(self._order), webhook))

    def _send_loop(self) -> None:
        while True:
            with self._lock:
                while True:
                    if self._stop:
                        return
                    now = time.monotonic()
                    if self.url is not None and self._heap and self._heap[0][0] <= now:
                        _, _, webhook = heapq.heappop(self._heap)
                        self._busy += 1
                        url = self.url
                        break
                    wait = 0.5 if not self._heap or self.url is None else self._heap[0][0] - now
                    self._lock.wait(timeout=max(0.001, min(wait, 0.5)))
            try:
                self._send(url, webhook)
            finally:
                with self._lock:
                    self._busy -= 1

    def _send(self, url: tuple[str, int, str], webhook: Webhook) -> None:
        body = json.dumps(webhook.event, separators=(",", ":")).encode()
        at = int(time.time())
        headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "Stripe/1.0"}
        purpose = webhook.purpose
        if purpose == "forged:wrong_secret":
            headers["Stripe-Signature"] = stripe_signature("whsec_" + "0" * 32, body, at)
        elif purpose == "forged:stale":
            headers["Stripe-Signature"] = stripe_signature(self._secret, body, at - 3600)
        elif purpose == "forged:tampered":
            headers["Stripe-Signature"] = stripe_signature(self._secret, body, at)
            body = body.replace(b'"livemode":false', b'"livemode":true', 1)
        elif purpose != "forged:unsigned":
            headers["Stripe-Signature"] = stripe_signature(self._secret, body, at)
        host, port, path = url
        status, answer = 0, {}
        try:
            conn = http.client.HTTPConnection(host, port, timeout=15)
            try:
                conn.request("POST", path, body=body, headers=headers)
                response = conn.getresponse()
                status = response.status
                with contextlib.suppress(ValueError):
                    answer = json.loads(response.read() or b"{}")
            finally:
                conn.close()
        except OSError as exc:
            self.failures[type(exc).__name__] += 1
        recorded = int(answer.get("recorded", 0)) if isinstance(answer, dict) else 0
        matched = int(answer.get("matched", 0)) if isinstance(answer, dict) else 0
        with self._lock:
            self.sent.append(Sent(webhook.event["id"], purpose, status, recorded, matched))
            if not 200 <= status < 300 and not purpose.startswith("forged:"):
                # As Stripe does: again, later, until the endpoint answers 2xx.
                webhook.attempts += 1
                if webhook.attempts < 12:
                    self._push(time.monotonic() + min(8.0, 0.25 * 2**webhook.attempts), webhook)
                    self._lock.notify_all()
                else:
                    self.failures["gave_up"] += 1


# --------------------------------------------------------------------------
# The agents
# --------------------------------------------------------------------------


@dataclass
class Order:
    order_id: int
    scope: str
    tenant: str
    amount: int
    plan_id: str
    committed: bool = False
    status: str = INITIAL
    payment_intent: str | None = None
    refund_status: str | None = None
    reconciled_at: float = 0.0
    compensated: bool = False


@dataclass
class PlanRecord:
    """What became of one plan an agent submitted."""

    kind: str
    scope: str
    committed: bool | None
    """``None``: no verdict, the plan raised."""
    blocked_by: tuple[str, ...] = ()
    error: str | None = None
    checkout: bool = False


INSERT_ORDER = (
    "INSERT INTO orders (id, tenant, amount_cents, status) "
    "VALUES (%(id)s, %(tenant)s, %(amount)s, %(status)s)"
)


class Workload:
    """The agents' shared memory, and the record of everything they did."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lock = threading.Lock()
        self.winding_down = threading.Event()
        self.orders: dict[int, Order] = {}
        self.by_plan: dict[str, int] = {}
        self.plans: dict[str, PlanRecord] = {}
        self.hot: dict[str, list[int]] = {t: [] for t in settings.tenant_names}
        self.by_tenant: dict[str, list[int]] = {t: [] for t in settings.tenant_names}
        self.burst: tuple[str, float] | None = None
        """A tenant every lane writes for, until a moment or its window refuses:
        whatever the machine's speed, the tenant window is pushed to its limit."""
        self.bursts: Counter[str] = Counter()
        self.consumed: dict[str, list[InboundFact]] = defaultdict(list)
        self.kinds: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()
        self.orphans = 0
        self.submitted = 0
        self.answered = 0
        self.inflight = 0
        self._ids = itertools.count(1)

    # -- submitting ---------------------------------------------------------

    async def submit(self, ctx: AgentContext, plan: Any, kind: str, scope: str) -> Any:
        """Execute ``plan``; record what became of it. ``None`` when it raised."""
        self.submitted += 1
        self.inflight += 1
        try:
            result = await ctx.execute(plan)
        except SupervisorStoppedError as exc:
            self._record(plan, kind, scope, None, error=f"stopped: {exc}")
            return None
        except StageConflictError as exc:
            self._record(plan, kind, scope, None, error=f"conflict: {exc}")
            return None
        except InboundFactError as exc:
            self._record(plan, kind, scope, None, error=f"fact: {exc}")
            return None
        except Exception as exc:  # recorded: the claims say whether it was expected
            self._record(plan, kind, scope, None, error=f"{type(exc).__name__}: {exc}")
            return None
        finally:
            self.inflight -= 1
            self.answered += 1
        self._record(plan, kind, scope, result.committed, blocked=result.blocked_by)
        return result

    def _record(
        self,
        plan: Any,
        kind: str,
        scope: str,
        committed: bool | None,
        *,
        blocked: tuple[str, ...] = (),
        error: str | None = None,
    ) -> None:
        checkout = kind in ("checkout", "misbehave:overcharge")
        self.plans[str(plan.plan_id)] = PlanRecord(
            kind, scope, committed, tuple(blocked), error, checkout
        )
        outcome = "error" if committed is None else "committed" if committed else "refused"
        self.kinds[f"{kind}:{outcome}"] += 1
        if error is not None:
            self.errors[f"{kind}: {error.split(':', 1)[0]}"] += 1

    # -- what agents do -------------------------------------------------------

    async def checkout(
        self, ctx: AgentContext, scope: str, rng: random.Random, *, overcharge: bool = False
    ) -> Any:
        tenant = rng.choice(self.settings.tenant_names)
        order_id = next(self._ids)
        amount = rng.randrange(500, 4501)
        plan = (
            ctx.plan(scope, intent=f"check out order {order_id}")
            .insert(
                table="orders",
                statement=INSERT_ORDER,
                parameters={"id": order_id, "tenant": tenant, "amount": amount, "status": INITIAL},
                tenant_id=tenant,
                stated_rows=1,
            )
            .enqueue(
                sink=SINK,
                operation=PAYMENT_INTENTS_CREATE,
                payload={
                    "amount": amount * 10 if overcharge else amount,
                    "currency": "usd",
                    "metadata": {"order": str(order_id)},
                },
                tenant_id=tenant,
                compensation=OutboundRequest(
                    SINK, REFUNDS_CREATE, {"payment_intent": {"$bind": "delivered.id"}}
                ),
            )
            .build()
        )
        order = Order(order_id, scope, tenant, amount, str(plan.plan_id))
        with self.lock:
            self.orders[order_id] = order
            self.by_plan[order.plan_id] = order_id
        result = await self.submit(
            ctx, plan, "misbehave:overcharge" if overcharge else "checkout", scope
        )
        if result is not None and result.committed:
            with self.lock:
                order.committed = True
                self.by_tenant[tenant].append(order_id)
                hot = self.hot[tenant]
                if len(hot) < 3:
                    hot.append(order_id)
        return result

    async def annotate(
        self, ctx: AgentContext, scope: str, rng: random.Random, *, tenant: str | None = None
    ) -> Any:
        """A note on one of a few hot rows every agent writes: contention. For
        a burst's ``tenant``, on any of its recent orders instead."""
        pool = self.by_tenant
        if tenant is None:
            tenant = rng.choice(self.settings.tenant_names)
            pool = self.hot
        with self.lock:
            rows = pool[tenant][-64:]
        if not rows:
            return await self.checkout(ctx, scope, rng)
        order_id = rng.choice(rows)
        plan = (
            ctx.plan(scope, intent=f"annotate order {order_id}")
            .update(
                table="orders",
                statement="UPDATE orders SET note = %(note)s WHERE id = %(id)s",
                parameters={"note": f"{scope} at {time.time():.3f}", "id": order_id},
                tenant_id=tenant,
                stated_rows=1,
            )
            .build()
        )
        return await self.submit(ctx, plan, "annotate", scope)

    async def reconcile(self, ctx: AgentContext, scope: str, fact: InboundFact) -> bool:
        """Consume ``fact`` and write what it says. Returns whether it is done
        with: consumed, or never to be."""
        with self.lock:
            order_id = self.by_plan.get(fact.plan_id)
            order = None if order_id is None else self.orders[order_id]
        if order is None:
            self.orphans += 1
            logger.warning("fact %s names plan %s, which no agent made", fact.fact_id, fact.plan_id)
            return True
        status = str(fact.fields.get("status", ""))
        if fact.kind in STATUS_KINDS:
            statement = (
                "UPDATE orders SET status = %(status)s, payment_intent = %(pi)s WHERE id = %(id)s"
            )
            parameters: dict[str, Any] = {
                "status": status,
                "pi": str(fact.fields.get("id", "")),
                "id": order.order_id,
            }
        else:
            statement = "UPDATE orders SET refund_status = %(status)s WHERE id = %(id)s"
            parameters = {"status": status, "id": order.order_id}
        plan = (
            ctx.plan(scope, intent=f"record {fact.kind} for order {order.order_id}")
            .consume(fact)
            .update(
                table="orders",
                statement=statement,
                parameters=parameters,
                tenant_id=order.tenant,
                stated_rows=1,
            )
            .build()
        )
        result = await self.submit(ctx, plan, "reconcile", scope)
        if result is None or not result.committed:
            return False
        with self.lock:
            if fact.kind in STATUS_KINDS:
                order.status = status
                order.payment_intent = str(parameters["pi"])
                order.reconciled_at = time.monotonic()
            else:
                order.refund_status = status
            self.consumed[scope].append(fact)
        return True

    async def misbehave(self, ctx: AgentContext, scope: str, rng: random.Random) -> None:
        """A plan that must be refused."""
        how = rng.choice(MISBEHAVIOURS)
        with self.lock:
            mine = [o for o in self.orders.values() if o.committed and o.scope == scope]
            others = [o for o in self.orders.values() if o.committed]
            replayable = list(self.consumed[scope])
        if how == "overcharge" or not mine:
            await self.checkout(ctx, scope, rng, overcharge=True)
            return
        builder = ctx.plan(scope, intent=f"misbehave: {how}")
        if how == "unfounded_status":
            order = rng.choice(mine)
            builder.update(
                table="orders",
                statement="UPDATE orders SET status = %(status)s WHERE id = %(id)s",
                parameters={"status": "refunded", "id": order.order_id},
                tenant_id=order.tenant,
                stated_rows=1,
            )
        elif how == "cross_tenant":
            first = rng.choice(mine)
            second = next((o for o in others if o.tenant != first.tenant), None)
            if second is None:
                await self.checkout(ctx, scope, rng, overcharge=True)
                return
            builder.update(
                table="orders",
                statement="UPDATE orders SET note = %(note)s WHERE id IN (%(a)s, %(b)s)",
                parameters={"note": "merged", "a": first.order_id, "b": second.order_id},
                tenant_id=first.tenant,
                stated_rows=2,
            )
        elif how == "self_refund":
            order = rng.choice(mine)
            builder.enqueue(
                sink=SINK,
                operation=REFUNDS_CREATE,
                payload={"payment_intent": order.payment_intent or "pi_unknown", "amount": 100},
                tenant_id=order.tenant,
            )
        else:  # fact_replay
            if not replayable:
                await self.checkout(ctx, scope, rng, overcharge=True)
                return
            fact = rng.choice(replayable)
            with self.lock:
                order_id = self.by_plan[fact.plan_id]
                order = self.orders[order_id]
            builder.consume(fact).update(
                table="orders",
                statement="UPDATE orders SET note = %(note)s WHERE id = %(id)s",
                parameters={"note": "again", "id": order.order_id},
                tenant_id=order.tenant,
                stated_rows=1,
            )
        await self.submit(ctx, builder.build(), f"misbehave:{how}", scope)

    def bursting(self) -> str | None:
        """The tenant of the burst under way, if one is."""
        burst = self.burst
        if burst is None or time.monotonic() > burst[1]:
            return None
        return burst[0]

    def refund_candidate(self, rng: random.Random, within: float) -> Order | None:
        """A paid order, reconciled within the last ``within`` seconds, not
        compensated yet: what the operator refunds."""
        now = time.monotonic()
        with self.lock:
            found = [
                o
                for o in self.orders.values()
                if o.status == "succeeded" and not o.compensated and now - o.reconciled_at < within
            ]
        return rng.choice(found) if found else None


def make_agent(workload: Workload, index: int) -> Callable[[AgentContext], Any]:
    """Agent ``index``: its scope, ``concurrency`` lanes, and a fact poller."""
    settings = workload.settings
    scope = settings.scopes[index]
    rng = random.Random(settings.seed * 1000 + index)

    async def agent(ctx: AgentContext) -> None:
        pending: asyncio.Queue[InboundFact] = asyncio.Queue()
        seen: set[uuid.UUID] = set()
        consumed: set[uuid.UUID] = set()

        async def poll() -> None:
            while not ctx.stopping:
                try:
                    facts = await ctx.facts(scope)
                except SupervisorStoppedError:
                    return
                except Exception as exc:  # the next poll tries again
                    logger.warning("%s: reading facts failed: %s", scope, exc)
                    facts = ()
                for fact in facts:
                    if fact.fact_id not in seen and fact.fact_id not in consumed:
                        seen.add(fact.fact_id)
                        pending.put_nowait(fact)
                await ctx.sleep(0.2)

        async def lane() -> None:
            while not ctx.stopping:
                try:
                    fact = pending.get_nowait()
                except asyncio.QueueEmpty:
                    fact = None
                if fact is not None:
                    if await workload.reconcile(ctx, scope, fact):
                        consumed.add(fact.fact_id)
                        seen.discard(fact.fact_id)
                    else:  # refused by a window, or lost a race: again shortly
                        await ctx.sleep(0.25)
                        pending.put_nowait(fact)
                    continue
                if workload.winding_down.is_set():
                    await ctx.sleep(0.1)
                    continue
                tenant = workload.bursting()
                if tenant is not None:
                    result = await workload.annotate(ctx, scope, rng, tenant=tenant)
                    if result is not None and TENANT_WINDOW in result.blocked_by:
                        workload.bursts[tenant] += 1
                        workload.burst = None  # the window is full: the burst made its point
                    continue
                roll = rng.random()
                if roll < 0.04:
                    await workload.misbehave(ctx, scope, rng)
                    continue
                if roll < 0.32:
                    await workload.annotate(ctx, scope, rng)
                    continue
                result = await workload.checkout(ctx, scope, rng)
                if result is not None and any(
                    b.startswith("rate_window") for b in result.blocked_by
                ):
                    # Told a window is full: an agent waits before it tries again.
                    await ctx.sleep(rng.uniform(0.2, 0.6))

        await asyncio.gather(poll(), *(lane() for _ in range(settings.concurrency)))

    agent.__name__ = f"agent_{index}"
    return agent


# --------------------------------------------------------------------------
# The operator's desk
# --------------------------------------------------------------------------


class Desk(threading.Thread):
    """An operator refunding paid orders, one signed action at a time. The
    operator log has one writer: the desk opens it for each action, as the
    daemon's vacuum does for each run, and waits its turn."""

    def __init__(self, config: InterlockConfig, site: Site, keys: Keys, workload: Workload) -> None:
        super().__init__(name="soak-desk", daemon=True)
        self._config = config
        self._site = site
        self._signer = load_key(keys.desk)
        self._workload = workload
        self._rng = random.Random(workload.settings.seed + 7)
        self._halt = threading.Event()
        self.applied = 0
        self.busy = 0
        self.refused: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        from interlock.deliveries import operations

        settings = self._workload.settings
        operators = self._config.operators
        assert operators is not None
        registry = self._config.sink_registry()
        governor = BudgetManager.open_postgres(self._site.owner)
        conn = psycopg.connect(self._site.owner, autocommit=True)
        try:
            outbox = operations(conn)
            while not self._halt.wait(settings.desk_every):
                if self._workload.winding_down.is_set():
                    return
                # Refunded while the charge is still in the outbox: a vacuum
                # prunes it once settled and past its retention.
                order = self._workload.refund_candidate(self._rng, settings.retain / 2)
                if order is None:
                    continue
                for _ in range(50):
                    try:
                        with OperatorLog(
                            operators.log,
                            self._signer,
                            operators.keyring(),
                            ledger=governor,
                            scope=operators.scope,
                        ) as log:
                            outcome = Operator(log, outbox).compensate(
                                plan_id=order.plan_id,
                                reason="the customer asked for a refund",
                                registry=registry,
                            )
                    except ChainInUseError:
                        self.busy += 1
                        time.sleep(0.1)
                        continue
                    except OperatorRefusedError as exc:
                        self.refused[str(exc)[:80]] += 1
                    except Exception as exc:
                        self.errors[f"{type(exc).__name__}: {str(exc)[:80]}"] += 1
                        logger.exception("the desk's compensation failed")
                    else:
                        if outcome.applied:
                            with self._workload.lock:
                                order.compensated = True
                            self.applied += 1
                        else:
                            self.refused["not applied"] += 1
                    break
        finally:
            conn.close()
            governor.close()


# --------------------------------------------------------------------------
# The auditor: what the database shows while it runs
# --------------------------------------------------------------------------

WAITS = """
SELECT a.usename::text, EXTRACT(EPOCH FROM clock_timestamp() - l.waitstart)::float8, l.locktype
  FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
 WHERE NOT l.granted AND l.waitstart IS NOT NULL AND a.datname = current_database()
"""

LINGERING_STAGES = """
WITH m AS (
    SELECT o.stage_id,
           s.state = 'cancelled'
           OR (s.state = 'delivered' AND EXISTS (
                   SELECT 1 FROM interlock.outbox_settlements t
                    WHERE t.message_id = o.message_id)) AS final,
           (SELECT max(a.at) FROM interlock.outbox_attempts a
             WHERE a.message_id = o.message_id) AS last_at
      FROM interlock.outbox o JOIN interlock.outbox_state s ON s.message_id = o.message_id
)
SELECT count(*) FROM (
    SELECT stage_id FROM m GROUP BY stage_id
    HAVING bool_and(final) AND max(last_at) < clock_timestamp() - make_interval(secs => %s)
) AS lingering
"""


@dataclass(frozen=True)
class Sample:
    at: float
    live: int
    pruned: int
    checkpoints: int
    lingering_stages: int
    lingering_windows: int
    events: int
    connections: int


class Auditor(threading.Thread):
    """Samples the database as the owner: every lock wait, every row of the
    rate windows' history before a vacuum can prune it, the outbox's size,
    and what a vacuum should have pruned by now and has not."""

    def __init__(self, site: Site, settings: Settings, started: float) -> None:
        super().__init__(name="soak-auditor", daemon=True)
        self._site = site
        self._settings = settings
        self._t0 = started
        self._halt = threading.Event()
        self.roles = {role: part for part, role in site.roles.items()}
        self.max_wait: dict[str, float] = defaultdict(float)
        self.waits = 0
        self.ticks = 0
        self.window_rows: dict[tuple[str, str, str], tuple[Decimal, datetime]] = {}
        self.event_ids: set[str] = set()
        self._last_seq = 0
        self.samples: list[Sample] = []
        self.errors: Counter[str] = Counter()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        conn = psycopg.connect(self._site.owner, autocommit=True)
        try:
            tick = 0
            while not self._halt.is_set():
                try:
                    self._tick(conn, heavy=tick % 4 == 0)
                except psycopg.Error as exc:
                    self.errors[type(exc).__name__] += 1
                    with contextlib.suppress(psycopg.Error):
                        conn.close()
                    conn = psycopg.connect(self._site.owner, autocommit=True)
                tick += 1
                self._halt.wait(0.5)
            self._tick(conn, heavy=True)
        finally:
            conn.close()

    def _tick(self, conn: psycopg.Connection[Any], *, heavy: bool) -> None:
        self.ticks += 1
        for user, waited, _ in conn.execute(WAITS).fetchall():
            part = self.roles.get(str(user), "owner")
            self.waits += 1
            self.max_wait[part] = max(self.max_wait[part], float(waited))
        for stage, window, key, amount, at in conn.execute(
            "SELECT stage_id::text, window_name, key, amount, at FROM interlock.window_ledger"
        ).fetchall():
            self.window_rows[(str(stage), str(window), str(key))] = (Decimal(amount), at)
        rows = conn.execute(
            "SELECT seq, event_id FROM interlock.inbox_events WHERE seq > %s ORDER BY seq",
            (self._last_seq,),
        ).fetchall()
        for seq, event_id in rows:
            self.event_ids.add(str(event_id))
            self._last_seq = max(self._last_seq, int(seq))
        if not heavy:
            return
        settings = self._settings
        live, pruned, checkpoints, events, connections = conn.execute(
            "SELECT (SELECT count(*) FROM interlock.outbox),"
            " (SELECT count(*) FROM interlock.outbox_compacted),"
            " (SELECT count(*) FROM interlock.checkpoints),"
            " (SELECT count(*) FROM interlock.inbox_events),"
            " (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database())"
        ).fetchone()
        (stages,) = conn.execute(LINGERING_STAGES, (settings.retain + settings.slack,)).fetchone()
        horizon = max(settings.charge_span, settings.tenant_span) + settings.margin + settings.slack
        (windows,) = conn.execute(
            "SELECT count(*) FROM interlock.window_ledger "
            "WHERE at < clock_timestamp() - make_interval(secs => %s)",
            (horizon,),
        ).fetchone()
        self.samples.append(
            Sample(
                time.monotonic() - self._t0,
                int(live),
                int(pruned),
                int(checkpoints),
                int(stages),
                int(windows),
                int(events),
                int(connections),
            )
        )


# --------------------------------------------------------------------------
# Running it
# --------------------------------------------------------------------------


class Captured(logging.Handler):
    """Every warning and error logged anywhere during the run."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.counts: Counter[str] = Counter()
        self.deadlocks: list[str] = []
        self._lock_ = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = record.getMessage()
        except Exception:  # a malformed record is still a record
            text = str(record.msg)
        if record.exc_info and record.exc_info[1] is not None:
            text += f" | {record.exc_info[1]}"
        with self._lock_:
            self.counts[f"{record.name}: {_shape(text)}"] += 1
            if "deadlock detected" in text:
                self.deadlocks.append(text[:300])


def _shape(text: str) -> str:
    """A message without what varies between its instances."""
    words = []
    for word in text.split()[:12]:
        if any(c.isdigit() for c in word) and len(word) > 6:
            words.append("…")
        else:
            words.append(word)
    return " ".join(words)[:140]


@dataclass
class Run:
    """Everything the run measured, for the claims."""

    settings: Settings
    config: InterlockConfig
    site: Site
    keys: Keys
    workload: Workload
    api: PaymentAPI
    vendor: Vendor
    desk: Desk
    auditor: Auditor
    captured: Captured
    deadlocks_before: int = 0
    deadlocks_after: int = 0
    started: float = 0.0
    load_seconds: float = 0.0
    quiesced: bool = False
    quiesce_seconds: float = 0.0
    outstanding: dict[str, int] = field(default_factory=dict)
    stop_seconds: float = 0.0
    status: dict[str, ServiceStatus] = field(default_factory=dict)
    second_status: dict[str, ServiceStatus] = field(default_factory=dict)
    second_ready: bool = False
    second_stop_seconds: float = 0.0
    live_at_end: int = 0
    total_at_end: int = 0
    failure: str | None = None


def deadlocks(dsn: str) -> int:
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
        ).fetchone()
    return int(row[0]) if row else 0


def outstanding(conn: psycopg.Connection[Any], run: Run) -> dict[str, int]:
    """What is still to happen before the run is settled."""
    (unfinished, dead, unsettled, unbound, pending) = conn.execute(
        """
        SELECT
          (SELECT count(*) FROM interlock.outbox_state
            WHERE state NOT IN ('delivered', 'cancelled', 'dead')),
          (SELECT count(*) FROM interlock.outbox_state WHERE state = 'dead'),
          (SELECT count(*) FROM interlock.outbox_state s
            WHERE s.state = 'delivered' AND NOT EXISTS (
                SELECT 1 FROM interlock.outbox_settlements t WHERE t.message_id = s.message_id)),
          (SELECT count(*) FROM interlock.inbox_events e
            WHERE e.refs NOT LIKE '%noise%'
              AND NOT EXISTS (SELECT 1 FROM interlock.inbox_facts f
                               WHERE f.source = e.source AND f.event_seq = e.seq)),
          (SELECT count(*) FROM interlock.inbox_facts f
            WHERE NOT EXISTS (SELECT 1 FROM interlock.inbox_consumed c
                               WHERE c.fact_id = f.fact_id))
        """
    ).fetchone()
    return {
        "undelivered messages": int(unfinished),
        "dead messages": int(dead),
        "unsettled deliveries": int(unsettled),
        "unbound events": int(unbound),
        "unconsumed facts": int(pending),
        "webhooks to send": run.vendor.backlog(),
        "plans in flight": run.workload.inflight,
    }


def say(settings: Settings, text: str) -> None:
    if not settings.quiet:
        print(text, flush=True)


def progress(run: Run, supervisor: InterlockSupervisor) -> str:
    status = supervisor.status()
    engines = status["engines"].counters if "engines" in status else {}
    delivered = sum(
        s.counters.get("delivered", 0) for name, s in status.items() if name.startswith("relay")
    )
    inbox = status["inbox"].counters if "inbox" in status else {}
    settler = status["settler"].counters if "settler" in status else {}
    vacuum = status["vacuum"].counters if "vacuum" in status else {}
    sample = run.auditor.samples[-1] if run.auditor.samples else None
    return (
        f"  {time.monotonic() - run.started:6.0f}s  plans {engines.get('committed', 0)} committed"
        f" / {engines.get('refused', 0)} refused / {engines.get('conflicts', 0)} conflicts"
        f"  delivered {delivered}  webhooks {inbox.get('answered_200', 0)}"
        f" (+{inbox.get('answered_401', 0) + inbox.get('answered_400', 0)} refused)"
        f"  matched {inbox.get('matched', 0)}  settled {settler.get('settled', 0)}"
        f"  credits {settler.get('credits', 0)}  vacuums {vacuum.get('applied', 0)}"
        + (f"  outbox {sample.live} live / {sample.pruned} pruned" if sample else "")
    )


async def drive(run: Run, supervisor: InterlockSupervisor) -> None:
    """Start the daemon, load it, wind it down, let it settle, and stop it:
    stopped whatever happens in between."""
    settings = run.settings
    runner = asyncio.create_task(supervisor.run(), name="soak-daemon")
    try:
        await started(run, supervisor, runner)
        await load(run, supervisor, runner)
        await settle(run, supervisor)
    finally:
        run.workload.winding_down.set()
        run.desk.stop()
        stopping = time.monotonic()
        supervisor.stop()
        with contextlib.suppress(Exception):
            await runner
        run.stop_seconds = time.monotonic() - stopping
        run.status = supervisor.status()
        run.auditor.stop()
        if run.auditor.is_alive():
            await asyncio.to_thread(run.auditor.join, 30)
        if run.desk.is_alive():
            await asyncio.to_thread(run.desk.join, 60)
    if not runner.cancelled() and runner.exception() is not None:
        raise SoakError(f"the daemon failed: {runner.exception()}")
    say(settings, f"daemon stopped in {run.stop_seconds:.2f}s")


async def started(run: Run, supervisor: InterlockSupervisor, runner: asyncio.Task[None]) -> None:
    """Until the daemon is ready; then the vendor, the auditor and the desk start."""
    ready = asyncio.create_task(supervisor.ready())
    await asyncio.wait({runner, ready}, timeout=180, return_when=asyncio.FIRST_COMPLETED)
    if not ready.done():
        ready.cancel()
        raise SoakError("the daemon was not ready within 180 seconds")
    if runner.done():
        raise SoakError("the daemon stopped before it was ready")
    port = supervisor.inbox_port
    if port is None:
        raise SoakError("the daemon runs no inbox")
    run.vendor.target(port)
    run.started = time.monotonic()
    run.auditor = Auditor(run.site, run.settings, run.started)
    run.auditor.start()
    run.desk.start()
    say(
        run.settings,
        f"daemon ready: inbox on 127.0.0.1:{port}; load for {run.settings.minutes:g} min",
    )


async def load(run: Run, supervisor: InterlockSupervisor, runner: asyncio.Task[None]) -> None:
    settings = run.settings
    end = run.started + settings.minutes * 60
    next_report = run.started + 10
    next_burst = run.started + BURST_EVERY
    tenants = itertools.cycle(settings.tenant_names)
    while (now := time.monotonic()) < end and not runner.done():
        await asyncio.sleep(min(1.0, end - now))
        if time.monotonic() >= next_burst:
            run.workload.burst = (next(tenants), time.monotonic() + BURST_SECONDS)
            next_burst += BURST_EVERY
        if time.monotonic() >= next_report:
            say(settings, progress(run, supervisor))
            next_report += 10
    run.load_seconds = time.monotonic() - run.started
    if runner.done():
        raise SoakError("the daemon stopped during the load")


async def settle(run: Run, supervisor: InterlockSupervisor) -> None:
    """No new work: until everything in flight is delivered, settled and
    consumed, or the quiesce bound passes."""
    settings = run.settings
    say(settings, "winding down: no new work; everything in flight settles")
    run.workload.winding_down.set()
    run.desk.stop()
    await asyncio.to_thread(run.desk.join, 60)
    begun = time.monotonic()
    conn = await asyncio.to_thread(psycopg.connect, run.site.owner, autocommit=True)
    try:
        calm = 0
        while time.monotonic() - begun < settings.quiesce:
            left = await asyncio.to_thread(outstanding, conn, run)
            run.outstanding = left
            busy = {k: v for k, v in left.items() if v and k != "dead messages"}
            calm = calm + 1 if not busy else 0
            if calm >= 3:
                run.quiesced = True
                break
            await asyncio.sleep(0.5)
        live, total = await asyncio.to_thread(
            lambda: (
                conn.execute(
                    "SELECT (SELECT count(*) FROM interlock.outbox),"
                    " (SELECT count(*) FROM interlock.outbox)"
                    " + (SELECT count(*) FROM interlock.outbox_compacted)"
                ).fetchone()
                or (0, 0)
            )
        )
        run.live_at_end, run.total_at_end = int(live), int(total)
    finally:
        conn.close()
    run.quiesce_seconds = time.monotonic() - begun
    say(settings, progress(run, supervisor))
    say(
        settings,
        f"{'settled' if run.quiesced else 'NOT settled'} in {run.quiesce_seconds:.1f}s"
        + ("" if run.quiesced else f": {run.outstanding}"),
    )


async def restart(run: Run) -> None:
    """A second daemon over the same files and database: it recovers nothing,
    and stops as cleanly."""
    supervisor = build_supervisor(run.config, Application(checkers=checkers()))
    runner = asyncio.create_task(supervisor.run(), name="soak-daemon-2")
    ready = asyncio.create_task(supervisor.ready())
    await asyncio.wait({runner, ready}, timeout=120, return_when=asyncio.FIRST_COMPLETED)
    run.second_ready = ready.done() and not runner.done()
    if not ready.done():
        ready.cancel()
    await asyncio.sleep(1.0)
    stopping = time.monotonic()
    supervisor.stop()
    await runner
    run.second_stop_seconds = time.monotonic() - stopping
    run.second_status = supervisor.status()


def soak(settings: Settings, cluster: Cluster, *, keep: bool, directory: Path | None) -> int:
    """Run the soak on ``cluster``; returns the exit status."""
    workdir = directory or Path(tempfile.mkdtemp(prefix="interlock-soak-"))
    workdir.mkdir(parents=True, exist_ok=True)
    captured = Captured()
    root = logging.getLogger()
    level = root.level
    root.addHandler(captured)
    file_log = logging.FileHandler(workdir / "soak.log")
    file_log.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(file_log)
    root.setLevel(logging.INFO)
    site = new_site(cluster, workdir)
    vendor: Vendor | None = None
    api: PaymentAPI | None = None
    try:
        create_site(site, settings)
        keys = Keys.generate(workdir)
        api_key = "sk_test_" + secrets.token_hex(12)
        webhook_secret = "whsec_" + secrets.token_hex(16)
        os.environ[API_KEY_ENV] = api_key
        os.environ[WEBHOOK_SECRET_ENV] = webhook_secret
        vendor = Vendor(webhook_secret, settings.seed + 1)
        api = PaymentAPI(api_key, vendor, Faults().scaled(settings.faults), settings.seed + 2)
        path = write_config(site, settings, keys, api.port)
        install(path, keys)
        config = load_config(path)
        say(settings, f"soak database {site.name}: Interlock installed, files in {workdir}")
        workload = Workload(settings)
        application = Application(
            checkers=checkers(),
            agents=[make_agent(workload, n) for n in range(settings.agents)],
        )
        supervisor = build_supervisor(config, application)
        api.start()
        vendor.start()
        run = Run(
            settings,
            config,
            site,
            keys,
            workload,
            api,
            vendor,
            Desk(config, site, keys, workload),
            Auditor(site, settings, time.monotonic()),
            captured,
        )
        run.deadlocks_before = deadlocks(site.owner)
        try:
            asyncio.run(drive(run, supervisor))
            asyncio.run(restart(run))
        except SoakError as exc:
            run.failure = str(exc)
        run.deadlocks_after = deadlocks(site.owner)
        claims = prove(run)
        report(run, claims)
        write_report(run, claims, workdir / "report.json")
        held = run.failure is None and all(c.held for c in claims)
        return EXIT_OK if held else EXIT_FAILED
    finally:
        if vendor is not None:
            vendor.close()
        if api is not None:
            api.close()
        root.removeHandler(captured)
        root.removeHandler(file_log)
        root.setLevel(level)
        file_log.close()
        if keep:
            print(f"kept: database {site.name} ({site.owner}), files in {workdir}")
        else:
            site.drop()
            if directory is None:
                shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# The claims
# --------------------------------------------------------------------------


@dataclass
class Claim:
    name: str
    held: bool
    evidence: list[str]


def prove(run: Run) -> list[Claim]:
    """Each claim, from the database, the ledger and the logs."""
    if run.failure is not None:
        return [Claim("the soak ran", False, [run.failure])]
    with psycopg.connect(run.site.owner, autocommit=True) as conn:
        governor = BudgetManager.open_postgres(run.site.owner, read_only=True)
        try:
            entries = tuple(governor.audit_trail())
            return [
                no_deadlocks(run),
                lock_waits_resolve(run),
                windows_hold(run),
                ledger_balances(run, conn, governor, entries),
                exactly_once(run, conn),
                no_forgery(run),
                vacuum_compacts(run, conn),
                everything_verifies(run, conn, entries),
                graceful(run),
            ]
        finally:
            governor.close()


def no_deadlocks(run: Run) -> Claim:
    moved = run.deadlocks_after - run.deadlocks_before
    logged = _cluster_log_deadlocks(run)
    evidence = [
        f"pg_stat_database.deadlocks: {run.deadlocks_before} before, {run.deadlocks_after} after",
        f"'deadlock detected' in what the daemon logged: {len(run.captured.deadlocks)}",
    ]
    if logged is not None:
        evidence.append(f"'deadlock detected' in the server's log: {logged}")
    held = moved == 0 and not run.captured.deadlocks and not logged
    evidence += run.captured.deadlocks[:3]
    return Claim("no deadlocks", held, evidence)


def _cluster_log_deadlocks(run: Run) -> int | None:
    text = run.site.cluster.logs()
    if not text and run.site.cluster.container is None:
        return None
    return text.count("deadlock detected")


def lock_waits_resolve(run: Run) -> Claim:
    auditor = run.auditor
    engines = run.status["engines"].counters if "engines" in run.status else {}
    stage_wait = auditor.max_wait.get("stage", 0.0)
    worst = max(auditor.max_wait.values(), default=0.0)
    expected_errors = sum(
        1 for p in run.workload.plans.values() if p.kind == "misbehave:fact_replay" and p.error
    )
    unexpected = {
        k: v for k, v in run.workload.errors.items() if not k.startswith("misbehave:fact_replay")
    }
    answered = run.workload.submitted == run.workload.answered and run.workload.inflight == 0
    counted = engines.get("committed", 0) + engines.get("refused", 0) + engines.get("failed", 0)
    held = (
        stage_wait <= LOCK_TIMEOUT + 0.5
        and worst <= LEDGER_LOCK_TIMEOUT + 1
        and engines.get("conflicts", 0) > 0
        and engines.get("conflicts_exhausted", 0) == 0
        and engines.get("unsettled", 0) == 0
        and engines.get("cancelled", 0) == 0
        and answered
        and counted == run.workload.submitted
        and engines.get("failed", 0) == expected_errors
        and not unexpected
    )
    return Claim(
        "lock waits resolve",
        held,
        [
            f"{auditor.ticks} samples of pg_locks: {auditor.waits} waits seen; longest by role: "
            + ", ".join(f"{k} {v:.2f}s" for k, v in sorted(auditor.max_wait.items()))
            + f" (stages bounded at {LOCK_TIMEOUT}s, the ledger at {LEDGER_LOCK_TIMEOUT}s)",
            f"lost races retried: {engines.get('conflicts', 0)}; given up: "
            f"{engines.get('conflicts_exhausted', 0)}",
            f"plans submitted {run.workload.submitted}, answered {run.workload.answered}, "
            f"staged to a verdict or error {counted}; cancelled {engines.get('cancelled', 0)}, "
            f"unsettled {engines.get('unsettled', 0)}",
            f"errors: {engines.get('failed', 0)} (fact replays refused at admission: "
            f"{expected_errors})" + (f"; unexpected: {dict(unexpected)}" if unexpected else ""),
        ],
    )


def windows_hold(run: Run) -> Claim:
    limits = {w.name: (w.limit, w.span) for w in run.config.windows}
    history: dict[tuple[str, str], list[tuple[datetime, Decimal, str]]] = defaultdict(list)
    for (stage, window, key), (amount, at) in run.auditor.window_rows.items():
        history[(window, key)].append((at, amount, stage))
    worst: dict[str, Decimal] = defaultdict(Decimal)
    breaches: list[str] = []
    for (window, key), rows in history.items():
        limit, span = limits[window]
        rows.sort()
        start = 0
        total = Decimal(0)
        for at, amount, _ in rows:
            total += amount
            while rows[start][0] <= at - span:
                total -= rows[start][1]
                start += 1
            worst[window] = max(worst[window], total / limit)
            if total > limit:
                breaches.append(f"{window} {key}: {total} within {span} ending {at.isoformat()}")
    refusals = Counter(
        b for p in run.workload.plans.values() for b in p.blocked_by if b.startswith("rate_window")
    )
    committed = sum(1 for p in run.workload.plans.values() if p.committed)
    checkouts = sum(1 for p in run.workload.plans.values() if p.committed and p.checkout)
    stages = {w: len({s for (s, n, _) in run.auditor.window_rows if n == w}) for w in limits}
    complete = (
        stages.get("plans_per_tenant") == committed and stages.get("charged_per_agent") == checkouts
    )
    exercised = all(refusals.get(f"rate_window:{w}", 0) > 0 for w in limits)
    held = not breaches and complete and exercised
    return Claim(
        "rate windows hold exactly",
        held,
        [
            f"{len(run.auditor.window_rows)} rows of history checked, the vacuum's included: "
            + ", ".join(
                f"{w}: {stages[w]} plans, fullest at {worst[w]:.0%} of its limit"
                for w in sorted(limits)
            ),
            "refused by each window: "
            + ", ".join(f"{w} {refusals.get(f'rate_window:{w}', 0)}" for w in sorted(limits))
            + f" ({sum(run.workload.bursts.values())} bursts for one tenant filled its window)",
            f"every committed plan's rows seen: {committed} committed, {checkouts} of them charges",
            *(breaches[:5] or ["no key ever held more than its limit within its span"]),
        ],
    )


def ledger_balances(
    run: Run, conn: psycopg.Connection[Any], governor: BudgetManager, entries: Sequence[Any]
) -> Claim:
    problems: list[str] = []
    try:
        governor.verify_integrity()
    except Exception as exc:
        problems.append(f"verify_integrity: {exc}")
    claims = governor.pending_claims()
    holds = governor.stale_authorizations(0)
    if claims:
        problems.append(f"{len(claims)} settlement claim(s) never redeemed")
    if holds:
        problems.append(f"{len(holds)} hold(s) left open")
    memo_plan: dict[str, str] = {}
    for path in chain_paths(run):
        for record in EscrowChain.load(path).records():
            memo_plan[f"interlock:{record.record_hash[:16]}"] = str(record.plan_id)
    scopes = set(run.settings.scopes)
    charged: dict[str, list[Decimal]] = defaultdict(list)
    credits: dict[str, list[Decimal]] = defaultdict(list)
    for entry in entries:
        if entry.scope_id not in scopes:
            continue
        if entry.entry_type is EntryType.SPEND:
            plan = memo_plan.get(entry.memo)
            if plan is None:
                problems.append(f"spend {entry.sequence} names no plan a chain holds: {entry.memo}")
            else:
                charged[plan].append(entry.amount)
        elif entry.entry_type is EntryType.REVERSAL:
            credits[entry.scope_id].append(entry.amount)
    spent: dict[str, Decimal] = defaultdict(Decimal)
    for plan_id, record in run.workload.plans.items():
        got = charged.pop(plan_id, [])
        if record.committed is None:
            if got:
                problems.append(f"plan {plan_id} raised, and was charged {got}")
            continue
        price = SETTLE_COST + (CALL_COST if record.committed and record.checkout else Decimal(0))
        if got != [price]:
            problems.append(f"plan {plan_id} ({record.kind}) was charged {got}, not [{price}]")
        spent[record.scope] += sum(got, Decimal(0))
    for plan_id, got in charged.items():
        problems.append(f"plan {plan_id}, which no agent submitted, was charged {got}")
    credited = conn.execute(
        "SELECT (SELECT count(*) FROM interlock.outbox_settlements WHERE credit IS NOT NULL)"
        " + (SELECT count(*) FROM interlock.outbox_compacted WHERE credit IS NOT NULL)"
    ).fetchone()[0]
    all_credits = [a for amounts in credits.values() for a in amounts]
    if len(all_credits) != int(credited) or any(a != CALL_COST for a in all_credits):
        problems.append(
            f"{len(all_credits)} credit(s) in the ledger, {credited} settled; amounts "
            f"{sorted(set(all_credits))}"
        )
    if int(credited) != run.desk.applied:
        # Every refund the desk made was delivered and settled: each earns
        # back what its payment was charged.
        problems.append(f"{run.desk.applied} refunds made, {credited} credited")
    for scope in sorted(scopes):
        expected = ENVELOPE - spent[scope] + sum(credits[scope], Decimal(0))
        available = governor.available(scope)
        if available != expected:
            problems.append(f"{scope}: {available} available, {expected} expected")
    total = sum(spent.values(), Decimal(0))
    return Claim(
        "the ledger balances",
        not problems,
        [
            f"AgentGov: {len(entries)} entries; integrity and conservation verified"
            if not any(p.startswith("verify_integrity") for p in problems)
            else "AgentGov's integrity check FAILED",
            f"{sum(1 for r in run.workload.plans.values() if r.committed is not None)} plans "
            f"charged once each, exactly their price: {total} in all",
            f"{len(all_credits)} of {run.desk.applied} refunds credited back at {CALL_COST}, "
            f"each once",
            f"no hold left open ({len(holds)}), no claim unredeemed ({len(claims)})",
            *problems[:8],
        ],
    )


def chain_paths(run: Run) -> list[Path]:
    engine = run.config.engine
    return [
        path
        for index in range(engine.workers)
        if (path := engine.chain_for(index, engine.workers)) is not None
    ]


def exactly_once(run: Run, conn: psycopg.Connection[Any]) -> Claim:
    problems: list[str] = []
    api = run.api
    twice = [k for k, n in api.executions.items() if n > 1]
    if twice:
        problems.append(f"{len(twice)} idempotency key(s) acted on more than once")
    intents = api.of("payment_intent")
    refunds = api.of("refund")
    per_order = Counter(str(i["metadata"].get("order")) for i in intents)
    charged_twice = [o for o, n in per_order.items() if n > 1]
    if charged_twice:
        problems.append(f"orders charged twice: {charged_twice[:5]}")
    committed = {str(o.order_id) for o in run.workload.orders.values() if o.committed}
    if set(per_order) != committed:
        problems.append(
            f"{len(committed - set(per_order))} committed order(s) never charged, "
            f"{len(set(per_order) - committed)} charge(s) for no committed order"
        )
    per_intent = Counter(str(r["payment_intent"]) for r in refunds)
    if any(n > 1 for n in per_intent.values()):
        problems.append("a payment refunded twice")
    if len(refunds) != run.desk.applied:
        problems.append(
            f"{len(refunds)} refund(s) made, {run.desk.applied} compensation(s) applied"
        )
    states = dict(
        conn.execute("SELECT s.state, count(*) FROM interlock.outbox_state s GROUP BY 1").fetchall()
    )
    pruned = dict(
        conn.execute("SELECT state, count(*) FROM interlock.outbox_compacted GROUP BY 1").fetchall()
    )
    delivered = int(states.get("delivered", 0)) + int(pruned.get("delivered", 0))
    others = {k: v for k, v in states.items() if k != "delivered"}
    if others:
        problems.append(f"messages not delivered: {others}")
    if delivered != len(intents) + len(refunds):
        problems.append(f"{delivered} delivered, {len(intents) + len(refunds)} objects created")
    (twice_delivered,) = conn.execute(
        "SELECT count(*) FROM (SELECT message_id FROM interlock.outbox_attempts"
        " WHERE event = 'delivered' GROUP BY message_id HAVING count(*) > 1) AS d"
    ).fetchone()
    if twice_delivered:
        problems.append(f"{twice_delivered} message(s) recorded delivered twice")
    (unreceipted,) = conn.execute(
        "SELECT (SELECT count(*) FROM interlock.outbox_settlements WHERE receipt_id IS NULL)"
        " + (SELECT count(*) FROM interlock.outbox_compacted"
        "     WHERE state = 'delivered' AND receipt_id IS NULL)"
    ).fetchone()
    from agentgov.receipts import ReceiptLog

    receipts = run.config.receipts
    assert receipts is not None
    log = ReceiptLog(receipts.log_id, load_key(receipts.key), path=receipts.log)
    try:
        per_message = Counter(str(d.request.message_id) for d in log.deliveries())
        actions = len(log) - sum(per_message.values())
    finally:
        log.close()
    if unreceipted or len(per_message) != delivered or any(n > 1 for n in per_message.values()):
        problems.append(
            f"{len(per_message)} message(s) receipted for {delivered} delivered; "
            f"{unreceipted} settled without one"
        )
    events, distinct, facts, consumed_twice, unconsumed = conn.execute(
        "SELECT (SELECT count(*) FROM interlock.inbox_events),"
        " (SELECT count(DISTINCT (source, event_id)) FROM interlock.inbox_events),"
        " (SELECT count(*) FROM interlock.inbox_facts),"
        " (SELECT count(*) - count(DISTINCT fact_id) FROM interlock.inbox_consumed),"
        " (SELECT count(*) FROM interlock.inbox_facts f WHERE NOT EXISTS"
        "   (SELECT 1 FROM interlock.inbox_consumed c WHERE c.fact_id = f.fact_id))"
    ).fetchone()
    if events != distinct or consumed_twice or unconsumed:
        problems.append(
            f"{events} events for {distinct} ids; facts consumed twice {consumed_twice}, "
            f"never {unconsumed}"
        )
    genuine = [s for s in run.vendor.sent if s.purpose == "genuine" and s.status == 200]
    duplicates = [s for s in run.vendor.sent if s.purpose == "duplicate" and s.status == 200]
    recorded_twice = [s for s in duplicates if s.recorded]
    if recorded_twice:
        problems.append(f"{len(recorded_twice)} duplicate webhook(s) recorded again")
    early = sum(1 for s in genuine if s.recorded and not s.matched)
    return Claim(
        "exactly once",
        not problems,
        [
            f"payment API: {sum(api.executions.values())} calls acted, each on its own key; "
            f"{api.answers.get('replayed', 0)} replays of a key's result, "
            f"{api.answers.get('in_use', 0)} answered 409 while its first was running",
            f"{len(intents)} payments for {len(committed)} committed orders, none twice; "
            f"{len(refunds)} refunds for {run.desk.applied} compensations",
            f"{delivered} messages delivered once each, {delivered} delivery receipts "
            f"({actions} action receipts beside them)",
            f"{events} events recorded, one per id ({len(duplicates)} duplicates answered and "
            f"not recorded again; {early} arrived before their delivery was recorded and were "
            f"bound later); {facts} facts, each consumed once",
            *problems[:8],
        ],
    )


def no_forgery(run: Run) -> Claim:
    forged = [s for s in run.vendor.sent if s.purpose.startswith("forged:")]
    by_how = Counter((s.purpose.split(":", 1)[1], s.status) for s in forged)
    accepted = [s for s in forged if s.status not in (400, 401)]
    recorded = run.vendor.forged & run.auditor.event_ids
    held = bool(forged) and not accepted and not recorded
    return Claim(
        "no forgery accepted",
        held,
        [
            f"{len(forged)} forged webhooks sent: "
            + ", ".join(f"{how} -> {status} x{n}" for (how, status), n in sorted(by_how.items())),
            f"answered otherwise: {len(accepted)}; recorded: {len(recorded)}",
        ],
    )


def vacuum_compacts(run: Run, conn: psycopg.Connection[Any]) -> Claim:
    vacuum = run.status.get("vacuum")
    counters = dict(vacuum.counters) if vacuum is not None else {}
    checkpoints = conn.execute("SELECT seq, at FROM interlock.checkpoints ORDER BY seq").fetchall()
    samples = run.auditor.samples
    warm = run.settings.retain + run.settings.slack + 5
    late = [s for s in samples if s.at > warm and s.at <= run.load_seconds]
    lingering = max((s.lingering_stages for s in late), default=0)
    stale = max((s.lingering_windows for s in late), default=0)
    live_max = max((s.live for s in samples), default=0)
    spread = len({int(s.checkpoints) for s in samples})
    held = (
        counters.get("applied", 0) >= 2
        and not any(counters.get(k, 0) for k in ("refused", "rejected", "abandoned"))
        and counters.get("messages", 0) > 0
        and counters.get("window_rows", 0) > 0
        and counters.get("inbox_events", 0) > 0
        and len(checkpoints) >= 2
        and spread >= 3
        and lingering == 0
        and stale == 0
    )
    return Claim(
        "the vacuum compacts as it goes",
        held,
        [
            f"{len(checkpoints)} checkpoints signed, anchored and applied over the run; "
            f"the daemon's vacuum runs: "
            + ", ".join(f"{k} {counters.get(k, 0)}" for k in OUTCOMES)
            + f"; {counters.get('busy', 0)} put off while the desk held the operator log",
            f"pruned: {counters.get('messages', 0)} messages, "
            f"{counters.get('window_rows', 0)} window rows, "
            f"{counters.get('inbox_events', 0)} inbound events",
            f"the live outbox peaked at {live_max} messages; {run.live_at_end} of "
            f"{run.total_at_end} ever enqueued were still live at the end",
            f"prunable and still there past retention plus {run.settings.slack}s: at most "
            f"{lingering} stages and {stale} window rows in {len(late)} samples",
        ],
    )


def everything_verifies(run: Run, conn: psycopg.Connection[Any], entries: Sequence[Any]) -> Claim:
    from agentgov.receipts import ReceiptLog

    from interlock.attestations import verify_attestations
    from interlock.deliveries import verify_delivery_log
    from interlock.inbox import verify_inbox
    from interlock.operators import legacy_vouch, verify_operators
    from interlock.records import read_records
    from interlock.settlement import verify_settlements

    config = run.config
    operators = config.operators
    relays = config.relay_keyring()
    inbox = config.inbox_keyring()
    receipts = config.receipts
    assert operators is not None and relays is not None and inbox is not None
    assert receipts is not None
    found: dict[str, list[str]] = {}
    records = read_records(operators.log)
    found["delivery logs"] = list(verify_delivery_log(conn))
    found["attestations"] = list(
        verify_attestations(
            conn, relays, legacy=legacy_vouch(records, operators.keyring())
        ).problems
    )
    found["operators"] = list(
        verify_operators(conn, records, operators.keyring(), ledger=entries).problems
    )
    log = ReceiptLog(receipts.log_id, load_key(receipts.key), path=receipts.log)
    try:
        found["settlements"] = list(
            verify_settlements(conn, log=log, relays=relays, ledger=entries)
        )
        receipt_count = len(log)
    finally:
        log.close()
    report = verify_inbox(conn, inbox, relays=relays)
    found["inbox"] = list(report.problems)
    chains = 0
    found["escrow chains"] = []
    for path in chain_paths(run):
        try:
            chain = EscrowChain.load(path)
            chain.verify_anchors()
            chains += len(chain.records())
        except Exception as exc:
            found["escrow chains"].append(f"{path.name}: {exc}")
    problems = [f"{what}: {p}" for what, items in found.items() for p in items]
    return Claim(
        "everything verifies after",
        not problems,
        [
            f"delivery logs, relays' attestations, {len(records)} operator records with their "
            f"AgentGov anchors, settlements against {receipt_count} receipts, "
            f"{report.events} inbound events and {report.facts} facts, "
            f"{len(chain_paths(run))} escrow chains ({chains} records) with their anchors",
            *(problems[:8] or ["no problem found"]),
        ],
    )


def graceful(run: Run) -> Claim:
    states = {name: s.state for name, s in run.status.items()}
    engines = run.status["engines"].counters if "engines" in run.status else {}
    second = run.second_status
    recovered = second["engines"].counters.get("recovered", 0) if "engines" in second else -1
    failed = {n: s.last_error for n, s in second.items() if s.failures}
    stopped = all(state == "stopped" for state in states.values())
    held = (
        run.quiesced
        and stopped
        and run.stop_seconds <= 30
        and engines.get("cancelled", 0) == 0
        and run.second_ready
        and recovered == 0
        and not failed
        and all(s.state == "stopped" for s in second.values())
    )
    return Claim(
        "shutdown is graceful",
        held,
        [
            f"settled after the load in {run.quiesce_seconds:.1f}s"
            + ("" if run.quiesced else f" -- NOT: {run.outstanding}"),
            f"stopped in {run.stop_seconds:.2f}s (bound 30s); every part stopped: {stopped}; "
            f"plans cancelled: {engines.get('cancelled', 0)}",
            f"a second daemon: ready {run.second_ready}, recovered {recovered} intents, "
            f"stopped in {run.second_stop_seconds:.2f}s"
            + (f"; failures {failed}" if failed else ""),
        ],
    )


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def report(run: Run, claims: Sequence[Claim]) -> None:
    workload = run.workload
    print()
    print("=" * 100)
    print(
        f"Interlock soak: {run.settings.agents} agents x {run.settings.concurrency} plans in "
        f"flight, {run.settings.workers} engines, {run.settings.relays} relays, "
        f"{run.load_seconds / 60:.1f} min of load, seed {run.settings.seed}"
    )
    print("-" * 100)
    kinds = Counter[str]()
    for key, count in workload.kinds.items():
        kinds[key] += count
    print("plans: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
    refused = Counter(
        b for p in workload.plans.values() for b in p.blocked_by if p.committed is False
    )
    print("refused by: " + ", ".join(f"{k} {v}" for k, v in refused.most_common()))
    print(
        f"payment API: {dict(sorted(run.api.answers.items()))}; desk: {run.desk.applied} "
        f"refunds, {run.desk.busy} waits for the operator log, refused {dict(run.desk.refused)}"
        + (f", errors {dict(run.desk.errors)}" if run.desk.errors else "")
    )
    sent = Counter(s.purpose for s in run.vendor.sent)
    failures = dict(run.vendor.failures)
    print(f"webhooks sent: {dict(sorted(sent.items()))}; transport failures {failures}")
    if run.captured.counts:
        print("logged warnings (most frequent):")
        for text, count in run.captured.counts.most_common(8):
            print(f"  {count:6d}  {text}")
    print("-" * 100)
    for claim in claims:
        print(f"[{'PASS' if claim.held else 'FAIL'}] {claim.name}")
        for line in claim.evidence:
            print(f"       {line}")
    print("=" * 100)
    held = run.failure is None and all(c.held for c in claims)
    print("EVERY CLAIM HOLDS" if held else "A CLAIM DOES NOT HOLD")


def write_report(run: Run, claims: Sequence[Claim], path: Path) -> None:
    document = {
        "settings": {k: getattr(run.settings, k) for k in run.settings.__dataclass_fields__},
        "load_seconds": run.load_seconds,
        "claims": [{"name": c.name, "held": c.held, "evidence": c.evidence} for c in claims],
        "plans": dict(run.workload.kinds),
        "status": {
            name: {"state": s.state, "counters": dict(s.counters), "failures": s.failures}
            for name, s in run.status.items()
        },
        "samples": [s.__dict__ for s in run.auditor.samples],
    }
    path.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------


def parse(argv: Sequence[str] | None) -> tuple[Settings, argparse.Namespace]:
    parser = argparse.ArgumentParser(
        prog="live_stress_test.py",
        description="Soak the whole Interlock daemon against a live PostgreSQL.",
    )
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--docker", action="store_true", help="start postgres:16 for the run")
    where.add_argument(
        "--dsn",
        help="a server, as a role that may create databases and roles (default: "
        "$INTERLOCK_SOAK_DSN, else $INTERLOCK_TEST_POSTGRES_DSN)",
    )
    parser.add_argument("--image", default="postgres:16")
    defaults = Settings()
    parser.add_argument("--minutes", type=float, default=defaults.minutes)
    parser.add_argument("--agents", type=int, default=defaults.agents)
    parser.add_argument("--concurrency", type=int, default=defaults.concurrency)
    parser.add_argument("--workers", type=int, default=defaults.workers)
    parser.add_argument("--relays", type=int, default=defaults.relays)
    parser.add_argument("--tenants", type=int, default=defaults.tenants)
    parser.add_argument("--seed", type=int, default=defaults.seed)
    parser.add_argument("--retain", type=int, default=defaults.retain, help="seconds")
    parser.add_argument("--vacuum-every", type=int, default=defaults.vacuum_every)
    parser.add_argument("--faults", type=float, default=defaults.faults, help="fault scale")
    parser.add_argument("--quiesce", type=float, default=defaults.quiesce)
    parser.add_argument("--keep", action="store_true", help="keep the database and the files")
    parser.add_argument("--dir", type=Path, help="where the run's files go")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.tenants <= len(TENANTS):
        parser.error(f"--tenants is 1 to {len(TENANTS)}")
    settings = Settings(
        minutes=args.minutes,
        agents=args.agents,
        concurrency=args.concurrency,
        workers=args.workers,
        relays=args.relays,
        tenants=args.tenants,
        seed=args.seed,
        retain=args.retain,
        vacuum_every=args.vacuum_every,
        faults=args.faults,
        quiesce=args.quiesce,
        quiet=args.quiet,
    )
    return settings, args


def main(argv: Sequence[str] | None = None) -> int:
    settings, args = parse(argv)
    if hasattr(signal, "SIGUSR1"):  # kill -USR1 <pid>: every thread's stack, to stderr
        faulthandler.register(signal.SIGUSR1, all_threads=True)
    try:
        if args.docker:
            cluster = start_docker(args.image)
        else:
            dsn = (
                args.dsn
                or os.environ.get("INTERLOCK_SOAK_DSN")
                or os.environ.get("INTERLOCK_TEST_POSTGRES_DSN")
            )
            if not dsn:
                print("live_stress_test: give --docker or --dsn", file=sys.stderr)
                return EXIT_ERROR
            cluster = Cluster(dsn)
    except (SoakError, subprocess.SubprocessError, OSError) as exc:
        print(f"live_stress_test: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        return soak(settings, cluster, keep=args.keep, directory=args.dir)
    except (SoakError, psycopg.Error) as exc:
        print(f"live_stress_test: the soak could not run: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if not args.keep:
            cluster.close()


if __name__ == "__main__":
    sys.exit(main())
