#!/usr/bin/env python3
"""The soak: a cluster of Interlock daemons under sustained load and chaos, on a live PostgreSQL.

(``docs/EPIC6_DESIGN.md`` §3, ``docs/EPIC9_DESIGN.md`` §5.) ``--nodes`` daemons,
three by default, each ``interlock daemon --node`` in a process of its own, as
the pods of a StatefulSet run: every node runs the engines that execute the
agents' plans, the relays, the inbox, the settler of its own plans and the
metrics endpoint, over one database and one AgentGov ledger; the vacuum and the
inbox's matcher run on the node that leads their role. Each node has a
directory of its own, as a pod has a volume, for its escrow chains and its
receipt log; the operator log is in one every node shares. Around them, in the
harness:

- **A payment API** on localhost, in Stripe's shape. It honours
  ``Idempotency-Key``, replaying a key's first result, and injects faults: a
  500 after it acted, a 429, a reply slower than the relay waits, latency.
- **The vendor's webhooks**, signed as Stripe signs them, for every payment
  and every refund, through a balancer in front of the nodes' inboxes, as a
  Kubernetes Service is: some duplicated, some sent before the relay has
  recorded the delivery they are about, some about objects Interlock never
  created, and some forged (another secret, a stale timestamp, a rewritten
  body, no signature at all). Each carries the trace context of the call that
  made its object, continued, as a propagating vendor would; or a trace of the
  vendor's own; or a malformed one; or none, as Stripe sends.
- **Agents**, inside every node: each AgentGov scope with several plans in
  flight on each node, checkouts, reconciliations, notes on a few hot rows
  every node contends for, and, now and then, a plan that must be refused. A
  node's agents share no memory with another's: an order is found from its
  checkout's plan id, and each node writes what its agents did to a journal of
  its own, a line at a time, which outlives the node.
- **A key service**, holding the relays', the inbox's and the vacuum's Ed25519
  keys as a KMS does: every node signs through ``HttpRemoteSigner``
  (``docs/EPIC8_DESIGN.md`` §5).
- **An operator** compensating paid orders, every action signed; and, a
  quarter of the way through the load, rotating the relays' key: a new version,
  registered; every node reloaded (``SIGHUP``); the old key revoked while a
  stale relay, still holding it, has a call in flight.
- **The chaos.** At 45% of the load the node leading the vacuum is killed
  (``SIGKILL``) at a moment it has a call in flight; at 70% the node leading
  it then is frozen (``SIGSTOP``) with a call in flight and a stage open, its
  connections left open as a host lost to the network leaves them, and killed
  once the server and the cluster have ended everything it held: its session
  at its timeout, the rest when a survivor fenced it. The moment is found by
  stopping the node and looking, and letting it go on if it is not there yet.
  Each comes back, as a pod is rescheduled, and recovers.
- **An auditor** sampling the database throughout: lock waits, the rate
  windows' history, the outbox's size, what the vacuum has yet to prune, and
  who holds each node's lock and each role.
- **A scraper** reading each node's ``/metrics`` every second, as Prometheus
  would.

The load runs for ``--minutes``. Then no new work starts, everything in
flight is delivered, settled and consumed, every node is stopped, and a second
start of every node finds nothing to recover. Then each claim is proven from
the database, the ledger, the logs and the nodes' journals:

==========================  ====================================================================
Claim                       Measured by
==========================  ====================================================================
no deadlocks                ``pg_stat_database.deadlocks`` unchanged; no node logged one
lock waits resolve          sampled waits within the stage lock timeout; every lost race retried
                            to an outcome; every plan a node lived to answer, answered
rate windows hold exactly   every key's history, at every row's commit instant, within the limit
                            over its span: rows the vacuum pruned included
the ledger balances         AgentGov's integrity and conservation; each plan charged once, exactly
                            its price; each refund credited once; no hold left open
exactly once                one object per idempotency key and per order; one receipt per
                            delivery, but one whose plan's action receipt its node died before
                            issuing; every event recorded once, every fact consumed once
no forgery accepted         every forged webhook answered 400 or 401, and recorded nowhere
the vacuum compacts         checkpoints throughout; messages, window rows and events pruned;
                            nothing prunable outlives its retention by more than a few runs
everything verifies         delivery logs, attestations, operators, keys, settlements against
                            every node's receipt log, the inbox, every node's escrow chains
shutdown is graceful        every node stopped within the drain bound, nothing cut; a second
                            start of each recovers nothing
trace context survives      every call the payment API saw carried its plan's context, every
                            refund its charge's; every fact the trace of the delivery it binds;
                            every reconcile plan the trace of the checkout it reconciles
metrics agree               every scrape well formed; no counter fell; each node's plans and
                            webhooks what it counted itself; the settled outbox as sampled
keys rotate                 mid-load, every node reloaded with the new key; every outcome the old
                            key attested sealed, but the stale relay's, which the database
                            refused, and its message delivered once under the new key
nodes share the work        every node committed plans, delivered messages, answered webhooks
                            and settled its own deliveries
one leader at a time        no role ever held by two sessions; every vacuum run by the node
                            leading then; each receipt log settled by its own node; each dead
                            leader's role taken by another
a node killed is survived   its leases taken within a second, its call in flight made again
                            under its key and acted on once; its sessions gone at once; it came
                            back and recovered what it left
a node frozen is survived   its node's lock released at its session timeout, its leases taken
                            only then; every session it had ended by a survivor's fencing a
                            heartbeat later, every lock with it, no survivor waiting on one
                            longer; it was killed, came back and recovered
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
import base64
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
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, LiteralString, TypeVar

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
    PlanBuilder,
    SinkAllowlist,
    TenantIsolation,
)
from interlock.cluster import LEADER_LOCK, NODE_LOCK, lock_key
from interlock.config import InterlockConfig, load_config
from interlock.daemon import Application
from interlock.exceptions import (
    ChainInUseError,
    InboundFactError,
    KeyRevokedError,
    StageConflictError,
    SupervisorStoppedError,
)
from interlock.operators import Operator, OperatorLog, OperatorRefusedError, generate_key, load_key
from interlock.relay import Delivery, DeliveryResult, NoBreaker, Relay
from interlock.signers import HttpRemoteSigner
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.supervisor import AgentContext
from interlock.telemetry import CATALOG
from interlock.trace import child_traceparent, new_traceparent, parse_traceparent, trace_id
from interlock.types import InboundFact, OutboundRequest, PlanId

T = TypeVar("T")
logger = logging.getLogger("soak")

# --------------------------------------------------------------------------
# What the soak runs
# --------------------------------------------------------------------------

SINK = "payments"
SOURCE = "stripe"
API_KEY_ENV = "SOAK_STRIPE_KEY"
WEBHOOK_SECRET_ENV = "SOAK_WEBHOOK_SECRET"  # noqa: S105 - the name of a variable
KMS_TOKEN_ENV = "SOAK_KMS_TOKEN"  # noqa: S105 - the name of a variable
NODE_SPEC_ENV = "SOAK_NODE_SPEC"
"""The variable naming a node process's spec: its name, its incarnation, its
journal, and the run's settings."""
REMOTE = ("relay", "inbox", "vacuum")
"""The parts whose keys the key service holds: each signs as
``[signers.<part>]``, the key named ``soak-<part>``."""
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
HOT = 3
"""Rows each tenant has before the load, that every node's agents write."""
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
TRACE_MODES = ("echo", "foreign", "invalid", "none")
"""What a webhook carries as ``traceparent``: the context of the call that
made its object, continued, as a propagating vendor would; a trace of the
vendor's own; a malformed one; or none, as Stripe sends."""
MALFORMED_TRACES = (
    "00-00000000000000000000000000000000-00f067aa0ba902b7-01",  # a trace id of zeros
    "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",  # version ff, forbidden
    "00-4bf92f3577b34da6a3ce929d0e0e4736-01",  # no span
)
SHARE_AFTER = 2.0
"""Seconds a pending fact is left to the node it falls to before any node's
agents take it: fewer races for one fact, and none left behind by a node
that died."""
METRICS_EVERY = 1.0
"""How often each node samples the database for its metrics, and the soak
scrapes them."""
ROTATE_AT, KILL_AT, FREEZE_AT = 0.25, 0.45, 0.70
"""Where in the load the relays' key is rotated, the vacuum's leader killed,
and the vacuum's leader then frozen."""

EXIT_OK, EXIT_FAILED, EXIT_ERROR = 0, 1, 2


class SoakError(Exception):
    """The soak could not run: no database, no Docker, a part that would not start."""


@dataclass(frozen=True)
class Settings:
    """How hard and how long (``--help``). Agents, lanes, engines and relays
    are each node's."""

    minutes: float = 5.0
    nodes: int = 3
    agents: int = 4
    concurrency: int = 3
    workers: int = 4
    relays: int = 2
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
    heartbeat: float = 0.5
    session_timeout: float = 4.0
    max_stage: float = 6.0
    restart_after: float = 10.0
    chaos: bool = True
    quiet: bool = False

    @property
    def scopes(self) -> tuple[str, ...]:
        return tuple(f"soak-agent-{n}" for n in range(self.agents))

    @property
    def tenant_names(self) -> tuple[str, ...]:
        return TENANTS[: self.tenants]

    @property
    def node_names(self) -> tuple[str, ...]:
        return tuple(f"node-{n}" for n in range(self.nodes))

    @property
    def hot(self) -> dict[str, list[int]]:
        """Each tenant's hot rows: there before the load, written by every node."""
        return {
            tenant: [index * HOT + n + 1 for n in range(HOT)]
            for index, tenant in enumerate(self.tenant_names)
        }

    @property
    def slack(self) -> float:
        """How long past its retention a prunable row may stay: three vacuum
        runs, the time one takes, and a failover's."""
        return 3 * self.vacuum_every + 10 + self.session_timeout


# --------------------------------------------------------------------------
# PostgreSQL: a container for the run, or a server given by DSN
# --------------------------------------------------------------------------


@dataclass
class Server:
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


def start_docker(image: str) -> Server:
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
        "max_connections=300",
        "-c",
        "log_lock_waits=on",
    ]
    started = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
    if started.returncode != 0:
        raise SoakError(f"docker run failed: {started.stderr.strip()}")
    server = Server("", name)
    try:
        mapped = subprocess.run(
            ["docker", "port", name, "5432/tcp"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.split()[0]
        port = int(mapped.rsplit(":", 1)[1])
        server.admin = f"postgresql://postgres:{password}@127.0.0.1:{port}/postgres"
        deadline = time.monotonic() + 120
        while True:
            try:
                with psycopg.connect(server.admin, connect_timeout=3) as conn:
                    conn.execute("SELECT 1")
                break
            except psycopg.Error:
                if time.monotonic() > deadline:
                    raise SoakError("the PostgreSQL container did not come up") from None
                time.sleep(0.5)
    except BaseException:
        server.close()
        raise
    return server


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
    note           text,
    plan           text
)
"""
COLUMNS = (
    "id",
    "tenant",
    "amount_cents",
    "status",
    "refund_status",
    "payment_intent",
    "note",
    "plan",
)


@dataclass
class Site:
    """The soak's database on a server, its roles, and its files: a directory
    every node shares, and one of each node's own."""

    server: Server
    name: str
    directory: Path
    roles: dict[str, str]
    password: str
    created: bool = False

    @property
    def owner(self) -> str:
        """The database as the server's admin: it owns the tables, installs
        Interlock, owns the AgentGov ledger, and runs the vacuum."""
        return make_conninfo(self.server.admin, dbname=self.name)

    @property
    def shared(self) -> Path:
        """What every node reads: the operator log, and the files of keys."""
        return self.directory / "shared"

    def home(self, node: str) -> Path:
        """A node's own, as a pod's volume: its configuration, its chains,
        its receipt log, its journals."""
        return self.directory / node

    def dsn(self, part: str) -> str:
        return make_conninfo(self.owner, user=self.roles[part], password=self.password)

    def drop(self) -> None:
        """The database and the roles, whatever was created of them."""
        with psycopg.connect(self.server.admin, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(self.name))
            )
            for role in self.roles.values():
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def new_site(server: Server, directory: Path) -> Site:
    tag = secrets.token_hex(4)
    return Site(
        server,
        f"interlock_soak_{tag}",
        directory,
        {part: f"soak_{tag}_{part}" for part in PARTS},
        secrets.token_hex(16),
    )


def create_site(site: Site, settings: Settings) -> None:
    """A fresh database with the orders table and its hot rows, a role for
    each part, and the AgentGov ledger: a root scope for each agent and one
    for the operators."""
    server = site.server
    with psycopg.connect(server.admin, autocommit=True) as admin:
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
        # The rows every node's agents contend for: written before Interlock
        # observes the table, as rows that were there before it.
        for tenant, ids in settings.hot.items():
            for order_id in ids:
                conn.execute(
                    "INSERT INTO orders (id, tenant, amount_cents, status) VALUES (%s, %s, %s, %s)",
                    (order_id, tenant, 1000, INITIAL),
                )
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


class KeyService:
    """A key service on localhost, in :class:`~interlock.signers.HttpRemoteSigner`'s
    protocol: named Ed25519 keys with versions, held in memory as a KMS holds
    them, a bearer token on every request. Every signature it makes is
    counted, by key and version."""

    def __init__(self, token: str) -> None:
        from agentgov.receipts.signing import Ed25519Signer

        self._new = Ed25519Signer.generate
        self.token = token
        self._lock = threading.Lock()
        self._keys: dict[str, list[Any]] = {}
        self.signed: Counter[tuple[str, int]] = Counter()
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                service._handle(self, "GET")

            def do_POST(self) -> None:
                service._handle(self, "POST")

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="soak-key-service", daemon=True
        )
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def create(self, name: str) -> Any:
        """A key, at version 1."""
        key = self._new()
        with self._lock:
            self._keys[name] = [key]
        return key

    def rotate(self, name: str) -> Any:
        """A new version of ``name``: what a signer built from now on pins."""
        key = self._new()
        with self._lock:
            self._keys[name].append(key)
        return key

    def key(self, name: str, version: int | None = None) -> Any:
        with self._lock:
            versions = self._keys[name]
            return versions[-1 if version is None else version - 1]

    def signer(self, name: str, version: int | None = None) -> HttpRemoteSigner:
        """A signer for ``name`` at this service, pinned to ``version``."""
        return HttpRemoteSigner(self.url, name, token=self.token, version=version)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        url = urllib.parse.urlsplit(handler.path)
        parts = url.path.strip("/").split("/")
        if handler.headers.get("Authorization") != f"Bearer {self.token}":
            self._answer(handler, 401, {"errors": ["permission denied"]})
            return
        with self._lock:
            versions = list(self._keys.get(parts[2], ())) if len(parts) >= 3 else []
        if parts[:2] != ["v1", "keys"] or not versions:
            self._answer(handler, 404, {"errors": ["no such key"]})
            return
        if method == "GET" and len(parts) == 3:
            query = urllib.parse.parse_qs(url.query)
            version = int(query["version"][0]) if "version" in query else len(versions)
            if not 1 <= version <= len(versions):
                self._answer(handler, 404, {"errors": ["no such version"]})
                return
            public = versions[version - 1].public_key().raw.hex()
            self._answer(handler, 200, {"alg": "ed25519", "version": version, "public_key": public})
            return
        if method == "POST" and parts[3:] == ["sign"]:
            length = int(handler.headers.get("Content-Length") or 0)
            body = json.loads(handler.rfile.read(length))
            version = int(body["version"])
            if not 1 <= version <= len(versions):
                self._answer(handler, 400, {"errors": ["no such version"]})
                return
            signature = versions[version - 1].sign(base64.b64decode(body["message"]))
            with self._lock:
                self.signed[(parts[2], version)] += 1
            self._answer(handler, 200, {"version": version, "signature": signature.hex()})
            return
        self._answer(handler, 404, {"errors": ["no such route"]})

    @staticmethod
    def _answer(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
        payload = json.dumps(body).encode()
        with contextlib.suppress(OSError):
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            handler.wfile.write(payload)


@dataclass(frozen=True)
class Keys:
    """Every key the run signs with: the desk's and the receipt log's in files
    beside the configuration; the relays', the inbox's and the vacuum's at the
    key service, which never hands one out."""

    desk: Path
    receipts: Path
    service: KeyService

    @classmethod
    def generate(cls, directory: Path, service: KeyService) -> Keys:
        for part in REMOTE:
            service.create(f"soak-{part}")
        keys = cls(directory / "desk.key", directory / "receipts.key", service)
        generate_key(keys.desk)
        generate_key(keys.receipts)
        return keys

    def spec(self, name: str) -> str:
        if name in REMOTE:
            return str(self.service.key(f"soak-{name}").public_key().spec())
        return str(load_key(getattr(self, name)).public_key().spec())


def _q(text: str) -> str:
    """A TOML basic string."""
    return json.dumps(text)


def write_config(site: Site, settings: Settings, keys: Keys, api_port: int, node: str) -> Path:
    """Node ``node``'s ``interlock.toml``: every part, configured as in
    production, with its times scaled down to seconds. The nodes' files differ
    only in the node and its receipt log's id; each lives in the node's own
    directory, where its chains and receipt log are written; the operator log
    and the keys are in the one every node shares."""
    roles = site.roles
    shared = site.shared
    text = (
        f"""
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
signer = "relay"
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
log = {_q(str(shared / "operators.ilok1"))}
ledger = {_q(site.owner)}
scope = {_q(OPERATORS_SCOPE)}

[operators.keys]
desk = {_q(keys.spec("desk"))}
vacuum = {_q(keys.spec("vacuum"))}

[inbox]
signer = "inbox"
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
max_stage_seconds = {settings.max_stage}
lock_timeout_seconds = {LOCK_TIMEOUT}

[receipts]
log = "receipts.jsonl"
key = {_q(str(keys.receipts))}
log_id = {_q(receipts_log_id(node))}

[settler]
database = {_q(site.dsn("settle"))}
every_seconds = 1

[vacuum]
every_seconds = {settings.vacuum_every}
retain_seconds = {settings.retain}
margin_seconds = {settings.margin}
database = {_q(site.owner)}
signer = "vacuum"

[daemon]
drain_timeout_seconds = 30
restart_min_seconds = 0.2
restart_max_seconds = 5

[cluster]
node = {_q(node)}
# The owner: a node fences a gone node's sessions, the ledger's (a superuser's) among them.
database = {_q(site.owner)}
heartbeat_seconds = {settings.heartbeat}
session_timeout_seconds = {settings.session_timeout}
"""
        + "".join(
            f"""
[signers.{part}]
type = "http"
url = {_q(keys.service.url)}
key = "soak-{part}"
token_env = "{KMS_TOKEN_ENV}"
"""
            for part in REMOTE
        )
        + f"""

[metrics]
listen = "127.0.0.1:0"
every_seconds = {METRICS_EVERY}
database = {_q(site.dsn("audit"))}
"""
    )
    home = site.home(node)
    home.mkdir(parents=True, exist_ok=True)
    path = home / "interlock.toml"
    path.write_text(text, encoding="utf-8")
    return path


def receipts_log_id(node: str) -> str:
    """Each node's receipt log's id: a log has one writer, its node's."""
    return f"soak-receipts-{node}"


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
        self.traces: dict[str, set[str | None]] = defaultdict(set)
        """Every ``traceparent`` the calls with each idempotency key carried."""
        self.trace_of: dict[str, str | None] = {}
        """The ``traceparent`` of the call that created each object."""
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
        traceparent = handler.headers.get("traceparent")
        with self._lock:
            latency = self._rng.uniform(0.002, 0.03)
        time.sleep(latency)
        reply: tuple[int, dict[str, Any], dict[str, str]] | None = None
        mode = "ok"
        with self._lock:
            self.traces[key].add(traceparent)
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
                status, result = self._execute(path, params, traceparent)
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

    def _execute(
        self, path: str, params: Mapping[str, Any], traceparent: str | None
    ) -> tuple[int, dict[str, Any]]:
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
            self.trace_of[intent["id"]] = traceparent
            self._vendor.created(dict(intent), traceparent)
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
            self.trace_of[refund["id"]] = traceparent
            self._vendor.created(dict(refund), traceparent)
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
    trace: str = "none"
    """What the webhook carried as ``traceparent``: ``echo`` (ours, continued),
    ``foreign`` (the vendor's own), ``invalid``, or ``none``."""
    node: str = ""
    """The node whose inbox the balancer sent it to."""
    incarnation: int = -1
    """Which process of that node it was."""


FORGERIES = ("wrong_secret", "stale", "tampered", "unsigned")


class Vendor:
    """The payment provider's webhooks: each object's event, signed when it is
    sent, through the balancer to one node's inbox, and sent again while no
    inbox answers 2xx, as Stripe retries. A node that does not answer, a
    killed one or a frozen one, is tried no more until its health check says
    it is back, and the webhook goes to the next.

    Some are sent at once, before the relay can have recorded the delivery
    they are about; some twice; and beside them, events about objects nobody
    created, and forgeries of the real ones.
    """

    def __init__(self, secret: str, seed: int, balancer: Balancer, *, senders: int = 4) -> None:
        self._secret = secret
        self._rng = random.Random(seed)
        self._balancer = balancer
        self._lock = threading.Condition()
        self._heap: list[tuple[float, int, Webhook]] = []
        self._order = itertools.count()
        self._events = itertools.count(1)
        self._tag = secrets.token_hex(3)
        self._busy = 0
        self._stop = False
        self.sent: list[Sent] = []
        self.failures: Counter[str] = Counter()
        self.forged: set[str] = set()
        self.traces: dict[str, tuple[str, str | None]] = {}
        """For each genuine event, what its webhooks carry as ``traceparent``:
        how it was chosen, and the header sent, if any."""
        self._threads = [
            threading.Thread(target=self._send_loop, name=f"soak-vendor-{n}", daemon=True)
            for n in range(senders)
        ]

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def close(self) -> None:
        with self._lock:
            self._stop = True
            self._lock.notify_all()
        for thread in self._threads:
            thread.join(timeout=15)

    def backlog(self) -> int:
        with self._lock:
            return len(self._heap) + self._busy

    def created(self, obj: Mapping[str, Any], traceparent: str | None) -> None:
        """The API created ``obj``, on a call carrying ``traceparent``: its
        event goes out, and what rides with it."""
        if obj["object"] == "payment_intent":
            kind = STATUS_KINDS[0] if obj["status"] == "succeeded" else STATUS_KINDS[1]
        else:
            kind = REFUND_KIND
        now = time.monotonic()
        with self._lock:
            rng = self._rng
            event = self._event(kind, obj)
            roll = rng.random()
            if traceparent is None or roll < 0.35:
                self.traces[event["id"]] = ("none", None)
            elif roll < 0.8:
                self.traces[event["id"]] = ("echo", child_traceparent(traceparent))
            elif roll < 0.95:
                self.traces[event["id"]] = ("foreign", new_traceparent())
            else:
                self.traces[event["id"]] = ("invalid", rng.choice(MALFORMED_TRACES))
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
                    if self._heap and self._heap[0][0] <= now:
                        _, _, webhook = heapq.heappop(self._heap)
                        self._busy += 1
                        break
                    wait = 0.5 if not self._heap else self._heap[0][0] - now
                    self._lock.wait(timeout=max(0.001, min(wait, 0.5)))
            try:
                self._send(webhook)
            finally:
                with self._lock:
                    self._busy -= 1

    def _send(self, webhook: Webhook) -> None:
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
        trace, traceparent = self.traces.get(webhook.event["id"], ("none", None))
        if traceparent is not None:
            headers["traceparent"] = traceparent
        status, answer, node, incarnation = 0, {}, "", -1
        # Through the balancer: a node that does not answer is taken out, and
        # the next one tried at once, as a Service's next endpoint is.
        for _ in range(3):
            picked = self._balancer.pick()
            if picked is None:
                self.failures["no node up"] += 1
                break
            target, port, incarnation = picked
            node = target.name
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    conn.request("POST", f"/inbox/{SOURCE}", body=body, headers=headers)
                    response = conn.getresponse()
                    status = response.status
                    with contextlib.suppress(ValueError):
                        answer = json.loads(response.read() or b"{}")
                finally:
                    conn.close()
            except OSError as exc:
                self.failures[type(exc).__name__] += 1
                self._balancer.failed(target)
                with self._lock:
                    self.sent.append(
                        Sent(webhook.event["id"], purpose, 0, 0, 0, trace, node, incarnation)
                    )
                status = 0
                continue
            break
        recorded = int(answer.get("recorded", 0)) if isinstance(answer, dict) else 0
        matched = int(answer.get("matched", 0)) if isinstance(answer, dict) else 0
        with self._lock:
            if status:
                self.sent.append(
                    Sent(
                        webhook.event["id"],
                        purpose,
                        status,
                        recorded,
                        matched,
                        trace,
                        node,
                        incarnation,
                    )
                )
            if not 200 <= status < 300 and not purpose.startswith("forged:"):
                # As Stripe does: again, later, until the endpoint answers 2xx.
                webhook.attempts += 1
                if webhook.attempts < 12:
                    self._push(time.monotonic() + min(8.0, 0.25 * 2**webhook.attempts), webhook)
                    self._lock.notify_all()
                else:
                    self.failures["gave_up"] += 1


# --------------------------------------------------------------------------
# The agents, inside every node
# --------------------------------------------------------------------------

INSERT_ORDER = (
    "INSERT INTO orders (id, tenant, amount_cents, status, plan) "
    "VALUES (%(id)s, %(tenant)s, %(amount)s, %(status)s, %(plan)s)"
)


@dataclass(frozen=True)
class NodeSpec:
    """What one daemon process of the cluster needs to know of the run,
    written by the harness as JSON beside the node's configuration."""

    name: str
    index: int
    incarnation: int
    settings: Settings
    journal: str
    wind_down: str
    t0: float
    """When the load began, in seconds since the epoch: the bursts' clock."""
    hot: dict[str, list[int]]
    """Each tenant's few rows every node's agents contend for."""

    @property
    def order_base(self) -> int:
        """Where this incarnation's order ids begin: unique across the cluster
        and every incarnation of every node."""
        return (self.index + 1) * 10**12 + self.incarnation * 10**9

    def write(self, path: Path) -> None:
        document = {**self.__dict__, "settings": self.settings.__dict__}
        path.write_text(json.dumps(document), encoding="utf-8")

    @classmethod
    def read(cls, path: str | Path) -> NodeSpec:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        document["settings"] = Settings(**document["settings"])
        return cls(**document)


class Journal:
    """What a node's agents did, a line of JSON each, written to the OS as it
    happens: what a killed process wrote, the harness reads."""

    def __init__(self, path: str | Path) -> None:
        self._file = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, record: str, **fields: Any) -> None:
        line = json.dumps({"r": record, "at": time.time(), **fields}, default=str)
        with self._lock:
            self._file.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._file.close()


CHECKOUT = re.compile(r"\Acheckout-(\d+)-[0-9a-f]+\Z")
"""A checkout's plan id names its order: any node's agent finds the order a
fact is about from the fact's plan alone."""


@dataclass
class Order:
    order_id: int
    scope: str
    tenant: str
    amount: int
    plan_id: str
    committed: bool = False
    payment_intent: str | None = None
    traceparent: str | None = None


class Workload:
    """One node's agents: what they remember between plans, and the journal
    of everything they did. Nothing is shared between nodes but the
    database: an order is found from its checkout's plan id, and the hot rows
    every node writes exist before the load."""

    def __init__(self, spec: NodeSpec) -> None:
        self.spec = spec
        self.settings = spec.settings
        self.journal = Journal(spec.journal)
        self.lock = threading.Lock()
        self.winding_down = threading.Event()
        self.orders: dict[int, Order] = {}
        self.by_tenant: dict[str, list[int]] = {t: [] for t in self.settings.tenant_names}
        self.hot = {t: list(ids) for t, ids in spec.hot.items()}
        self.consumed: dict[str, list[InboundFact]] = defaultdict(list)
        self.bursts_filled: set[int] = set()
        self._ids = itertools.count(spec.order_base + 1)
        self.inflight = 0
        self.journal.write("start", node=spec.name, incarnation=spec.incarnation, pid=os.getpid())

    def watch(self) -> None:
        """Wind down when the harness says so: a file appears."""

        def watching() -> None:
            while not Path(self.spec.wind_down).exists():
                time.sleep(0.1)
            self.winding_down.set()
            self.journal.write("winding_down")

        threading.Thread(target=watching, name="soak-wind-down", daemon=True).start()

    # -- submitting ---------------------------------------------------------

    async def submit(self, ctx: AgentContext, plan: Any, kind: str, scope: str) -> Any:
        """Execute ``plan``; journal it, and what became of it. ``None`` when
        it raised."""
        checkout = kind in ("checkout", "misbehave:overcharge")
        self.journal.write(
            "plan", plan=str(plan.plan_id), kind=kind, scope=scope, checkout=checkout
        )
        self.inflight += 1
        try:
            result = await ctx.execute(plan)
        except SupervisorStoppedError as exc:
            self._answer(plan, None, error=f"stopped: {exc}")
            return None
        except StageConflictError as exc:
            self._answer(plan, None, error=f"conflict: {exc}")
            return None
        except InboundFactError as exc:
            self._answer(plan, None, error=f"fact: {exc}")
            return None
        except Exception as exc:  # journaled: the claims say whether it was expected
            self._answer(plan, None, error=f"{type(exc).__name__}: {exc}")
            return None
        finally:
            self.inflight -= 1
        self._answer(plan, result.committed, blocked=result.blocked_by)
        return result

    def _answer(
        self,
        plan: Any,
        committed: bool | None,
        *,
        blocked: tuple[str, ...] = (),
        error: str | None = None,
    ) -> None:
        self.journal.write(
            "answer",
            plan=str(plan.plan_id),
            committed=committed,
            blocked=list(blocked),
            error=error,
        )

    # -- what agents do -------------------------------------------------------

    async def checkout(
        self, ctx: AgentContext, scope: str, rng: random.Random, *, overcharge: bool = False
    ) -> Any:
        tenant = rng.choice(self.settings.tenant_names)
        order_id = next(self._ids)
        amount = rng.randrange(500, 4501)
        traceparent = new_traceparent()
        plan_id = PlanId(f"checkout-{order_id}-{uuid.uuid4().hex[:8]}")
        plan = (
            PlanBuilder(
                scope,
                intent=f"check out order {order_id}",
                traceparent=traceparent,
                plan_id=plan_id,
            )
            .insert(
                table="orders",
                statement=INSERT_ORDER,
                parameters={
                    "id": order_id,
                    "tenant": tenant,
                    "amount": amount,
                    "status": INITIAL,
                    "plan": plan_id,
                },
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
        order = Order(order_id, scope, tenant, amount, plan_id, traceparent=traceparent)
        self.journal.write(
            "order",
            order=order_id,
            plan=plan_id,
            scope=scope,
            tenant=tenant,
            amount=amount,
            traceparent=traceparent,
        )
        with self.lock:
            self.orders[order_id] = order
        result = await self.submit(
            ctx, plan, "misbehave:overcharge" if overcharge else "checkout", scope
        )
        if result is not None and result.committed:
            with self.lock:
                order.committed = True
                self.by_tenant[tenant].append(order_id)
        return result

    async def annotate(
        self, ctx: AgentContext, scope: str, rng: random.Random, *, tenant: str | None = None
    ) -> Any:
        """A note on one of the few hot rows every node's agents write:
        contention, across processes. For a burst's ``tenant``, on any of this
        node's recent orders of it, or a hot one."""
        if tenant is None:
            tenant = rng.choice(self.settings.tenant_names)
            rows = self.hot[tenant]
        else:
            with self.lock:
                rows = self.by_tenant[tenant][-64:] or self.hot[tenant]
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

    async def reconcile(self, ctx: AgentContext, scope: str, fact: InboundFact) -> str:
        """Consume ``fact`` and write what it says to its order, found from the
        fact's plan: ``done``; ``again`` when a window refused or a race was
        lost; ``gone`` when another node consumed it first, or it names no
        checkout."""
        named = CHECKOUT.match(fact.plan_id)
        if named is None or fact.tenant_id is None:
            self.journal.write("orphan", fact=str(fact.fact_id), plan=fact.plan_id)
            return "gone"
        order_id = int(named.group(1))
        status = str(fact.fields.get("status", ""))
        if fact.kind in STATUS_KINDS:
            statement = (
                "UPDATE orders SET status = %(status)s, payment_intent = %(pi)s WHERE id = %(id)s"
            )
            parameters: dict[str, Any] = {
                "status": status,
                "pi": str(fact.fields.get("id", "")),
                "id": order_id,
            }
        else:
            statement = "UPDATE orders SET refund_status = %(status)s WHERE id = %(id)s"
            parameters = {"status": status, "id": order_id}
        # The fact's trace, continued: agent, outbox, relay, vendor, webhook,
        # fact, and the agent again, on whichever node.
        parent = fact.traceparent
        plan = (
            ctx.plan(
                scope,
                intent=f"record {fact.kind} for order {order_id}",
                traceparent=None if parent is None else child_traceparent(parent),
            )
            .consume(fact)
            .update(
                table="orders",
                statement=statement,
                parameters=parameters,
                tenant_id=fact.tenant_id,
                stated_rows=1,
            )
            .build()
        )
        result = await self.submit(ctx, plan, "reconcile", scope)
        if result is None or not result.committed:
            pending = {f.fact_id for f in await ctx.facts(scope)}
            return "again" if fact.fact_id in pending else "gone"
        self.journal.write(
            "reconciled",
            fact=str(fact.fact_id),
            event=fact.event_id,
            kind=fact.kind,
            remote_ref=fact.remote_ref,
            plan=fact.plan_id,
            traceparent=fact.traceparent,
            planned=plan.traceparent,
        )
        with self.lock:
            self.consumed[scope].append(fact)
            order = self.orders.get(order_id)
            if order is not None and fact.kind in STATUS_KINDS:
                order.payment_intent = str(parameters["pi"])
        return "done"

    async def misbehave(self, ctx: AgentContext, scope: str, rng: random.Random) -> None:
        """A plan that must be refused."""
        how = rng.choice(MISBEHAVIOURS)
        with self.lock:
            mine = [o for o in self.orders.values() if o.committed and o.scope == scope]
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
            other = next(t for t in self.settings.tenant_names if t != first.tenant)
            builder.update(
                table="orders",
                statement="UPDATE orders SET note = %(note)s WHERE id IN (%(a)s, %(b)s)",
                parameters={"note": "merged", "a": first.order_id, "b": self.hot[other][0]},
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
            named = CHECKOUT.match(fact.plan_id)
            assert named is not None and fact.tenant_id is not None
            builder.consume(fact).update(
                table="orders",
                statement="UPDATE orders SET note = %(note)s WHERE id = %(id)s",
                parameters={"note": "again", "id": int(named.group(1))},
                tenant_id=fact.tenant_id,
                stated_rows=1,
            )
        await self.submit(ctx, builder.build(), f"misbehave:{how}", scope)

    def bursting(self) -> tuple[int, str] | None:
        """The burst under way, if one is, and this node has not seen its
        window fill yet: every node writes for one tenant for a few seconds,
        on one clock, the run's."""
        elapsed = time.time() - self.spec.t0
        number = int(elapsed // BURST_EVERY)
        if number < 1 or elapsed - number * BURST_EVERY > BURST_SECONDS:
            return None
        if number in self.bursts_filled:
            return None
        names = self.settings.tenant_names
        return number, names[(number - 1) % len(names)]


def make_agent(workload: Workload, index: int) -> Callable[[AgentContext], Any]:
    """Agent ``index``: its scope, ``concurrency`` lanes, and a fact poller.
    Every node runs every agent: each scope's plans come from every node."""
    settings = workload.settings
    scope = settings.scopes[index]
    spec = workload.spec
    rng = random.Random(f"{settings.seed}:{spec.name}:{spec.incarnation}:{index}")

    async def agent(ctx: AgentContext) -> None:
        pending: asyncio.Queue[InboundFact] = asyncio.Queue()
        queued: set[uuid.UUID] = set()
        seen: dict[uuid.UUID, float] = {}

        async def poll() -> None:
            while not ctx.stopping:
                try:
                    facts = await ctx.facts(scope)
                except SupervisorStoppedError:
                    return
                except Exception as exc:  # the next poll tries again
                    logger.warning("%s: reading facts failed: %s", scope, exc)
                    facts = ()
                now = time.monotonic()
                for fact in facts:
                    if fact.fact_id in queued:
                        continue
                    # Each fact is one node's first, then anyone's: a node
                    # that died leaves its facts to the rest of the cluster.
                    first = seen.setdefault(fact.fact_id, now)
                    if fact.fact_id.int % settings.nodes == spec.index or now - first > SHARE_AFTER:
                        queued.add(fact.fact_id)
                        pending.put_nowait(fact)
                current = {fact.fact_id for fact in facts}
                for fact_id in [f for f in seen if f not in current]:
                    del seen[fact_id]
                await ctx.sleep(0.2)

        async def lane() -> None:
            while not ctx.stopping:
                try:
                    fact = pending.get_nowait()
                except asyncio.QueueEmpty:
                    fact = None
                if fact is not None:
                    outcome = await workload.reconcile(ctx, scope, fact)
                    if outcome == "again":  # a window refused, or a race lost
                        await ctx.sleep(0.25)
                        pending.put_nowait(fact)
                    else:  # done, here or by another node: polled again if not
                        queued.discard(fact.fact_id)
                    continue
                if workload.winding_down.is_set():
                    await ctx.sleep(0.1)
                    continue
                burst = workload.bursting()
                if burst is not None:
                    number, tenant = burst
                    result = await workload.annotate(ctx, scope, rng, tenant=tenant)
                    if result is not None and TENANT_WINDOW in result.blocked_by:
                        if number not in workload.bursts_filled:
                            workload.bursts_filled.add(number)
                            workload.journal.write("burst", number=number, tenant=tenant)
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


def node_application(config: InterlockConfig) -> Application:
    """``interlock daemon --app live_stress_test:node_application``: one node's
    agents, as the harness specified them (:data:`NODE_SPEC_ENV`)."""
    spec = NodeSpec.read(os.environ[NODE_SPEC_ENV])
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s {spec.name}.{spec.incarnation} %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )
    workload = Workload(spec)
    workload.watch()
    return Application(
        checkers=checkers(),
        agents=[make_agent(workload, n) for n in range(spec.settings.agents)],
    )


# --------------------------------------------------------------------------
# What the nodes did, as their journals say
# --------------------------------------------------------------------------


@dataclass
class PlanRecord:
    """What became of one plan an agent submitted, on whichever node."""

    kind: str
    scope: str
    node: str
    incarnation: int
    checkout: bool
    answered: bool = False
    """``False``: its node died before it was answered."""
    committed: bool | None = None
    """``None``: no verdict, the plan raised, or no answer at all."""
    blocked_by: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class Reconciled:
    """A fact a plan consumed, as the journal of the node that consumed it says."""

    fact_id: str
    event_id: str
    kind: str
    remote_ref: str
    plan_id: str
    traceparent: str | None
    planned: str | None


@dataclass
class Incarnation:
    """One process of one node: from its start to its stop, or its death."""

    node: str
    number: int
    pid: int = 0
    submitted: int = 0
    answered: int = 0
    plans: list[str] = field(default_factory=list)
    """Every plan it submitted, in order."""


@dataclass
class Journals:
    """Every node's journals, read together: the cluster's workload, as the
    claims read it."""

    plans: dict[str, PlanRecord] = field(default_factory=dict)
    orders: dict[int, Order] = field(default_factory=dict)
    reconciled: list[Reconciled] = field(default_factory=list)
    bursts: Counter[str] = field(default_factory=Counter)
    kinds: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    orphans: int = 0
    incarnations: dict[tuple[str, int], Incarnation] = field(default_factory=dict)

    @classmethod
    def read(cls, paths: Mapping[tuple[str, int], Path]) -> Journals:
        found = cls()
        for (node, number), path in sorted(paths.items()):
            life = found.incarnations.setdefault((node, number), Incarnation(node, number))
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:  # a line torn by the death of its writer
                    continue
                found._take(entry, node, number, life)
        for record in found.plans.values():
            outcome = (
                "unanswered"
                if not record.answered
                else "error"
                if record.committed is None
                else "committed"
                if record.committed
                else "refused"
            )
            found.kinds[f"{record.kind}:{outcome}"] += 1
            if record.error is not None:
                found.errors[f"{record.kind}: {record.error.split(':', 1)[0]}"] += 1
        return found

    def _take(self, entry: dict[str, Any], node: str, number: int, life: Incarnation) -> None:
        kind = entry.get("r")
        if kind == "start":
            life.pid = int(entry["pid"])
        elif kind == "plan":
            self.plans[entry["plan"]] = PlanRecord(
                entry["kind"], entry["scope"], node, number, bool(entry["checkout"])
            )
            life.submitted += 1
            life.plans.append(entry["plan"])
        elif kind == "answer":
            record = self.plans[entry["plan"]]
            record.answered = True
            record.committed = entry["committed"]
            record.blocked_by = tuple(entry["blocked"])
            record.error = entry["error"]
            life.answered += 1
        elif kind == "order":
            self.orders[int(entry["order"])] = Order(
                int(entry["order"]),
                entry["scope"],
                entry["tenant"],
                int(entry["amount"]),
                entry["plan"],
                traceparent=entry["traceparent"],
            )
        elif kind == "reconciled":
            self.reconciled.append(
                Reconciled(
                    entry["fact"],
                    entry["event"],
                    entry["kind"],
                    entry["remote_ref"],
                    entry["plan"],
                    entry["traceparent"],
                    entry["planned"],
                )
            )
        elif kind == "burst":
            self.bursts[entry["tenant"]] += 1
        elif kind == "orphan":
            self.orphans += 1

    @property
    def submitted(self) -> int:
        return sum(life.submitted for life in self.incarnations.values())

    @property
    def answered(self) -> int:
        return sum(life.answered for life in self.incarnations.values())


# --------------------------------------------------------------------------
# The nodes: each `interlock daemon` in a process of its own
# --------------------------------------------------------------------------

ENTRY = (
    "import faulthandler, signal, sys; faulthandler.register(signal.SIGUSR1); "
    "from interlock.cli import main; sys.exit(main(sys.argv[1:]))"
)
"""``interlock daemon``, as the console script runs it, with its stacks on
SIGUSR1."""


class Node:
    """One node of the cluster, as the harness runs it: its configuration,
    and the process of its current incarnation."""

    def __init__(self, index: int, name: str, home: Path, config: Path) -> None:
        self.index = index
        self.name = name
        self.home = home
        self.config = config
        self.incarnation = -1
        self.process: subprocess.Popen[str] | None = None
        self.lines: list[str] = []
        self.inbox_port: int | None = None
        self.metrics_port: int | None = None
        self.started_at: dict[int, float] = {}
        self.ended_at: dict[int, float] = {}
        self.exits: dict[int, int] = {}
        self.statuses: dict[int, dict[str, str]] = {}
        """Each stopped incarnation's last word: every part's state line."""
        self.reloads: list[str] = []
        self._stderr: Any = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()

    def journal(self, incarnation: int) -> Path:
        return self.home / f"journal-{incarnation}.jsonl"

    def log(self, incarnation: int) -> Path:
        return self.home / f"daemon-{incarnation}.log"

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self, spec: NodeSpec, environment: Mapping[str, str]) -> None:
        """Its next incarnation: ``interlock daemon --node``, its agents the
        soak's."""
        self.incarnation = spec.incarnation
        path = self.home / f"spec-{spec.incarnation}.json"
        spec.write(path)
        self.lines = []
        self.inbox_port = self.metrics_port = None
        self._stderr = self.log(spec.incarnation).open("w", encoding="utf-8")
        env = {**environment, NODE_SPEC_ENV: str(path)}
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                "-c",
                ENTRY,
                "daemon",
                "--config",
                str(self.config),
                "--node",
                self.name,
                "--app",
                "live_stress_test:node_application",
            ],
            cwd=self.home,
            env=env,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
        )
        self.started_at[spec.incarnation] = time.time()
        self._reader = threading.Thread(
            target=self._read, args=(self.process, spec.incarnation), daemon=True
        )
        self._reader.start()

    def _read(self, process: subprocess.Popen[str], incarnation: int) -> None:
        assert process.stdout is not None
        status: dict[str, str] = {}
        for raw in process.stdout:
            line = raw.rstrip("\n")
            with self._lock:
                self.lines.append(line)
            if line.startswith("receiving webhooks on port "):
                self.inbox_port = int(line.rsplit(" ", 1)[1])
            elif line.startswith("serving metrics on port "):
                self.metrics_port = int(line.rsplit(" ", 1)[1])
            elif line.startswith(("reloaded:", "reload:")):
                with self._lock:
                    self.reloads.append(line)
            elif ": " in line and " step(s), " in line:
                name, _, rest = line.partition(": ")
                status[name] = rest
        self.statuses[incarnation] = status

    def wait_ready(self, timeout: float = 180.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise SoakError(
                    f"node {self.name} exited ({self.process.returncode}) before it was ready; "
                    f"see {self.log(self.incarnation)}"
                )
            with self._lock:
                running = any(line.startswith("interlock daemon running") for line in self.lines)
            if running and self.inbox_port is not None and self.metrics_port is not None:
                return
            time.sleep(0.05)
        raise SoakError(f"node {self.name} was not ready within {timeout:g}s")

    def signal(self, signum: signal.Signals) -> None:
        assert self.process is not None
        self.process.send_signal(signum)

    def kill(self) -> float:
        """SIGKILL: no drain, no close, its sockets closed by the kernel."""
        assert self.process is not None
        self.process.send_signal(signal.SIGKILL)
        at = time.time()
        self.process.wait(30)
        self._ended(at)
        return at

    def freeze(self) -> float:
        """SIGSTOP: it stops where it stands, every connection left open."""
        self.signal(signal.SIGSTOP)
        return time.time()

    def thaw(self) -> None:
        """SIGCONT: a frozen process carries on, as if it had been descheduled."""
        self.signal(signal.SIGCONT)

    def stop(self, timeout: float = 90.0) -> tuple[int, float]:
        """SIGTERM, as Kubernetes asks; its exit status and how long it took."""
        assert self.process is not None
        began = time.monotonic()
        self.process.send_signal(signal.SIGTERM)
        try:
            code = self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            code = -signal.SIGKILL
        took = time.monotonic() - began
        if self._reader is not None:
            self._reader.join(10)
        self._ended(time.time(), code)
        return code, took

    def _ended(self, at: float, code: int | None = None) -> None:
        assert self.process is not None
        self.ended_at[self.incarnation] = at
        self.exits[self.incarnation] = self.process.returncode if code is None else code
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None


class Balancer:
    """What stands in front of the nodes' inboxes, as a Kubernetes Service
    does: each webhook to the next node that answers its health check; a node
    that does not, or fails a send, taken out until it answers again."""

    def __init__(self) -> None:
        self._nodes: list[Node] = []
        self._lock = threading.Lock()
        self._turn = itertools.count()
        self._down: dict[str, float] = {}
        """Nodes out, until when, on the monotonic clock."""
        self._halt = threading.Event()
        self._thread = threading.Thread(target=self._probe, name="soak-balancer", daemon=True)

    def serve(self, nodes: Sequence[Node]) -> None:
        """Stand in front of ``nodes``."""
        with self._lock:
            self._nodes = list(nodes)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._halt.set()

    def pick(self) -> tuple[Node, int, int] | None:
        """The next node up: it, its inbox's port, its incarnation."""
        now = time.monotonic()
        with self._lock:
            up = [
                n
                for n in self._nodes
                if n.alive and n.inbox_port is not None and self._down.get(n.name, 0.0) <= now
            ]
            if not up:
                return None
            node = up[next(self._turn) % len(up)]
            port = node.inbox_port
            assert port is not None
            return node, port, node.incarnation

    def failed(self, node: Node) -> None:
        """A send to ``node`` found nothing answering: out, until its health
        check says otherwise."""
        with self._lock:
            self._down[node.name] = time.monotonic() + 30.0

    def _probe(self) -> None:
        while not self._halt.wait(0.5):
            for node in self._nodes:
                port = node.inbox_port
                healthy = False
                if node.alive and port is not None:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/healthz", timeout=1.0
                        ) as answer:
                            healthy = answer.status == 200
                    except urllib.error.HTTPError as exc:
                        healthy = exc.code == 503  # degraded, and answering
                    except OSError:
                        healthy = False
                with self._lock:
                    if healthy:
                        self._down.pop(node.name, None)
                    else:
                        self._down[node.name] = time.monotonic() + 30.0


# --------------------------------------------------------------------------
# The operator's desk
# --------------------------------------------------------------------------

PAID = """
SELECT id, plan FROM orders
 WHERE status = 'succeeded' AND refund_status IS NULL AND plan IS NOT NULL
"""
"""The orders whose payment a fact said succeeded, on any node, and that no
refund has been recorded for."""


class Desk(threading.Thread):
    """An operator refunding paid orders, one signed action at a time, found
    in the database, whichever node's agents made them. The operator log has
    one writer: the desk opens it for each action, as the vacuum's leader does
    for each run, and waits its turn."""

    def __init__(self, config: InterlockConfig, site: Site, keys: Keys, settings: Settings) -> None:
        super().__init__(name="soak-desk", daemon=True)
        self._config = config
        self._site = site
        self._settings = settings
        self._signer = load_key(keys.desk)
        self._rng = random.Random(settings.seed + 7)
        self._halt = threading.Event()
        self._seen: dict[int, tuple[float, str]] = {}
        """Each paid order, when the desk first saw it paid, and its plan."""
        self.compensated: set[str] = set()
        self.applied = 0
        self.busy = 0
        self.refused: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()

    def stop(self) -> None:
        self._halt.set()

    def act(self, action: Callable[[Operator], T]) -> T:
        """One more action, signed with the desk's key, from another thread:
        the operator log's one writer at a time, as the desk's own wait. Its
        records are anchored when the log is next opened with the ledger, by
        the desk or the vacuum: a governor opened mid-run would read the whole
        ledger under its writer lock, every engine waiting."""
        from interlock.deliveries import operations

        operators = self._config.operators
        assert operators is not None
        conn = psycopg.connect(self._site.owner, autocommit=True)
        try:
            deadline = time.monotonic() + 120
            while True:
                try:
                    with OperatorLog(
                        operators.log, self._signer, operators.keyring(), scope=operators.scope
                    ) as log:
                        return action(Operator(log, operations(conn)))
                except ChainInUseError:
                    if time.monotonic() > deadline:
                        raise SoakError("the operator log was not free in two minutes") from None
                    time.sleep(0.05)
        finally:
            conn.close()

    def candidate(self, conn: psycopg.Connection[Any]) -> str | None:
        """A paid order's checkout plan, the order seen paid within the last
        half retention (its charge still in the outbox: a vacuum prunes it
        once settled and past retention), and not refunded yet."""
        now = time.monotonic()
        for order_id, plan in conn.execute(PAID).fetchall():
            self._seen.setdefault(int(order_id), (now, str(plan)))
        within = self._settings.retain / 2
        found = [
            plan
            for seen, plan in self._seen.values()
            if plan not in self.compensated and now - seen < within
        ]
        return self._rng.choice(found) if found else None

    def run(self) -> None:
        from interlock.deliveries import operations

        settings = self._settings
        operators = self._config.operators
        assert operators is not None
        registry = self._config.sink_registry()
        governor = BudgetManager.open_postgres(self._site.owner)
        conn = psycopg.connect(self._site.owner, autocommit=True)
        try:
            outbox = operations(conn)
            while not self._halt.wait(settings.desk_every):
                plan = self.candidate(conn)
                if plan is None:
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
                                plan_id=plan,
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
                            self.compensated.add(plan)
                            self.applied += 1
                        else:
                            self.refused["not applied"] += 1
                    break
        finally:
            conn.close()
            governor.close()


# --------------------------------------------------------------------------
# The rotation: the relays' key, mid-load (docs/EPIC8_DESIGN.md §2.6, §5)
# --------------------------------------------------------------------------
class _Held:
    """The payment API's adapter, holding what each call answered until the
    gate opens: its relay records the outcome only then."""

    def __init__(self, inner: Any, called: threading.Event, gate: threading.Event) -> None:
        self._inner = inner
        self._called = called
        self._gate = gate
        self.message: str | None = None

    def send(self, delivery: Delivery) -> DeliveryResult:
        result: DeliveryResult = self._inner.send(delivery)
        self.message = str(delivery.message_id)
        self._called.set()
        self._gate.wait(120)
        return result


class StaleRelay(threading.Thread):
    """A relay that kept the old key: it claims a message and calls the
    payment API before the key is revoked, and records the outcome after. The
    database refuses it, the lease runs out, and a relay of the daemon's calls
    again, the idempotency key answering with what was already done."""

    def __init__(self, run: Run, signer: HttpRemoteSigner) -> None:
        super().__init__(name="soak-stale-relay", daemon=True)
        from interlock.wiring import relay_adapters

        settings = run.config.relay
        assert settings is not None
        self.called = threading.Event()
        self.gate = threading.Event()
        adapters = dict(relay_adapters(settings))
        self.held = _Held(adapters[SINK], self.called, self.gate)
        adapters[SINK] = self.held
        self._relay = Relay(
            run.site.dsn("relay"),
            adapters=adapters,
            breaker=NoBreaker(),
            relay_id="soak-stale-relay",
            lease=settings.lease,
            timeout=settings.timeout,
            batch=1,
            signer=signer,
        )
        self.result = "never ran"

    def run(self) -> None:
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                report = self._relay.run_once()
                if report.claimed:
                    self.result = f"recorded its outcome: {report}"
                    return
                time.sleep(0.05)
            self.result = "claimed nothing in a minute"
        except KeyRevokedError as exc:
            self.result = f"refused: {exc}"
        except Exception as exc:
            self.result = f"failed: {type(exc).__name__}: {exc}"
        finally:
            self._relay.close()


@dataclass
class Rotation:
    """What the rotation did, and when, in seconds into the load."""

    began: float = 0.0
    ended: float = 0.0
    old: str = ""
    new: str = ""
    registered: int = 0
    """The ``key.registered`` record's sequence."""
    reload: dict[str, dict[str, str | None]] = field(default_factory=dict)
    """Each node reloaded: each part, and why it did not open again, if not."""
    called_first: bool = False
    """The stale relay called the payment API before the revocation."""
    revoked: int = 0
    """The ``revoke-key`` intent's sequence."""
    seal: dict[str, Any] = field(default_factory=dict)
    stale: str = ""
    held: str | None = None
    """The message the stale relay held."""
    old_signed_after: int = 0
    """Signatures the old version made after the revocation: the stale relay's one."""
    unsealed: int = -1
    """The old key's outcomes outside its seal, read as the revocation committed."""
    new_after: int = 0
    """Outcomes by the new key after the revocation, read before a vacuum prunes them."""
    old_after: int = 0
    error: str | None = None


def reload_all(run: Run) -> dict[str, dict[str, str | None]]:
    """``SIGHUP`` to every node up, as an operator's rollout of a new key
    does: what each said it opened again, and what it could not."""
    outcome: dict[str, dict[str, str | None]] = {}
    for node in run.nodes:
        if not node.alive:
            continue
        before = len(node.reloads)
        node.signal(signal.SIGHUP)
        deadline = time.monotonic() + 60
        while len(node.reloads) == before and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)  # what could not open again is said right after
        said: dict[str, str | None] = {}
        for line in node.reloads[before:]:
            if line.startswith("reloaded: "):
                for name in line.removeprefix("reloaded: ").split(", "):
                    if name and name != "nothing":
                        said[name] = None
            elif line.startswith("reload: "):
                name, _, why = line.removeprefix("reload: ").partition(" could not open again: ")
                said[name] = why
        outcome[node.name] = said
    return outcome


def rotate(run: Run) -> None:
    """A quarter of the way through the load, the operator rotates the relays'
    key: a new version at the key service, registered; every node reloaded;
    then, while a stale relay still holding the old key has a call in flight,
    the old key revoked. Never raises: what went wrong is the claim's to report."""
    rotation = run.rotation
    service = run.keys.service
    roots = run.config.key_roots()
    rotation.began = time.monotonic() - run.started
    try:
        old = service.key("soak-relay", 1)
        rotation.old = old.key_id
        new = service.rotate("soak-relay")
        rotation.new = new.key_id
        record = run.desk.act(
            lambda op: op.register_key("relay", "soak-relay-2", new.public_key(), roots=roots)
        )
        rotation.registered = record.seq
        rotation.reload = reload_all(run)
        stale = StaleRelay(run, service.signer("soak-relay", 1))
        stale.start()
        rotation.called_first = stale.called.wait(30)
        outcome = run.desk.act(
            lambda op: op.revoke_key("relay", old.key_id, reason="rotated mid-soak", roots=roots)
        )
        before = service.signed[("soak-relay", 1)]
        rotation.revoked = outcome.intent.seq
        rotation.seal = dict(outcome.record.body.get("seal") or {})
        stale.gate.set()
        stale.join(60)
        rotation.stale = stale.result
        rotation.held = stale.held.message
        rotation.old_signed_after = service.signed[("soak-relay", 1)] - before
        _after_revocation(run)
    except Exception as exc:
        rotation.error = f"{type(exc).__name__}: {exc}"
        logger.exception("the rotation failed")
    rotation.ended = time.monotonic() - run.started
    say(
        run.settings,
        f"  {rotation.ended:6.0f}s  the relays' key rotated: {rotation.old} -> {rotation.new}, "
        f"{len(rotation.reload)} node(s) reloaded; the stale relay "
        f"{rotation.stale.split(':')[0] or 'did nothing'}",
    )


# --------------------------------------------------------------------------
# The auditor: what the database shows while it runs
# --------------------------------------------------------------------------

WAITS = """
SELECT a.usename::text, EXTRACT(EPOCH FROM clock_timestamp() - l.waitstart)::float8, l.locktype,
       ARRAY(SELECT b.application_name FROM pg_stat_activity AS b
              WHERE b.pid = ANY (pg_blocking_pids(l.pid)))
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
    what a vacuum should have pruned by now and has not, and which relay
    delivered each message, before the vacuum prunes its log."""

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
        self.message_traces: dict[str, tuple[str, str | None]] = {}
        """Every message seen in the outbox: its plan, and the context kept beside it."""
        self.event_traces: dict[str, str | None] = {}
        """Every inbound event seen: the context kept beside it, by event id."""
        self.delivered_by: dict[str, str] = {}
        """Every message seen delivered: the relay that recorded it."""
        self.longest: list[tuple[float, float, str, tuple[str, ...]]] = []
        """Every lock wait seen: when, how long so far, whose, and the sessions
        it waited on (holding the lock, or ahead in its queue), by name."""
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
        for user, waited, _, blockers in conn.execute(WAITS).fetchall():
            part = self.roles.get(str(user), "owner")
            self.waits += 1
            self.max_wait[part] = max(self.max_wait[part], float(waited))
            self.longest.append(
                (time.time(), float(waited), part, tuple(str(b) for b in blockers or ()))
            )
        for message, actor in conn.execute(
            "SELECT message_id::text, actor FROM interlock.outbox_attempts "
            "WHERE event = 'delivered' AND at > clock_timestamp() - interval '60 seconds'"
        ).fetchall():
            self.delivered_by[str(message)] = str(actor)
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
        # Trace context, before the vacuum prunes it with what it describes.
        for message, plan, traceparent in conn.execute(
            "SELECT o.message_id::text, o.plan_id, t.traceparent FROM interlock.outbox AS o "
            "LEFT JOIN interlock.outbox_traces AS t ON t.message_id = o.message_id"
        ).fetchall():
            self.message_traces[str(message)] = (str(plan), traceparent)
        for event_id, traceparent in conn.execute(
            "SELECT e.event_id, t.traceparent FROM interlock.inbox_events AS e "
            "LEFT JOIN interlock.inbox_traces AS t ON t.source = e.source AND t.seq = e.seq"
        ).fetchall():
            self.event_traces[str(event_id)] = traceparent
        if not heavy:
            return
        settings = self._settings
        live, pruned, checkpoints, events, connections = one(
            conn,
            "SELECT (SELECT count(*) FROM interlock.outbox),"
            " (SELECT count(*) FROM interlock.outbox_compacted),"
            " (SELECT count(*) FROM interlock.checkpoints),"
            " (SELECT count(*) FROM interlock.inbox_events),"
            " (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database())",
        )
        (stages,) = one(conn, LINGERING_STAGES, (settings.retain + settings.slack,))
        horizon = max(settings.charge_span, settings.tenant_span) + settings.margin + settings.slack
        (windows,) = one(
            conn,
            "SELECT count(*) FROM interlock.window_ledger "
            "WHERE at < clock_timestamp() - make_interval(secs => %s)",
            (horizon,),
        )
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


Scrape = dict[str, dict[tuple[tuple[str, str], ...], float]]
"""A scrape's samples: ``{name: {labels: value}}``."""

_TYPE = re.compile(r"# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge|histogram)")
_SAMPLE = re.compile(
    r"([a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{((?:[a-zA-Z_][a-zA-Z0-9_]*=\"(?:[^\"\\\n]|\\[\\\"n])*\",?)*)\})?"
    r" ([-+]?(?:[0-9.]+(?:[eE][-+]?[0-9]+)?|Inf|NaN))"
)
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\[\\"n])*)"')
_MONOTONIC = ("_total", "_count", "_sum", "_bucket")


def parse_scrape(text: str) -> tuple[set[str], Scrape]:
    """The families a Prometheus text exposition declares, and its samples;
    :class:`ValueError` on any line the format does not allow."""
    families: set[str] = set()
    samples: Scrape = {}
    if not text.endswith("\n"):
        raise ValueError("the exposition does not end with a newline")
    for line in text.rstrip("\n").split("\n"):
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            typed = _TYPE.fullmatch(line)
            if typed is None or typed.group(1) in families:
                raise ValueError(f"a bad or repeated TYPE line: {line!r}")
            families.add(typed.group(1))
            continue
        match = _SAMPLE.fullmatch(line)
        if match is None:
            raise ValueError(f"not a sample: {line!r}")
        labels = tuple(_LABEL.findall(match.group(2) or ""))
        series = samples.setdefault(match.group(1), {})
        if labels in series:
            raise ValueError(f"a series twice: {line!r}")
        series[labels] = float("inf") if match.group(3) == "+Inf" else float(match.group(3))
    return families, samples


class Scraper(threading.Thread):
    """Scrapes one node's ``/metrics`` every :data:`METRICS_EVERY` seconds, as
    Prometheus would, for as long as that process lives, and checks each
    scrape as it comes: well formed; every counter and histogram at least what
    it was; no window above its limit; no more engines busy than there are."""

    def __init__(self, port: int, node: str = "", incarnation: int = 0) -> None:
        super().__init__(name=f"soak-scraper-{node}-{incarnation}", daemon=True)
        self.port = port
        self.node = node
        self.incarnation = incarnation
        self._halt = threading.Event()
        self._serial = threading.Lock()
        self.scrapes = 0
        self.errors: Counter[str] = Counter()
        self.fell: list[str] = []
        self.saturation: dict[str, float] = defaultdict(float)
        self.busy = 0.0
        self.workers = 0.0
        self.families: set[str] = set()
        self._last: Scrape = {}
        self.last: Scrape = {}
        """The last scrape that came: what a process killed last said."""

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        while not self._halt.wait(METRICS_EVERY):
            self.scrape()

    def scrape(self) -> Scrape | None:
        """One scrape, checked; ``None`` when it could not be had or read.
        One at a time: a scrape checked after a later one would seem to fall."""
        with self._serial:
            return self._scrape()

    def _scrape(self) -> Scrape | None:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/metrics", timeout=10) as r:
                text = r.read().decode()
        except OSError as exc:
            self.errors[type(exc).__name__] += 1
            return None
        try:
            families, samples = parse_scrape(text)
        except ValueError as exc:
            self.errors["malformed"] += 1
            logger.error("an ill-formed scrape: %s", exc)
            return None
        self.scrapes += 1
        self.families = families
        for name, series in samples.items():
            if not name.endswith(_MONOTONIC):
                continue
            before = self._last.get(name, {})
            for labels, value in series.items():
                if value < before.get(labels, 0.0):
                    self.fell.append(f"{name}{dict(labels)}: {before[labels]} to {value}")
        self._last = samples
        self.last = samples
        for labels, value in samples.get("interlock_window_saturation", {}).items():
            window = dict(labels)["window"]
            self.saturation[window] = max(self.saturation[window], value)
        self.busy = max(self.busy, samples.get("interlock_engine_workers_busy", {}).get((), 0))
        self.workers = samples.get("interlock_engine_workers", {}).get((), self.workers)
        return samples


@dataclass
class Settled:
    """A scrape of the settled daemon, of a sample of the database that began
    after ``before`` was read and ended before ``after`` was: the vacuum may
    prune between them, so each state's count in the sample lies between."""

    scrape: Scrape
    before: dict[str, int]
    after: dict[str, int]


def outbox_states(conn: psycopg.Connection[Any]) -> dict[str, int]:
    rows = conn.execute("SELECT state, count(*) FROM interlock.outbox_state GROUP BY state")
    return {str(state): int(n) for state, n in rows.fetchall()}


def read_settled(scraper: Scraper, conn: psycopg.Connection[Any]) -> Settled | None:
    """A settled node's metrics, against the database. Its sampler takes one
    sample after another, so the second sampled after ``before`` was read
    began after it; any scrape after that one shows it, or a later one."""
    before = outbox_states(conn)
    asked = time.time()
    seen: set[float] = set()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        scraped = scraper.scrape()
        at = (scraped or {}).get("interlock_metrics_sampled_at_seconds", {}).get((), 0.0)
        if at > asked:
            seen.add(at)
        if len(seen) >= 2:
            final = scraper.scrape()
            if final is not None:
                return Settled(final, before, outbox_states(conn))
        time.sleep(METRICS_EVERY / 4)
    return None


# --------------------------------------------------------------------------
# What the harness itself logs
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


# --------------------------------------------------------------------------
# The cluster, as the database sees it
# --------------------------------------------------------------------------

HOLDERS = """
SELECT l.objid::bigint, a.application_name
  FROM pg_locks AS l JOIN pg_stat_activity AS a ON a.pid = l.pid
 WHERE l.locktype = 'advisory' AND l.classid = %s::bigint::oid AND l.objsubid = 2 AND l.granted
   AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
"""
"""Who holds the locks of one class: each lock's key, and its session's name."""


class Watch(threading.Thread):
    """Samples who holds each role every 0.2 seconds, from ``pg_locks``: the
    claims of who led what read it, and the chaos picks its victim from it."""

    def __init__(self, site: Site, roles: Sequence[str]) -> None:
        super().__init__(name="soak-watch", daemon=True)
        self._site = site
        self._halt = threading.Event()
        self.role_keys = {lock_key("role", r) & 0xFFFFFFFF: r for r in roles}
        self.leaders: list[tuple[float, dict[str, str]]] = []
        """Each change of who leads what: when (wall clock), and every role's holder then."""
        self.doubled: list[str] = []
        """Any sample in which two sessions held one role: never, by PostgreSQL."""
        self.samples = 0
        self.errors: Counter[str] = Counter()

    def stop(self) -> None:
        self._halt.set()

    def leader(self, role: str, at: float | None = None) -> str | None:
        """Who held ``role`` at wall-clock ``at`` (now, by default), as sampled."""
        holder = None
        for when, holders in list(self.leaders):
            if at is not None and when > at:
                break
            holder = holders.get(role)
        return holder

    def run(self) -> None:
        conn = psycopg.connect(self._site.owner, autocommit=True)
        try:
            while not self._halt.wait(0.2):
                try:
                    self._tick(conn)
                except psycopg.Error as exc:
                    self.errors[type(exc).__name__] += 1
                    with contextlib.suppress(psycopg.Error):
                        conn.close()
                    conn = psycopg.connect(self._site.owner, autocommit=True)
        finally:
            conn.close()

    def _tick(self, conn: psycopg.Connection[Any]) -> None:
        self.samples += 1
        holders: dict[str, str] = {}
        for objid, name in conn.execute(HOLDERS, (LEADER_LOCK,)).fetchall():
            role = self.role_keys.get(int(objid))
            if role is None:
                continue
            node = str(name).removeprefix("interlock-cluster@")
            if role in holders and holders[role] != node:
                self.doubled.append(f"{role}: {holders[role]} and {node} at {time.time():.3f}")
            holders[role] = node
        if not self.leaders or self.leaders[-1][1] != holders:
            self.leaders.append((time.time(), holders))


# --------------------------------------------------------------------------
# The chaos: a node killed, a node frozen
# --------------------------------------------------------------------------

IN_FLIGHT = """
SELECT s.message_id::text,
       (SELECT a.event FROM interlock.outbox_attempts AS a
         WHERE a.message_id = s.message_id ORDER BY a.seq DESC LIMIT 1)
  FROM interlock.outbox_state AS s
 WHERE s.state = 'leased' AND s.lease_node = %s
"""
"""The leases a node holds, and the last thing each message's log says:
``sending`` is a call made and not answered yet."""

SESSIONS = """
SELECT a.pid, a.application_name, a.state, a.xact_start IS NOT NULL,
       EXISTS (SELECT 1 FROM pg_locks AS l
                WHERE l.pid = a.pid AND l.granted AND l.locktype <> 'virtualxid'
                  AND NOT (l.locktype = 'relation' AND l.mode = 'AccessShareLock'))
  FROM pg_stat_activity AS a
 WHERE a.datname = current_database() AND a.application_name LIKE %s
"""
"""A node's sessions: each one's name and state, whether it is inside a
transaction, and whether it holds a lock another session could wait for: a
row's, an advisory lock, a writer's; a read snapshot's ``AccessShareLock``
holds no writer up."""


@dataclass
class DeathReport:
    """One death, and what the cluster and the database did about it."""

    how: str
    """``killed``: SIGKILL, its sockets closed at once by the kernel.
    ``frozen``: SIGSTOP, its connections left open as a host lost to the
    network leaves them; then SIGKILL, once the server had let go of it."""
    node: str
    incarnation: int
    at: float = 0.0
    """Wall clock: the SIGKILL, or the SIGSTOP."""
    led: list[str] = field(default_factory=list)
    """The roles the node led as it died."""
    leases: dict[str, str] = field(default_factory=dict)
    """Each message it held leased then, and its log's last event."""
    keys: dict[str, str] = field(default_factory=dict)
    """Each of those messages' idempotency key: a tombstone keeps none, and
    the vacuum may prune the message before the claims are read."""
    sessions: dict[int, tuple[str, str, bool, bool]] = field(default_factory=dict)
    """Each session it had then: its name, its state, whether inside a
    transaction, whether holding a lock another could wait for."""
    gone: dict[int, float] = field(default_factory=dict)
    """Seconds after the death until each of its sessions was gone."""
    released: dict[int, float] = field(default_factory=dict)
    """Seconds after the death until each session that held a lock another
    could wait for held none: gone, or its transaction over. A statement past
    its bound aborts the transaction and its locks with it; the session may
    stay, idle in the aborted transaction, holding nothing."""
    fenced: float | None = None
    """Seconds after the death until every session it had was gone: at once
    for a process killed; for one frozen, once a survivor fenced it."""
    fencers: list[str] = field(default_factory=list)
    """The nodes whose heartbeat ended its sessions, as their logs say."""
    node_lock: float | None = None
    """Seconds after the death until no session held its node's lock."""
    taken: dict[str, float] = field(default_factory=dict)
    """Seconds after the death until each of its leases was another's, or done."""
    took: dict[str, tuple[str, float]] = field(default_factory=dict)
    """Each role it led: the node that took it, and seconds after the death."""
    killed_after: float = 0.0
    """For a freeze: seconds after it froze until it was killed."""
    back_after: float = 0.0
    """Seconds after the death until its next incarnation was up."""
    waited: float = 0.0
    """The longest a survivor waited on any lock, from the death until every
    session the dead node had was gone."""
    blocked: float = 0.0
    """The longest a survivor waited on one of the dead node's sessions
    (holding the lock, or ahead in its queue) over the same span."""
    error: str | None = None


def victim(run: Run) -> Node | None:
    """The node leading the vacuum now, alive: the costliest to lose, since
    it holds the cluster's one singleton every node waits on."""
    holder = run.watch.leader("vacuum")
    return next((n for n in run.nodes if n.name == holder and n.alive), None)


def _poised(conn: psycopg.Connection[Any], node: Node, how: str) -> bool:
    """Whether ``node`` is in the middle of things: a call made and not
    answered; and, for a freeze, a stage open too."""
    calls = [m for m, last in conn.execute(IN_FLIGHT, (node.name,)).fetchall() if last == "sending"]
    if not calls:
        return False
    if how == "killed":
        return True
    row = conn.execute(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s "
        "AND xact_start IS NOT NULL",
        (f"interlock-stage@{node.name}",),
    ).fetchone()
    return bool(row and row[0])


def die(run: Run, how: str) -> DeathReport | None:
    """Kill, or freeze then kill, the node leading the vacuum, at a moment its
    relays have a call in flight (and, to freeze it, a stage open); watch
    what the database and the cluster do about it; and bring it back, as a
    pod is rescheduled. Never raises: what went wrong is the claims' to report.

    The moment is found by stopping the node (``SIGSTOP``) and looking: a
    stopped process changes nothing, so what is read then is what it dies
    holding. Not poised, it is let go on (``SIGCONT``), as if descheduled for a
    few milliseconds, and looked at again shortly. Poised, it is killed
    (``SIGKILL``), or left frozen."""
    node = victim(run)
    if node is None:
        return None
    report = DeathReport(how, node.name, node.incarnation)
    try:
        conn = psycopg.connect(run.site.owner, autocommit=True)
        try:
            deadline = time.monotonic() + 30
            while True:
                stopped = node.freeze()
                if _poised(conn, node, how) or time.monotonic() > deadline:
                    break
                node.thaw()
                time.sleep(random.uniform(0.005, 0.03))
            holders = run.watch.leaders[-1][1] if run.watch.leaders else {}
            report.led = sorted(role for role, holder in holders.items() if holder == node.name)
            scraper = run.scraper(node)
            if scraper is not None:
                scraper.stop()
            # What it holds as it dies, read while it is stopped.
            report.sessions = {
                int(pid): (str(name), str(state), bool(open_), bool(holding))
                for pid, name, state, open_, holding in conn.execute(
                    SESSIONS, (f"%@{node.name}",)
                ).fetchall()
            }
            report.leases = dict(conn.execute(IN_FLIGHT, (node.name,)).fetchall())
            report.keys = dict(
                conn.execute(
                    "SELECT message_id::text, idempotency_key FROM interlock.outbox "
                    "WHERE message_id::text = ANY (%s)",
                    (list(report.leases),),
                ).fetchall()
            )
            report.at = node.kill() if how == "killed" else stopped
            say(
                run.settings,
                f"  {time.monotonic() - run.started:6.0f}s  node {node.name} {how}, leading "
                f"{', '.join(report.led) or 'nothing'}, with {len(report.leases)} lease(s) and "
                f"{sum(1 for *_, h in report.sessions.values() if h)} session(s) holding locks",
            )
            _watch_death(run, conn, node, report)
            if how == "frozen":
                node.kill()
                report.killed_after = time.time() - report.at
        finally:
            conn.close()
        report.fencers = fencers(run, node)
        rest = run.settings.restart_after - (time.time() - report.at - report.killed_after)
        time.sleep(max(0.0, rest))
        start(run, node)
        node.wait_ready()
        scrape(run, node)
        report.back_after = time.time() - report.at
        say(
            run.settings,
            f"  {time.monotonic() - run.started:6.0f}s  node {node.name} back as incarnation "
            f"{node.incarnation}",
        )
    except Exception as exc:
        report.error = f"{type(exc).__name__}: {exc}"
        logger.exception("the %s node could not be watched or brought back", how)
        if node.alive and node.incarnation == report.incarnation:
            with contextlib.suppress(Exception):
                node.kill()
    # The waits from the death until every session it had was gone: any
    # survivor's, and those on one of its sessions.
    until = report.at + (report.fenced if report.fenced is not None else report.back_after)
    mine = f"@{node.name}"
    spans = [w for w in run.auditor.longest if report.at <= w[0] <= until]
    report.waited = max((w[1] for w in spans), default=0.0)
    report.blocked = max((w[1] for w in spans if any(b.endswith(mine) for b in w[3])), default=0.0)
    return report


FENCED = re.compile(r"node (?P<fencer>\S+): node (?P<gone>\S+) is gone; its sessions ended")
"""What a node logs when it fences another (``interlock.cluster``)."""


def fencers(run: Run, dead: Node) -> list[str]:
    """The nodes whose logs say they ended a session of ``dead``'s."""
    found: set[str] = set()
    for node in run.nodes:
        if node is dead or node.incarnation < 0:
            continue
        with contextlib.suppress(OSError):
            for line in node.log(node.incarnation).read_text(encoding="utf-8").splitlines():
                match = FENCED.search(line)
                if match is not None and match.group("gone") == dead.name:
                    found.add(match.group("fencer"))
    return sorted(found)


def _watch_death(run: Run, conn: psycopg.Connection[Any], node: Node, report: DeathReport) -> None:
    """Until the database and the cluster have let go of all the dead node
    held: its node's lock, every lock its sessions held, every session it had
    (fenced, for one frozen), its leases, the roles it led; or until every
    bound has passed, with margin."""
    settings = run.settings
    bound = 2 * settings.max_stage + LOCK_TIMEOUT + settings.session_timeout + 10
    deadline = report.at + bound
    key = lock_key("node", node.name) & 0xFFFFFFFF
    leases = set(report.leases)
    holding = {pid for pid, (*_, held) in report.sessions.items() if held}
    while time.time() < deadline:
        now = time.time() - report.at
        current = {
            int(row[0]): bool(row[4])
            for row in conn.execute(SESSIONS, (f"%@{node.name}",)).fetchall()
        }
        for pid in report.sessions:
            if pid not in current and pid not in report.gone:
                report.gone[pid] = now
            if pid in holding and pid not in report.released and not current.get(pid):
                report.released[pid] = now
        if report.fenced is None and not set(report.sessions) & set(current):
            report.fenced = now
        held = {int(o) for o, _ in conn.execute(HOLDERS, (NODE_LOCK,)).fetchall()}
        if report.node_lock is None and key not in held:
            report.node_lock = now
        for message in leases - set(report.taken):
            row = conn.execute(
                "SELECT state, lease_node FROM interlock.outbox_state WHERE message_id = %s",
                (message,),
            ).fetchone()
            if row is None or row[0] != "leased" or row[1] != node.name:
                report.taken[message] = now
        holders = run.watch.leaders[-1][1] if run.watch.leaders else {}
        for role in report.led:
            holder = holders.get(role)
            if role not in report.took and holder is not None and holder != node.name:
                report.took[role] = (holder, now)
        others = [r for r in report.led if r != f"settler:{receipts_log_id(node.name)}"]
        if (
            report.node_lock is not None
            and report.fenced is not None
            and holding <= set(report.released)
            and leases <= set(report.taken)
            and all(r in report.took for r in others)
        ):
            return
        time.sleep(0.05)


# --------------------------------------------------------------------------
# Running it
# --------------------------------------------------------------------------

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent


@dataclass
class Run:
    """Everything the run measured, for the claims."""

    settings: Settings
    config: InterlockConfig
    """The first node's configuration: what every node's but its node and
    receipt log, as the harness's operator and verifiers read it."""
    site: Site
    keys: Keys
    nodes: list[Node]
    environment: dict[str, str]
    api: PaymentAPI
    vendor: Vendor
    balancer: Balancer
    desk: Desk
    auditor: Auditor
    watch: Watch
    captured: Captured
    t0: float = 0.0
    """When the run began, wall clock: the bursts' clock, every node's."""
    deadlocks_before: int = 0
    deadlocks_after: int = 0
    started: float = 0.0
    load_seconds: float = 0.0
    quiesced: bool = False
    quiesce_seconds: float = 0.0
    outstanding: dict[str, int] = field(default_factory=dict)
    stops: dict[str, tuple[int, float]] = field(default_factory=dict)
    """Each node's last stop: its exit status, and how long it took."""
    second: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Each node started again after the run: ready, what it recovered, its
    stop, its failures."""
    scrapers: dict[tuple[str, int], Scraper] = field(default_factory=dict)
    settled: Settled | None = None
    rotation: Rotation = field(default_factory=Rotation)
    deaths: list[DeathReport] = field(default_factory=list)
    journals: Journals = field(default_factory=Journals)
    live_at_end: int = 0
    total_at_end: int = 0
    failure: str | None = None

    def scraper(self, node: Node) -> Scraper | None:
        return self.scrapers.get((node.name, node.incarnation))


def node_environment(api_key: str, webhook_secret: str, token: str) -> dict[str, str]:
    """What a node's process runs with: the harness's environment, without
    anything of Interlock's own, and the secrets the parts read from it."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("INTERLOCK_")}
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SCRIPTS), str(ROOT / "src"), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    env.update({API_KEY_ENV: api_key, WEBHOOK_SECRET_ENV: webhook_secret, KMS_TOKEN_ENV: token})
    return env


def start(run: Run, node: Node) -> None:
    """``node``'s next incarnation, as a pod is started: its spec written
    beside its configuration, its process started."""
    settings = run.settings
    incarnation = node.incarnation + 1
    spec = NodeSpec(
        name=node.name,
        index=node.index,
        incarnation=incarnation,
        settings=settings,
        journal=str(node.journal(incarnation)),
        wind_down=str(run.site.directory / "wind-down"),
        t0=run.t0,
        hot=settings.hot,
    )
    node.start(spec, run.environment)


def scrape(run: Run, node: Node) -> None:
    """A scraper for ``node``'s incarnation that is up."""
    assert node.metrics_port is not None
    scraper = Scraper(node.metrics_port, node.name, node.incarnation)
    run.scrapers[(node.name, node.incarnation)] = scraper
    scraper.start()


def deadlocks(dsn: str) -> int:
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
        ).fetchone()
    return int(row[0]) if row else 0


def journals(run: Run) -> Journals:
    """Every node's journals, as they stand."""
    return Journals.read(
        {
            (node.name, number): node.journal(number)
            for node in run.nodes
            for number in range(node.incarnation + 1)
        }
    )


def outstanding(conn: psycopg.Connection[Any], run: Run) -> dict[str, int]:
    """What is still to happen before the run is settled."""
    (unfinished, dead, unsettled, unbound, pending) = one(
        conn,
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
        """,
    )
    lives = journals(run).incarnations
    inflight = sum(
        life.submitted - life.answered
        for (name, number), life in lives.items()
        if any(n.name == name and n.incarnation == number and n.alive for n in run.nodes)
    )
    return {
        "undelivered messages": int(unfinished),
        "dead messages": int(dead),
        "unsettled deliveries": int(unsettled),
        "unbound events": int(unbound),
        "unconsumed facts": int(pending),
        "webhooks to send": run.vendor.backlog(),
        "plans in flight": inflight,
    }


def one(
    conn: psycopg.Connection[Any], query: LiteralString, args: Sequence[Any] = ()
) -> tuple[Any, ...]:
    """The one row a query of counts answers with. Without arguments, a
    ``%`` in the query is the query's own."""
    row = conn.execute(query, args or None).fetchone()
    assert row is not None
    return tuple(row)


def say(settings: Settings, text: str) -> None:
    if not settings.quiet:
        print(text, flush=True)


def progress(run: Run) -> str:
    """What every node up has done, as its metrics say."""

    def total(name: str, **labels: str) -> float:
        summed = 0.0
        for node in run.nodes:
            scraper = run.scraper(node)
            if scraper is None or not node.alive:
                continue
            summed += scraper.last.get(name, {}).get(tuple(labels.items()), 0.0)
        return summed

    sample = run.auditor.samples[-1] if run.auditor.samples else None
    up = [n.name for n in run.nodes if n.alive]
    leading = run.watch.leader("vacuum") or "-"
    return (
        f"  {time.monotonic() - run.started:6.0f}s  {len(up)} node(s) up, vacuum led by "
        f"{leading}  plans {total('interlock_plans_total', outcome='committed'):.0f} committed"
        f" / {total('interlock_plans_total', outcome='refused'):.0f} refused"
        f"  delivered {total('interlock_deliveries_total', sink=SINK, outcome='delivered'):.0f}"
        f"  webhooks {sum(1 for s in run.vendor.sent if s.status == 200)}"
        f"  receipts {total('interlock_receipts_issued_total'):.0f}"
        + (f"  outbox {sample.live} live / {sample.pruned} pruned" if sample else "")
    )


def drive(run: Run) -> None:
    """Start every node, load the cluster, kill two of its nodes, wind it
    down, let it settle, and stop it."""
    settings = run.settings
    run.t0 = time.time()
    for node in run.nodes:
        start(run, node)
    for node in run.nodes:
        node.wait_ready()
        scrape(run, node)
    run.started = time.monotonic()
    run.balancer.start()
    run.auditor = Auditor(run.site, settings, run.started)
    run.auditor.start()
    run.watch.start()
    run.desk.start()
    say(
        settings,
        f"cluster ready: {len(run.nodes)} nodes, inboxes on "
        + ", ".join(f"{n.name} 127.0.0.1:{n.inbox_port}" for n in run.nodes)
        + f"; load for {settings.minutes:g} min",
    )
    load(run)
    settle(run)
    stop_all(run)


def load(run: Run) -> None:
    settings = run.settings
    end = run.started + settings.minutes * 60
    events: list[tuple[float, str]] = [(ROTATE_AT, "rotate")]
    if settings.chaos and settings.nodes >= 2:
        events += [(KILL_AT, "killed"), (FREEZE_AT, "frozen")]
    threads: list[threading.Thread] = []
    next_report = run.started + 10
    while (now := time.monotonic()) < end:
        time.sleep(min(1.0, end - now))
        elapsed = (time.monotonic() - run.started) / (settings.minutes * 60)
        while events and elapsed >= events[0][0]:
            _, what = events.pop(0)
            if what == "rotate":
                target: Callable[[], Any] = lambda: rotate(run)  # noqa: E731
            else:
                target = _death(run, what)
            thread = threading.Thread(target=target, name=f"soak-{what}", daemon=True)
            thread.start()
            threads.append(thread)
        if time.monotonic() >= next_report:
            say(settings, progress(run))
            next_report += 10
    run.load_seconds = time.monotonic() - run.started
    # A death late in the load is still being watched, and its node brought
    # back: everything it left is settled by its next incarnation.
    for thread in threads:
        thread.join(240)
    if not all(node.alive for node in run.nodes):
        raise SoakError(
            "a node is not up after the load: "
            + ", ".join(
                f"{n.name} exited {n.exits.get(n.incarnation)}" for n in run.nodes if not n.alive
            )
        )


def _death(run: Run, how: str) -> Callable[[], None]:
    def dying() -> None:
        report = die(run, how)
        if report is not None:
            run.deaths.append(report)

    return dying


def settle(run: Run) -> None:
    """No new work: until everything in flight is delivered, settled and
    consumed, or the quiesce bound passes."""
    settings = run.settings
    say(settings, "winding down: no new work; everything in flight settles")
    (run.site.directory / "wind-down").touch()
    run.desk.stop()
    run.desk.join(60)
    begun = time.monotonic()
    conn = psycopg.connect(run.site.owner, autocommit=True)
    try:
        calm = 0
        while time.monotonic() - begun < settings.quiesce:
            left = outstanding(conn, run)
            run.outstanding = left
            busy = {k: v for k, v in left.items() if v and k != "dead messages"}
            calm = calm + 1 if not busy else 0
            if calm >= 3:
                run.quiesced = True
                break
            time.sleep(0.5)
        if run.quiesced:
            scraper = next(
                (run.scraper(n) for n in run.nodes if n.alive and run.scraper(n) is not None), None
            )
            if scraper is not None:
                run.settled = read_settled(scraper, conn)
        row = conn.execute(
            "SELECT (SELECT count(*) FROM interlock.outbox),"
            " (SELECT count(*) FROM interlock.outbox)"
            " + (SELECT count(*) FROM interlock.outbox_compacted)"
        ).fetchone()
        run.live_at_end, run.total_at_end = (int(row[0]), int(row[1])) if row else (0, 0)
    finally:
        conn.close()
    run.quiesce_seconds = time.monotonic() - begun
    say(settings, progress(run))
    say(
        settings,
        f"{'settled' if run.quiesced else 'NOT settled'} in {run.quiesce_seconds:.1f}s"
        + ("" if run.quiesced else f": {run.outstanding}"),
    )


def stop_all(run: Run) -> None:
    """``SIGTERM`` to every node, together, as a rollout's end does; each
    must stop within its drain bound."""
    for scraper in run.scrapers.values():
        scraper.stop()
    stops: dict[str, tuple[int, float]] = {}

    def stopping(node: Node) -> None:
        stops[node.name] = node.stop()

    threads = [
        threading.Thread(target=stopping, args=(n,), daemon=True) for n in run.nodes if n.alive
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    run.stops = stops
    say(
        run.settings,
        "every node stopped: "
        + ", ".join(
            f"{name} {code} in {took:.2f}s" for name, (code, took) in sorted(stops.items())
        ),
    )


def second(run: Run) -> None:
    """Every node started again over its files and the database: it
    recovers nothing, and stops as cleanly."""
    for node in run.nodes:
        start(run, node)
    for node in run.nodes:
        try:
            node.wait_ready(120)
            ready = True
        except SoakError:
            ready = False
        run.second[node.name] = {"ready": ready, "incarnation": node.incarnation}
    time.sleep(1.0)
    for node in run.nodes:
        if node.alive:
            code, took = node.stop()
        else:
            code, took = node.exits.get(node.incarnation, -1), 0.0
        status = node.statuses.get(node.incarnation, {})
        engines = parse_status(status.get("engines", ""))
        run.second[node.name].update(
            {
                "exit": code,
                "seconds": took,
                "recovered": engines[3].get("recovered", 0) if engines else -1,
                "failed": {
                    name: rest for name, rest in status.items() if " 0 failure(s)" not in rest
                },
            }
        )


def parse_status(rest: str) -> tuple[str, int, int, dict[str, int]] | None:
    """A part's line as a stopped daemon prints it: ``stopped, 3 step(s), 0
    failure(s); committed 12, refused 2``."""
    head, _, tail = rest.partition("; ")
    parts = head.split(", ")
    if len(parts) != 3:
        return None
    counters: dict[str, int] = {}
    for item in filter(None, tail.split(", ")):
        name, _, value = item.rpartition(" ")
        with contextlib.suppress(ValueError):
            counters[name] = int(value)
    return parts[0], int(parts[1].split()[0]), int(parts[2].split()[0]), counters


def halt(run: Run) -> None:
    """Whatever is left: every thread stopped, every node's process gone."""
    for scraper in run.scrapers.values():
        scraper.stop()
    for node in run.nodes:
        if node.process is not None and node.process.poll() is None:
            with contextlib.suppress(Exception):
                node.process.send_signal(signal.SIGCONT)
                node.process.kill()
                node.process.wait(30)
    run.desk.stop()
    run.auditor.stop()
    run.watch.stop()
    run.balancer.stop()
    for thread in (run.auditor, run.watch, run.desk):
        if thread.is_alive():
            thread.join(30)


def soak(settings: Settings, server: Server, *, keep: bool, directory: Path | None) -> int:
    """Run the soak on ``server``; returns the exit status."""
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
    site = new_site(server, workdir)
    vendor: Vendor | None = None
    api: PaymentAPI | None = None
    service: KeyService | None = None
    balancer: Balancer | None = None
    try:
        create_site(site, settings)
        site.shared.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(16)
        os.environ[KMS_TOKEN_ENV] = token
        service = KeyService(token)
        keys = Keys.generate(site.shared, service)
        api_key = "sk_test_" + secrets.token_hex(12)
        webhook_secret = "whsec_" + secrets.token_hex(16)
        # The harness's stale relay reads the API key as every relay does.
        os.environ[API_KEY_ENV] = api_key
        os.environ[WEBHOOK_SECRET_ENV] = webhook_secret
        balancer = Balancer()
        vendor = Vendor(webhook_secret, settings.seed + 1, balancer)
        api = PaymentAPI(api_key, vendor, Faults().scaled(settings.faults), settings.seed + 2)
        nodes = [
            Node(index, name, site.home(name), write_config(site, settings, keys, api.port, name))
            for index, name in enumerate(settings.node_names)
        ]
        balancer.serve(nodes)
        install(nodes[0].config, keys)
        os.environ.pop("INTERLOCK_NODE", None)
        config = load_config(nodes[0].config)
        say(
            settings,
            f"soak database {site.name}: Interlock installed, {len(nodes)} nodes' files in "
            f"{workdir}",
        )
        api.start()
        vendor.start()
        roles = ["vacuum", "inbox-matcher", *(f"settler:{receipts_log_id(n.name)}" for n in nodes)]
        run = Run(
            settings,
            config,
            site,
            keys,
            nodes,
            node_environment(api_key, webhook_secret, token),
            api,
            vendor,
            balancer,
            Desk(config, site, keys, settings),
            Auditor(site, settings, time.monotonic()),
            Watch(site, roles),
            captured,
        )
        run.deadlocks_before = deadlocks(site.owner)
        try:
            drive(run)
            second(run)
        except SoakError as exc:
            run.failure = str(exc)
        except Exception as exc:
            logger.exception("the soak failed")
            run.failure = f"{type(exc).__name__}: {exc}"
        finally:
            halt(run)
        run.deadlocks_after = deadlocks(site.owner)
        run.journals = journals(run)
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
        if service is not None:
            service.close()
        if balancer is not None:
            balancer.stop()
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


@dataclass
class Evidence:
    """What the claims read once, after the run: every node's chains and
    receipt logs, the operator log, and each node's incarnations."""

    chains: dict[str, list[Any]]
    """Each node's escrow chains' records."""
    committed: set[str]
    """Every plan a chain records committed, recovered commits included."""
    terminal: dict[str, str]
    """Each plan's last record in the chains: committed, aborted..."""
    recovered: set[str]
    """Every plan whose commit intent a recovery resolved."""
    receipts: dict[str, list[Any]]
    """Each node's receipt log's delivery receipts."""
    actions: dict[str, int]
    """Each node's receipt log's action receipts."""
    records: tuple[Any, ...]
    """The operator log."""
    stopped: dict[tuple[str, int], dict[str, tuple[str, int, int, dict[str, int]]]]
    """Each incarnation of the run proper that stopped (not one killed, not the
    second start): its parts' last lines."""
    killed: list[tuple[str, int]]
    unissued: dict[str, set[str]] = field(default_factory=dict)
    """Each node's plans whose commit names an action receipt its log does not
    hold: committed by an incarnation that died before it issued it."""


def chain_paths(run: Run, node: Node) -> list[Path]:
    engine = run.config.engine
    assert engine.chain is not None
    return [
        node.home / path.name
        for index in range(engine.workers)
        if (path := engine.chain_for(index, engine.workers)) is not None
    ]


def gather(run: Run) -> Evidence:
    from agentgov.receipts import ReceiptLog

    from interlock.chain import RecordType
    from interlock.records import read_records

    chains: dict[str, list[Any]] = {}
    committed: set[str] = set()
    terminal: dict[str, str] = {}
    recovered: set[str] = set()
    for node in run.nodes:
        chains[node.name] = []
        for path in chain_paths(run, node):
            if path.exists():
                chains[node.name] += EscrowChain.load(path).records()
        for record in chains[node.name]:
            if record.record_type in (RecordType.COMMITTED, RecordType.ABORTED):
                terminal[str(record.plan_id)] = record.record_type.value
                if record.note.startswith("recovered:"):
                    recovered.add(str(record.plan_id))
            if record.record_type is RecordType.COMMITTED:
                committed.add(str(record.plan_id))
    receipts: dict[str, list[Any]] = {}
    actions: dict[str, int] = {}
    settings = run.config.receipts
    assert settings is not None and settings.key is not None
    unissued: dict[str, set[str]] = {}
    for node in run.nodes:
        path = node.home / settings.log.name
        named = {
            str(record.plan_id): record.note.rsplit("; receipt ", 1)[1]
            for record in chains[node.name]
            if record.record_type is RecordType.COMMITTED and "; receipt " in record.note
        }
        if not path.exists():
            receipts[node.name], actions[node.name] = [], 0
            unissued[node.name] = set(named)
            continue
        log = ReceiptLog(receipts_log_id(node.name), load_key(settings.key), path=path)
        try:
            receipts[node.name] = list(log.deliveries())
            actions[node.name] = len(log) - len(receipts[node.name])
            unissued[node.name] = {p for p, r in named.items() if log.index_of(r) is None}
        finally:
            log.close()
    operators = run.config.operators
    assert operators is not None
    records = read_records(operators.log) if operators.log.exists() else ()
    second = {(name, int(found["incarnation"])) for name, found in run.second.items()}
    stopped = {}
    killed = []
    for node in run.nodes:
        for number, lines in node.statuses.items():
            if (node.name, number) in second:
                continue
            if node.exits.get(number) == -signal.SIGKILL:
                killed.append((node.name, number))
                continue
            stopped[(node.name, number)] = {
                part: parsed for part, rest in lines.items() if (parsed := parse_status(rest))
            }
        for number in range(node.incarnation + 1):
            if node.exits.get(number) == -signal.SIGKILL and (node.name, number) not in killed:
                killed.append((node.name, number))
    return Evidence(
        chains,
        committed,
        terminal,
        recovered,
        receipts,
        actions,
        records,
        stopped,
        killed,
        unissued=unissued,
    )


def prove(run: Run) -> list[Claim]:
    """Each claim, from the database, the ledger, the logs and the journals."""
    if run.failure is not None:
        return [Claim("the soak ran", False, [run.failure])]
    evidence = gather(run)
    with psycopg.connect(run.site.owner, autocommit=True) as conn:
        governor = BudgetManager.open_postgres(run.site.owner, read_only=True)
        try:
            entries = tuple(governor.audit_trail())
            proofs: list[tuple[str, Callable[[], Claim]]] = [
                ("no deadlocks", lambda: no_deadlocks(run)),
                ("lock waits resolve", lambda: lock_waits_resolve(run, evidence)),
                ("rate windows hold exactly", lambda: windows_hold(run, evidence)),
                (
                    "the ledger balances",
                    lambda: ledger_balances(run, evidence, conn, governor, entries),
                ),
                ("exactly once", lambda: exactly_once(run, evidence, conn)),
                ("no forgery accepted", lambda: no_forgery(run)),
                ("the vacuum compacts as it goes", lambda: vacuum_compacts(run, evidence, conn)),
                (
                    "everything verifies after",
                    lambda: everything_verifies(run, evidence, conn, entries),
                ),
                ("shutdown is graceful", lambda: graceful(run, evidence)),
                ("trace context survives", lambda: trace_survives(run)),
                ("metrics agree", lambda: metrics_agree(run, evidence, conn)),
                ("keys rotate", lambda: keys_rotate(run, conn)),
                ("nodes share the work", lambda: nodes_share_the_work(run, evidence)),
                ("one leader at a time", lambda: one_leader_at_a_time(run, evidence)),
                ("a node killed is survived", lambda: survived(run, evidence, "killed")),
                ("a node frozen is survived", lambda: survived(run, evidence, "frozen")),
            ]
            return [_proven(name, proof) for name, proof in proofs]
        finally:
            governor.close()


def _proven(name: str, proof: Callable[[], Claim]) -> Claim:
    """A claim, or why it could not be read: one that raises fails, and the
    rest are still read."""
    try:
        return proof()
    except Exception as exc:
        logger.exception("the claim %r could not be read", name)
        return Claim(name, False, [f"could not be read: {type(exc).__name__}: {exc}"])


def counters(evidence: Evidence, part: str) -> Counter[str]:
    """A part's counters, summed over every incarnation that stopped."""
    total: Counter[str] = Counter()
    for parts in evidence.stopped.values():
        for name, parsed in parts.items():
            if name == part or (part == "relay" and name.startswith("relay-")):
                total.update(parsed[3])
    return total


def no_deadlocks(run: Run) -> Claim:
    moved = run.deadlocks_after - run.deadlocks_before
    logged = _server_log_deadlocks(run)
    in_nodes = [
        f"{node.name}.{number}"
        for node in run.nodes
        for number in range(node.incarnation + 1)
        if node.log(number).exists()
        and "deadlock detected" in node.log(number).read_text(encoding="utf-8", errors="replace")
    ]
    evidence = [
        f"pg_stat_database.deadlocks: {run.deadlocks_before} before, {run.deadlocks_after} after",
        f"'deadlock detected' in what the nodes logged: {len(in_nodes)} "
        f"of {sum(n.incarnation + 1 for n in run.nodes)} processes; in the harness's: "
        f"{len(run.captured.deadlocks)}",
    ]
    if logged is not None:
        evidence.append(f"'deadlock detected' in the server's log: {logged}")
    held = moved == 0 and not run.captured.deadlocks and not logged and not in_nodes
    evidence += run.captured.deadlocks[:3] + in_nodes[:3]
    return Claim("no deadlocks", held, evidence)


def _server_log_deadlocks(run: Run) -> int | None:
    text = run.site.server.logs()
    if not text and run.site.server.container is None:
        return None
    return text.count("deadlock detected")


def _expected_error(key: str) -> bool:
    """An error the cluster expects: a fact replayed, refused at admission;
    and a fact another node's agent consumed first, a race lost across nodes."""
    return key.startswith("misbehave:fact_replay") or key == "reconcile: fact"


def lock_waits_resolve(run: Run, evidence: Evidence) -> Claim:
    auditor = run.auditor
    journals = run.journals
    engines = counters(evidence, "engines")
    stage_wait = auditor.max_wait.get("stage", 0.0)
    worst = max(auditor.max_wait.values(), default=0.0)
    unexpected = {k: v for k, v in journals.errors.items() if not _expected_error(k)}
    killed = set(evidence.killed)
    lives = journals.incarnations
    unanswered = {
        f"{name}.{number}": life.submitted - life.answered
        for (name, number), life in lives.items()
        if life.submitted != life.answered
    }
    unanswered_alive = {
        k: v
        for k, v in unanswered.items()
        if tuple(k.rsplit(".", 1)) not in {(n, str(i)) for n, i in killed}
    }
    mismatched = []
    for key, parts in evidence.stopped.items():
        life = lives.get(key)
        staged = parts.get("engines")
        if life is None or staged is None:
            continue
        counted = sum(staged[3].get(k, 0) for k in ("committed", "refused", "failed"))
        if counted != life.submitted:
            mismatched.append(f"{key[0]}.{key[1]}: staged {counted}, submitted {life.submitted}")
    conflicts = engines.get("conflicts", 0) + sum(
        scraper.last.get("interlock_plan_conflicts_total", {}).get((("cause", "lock"),), 0.0)
        for (name, number), scraper in run.scrapers.items()
        if (name, number) in killed
    )
    held = (
        stage_wait <= LOCK_TIMEOUT + 0.5
        and worst <= LEDGER_LOCK_TIMEOUT + 1
        and conflicts > 0
        and engines.get("conflicts_exhausted", 0) == 0
        and engines.get("unsettled", 0) == 0
        and engines.get("cancelled", 0) == 0
        and not unanswered_alive
        and not mismatched
        and not unexpected
    )
    races = sum(v for k, v in journals.errors.items() if k == "reconcile: fact")
    return Claim(
        "lock waits resolve",
        held,
        [
            f"{auditor.ticks} samples of pg_locks: {auditor.waits} waits seen; longest by role: "
            + ", ".join(f"{k} {v:.2f}s" for k, v in sorted(auditor.max_wait.items()))
            + f" (stages bounded at {LOCK_TIMEOUT}s, the ledger at {LEDGER_LOCK_TIMEOUT}s)",
            f"lost races retried: {conflicts:.0f}; given up: "
            f"{engines.get('conflicts_exhausted', 0)}; facts another node consumed first: {races}",
            f"plans submitted {journals.submitted}, answered {journals.answered}; in flight when "
            f"their node was killed: "
            + (", ".join(f"{k} {v}" for k, v in sorted(unanswered.items())) or "none")
            + f"; every process that stopped staged what it was given ({len(evidence.stopped)})",
            f"errors: {sum(journals.errors.values())}, all of them expected: fact replays refused "
            f"at admission, facts consumed first elsewhere"
            + (f"; unexpected: {dict(unexpected)}" if unexpected else ""),
            *(
                [f"answered fewer than submitted in a process that lived: {unanswered_alive}"]
                if unanswered_alive
                else []
            ),
            *mismatched[:3],
        ],
    )


def windows_hold(run: Run, evidence: Evidence) -> Claim:
    journals = run.journals
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
        b for p in journals.plans.values() for b in p.blocked_by if b.startswith("rate_window")
    )
    # Committed: what the chains say, recovered commits of a killed node's
    # plans in flight included.
    committed = {p for p in evidence.committed if p in journals.plans}
    checkouts = {p for p in committed if journals.plans[p].checkout}
    stages = {w: len({s for (s, n, _) in run.auditor.window_rows if n == w}) for w in limits}
    complete = stages.get("plans_per_tenant") == len(committed) and stages.get(
        "charged_per_agent"
    ) == len(checkouts)
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
            "refused by each window, across the nodes: "
            + ", ".join(f"{w} {refusals.get(f'rate_window:{w}', 0)}" for w in sorted(limits))
            + f" ({sum(journals.bursts.values())} bursts for one tenant filled its window)",
            f"every committed plan's rows seen: {len(committed)} committed, {len(checkouts)} of "
            f"them charges",
            *(breaches[:5] or ["no key ever held more than its limit within its span"]),
        ],
    )


def ledger_balances(
    run: Run,
    evidence: Evidence,
    conn: psycopg.Connection[Any],
    governor: BudgetManager,
    entries: Sequence[Any],
) -> Claim:
    journals = run.journals
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
    for records in evidence.chains.values():
        for record in records:
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
    in_flight = 0
    for plan_id, record in journals.plans.items():
        got = charged.pop(plan_id, [])
        price = SETTLE_COST + (CALL_COST if record.checkout else Decimal(0))
        if not record.answered:
            # In flight when its node was killed: committed, its whole price;
            # or not, at most what producing it cost.
            in_flight += 1
            if plan_id in evidence.committed:
                if got != [price]:
                    problems.append(f"plan {plan_id}, committed as its node died, charged {got}")
            elif got not in ([], [SETTLE_COST]):
                problems.append(f"plan {plan_id}, not committed as its node died, charged {got}")
        elif record.committed is None:
            if got:
                problems.append(f"plan {plan_id} raised, and was charged {got}")
            continue
        else:
            expected = price if record.committed else SETTLE_COST
            if got != [expected]:
                problems.append(
                    f"plan {plan_id} ({record.kind}) was charged {got}, not [{expected}]"
                )
        spent[record.scope] += sum(got, Decimal(0))
    for plan_id, got in charged.items():
        problems.append(f"plan {plan_id}, which no agent submitted, was charged {got}")
    (credited,) = one(
        conn,
        "SELECT (SELECT count(*) FROM interlock.outbox_settlements WHERE credit IS NOT NULL)"
        " + (SELECT count(*) FROM interlock.outbox_compacted WHERE credit IS NOT NULL)",
    )
    all_credits = [a for amounts in credits.values() for a in amounts]
    if len(all_credits) != int(credited) or any(a != CALL_COST for a in all_credits):
        problems.append(
            f"{len(all_credits)} credit(s) in the ledger, {credited} settled; amounts "
            f"{sorted(set(all_credits))}"
        )
    if int(credited) != run.desk.applied:
        problems.append(f"{run.desk.applied} refunds made, {credited} credited")
    for scope in sorted(scopes):
        expected_total = ENVELOPE - spent[scope] + sum(credits[scope], Decimal(0))
        available = governor.available(scope)
        if available != expected_total:
            problems.append(f"{scope}: {available} available, {expected_total} expected")
    total = sum(spent.values(), Decimal(0))
    charged_plans = sum(
        1 for r in journals.plans.values() if r.committed is not None or not r.answered
    )
    return Claim(
        "the ledger balances",
        not problems,
        [
            f"AgentGov: {len(entries)} entries, written by every node's governors; integrity and "
            f"conservation verified"
            if not any(p.startswith("verify_integrity") for p in problems)
            else "AgentGov's integrity check FAILED",
            f"{charged_plans} plans charged once each, exactly their price: {total} in all "
            f"({in_flight} in "
            f"flight when their node was killed, each charged as its chain says it ended)",
            f"{len(all_credits)} of {run.desk.applied} refunds credited back at {CALL_COST}, "
            f"each once, by the node that committed its charge",
            f"no hold left open ({len(holds)}), no claim unredeemed ({len(claims)}): every "
            f"killed node's next incarnation recovered what it left",
            *problems[:8],
        ],
    )


def exactly_once(run: Run, evidence: Evidence, conn: psycopg.Connection[Any]) -> Claim:
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
    hot = {str(i) for ids in run.settings.hot.values() for i in ids}
    committed = {
        str(r[0]) for r in conn.execute("SELECT id FROM orders").fetchall() if str(r[0]) not in hot
    }
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
    (twice_delivered,) = one(
        conn,
        "SELECT count(*) FROM (SELECT message_id FROM interlock.outbox_attempts"
        " WHERE event = 'delivered' GROUP BY message_id HAVING count(*) > 1) AS d",
    )
    if twice_delivered:
        problems.append(f"{twice_delivered} message(s) recorded delivered twice")
    # A delivery settled without a receipt only when its plan's never could
    # be: the plan in flight on a node that died between its commit and its
    # action receipt, which its commit names and its log does not hold.
    plans = {
        str(message): str(plan)
        for message, plan in conn.execute(
            "SELECT s.message_id, o.plan_id FROM interlock.outbox_settlements AS s"
            " JOIN interlock.outbox AS o USING (message_id) WHERE s.receipt_id IS NULL"
            " UNION ALL SELECT message_id, plan_id FROM interlock.outbox_compacted"
            " WHERE state = 'delivered' AND receipt_id IS NULL"
        ).fetchall()
    }
    died = {(d.node, d.incarnation) for d in run.deaths}
    unissued = set().union(*evidence.unissued.values()) if evidence.unissued else set()

    def never_issued(plan: str) -> bool:
        record = run.journals.plans.get(plan)
        return (
            plan in unissued
            and record is not None
            and (record.node, record.incarnation) in died
            and not record.answered
        )

    justified = sorted(m for m, plan in plans.items() if never_issued(plan))
    unreceipted = len(plans) - len(justified)
    per_message = Counter(
        str(d.request.message_id) for receipts in evidence.receipts.values() for d in receipts
    )
    actions = sum(evidence.actions.values())
    if (
        unreceipted
        or len(per_message) + len(justified) != delivered
        or any(n > 1 for n in per_message.values())
    ):
        problems.append(
            f"{len(per_message)} message(s) receipted for {delivered} delivered; "
            f"{unreceipted} settled without one, {len(justified)} of a plan whose action "
            f"receipt its node died before issuing"
        )
    events, distinct, facts, consumed_twice, unconsumed = one(
        conn,
        "SELECT (SELECT count(*) FROM interlock.inbox_events),"
        " (SELECT count(DISTINCT (source, event_id)) FROM interlock.inbox_events),"
        " (SELECT count(*) FROM interlock.inbox_facts),"
        " (SELECT count(*) - count(DISTINCT fact_id) FROM interlock.inbox_consumed),"
        " (SELECT count(*) FROM interlock.inbox_facts f WHERE NOT EXISTS"
        "   (SELECT 1 FROM interlock.inbox_consumed c WHERE c.fact_id = f.fact_id))",
    )
    if events != distinct or consumed_twice or unconsumed:
        problems.append(
            f"{events} events for {distinct} ids; facts consumed twice {consumed_twice}, "
            f"never {unconsumed}"
        )
    answered = [s for s in run.vendor.sent if s.status == 200]
    duplicates = [s for s in answered if s.purpose == "duplicate"]
    # Recordings by event, whichever of its sends, to whichever node, made them.
    recordings = Counter(
        s.event_id for s in answered if s.recorded and not s.purpose.startswith("forged:")
    )
    recorded_twice = sorted(e for e, n in recordings.items() if n > 1)
    if recorded_twice:
        problems.append(f"{len(recorded_twice)} event(s) recorded more than once")
    spread = Counter(s.node for s in answered if s.recorded)
    lost = sum(1 for s in run.vendor.sent if s.status == 0)
    return Claim(
        "exactly once",
        not problems,
        [
            f"payment API: {sum(api.executions.values())} calls acted, each on its own key; "
            f"{api.answers.get('replayed', 0)} replays of a key's result, "
            f"{api.answers.get('in_use', 0)} answered 409 while its first was running",
            f"{len(intents)} payments for {len(committed)} committed orders, none twice; "
            f"{len(refunds)} refunds for {run.desk.applied} compensations",
            f"{delivered} messages delivered once each, {len(per_message)} delivery receipts "
            f"across {len(evidence.receipts)} nodes' logs ({actions} action receipts beside them)"
            + (
                f"; {len(justified)} settled without one, its plan committed by a node that "
                f"died before issuing the action receipt its commit names"
                if justified
                else ""
            ),
            f"{len(recordings)} events recorded over the run, each by one send, by inbox: "
            + ", ".join(f"{n} {c}" for n, c in sorted(spread.items()))
            + f" ({events} still held, the rest pruned)"
            + f"; {len(duplicates)} duplicates answered; {lost} sends found no node answering "
            f"and went to another; {facts} facts, each consumed once",
            *problems[:8],
        ],
    )


def no_forgery(run: Run) -> Claim:
    forged = [s for s in run.vendor.sent if s.purpose.startswith("forged:") and s.status]
    by_how = Counter((s.purpose.split(":", 1)[1], s.status) for s in forged)
    accepted = [s for s in forged if s.status not in (400, 401)]
    recorded = run.vendor.forged & run.auditor.event_ids
    held = bool(forged) and not accepted and not recorded
    return Claim(
        "no forgery accepted",
        held,
        [
            f"{len(forged)} forged webhooks answered: "
            + ", ".join(f"{how} -> {status} x{n}" for (how, status), n in sorted(by_how.items())),
            f"answered otherwise: {len(accepted)}; recorded: {len(recorded)}",
        ],
    )


@dataclass(order=True)
class VacuumRun:
    """One vacuum run, as the operator log records it."""

    at: float
    """When its intent was signed, wall clock."""
    node: str
    """The node that ran it, as its reason names it."""
    outcome: str = "open"
    pruned: dict[str, int] = field(default_factory=dict, compare=False)


def vacuum_runs(evidence: Evidence) -> list[VacuumRun]:
    """Every vacuum run the operator log records: when its intent was signed,
    the node that ran it, what became of it, and what it pruned."""
    from interlock.operators import ABANDONED, APPLIED, INTENT, REFUSED

    runs: dict[str, VacuumRun] = {}
    for record in evidence.records:
        if record.kind == INTENT.value and record.body.get("action") == "compact":
            reason = str(record.body.get("reason") or "")
            node = reason.rsplit(" on ", 1)[1] if " on " in reason else "?"
            when = datetime.fromisoformat(record.issued_at.replace("Z", "+00:00")).timestamp()
            runs[record.record_hash] = VacuumRun(when, node)
    for record in evidence.records:
        found = runs.get(str(record.body.get("intent", {}).get("hash", "")))
        if found is None:
            continue
        if record.kind == APPLIED.value:
            found.outcome = "applied"
            found.pruned = {k: int(v) for k, v in dict(record.body.get("pruned") or {}).items()}
        elif record.kind == REFUSED.value:
            found.outcome = "rejected"
        elif record.kind == ABANDONED.value:
            found.outcome = "abandoned"
    return sorted(runs.values())


def vacuum_compacts(run: Run, evidence: Evidence, conn: psycopg.Connection[Any]) -> Claim:
    runs = vacuum_runs(evidence)
    outcomes = Counter(r.outcome for r in runs)
    pruned: Counter[str] = Counter()
    for r in runs:
        pruned.update(r.pruned)
    # A run abandoned by its node's death: its intent signed as it died.
    deaths = [(d.node, d.at) for d in run.deaths]
    unexplained = [
        (r.at, r.node, r.outcome)
        for r in runs
        if r.outcome != "applied"
        and not any(r.node == n and r.at <= died + 1.0 for n, died in deaths)
    ]
    vacuum = counters(evidence, "vacuum")
    checkpoints = conn.execute("SELECT seq, at FROM interlock.checkpoints ORDER BY seq").fetchall()
    samples = run.auditor.samples
    warm = run.settings.retain + run.settings.slack + 5
    late = [s for s in samples if s.at > warm and s.at <= run.load_seconds]
    lingering = max((s.lingering_stages for s in late), default=0)
    stale = max((s.lingering_windows for s in late), default=0)
    live_max = max((s.live for s in samples), default=0)
    spread = len({int(s.checkpoints) for s in samples})
    held = (
        outcomes.get("applied", 0) >= 2
        and not unexplained
        and vacuum.get("refused", 0) == 0
        and pruned.get("messages", 0) > 0
        and pruned.get("windows", 0) > 0
        and pruned.get("inbox_events", 0) > 0
        and len(checkpoints) >= 2
        and spread >= 3
        and lingering == 0
        and stale == 0
    )
    return Claim(
        "the vacuum compacts as it goes",
        held,
        [
            f"{len(checkpoints)} checkpoints signed, anchored and applied over the run, by "
            f"whichever node led the vacuum: "
            + ", ".join(f"{o} {n}" for o, n in sorted(outcomes.items()))
            + f"; surveys refused {vacuum.get('refused', 0)}; {vacuum.get('busy', 0)} runs put off "
            f"while another writer held the operator log",
            f"pruned: {pruned.get('messages', 0)} messages, {pruned.get('windows', 0)} window "
            f"rows, {pruned.get('inbox_events', 0)} inbound events",
            f"the live outbox peaked at {live_max} messages; {run.live_at_end} of "
            f"{run.total_at_end} ever enqueued were still live at the end",
            f"prunable and still there past retention plus {run.settings.slack:g}s: at most "
            f"{lingering} stages and {stale} window rows in {len(late)} samples",
            *(
                [f"runs not applied, and no death to explain them: {unexplained[:3]}"]
                if unexplained
                else []
            ),
        ],
    )


def everything_verifies(
    run: Run, evidence: Evidence, conn: psycopg.Connection[Any], entries: Sequence[Any]
) -> Claim:
    from agentgov.receipts import ReceiptLog

    from interlock.attestations import verify_attestations
    from interlock.deliveries import verify_delivery_log
    from interlock.inbox import verify_inbox
    from interlock.keys import verify_keys
    from interlock.operators import legacy_vouch, verify_operators
    from interlock.settlement import verify_settlements
    from interlock.wiring import trusted_keyring

    config = run.config
    operators = config.operators
    relays = trusted_keyring(config, "relay")
    inbox = trusted_keyring(config, "inbox")
    receipts = config.receipts
    assert operators is not None and relays is not None and inbox is not None
    assert receipts is not None and receipts.key is not None
    records = evidence.records
    found: dict[str, list[str]] = {}
    found["delivery logs"] = list(verify_delivery_log(conn))
    found["attestations"] = list(
        verify_attestations(
            conn, relays, legacy=legacy_vouch(records, operators.keyring())
        ).problems
    )
    found["operators"] = list(
        verify_operators(conn, records, operators.keyring(), ledger=entries).problems
    )
    keys = verify_keys(conn, records, config.key_roots())
    found["keys"] = list(keys.problems)
    logs = [
        ReceiptLog(
            receipts_log_id(node.name), load_key(receipts.key), path=node.home / receipts.log.name
        )
        for node in run.nodes
        if (node.home / receipts.log.name).exists()
    ]
    try:
        found["settlements"] = list(
            verify_settlements(conn, log=logs, relays=relays, ledger=entries)
        )
        receipt_count = sum(len(log) for log in logs)
    finally:
        for log in logs:
            log.close()
    report = verify_inbox(conn, inbox, relays=relays)
    found["inbox"] = list(report.problems)
    chains = 0
    found["escrow chains"] = []
    for node in run.nodes:
        for path in chain_paths(run, node):
            try:
                chain = EscrowChain.load(path)
                chain.verify_anchors()
                chains += len(chain.records())
                if chain.unresolved_intents():
                    found["escrow chains"].append(
                        f"{node.name}/{path.name}: {len(chain.unresolved_intents())} intent(s) open"
                    )
            except Exception as exc:
                found["escrow chains"].append(f"{node.name}/{path.name}: {exc}")
    problems = [f"{what}: {p}" for what, items in found.items() for p in items]
    return Claim(
        "everything verifies after",
        not problems,
        [
            f"delivery logs, relays' attestations, {len(records)} operator records with their "
            f"AgentGov anchors, {keys.registered} key(s) registered and {keys.revoked} revoked "
            f"with the seal its operator signed, settlements against {receipt_count} receipts in "
            f"{len(logs)} nodes' logs, {report.events} inbound events and {report.facts} facts, "
            f"{sum(len(chain_paths(run, n)) for n in run.nodes)} escrow chains ({chains} records) "
            f"with their anchors, no intent left open",
            *(problems[:8] or ["no problem found"]),
        ],
    )


def graceful(run: Run, evidence: Evidence) -> Claim:
    problems: list[str] = []
    for name, (code, took) in sorted(run.stops.items()):
        if code != 0 or took > 30:
            problems.append(f"{name} stopped with {code} in {took:.2f}s")
    if len(run.stops) != len(run.nodes):
        problems.append(f"{len(run.stops)} of {len(run.nodes)} nodes stopped at the end")
    engines = counters(evidence, "engines")
    not_stopped = [
        f"{node}.{number} {part}: {parsed[0]}"
        for (node, number), parts in evidence.stopped.items()
        for part, parsed in parts.items()
        if parsed[0] != "stopped"
    ]
    second = run.second
    for name, found in sorted(second.items()):
        if not found.get("ready") or found.get("recovered") != 0 or found.get("exit") != 0:
            problems.append(f"{name} started again: {found}")
    held = run.quiesced and not problems and not not_stopped and engines.get("cancelled", 0) == 0
    return Claim(
        "shutdown is graceful",
        held,
        [
            f"settled after the load in {run.quiesce_seconds:.1f}s"
            + ("" if run.quiesced else f" -- NOT: {run.outstanding}"),
            "every node stopped on SIGTERM: "
            + ", ".join(f"{n} in {t:.2f}s" for n, (_, t) in sorted(run.stops.items()))
            + f" (bound 30s); every part of every process stopped; plans cancelled: "
            f"{engines.get('cancelled', 0)}",
            "each node started again: "
            + ", ".join(
                f"{n} ready {f.get('ready')}, recovered {f.get('recovered')}, stopped in "
                f"{f.get('seconds', 0.0):.2f}s"
                for n, f in sorted(second.items())
            ),
            *(problems + not_stopped)[:6],
        ],
    )


def trace_survives(run: Run) -> Claim:
    """Agent, outbox, relay, vendor, webhook, fact and agent again: one trace
    for each checkout (``docs/EPIC7_DESIGN.md`` §5), whichever nodes the
    plans, the call, the webhook and the reconciliation ran on."""
    api, vendor, journals = run.api, run.vendor, run.journals
    problems: list[str] = []
    untraced = [k for k, seen in api.traces.items() if None in seen]
    varied = [k for k, seen in api.traces.items() if len(seen) > 1]
    if untraced or varied:
        problems.append(
            f"idempotency keys called with no traceparent: {len(untraced)}; "
            f"with more than one: {len(varied)}"
        )
    orders = {str(o.order_id): o for o in journals.orders.values()}
    intents = api.of("payment_intent")
    for intent in intents:
        order = orders.get(str(intent["metadata"].get("order")))
        sent = api.trace_of.get(str(intent["id"]))
        if order is None or order.traceparent is None or sent != order.traceparent:
            problems.append(f"charge {intent['id']} carried {sent}, not its checkout's")
    refunds = api.of("refund")
    for refund in refunds:
        charged = api.trace_of.get(str(refund["payment_intent"]))
        sent = api.trace_of.get(str(refund["id"]))
        if charged is None or sent != charged:
            problems.append(f"refund {refund['id']} carried {sent}, its charge {charged}")
    modes: Counter[str] = Counter()
    for fact in journals.reconciled:
        mode, header = vendor.traces.get(fact.event_id, ("none", None))
        delivered = api.trace_of.get(fact.remote_ref)
        expected = header if mode == "echo" else delivered
        if delivered is None or fact.traceparent != expected:
            problems.append(
                f"fact {fact.fact_id} ({mode}) continues {fact.traceparent}, not {expected}"
            )
        elif (
            fact.planned is None
            or trace_id(fact.planned) != trace_id(delivered)
            or fact.planned == expected
        ):
            problems.append(f"the plan consuming fact {fact.fact_id} is traced {fact.planned}")
        else:
            modes[mode] += 1
    if any(parse_traceparent(t) is not None for t in MALFORMED_TRACES):
        problems.append("a malformed traceparent the soak sends is valid")
    by_plan = {o.plan_id: o.traceparent for o in journals.orders.values()}
    messages = run.auditor.message_traces
    for message, (plan_id, traceparent) in messages.items():
        if traceparent is None or traceparent != by_plan.get(plan_id):
            problems.append(f"message {message} of plan {plan_id} keeps {traceparent}")
    events = run.auditor.event_traces
    kept = 0
    for event_id, traceparent in events.items():
        mode, header = vendor.traces.get(event_id, ("none", None))
        valid = header if mode in ("echo", "foreign") else None
        if traceparent != valid:
            problems.append(f"event {event_id} ({mode}) keeps {traceparent}")
        kept += traceparent is not None
    carried = Counter(
        s.trace for s in vendor.sent if s.purpose in ("genuine", "duplicate") and s.status
    )
    return Claim(
        "trace context survives",
        not problems and bool(journals.reconciled) and all(modes[m] for m in TRACE_MODES[:2]),
        [
            f"payment API: {sum(len(s) for s in api.traces.values())} contexts on "
            f"{len(api.traces)} idempotency keys, one each; {len(intents)} charges carried "
            f"their checkout's, {len(refunds)} refunds their charge's",
            "webhooks answered, by trace context: "
            + ", ".join(f"{m} {carried.get(m, 0)}" for m in TRACE_MODES),
            f"{len(journals.reconciled)} facts consumed, on every node, each continuing its "
            f"delivery's trace: "
            + ", ".join(f"{m} {modes.get(m, 0)}" for m in TRACE_MODES)
            + "; each consuming plan a new span of it",
            f"seen in the database over the run: {len(messages)} messages, each beside its "
            f"plan's context; {len(events)} events, {kept} beside the context they carried",
            *(problems[:8] or ["every context where it was sent, and nothing invented"]),
        ],
    )


def metrics_agree(run: Run, evidence: Evidence, conn: psycopg.Connection[Any]) -> Claim:
    """What each node exported, against what it did, as the run counted it
    (``docs/EPIC7_DESIGN.md`` §5): every process that lived to its stop, its
    own figures; the settled outbox, as a node sampled it."""
    settled = run.settled
    if settled is None:
        return Claim("metrics agree", False, ["no settled node was scraped"])
    problems: list[str] = []
    catalog = {m.name for m in CATALOG}
    journals = run.journals
    final = settled.scrape
    checked = 0
    for (name, number), scraper in sorted(run.scrapers.items()):
        if (name, number) not in evidence.stopped:
            # Killed: what it exported until then was well formed, and only rose.
            if scraper.errors.get("malformed") or scraper.fell:
                problems.append(f"{name}.{number}: malformed scrapes or counters that fell")
            continue
        checked += 1
        last = scraper.last
        where = f"{name}.{number}"
        if scraper.errors or scraper.fell:
            problems.append(
                f"{where}: scrape errors {dict(scraper.errors)}; fell {scraper.fell[:2]}"
            )
        silent = sorted(n for n in catalog if n not in last and f"{n}_count" not in last)
        if scraper.families != catalog or silent:
            problems.append(
                f"{where}: families missing {sorted(catalog - scraper.families)}; silent {silent}"
            )
        over = {w: s for w, s in scraper.saturation.items() if s > 1}
        if over:
            problems.append(f"{where}: window saturation {over}")
        if not scraper.busy <= scraper.workers:
            problems.append(f"{where}: {scraper.busy} engines busy of {scraper.workers}")

        def value(metric: str, _last: Scrape = last, **labels: str) -> float:
            return _last.get(metric, {}).get(tuple(labels.items()), 0.0)

        plans = [p for p in journals.plans.values() if (p.node, p.incarnation) == (name, number)]
        counted = {
            "committed": sum(1 for p in plans if p.committed),
            "refused": sum(1 for p in plans if p.committed is False),
            "failed": sum(1 for p in plans if p.answered and p.committed is None),
        }
        exported = {o: value("interlock_plans_total", outcome=o) for o in counted}
        if exported != counted:
            problems.append(f"{where}: plans exported {exported}, counted {counted}")
        sends = [
            s for s in run.vendor.sent if (s.node, s.incarnation) == (name, number) and s.status
        ]
        answered = dict(Counter(str(s.status) for s in sends))
        webhooks = {
            dict(k)["status"]: v
            for k, v in last.get("interlock_webhooks_total", {}).items()
            if dict(k)["source"] == SOURCE
        }
        if webhooks != answered:
            problems.append(f"{where}: webhooks exported {webhooks}, answered {answered}")
        receipts = value("interlock_receipts_issued_total")
        lags = value("interlock_settlement_lag_seconds_count")
        if receipts != lags:
            problems.append(f"{where}: {receipts} receipts and {lags} settlement lags exported")
        node_label = value("interlock_cluster_node", node=name)
        if node_label != 1:
            problems.append(f"{where}: interlock_cluster_node {node_label} while it ran")
    sampled = {
        dict(k)["state"]: int(v) for k, v in final.get("interlock_outbox_messages", {}).items()
    }
    for state in sorted(set(sampled) | set(settled.before)):
        low, high = settled.after.get(state, 0), settled.before.get(state, 0)
        if not low <= sampled.get(state, 0) <= high:
            problems.append(f"{state}: sampled {sampled.get(state, 0)}, read {high} then {low}")
    idle = {
        name: final.get(name, {}).get((), 0.0)
        for name in (
            "interlock_settlement_backlog",
            "interlock_inbox_facts_pending",
            "interlock_engine_queue_depth",
            "interlock_metrics_sample_errors_total",
        )
    }
    if any(idle.values()):
        problems.append(f"settled, and yet: {idle}")
    takeovers = sum(
        scraper.last.get("interlock_lease_takeovers_total", {}).get((), 0.0)
        for scraper in run.scrapers.values()
    )
    return Claim(
        "metrics agree",
        not problems and checked >= len(run.nodes),
        [
            f"{sum(s.scrapes for s in run.scrapers.values())} scrapes of "
            f"{len(run.scrapers)} processes, every one well formed; {len(catalog)} families "
            f"exported by each process that lived to its stop ({checked}), each with data; no "
            f"counter fell",
            f"each such process's plans by outcome and webhooks by answer what its journal and "
            f"the vendor counted; its receipts and settlement lags one for one; "
            f"{takeovers:.0f} leases taken over from nodes gone, as the relays exported them",
            f"the settled outbox, sampled: {sampled}; read before {settled.before} and after "
            f"{settled.after}",
            *(problems[:8] or ["every figure what the run counted itself"]),
        ],
    )


ATTESTED_AFTER = """
SELECT count(*) FROM interlock.outbox_attempts AS a
 WHERE a.attestation IS NOT NULL AND (a.attestation::jsonb)->>'key_id' = %s AND a.at > %s
"""
UNSEALED = """
SELECT count(*) FROM interlock.outbox_attempts AS a
 WHERE a.attestation IS NOT NULL AND (a.attestation::jsonb)->>'key_id' = %s
   AND NOT EXISTS (SELECT 1 FROM interlock.key_seals AS s
                    WHERE s.key_id = %s AND s.kind = 'outcome'
                      AND s.ref = a.message_id::text || ':' || a.seq
                      AND s.row_hash = a.event_hash)
"""


def _count(conn: psycopg.Connection[Any], query: str, args: Sequence[Any]) -> int:
    row = conn.execute(query, args).fetchone()
    return int(row[0]) if row else 0


def _after_revocation(run: Run) -> None:
    """What the database holds of each key once the old one is revoked, read
    then: the vacuum prunes delivered messages within seconds. The new key's
    outcomes are waited for, ten seconds at most."""
    rotation = run.rotation
    with psycopg.connect(run.site.owner, autocommit=True) as conn:
        row = conn.execute(
            "SELECT revoked_at FROM interlock.key_revocations WHERE key_id = %s", (rotation.old,)
        ).fetchone()
        if row is None:
            return
        rotation.unsealed = _count(conn, UNSEALED, (rotation.old, rotation.old))
        deadline = time.monotonic() + 10
        while True:
            rotation.new_after = _count(conn, ATTESTED_AFTER, (rotation.new, row[0]))
            rotation.old_after = _count(conn, ATTESTED_AFTER, (rotation.old, row[0]))
            if rotation.new_after or time.monotonic() > deadline:
                return
            time.sleep(0.2)


def keys_rotate(run: Run, conn: psycopg.Connection[Any]) -> Claim:
    """The relays' key rotated mid-load (``docs/EPIC8_DESIGN.md`` §5): what the
    old key attested sealed, or refused; what came after, the new key's."""
    rotation = run.rotation
    problems: list[str] = []
    if rotation.error is not None:
        problems.append(f"the rotation failed: {rotation.error}")
    if not 0 < rotation.began < rotation.ended < run.load_seconds:
        problems.append(
            f"it ran from {rotation.began:.0f}s to {rotation.ended:.0f}s, not within the "
            f"load's {run.load_seconds:.0f}s"
        )
    failed = {
        f"{node}/{part}": error
        for node, said in rotation.reload.items()
        for part, error in said.items()
        if error is not None
    }
    silent = sorted(node for node, said in rotation.reload.items() if not said)
    if len(rotation.reload) != len(run.nodes) or failed or silent:
        problems.append(
            f"the reload did not open every part of every node again: {len(rotation.reload)} of "
            f"{len(run.nodes)} nodes, failed {failed}, said nothing {silent}"
        )
    if not rotation.called_first:
        problems.append("the stale relay had no call in flight when the key was revoked")
    if "the database refused" not in rotation.stale:
        problems.append(f"the stale relay's outcome was not refused: {rotation.stale}")
    if rotation.old_signed_after > 1:
        problems.append(
            f"the old version signed {rotation.old_signed_after} times after the revocation"
        )
    signed = run.keys.service.signed
    old_signed, new_signed = signed[("soak-relay", 1)], signed[("soak-relay", 2)]
    if not old_signed or not new_signed:
        problems.append(f"signatures: {old_signed} by the old version, {new_signed} by the new")
    row = conn.execute(
        "SELECT revoked_at, seal_count, seal_digest FROM interlock.key_revocations"
        " WHERE key_id = %s",
        (rotation.old,),
    ).fetchone()
    old_after = unsealed = new_after = 0
    if row is None:
        problems.append("the database holds no revocation of the old key")
    else:
        revoked_at, count, digest = row
        if {"count": count, "digest": digest} != rotation.seal:
            problems.append(f"the seal recorded, {count} ({digest[:16]}), is not the one signed")
        # Read as the revocation committed, and again now: the seal's rows
        # may since be pruned, never joined by another.
        old_after = rotation.old_after + _count(conn, ATTESTED_AFTER, (rotation.old, revoked_at))
        unsealed = _count(conn, UNSEALED, (rotation.old, rotation.old))
        if rotation.unsealed:
            problems.append(f"as it was revoked, {rotation.unsealed} of its outcomes unsealed")
        if old_after or unsealed:
            problems.append(
                f"the old key's outcomes: {old_after} after its revocation, {unsealed} outside "
                f"its seal"
            )
        new_after = rotation.new_after
        if not new_after:
            problems.append("no outcome after the revocation is the new key's")
    held = "nothing"
    if rotation.held is not None:
        keys = [
            str(r[0])
            for r in conn.execute(
                "SELECT (attestation::jsonb)->>'key_id' FROM interlock.outbox_attempts"
                " WHERE message_id = %s AND event = 'delivered'",
                (rotation.held,),
            )
        ]
        pruned = conn.execute(
            "SELECT state FROM interlock.outbox_compacted WHERE message_id = %s", (rotation.held,)
        ).fetchone()
        if keys == [rotation.new]:
            held = "delivered once, under the new key"
        elif not keys and pruned is not None and pruned[0] == "delivered":
            held = "delivered once, and pruned since"
        else:
            problems.append(f"the stale relay's message: delivered by {keys or 'none'}")
    return Claim(
        "keys rotate",
        not problems,
        [
            f"from {rotation.began:.0f}s to {rotation.ended:.0f}s of {run.load_seconds:.0f}s: "
            f"relay key {rotation.old} -> {rotation.new}, registered by operator record "
            f"{rotation.registered}, revoked by {rotation.revoked}; the seal "
            f"{rotation.seal.get('count')} rows ({str(rotation.seal.get('digest'))[:16]})",
            f"SIGHUP reloaded {len(rotation.reload)} nodes, every part of each opened again: "
            + "; ".join(
                f"{node} {len(said)} parts" for node, said in sorted(rotation.reload.items())
            ),
            f"the stale relay {rotation.stale[:160]}; its message {held}",
            f"the key service signed {old_signed} times with the old version "
            f"({rotation.old_signed_after} after the revocation: the stale relay's), "
            f"{new_signed} with the new; {new_after} outcomes by the new key after it, "
            f"{old_after} by the old, {unsealed} of the old key's outside its seal",
            *problems[:6],
        ],
    )


# --------------------------------------------------------------------------
# The claims of a cluster (docs/EPIC9_DESIGN.md §5)
# --------------------------------------------------------------------------


def _relay_node(actor: str) -> str:
    """The node a relay's id names: ``relay:<node>:<pid>:<tag>``."""
    parts = actor.split(":")
    return parts[1] if len(parts) >= 4 and parts[0] == "relay" else "?"


def nodes_share_the_work(run: Run, evidence: Evidence) -> Claim:
    """Every node committed plans, delivered messages, answered webhooks and
    settled the deliveries of its own plans, into its own receipt log."""
    journals = run.journals
    names = [n.name for n in run.nodes]
    committed = Counter(r.node for p, r in journals.plans.items() if p in evidence.committed)
    delivered = Counter(_relay_node(actor) for actor in run.auditor.delivered_by.values())
    answered = Counter(s.node for s in run.vendor.sent if s.status == 200)
    settled = {name: len(evidence.receipts.get(name, ())) for name in names}
    idle = [
        f"{name}: no {what}"
        for name in names
        for what, counts in (
            ("plan committed", committed),
            ("message delivered", delivered),
            ("webhook answered", answered),
            ("delivery settled", settled),
        )
        if not counts.get(name)
    ]
    return Claim(
        "nodes share the work",
        not idle,
        [
            "plans committed, by node: " + ", ".join(f"{n} {committed.get(n, 0)}" for n in names),
            "messages delivered by each node's relays: "
            + ", ".join(f"{n} {delivered.get(n, 0)}" for n in names),
            "webhooks each node's inbox answered 200: "
            + ", ".join(f"{n} {answered.get(n, 0)}" for n in names),
            "deliveries each node settled, receipted into its own log: "
            + ", ".join(f"{n} {settled[n]}" for n in names),
            *(idle[:4] or ["every node did every kind of work"]),
        ],
    )


def one_leader_at_a_time(run: Run, evidence: Evidence) -> Claim:
    """Who led what, as ``pg_locks`` said every 0.2 seconds: no role held by
    two sessions; every vacuum run by the node that led then, as its operator
    record names it; each receipt log's settler role held by its own node
    only; each dead leader's role taken by another."""
    watch = run.watch
    problems = list(watch.doubled)
    for _, holders in watch.leaders:
        for role, node in holders.items():
            if role.startswith("settler:") and role != f"settler:{receipts_log_id(node)}":
                problems.append(f"{role} held by node {node}")
    changes: Counter[str] = Counter()
    for (_, before), (_, after) in itertools.pairwise(watch.leaders):
        for role in set(before) | set(after):
            if before.get(role) != after.get(role) and after.get(role) is not None:
                changes[role] += 1
    runs = vacuum_runs(evidence)
    misled = [
        f"{r.node} at {r.at:.1f}"
        for r in runs
        if r.node not in {watch.leader("vacuum", r.at), watch.leader("vacuum", r.at - 1.0)}
    ]
    if misled:
        problems.append(f"{len(misled)} vacuum run(s) by a node not leading then: {misled[:3]}")
    by_node = Counter(r.node for r in runs)
    for death in run.deaths:
        if "vacuum" in death.led and "vacuum" not in death.took:
            problems.append(f"the {death.how} node {death.node}'s vacuum was never taken")
    if run.deaths and len(by_node) < 2:
        problems.append(f"vacuums by node {dict(by_node)}: none after a failover")
    roles = sorted({role for _, holders in watch.leaders for role in holders})
    return Claim(
        "one leader at a time",
        not problems and bool(runs) and watch.samples > 0,
        [
            f"{watch.samples} samples of pg_locks, {len(roles)} roles: never one held by two "
            f"sessions; leadership changed hands: "
            + ", ".join(f"{role} {n}" for role, n in sorted(changes.items())),
            f"{len(runs)} vacuum runs recorded, by node: "
            + ", ".join(f"{n} {c}" for n, c in sorted(by_node.items()))
            + "; each by the node leading the vacuum as it ran",
            "each receipt log's settler role held by its own node, and by no other",
            *[
                f"the {d.how} node {d.node} led "
                + (", ".join(d.led) or "nothing")
                + "; taken: "
                + (
                    ", ".join(f"{r} by {n} {s:.2f}s after" for r, (n, s) in sorted(d.took.items()))
                    or "-"
                )
                for d in run.deaths
            ],
            *(problems[:6] or ["no role ever led by two nodes, or by the wrong one"]),
        ],
    )


def survived(run: Run, evidence: Evidence, how: str) -> Claim:
    """A node killed (``SIGKILL``: its sockets closed at once), or frozen
    (``SIGSTOP``: its connections left open, then killed), mid-load, and what
    the database and the rest of the cluster did about it."""
    name = "a node killed is survived" if how == "killed" else "a node frozen is survived"
    if not run.settings.chaos or run.settings.nodes < 2:
        return Claim(name, True, ["no chaos asked for (--no-chaos, or one node)"])
    death = next((d for d in run.deaths if d.how == how), None)
    if death is None:
        return Claim(name, False, [f"no node was {how}: none led the vacuum when it was time"])
    settings = run.settings
    problems: list[str] = [] if death.error is None else [death.error]
    calls = [m for m, last in death.leases.items() if last == "sending"]
    if not calls:
        problems.append("it had no call in flight as it died")
    # Its leases: taken over once its node was gone, and only then.
    lock = death.node_lock
    if lock is None:
        problems.append("its node's lock was never released")
    else:
        late = {m[:8]: round(s, 2) for m, s in death.taken.items() if s > lock + 2.0}
        early = {m[:8]: round(s, 2) for m, s in death.taken.items() if s < lock - 0.5}
        if late:
            problems.append(f"leases taken late, past its node's lock: {late}")
        if early:
            problems.append(f"leases taken while its node still held its lock: {early}")
    untaken = sorted(set(death.leases) - set(death.taken))
    if untaken:
        problems.append(f"leases never taken: {[m[:8] for m in untaken]}")
    # Each call it had in flight: made again under the same key, acted once.
    acted = {m: run.api.executions.get(death.keys.get(m, ""), 0) for m in calls}
    if any(n != 1 for n in acted.values()):
        problems.append(f"calls in flight acted on other than once: {acted}")
    # Every lock it held, let go by the server within its bound: at once for
    # a process killed; for one frozen, at its own bound or when a survivor
    # fenced it, whichever came first.
    fencing = settings.session_timeout + settings.heartbeat + 1.5
    holding = {p: s for p, s in death.sessions.items() if s[3]}
    slow: list[str] = []
    for pid, (application, state, _, _) in sorted(holding.items()):
        released = death.released.get(pid)
        if how == "killed":
            bound = 1.5 + (LOCK_TIMEOUT if state == "active" else 0.0)
        elif application.startswith("interlock-stage@"):
            bound = min(settings.max_stage + LOCK_TIMEOUT, fencing) + 1.5
        else:
            bound = fencing
        if released is None or released > bound:
            slow.append(
                f"{application} ({state}): {released if released is None else round(released, 2)}s"
            )
    if slow:
        problems.append(f"locks held past their bound: {slow[:4]}")
    # Every session it had, gone: at once for a process killed; for one
    # frozen, fenced once its node's session timed out, by a survivor.
    if death.fenced is None:
        problems.append("some of its sessions were never ended")
    elif how == "killed" and death.fenced > 1.5:
        problems.append(f"its sessions outlived it by {death.fenced:.2f}s")
    elif how == "frozen" and death.fenced > fencing:
        problems.append(
            f"its sessions ended {death.fenced:.2f}s after it froze, past its session timeout "
            f"and a heartbeat ({fencing:g}s)"
        )
    if how == "frozen" and not death.fencers:
        problems.append("no survivor's log says it fenced the frozen node")
    if lock is not None:
        if how == "killed" and lock > 1.5:
            problems.append(f"its node's lock outlived it by {lock:.2f}s")
        if how == "frozen" and not settings.session_timeout - settings.heartbeat - 1.0 <= lock <= (
            settings.session_timeout + 2.0
        ):
            problems.append(
                f"its node's lock released {lock:.2f}s after it froze, not at its session "
                f"timeout ({settings.session_timeout:g}s)"
            )
    # No survivor waited on anything of its past the moment it was fenced.
    if death.blocked > (1.5 if how == "killed" else fencing):
        problems.append(f"a survivor waited {death.blocked:.2f}s on one of its sessions")
    if death.waited > LEDGER_LOCK_TIMEOUT:
        problems.append(f"a survivor waited {death.waited:.2f}s on a lock")
    # It came back, and its next incarnation recovered what it left: its
    # chains have no intent open, and the ledger no hold of it (claimed by
    # "the ledger balances" and "everything verifies after").
    successor = evidence.stopped.get((death.node, death.incarnation + 1), {}).get("engines")
    recovered = successor[3].get("recovered", 0) if successor else None
    if not death.back_after or successor is None:
        problems.append("it never came back, or its next incarnation did not stop cleanly")
    plans = [
        p
        for p, r in run.journals.plans.items()
        if (r.node, r.incarnation) == (death.node, death.incarnation) and not r.answered
    ]
    committed = [p for p in plans if p in evidence.committed]
    recovered_plans = [p for p in committed if p in evidence.recovered]
    transactions = sum(1 for *_, held in death.sessions.values() if held)
    return Claim(
        name,
        not problems,
        [
            f"node {death.node} (incarnation {death.incarnation}), leading "
            + (", ".join(death.led) or "nothing")
            + f", {how} with {len(death.leases)} lease(s) in hand, {len(calls)} of them mid-call, "
            f"{len(death.sessions)} session(s), {transactions} of them holding locks, "
            f"{len(plans)} plan(s) in flight",
            (
                f"its node's lock released {lock:.2f}s after it died; its leases taken over "
                f"{max(death.taken.values(), default=0.0):.2f}s after at most, each call in "
                f"flight made again under its key, and acted on once: {sorted(acted.values())}"
            )
            if lock is not None
            else "its node's lock: never released",
            "what it held, let go by the server: "
            + ", ".join(
                f"{app.removeprefix('interlock-').split('@')[0]} {death.released.get(p, -1):.2f}s"
                for p, (app, _, _, _) in sorted(holding.items())
            )
            + (
                f"; every session it had ended {death.fenced:.2f}s after it died"
                if death.fenced is not None
                else "; some of its sessions never ended"
            )
            + (
                f", fenced by {', '.join(death.fencers)}; killed {death.killed_after:.1f}s "
                f"after it froze"
                if how == "frozen"
                else ""
            ),
            f"its plans in flight: {len(committed)} committed ({len(recovered_plans)} of them "
            f"by its next incarnation's recovery), {len(plans) - len(committed)} left nothing; it "
            f"came back {death.back_after:.1f}s after it died and recovered {recovered} intent(s)",
            f"the longest any survivor waited on one of its sessions: {death.blocked:.2f}s; on "
            f"any lock meanwhile: {death.waited:.2f}s",
            *(problems[:6] or ["nothing it held outlived its bound; nothing was done twice"]),
        ],
    )


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def report(run: Run, claims: Sequence[Claim]) -> None:
    journals = run.journals
    settings = run.settings
    print()
    print("=" * 100)
    print(
        f"Interlock soak: {settings.nodes} nodes, each with {settings.agents} agents x "
        f"{settings.concurrency} plans in flight, {settings.workers} engines and "
        f"{settings.relays} relays; {run.load_seconds / 60:.1f} min of load, seed {settings.seed}"
    )
    print("-" * 100)
    print("plans: " + ", ".join(f"{k} {v}" for k, v in sorted(journals.kinds.items())))
    refused = Counter(
        b for p in journals.plans.values() for b in p.blocked_by if p.committed is False
    )
    print("refused by: " + ", ".join(f"{k} {v}" for k, v in refused.most_common()))
    print(
        f"payment API: {dict(sorted(run.api.answers.items()))}; desk: {run.desk.applied} "
        f"refunds, {run.desk.busy} waits for the operator log, refused {dict(run.desk.refused)}"
        + (f", errors {dict(run.desk.errors)}" if run.desk.errors else "")
    )
    sent = Counter(s.purpose for s in run.vendor.sent if s.status)
    print(
        f"webhooks answered: {dict(sorted(sent.items()))}; transport failures "
        f"{dict(run.vendor.failures)}"
    )
    for death in run.deaths:
        print(
            f"{death.how}: {death.node}.{death.incarnation}, back after {death.back_after:.1f}s"
            + (f" ({death.error})" if death.error else "")
        )
    if run.captured.counts:
        print("the harness's warnings (most frequent):")
        for text, count in run.captured.counts.most_common(5):
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
        "plans": dict(run.journals.kinds),
        "stops": run.stops,
        "second": run.second,
        "deaths": [d.__dict__ for d in run.deaths],
        "leaders": run.watch.leaders,
        "samples": [s.__dict__ for s in run.auditor.samples],
    }
    path.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------


def parse(argv: Sequence[str] | None) -> tuple[Settings, argparse.Namespace]:
    parser = argparse.ArgumentParser(
        prog="live_stress_test.py",
        description="Soak a cluster of Interlock daemons, under load and chaos, against a live "
        "PostgreSQL.",
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
    parser.add_argument("--nodes", type=int, default=defaults.nodes, help="daemons in the cluster")
    parser.add_argument("--agents", type=int, default=defaults.agents)
    parser.add_argument(
        "--concurrency", type=int, default=defaults.concurrency, help="lanes per agent per node"
    )
    parser.add_argument("--workers", type=int, default=defaults.workers, help="engines per node")
    parser.add_argument("--relays", type=int, default=defaults.relays, help="relays per node")
    parser.add_argument("--tenants", type=int, default=defaults.tenants)
    parser.add_argument("--seed", type=int, default=defaults.seed)
    parser.add_argument("--retain", type=int, default=defaults.retain, help="seconds")
    parser.add_argument("--vacuum-every", type=int, default=defaults.vacuum_every)
    parser.add_argument("--faults", type=float, default=defaults.faults, help="fault scale")
    parser.add_argument("--quiesce", type=float, default=defaults.quiesce)
    parser.add_argument("--heartbeat", type=float, default=defaults.heartbeat)
    parser.add_argument(
        "--session-timeout",
        type=float,
        default=defaults.session_timeout,
        help="seconds a silent node keeps what it holds",
    )
    parser.add_argument(
        "--max-stage", type=float, default=defaults.max_stage, help="each stage's bound, seconds"
    )
    parser.add_argument(
        "--restart-after",
        type=float,
        default=defaults.restart_after,
        help="seconds before a dead node comes back",
    )
    parser.add_argument("--no-chaos", action="store_true", help="no node is killed or frozen")
    parser.add_argument("--keep", action="store_true", help="keep the database and the files")
    parser.add_argument("--dir", type=Path, help="where the run's files go")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.tenants <= len(TENANTS):
        parser.error(f"--tenants is 1 to {len(TENANTS)}")
    if args.nodes < 1:
        parser.error("--nodes is at least 1")
    settings = Settings(
        minutes=args.minutes,
        nodes=args.nodes,
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
        heartbeat=args.heartbeat,
        session_timeout=args.session_timeout,
        max_stage=args.max_stage,
        restart_after=args.restart_after,
        chaos=not args.no_chaos,
        quiet=args.quiet,
    )
    return settings, args


def main(argv: Sequence[str] | None = None) -> int:
    settings, args = parse(argv)
    if hasattr(signal, "SIGUSR1"):  # kill -USR1 <pid>: every thread's stack, to stderr
        faulthandler.register(signal.SIGUSR1, all_threads=True)
    try:
        if args.docker:
            server = start_docker(args.image)
        else:
            dsn = (
                args.dsn
                or os.environ.get("INTERLOCK_SOAK_DSN")
                or os.environ.get("INTERLOCK_TEST_POSTGRES_DSN")
            )
            if not dsn:
                print("live_stress_test: give --docker or --dsn", file=sys.stderr)
                return EXIT_ERROR
            server = Server(dsn)
    except (SoakError, subprocess.SubprocessError, OSError) as exc:
        print(f"live_stress_test: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        return soak(settings, server, keep=args.keep, directory=args.dir)
    except (SoakError, psycopg.Error) as exc:
        print(f"live_stress_test: the soak could not run: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if not args.keep:
            server.close()


if __name__ == "__main__":
    sys.exit(main())
