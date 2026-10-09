#!/usr/bin/env python3
"""The security audit: does any sensitive value reach a hash Interlock commits to?

(``docs/EPIC8_DESIGN.md`` §4.) *Sensitive*: a webhook's body, its headers, the
trace context of a plan or a webhook, the webhooks' signing secret, a sink's
credential. *Committed to*: an ``EffectPlan``'s hash, an ``Effect``'s, an
``OutboundRequest``'s, a delivery log's, an ARC1 statement's, an inbound
event's statement and hash, a fact's: every hash and signature Interlock and
AgentGov make. On each store, SQLite and PostgreSQL:

1. **Canaries.** One scenario, run by the daemon's own parts as
   ``interlock.toml`` builds them. A plan traced with a canary trace id charges
   a payment, through a relay holding a canary API key. The payment's webhook
   comes back with canaries in its body, a canary header and the canary trace
   continued, signed with a canary secret; it becomes a fact, which an agent
   consumes. The daemon stops; everything is verified; a vacuum prunes what it
   may; everything is verified again.
2. **Taint.** The exact input of every SHA-256 Interlock and AgentGov compute,
   and every message an Ed25519 key signs or verifies, recorded through the
   functions that compute them as the run makes them. PostgreSQL computes some
   hashes itself: verification recomputes every one, and the recomputation is
   recorded.
3. **Crawl.** Every column of every table, Interlock's, the application's and
   AgentGov's, listed from ``sqlite_master`` or ``information_schema``, read
   row by row; and every file the run wrote.
4. **Assert.** No sensitive value, and no SHA-256 of one, is in any input
   recorded, but for one commitment: the inbound event's statement and hash
   hold the SHA-256 of the body, which is how a body is attested without being
   hashed in. The audit lists it. Each canary is found where it is meant to be
   kept (the event's body and signature, the trace tables), so the audit is
   seen to look, and nowhere else.

It prints, column by column, what holds a sensitive value and which hash
reads it. Run::

    uv run python scripts/security_audit.py             # SQLite
    uv run python scripts/security_audit.py --docker    # and PostgreSQL, in a container
    uv run python scripts/security_audit.py --dsn postgresql://admin:pw@localhost:5432/postgres

``--dsn`` names a server, and a role on it that may create databases and
roles: the audit creates its own, and drops them after. Exit status: 0 when
nothing leaked; 1 when something did, or the audit did not find a canary
where it planted it; 2 when it could not run.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import logging
import os
import secrets
import shutil
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType, ModuleType
from typing import Any, TypeVar

from agentgov import BudgetManager

from interlock import BlastRadius
from interlock.cli import main as interlock
from interlock.config import load_config
from interlock.daemon import Application, build_supervisor
from interlock.deliveries import frame
from interlock.inbox import INBOUND_DOMAIN
from interlock.operators import generate_key, load_key
from interlock.stripe import PAYMENT_INTENTS_CREATE, REFUNDS_CREATE
from interlock.supervisor import AgentContext
from interlock.trace import child_traceparent
from interlock.types import OutboundRequest

T = TypeVar("T")

EXIT_CLEAN, EXIT_LEAKED, EXIT_ERROR = 0, 1, 2
SCOPE = "audit"
OPERATORS_SCOPE = "interlock-operators"
SINK = "payments"
SOURCE = "stripe"
API_KEY_ENV = "AUDIT_STRIPE_KEY"
WEBHOOK_SECRET_ENV = "AUDIT_WEBHOOK_SECRET"  # noqa: S105 - the name of a variable
OURS = ("interlock", "agentgov")
"""The packages whose hashes and signatures are recorded."""

EVENT_HASH = frame("interlock-inbox-event-v1").encode("utf-8")
"""How the input of an inbound event's hash begins. Its signed statement's
begins with :data:`~interlock.inbox.INBOUND_DOMAIN`: the two inputs that
commit to the SHA-256 of a body."""
BODY = frozenset({"the webhook's body", "the body canary", "the receipt email"})
"""The body, and what the run planted in it."""


class AuditError(Exception):
    """The audit could not run."""


# --------------------------------------------------------------------------
# 1. Canaries
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Canaries:
    """What a run plants: values no code, and no other run, would make."""

    body: str
    """In the webhook's body, where no source projects it."""
    header: str
    """A header of the webhook's own."""
    trace: str
    """The plan's trace id, which the payment API's call and the webhook continue."""
    secret: str
    """The webhooks' signing secret."""
    api_key: str
    """The payment API's credential, the relay's."""

    @classmethod
    def make(cls) -> Canaries:
        tag = secrets.token_hex(8)
        return cls(
            body=f"canary-body-{tag}",
            header=f"canary-header-{tag}",
            trace=secrets.token_hex(16),
            secret=f"whsec_canary{tag}",
            api_key=f"sk_test_canary{tag}",
        )

    @property
    def traceparent(self) -> str:
        """The plan's trace context."""
        return f"00-{self.trace}-{self.trace[:16]}-01"


@dataclass
class Sensitive:
    """Every sensitive value the run made, by what it is: the canaries, and
    what they arrived in (the whole body, each header's whole value, each
    trace context sent)."""

    values: dict[str, str] = field(default_factory=dict)

    def add(self, what: str, value: str) -> None:
        if value:
            self.values[what] = value

    def found(self, data: bytes) -> list[tuple[str, str]]:
        """What of each value ``data`` holds: ``(what, "itself")``, or
        ``(what, "its SHA-256")``."""
        held: list[tuple[str, str]] = []
        for what, value in self.values.items():
            raw = value.encode("utf-8")
            if raw in data:
                held.append((what, "itself"))
            if digest(value).encode("ascii") in data:
                held.append((what, "its SHA-256"))
        return held


def digest(value: str) -> str:
    """SHA-256 as Interlock writes one: lowercase hex. Computed with the
    function the taint does not record."""
    return _SHA256(value.encode("utf-8")).hexdigest()


_SHA256 = hashlib.sha256


# --------------------------------------------------------------------------
# 2. Taint
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Input:
    """One input to a hash or a signature, as it was computed."""

    kind: str
    """``sha256``, ``signed`` or ``verified``."""
    where: str
    """The function that computed it, and the one of ours that called it."""
    data: bytes


class Taint:
    """Records the input of every SHA-256 computed in Interlock or AgentGov,
    and of every Ed25519 signature made or verified, while installed. HMAC's
    inner hashes (a webhook's signature checked) are its own, and not
    recorded: they commit to nothing."""

    def __init__(self) -> None:
        self.inputs: list[Input] = []
        self._lock = threading.Lock()
        self._undo: list[Callable[[], None]] = []

    def record(self, kind: str, where: str, data: bytes) -> None:
        with self._lock:
            self.inputs.append(Input(kind, where, bytes(data)))

    def install(self) -> None:
        taint = self
        original = _SHA256

        class Recording:
            """``hashlib.sha256``, keeping what it was given."""

            name = "sha256"
            digest_size = 32
            block_size = 64

            def __init__(
                self,
                data: bytes = b"",
                *,
                usedforsecurity: bool = True,
                _where: str | None = None,
                _hash: Any = None,
            ) -> None:
                self._hash = _hash if _hash is not None else original()
                self._where = _where if _hash is not None else _site(sys._getframe(1))
                self._data = bytearray()
                if data:
                    self.update(data)

            def update(self, data: bytes) -> None:
                self._data += bytes(data)
                self._hash.update(data)

            def digest(self) -> bytes:
                self._record()
                return bytes(self._hash.digest())

            def hexdigest(self) -> str:
                self._record()
                return str(self._hash.hexdigest())

            def copy(self) -> Recording:
                twin = Recording(_where=self._where, _hash=self._hash.copy())
                twin._data = bytearray(self._data)
                return twin

            def _record(self) -> None:
                if self._where is not None:
                    taint.record("sha256", self._where, bytes(self._data))

        hashlib.sha256 = Recording  # type: ignore[assignment]
        self._undo.append(lambda: setattr(hashlib, "sha256", original))

        from agentgov.receipts.signing import Ed25519PublicKey, Ed25519Signer

        from interlock.signers import RemoteSigner

        for owner, method, kind in (
            (Ed25519Signer, "sign", "signed"),
            (RemoteSigner, "sign", "signed"),
            (Ed25519Signer, "verify", "verified"),
            (Ed25519PublicKey, "verify", "verified"),
        ):
            self._wrap(owner, method, kind)

    def _wrap(self, owner: type, method: str, kind: str) -> None:
        original = owner.__dict__[method]
        taint = self

        def recording(this: Any, message: bytes, *args: Any, **kwargs: Any) -> Any:
            where = _site(sys._getframe(1)) or f"{owner.__name__}.{method}, by another"
            taint.record(kind, where, bytes(message))
            return original(this, message, *args, **kwargs)

        setattr(owner, method, recording)
        self._undo.append(lambda: setattr(owner, method, original))

    def remove(self) -> None:
        while self._undo:
            self._undo.pop()()


HELPERS = frozenset(
    {
        "_digest",
        "frame",
        "canonical_hash",
        "canonical_bytes",
        "_sign",
        "_verifies",
        "sign",
        "verify",
    }
)
"""Functions that hash or sign for another: a site is named by its caller."""


def _site(frame: FrameType | None) -> str | None:
    """Where a hash was asked for: the first function of ours, above the
    helpers that hash for another, with the one that called it. ``None`` for
    anyone else's, HMAC's included."""
    if frame is None or not str(frame.f_globals.get("__name__", "")).startswith(OURS):
        return None
    ours: list[str] = []
    while frame is not None and len(ours) < 2:
        module = str(frame.f_globals.get("__name__", ""))
        name = frame.f_code.co_name
        if module.startswith(OURS) and (ours or name not in HELPERS):
            ours.append(f"{module}.{name}")
        frame = frame.f_back
    return " ← ".join(ours) or "a helper"


# --------------------------------------------------------------------------
# What the scenario talks to: a payment API, and the vendor's webhook
# --------------------------------------------------------------------------


class _Server(ThreadingHTTPServer):
    """Binds without ``socket.getfqdn``, whose reverse lookup takes seconds
    on some machines."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class PaymentAPI:
    """Stripe's payment intents on localhost: a bearer key, form-encoded
    bodies, an idempotency key's first result replayed. Every call's headers
    are kept: the canaries are seen to arrive."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.calls: list[dict[str, str]] = []
        self.intents: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                api._handle(self)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        params = dict(urllib.parse.parse_qsl(handler.rfile.read(length).decode("ascii")))
        with self._lock:
            self.calls.append({k.lower(): v for k, v in handler.headers.items()})
            if handler.headers.get("Authorization") != f"Bearer {self.key}":
                status, body = 401, {"error": {"type": "invalid_request_error"}}
            else:
                key = handler.headers.get("Idempotency-Key") or secrets.token_hex(8)
                found = self.intents.get(key)
                if found is None:
                    found = {
                        "id": f"pi_audit{len(self.intents) + 1}",
                        "object": "payment_intent",
                        "amount": int(params.get("amount", "0")),
                        "currency": params.get("currency", "usd"),
                        "status": "requires_confirmation",
                    }
                    self.intents[key] = found
                status, body = 200, found
        payload = json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)


def webhook(
    intent: Mapping[str, Any], canaries: Canaries, sensitive: Sensitive
) -> tuple[dict[str, str], bytes]:
    """The vendor's webhook for ``intent``: the canaries where no source
    projects them, the canary trace continued, signed with the canary
    secret. Every value it carries is added to ``sensitive``."""
    event = {
        "id": "evt_audit1",
        "object": "event",
        "type": "payment_intent.succeeded",
        "created": int(time.time()),
        "data": {
            "object": {
                **intent,
                "status": "succeeded",
                "description": canaries.body,
                "receipt_email": f"{canaries.body}@example.com",
                "metadata": {"note": canaries.body},
            }
        },
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    at = int(time.time())
    mac = hmac.new(canaries.secret.encode(), f"{at}.".encode() + body, "sha256").hexdigest()
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Stripe-Signature": f"t={at},v1={mac}",
        "traceparent": child_traceparent(canaries.traceparent),
        "X-Audit-Canary": canaries.header,
        "User-Agent": f"Stripe/1.0 (+{canaries.header})",
    }
    sensitive.add("the webhook's body", body.decode())
    sensitive.add("the webhook's Stripe-Signature", headers["Stripe-Signature"])
    sensitive.add("the webhook's signature MAC", mac)
    sensitive.add("the webhook's traceparent", headers["traceparent"])
    sensitive.add("the webhook's own header", headers["X-Audit-Canary"])
    sensitive.add("the webhook's User-Agent", headers["User-Agent"])
    return headers, body


def post(port: int, headers: Mapping[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/inbox/{SOURCE}", data=body, headers=dict(headers)
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310 - ours
            return int(answer.status), json.loads(answer.read())
    except urllib.error.HTTPError as refused:
        return int(refused.code), json.loads(refused.read() or b"{}")


# --------------------------------------------------------------------------
# The stores
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Cell:
    """One value the crawl read."""

    table: str
    column: str
    value: str


class Store:
    """A store the scenario runs on: set up, crawled, and taken down."""

    name: str
    status: str
    """The scenario's statement, in the store's parameter style."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        for part in ("relay", "inbox", "ops", "receipts"):
            generate_key(directory / f"{part}.key")

    def spec(self, part: str) -> str:
        return str(load_key(self.directory / f"{part}.key").public_key().spec())

    def prepare(self, api: PaymentAPI) -> Path:
        """The store, set up and installed; the configuration's path."""
        raise NotImplementedError

    def crawl(self) -> Iterator[Cell]:
        """Every value of every column of every table."""
        raise NotImplementedError

    def tables(self) -> int:
        """How many tables the last crawl read."""
        raise NotImplementedError

    def close(self) -> None:
        pass

    def install(self, path: Path) -> None:
        out = io.StringIO()
        code = interlock(
            ["install", "--config", str(path), "--key", str(self.directory / "ops.key")], out=out
        )
        if code != 0:
            raise AuditError(f"interlock install failed ({code}):\n{out.getvalue()}")

    def common(self, api: PaymentAPI) -> str:
        """The configuration both stores share: every part the scenario runs."""
        return f"""
[[sinks]]
name = "{SINK}"
type = "stripe"
cost_per_call = "0.30"
backoff_base_seconds = 0.05
backoff_cap_seconds = 0.2

[[sinks.operations]]
name = "{PAYMENT_INTENTS_CREATE}"

[[sinks.operations]]
name = "{REFUNDS_CREATE}"

[relays.keys]
relay = "{self.spec("relay")}"

[[relay.endpoints]]
sink = "{SINK}"
url = "{api.url}"
secret_env = "{API_KEY_ENV}"

[operators.keys]
ops = "{self.spec("ops")}"

[[inbox.sources]]
name = "{SOURCE}"
kind = "stripe"
secret_env = "{WEBHOOK_SECRET_ENV}"

[inbox.keys]
inbox = "{self.spec("inbox")}"

[receipts]
log = "receipts.jsonl"
key = "receipts.key"

[daemon]
drain_timeout_seconds = 10
restart_min_seconds = 0.05
"""


class SqliteStore(Store):
    name = "SQLite"
    status = "UPDATE orders SET status = :s WHERE id = 1"

    def prepare(self, api: PaymentAPI) -> Path:
        app = self.directory / "app.db"
        with contextlib.closing(sqlite3.connect(app)) as conn:
            conn.execute(
                "CREATE TABLE orders (id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, "
                "status TEXT NOT NULL, amount_cents INTEGER NOT NULL)"
            )
            conn.execute("INSERT INTO orders VALUES (1, 'acme', 'new', 500)")
            conn.commit()
        with BudgetManager.open_sqlite(str(self.directory / "governor.db")) as governor:
            governor.open_root(SCOPE, "10")
            governor.open_root(OPERATORS_SCOPE, "1")
        path = self.directory / "interlock.toml"
        path.write_text(
            f"""
substrate = "sqlite"
database = "{app}"

[[tables]]
name = "orders"
columns = ["id", "tenant", "status", "amount_cents"]
tenant_column = "tenant"

[relay]
key = "relay.key"
breaker = "none"
poll_seconds = 0.05
lease_seconds = 4
timeout_seconds = 2

[operators]
log = "operators.ilok1"
ledger = "governor.db"

[inbox]
key = "inbox.key"
listen = "127.0.0.1:0"
match_every_seconds = 0.1

[engine]
chain = "escrow.chain"
settle_cost = "0.01"
ledger = "governor.db"

[settler]
every_seconds = 0.1

[vacuum]
retain_seconds = 0
margin_seconds = 0
key = "ops.key"
"""
            + self.common(api)
        )
        self.install(path)
        return path

    def crawl(self) -> Iterator[Cell]:
        self._tables = 0
        for name in ("app.db", "governor.db"):
            with contextlib.closing(sqlite3.connect(self.directory / name)) as conn:
                tables = [
                    str(row[0])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
                    )
                ]
                for table in tables:
                    self._tables += 1
                    cursor = conn.execute(f'SELECT * FROM "{table}"')  # noqa: S608 - listed
                    columns = [d[0] for d in cursor.description]
                    for row in cursor:
                        for column, value in zip(columns, row, strict=True):
                            if value is not None:
                                yield Cell(f"{name}:{table}", column, _text(value))

    def tables(self) -> int:
        return self._tables


class PostgresStore(Store):
    name = "PostgreSQL"
    status = "UPDATE orders SET status = %(s)s WHERE id = 1"

    PARTS = ("stage", "relay", "inbox", "settle")

    def __init__(self, directory: Path, admin: str) -> None:
        super().__init__(directory)
        tag = secrets.token_hex(4)
        self.admin = admin
        self.database = f"interlock_audit_{tag}"
        self.roles = {part: f"audit_{tag}_{part}" for part in self.PARTS}
        self.password = secrets.token_hex(16)
        self._tables = 0

    @property
    def owner(self) -> str:
        from psycopg.conninfo import make_conninfo

        return make_conninfo(self.admin, dbname=self.database)

    def dsn(self, part: str) -> str:
        from psycopg.conninfo import make_conninfo

        return make_conninfo(self.owner, user=self.roles[part], password=self.password)

    def prepare(self, api: PaymentAPI) -> Path:
        import psycopg
        from agentgov.postgres import PostgresStore as Ledger
        from psycopg import sql

        with psycopg.connect(self.admin, autocommit=True) as admin:
            admin.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
                    sql.Identifier(self.database)
                )
            )
            for role in self.roles.values():
                admin.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(self.password)
                    )
                )
        with psycopg.connect(self.owner, autocommit=True) as conn:
            conn.execute(
                "CREATE TABLE orders (id bigint PRIMARY KEY, tenant text NOT NULL, "
                "status text NOT NULL, amount_cents bigint NOT NULL)"
            )
            conn.execute("INSERT INTO orders VALUES (1, 'acme', 'new', 500)")
            conn.execute(
                sql.SQL("GRANT SELECT, INSERT, UPDATE ON orders TO {}").format(
                    sql.Identifier(self.roles["stage"])
                )
            )
        with BudgetManager.open_postgres(self.owner) as governor:
            governor.open_root(SCOPE, "10")
            governor.open_root(OPERATORS_SCOPE, "1")
            store = governor.store
            assert isinstance(store, Ledger)
            store.grant_join(self.roles["stage"])
        roles = self.roles
        path = self.directory / "interlock.toml"
        path.write_text(
            f"""
substrate = "postgres"
database = {json.dumps(self.owner)}
schema = "public"
stage_roles = [{json.dumps(roles["stage"])}]
relay_roles = [{json.dumps(roles["relay"])}]
settler_roles = [{json.dumps(roles["settle"])}]
inbox_roles = [{json.dumps(roles["inbox"])}]

[[tables]]
name = "orders"
primary_key = "id"
columns = ["id", "tenant", "status", "amount_cents"]
tenant_column = "tenant"

[relay]
key = "relay.key"
database = {json.dumps(self.dsn("relay"))}
breaker = "none"
poll_seconds = 0.05
lease_seconds = 4
timeout_seconds = 2

[operators]
log = "operators.ilok1"
ledger = {json.dumps(self.owner)}

[inbox]
key = "inbox.key"
database = {json.dumps(self.dsn("inbox"))}
listen = "127.0.0.1:0"
match_every_seconds = 0.1

[engine]
database = {json.dumps(self.dsn("stage"))}
chain = "escrow.chain"
settle_cost = "0.01"
ledger = {json.dumps(self.owner)}
same_transaction = true

[settler]
database = {json.dumps(self.dsn("settle"))}
every_seconds = 0.1

[vacuum]
retain_seconds = 0
margin_seconds = 0
database = {json.dumps(self.owner)}
key = "ops.key"
"""
            + self.common(api)
        )
        self.install(path)
        return path

    def crawl(self) -> Iterator[Cell]:
        import psycopg
        from psycopg import sql

        self._tables = 0
        with psycopg.connect(self.owner, autocommit=True) as conn:
            tables = conn.execute(
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_type = 'BASE TABLE' AND table_schema NOT IN "
                "('pg_catalog', 'information_schema') ORDER BY 1, 2"
            ).fetchall()
            for schema, table in tables:
                self._tables += 1
                query = sql.SQL("SELECT pg_catalog.row_to_json(t)::text FROM {}.{} AS t").format(
                    sql.Identifier(schema), sql.Identifier(table)
                )
                for (row,) in conn.execute(query):
                    for column, value in json.loads(row).items():
                        if value is not None:
                            yield Cell(f"{schema}.{table}", column, _text(value))

    def tables(self) -> int:
        return self._tables

    def close(self) -> None:
        import psycopg
        from psycopg import sql

        with psycopg.connect(self.admin, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                    sql.Identifier(self.database)
                )
            )
            for role in self.roles.values():
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def _text(value: object) -> str:
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


# --------------------------------------------------------------------------
# The scenario
# --------------------------------------------------------------------------


async def _until(check: Callable[[], T], timeout: float, what: str) -> T:
    deadline = time.monotonic() + timeout
    while not (found := check()):
        if time.monotonic() > deadline:
            raise AuditError(f"timed out waiting for {what}")
        await asyncio.sleep(0.02)
    return found


def _agent(
    canaries: Canaries, status: str, results: list[Any]
) -> Callable[[AgentContext], Awaitable[None]]:
    """Charges the order under the canary trace, then consumes the fact the
    payment's webhook becomes, continuing the fact's trace."""

    async def agent(ctx: AgentContext) -> None:
        charge = (
            ctx.plan(SCOPE, intent="charge order 1", traceparent=canaries.traceparent)
            .update(
                table="orders",
                statement=status,
                parameters={"s": "charging"},
                tenant_id="acme",
                stated_rows=1,
            )
            .enqueue(
                sink=SINK,
                operation=PAYMENT_INTENTS_CREATE,
                payload={"amount": 500, "currency": "usd"},
                tenant_id="acme",
                compensation=OutboundRequest(
                    SINK, REFUNDS_CREATE, {"payment_intent": {"$bind": "delivered.id"}}
                ),
            )
            .build()
        )
        results.append(await ctx.execute(charge))
        while not ctx.stopping:
            facts = await ctx.facts(SCOPE)
            if facts:
                (fact,) = facts
                parent = fact.traceparent
                consume = (
                    ctx.plan(
                        SCOPE,
                        intent="the payment went through",
                        traceparent=None if parent is None else child_traceparent(parent),
                    )
                    .consume(fact)
                    .update(
                        table="orders",
                        statement=status,
                        parameters={"s": str(fact.fields["status"])},
                        tenant_id="acme",
                        stated_rows=1,
                    )
                    .build()
                )
                results.append(await ctx.execute(consume))
                return
            await ctx.sleep(0.05)

    return agent


@dataclass
class Run:
    """What one store's scenario did, and what the audit found."""

    store: str
    tables: int = 0
    cells: int = 0
    inputs: int = 0
    commitments: dict[str, int] = field(default_factory=dict)
    families: dict[str, int] = field(default_factory=dict)
    held: dict[tuple[str, str], dict[str, set[str]]] = field(default_factory=dict)
    """Each column holding a sensitive value: what it holds, and the hashes
    that read the column's values."""
    leaks: list[str] = field(default_factory=list)
    unseen: list[str] = field(default_factory=list)
    """Canaries not found where they were planted: the audit proves nothing then."""

    @property
    def clean(self) -> bool:
        return not self.leaks and not self.unseen


KEPT: Mapping[tuple[str, str], frozenset[str]] = {
    ("inbox_events", "body"): frozenset(
        {"the body canary", "the webhook's body", "the receipt email"}
    ),
    ("inbox_events", "signature"): frozenset(
        {"the webhook's Stripe-Signature", "the webhook's signature MAC"}
    ),
    ("inbox_events", "body_hash"): frozenset({"the webhook's body"}),
    ("inbox_traces", "traceparent"): frozenset({"the trace id", "the webhook's traceparent"}),
    ("outbox_traces", "traceparent"): frozenset({"the trace id", "the plan's traceparent"}),
}
"""The columns made to hold a sensitive value, by table and column name, and
what each may hold: the event's body, its digest and its vendor signature,
and the trace context, kept beside the outbox and the inbox in no hash."""

FAMILIES: Sequence[tuple[str, str, str]] = (
    ("an EffectPlan's or an Effect's hash", "sha256", "interlock.types.content_hash"),
    ("an OutboundRequest's payload hash", "sha256", "interlock.types.payload_hash"),
    ("an OutboundRequest's idempotency key", "sha256", "interlock.types.outbound_key"),
    ("a delivery log row's hash", "sha256", "interlock.deliveries.event_hash"),
    ("a relay's ARC1 attestation", "signed", "interlock.relay.attest"),
    ("an ARC1 receipt", "signed", "agentgov.receipts.log.issue"),
    ("an inbound event's statement", "signed", "interlock.inbox.receive"),
    ("an inbound event's hash", "sha256", "interlock.inbox.event_hash"),
    ("a fact's statement", "signed", "interlock.inbox._match"),
    ("an operator record", "signed", "interlock.records.append"),
    ("an escrow chain record's hash", "sha256", "interlock.chain.recompute_hash"),
    ("a checkpoint's fold", "sha256", "interlock.compaction.fold"),
    ("a ledger entry's hash", "sha256", "agentgov.core._hash_entry"),
)
"""What the hashes recorded must include, each by the function that computes
it: a family never recorded is one the audit did not look at."""

PLANTED: Sequence[tuple[str, str, str]] = (
    ("inbox_events", "body", "the body canary"),
    ("inbox_events", "signature", "the webhook's signature MAC"),
    ("inbox_traces", "traceparent", "the trace id"),
    ("outbox_traces", "traceparent", "the trace id"),
)
"""Where the first crawl must find a canary: the audit is seen to look."""


def audit(store: Store, canaries: Canaries, *, say: Callable[[str], None]) -> Run:
    """The scenario on ``store``, under the taint, then the crawl and the
    asserts. The canary secrets are handed to the daemon as production hands
    them: through the process's environment."""
    run = Run(store.name)
    sensitive = Sensitive()
    sensitive.add("the body canary", canaries.body)
    sensitive.add("the receipt email", f"{canaries.body}@example.com")
    sensitive.add("the header canary", canaries.header)
    sensitive.add("the trace id", canaries.trace)
    sensitive.add("the plan's traceparent", canaries.traceparent)
    sensitive.add("the webhook secret", canaries.secret)
    sensitive.add("the API key", canaries.api_key)
    os.environ[API_KEY_ENV] = canaries.api_key
    os.environ[WEBHOOK_SECRET_ENV] = canaries.secret
    api = PaymentAPI(canaries.api_key)
    taint = Taint()
    try:
        path = store.prepare(api)
        taint.install()
        try:
            _scenario(path, store, canaries, sensitive, api, say)
            _verified(path, "before the vacuum")
            before = list(store.crawl())
            run.tables = store.tables()
            _vacuumed(path, store)
            _verified(path, "after the vacuum")
            after = list(store.crawl())
        finally:
            taint.remove()
        files = {
            p.name: p.read_bytes()
            for p in sorted(path.parent.iterdir())
            if p.is_file() and not p.name.endswith((".key", ".toml", ".db", ".db-wal", ".db-shm"))
        }
    finally:
        api.close()
    run.cells = len(before) + len(after)
    run.inputs = len(taint.inputs)
    _calls(api, canaries, sensitive, run)
    _hashes(taint.inputs, sensitive, run)
    _families(taint.inputs, run)
    _columns(before + after, taint.inputs, sensitive, run)
    _planted(before, sensitive, run)
    for name, data in files.items():
        for what, how in sensitive.found(data):
            run.leaks.append(f"file {name} holds {what} ({how})")
    return run


def _scenario(
    path: Path,
    store: Store,
    canaries: Canaries,
    sensitive: Sensitive,
    api: PaymentAPI,
    say: Callable[[str], None],
) -> None:
    """The daemon, as ``interlock.toml`` builds it, running the agent; the
    webhook sent; the fact consumed; the daemon stopped."""
    results: list[Any] = []
    config = load_config(path)
    supervisor = build_supervisor(
        config,
        Application(checkers=[BlastRadius(5)], agents=[_agent(canaries, store.status, results)]),
    )

    def receipts() -> int:
        return supervisor.status()["settler"].counters.get("receipts", 0)

    async def drive() -> None:
        running = asyncio.create_task(supervisor.run())
        try:
            await asyncio.wait_for(supervisor.ready(), 60)
            await _until(lambda: receipts() >= 1, 60, "the charge's delivery receipt")
            (intent,) = api.intents.values()
            headers, body = webhook(intent, canaries, sensitive)
            port = supervisor.inbox_port
            assert port is not None
            answered = await asyncio.to_thread(post, port, headers, body)
            if answered != (200, {"recorded": 1, "matched": 1}):
                raise AuditError(f"the webhook was answered {answered}")
            await _until(lambda: len(results) == 2, 60, "the fact to be consumed")
        finally:
            supervisor.stop()
            await running

    asyncio.run(drive())
    if [getattr(r, "committed", False) for r in results] != [True, True]:
        raise AuditError(f"the agent's plans did not both commit: {results}")
    failed = {n: s.last_error for n, s in supervisor.status().items() if s.failures}
    if failed:
        raise AuditError(f"parts failed during the scenario: {failed}")
    say("  the scenario ran: charged, delivered, receipted, webhook recorded, fact consumed")


def _cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = interlock(list(argv), out=out)
    return code, out.getvalue()


def _verified(path: Path, when: str) -> None:
    for command in (("outbox", "verify"), ("inbox", "verify")):
        code, said = _cli(*command, "--config", str(path))
        if code != 0:
            raise AuditError(f"interlock {' '.join(command)} {when} failed ({code}):\n{said}")


def _vacuumed(path: Path, store: Store) -> None:
    key = str(store.directory / "ops.key")
    code, said = _cli("vacuum", "--config", str(path), "--key", key, "--reason", "the audit")
    if code != 0 or "pruned" not in said:
        raise AuditError(f"interlock vacuum failed ({code}):\n{said}")


def _calls(api: PaymentAPI, canaries: Canaries, sensitive: Sensitive, run: Run) -> None:
    """The canaries reached the payment API: the run did use them."""
    if not api.calls:
        run.unseen.append("the payment API was never called")
        return
    (call,) = api.calls
    if call.get("authorization") != f"Bearer {canaries.api_key}":
        run.unseen.append("the API key never reached the payment API")
    sent = call.get("traceparent") or ""
    if canaries.trace not in sent:
        run.unseen.append("the plan's trace never reached the payment API")
    elif sent != canaries.traceparent:
        sensitive.add("the relay's traceparent", sent)


def _commitment(item: Input, sensitive: Sensitive) -> str | None:
    """What a hash input holding the body, or its SHA-256, is when it is the
    body's commitment: the body's own SHA-256; the inbound event's hash or its
    signed statement, each over that SHA-256. ``None`` when it is not."""
    body = sensitive.values.get("the webhook's body", "")
    if item.kind == "sha256" and body and item.data == body.encode("utf-8"):
        return "the body's own SHA-256"
    if item.data.startswith(EVENT_HASH):
        return "the inbound event's hash, over the body's SHA-256"
    if item.data.startswith(INBOUND_DOMAIN):
        try:
            statement = json.loads(item.data[len(INBOUND_DOMAIN) :])
        except ValueError:
            return None
        if isinstance(statement, dict) and statement.get("body_hash") == digest(body):
            return "the inbound event's statement, over the body's SHA-256"
    return None


def _hashes(inputs: Sequence[Input], sensitive: Sensitive, run: Run) -> None:
    """No input holds a sensitive value, or its SHA-256, but the body's
    commitment: the body itself, hashed; its SHA-256, in the event's hash and
    statement."""
    for item in inputs:
        held = sensitive.found(item.data)
        if not held:
            continue
        commitment = _commitment(item, sensitive)
        if commitment == "the body's own SHA-256":
            allowed = all(what in BODY and how == "itself" for what, how in held)
        elif commitment is not None:
            allowed = held == [("the webhook's body", "its SHA-256")]
        else:
            allowed = False
        if allowed:
            assert commitment is not None
            run.commitments[commitment] = run.commitments.get(commitment, 0) + 1
            continue
        for what, how in held:
            run.leaks.append(
                f"{item.kind} input at {item.where} holds {what} ({how}): {item.data[:160]!r}"
            )


def _families(inputs: Sequence[Input], run: Run) -> None:
    """Every family of hash the audit claims was computed, and recorded."""
    for what, kind, site in FAMILIES:
        count = sum(1 for i in inputs if i.kind == kind and i.where.split(" ← ")[0] == site)
        run.families[what] = count
        if not count:
            run.unseen.append(f"no input of {what} ({site}) was recorded")


def _name(table: str) -> str:
    """A table's name in either store: ``inbox_events`` for
    ``app.db:_interlock_inbox_events`` and ``interlock.inbox_events``."""
    return table.rsplit(":", 1)[-1].rsplit(".", 1)[-1].lstrip("_").removeprefix("interlock_")


def _columns(
    cells: Sequence[Cell], inputs: Sequence[Input], sensitive: Sensitive, run: Run
) -> None:
    """No column holds a sensitive value, or its SHA-256, but those made to
    (:data:`KEPT`); and which hashes read each that does."""
    for cell in cells:
        held = sensitive.found(cell.value.encode("utf-8"))
        if not held:
            continue
        kept = KEPT.get((_name(cell.table), cell.column), frozenset())
        entry = run.held.setdefault((cell.table, cell.column), {})
        value = cell.value.encode("utf-8")
        readers = {f"{i.where.split(' ← ')[0]} ({i.kind})" for i in inputs if value in i.data}
        for what, how in held:
            digested = how == "its SHA-256"
            entry.setdefault(f"the SHA-256 of {what}" if digested else what, set()).update(readers)
            if what not in kept or digested != (cell.column == "body_hash"):
                run.leaks.append(f"column {cell.table}.{cell.column} holds {what} ({how})")


def _planted(before: Sequence[Cell], sensitive: Sensitive, run: Run) -> None:
    """Each canary is where it was planted, before the vacuum: the audit is
    seen to look."""
    found = {
        (_name(cell.table), cell.column, what)
        for cell in before
        for what, how in sensitive.found(cell.value.encode("utf-8"))
        if how == "itself"
    }
    for table, column, what in PLANTED:
        if (table, column, what) not in found:
            run.unseen.append(f"{what} was not found in {table}.{column}, where it was planted")


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def report(run: Run, say: Callable[[str], None]) -> None:
    say(
        f"  crawled {run.tables} tables, {run.cells} values; recorded {run.inputs} hash and "
        f"signature inputs, among them:"
    )
    for what, count in run.families.items():
        say(f"    {count:4} of {what}")
    say("  columns holding a sensitive value, and the hashes that read them:")
    for (table, column), held in sorted(run.held.items()):
        for what, readers in sorted(held.items()):
            read = ", ".join(sorted(readers)) or "no hash"
            say(f"    {table}.{column}: {what}; read by {read}")
    say("  the one commitment a sensitive value has (the inbound event to its body's SHA-256):")
    for what, count in sorted(run.commitments.items()):
        say(f"    {what}: {count} input(s)")
    for unseen in run.unseen:
        say(f"  NOT SEEN: {unseen}")
    for leak in run.leaks:
        say(f"  LEAK: {leak}")
    say(f"  {run.store}: " + ("clean" if run.clean else "FAILED"))


# --------------------------------------------------------------------------
# Running it
# --------------------------------------------------------------------------


def _soak() -> ModuleType:
    """The soak's PostgreSQL container helpers."""
    path = Path(__file__).with_name("live_stress_test.py")
    spec = importlib.util.spec_from_file_location("interlock_soak", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--dsn", help="a PostgreSQL server, as a role that creates databases")
    where.add_argument("--docker", action="store_true", help="start postgres:16 for the audit")
    parser.add_argument("--image", default="postgres:16")
    parser.add_argument("--keep", action="store_true", help="keep the run's files")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    def say(text: str) -> None:
        print(text, flush=True)

    canaries = Canaries.make()
    directory = Path(tempfile.mkdtemp(prefix="interlock-audit-"))
    cluster: Any = None
    runs: list[Run] = []
    try:
        stores: list[Store] = [SqliteStore(directory / "sqlite")]
        admin = args.dsn
        if args.docker:
            soak = _soak()
            cluster = soak.start_docker(args.image)
            admin = cluster.admin
        if admin:
            stores.append(PostgresStore(directory / "postgres", admin))
        for store in stores:
            say(f"{store.name}:")
            try:
                run = audit(store, canaries, say=say)
            finally:
                store.close()
            report(run, say)
            runs.append(run)
    except AuditError as exc:
        print(f"security audit: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if cluster is not None:
            cluster.close()
        if args.keep:
            say(f"files kept in {directory}")
        else:
            shutil.rmtree(directory, ignore_errors=True)
    clean = all(run.clean for run in runs)
    say(
        "no sensitive value reaches a hash; each is kept only where it is meant to be"
        if clean
        else "the audit FAILED"
    )
    return EXIT_CLEAN if clean else EXIT_LEAKED


if __name__ == "__main__":
    sys.exit(main())
