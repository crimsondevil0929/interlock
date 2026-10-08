"""The configuration file the ``interlock`` command reads.

TOML, so the standard library reads it::

    substrate = "postgres"            # or "sqlite"
    database = "postgresql://interlock_agent@db/app"   # or a SQLite path
    schema = "public"                 # PostgreSQL only
    stage_roles = ["interlock_agent"] # PostgreSQL install only
    audit_roles = ["interlock_audit"] # PostgreSQL install only
    relay_roles = ["interlock_relay"] # PostgreSQL install only
    settler_roles = ["interlock_settle"]  # PostgreSQL install only; interlock.settlement
    acknowledge_cascades = []

    [[tables]]
    name = "orders"
    primary_key = "id"
    columns = ["id", "tenant", "total"]
    tenant_column = "tenant"

    [[sinks]]                         # outbound requests; see docs/OUTBOX_DESIGN.md
    name = "mail"
    cost_per_call = "0.002"           # a decimal string, settled at commit
    idempotency = "header"            # or "none"
    max_payload_bytes = 16384
    not_after_seconds = 900
    max_attempts = 10                 # calls before a request is dead
    backoff_base_seconds = 1          # doubling, with jitter, up to the cap
    backoff_cap_seconds = 600
    unknown_outcome = "redeliver"     # or "dead-letter": at most once

    [[sinks.operations]]
    name = "send"
    compensation = "none-possible"    # or the operation that undoes this one
    schema = "schemas/mail-send.json" # relative to this file; omit for any object

    [relay]                           # interlock relay; see interlock.relay
    key = "relay.key"                 # this relay's Ed25519 key (interlock keygen --role relay)
    database = "postgresql://interlock_relay@db/app"  # a relay role
    ledger = "postgresql://interlock_relay@db/app"    # AgentGov, for the breaker
    ledger_schema = "agentgov"
    breaker = "agentgov"              # or "none", explicitly, without AgentGov
    lease_seconds = 60                # at least twice timeout_seconds
    timeout_seconds = 10
    poll_seconds = 1
    batch = 1
    workers = 1

    [[relay.endpoints]]
    sink = "mail"
    url = "https://api.mail.example"
    routes = { send = "POST /v3/mail/send" }        # every operation of the sink
    header_env = { Authorization = "MAIL_AUTHORIZATION" }

A typed sink (``docs/EPIC3_DESIGN.md`` §4) brings its operations' schemas
and its relay adapter; configuration names which of its operations to allow::

    [[sinks]]
    name = "payments"
    type = "stripe"                   # or "sendgrid"; "http" by default
    cost_per_call = "0.30"

    [[sinks.operations]]
    name = "payment_intents.create"   # undone by refunds.create, so it is listed too

    [[sinks.operations]]
    name = "refunds.create"

    [[relay.endpoints]]
    sink = "payments"
    secret_env = "STRIPE_SECRET_KEY"  # the variable holding the API key
    # url = "https://api.stripe.com"  # the vendor's own, unless given
    # stripe_version = "2024-06-20"   # stripe; sandbox = true for sendgrid

Rate windows (``docs/EPIC4_DESIGN.md`` §3) bound what plans add up to over
time, whatever each plan alone may do; an engine takes them as
``EscrowEngine(windows=config.windows)``::

    [[windows]]
    name = "refunds_per_agent_day"    # what the agent a window refuses is told
    span_seconds = 86400              # it slides
    limit = "10000"                   # a decimal string, or an integer
    per = "scope"                     # or "tenant", "global"
    measure = "request_sum"           # requests, request_sum, row_sum or plans
    sink = "payments"                 # requests, request_sum: a [[sinks]] name...
    operation = "refunds.create"      # ...and one of its operations
    field = "amount"                  # request_sum: the payload's number
    # table = "refunds"               # row_sum: a [[tables]] name...
    # column = "amount"               # ...and one of its columns
    # rows = "inserted"               # row_sum: or "net"

Relays sign every outcome they record (``docs/EPIC4_DESIGN.md`` §2); their
public keys are registered for verification::

    [relays.keys]
    east-1 = "ed25519:9a1b..."

Operators sign every action on the outbox (``docs/EPIC3_DESIGN.md`` §6)::

    [operators]
    log = "operators.ilok1"           # the signed operator log, beside this file
    ledger = "governor.db"            # optional: anchor every record in AgentGov
    scope = "interlock-operators"     # the ledger scope the anchors go to

    [operators.keys]                  # public halves only: `interlock operator keygen`
    alice = "ed25519:5f0c..."

A vacuum (``docs/EPIC5_DESIGN.md`` §1) prunes what no check will read again,
under a checkpoint an operator signs and AgentGov anchors (``[operators]``
needs its ``ledger``); window history goes only past the longest
``[[windows]]`` span::

    [vacuum]
    retain_days = 30                  # a final message stays this long after its last row
    margin_seconds = 3600             # window history stays this long past the longest span
    archive = "archive"               # optional: pruned rows written here first, provable

The inbox (``docs/EPIC5_DESIGN.md`` §2) receives vendors' webhooks in a
process of its own, verifies each one's signature, binds it to the delivered
request it names, and attests the fact; an engine consumes only facts that
verify under ``[inbox.keys]``, as ``EscrowEngine(inbox=config.inbox_keyring())``::

    inbox_roles = ["interlock_inbox"] # PostgreSQL install only

    [inbox]                           # interlock inbox serve; see interlock.inbox
    key = "inbox.key"                 # its Ed25519 key (interlock keygen --role inbox)
    database = "postgresql://interlock_inbox@db/app"  # an inbox role
    listen = "127.0.0.1:8787"         # plain HTTP: put TLS in front of it
    max_body_bytes = 262144
    match_window_seconds = 3600       # an event that matched nothing is tried again this long
    match_every_seconds = 5

    [[inbox.sources]]                 # served at POST /inbox/<name>
    name = "stripe"
    kind = "stripe"                   # or "sendgrid", or "http" (Standard Webhooks)
    secret_env = "STRIPE_WEBHOOK_SECRET"  # the variable holding the signing secret
    tolerance_seconds = 300
    # verification_key = "MFkw..."    # sendgrid: the account's public verification key
    # type_field = "type"             # http: where the event names its type
    # references = ["data.id"]        # http: where it names what it is about
    # fields = [{ name = "status", path = "data.status", type = "code" }]  # http

    [inbox.keys]                      # public halves only: what facts verify under
    main = "ed25519:7d2e..."

The daemon (``interlock daemon``; ``docs/EPIC6_DESIGN.md`` §2) runs the engines
that execute agents' plans beside the relays, the inbox, the settler and the
vacuum, each part connecting as its own role::

    [engine]                          # the engines executing agents' plans
    workers = 4                       # plans staged at once: one engine each
    database = "postgresql://interlock_agent@db/app"  # the stage role
    chain = "escrow.chain"            # worker n writes escrow-<n>.chain
    settle_cost = "0.01"              # what producing a plan costs its scope
    ledger = "postgresql://owner@db/app"  # AgentGov: the ledger's owner, or a SQLite file
    same_transaction = true           # PostgreSQL: settle each plan with its commit
    conflict_retries = 16             # a plan that lost a race is staged again
    max_stage_seconds = 10
    lock_timeout_seconds = 2
    pool_timeout_seconds = 2          # PostgreSQL: the rate windows' connection, or retried

    [receipts]                        # the receipt log: action and delivery receipts
    log = "receipts.jsonl"
    key = "receipts.key"              # its Ed25519 key
    log_id = "interlock-receipts"

    [settler]
    database = "postgresql://interlock_settle@db/app"  # a settler role
    every_seconds = 5

    [vacuum]                          # with the keys above
    every_seconds = 3600              # the daemon's vacuums; 0 or unset: none
    # retain_seconds = 600            # in place of retain_days: retention in seconds
    database = "postgresql://owner@db/app"  # the installer
    key = "vacuum.key"                # an operator key in [operators.keys]

    [daemon]
    drain_timeout_seconds = 30        # each shutdown step's bound
    restart_min_seconds = 0.5         # a failed service backs off from here...
    restart_max_seconds = 30          # ...doubling to here

``database`` may be left out and given on the command line or in
``INTERLOCK_DATABASE`` instead, which keeps a password out of the file; the
relay's in ``INTERLOCK_RELAY_DATABASE``, the inbox's in
``INTERLOCK_INBOX_DATABASE``. A sink has no endpoint or credential in
``[[sinks]]``: those belong to the relay, and its credentials only to its
environment: ``header_env`` names the variable holding each header's value.
A webhook's signing secret, likewise, lives only in the inbox's environment:
``secret_env`` names the variable.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from interlock.inbox import MAX_BODY, TYPES, FieldSpec, InboundSource
from interlock.outbound import (
    HTTP,
    KINDS,
    NONE_POSSIBLE,
    OperationSpec,
    SinkRegistry,
    SinkSpec,
    typed_sink,
)
from interlock.records import Keyring
from interlock.substrate import TableSpec
from interlock.windows import Measure, Plans, RateWindow, Requests, RequestSum, RowSum

__all__ = [
    "DATABASE_ENV",
    "INBOX_DATABASE_ENV",
    "RELAY_DATABASE_ENV",
    "SETTLER_DATABASE_ENV",
    "DaemonConfig",
    "Endpoint",
    "EngineConfig",
    "InboxConfig",
    "InterlockConfig",
    "OperatorsConfig",
    "ReceiptsConfig",
    "RelayConfig",
    "SettlerConfig",
    "VacuumConfig",
    "load_config",
]

DATABASE_ENV = "INTERLOCK_DATABASE"
RELAY_DATABASE_ENV = "INTERLOCK_RELAY_DATABASE"
INBOX_DATABASE_ENV = "INTERLOCK_INBOX_DATABASE"
SETTLER_DATABASE_ENV = "INTERLOCK_SETTLER_DATABASE"


class ConfigError(ValueError):
    """The configuration file is missing, unreadable or malformed."""


def is_dsn(text: str) -> bool:
    """Whether ``text`` is a PostgreSQL connection string, a URI or libpq's
    ``key=value`` form, rather than a file's path."""
    return "://" in text or "=" in text


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Where the relay delivers one sink's requests.

    :ivar routes: ``"METHOD /path"`` for every operation of an ``http`` sink.
    :ivar header_env: Each header sent with every call to an ``http`` sink,
        mapped to the environment variable that holds its value.
    :ivar kind: The sink's kind, which picks the adapter.
    :ivar secret_env: A typed sink's API key: the variable that holds it.
    :ivar stripe_version: The ``Stripe-Version`` a Stripe adapter pins.
    :ivar sandbox: A SendGrid adapter validates and sends nothing.
    """

    sink: str
    url: str
    routes: Mapping[str, str]
    header_env: Mapping[str, str]
    kind: str = HTTP
    secret_env: str = ""
    stripe_version: str = ""
    sandbox: bool = False


@dataclass(frozen=True, slots=True)
class RelayConfig:
    """``[relay]``: how ``interlock relay`` runs."""

    database: str
    endpoints: tuple[Endpoint, ...]
    ledger: str | None = None
    ledger_schema: str = "agentgov"
    breaker: str = "agentgov"
    lease: timedelta = timedelta(seconds=60)
    timeout: timedelta = timedelta(seconds=10)
    poll_seconds: float = 1.0
    batch: int = 1
    workers: int = 1
    key: Path | None = None
    """This relay's own Ed25519 key file (``interlock keygen --role relay``),
    or ``INTERLOCK_RELAY_KEY``: it signs every outcome the relay records."""


@dataclass(frozen=True, slots=True)
class OperatorsConfig:
    """``[operators]``: who may act on the outbox, and the signed log of what
    they did (``docs/EPIC3_DESIGN.md`` §6).

    :ivar log: The operator log's file.
    :ivar keys: Each operator's name and Ed25519 public key
        (``ed25519:<hex>``). Only public halves: each operator holds their own
        private key, and verifying needs none.
    :ivar ledger: An AgentGov ledger every record is anchored into: a SQLite
        file or a ``postgresql://`` DSN.
    :ivar scope: The ledger scope the anchors are written to.
    """

    log: Path
    keys: Mapping[str, str]
    ledger: str | None = None
    scope: str = "interlock-operators"

    def keyring(self) -> Keyring:
        return Keyring(self.keys)


@dataclass(frozen=True, slots=True)
class VacuumConfig:
    """``[vacuum]``: what ``interlock vacuum`` keeps (``docs/EPIC5_DESIGN.md`` §1).

    :ivar retain: How long a final message stays after its last log row.
        Past it, a delivered request can no longer be compensated.
    :ivar margin: How long window history stays past the longest span.
    :ivar archive: A directory each checkpoint's pruned rows are written to
        first, or ``None``.
    :ivar every: How often the daemon vacuums, or ``None`` for never.
    :ivar database: The installer's connection the daemon vacuums through;
        ``""`` for the file's own.
    :ivar key: The operator key the daemon signs its vacuums with: one of
        ``[operators.keys]``, as accountable as any operator's.
    """

    retain: timedelta = timedelta(days=30)
    margin: timedelta = timedelta(hours=1)
    archive: Path | None = None
    every: timedelta | None = None
    database: str = ""
    key: Path | None = None


@dataclass(frozen=True, slots=True)
class EngineConfig:
    """``[engine]``: the engines that execute agents' plans, in a runtime
    (``EscrowRuntime.from_config``) or the daemon (``docs/EPIC6_DESIGN.md``).

    :ivar workers: How many plans the daemon stages at once: one engine per
        worker, each with its own substrate, governor and escrow chain.
    :ivar database: The stage role's connection; ``""`` for the file's own.
    :ivar chain: The escrow chain's file, or ``None`` to keep chains in
        memory. Worker ``n`` of several writes ``<stem>-<n><suffix>``.
    :ivar settle_cost: What producing a plan costs, charged to its scope.
    :ivar ledger: The AgentGov ledger plans are charged to: a
        ``postgresql://`` connection string, as the ledger's owner, or a
        SQLite file. ``None``: no ledger.
    :ivar same_transaction: Settle each plan with its commit: claim and
        settle (PostgreSQL, with the ledger in the same database).
    :ivar conflict_retries: How often the daemon stages a plan again after it
        lost a race for a row or a window key.
    """

    workers: int = 1
    database: str = ""
    chain: Path | None = None
    settle_cost: Decimal = Decimal(0)
    ledger: str | None = None
    ledger_schema: str = "agentgov"
    same_transaction: bool = False
    conflict_retries: int = 16
    max_stage_seconds: float = 10.0
    lock_timeout_seconds: float = 2.0
    pool_timeout_seconds: float | None = None

    def chain_for(self, worker: int, workers: int | None = None) -> Path | None:
        """The chain file worker ``worker`` writes: the configured one for a
        single worker, ``<stem>-<n><suffix>`` for each of several."""
        if self.chain is None:
            return None
        if (workers if workers is not None else self.workers) == 1:
            return self.chain
        return self.chain.with_name(f"{self.chain.stem}-{worker}{self.chain.suffix}")


@dataclass(frozen=True, slots=True)
class ReceiptsConfig:
    """``[receipts]``: the receipt log the engines issue action receipts
    into, and the settler delivery receipts. One process writes it.

    :ivar log: Its file.
    :ivar key: Its Ed25519 key's file (``interlock keygen``).
    """

    log: Path
    key: Path
    log_id: str = "interlock-receipts"
    issuer: str = "interlock"
    policy_epoch: int = 0


@dataclass(frozen=True, slots=True)
class SettlerConfig:
    """``[settler]``: how the daemon settles delivered requests.

    :ivar database: A settler role's connection (``settler_roles``); ``""``
        for the file's own, or ``INTERLOCK_SETTLER_DATABASE``.
    :ivar every: How often it settles.
    """

    database: str = ""
    every: timedelta = timedelta(seconds=5)


@dataclass(frozen=True, slots=True)
class DaemonConfig:
    """``[daemon]``: the supervisor's own bounds.

    :ivar drain_timeout: The most each step of a shutdown waits.
    :ivar restart_min: A failed service is restarted after this...
    :ivar restart_max: ...doubling each failure in a row, up to this.
    """

    drain_timeout: timedelta = timedelta(seconds=30)
    restart_min: timedelta = timedelta(milliseconds=500)
    restart_max: timedelta = timedelta(seconds=30)


@dataclass(frozen=True, slots=True)
class InboxConfig:
    """``[inbox]``: how ``interlock inbox`` runs, and what facts verify under
    (``docs/EPIC5_DESIGN.md`` §2).

    :ivar sources: ``[[inbox.sources]]``: each vendor sending webhooks.
    :ivar keys: ``[inbox.keys]``: each inbox's name and Ed25519 public key.
        An engine consumes a fact only when its attestations verify under one.
    :ivar database: The inbox role's connection, or ``""`` for the
        configuration's own (SQLite) or ``INTERLOCK_INBOX_DATABASE``.
    :ivar key: The inbox's own key file (``interlock keygen --role inbox``),
        or ``INTERLOCK_INBOX_KEY``.
    """

    sources: tuple[InboundSource, ...] = ()
    keys: Mapping[str, str] | None = None
    database: str = ""
    key: Path | None = None
    listen: str = "127.0.0.1:8787"
    max_body: int = MAX_BODY
    match_window: timedelta = timedelta(hours=1)
    match_every: timedelta = timedelta(seconds=5)

    def keyring(self) -> Keyring | None:
        return None if self.keys is None else Keyring(self.keys)


@dataclass(frozen=True, slots=True)
class InterlockConfig:
    substrate: str
    database: str
    tables: tuple[TableSpec, ...]
    schema: str = "public"
    stage_roles: tuple[str, ...] = ()
    audit_roles: tuple[str, ...] = ()
    acknowledge_cascades: tuple[str, ...] = ()
    sinks: tuple[SinkSpec, ...] = ()
    relay_roles: tuple[str, ...] = ()
    settler_roles: tuple[str, ...] = ()
    relay: RelayConfig | None = None
    operators: OperatorsConfig | None = None
    relays: Mapping[str, str] | None = None
    """``[relays.keys]``: each relay's name and Ed25519 public key. A relay
    starts only with a key registered here, and verification holds every
    outcome to one of them."""
    windows: tuple[RateWindow, ...] = ()
    """``[[windows]]``: the rate windows, as an engine takes them."""
    vacuum: VacuumConfig = VacuumConfig()
    """``[vacuum]``: what a vacuum keeps."""
    inbox: InboxConfig = InboxConfig()
    """``[inbox]``: the inbox, and the keys its facts verify under."""
    inbox_roles: tuple[str, ...] = ()
    engine: EngineConfig = EngineConfig()
    """``[engine]``: the engines that execute agents' plans."""
    receipts: ReceiptsConfig | None = None
    """``[receipts]``: the receipt log, or ``None`` for no receipts."""
    settler: SettlerConfig = SettlerConfig()
    daemon: DaemonConfig = DaemonConfig()

    def relay_keyring(self) -> Keyring | None:
        return None if self.relays is None else Keyring(self.relays)

    def inbox_keyring(self) -> Keyring | None:
        """``[inbox.keys]``, as an engine takes them: ``EscrowEngine(inbox=...)``."""
        return self.inbox.keyring()

    def with_database(self, database: str | None) -> InterlockConfig:
        if not database:
            return self
        return replace(self, database=database)

    def sink_registry(self) -> SinkRegistry:
        """The sinks as an engine takes them."""
        return SinkRegistry(self.sinks)


def load_config(
    path: str | Path, *, database: str | None = None, require_database: bool = True
) -> InterlockConfig:
    """Read and validate a configuration file.

    :param database: Overrides the file's ``database``, as does
        ``INTERLOCK_DATABASE`` when this is not given.
    :param require_database: Refuse a file that names no ``database``. A
        relay host connects with ``[relay]``'s instead, and needs none.
    :raises ConfigError: On anything missing or malformed, naming it.
    """
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

    substrate = _string(raw, "substrate", default="sqlite")
    if substrate not in ("sqlite", "postgres"):
        raise ConfigError(f"substrate must be 'sqlite' or 'postgres', not {substrate!r}")
    url = database or os.environ.get(DATABASE_ENV) or _string(raw, "database", default="")
    if not url and require_database:
        raise ConfigError(
            f"no database: set 'database' in {path}, pass --database, or set {DATABASE_ENV}"
        )
    entries = raw.get("tables")
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{path} lists no [[tables]]")
    tables: list[TableSpec] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"tables[{index}] is not a table")
        try:
            tables.append(
                TableSpec(
                    _string(entry, "name"),
                    primary_key=_string(entry, "primary_key", default="id"),
                    columns=_strings(entry, "columns"),
                    tenant_column=_string(entry, "tenant_column", default="") or None,
                )
            )
        except ValueError as exc:
            raise ConfigError(f"tables[{index}]: {exc}") from exc
    sinks = _sinks(raw.get("sinks", []), Path(path).parent)
    relay_roles = tuple(_strings(raw, "relay_roles", required=False))
    settler_roles = tuple(_strings(raw, "settler_roles", required=False))
    inbox_roles = tuple(_strings(raw, "inbox_roles", required=False))
    for label, roles in (
        ("relay_roles", relay_roles),
        ("settler_roles", settler_roles),
        ("inbox_roles", inbox_roles),
    ):
        if roles and substrate != "postgres":
            raise ConfigError(
                f"{label} are PostgreSQL roles; on SQLite the file's permissions bound who "
                f"writes it instead"
            )
    relay = _relay(raw.get("relay"), sinks, Path(path).parent)
    operators = _operators(raw.get("operators"), Path(path).parent)
    relays = _relays(raw.get("relays"))
    windows = _windows(raw.get("windows", []), tuple(tables), sinks)
    vacuum = _vacuum(raw.get("vacuum"), Path(path).parent)
    inbox = _inbox(raw.get("inbox"), Path(path).parent)
    engine = _engine(raw.get("engine"), Path(path).parent, substrate)
    return InterlockConfig(
        substrate=substrate,
        database=url,
        tables=tuple(tables),
        schema=_string(raw, "schema", default="public"),
        stage_roles=tuple(_strings(raw, "stage_roles", required=False)),
        audit_roles=tuple(_strings(raw, "audit_roles", required=False)),
        acknowledge_cascades=tuple(_strings(raw, "acknowledge_cascades", required=False)),
        sinks=sinks,
        relay_roles=relay_roles,
        settler_roles=settler_roles,
        relay=relay,
        operators=operators,
        relays=relays,
        windows=windows,
        vacuum=vacuum,
        inbox=inbox,
        inbox_roles=inbox_roles,
        engine=engine,
        receipts=_receipts(raw.get("receipts"), Path(path).parent),
        settler=_settler(raw.get("settler")),
        daemon=_daemon(raw.get("daemon")),
    )


def _vacuum(raw: object, base: Path) -> VacuumConfig:
    if raw is None:
        return VacuumConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'vacuum' must be a table ([vacuum])")
    known = {
        "retain_days",
        "retain_seconds",
        "margin_seconds",
        "archive",
        "every_seconds",
        "database",
        "key",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"[vacuum]: unknown key(s) {', '.join(unknown)}")
    if "retain_days" in raw and "retain_seconds" in raw:
        raise ConfigError("[vacuum]: retain_days or retain_seconds, not both")
    retain = (
        timedelta(seconds=_integer(raw, "retain_seconds", 0))
        if "retain_seconds" in raw
        else timedelta(days=_integer(raw, "retain_days", 30))
    )
    margin = _integer(raw, "margin_seconds", 3600)
    every = _integer(raw, "every_seconds", 0)
    if retain < timedelta(0) or margin < 0 or every < 0:
        raise ConfigError(
            "[vacuum]: retain_days, retain_seconds, margin_seconds and every_seconds are not "
            "negative"
        )
    archive = _string(raw, "archive", default="") or None
    key = _string(raw, "key", default="")
    return VacuumConfig(
        retain=retain,
        margin=timedelta(seconds=margin),
        archive=None if archive is None else base / archive,
        every=timedelta(seconds=every) if every else None,
        database=_string(raw, "database", default=""),
        key=base / key if key else None,
    )


_ENGINE_KEYS = frozenset(
    {
        "workers",
        "database",
        "chain",
        "settle_cost",
        "ledger",
        "ledger_schema",
        "same_transaction",
        "conflict_retries",
        "max_stage_seconds",
        "lock_timeout_seconds",
        "pool_timeout_seconds",
    }
)


def _engine(raw: object, base: Path, substrate: str) -> EngineConfig:
    if raw is None:
        return EngineConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'engine' must be a table ([engine])")
    unknown = sorted(set(raw) - _ENGINE_KEYS)
    if unknown:
        raise ConfigError(f"[engine]: unknown key(s) {', '.join(unknown)}")
    workers = _integer(raw, "workers", 1)
    retries = _integer(raw, "conflict_retries", 16)
    if workers < 1 or retries < 0:
        raise ConfigError("[engine]: workers is at least 1, conflict_retries not negative")
    if workers > 1 and substrate == "sqlite":
        raise ConfigError(
            "[engine]: SQLite admits one writer, and a stage holds the write lock for its "
            "whole life: one worker"
        )
    cost = _decimal(raw, "settle_cost")
    if cost < 0:
        raise ConfigError("[engine]: settle_cost is not negative")
    ledger = _string(raw, "ledger", default="") or None
    together = raw.get("same_transaction", False)
    if not isinstance(together, bool):
        raise ConfigError("[engine]: same_transaction is true or false")
    if together and (substrate != "postgres" or ledger is None or not is_dsn(ledger)):
        raise ConfigError(
            "[engine]: same_transaction settles a plan inside its stage's transaction: it "
            'needs substrate = "postgres" and a ledger in the same database'
        )
    chain = _string(raw, "chain", default="")
    if ledger is not None and not is_dsn(ledger):
        ledger = str(base / ledger)
    return EngineConfig(
        workers=workers,
        database=_string(raw, "database", default=""),
        chain=base / chain if chain else None,
        settle_cost=cost,
        ledger=ledger,
        ledger_schema=_string(raw, "ledger_schema", default="agentgov"),
        same_transaction=together,
        conflict_retries=retries,
        max_stage_seconds=_seconds(raw, "max_stage_seconds", 10.0),
        lock_timeout_seconds=_seconds(raw, "lock_timeout_seconds", 2.0),
        pool_timeout_seconds=(
            _seconds(raw, "pool_timeout_seconds", 2.0) if "pool_timeout_seconds" in raw else None
        ),
    )


def _receipts(raw: object, base: Path) -> ReceiptsConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("'receipts' must be a table ([receipts])")
    unknown = sorted(set(raw) - {"log", "key", "log_id", "issuer", "policy_epoch"})
    if unknown:
        raise ConfigError(f"[receipts]: unknown key(s) {', '.join(unknown)}")
    epoch = _integer(raw, "policy_epoch", 0)
    if epoch < 0:
        raise ConfigError("[receipts]: policy_epoch is not negative")
    return ReceiptsConfig(
        log=base / _string(raw, "log"),
        key=base / _string(raw, "key"),
        log_id=_string(raw, "log_id", default="interlock-receipts"),
        issuer=_string(raw, "issuer", default="interlock"),
        policy_epoch=epoch,
    )


def _settler(raw: object) -> SettlerConfig:
    if raw is None:
        return SettlerConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'settler' must be a table ([settler])")
    unknown = sorted(set(raw) - {"database", "every_seconds"})
    if unknown:
        raise ConfigError(f"[settler]: unknown key(s) {', '.join(unknown)}")
    return SettlerConfig(
        database=_string(raw, "database", default=""),
        every=timedelta(seconds=_seconds(raw, "every_seconds", 5.0)),
    )


def _daemon(raw: object) -> DaemonConfig:
    if raw is None:
        return DaemonConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'daemon' must be a table ([daemon])")
    known = {"drain_timeout_seconds", "restart_min_seconds", "restart_max_seconds"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"[daemon]: unknown key(s) {', '.join(unknown)}")
    low = _seconds(raw, "restart_min_seconds", 0.5)
    high = _seconds(raw, "restart_max_seconds", 30.0)
    if high < low:
        raise ConfigError("[daemon]: restart_max_seconds is at least restart_min_seconds")
    return DaemonConfig(
        drain_timeout=timedelta(seconds=_seconds(raw, "drain_timeout_seconds", 30.0)),
        restart_min=timedelta(seconds=low),
        restart_max=timedelta(seconds=high),
    )


_INBOX_KEYS = frozenset(
    {
        "key",
        "database",
        "listen",
        "max_body_bytes",
        "match_window_seconds",
        "match_every_seconds",
        "sources",
        "keys",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "name",
        "kind",
        "secret_env",
        "verification_key",
        "tolerance_seconds",
        "type_field",
        "references",
        "fields",
    }
)


def _inbox(raw: object, base: Path) -> InboxConfig:
    if raw is None:
        return InboxConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'inbox' must be a table ([inbox])")
    unknown = sorted(set(raw) - _INBOX_KEYS)
    if unknown:
        raise ConfigError(f"[inbox]: unknown key(s) {', '.join(unknown)}")
    entries = raw.get("sources", [])
    if not isinstance(entries, list):
        raise ConfigError("inbox.sources must be an array of tables ([[inbox.sources]])")
    sources = tuple(_source(entry, index) for index, entry in enumerate(entries))
    names = [s.name for s in sources]
    twice = sorted({n for n in names if names.count(n) > 1})
    if twice:
        raise ConfigError(f"[[inbox.sources]]: {', '.join(twice)} configured twice")
    keys = None
    if "keys" in raw:
        keys = _table_of_strings(raw, "keys")
        try:
            Keyring(keys)
        except ValueError as exc:
            raise ConfigError(f"[inbox.keys]: {exc}") from exc
    key = _string(raw, "key", default="")
    max_body = _integer(raw, "max_body_bytes", MAX_BODY)
    window = _integer(raw, "match_window_seconds", 3600)
    every = _seconds(raw, "match_every_seconds", 5.0)
    if max_body <= 0 or window < 0 or every <= 0:
        raise ConfigError(
            "[inbox]: max_body_bytes and match_every_seconds are positive, "
            "match_window_seconds is not negative"
        )
    listen = _string(raw, "listen", default="127.0.0.1:8787")
    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise ConfigError(f"[inbox]: listen is HOST:PORT, not {listen!r}")
    return InboxConfig(
        sources=sources,
        keys=keys,
        database=_string(raw, "database", default=""),
        key=base / key if key else None,
        listen=listen,
        max_body=max_body,
        match_window=timedelta(seconds=window),
        match_every=timedelta(seconds=every),
    )


def _source(entry: object, index: int) -> InboundSource:
    where = f"inbox.sources[{index}]"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where} is not a table")
    unknown = sorted(set(entry) - _SOURCE_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
    fields: list[FieldSpec] = []
    raw_fields = entry.get("fields", [])
    if not isinstance(raw_fields, list):
        raise ConfigError(f"{where}: fields is an array of {{ name, path, type }} tables")
    for number, spec in enumerate(raw_fields):
        if not isinstance(spec, dict) or set(spec) != {"name", "path", "type"}:
            raise ConfigError(
                f"{where}: fields[{number}] is a {{ name, path, type }} table, type one of "
                f"{', '.join(TYPES)}"
            )
        try:
            fields.append(
                FieldSpec(_string(spec, "name"), _string(spec, "path"), _string(spec, "type"))
            )
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from exc
    tolerance = _integer(entry, "tolerance_seconds", 300)
    if tolerance <= 0:
        raise ConfigError(f"{where}: tolerance_seconds is positive")
    try:
        return InboundSource(
            name=_string(entry, "name"),
            kind=_string(entry, "kind", default=HTTP),
            secret_env=_string(entry, "secret_env", default=""),
            verification_key=_string(entry, "verification_key", default=""),
            tolerance=timedelta(seconds=tolerance),
            type_field=_string(entry, "type_field", default="type"),
            references=tuple(_strings(entry, "references", required=False)),
            fields=tuple(fields),
        )
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


_MEASURES = ("requests", "request_sum", "row_sum", "plans")


def _windows(
    entries: object, tables: tuple[TableSpec, ...], sinks: tuple[SinkSpec, ...]
) -> tuple[RateWindow, ...]:
    if not isinstance(entries, list):
        raise ConfigError("[[windows]] must be an array of tables")
    windows: list[RateWindow] = []
    for index, entry in enumerate(entries):
        where = f"windows[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} is not a table")
        try:
            name = _string(entry, "name")
            where = f"window {name}"
            if any(w.name == name for w in windows):
                raise ConfigError("is configured twice")
            limit = entry.get("limit")
            if not isinstance(limit, str | int) or isinstance(limit, bool):
                raise ConfigError("'limit' must be a decimal string or an integer, such as \"10\"")
            windows.append(
                RateWindow(
                    name,
                    timedelta(seconds=_seconds(entry, "span_seconds", 0)),
                    limit,
                    _measure(entry, tables, sinks),
                    _string(entry, "per", default="scope"),
                )
            )
        except (ConfigError, ValueError) as exc:
            raise ConfigError(f"{where}: {exc}") from exc
    return tuple(windows)


def _measure(
    entry: Mapping[str, Any], tables: tuple[TableSpec, ...], sinks: tuple[SinkSpec, ...]
) -> Measure:
    kind = _string(entry, "measure")
    allowed = {
        "requests": {"sink", "operation"},
        "request_sum": {"sink", "operation", "field"},
        "row_sum": {"table", "column", "rows"},
        "plans": set(),
    }.get(kind)
    if allowed is None:
        raise ConfigError(f"'measure' is one of {', '.join(_MEASURES)}, not {kind!r}")
    extra = sorted(set(entry) - {"name", "span_seconds", "limit", "per", "measure"} - allowed)
    if extra:
        raise ConfigError(f"a {kind} window takes no {', '.join(map(repr, extra))}")
    if kind == "plans":
        return Plans()
    if kind == "row_sum":
        name = _string(entry, "table")
        spec = next((t for t in tables if t.name.lower() == name.lower()), None)
        if spec is None:
            raise ConfigError(f"table {name!r} is not one of [[tables]]")
        column = _string(entry, "column")
        if column not in spec.columns:
            raise ConfigError(f"{name} has no column {column!r} in [[tables]]")
        return RowSum(name, column, _string(entry, "rows", default="inserted"))
    sink_name = _string(entry, "sink")
    sink = next((s for s in sinks if s.name == sink_name), None)
    if sink is None:
        raise ConfigError(f"sink {sink_name!r} is not one of [[sinks]]")
    operation = (
        _string(entry, "operation") if kind == "request_sum" or "operation" in entry else None
    )
    if operation is not None and operation not in {op.name for op in sink.operations}:
        raise ConfigError(f"sink {sink_name} has no operation {operation!r}")
    if kind == "requests":
        return Requests(sink_name, operation)
    assert operation is not None
    return RequestSum(sink_name, operation, _string(entry, "field"))


def _relays(raw: object) -> Mapping[str, str] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"keys"}:
        raise ConfigError("[relays] holds one table, [relays.keys]: each relay's public key")
    try:
        keys = _table_of_strings(raw, "keys")
        Keyring(keys)
    except ValueError as exc:
        raise ConfigError(f"[relays.keys]: {exc}") from exc
    return keys


def _operators(raw: object, base: Path) -> OperatorsConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("'operators' must be a table ([operators])")
    try:
        keys = _table_of_strings(raw, "keys")
        config = OperatorsConfig(
            log=base / _string(raw, "log"),
            keys=keys,
            ledger=_string(raw, "ledger", default="") or None,
            scope=_string(raw, "scope", default="interlock-operators"),
        )
        config.keyring()
    except ValueError as exc:
        raise ConfigError(f"[operators]: {exc}") from exc
    if config.ledger is not None and not is_dsn(config.ledger):
        config = replace(config, ledger=str(base / config.ledger))
    return config


def _relay(raw: object, sinks: tuple[SinkSpec, ...], base: Path) -> RelayConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("'relay' must be a table ([relay])")
    try:
        database = os.environ.get(RELAY_DATABASE_ENV) or _string(raw, "database", default="")
        breaker = _string(raw, "breaker", default="agentgov")
        if breaker not in ("agentgov", "none"):
            raise ConfigError("'breaker' is 'agentgov' or 'none'")
        ledger = _string(raw, "ledger", default="") or None
        if breaker == "agentgov" and ledger is None:
            raise ConfigError(
                "'ledger' names the AgentGov ledger whose breaker holds deliveries; set "
                "breaker = 'none' to run without one, explicitly"
            )
        registered = {sink.name: sink for sink in sinks}
        entries = raw.get("endpoints")
        if not isinstance(entries, list) or not entries:
            raise ConfigError("lists no [[relay.endpoints]]")
        endpoints: list[Endpoint] = []
        for index, entry in enumerate(entries):
            where = f"endpoints[{index}]"
            if not isinstance(entry, dict):
                raise ConfigError(f"{where} is not a table")
            sink_name = _string(entry, "sink")
            sink = registered.get(sink_name)
            if sink is None:
                raise ConfigError(f"{where}: no [[sinks]] entry named {sink_name!r}")
            if sink.kind != HTTP:
                endpoints.append(_typed_endpoint(entry, sink, where))
                continue
            for key in ("secret_env", "stripe_version", "sandbox"):
                if key in entry:
                    raise ConfigError(
                        f"{where}: {key!r} is for a typed sink; {sink_name!r} is http"
                    )
            routes = _table_of_strings(entry, "routes")
            missing = sorted({op.name for op in sink.operations} - set(routes))
            extra = sorted(set(routes) - {op.name for op in sink.operations})
            if missing or extra:
                raise ConfigError(
                    f"{where}: routes must name exactly the operations sink {sink_name!r} "
                    f"registers; missing {missing or 'none'}, unknown {extra or 'none'}"
                )
            endpoints.append(
                Endpoint(
                    sink=sink_name,
                    url=_string(entry, "url"),
                    routes=routes,
                    header_env=_table_of_strings(entry, "header_env", required=False),
                )
            )
        if len({e.sink for e in endpoints}) != len(endpoints):
            raise ConfigError("two [[relay.endpoints]] name the same sink")
        lease = timedelta(seconds=_seconds(raw, "lease_seconds", 60))
        timeout = timedelta(seconds=_seconds(raw, "timeout_seconds", 10))
        if lease < 2 * timeout:
            raise ConfigError("'lease_seconds' must be at least twice 'timeout_seconds'")
        return RelayConfig(
            database=database,
            endpoints=tuple(endpoints),
            ledger=ledger,
            ledger_schema=_string(raw, "ledger_schema", default="agentgov"),
            breaker=breaker,
            lease=lease,
            timeout=timeout,
            poll_seconds=_seconds(raw, "poll_seconds", 1),
            batch=_integer(raw, "batch", 1),
            workers=_integer(raw, "workers", 1),
            key=base / _string(raw, "key") if "key" in raw else None,
        )
    except ConfigError as exc:
        raise ConfigError(f"[relay]: {exc}") from exc


def _typed_endpoint(entry: Mapping[str, Any], sink: SinkSpec, where: str) -> Endpoint:
    """A Stripe or SendGrid sink's endpoint: the adapter knows its routes and
    how to present its key; configuration says where the key is."""
    for key in ("routes", "header_env"):
        if key in entry:
            raise ConfigError(
                f"{where}: a {sink.kind} sink's adapter knows its routes and credentials; "
                f"give 'secret_env', not {key!r}"
            )
    if "stripe_version" in entry and sink.kind != "stripe":
        raise ConfigError(f"{where}: 'stripe_version' is for a stripe sink")
    sandbox = entry.get("sandbox", False)
    if not isinstance(sandbox, bool) or (sandbox and sink.kind != "sendgrid"):
        raise ConfigError(f"{where}: 'sandbox' is true or false, for a sendgrid sink")
    url = _string(entry, "url", default="")
    if url and not url.startswith(("http://", "https://")):
        raise ConfigError(f"{where}: 'url' is an http(s) URL")
    return Endpoint(
        sink=sink.name,
        url=url,
        routes={},
        header_env={},
        kind=sink.kind,
        secret_env=_string(entry, "secret_env"),
        stripe_version=_string(entry, "stripe_version", default=""),
        sandbox=sandbox,
    )


def _table_of_strings(raw: Mapping[str, Any], key: str, *, required: bool = True) -> dict[str, str]:
    value = raw.get(key)
    if value is None and not required:
        return {}
    if not isinstance(value, dict) or (not value and required):
        raise ConfigError(f"{key!r} must be a table of strings")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ConfigError(f"{key!r} must be a table of strings")
    return dict(value)


def _sinks(entries: object, base: Path) -> tuple[SinkSpec, ...]:
    if not isinstance(entries, list):
        raise ConfigError("'sinks' must be an array of tables ([[sinks]])")
    sinks: list[SinkSpec] = []
    for index, entry in enumerate(entries):
        where = f"sinks[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} is not a table")
        try:
            operations = entry.get("operations")
            if not isinstance(operations, list) or not operations:
                raise ConfigError("lists no [[sinks.operations]]")
            kind = _string(entry, "type", default=HTTP)
            if kind not in KINDS:
                raise ConfigError(f"'type' is one of {', '.join(KINDS)}")
            sinks.append(
                SinkSpec(
                    _string(entry, "name"),
                    operations=tuple(
                        _operation(op, base, f"operations[{i}]")
                        if kind == HTTP
                        else _typed_operation(op, kind, f"operations[{i}]")
                        for i, op in enumerate(operations)
                    ),
                    cost_per_call=_decimal(entry, "cost_per_call"),
                    idempotency=_string(entry, "idempotency", default=""),
                    max_payload_bytes=_integer(entry, "max_payload_bytes", 16_384),
                    not_after=timedelta(seconds=_integer(entry, "not_after_seconds", 900)),
                    max_attempts=_integer(entry, "max_attempts", 10),
                    backoff_base=timedelta(seconds=_seconds(entry, "backoff_base_seconds", 1)),
                    backoff_cap=timedelta(seconds=_seconds(entry, "backoff_cap_seconds", 600)),
                    unknown_outcome=_string(entry, "unknown_outcome", default=""),
                    kind=kind,
                )
            )
        except ConfigError as exc:
            raise ConfigError(f"{where}: {exc}") from exc
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from exc
    try:
        SinkRegistry(sinks)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    return tuple(sinks)


def _operation(raw: object, base: Path, where: str) -> OperationSpec:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} is not a table")
    schema: Mapping[str, Any] | None = None
    reference = raw.get("schema")
    if reference is not None:
        if not isinstance(reference, str):
            raise ConfigError(f"{where}: 'schema' must be a path to a JSON Schema file")
        target = base / reference
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"{where}: cannot read schema {target}: {exc}") from exc
        except ValueError as exc:
            raise ConfigError(f"{where}: schema {target} is not valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"{where}: schema {target} is not a JSON object")
        schema = loaded
    try:
        return OperationSpec(
            _string(raw, "name"),
            compensation=_string(raw, "compensation", default=NONE_POSSIBLE),
            schema=schema,
        )
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


def _typed_operation(raw: object, kind: str, where: str) -> OperationSpec:
    """One of a typed sink's own operations, by name: its schema and its
    compensation are the kind's."""
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} is not a table")
    extra = sorted(set(raw) - {"name"})
    if extra:
        raise ConfigError(
            f"{where}: a {kind} sink's operations bring their own schema and compensation; "
            f"give only 'name', not {', '.join(extra)}"
        )
    name = _string(raw, "name")
    catalog = typed_sink(kind).CATALOG
    if name not in catalog:
        raise ConfigError(
            f"{where}: {kind} has no operation {name!r}; it has {', '.join(sorted(catalog))}"
        )
    spec: OperationSpec = catalog[name]
    return spec


def _decimal(raw: Mapping[str, Any], key: str) -> Decimal:
    value = raw.get(key, "0")
    # A TOML float is binary: 0.1 is not one tenth. Money is a string.
    if not isinstance(value, str | int) or isinstance(value, bool):
        raise ConfigError(f'{key!r} must be a decimal string, such as "0.002"')
    try:
        return Decimal(str(value))
    except InvalidOperation as exc:
        raise ConfigError(f"{key!r} is not a decimal: {value!r}") from exc


def _seconds(raw: Mapping[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{key!r} must be a positive number of seconds")
    return float(value)


def _integer(raw: Mapping[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{key!r} must be an integer")
    return value


def _string(raw: Mapping[str, Any], key: str, *, default: str | None = None) -> str:
    value = raw.get(key, default)
    if value is None:
        raise ConfigError(f"missing {key!r}")
    if not isinstance(value, str):
        raise ConfigError(f"{key!r} must be a string")
    return value


def _strings(raw: Mapping[str, Any], key: str, *, required: bool = True) -> list[str]:
    value = raw.get(key)
    if value is None:
        if required:
            raise ConfigError(f"missing {key!r}")
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key!r} must be a list of strings")
    return list(value)
