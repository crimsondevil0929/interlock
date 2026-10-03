"""The configuration file the ``interlock`` command reads.

TOML, so the standard library reads it::

    substrate = "postgres"            # or "sqlite"
    database = "postgresql://interlock_agent@db/app"   # or a SQLite path
    schema = "public"                 # PostgreSQL only
    stage_roles = ["interlock_agent"] # PostgreSQL install only
    audit_roles = ["interlock_audit"] # PostgreSQL install only
    relay_roles = ["interlock_relay"] # PostgreSQL install only
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

Operators sign every action on the outbox (``docs/EPIC3_DESIGN.md`` §6)::

    [operators]
    log = "operators.ilok1"           # the signed operator log, beside this file
    ledger = "governor.db"            # optional: anchor every record in AgentGov
    scope = "interlock-operators"     # the ledger scope the anchors go to

    [operators.keys]                  # public halves only: `interlock operator keygen`
    alice = "ed25519:5f0c..."

``database`` may be left out and given on the command line or in
``INTERLOCK_DATABASE`` instead, which keeps a password out of the file; the
relay's in ``INTERLOCK_RELAY_DATABASE``. A sink has no endpoint or credential
in ``[[sinks]]``: those belong to the relay, and its credentials only to its
environment: ``header_env`` names the variable holding each header's value.
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

__all__ = [
    "DATABASE_ENV",
    "RELAY_DATABASE_ENV",
    "Endpoint",
    "InterlockConfig",
    "OperatorsConfig",
    "RelayConfig",
    "load_config",
]

DATABASE_ENV = "INTERLOCK_DATABASE"
RELAY_DATABASE_ENV = "INTERLOCK_RELAY_DATABASE"


class ConfigError(ValueError):
    """The configuration file is missing, unreadable or malformed."""


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
    relay: RelayConfig | None = None
    operators: OperatorsConfig | None = None

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
    if relay_roles and substrate != "postgres":
        raise ConfigError(
            "relay_roles are PostgreSQL roles; a SQLite relay is bounded by the file's "
            "permissions instead"
        )
    relay = _relay(raw.get("relay"), sinks)
    operators = _operators(raw.get("operators"), Path(path).parent)
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
        relay=relay,
        operators=operators,
    )


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
    if config.ledger is not None and not config.ledger.startswith(("postgres://", "postgresql://")):
        config = replace(config, ledger=str(base / config.ledger))
    return config


def _relay(raw: object, sinks: tuple[SinkSpec, ...]) -> RelayConfig | None:
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
