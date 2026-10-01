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

    [[sinks.operations]]
    name = "send"
    compensation = "none-possible"    # or the operation that undoes this one
    schema = "schemas/mail-send.json" # relative to this file; omit for any object

``database`` may be left out and given on the command line or in
``INTERLOCK_DATABASE`` instead, which keeps a password out of the file. A
sink has no endpoint or credential here: those belong to the relay.
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

from interlock.outbound import NONE_POSSIBLE, OperationSpec, SinkRegistry, SinkSpec
from interlock.substrate import TableSpec

__all__ = ["DATABASE_ENV", "InterlockConfig", "load_config"]

DATABASE_ENV = "INTERLOCK_DATABASE"


class ConfigError(ValueError):
    """The configuration file is missing, unreadable or malformed."""


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

    def with_database(self, database: str | None) -> InterlockConfig:
        if not database:
            return self
        return replace(self, database=database)

    def sink_registry(self) -> SinkRegistry:
        """The sinks as an engine takes them."""
        return SinkRegistry(self.sinks)


def load_config(path: str | Path, *, database: str | None = None) -> InterlockConfig:
    """Read and validate a configuration file.

    :param database: Overrides the file's ``database``, as does
        ``INTERLOCK_DATABASE`` when this is not given.
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
    if not url:
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
    if sinks and substrate != "postgres":
        raise ConfigError(
            "[[sinks]] need substrate = 'postgres': the outbox is a PostgreSQL table, "
            "written in the stage's transaction"
        )
    return InterlockConfig(
        substrate=substrate,
        database=url,
        tables=tuple(tables),
        schema=_string(raw, "schema", default="public"),
        stage_roles=tuple(_strings(raw, "stage_roles", required=False)),
        audit_roles=tuple(_strings(raw, "audit_roles", required=False)),
        acknowledge_cascades=tuple(_strings(raw, "acknowledge_cascades", required=False)),
        sinks=sinks,
        relay_roles=tuple(_strings(raw, "relay_roles", required=False)),
    )


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
            sinks.append(
                SinkSpec(
                    _string(entry, "name"),
                    operations=tuple(
                        _operation(op, base, f"operations[{i}]") for i, op in enumerate(operations)
                    ),
                    cost_per_call=_decimal(entry, "cost_per_call"),
                    idempotency=_string(entry, "idempotency", default="header"),
                    max_payload_bytes=_integer(entry, "max_payload_bytes", 16_384),
                    not_after=timedelta(seconds=_integer(entry, "not_after_seconds", 900)),
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


def _decimal(raw: Mapping[str, Any], key: str) -> Decimal:
    value = raw.get(key, "0")
    # A TOML float is binary: 0.1 is not one tenth. Money is a string.
    if not isinstance(value, str | int) or isinstance(value, bool):
        raise ConfigError(f'{key!r} must be a decimal string, such as "0.002"')
    try:
        return Decimal(str(value))
    except InvalidOperation as exc:
        raise ConfigError(f"{key!r} is not a decimal: {value!r}") from exc


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
