"""The configuration file the ``interlock`` command reads.

TOML, so the standard library reads it::

    substrate = "postgres"            # or "sqlite"
    database = "postgresql://interlock_agent@db/app"   # or a SQLite path
    schema = "public"                 # PostgreSQL only
    stage_roles = ["interlock_agent"] # PostgreSQL install only
    audit_roles = ["interlock_audit"] # PostgreSQL install only
    acknowledge_cascades = []

    [[tables]]
    name = "orders"
    primary_key = "id"
    columns = ["id", "tenant", "total"]
    tenant_column = "tenant"

``database`` may be left out and given on the command line or in
``INTERLOCK_DATABASE`` instead, which keeps a password out of the file.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    def with_database(self, database: str | None) -> InterlockConfig:
        if not database:
            return self
        return InterlockConfig(
            substrate=self.substrate,
            database=database,
            tables=self.tables,
            schema=self.schema,
            stage_roles=self.stage_roles,
            audit_roles=self.audit_roles,
            acknowledge_cascades=self.acknowledge_cascades,
        )


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
    return InterlockConfig(
        substrate=substrate,
        database=url,
        tables=tuple(tables),
        schema=_string(raw, "schema", default="public"),
        stage_roles=tuple(_strings(raw, "stage_roles", required=False)),
        audit_roles=tuple(_strings(raw, "audit_roles", required=False)),
        acknowledge_cascades=tuple(_strings(raw, "acknowledge_cascades", required=False)),
    )


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
