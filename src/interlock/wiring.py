"""How each part ``interlock.toml`` configures is built (``docs/EPIC6_DESIGN.md``).

One place for what a runtime, the daemon and the command line all build from a
configuration: the substrate an engine stages on, the governor plans are
charged to, the anchor that joins them, and the receipt issuer. Each function
builds one fresh part and hands its ownership to the caller, which closes it.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from interlock.anchor import LedgerAnchor
from interlock.config import INBOX_DATABASE_ENV, is_dsn
from interlock.exceptions import SubstrateConfigurationError, SubstrateUnavailableError
from interlock.postgres import PostgresSubstrate
from interlock.receipts import ReceiptIssuer
from interlock.substrate import ShadowSubstrate, SqliteSubstrate

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.config import Endpoint, InterlockConfig, RelayConfig

__all__ = [
    "INBOX_KEY_ENV",
    "RELAY_KEY_ENV",
    "RefusedError",
    "compactor",
    "inbox_signer",
    "inbox_store",
    "open_anchor",
    "open_governor",
    "open_ledger",
    "open_receipts",
    "open_substrate",
    "relay_adapter",
    "relay_adapters",
    "relay_signer",
]


def open_substrate(config: InterlockConfig, *, database: str | None = None) -> ShadowSubstrate:
    """The substrate the file names, connected as the stage role: ``database``,
    else ``[engine] database``, else the file's ``database``."""
    dsn = database or config.engine.database or config.database
    if config.substrate == "postgres":
        return PostgresSubstrate(
            dsn,
            tables=config.tables,
            schema=config.schema,
            max_stage_seconds=config.engine.max_stage_seconds,
            lock_timeout_seconds=config.engine.lock_timeout_seconds,
            acknowledge_cascades=config.acknowledge_cascades,
        )
    return SqliteSubstrate(
        dsn,
        tables=config.tables,
        max_stage_seconds=config.engine.max_stage_seconds,
        acknowledge_cascades=config.acknowledge_cascades,
    )


def open_governor(config: InterlockConfig) -> BudgetManager | None:
    """A governor of the ledger ``[engine] ledger`` names, write-capable, or
    ``None`` when no ledger is configured. On PostgreSQL every caller gets a
    governor of its own: any number may share the ledger."""
    from agentgov import BudgetManager

    ledger = config.engine.ledger
    if ledger is None:
        return None
    if is_dsn(ledger):
        return BudgetManager.open_postgres(ledger, schema=config.engine.ledger_schema)
    return BudgetManager.open_sqlite(ledger)


def open_anchor(config: InterlockConfig, governor: BudgetManager | None) -> LedgerAnchor | None:
    """The anchor an engine charges its plans through: governed by
    ``governor``, settling with the commit when ``[engine] same_transaction``."""
    if governor is None:
        return None
    return LedgerAnchor(governed=governor, same_transaction=config.engine.same_transaction)


def open_receipts(config: InterlockConfig) -> ReceiptIssuer | None:
    """The receipt issuer over ``[receipts]``'s log, or ``None``. The log is
    claimed by this process until :meth:`ReceiptLog.close`."""
    from agentgov.receipts import ReceiptLog

    from interlock.operators import load_key

    settings = config.receipts
    if settings is None:
        return None
    log = ReceiptLog(settings.log_id, load_key(settings.key), path=settings.log)
    return ReceiptIssuer(log, issuer=settings.issuer, policy_epoch=settings.policy_epoch)


# --------------------------------------------------------------------------
# the relay, the inbox, the vacuum: as the command line and the daemon build them
# --------------------------------------------------------------------------


RELAY_KEY_ENV = "INTERLOCK_RELAY_KEY"
"""The path to a relay's key file, when ``--key`` is not given; it overrides
``[relay] key``."""

INBOX_KEY_ENV = "INTERLOCK_INBOX_KEY"
"""The path to the inbox's key file, when ``--key`` is not given; it
overrides ``[inbox] key``."""


class RefusedError(Exception):
    """A part refused to start before it began: its key missing, unreadable,
    or registered nowhere. Usage, not the database."""


def relay_signer(config: InterlockConfig, path: str | Path | None) -> Any:
    """The relay's key, registered in ``[relays.keys]``; or why the relay
    may not start. An attestation no registered key verifies proves nothing,
    so a relay does not make one."""
    from agentgov.exceptions import SignerUnavailableError

    from interlock.operators import load_key

    if not path:
        raise RefusedError(
            f"a relay signs every outcome it records: give it its key with [relay] key, "
            f"--key PATH or {RELAY_KEY_ENV} (a new one: interlock keygen --role relay)"
        )
    try:
        signer = load_key(path)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise RefusedError(f"cannot read the relay key: {exc}") from exc
    keyring = config.relay_keyring()
    if keyring is None or signer.key_id not in keyring:
        raise RefusedError(
            f"the relay's key {signer.key_id} is not registered, so nothing it signs would "
            f"verify: register it in [relays.keys] under the relay's name, as "
            f'"{signer.public_key().spec()}"'
        )
    return signer


def relay_adapters(settings: RelayConfig) -> dict[str, Any]:
    missing = sorted(
        [
            f"{variable} (sink {endpoint.sink}, header {header})"
            for endpoint in settings.endpoints
            for header, variable in endpoint.header_env.items()
            if variable not in os.environ
        ]
        + [
            f"{endpoint.secret_env} (sink {endpoint.sink}, its API key)"
            for endpoint in settings.endpoints
            if endpoint.secret_env and endpoint.secret_env not in os.environ
        ]
    )
    if missing:
        raise SubstrateConfigurationError(
            f"the relay's credentials come from its environment, and these are not set: "
            f"{', '.join(missing)}"
        )
    return {endpoint.sink: relay_adapter(endpoint) for endpoint in settings.endpoints}


def relay_adapter(endpoint: Endpoint) -> Any:
    """The adapter for one endpoint: the generic one, or its vendor's."""
    if endpoint.kind == "stripe":
        from interlock.stripe import API, STRIPE_VERSION, StripeAdapter

        return StripeAdapter(
            _variable(endpoint.secret_env),
            base_url=endpoint.url or API,
            version=endpoint.stripe_version or STRIPE_VERSION,
        )
    if endpoint.kind == "sendgrid":
        from interlock.sendgrid import API as SENDGRID_API
        from interlock.sendgrid import SendGridAdapter

        return SendGridAdapter(
            _variable(endpoint.secret_env),
            base_url=endpoint.url or SENDGRID_API,
            sandbox=endpoint.sandbox,
        )
    from interlock.adapters import HttpAdapter

    return HttpAdapter(
        endpoint.url, routes=endpoint.routes, headers=_environment(endpoint.header_env)
    )


def _variable(name: str) -> Callable[[], str]:
    """A secret read from the environment on every call, so a rotated key
    takes effect without a restart."""

    def value() -> str:
        return os.environ[name]

    return value


def _environment(names: Mapping[str, str]) -> Callable[[], dict[str, str]]:
    """Header values read from the environment on every call, so a rotated
    credential takes effect without a restart."""
    fixed = dict(names)

    def headers() -> dict[str, str]:
        return {header: os.environ[variable] for header, variable in fixed.items()}

    return headers


def inbox_signer(config: InterlockConfig, path: str | Path | None) -> Any:
    """The inbox's key, registered in ``[inbox.keys]``; or why the inbox may
    not start. A fact no registered key verifies is consumed by no engine, so
    the inbox does not make one."""
    from agentgov.exceptions import SignerUnavailableError

    from interlock.operators import load_key

    if not path:
        raise RefusedError(
            f"an inbox attests every event and fact: give it its key with [inbox] key, "
            f"--key PATH or {INBOX_KEY_ENV} (a new one: interlock keygen --role inbox)"
        )
    try:
        signer = load_key(path)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise RefusedError(f"cannot read the inbox key: {exc}") from exc
    keyring = config.inbox_keyring()
    if keyring is None or signer.key_id not in keyring:
        raise RefusedError(
            f"the inbox's key {signer.key_id} is not registered, so nothing it attests would "
            f"verify: register it in [inbox.keys] under the inbox's name, as "
            f'"{signer.public_key().spec()}"'
        )
    return signer


def inbox_store(config: InterlockConfig, database: str | None) -> tuple[Any, Callable[[], None]]:
    """Where the inbox records, as its own role, and how to close it."""
    sqlite = config.substrate != "postgres"
    dsn = (
        database
        or config.inbox.database
        or os.environ.get(INBOX_DATABASE_ENV)
        or (config.database if sqlite else "")
    )
    if not dsn:
        raise SubstrateConfigurationError(
            f"no database for the inbox: set [inbox] database, pass --database, or set "
            f"{INBOX_DATABASE_ENV}"
        )
    if sqlite:
        from interlock.sqlite_outbox import INBOX, SqliteOutboxStore

        store = SqliteOutboxStore(dsn, writes=INBOX)
        return store, store.close
    import psycopg

    from interlock.inbox_store import PostgresInboxStore

    try:
        conn = psycopg.connect(dsn, autocommit=True)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    return PostgresInboxStore(conn), conn.close


def open_ledger(ledger: str, *, read_only: bool = False) -> Any:
    """A governor of the AgentGov ledger ``ledger`` names: a PostgreSQL
    connection string, or a SQLite file."""
    from agentgov import BudgetManager

    if is_dsn(ledger):
        return BudgetManager.open_postgres(ledger, read_only=read_only)
    return BudgetManager.open_sqlite(ledger, read_only=read_only)


def compactor(
    config: InterlockConfig, database: str | None = None
) -> tuple[Any, Callable[[], None]]:
    """The outbox as a vacuum acts on it, as the installer (``database``, else
    the file's), and how to close it."""
    dsn = database or config.database
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import COMPACTOR, SqliteOutboxStore

        store = SqliteOutboxStore(dsn, writes=COMPACTOR)
        return store, store.close
    import psycopg

    from interlock.deliveries import operations

    try:
        conn = psycopg.connect(dsn, autocommit=True)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    return operations(conn), conn.close
