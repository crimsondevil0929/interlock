"""How each part ``interlock.toml`` configures is built (``docs/EPIC6_DESIGN.md``).

One place for what a runtime, the daemon and the command line all build from a
configuration: the substrate an engine stages on, the governor plans are
charged to, the anchor that joins them, and the receipt issuer. Each function
builds one fresh part and hands its ownership to the caller, which closes it.
"""

from __future__ import annotations

import logging
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
    from interlock.keys import KeyRegistry
    from interlock.records import Keyring
    from interlock.telemetry import Metrics

__all__ = [
    "ALONE",
    "INBOX_KEY_ENV",
    "RELAY_KEY_ENV",
    "RefusedError",
    "bounded_session",
    "compactor",
    "inbox_signer",
    "inbox_store",
    "key_registry",
    "live_keyring",
    "open_anchor",
    "open_governor",
    "open_ledger",
    "open_receipts",
    "open_signer",
    "open_substrate",
    "operator_signer",
    "relay_adapter",
    "relay_adapters",
    "relay_signer",
    "trusted_keyring",
]


logger = logging.getLogger("interlock.wiring")


def open_substrate(
    config: InterlockConfig,
    *,
    database: str | None = None,
    metrics: Metrics | None = None,
    application_name: str = "interlock",
) -> ShadowSubstrate:
    """The substrate the file names, connected as the stage role: ``database``,
    else ``[engine] database``, else the file's ``database``; on PostgreSQL,
    measuring its waits into ``metrics``, its connections called
    ``application_name``."""
    dsn = database or config.engine.database or config.database
    if config.substrate == "postgres":
        return PostgresSubstrate(
            dsn,
            tables=config.tables,
            schema=config.schema,
            max_stage_seconds=config.engine.max_stage_seconds,
            lock_timeout_seconds=config.engine.lock_timeout_seconds,
            pool_timeout_seconds=config.engine.pool_timeout_seconds,
            acknowledge_cascades=config.acknowledge_cascades,
            metrics=metrics,
            application_name=application_name,
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

    settings = config.receipts
    if settings is None:
        return None
    signer = open_signer(config, settings.signer, settings.key)
    log = ReceiptLog(settings.log_id, signer, path=settings.log)
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


def key_registry(config: InterlockConfig) -> KeyRegistry:
    """What the configuration's keyrings and the operator log say about keys
    (``docs/EPIC8_DESIGN.md`` §2.1). The log is evidence up to its first
    record that does not hold under ``[operators.keys]``
    (:meth:`~interlock.keys.KeyRegistry.build` verifies as it reads): a log
    that does not verify is the verifiers' to report, and never adds a key."""
    from interlock.exceptions import RecordIntegrityError
    from interlock.keys import KeyRegistry
    from interlock.records import read_records

    operators = config.operators
    records: tuple[Any, ...] = ()
    if operators is not None and operators.log.exists():
        try:
            records = read_records(operators.log)
        except RecordIntegrityError as exc:  # unreadable: the configured keys alone
            logger.warning(
                "operator log %s: %s; trusting the configured keys only", operators.log, exc
            )
    return KeyRegistry.build(config.key_roots(), records)


def trusted_keyring(config: InterlockConfig, role: str) -> Keyring | None:
    """A role's keys as verification and the running parts take them: the
    configured ones, and those operators registered since
    (``docs/EPIC8_DESIGN.md`` §2.1); ``None`` when the role has neither."""
    configured = {
        "relay": config.relays,
        "inbox": config.inbox.keys,
        "operator": None if config.operators is None else config.operators.keys,
    }[role]
    registry = key_registry(config)
    if configured is None and not registry.keys(role):
        return None
    return registry.keyring(role)


def live_keyring(config: InterlockConfig, role: str) -> Keyring | None:
    """A role's keys, for a part that runs (``docs/EPIC8_DESIGN.md`` §3): the
    :func:`trusted_keyring`, and a key id it does not hold looked up among the
    keys the operator log registers when it is asked for, so a key registered
    while the part runs is trusted at its first use. The log is read again
    only when it changed since it was last read."""
    keyring = trusted_keyring(config, role)
    if keyring is None:
        return None
    return keyring.resolving(_Registered(config, role))


class _Registered:
    """The keys the operator log registers for a role, read again when the
    log's size or modification time changed."""

    __slots__ = ("_config", "_keys", "_lock", "_role", "_seen")

    def __init__(self, config: InterlockConfig, role: str) -> None:
        import threading

        self._config = config
        self._role = role
        self._lock = threading.Lock()
        self._seen: tuple[int, int] | None = None
        self._keys: dict[str, tuple[str, str]] = {}

    def __call__(self, key_id: str) -> tuple[str, str] | None:
        from agentgov.receipts.signing import parse_key

        operators = self._config.operators
        if operators is None:
            return None
        try:
            stat = operators.log.stat()
        except OSError:
            return None
        mark = (stat.st_size, stat.st_mtime_ns)
        with self._lock:
            if mark != self._seen:
                keys = key_registry(self._config).keys(self._role)
                self._keys = {parse_key(spec).key_id: (name, spec) for name, spec in keys.items()}
                self._seen = mark
            return self._keys.get(key_id)


def _held(config: InterlockConfig, role: str, signer: Any, *, part: str, register: str) -> None:
    """Refuse a key ``role`` does not trust as the operator log stands
    (``docs/EPIC8_DESIGN.md`` §2): one never registered (``register`` says
    where to), or one an operator revoked."""
    registry = key_registry(config)
    if signer.key_id not in registry.keyring(role):
        raise RefusedError(register)
    revoked = registry.revocation(signer.key_id)
    # A relay's or an inbox's key is revoked when its revocation applied; an
    # operator's, by the intent that revokes it (§2.5).
    if revoked is not None and (role == "operator" or revoked.applied is not None):
        raise RefusedError(
            f"the {part}'s key {signer.key_id} was revoked by operator record "
            f"{revoked.intent.seq}: it signs nothing more. Give the {part} its new key"
        )


def open_signer(config: InterlockConfig, signer: str | None, key: str | Path | None) -> Any:
    """What a part signs with: the key the ``[signers.<name>]`` that
    ``signer`` names holds, its version pinned now (``docs/EPIC8_DESIGN.md``
    §1), or the key file at ``key``.

    :raises OSError: If the file cannot be read.
    :raises ValueError: If neither is given, or the file holds no key.
    :raises SignerUnavailableError: If the signing service cannot be used.
    """
    if signer is not None:
        return config.signers[signer].open()
    if not key:
        raise ValueError("no key file and no signer")
    from interlock.operators import load_key

    return load_key(key)


def relay_signer(config: InterlockConfig, path: str | Path | None) -> Any:
    """The relay's key: the file at ``path`` (``--key``, ``INTERLOCK_RELAY_KEY``
    or ``[relay] key``), else ``[relay] signer``'s; registered in
    ``[relays.keys]``; or why the relay may not start. An attestation no
    registered key verifies proves nothing, so a relay does not make one."""
    from agentgov.exceptions import SignerUnavailableError

    remote = None if path or config.relay is None else config.relay.signer
    if not path and remote is None:
        raise RefusedError(
            f"a relay signs every outcome it records: give it its key with [relay] key or "
            f"signer, --key PATH or {RELAY_KEY_ENV} (a new one: interlock keygen --role relay)"
        )
    try:
        signer = open_signer(config, remote, path)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise RefusedError(f"cannot open the relay key: {exc}") from exc
    _held(
        config,
        "relay",
        signer,
        part="relay",
        register=f"the relay's key {signer.key_id} is not registered, so nothing it signs would "
        f"verify: register it in [relays.keys] under the relay's name, as "
        f'"{signer.public_key().spec()}"',
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
    """The inbox's key: the file at ``path`` (``--key``,
    ``INTERLOCK_INBOX_KEY`` or ``[inbox] key``), else ``[inbox] signer``'s;
    registered in ``[inbox.keys]``; or why the inbox may not start. A fact no
    registered key verifies is consumed by no engine, so the inbox does not
    make one."""
    from agentgov.exceptions import SignerUnavailableError

    remote = None if path else config.inbox.signer
    if not path and remote is None:
        raise RefusedError(
            f"an inbox attests every event and fact: give it its key with [inbox] key or "
            f"signer, --key PATH or {INBOX_KEY_ENV} (a new one: interlock keygen --role inbox)"
        )
    try:
        signer = open_signer(config, remote, path)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise RefusedError(f"cannot open the inbox key: {exc}") from exc
    _held(
        config,
        "inbox",
        signer,
        part="inbox",
        register=f"the inbox's key {signer.key_id} is not registered, so nothing it attests "
        f"would verify: register it in [inbox.keys] under the inbox's name, as "
        f'"{signer.public_key().spec()}"',
    )
    return signer


def operator_signer(
    config: InterlockConfig, signer: str | None, key: str | Path | None, *, part: str
) -> Any:
    """An operator key a part signs operator records with (the vacuum's): the
    ``[signers.<name>]`` that ``signer`` names, or the file at ``key``; one
    ``[operators.keys]`` holds or an operator registered, and none revoked; or
    why the part may not run."""
    from agentgov.exceptions import SignerUnavailableError

    try:
        opened = open_signer(config, signer, key)
    except (OSError, ValueError, SignerUnavailableError) as exc:
        raise RefusedError(f"cannot open the {part}'s key: {exc}") from exc
    _held(
        config,
        "operator",
        opened,
        part=part,
        register=f"the {part}'s key {opened.key_id} is no registered operator's: register it "
        f'in [operators.keys], as "{opened.public_key().spec()}"',
    )
    return opened


ALONE: float = 60.0
"""Seconds a session of a part outside a cluster may sit inside a
transaction, holding what its writes lock, before the server ends it: what
the relays have always had (``docs/EPIC9_DESIGN.md`` §3.3)."""


def bounded_session(dsn: str, *, application_name: str, idle_timeout: float) -> Any:
    """A connection of a part's own, autocommit, called ``application_name``,
    whose transactions the server ends once they sit idle ``idle_timeout``
    seconds: a part that freezes inside one holds its locks no longer
    (``docs/EPIC9_DESIGN.md`` §3.3).

    :raises SubstrateUnavailableError: If it cannot be had.
    """
    import psycopg

    try:
        conn = psycopg.connect(dsn, autocommit=True, application_name=application_name)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    try:
        conn.execute(
            f"SET idle_in_transaction_session_timeout = {max(1, int(idle_timeout * 1000))}"
        )
    except psycopg.Error as exc:
        conn.close()
        raise SubstrateUnavailableError(f"cannot set up the connection: {exc}") from exc
    return conn


def inbox_store(
    config: InterlockConfig,
    database: str | None,
    *,
    application_name: str = "interlock-inbox",
    idle_timeout: float = ALONE,
) -> tuple[Any, Callable[[], None]]:
    """Where the inbox records, as its own role, and how to close it. On
    PostgreSQL its transactions are bounded by ``idle_timeout``: each holds its
    source's log while it records, and another inbox waits for it."""
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
    from interlock.inbox_store import PostgresInboxStore

    conn = bounded_session(dsn, application_name=application_name, idle_timeout=idle_timeout)
    return PostgresInboxStore(conn), conn.close


def open_ledger(ledger: str, *, read_only: bool = False) -> Any:
    """A governor of the AgentGov ledger ``ledger`` names: a PostgreSQL
    connection string, or a SQLite file."""
    from agentgov import BudgetManager

    if is_dsn(ledger):
        return BudgetManager.open_postgres(ledger, read_only=read_only)
    return BudgetManager.open_sqlite(ledger, read_only=read_only)


def compactor(
    config: InterlockConfig,
    database: str | None = None,
    *,
    application_name: str = "interlock-vacuum",
) -> tuple[Any, Callable[[], None]]:
    """The outbox as a vacuum acts on it, as the installer (``database``, else
    the file's), and how to close it. Its transactions are not bounded: a
    survey verifies inside its snapshot, which holds no lock a writer waits
    for, for as long as the history takes, and the act is one statement."""
    dsn = database or config.database
    if config.substrate != "postgres":
        from interlock.sqlite_outbox import COMPACTOR, SqliteOutboxStore

        store = SqliteOutboxStore(dsn, writes=COMPACTOR)
        return store, store.close
    import psycopg

    from interlock.deliveries import operations

    try:
        conn = psycopg.connect(dsn, autocommit=True, application_name=application_name)
    except psycopg.Error as exc:
        raise SubstrateUnavailableError(f"cannot connect to PostgreSQL: {exc}") from exc
    return operations(conn), conn.close
