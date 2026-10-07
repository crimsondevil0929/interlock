"""How each part ``interlock.toml`` configures is built (``docs/EPIC6_DESIGN.md``).

One place for what a runtime, the daemon and the command line all build from a
configuration: the substrate an engine stages on, the governor plans are
charged to, the anchor that joins them, and the receipt issuer. Each function
builds one fresh part and hands its ownership to the caller, which closes it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from interlock.anchor import LedgerAnchor
from interlock.postgres import PostgresSubstrate
from interlock.receipts import ReceiptIssuer
from interlock.substrate import ShadowSubstrate, SqliteSubstrate

if TYPE_CHECKING:
    from agentgov import BudgetManager

    from interlock.config import InterlockConfig

__all__ = ["open_anchor", "open_governor", "open_receipts", "open_substrate"]


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

    from interlock.config import is_dsn

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
