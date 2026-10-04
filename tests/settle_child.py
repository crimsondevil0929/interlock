"""A settler in a process of its own, for ``tests/test_settlement_crash.py``.

Run as ``python -m tests.settle_child scenario.json``. It opens what the
engine's process holds (the receipt log, the escrow chain, the AgentGov ledger)
and the outbox as the settler sees it, and settles everything delivered. At
the scenario's kill point, a step of one message's settlement (``receipt``,
``credit``, ``settled``) made durable, it prints one line saying so and
SIGKILLs itself: no ``finally``, no flush, no close. With no kill point it
reports what it settled and exits.

The scenario names the outbox (``store``: ``postgres`` with ``dsn`` a settler
role's connection string, or ``sqlite`` with ``dsn`` the file), the files the
engine wrote, and the operators' public keys.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import uuid
from pathlib import Path
from typing import Any, NoReturn

from agentgov import BudgetManager
from agentgov.receipts import ReceiptLog

from interlock.receipts import ReceiptIssuer
from interlock.records import Keyring
from interlock.settlement import Settler
from interlock.sqlite_outbox import SETTLER, SqliteOutboxStore
from tests.outbox_env import RELAYS
from tests.settling import LOG_ID, LOG_KEY, ROW_SECRET


def say(event: str, **context: object) -> None:
    sys.stdout.write(json.dumps({"event": event, **context}) + "\n")
    sys.stdout.flush()


def run(scenario: dict[str, Any]) -> NoReturn:
    if scenario["store"] == "sqlite":
        outbox: Any = SqliteOutboxStore(str(scenario["dsn"]), writes=SETTLER)
    else:
        import psycopg

        outbox = psycopg.connect(str(scenario["dsn"]), autocommit=True)
    log = ReceiptLog(LOG_ID, LOG_KEY, path=str(scenario["receipts"]))
    governor = BudgetManager.open_sqlite(str(scenario["ledger"]))
    kill_at, victim = str(scenario.get("kill_at", "")), str(scenario.get("message", ""))

    def checkpoint(point: str, message: uuid.UUID) -> None:
        say("reached", at=point, message=str(message))
        if point == kill_at and str(message) == victim:
            say("killed", at=point, message=str(message))
            os.kill(os.getpid(), signal.SIGKILL)

    settler = Settler(
        outbox,
        receipts=ReceiptIssuer(log, row_secret=ROW_SECRET),
        chain=Path(str(scenario["chain"])),
        relays=RELAYS,
        ledger=governor,
        operator_log=str(scenario["operator_log"]),
        operators=Keyring(dict(scenario["operators"])),
        checkpoint=checkpoint,
    )
    say("started", pid=os.getpid())
    report = settler.settle()
    say(
        "finished",
        settled=[str(m) for m in report.settled],
        receipts=report.receipts,
        credits=report.credits,
        problems=list(report.problems),
    )
    log.close()
    governor.close()
    outbox.close()
    sys.exit(0)


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
