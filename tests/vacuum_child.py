"""A vacuum in a process of its own, for ``tests/test_vacuum_crash.py``.

``python -m tests.vacuum_child scenario.json`` opens the operator log with the
operator's key file, anchored into the AgentGov ledger, and the outbox as a
vacuum acts on it (PostgreSQL as the installer, or the SQLite file with the
compactor's write set), and runs one vacuum. At the scenario's point it prints
one line and SIGKILLs itself:

================  ==========================================================
``intent``        the intent is signed, on disk and anchored; nothing pruned
``anchored``      its anchor checked; the database untouched
``transaction``   inside the database's transaction, everything done but its
                  commit: the process dies with it open
``acted``         the transaction committed; no outcome recorded
``recorded``      the outcome record is on disk
================  ==========================================================

A SIGKILL runs nothing after it: no ``finally``, no flush, no close. The
kernel releases the log's file claim, PostgreSQL ends the session and rolls
back what it had open, SQLite's journal is never committed.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

from agentgov import BudgetManager

from interlock.operators import OperatorLog, load_key
from interlock.records import Keyring
from interlock.vacuum import Vacuum
from tests.outbox_env import RELAYS


def say(event: str, **context: object) -> None:
    sys.stdout.write(json.dumps({"event": event, **context}) + "\n")
    sys.stdout.flush()


def run(scenario: dict[str, Any]) -> NoReturn:
    if scenario["store"] == "sqlite":
        from interlock.sqlite_outbox import COMPACTOR, SqliteOutboxStore

        outbox: Any = SqliteOutboxStore(scenario["dsn"], writes=COMPACTOR)
    else:
        import psycopg

        from interlock.deliveries import operations

        outbox = operations(psycopg.connect(scenario["dsn"], autocommit=True))
    governor = BudgetManager.open_sqlite(scenario["ledger"])

    def checkpoint(point: str) -> None:
        say("reached", at=point)
        if point == scenario["kill_at"]:
            say("killed", at=point)
            os.kill(os.getpid(), signal.SIGKILL)

    keyring = Keyring(scenario["keys"])
    log = OperatorLog(
        scenario["log"], load_key(scenario["key"]), keyring, ledger=governor, scope="operators"
    )
    vacuum = Vacuum(
        log,
        outbox,
        operators=keyring,
        relays=RELAYS,
        ledger=governor,
        retain=timedelta(0),
        checkpoint=checkpoint,
    )
    say("started", pid=os.getpid())
    report = vacuum.run(reason="in a process of its own")
    say("finished", outcome=report.outcome, messages=report.messages)
    sys.exit(0)


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
