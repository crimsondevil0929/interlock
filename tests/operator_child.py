"""An operator command in a process of its own, for ``tests/test_operator_crash.py``.

``python -m tests.operator_child scenario.json`` opens the operator log with
the operator's key file, as ``interlock outbox`` does, and runs one action
against the outbox (PostgreSQL as the installer, or the SQLite file). At the
scenario's point it SIGKILLs itself:

============  ===============================================================
``intent``    the intent is signed and on disk; the database is untouched
``acted``     the database action committed; no outcome recorded
``recorded``  the outcome record is on disk
============  ===============================================================

A SIGKILL runs nothing after it: the log's file claim is released by the
kernel, a PostgreSQL session ends, and nothing is flushed or closed.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import uuid
from pathlib import Path
from typing import Any, NoReturn

from interlock.deliveries import operations
from interlock.operators import Operator, OperatorLog, load_key
from interlock.records import Keyring


def run(scenario: dict[str, Any]) -> NoReturn:
    if scenario["store"] == "sqlite":
        from interlock.sqlite_outbox import OPERATOR, SqliteOutboxStore

        source: Any = SqliteOutboxStore(scenario["dsn"], writes=OPERATOR)
    else:
        import psycopg

        source = psycopg.connect(scenario["dsn"], autocommit=True)

    def checkpoint(point: str) -> None:
        if point == scenario["kill_at"]:
            print(json.dumps({"event": "killed", "at": point}), flush=True)
            os.kill(os.getpid(), signal.SIGKILL)

    log = OperatorLog(
        scenario["log"], load_key(scenario["key"]), Keyring(scenario["keys"]), scope="operators"
    )
    operator = Operator(log, operations(source), checkpoint=checkpoint)
    print(json.dumps({"event": "started"}), flush=True)
    operator.release([uuid.UUID(scenario["message"])], reason="in a process of its own")
    print(json.dumps({"event": "finished"}), flush=True)
    sys.exit(0)


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
