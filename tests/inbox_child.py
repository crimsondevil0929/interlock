"""The inbox, and an engine consuming its facts, in a process of its own, for
``tests/test_inbox_crash.py``.

``python -m tests.inbox_child scenario.json`` runs one of two things and, at
the scenario's point (its ``occurrence``-th time there), prints one line and
SIGKILLs itself.

``receive``: an inbox, as its own role, takes one webhook:

======================  =====================================================
``verified``            the vendor's signature verified; nothing recorded
``record-uncommitted``  an event appended inside its transaction, uncommitted
``recorded``            the event committed; not yet bound
``match-uncommitted``   its fact written inside its transaction, uncommitted
``matched``             the fact committed
======================  =====================================================

``consume``: an engine executes one plan consuming a fact and marking order
500 refunded:

=============  ================================================================
``consumed``   the stage consumed the fact, uncommitted; no effect applied yet
``applied``    the effect applied too; nothing committed
``committed``  the stage committed
=============  ================================================================

A SIGKILL runs nothing after it: no ``finally``, no flush, no close.
PostgreSQL ends the session and rolls back what it had open; SQLite's journal
is never committed.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import uuid
from pathlib import Path
from typing import Any, NoReturn

from interlock import BlastRadius, EscrowEngine, PlanBuilder
from interlock.inbox import Inbox
from tests.conftest import OBSERVED
from tests.inbox_env import INBOX_KEYS, SECRETS, SOURCES, inbox_signer
from tests.outbox_env import RELAYS
from tests.schemas import specs


def say(event: str, **context: object) -> None:
    sys.stdout.write(json.dumps({"event": event, **context}) + "\n")
    sys.stdout.flush()


class Killer:
    """Kills the process the ``occurrence``-th time it reaches ``kill_at``."""

    def __init__(self, kill_at: str, occurrence: int) -> None:
        self.kill_at = kill_at
        self.left = occurrence

    def __call__(self, point: str, *_: object) -> None:
        say("reached", at=point)
        if point == self.kill_at:
            self.left -= 1
            if self.left == 0:
                say("killed", at=point)
                os.kill(os.getpid(), signal.SIGKILL)


def receive(scenario: dict[str, Any], kill: Killer) -> NoReturn:
    if scenario["store"] == "sqlite":
        from interlock.sqlite_outbox import INBOX, SqliteOutboxStore

        store: Any = SqliteOutboxStore(scenario["dsn"], writes=INBOX)
    else:
        import psycopg

        from interlock.inbox_store import PostgresInboxStore

        store = PostgresInboxStore(psycopg.connect(scenario["dsn"], autocommit=True))
    store.checkpoint = kill
    inbox = Inbox(
        store,
        SOURCES,
        signer=inbox_signer(),
        relays=RELAYS,
        secrets=SECRETS.get,
        checkpoint=kill,
    )
    say("started", pid=os.getpid())
    answer = inbox.receive(scenario["source"], scenario["headers"], bytes.fromhex(scenario["body"]))
    say("finished", status=answer.status, body=dict(answer.body))
    sys.exit(0)


class Stopping:
    """A substrate that stops the process where the scenario says."""

    def __init__(self, inner: Any, kill: Killer) -> None:
        self._inner = inner
        self._kill = kill

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def consume_facts(self, handle: Any, fact_ids: Any, scope_id: str) -> None:
        self._inner.consume_facts(handle, fact_ids, scope_id)
        self._kill("consumed")

    def apply(self, handle: Any, effect: Any) -> Any:
        outcome = self._inner.apply(handle, effect)
        self._kill("applied")
        return outcome

    def commit(self, handle: Any) -> Any:
        receipt = self._inner.commit(handle)
        self._kill("committed")
        return receipt


def consume(scenario: dict[str, Any], kill: Killer) -> NoReturn:
    if scenario["store"] == "sqlite":
        from interlock import SqliteSubstrate

        inner: Any = SqliteSubstrate(scenario["dsn"], tables=specs(*OBSERVED))
        status = ":status"
    else:
        from interlock import PostgresSubstrate

        inner = PostgresSubstrate(scenario["dsn"], tables=specs(*OBSERVED))
        status = "%(status)s"
    engine = EscrowEngine(Stopping(inner, kill), checkers=[BlastRadius(10)], inbox=INBOX_KEYS)
    plan = (
        PlanBuilder("agent")
        .consume(uuid.UUID(scenario["fact"]))
        .update(
            table="orders",
            statement=f"UPDATE orders SET status = {status} WHERE id = 500",
            parameters={"status": "refunded"},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )
    say("started", pid=os.getpid())
    result = engine.execute(plan)
    say("finished", committed=result.committed)
    sys.exit(0)


if __name__ == "__main__":
    loaded = json.loads(Path(sys.argv[1]).read_text())
    killer = Killer(loaded["kill_at"], int(loaded.get("occurrence", 1)))
    if loaded["mode"] == "receive":
        receive(loaded, killer)
    consume(loaded, killer)
