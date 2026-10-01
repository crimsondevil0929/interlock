"""A relay in a process of its own, for ``tests/test_relay_crash.py``.

Run as ``python -m tests.relay_child scenario.json``. It delivers through
real HTTP adapters to the parent's fake sinks, reads the breaker from the
parent's AgentGov ledger, and either SIGKILLs itself at a configured point on
the delivery path, or runs until the parent SIGKILLs it.

The points are :meth:`interlock.relay.Relay._reached`'s:

==========================  ==============================================
``claim-uncommitted``       inside the claim's transaction, before COMMIT
``claimed``                 the lease committed; nothing else done
``checked``                 the breaker read, the call not yet recorded
``sending-uncommitted``     inside the transaction recording the call
``sending``                 the call recorded and committed, not made
``called``                  the sink answered; nothing recorded of it
``outcome-uncommitted``     inside the transaction recording the outcome
``recorded``                the outcome committed
==========================  ==============================================

A SIGKILL runs nothing after it: no ``finally``, no ``atexit``, no
connection close. The server finds the session gone and rolls back whatever
transaction it had open, exactly as for a machine that lost power.

Only ``started`` goes to stdout, which the parent reads; everything else to
stderr, which is a file, so a busy relay never blocks on a full pipe.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

from interlock.adapters import HttpAdapter
from interlock.relay import Lease, LedgerBreaker, Relay
from tests.outbox_env import ROUTES


def say(event: str, stream: Any = None, **context: object) -> None:
    out = stream or sys.stderr
    out.write(json.dumps({"event": event, **context}) + "\n")
    out.flush()


@dataclass(frozen=True)
class Kill:
    at: str
    message: str
    """Only on this message's way; any message's when empty."""

    def due(self, point: str, lease: Lease | None) -> bool:
        if point != self.at:
            return False
        # Inside the claim no message is leased yet: the point is the claim's.
        return lease is None or not self.message or str(lease.message_id) == self.message


class Dying(Relay):
    __slots__ = ("_kill",)
    _kill: Kill

    def _reached(self, point: str, lease: Lease | None) -> None:
        say("reached", point=point, message=None if lease is None else str(lease.message_id))
        if self._kill.due(point, lease):
            say("killed", point=point)
            os.kill(os.getpid(), signal.SIGKILL)


def run(scenario: dict[str, Any]) -> NoReturn:
    adapters = {
        name: HttpAdapter(url, routes=ROUTES[name]) for name, url in scenario["sinks"].items()
    }
    relay = Dying(
        scenario["dsn"],
        adapters=adapters,
        breaker=LedgerBreaker.open(scenario["ledger"]),
        relay_id=scenario["relay_id"],
        lease=timedelta(seconds=scenario["lease"]),
        timeout=timedelta(seconds=scenario["timeout"]),
        batch=int(scenario.get("batch", 1)),
    )
    relay._kill = Kill(
        at=str(scenario.get("kill_at", "")), message=str(scenario.get("message", ""))
    )
    say("started", stream=sys.stdout, pid=os.getpid())
    idle, limit = 0, int(scenario.get("idle_rounds", 25))
    while idle < limit:
        report = relay.run_once()
        idle = idle + 1 if report.claimed == 0 else 0
        if report.claimed == 0:
            time.sleep(0.02)
    say("idle", stream=sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()))
