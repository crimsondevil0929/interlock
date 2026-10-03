"""A child process the crash tests kill, and the lines it prints.

The child runs ``python -m <module> scenario.json`` and prints one JSON object
per line to stdout: where it is, and what it knew there. The parent reads
them, decides when to SIGKILL, and never asks the child to stop.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Event:
    """One line the child printed: where it is, and what it knew there."""

    raw: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.raw["event"])

    @property
    def at(self) -> str:
        return str(self.raw.get("at", ""))

    @property
    def stage_id(self) -> uuid.UUID:
        return uuid.UUID(str(self.raw["stage_id"]))

    @property
    def txid(self) -> str:
        return str(self.raw["txid"])

    @property
    def backend_pid(self) -> int:
        return int(self.raw["backend_pid"])


class Child:
    """A child process running a scenario. Never asked to stop: killed."""

    def __init__(
        self,
        scenario: dict[str, Any],
        workdir: Path,
        number: int,
        *,
        module: str = "tests.crash_child",
    ) -> None:
        path = workdir / f"scenario-{number}.json"
        path.write_text(json.dumps(scenario))
        self.stderr_path = workdir / f"child-{number}.stderr"
        with self.stderr_path.open("wb") as stderr:
            self.process = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", module, str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=stderr,
            )
        assert self.process.stdout is not None
        self._fd = self.process.stdout.fileno()
        self._buffer = b""

    @property
    def pid(self) -> int:
        return self.process.pid

    def next_event(self, timeout: float = 60.0) -> Event:
        """The child's next line. Fails with its stderr if it died first."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"child printed nothing for {timeout}s\n{self.stderr()}")
            ready, _, _ = select.select([self._fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(self._fd, 65536)
            if not chunk:
                code = self.process.wait()
                raise AssertionError(f"child exited {code} before its kill point\n{self.stderr()}")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return Event(json.loads(line))

    def wait_for(self, name: str, timeout: float = 60.0) -> Event:
        while True:
            event = self.next_event(timeout)
            if event.name == name:
                return event

    def kill(self) -> None:
        """SIGKILL: the process ends where it is, with nothing run after."""
        os.kill(self.process.pid, signal.SIGKILL)
        code = self.process.wait(timeout=30)
        assert code == -signal.SIGKILL, f"child ended {code}, not by SIGKILL\n{self.stderr()}"
        if self.process.stdout is not None:
            self.process.stdout.close()

    def stderr(self) -> str:
        return self.stderr_path.read_text(errors="replace")[-4000:]
