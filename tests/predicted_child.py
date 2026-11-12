"""A process that commits one REST plan and stops between its writes and the read-back, for
the parent to kill there (1.5.2).

``python -m tests.predicted_child scenario.json``. The scenario names the API, the directory
that holds the chain and the undo journal, and the change to ticket ``tkt-1``. The child
prints one line when every write has landed and the read-back has not started, then sleeps:
it is never asked to stop, only killed (``tests/children.py``).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from tests.test_rest import TOKEN, TYPES, _Rest, engine, patch, plan


def main() -> None:
    scenario = json.loads(Path(sys.argv[1]).read_text())
    directory = Path(scenario["directory"])
    sub = _Rest(scenario["server"], resources=TYPES, journal=directory / "journal", token=TOKEN)

    def stop_here(stage: Any) -> list[str]:
        print(json.dumps({"event": "written", "stage_id": str(stage.handle.stage_id)}), flush=True)
        time.sleep(600)
        raise AssertionError("the parent never killed this process")

    sub._discrepancies = stop_here  # type: ignore[method-assign]
    engine(sub, directory).execute(plan(patch("tkt-1", scenario["change"])))


if __name__ == "__main__":
    main()
