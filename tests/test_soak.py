"""The soak (``docs/EPIC6_DESIGN.md`` §3), scaled down to half a minute of load:
``scripts/live_stress_test.py`` runs the whole daemon against the test
PostgreSQL, its relays, inbox and vacuum signing through a key service, the
relays' key rotated halfway (``docs/EPIC8_DESIGN.md`` §5); and every claim it
proves must hold. Run for minutes, it is the same script
(``uv run python scripts/live_stress_test.py --docker``)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _soak(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The script, imported: registered first, as its dataclasses need."""
    spec = importlib.util.spec_from_file_location(
        "live_stress_test", ROOT / "scripts" / "live_stress_test.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_the_daemon_under_load_holds_every_claim(
    pg_admin_dsn: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    soak = _soak(monkeypatch)
    # The soak hands the daemon its secrets through the environment.
    monkeypatch.setenv(soak.API_KEY_ENV, "")
    monkeypatch.setenv(soak.WEBHOOK_SECRET_ENV, "")
    workdir = tmp_path / "soak"
    code = soak.main(
        [
            "--dsn",
            pg_admin_dsn,
            "--minutes",
            "0.5",
            "--agents",
            "2",
            # Enough plans in flight on enough engines that some lose a race
            # for a hot row in half a minute: the claims want one retried.
            "--concurrency",
            "4",
            "--workers",
            "4",
            "--relays",
            "2",
            "--tenants",
            "2",
            "--retain",
            "4",
            "--vacuum-every",
            "2",
            "--quiet",
            "--dir",
            str(workdir),
        ]
    )
    report = json.loads((workdir / "report.json").read_text())
    failed = [claim for claim in report["claims"] if not claim["held"]]
    assert code == 0 and not failed, json.dumps(failed, indent=2)
    assert {claim["name"] for claim in report["claims"]} == {
        "no deadlocks",
        "lock waits resolve",
        "rate windows hold exactly",
        "the ledger balances",
        "exactly once",
        "no forgery accepted",
        "the vacuum compacts as it goes",
        "everything verifies after",
        "shutdown is graceful",
        "trace context survives",
        "metrics agree",
        "keys rotate",
    }
