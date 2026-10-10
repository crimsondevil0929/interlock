"""The soak (``docs/EPIC6_DESIGN.md`` §3, ``docs/EPIC9_DESIGN.md`` §5), scaled
down to a minute and a half of load: ``scripts/live_stress_test.py`` runs a
cluster of three daemons, each ``interlock daemon --node`` in a process of its
own, against the test PostgreSQL; rotates the relays' key across them
(``docs/EPIC8_DESIGN.md`` §5); kills the node leading the vacuum, and later
freezes the one leading it then, which the others fence; and every claim it
proves must hold. Run for minutes, it is the same script (``uv run python
scripts/live_stress_test.py --docker``)."""

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


def test_a_cluster_under_load_and_chaos_holds_every_claim(
    pg_admin_dsn: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    soak = _soak(monkeypatch)
    # The soak hands its nodes their secrets through the environment.
    monkeypatch.setenv(soak.API_KEY_ENV, "")
    monkeypatch.setenv(soak.WEBHOOK_SECRET_ENV, "")
    monkeypatch.setenv(soak.KMS_TOKEN_ENV, "")
    workdir = tmp_path / "soak"
    code = soak.main(
        [
            "--dsn",
            pg_admin_dsn,
            "--minutes",
            "1.5",
            "--nodes",
            "3",
            "--agents",
            "2",
            # Enough plans in flight on enough engines that some lose a race
            # for a hot row: the claims want one retried.
            "--concurrency",
            "2",
            "--workers",
            "3",
            "--relays",
            "2",
            "--tenants",
            "2",
            "--retain",
            "4",
            "--vacuum-every",
            "2",
            "--heartbeat",
            "0.5",
            "--session-timeout",
            "3",
            "--max-stage",
            "5",
            "--restart-after",
            "5",
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
        "nodes share the work",
        "one leader at a time",
        "a node killed is survived",
        "a node frozen is survived",
    }
