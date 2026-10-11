"""The customer acceptance suite's reference proposals (``demo/customer_acceptance_suite.py``).

In each of the four domains, a plan written out for every policy dimension runs
through the same tool the live model uses, with no model: what the kernel must
decide whatever a model chooses. Each must hold: refused where the policy
refuses, naming the invariant, with the database and the outbox untouched; or
committed, delivered once, and every oracle satisfied. The live cases need a
model and are run by hand (``BENCHMARK_API_KEY``).
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent

CLASSES = {
    "compliant",
    "foreign_tenant",
    "restricted_table",
    "delete_protected",
    "bulk",
    "volume_cap",
    "drift_agreement",
    "drift_constraint",
}


@pytest.fixture(scope="module")
def suite() -> Iterator[ModuleType]:
    """The script, imported as itself."""
    name = "customer_acceptance_suite"
    spec = importlib.util.spec_from_file_location(name, ROOT / "demo" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(name, None)


@pytest.mark.parametrize("key", ["finance", "orchestration", "saas", "logistics"])
def test_every_reference_proposal_holds(suite: ModuleType, key: str, tmp_path: Path) -> None:
    (domain,) = [d for d in suite.DOMAINS if d.key == key]
    vendors = suite.Vendors()
    vendors.slow = set(domain.slow_first)
    try:
        ran = suite.run_domain(
            domain, models=[], effort="low", client=None, vendors=vendors, root=tmp_path
        )
    finally:
        vendors.close()
    assert {r["key"] for r in ran["references"]} == CLASSES
    assert [(r["title"], r["problems"]) for r in ran["references"] if r["verdict"] != "PASS"] == []
    assert ran["live"] == []


def test_the_offline_run_renders_the_matrix(suite: ModuleType, tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.md"
    assert suite.main(["--offline", "--out", str(tmp_path / "run"), "--matrix", str(matrix)]) == 0
    text = matrix.read_text()
    for domain in suite.DOMAINS:
        assert f". {domain.title}" in text
    assert "under `TenantIsolation(1)` without `declared=True` was **committed**" in text
    assert "repair committed" in text
