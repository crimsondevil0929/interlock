"""Pinned checker packs (1.3.0): a domain's own checkers, run only as the code
pinned by module, version and digest."""

from __future__ import annotations

import importlib
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlock import CheckerPackError, PackPin, load_pack, pack_digest
from interlock.receipts import checker_records

PACK = textwrap.dedent(
    """
    from interlock.types import InvariantViolation, Severity

    PACK_NAME = "acme-dose-checkers"
    PACK_VERSION = "1.0.0"


    class DoseCeiling:
        __slots__ = ("_ceiling",)

        def __init__(self, ceiling: str) -> None:
            self._ceiling = int(ceiling)

        @property
        def name(self) -> str:
            return "dose_ceiling"

        def check(self, plan, diff):
            over = [d for d in diff.deltas if (d.after or {}).get("dose_mg", 0) > self._ceiling]
            return tuple(
                InvariantViolation(self.name, Severity.BLOCKING, f"{d.primary_key} is over")
                for d in over
            )


    def not_a_checker(**config):
        return object()


    CHECKERS = {"dose_ceiling": DoseCeiling, "broken": not_a_checker}
    """
)


@pytest.fixture
def packs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "site"
    (root / "acme_checks").mkdir(parents=True)
    (root / "acme_checks" / "__init__.py").write_text(PACK)
    (root / "acme_checks" / "formulary.py").write_text("LIMITS = {'morphine': 90}\n")
    (root / "single_check.py").write_text(PACK.replace("1.0.0", "2.0.0"))
    (root / "empty_pack.py").write_text("PACK_VERSION = '1'\nCHECKERS = 'none'\n")
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in ("acme_checks", "acme_checks.formulary", "single_check", "empty_pack"):
        sys.modules.pop(name, None)


def _digest(module: str) -> str:
    return pack_digest(importlib.import_module(module))


def test_a_pack_loads_as_pinned_and_its_checker_runs(packs: Path) -> None:
    pin = PackPin("acme_checks", "1.0.0", _digest("acme_checks"))
    pack = load_pack(pin)
    assert pack.name == "acme-dose-checkers" and pack.pin == pin
    checker = pack.checker("dose_ceiling", {"ceiling": "90"})
    assert checker.name == "dose_ceiling"
    assert checker_records([checker])[0].name == "dose_ceiling"
    single = PackPin("single_check", "2.0.0", _digest("single_check"))
    assert load_pack(single).checker("dose_ceiling", {"ceiling": "5"}).name == "dose_ceiling"


def test_a_digest_covers_every_file_of_the_package(packs: Path) -> None:
    before = _digest("acme_checks")
    (packs / "acme_checks" / "formulary.py").write_text("LIMITS = {'morphine': 900}\n")
    assert _digest("acme_checks") != before
    (packs / "acme_checks" / "formulary.py").write_text("LIMITS = {'morphine': 90}\n")
    assert _digest("acme_checks") == before
    (packs / "acme_checks" / "extra.py").write_text("")
    assert _digest("acme_checks") != before


def test_a_tampered_pack_is_refused(packs: Path) -> None:
    pin = PackPin("acme_checks", "1.0.0", _digest("acme_checks"))
    (packs / "acme_checks" / "formulary.py").write_text("LIMITS = {'morphine': 9000}\n")
    with pytest.raises(CheckerPackError, match="not the code pinned") as raised:
        load_pack(pin)
    assert raised.value.reason == "digest"


def test_a_missing_pack_or_another_version_is_refused(packs: Path) -> None:
    with pytest.raises(CheckerPackError, match="not installed") as raised:
        load_pack(PackPin("no_such_pack", "1.0.0", "0" * 64))
    assert raised.value.reason == "missing"
    with pytest.raises(CheckerPackError, match="cannot be imported"):
        load_pack(PackPin("acme_checks.nothing_here", "1.0.0", "0" * 64))
    with pytest.raises(CheckerPackError, match=r"is version 1\.0\.0") as raised:
        load_pack(PackPin("acme_checks", "1.0.1", _digest("acme_checks")))
    assert raised.value.reason == "version"
    with pytest.raises(CheckerPackError, match="no CHECKERS"):
        load_pack(PackPin("empty_pack", "1", _digest("empty_pack")))


def test_a_checker_it_lacks_or_cannot_build_is_refused(packs: Path) -> None:
    pack = load_pack(PackPin("acme_checks", "1.0.0", _digest("acme_checks")))
    with pytest.raises(CheckerPackError, match="has no checker 'dose_cap'"):
        pack.checker("dose_cap", {})
    with pytest.raises(CheckerPackError, match="refuses its configuration"):
        pack.checker("dose_ceiling", {"floor": "1"})
    with pytest.raises(CheckerPackError, match="refuses its configuration"):
        pack.checker("dose_ceiling", {"ceiling": "high"})
    with pytest.raises(CheckerPackError, match="is not a checker"):
        pack.checker("broken", {})


def test_a_pin_is_well_formed() -> None:
    with pytest.raises(ValueError, match="module name"):
        PackPin("acme-checks", "1", "0" * 64)
    with pytest.raises(ValueError, match="version is named"):
        PackPin("acme", "", "0" * 64)
    with pytest.raises(ValueError, match="64 lowercase hex"):
        PackPin("acme", "1", "ABC")


def test_a_namespace_package_has_no_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "loose").mkdir()
    monkeypatch.syspath_prepend(str(tmp_path))
    module = importlib.import_module("loose")
    try:
        with pytest.raises(CheckerPackError, match="no files"):
            pack_digest(module)
    finally:
        sys.modules.pop("loose", None)
