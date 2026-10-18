"""A checker's configuration digest is the same in every process.

ARC1 receipts record each checker with a digest of its configuration
(``checker_records``). A digest over a set of strings rendered in hash order
changed with ``PYTHONHASHSEED``, so nobody could recompute it from the
configuration in another process. These tests compute the digests of every
built-in checker in processes with different seeds, and pin them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from interlock.receipts import _render
from tests.checker_digests import checkers, digests

ROOT = Path(__file__).resolve().parent.parent

SEEDS = ("0", "1", "2", "3", "4", "5", "6", "7", "random")

PINNED = {
    # Unchanged by sorting sets: these hold no set, and digest as they did in 1.0.2.
    "blast_radius": "cfd7cd9e040d35c02c638690ae5b5eca18801bdd0364560779252561935322cc",
    "column_value_guard:orders.total": (
        "ecace65b3b18688cc2c60e4761dea67bf3718886d217a58b422168da238fcdeb"
    ),
    "cross_effect_agreement:stripe.refunds.create.amount=refunds.amount": (
        "d703fab82ebd7949786c12559f86aa9c0b17506626d252bf437912249133706b"
    ),
    "no_schema_change": "83144a07057ba469096d1f5bf9fb95759d35f6d9b082df4d45e94e804a4b2642",
    "outbound_count": "112c1825eda030d2b0b74e90c995cd5b127316168a099e55d7c4b34808b36973",
    "outbound_tenant_isolation": (
        "3bad56dce11528116ac20ebc04d72b6f58f0e1ebc8a9d51219b004394c0364d3"
    ),
    "payload_amount_cap:stripe.refunds.create.amount": (
        "a26b087862497d126c2eed5faaa539990e3c33d24235ce6521425dcc66255a91"
    ),
    "rate_window:w": "16150be1c6a971100d9a9c6991f6c17b1a71f673417f966ae3f8b9d7a1bdd107",
    "stated_footprint": "0736727a462e9580692ddb36c936b40cbb08602252c51b2d80ad605ffc7af8b9",
    "tenant_drawdown_guard:orders.total": (
        "9e6e8458bcd0d5aa11c4714ac2aae053d7fd06c9043a83257cae2dcdad1cc6bf"
    ),
    "tenant_isolation": "153867730e32a368ced539179d47f62ef4ff1c2c8b9dbfca8566b09070eb05d3",
    "truncation_guard": "b4f9930e0a2c7afa8b44f2462828c4794801cc198d6590ff811957dca4c15abb",
    # These hold sets: in 1.0.2 each digested a different way in each process.
    "fact_agreement:charge.failed|charge.refunded|charge.updated.amount=refunds.amount": (
        "eb0dcfc9ffa5992e4946d0d3bd16477737e1da616ea6877a1e554b8657f4bae0"
    ),
    "no_delete": "21502bb8be61e30f555eedd3e9133fe421f8453a0d057fe2d6f56953ea79fb9e",
    "recipient_allowlist:mail.send": (
        "bc546b9b5a3c339c2f3082dc9543d1288822c36958e2377e379806791614275d"
    ),
    "sink_allowlist": "f01e9685cabc337393d5344ff2f279ddccf2c853cdab039fca62c4945ae79141",
    "table_allowlist": "ca3a4a2575706aa66669a4f926bb5153c198b417bf3b3ab9de59cd3c96a9a8e6",
}


def _digests_under(seed: str) -> dict[str, str]:
    env = {**os.environ, "PYTHONHASHSEED": seed}
    done = subprocess.run(
        [sys.executable, "-m", "tests.checker_digests"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    found: dict[str, str] = json.loads(done.stdout)
    return found


def test_every_built_in_checker_digests_the_same_under_every_hash_seed() -> None:
    seen = {seed: _digests_under(seed) for seed in SEEDS}
    assert len(seen["0"]) == len(checkers()) == 17
    for seed, found in seen.items():
        assert found == seen["0"], f"PYTHONHASHSEED={seed} digests differently"
    assert seen["0"] == digests()


def test_the_digests_are_pinned() -> None:
    assert digests() == PINNED


@pytest.mark.parametrize(
    "value",
    [
        0,
        "x",
        (),
        ("a",),
        ("a", 1),
        [],
        ["a", ("b",)],
        {},
        {"a": [1, 2], "b": {"c": None}},
        None,
        2.5,
        frozenset(),
        set(),
    ],
)
def test_a_value_holding_no_set_renders_exactly_as_repr(value: object) -> None:
    assert _render(value) == repr(value)


def test_a_set_renders_its_members_sorted() -> None:
    assert _render(frozenset({"b", "a", "c"})) == "frozenset({'a', 'b', 'c'})"
    assert _render({"b", "a"}) == "{'a', 'b'}"
    assert _render({"x": frozenset({2, 1})}) == "{'x': frozenset({1, 2})}"
    assert _render([frozenset({"z", "y"})]) == "[frozenset({'y', 'z'})]"
