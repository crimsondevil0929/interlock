"""Execute every Python block in README.md.

A README that cannot be copied and run is a README that has already drifted.
This module extracts each ``python`` fence, runs it in a scratch directory
against a prepared database, and fails the build when one of them stops
working.

Three gates, weakest to strongest:

1. **Parse.** Every block must be syntactically valid Python.
2. **Resolve.** Every ``from interlock import X`` must name something that
   exists, and every backticked ``symbol()`` in the prose must resolve to a
   real attribute of the package. This is the gate that catches a README
   documenting a function nobody shipped.
3. **Run.** Every block executes, unless it carries an explicit opt-out.

Opting out is deliberate and reviewable. Put an HTML comment directly above
the fence::

    <!-- readme-test: skip reason="needs a live provider client" -->

A ``skip`` without a ``reason`` is itself a failure, so a block can never be
quietly excluded. ``<!-- readme-test: continue -->`` runs a block in the
namespace left by the previous one, for a narrative split across fences.
"""

from __future__ import annotations

import ast
import importlib
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

import interlock

README = Path(__file__).resolve().parent.parent / "README.md"
PACKAGE = "interlock"

_BLOCK = re.compile(
    r"(?:<!--\s*readme-test:(?P<directive>.*?)-->\s*\n)?```python\n(?P<code>.*?)```",
    re.S,
)
_DIRECTIVE_REASON = re.compile(r'reason="(?P<reason>[^"]*)"')
_PROSE_SYMBOL = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\(\)`")

#: Backticked ``name()`` tokens in the prose that are not Interlock API.
#: Every entry is a deliberate exemption; an unknown symbol fails the build.
PROSE_EXEMPT = frozenset(
    {
        "check",
        "admit",
        "connection.set_authorizer",
        "set_authorizer",
        "uv.sync",
    }
)


class Block:
    """One fenced block, with its directive."""

    def __init__(self, index: int, code: str, directive: str) -> None:
        self.index = index
        self.code = code
        self.directive = directive.strip()

    @property
    def skipped(self) -> bool:
        return self.directive.startswith("skip")

    @property
    def continues(self) -> bool:
        return "continue" in self.directive

    @property
    def reason(self) -> str:
        found = _DIRECTIVE_REASON.search(self.directive)
        return found.group("reason") if found else ""

    def __repr__(self) -> str:
        return f"block#{self.index}"


def _blocks() -> list[Block]:
    text = README.read_text(encoding="utf-8")
    return [
        Block(i, m.group("code"), m.group("directive") or "")
        for i, m in enumerate(_BLOCK.finditer(text))
    ]


BLOCKS = _blocks()


def _seed(directory: Path) -> Path:
    """The database every runnable README block is written against."""
    path = directory / "prod.db"
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE orders (
                id      INTEGER PRIMARY KEY,
                tenant  TEXT NOT NULL,
                total   REAL NOT NULL
            );
            INSERT INTO orders (id, tenant, total) VALUES
                (1, 'acme', 500.0),
                (2, 'acme', 300.0),
                (3, 'globex', 900.0);
            CREATE TABLE order_audit (
                id     INTEGER PRIMARY KEY,
                tenant TEXT NOT NULL,
                note   TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
    return path


def test_readme_has_python_blocks() -> None:
    """A README with no executable blocks would pass every other test here."""
    assert BLOCKS, "README.md contains no ```python blocks"


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_block_parses(block: Block) -> None:
    """Gate 1: every block is valid Python, including the skipped ones."""
    ast.parse(block.code)


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_block_imports_resolve(block: Block) -> None:
    """Gate 2: every name imported from this package actually exists."""
    tree = ast.parse(block.code)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(PACKAGE):
            module = _import_module(node.module or PACKAGE)
            for alias in node.names:
                assert hasattr(module, alias.name), (
                    f"{block}: README imports {alias.name!r} from "
                    f"{node.module!r}, which does not export it"
                )


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_skip_carries_a_reason(block: Block) -> None:
    """A block can be excluded, but never silently."""
    if block.skipped:
        assert block.reason, f"{block}: 'skip' needs reason=\"...\" so the exclusion is reviewable"


def test_prose_symbols_resolve() -> None:
    """Gate 2, continued: backticked ``symbol()`` in prose must be real.

    This is the gate that would have caught a README naming a function that
    only ever existed in an unreleased branch.
    """
    text = README.read_text(encoding="utf-8")
    unresolved: list[str] = []
    for symbol in sorted(set(_PROSE_SYMBOL.findall(text))):
        if symbol in PROSE_EXEMPT or not _resolves(symbol):
            if symbol not in PROSE_EXEMPT:
                unresolved.append(symbol)
    assert not unresolved, (
        "README names these symbols in prose but the package does not provide "
        f"them: {', '.join(unresolved)}. Fix the name, ship the symbol, or add "
        "it to PROSE_EXEMPT with a reason."
    )


def test_all_blocks_execute(tmp_path: Path) -> None:
    """Gate 3: run them, in order, sharing a namespace where asked."""
    import os

    seeded = _seed(tmp_path)
    previous = os.getcwd()
    namespace: dict[str, Any] = {}
    os.chdir(tmp_path)
    try:
        for block in BLOCKS:
            if block.skipped:
                continue
            if not block.continues:
                namespace = {"__name__": "__readme__"}
                # Each independent block gets a pristine database, so block
                # order never becomes a hidden dependency.
                seeded.unlink(missing_ok=True)
                for stale in tmp_path.glob("*.jsonl"):
                    stale.unlink()
                _seed(tmp_path)
            try:
                # S102: executing the README is the entire purpose of this
                # module. The input is a file in this repository, reviewed in
                # the same pull request as the code it documents.
                exec(  # noqa: S102
                    compile(block.code, f"README.md::{block}", "exec"), namespace
                )
            except Exception as exc:
                pytest.fail(
                    f"{block} failed to run verbatim: {type(exc).__name__}: {exc}\n"
                    f"--- block ---\n{block.code}"
                )
    finally:
        os.chdir(previous)


def _import_module(dotted: str) -> Any:
    """Import a dotted submodule. ``getattr`` is not enough: a subpackage that
    ``__init__`` does not itself import is absent as an attribute."""
    return importlib.import_module(dotted)


def _resolves(symbol: str) -> bool:
    """Whether ``a.b()`` names something reachable from the package."""
    head, *rest = symbol.split(".")
    target: Any = getattr(interlock, head, None)
    if target is None:
        # Bare method names like ``verify()`` resolve against any export.
        return any(
            hasattr(getattr(interlock, name), head)
            for name in interlock.__all__
            if isinstance(getattr(interlock, name, None), type)
        )
    for part in rest:
        target = getattr(target, part, None)
        if target is None:
            return False
    return True
