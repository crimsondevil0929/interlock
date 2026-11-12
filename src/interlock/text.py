"""Counted nouns for the messages Interlock writes: ``1 row``, ``3 rows``.

Every count a message reports is spelled out in the form its number takes (1.5.0), never as
``row(s)``: a refusal is read by people and by models, and both read it as English.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = ["Nouns", "noun", "nouns", "tally"]

_IRREGULAR: Final = {
    "child": "children",
    "person": "people",
    "index": "indexes",
}


def noun(count: int | str, word: str, plural: str | None = None) -> str:
    """``word`` in the form ``count`` takes: ``row`` for one, ``rows`` otherwise.

    :param count: A number, or a range a message reports instead of one (``"10-99"``).
    :param plural: The plural when the usual rules get it wrong.
    """
    if count in (1, "1"):
        return word
    if plural is not None:
        return plural
    if word in _IRREGULAR:
        return _IRREGULAR[word]
    if word.endswith("y") and len(word) > 1 and word[-2] not in "aeiou":
        return word[:-1] + "ies"
    if word.endswith(("s", "x", "z", "ch", "sh")):
        return word + "es"
    return word + "s"


def tally(count: int | str, word: str, plural: str | None = None) -> str:
    """``count`` and ``word`` in the form it takes: ``1 row``, ``3 rows``, ``0 rows``."""
    return f"{count} {noun(count, word, plural)}"


@dataclass(frozen=True, slots=True)
class Nouns:
    """What a system calls the two things every diff is made of (1.5.2): one changed thing
    (a ``RowDelta``), and the kind of thing it is (its ``table``). A file is not a row, and a
    path class is not a table: a refusal read by someone who works on files says so."""

    row: str
    table: str


_SQL: Final = Nouns("row", "table")
_NOUNS: Final = {
    "git": Nouns("file", "path class"),
    "filesystem": Nouns("file", "path class"),
    "kubernetes": Nouns("object", "kind"),
    "terraform": Nouns("resource", "resource type"),
    "fhir": Nouns("resource", "resource type"),
    "rest": Nouns("record", "resource type"),
}


def nouns(substrate_id: str) -> Nouns:
    """The nouns of the system a diff was measured on (``EffectDiff.substrate_id``). SQL's,
    for a database and for any substrate this release does not know."""
    return _NOUNS.get(substrate_id, _SQL)
