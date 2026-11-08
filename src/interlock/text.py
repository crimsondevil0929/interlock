"""Counted nouns for the messages Interlock writes: ``1 row``, ``3 rows``.

Every count a message reports is spelled out in the form its number takes (1.5.0), never as
``row(s)``: a refusal is read by people and by models, and both read it as English.
"""

from __future__ import annotations

from typing import Final

__all__ = ["noun", "tally"]

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
