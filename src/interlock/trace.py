"""W3C trace context (``docs/EPIC7_DESIGN.md`` §1).

A ``traceparent`` rides with a plan into the outbox, out as a header on the
relay's request, and back on the fact a webhook becomes::

    plan = PlanBuilder("support", traceparent=span_context).update(...).build()
    ...
    for fact in await ctx.facts("support"):
        reply = ctx.plan("support", traceparent=child_traceparent(fact.traceparent))

Interlock carries the context and never decides anything by it: no hash,
signature or check covers it, so the same plan has the same hash, traced or
not. It is version ``00``: ``00-<trace-id>-<parent-id>-<flags>``, 32, 16 and 2
lowercase hex digits, neither id all zeros.
"""

from __future__ import annotations

import re
import secrets
from typing import Final

__all__ = [
    "TRACEPARENT_PATTERN",
    "child_traceparent",
    "fact_traceparent",
    "new_traceparent",
    "parse_traceparent",
    "require_traceparent",
    "span_id",
    "trace_id",
]

TRACEPARENT_PATTERN: Final = r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
"""What every stored ``traceparent`` matches; the databases' ``CHECK`` too."""

_VERSION_00: Final = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})")
# A later version keeps the first four fields' shape and may add fields after
# a dash (W3C Trace Context, "Versioning of traceparent").
_LATER: Final = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:-.*)?")
_ZERO_TRACE: Final = "0" * 32
_ZERO_SPAN: Final = "0" * 16


def require_traceparent(value: str) -> str:
    """``value``, if it is a valid version-``00`` ``traceparent``: what an
    agent writes into a plan.

    :raises ValueError: Naming what is wrong with it.
    """
    if not isinstance(value, str):
        raise ValueError(f"a traceparent is a string, not {type(value).__name__}")
    match = _VERSION_00.fullmatch(value)
    if match is None:
        raise ValueError(
            f"{value[:80]!r} is not a traceparent: 00-<32 hex>-<16 hex>-<2 hex>, lowercase"
        )
    if match.group(1) == _ZERO_TRACE:
        raise ValueError("a traceparent's trace id is never all zeros")
    if match.group(2) == _ZERO_SPAN:
        raise ValueError("a traceparent's parent id is never all zeros")
    return value


def parse_traceparent(value: str | None) -> str | None:
    """A received ``traceparent`` header, as version ``00``, or ``None`` when
    it is absent or invalid: what a receiver must ignore, it ignores.

    Surrounding whitespace is trimmed; a version above ``00`` is read for its
    ``00`` fields, and ``ff`` is no version at all.
    """
    if value is None:
        return None
    text = value.strip(" \t")
    if text.startswith("00-"):
        match = _VERSION_00.fullmatch(text)
        fields = None if match is None else match.groups()
    else:
        later = _LATER.fullmatch(text)
        if later is None or later.group(1) == "ff":
            return None
        fields = later.group(2, 3, 4)
    if fields is None or fields[0] == _ZERO_TRACE or fields[1] == _ZERO_SPAN:
        return None
    return f"00-{fields[0]}-{fields[1]}-{fields[2]}"


def trace_id(traceparent: str) -> str:
    """The trace a ``traceparent`` belongs to."""
    return require_traceparent(traceparent)[3:35]


def span_id(traceparent: str) -> str:
    """The span a ``traceparent`` names as the parent."""
    return require_traceparent(traceparent)[36:52]


def new_traceparent(*, sampled: bool = True) -> str:
    """A new trace, and its first span."""
    trace = secrets.token_hex(16)
    while trace == _ZERO_TRACE:  # pragma: no cover - one in 2**128
        trace = secrets.token_hex(16)
    return f"00-{trace}-{_span()}-{'01' if sampled else '00'}"


def child_traceparent(parent: str) -> str:
    """A new span in ``parent``'s trace, with its flags: what continues it."""
    require_traceparent(parent)
    return f"00-{parent[3:35]}-{_span()}-{parent[53:55]}"


def fact_traceparent(delivery: str | None, webhook: str | None) -> str | None:
    """The context a fact continues (``docs/EPIC7_DESIGN.md`` §1.4): the
    trace of the plan whose delivery it is bound to, with the webhook's span as
    the parent when the webhook carried that same trace; the webhook's, when
    the plan carried none."""
    if delivery is None:
        return webhook
    if webhook is not None and webhook[3:35] == delivery[3:35]:
        return webhook
    return delivery


def _span() -> str:
    span = secrets.token_hex(8)
    while span == _ZERO_SPAN:  # pragma: no cover - one in 2**64
        span = secrets.token_hex(8)
    return span
