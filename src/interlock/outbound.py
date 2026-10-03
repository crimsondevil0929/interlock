"""The sink registry, and what makes an outbound request admissible.

An agent cannot call an external system: it holds no credentials. It can only
propose an :class:`~interlock.types.OutboundRequest`, as an ``ENQUEUE`` effect,
naming a *sink* the operator registered and one of that sink's *operations*.
This module is the registry, and the admission rules a request must pass before
anything is staged (``docs/OUTBOX_DESIGN.md`` §3):

- the sink is registered, and the operation is one of its own;
- the payload fits the operation's JSON Schema (a strict subset, below) and the
  sink's size bound;
- no payload field is named like a credential: credentials belong to the relay,
  and a payload carrying one is an agent choosing its own;
- an operation the operator says can be undone carries its undo, as a
  compensating request that passes the same rules (E4-3); one the operator
  declares cannot be undone carries none.

Endpoints and credentials are relay configuration. Nothing here holds either.

**The schema subset.** ``type`` (``object``, ``array``, ``string``,
``integer``, ``boolean``, ``null``, or a list of them), ``properties``,
``required``, ``additionalProperties`` (a boolean), ``items``, ``enum``,
``const``, ``minLength``, ``maxLength``, ``pattern``, ``minimum``,
``maximum``, ``minItems`` and ``maxItems``. A schema using any other keyword
is refused when the sink is registered, rather than having that keyword
silently ignored: an unenforced constraint reads as an enforced one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from interlock.exceptions import OutboundRequestError
from interlock.types import MAX_NOT_AFTER, OutboundRequest, canonical_hash

__all__ = [
    "DEAD_LETTER",
    "NONE_POSSIBLE",
    "REDELIVER",
    "OperationSpec",
    "SinkRegistry",
    "SinkSpec",
    "schema_problems",
]

REDELIVER: Final = "redeliver"
"""A call whose outcome is unknown is made again, with the same key."""
DEAD_LETTER: Final = "dead-letter"
"""A call whose outcome is unknown is not made again: the message is dead."""

NONE_POSSIBLE: Final = "none-possible"
"""The ``compensation`` an operator declares for an operation nothing can
undo. The declaration is part of the sink's configuration hash."""

_NAME: Final = re.compile(r"\A[a-z][a-z0-9_-]{0,62}\Z")
_OPERATION: Final = re.compile(r"\A[a-z][a-z0-9_.-]{0,126}\Z")

_CREDENTIAL_PARTS: Final = (
    "apikey",
    "password",
    "passwd",
    "secret",
    "privatekey",
    "accesstoken",
    "refreshtoken",
    "authorization",
    "bearer",
)
_CREDENTIAL_NAMES: Final = frozenset({"token", "auth", "credential", "credentials"})

_SCHEMA_KEYWORDS: Final = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        # Annotations: carried, never enforced, and harmless to carry.
        "title",
        "description",
        "$comment",
    }
)
_TYPES: Final = frozenset({"object", "array", "string", "integer", "boolean", "null"})


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """One operation a sink allows.

    :ivar schema: The payload's JSON Schema (the subset above), or ``None``
        for any object.
    :ivar compensation: The name of the operation that undoes this one, which
        every request must then carry as its ``compensation``; or
        :data:`NONE_POSSIBLE`, the operator's declaration that nothing can.
    """

    name: str
    compensation: str = NONE_POSSIBLE
    schema: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not _OPERATION.match(self.name):
            raise ValueError(f"operation name {self.name!r} is not a plain dotted identifier")
        if self.compensation != NONE_POSSIBLE and not _OPERATION.match(self.compensation):
            raise ValueError(
                f"operation {self.name!r}: compensation must name an operation or be "
                f"{NONE_POSSIBLE!r}, not {self.compensation!r}"
            )
        if self.schema is not None:
            _check_schema(self.schema, f"operation {self.name!r} schema")


@dataclass(frozen=True, slots=True)
class SinkSpec:
    """An external system requests may be delivered to.

    :ivar cost_per_call: Settled through AgentGov with the plan that
        enqueues the request (claim and settle), as a decimal string.
    :ivar idempotency: ``"header"`` when the sink deduplicates on an
        ``Idempotency-Key``; ``"none"`` when a relay crash after a call can
        deliver twice.
    :ivar not_after: How long after staging a request may still be delivered,
        when the request does not say.
    :ivar max_attempts: Calls the relay makes before a request is dead.
    :ivar backoff_base: The wait after the first failed call. Each later wait
        doubles, up to ``backoff_cap``, with jitter
        (:func:`interlock.relay.retry_delay`).
    :ivar unknown_outcome: What the relay does when it cannot tell whether a
        call reached the sink (a timeout after sending, a relay that died
        mid-call): ``"redeliver"`` with the same idempotency key, at least
        once; or ``"dead-letter"``, at most once, for an operator to resolve.
        A sink without idempotency duplicates on redelivery.
    """

    name: str
    operations: tuple[OperationSpec, ...]
    cost_per_call: Decimal = Decimal(0)
    idempotency: str = "header"
    max_payload_bytes: int = 16_384
    not_after: timedelta = timedelta(minutes=15)
    max_attempts: int = 10
    backoff_base: timedelta = timedelta(seconds=1)
    backoff_cap: timedelta = timedelta(minutes=10)
    unknown_outcome: str = REDELIVER
    _by_name: Mapping[str, OperationSpec] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"sink name {self.name!r} is not a plain lowercase identifier")
        if not self.operations:
            raise ValueError(f"sink {self.name!r} registers no operations")
        by_name = {op.name: op for op in self.operations}
        if len(by_name) != len(self.operations):
            raise ValueError(f"sink {self.name!r} registers an operation twice")
        for op in self.operations:
            if op.compensation != NONE_POSSIBLE and op.compensation not in by_name:
                raise ValueError(
                    f"sink {self.name!r}: operation {op.name!r} is compensated by "
                    f"{op.compensation!r}, which the sink does not register"
                )
        if self.cost_per_call < 0:
            raise ValueError(f"sink {self.name!r}: cost_per_call cannot be negative")
        if self.idempotency not in ("header", "none"):
            raise ValueError(f"sink {self.name!r}: idempotency is 'header' or 'none'")
        if self.max_payload_bytes <= 0:
            raise ValueError(f"sink {self.name!r}: max_payload_bytes must be positive")
        if not timedelta(0) < self.not_after <= MAX_NOT_AFTER:
            raise ValueError(
                f"sink {self.name!r}: not_after must be positive and at most {MAX_NOT_AFTER}"
            )
        if self.max_attempts < 1:
            raise ValueError(f"sink {self.name!r}: max_attempts must be at least 1")
        if not timedelta(milliseconds=1) <= self.backoff_base <= self.backoff_cap:
            raise ValueError(
                f"sink {self.name!r}: backoff_base must be at least a millisecond and no "
                f"more than backoff_cap"
            )
        if self.backoff_cap > MAX_NOT_AFTER:
            raise ValueError(f"sink {self.name!r}: backoff_cap is at most {MAX_NOT_AFTER}")
        if self.unknown_outcome not in (REDELIVER, DEAD_LETTER):
            raise ValueError(
                f"sink {self.name!r}: unknown_outcome is {REDELIVER!r} or {DEAD_LETTER!r}"
            )
        object.__setattr__(self, "_by_name", by_name)

    def operation(self, name: str) -> OperationSpec | None:
        return self._by_name.get(name)

    def config_hash(self) -> str:
        """A digest of everything the sink permits, for the database's mirror
        of the registry and for the receipts of plans that use it."""
        return canonical_hash(
            [
                "sink",
                self.name,
                str(self.cost_per_call),
                self.idempotency,
                self.max_payload_bytes,
                int(self.not_after.total_seconds()),
                self.max_attempts,
                int(self.backoff_base / timedelta(milliseconds=1)),
                int(self.backoff_cap / timedelta(milliseconds=1)),
                self.unknown_outcome,
                sorted(
                    [
                        op.name,
                        op.compensation,
                        None
                        if op.schema is None
                        else json.dumps(op.schema, sort_keys=True, separators=(",", ":")),
                    ]
                    for op in self.operations
                ),
            ]
        )


class SinkRegistry:
    """The sinks an engine admits requests for.

    :raises ValueError: If two sinks share a name.
    """

    __slots__ = ("_sinks",)

    def __init__(self, sinks: Iterable[SinkSpec] = ()) -> None:
        self._sinks: dict[str, SinkSpec] = {}
        for sink in sinks:
            if sink.name in self._sinks:
                raise ValueError(f"sink {sink.name!r} is registered twice")
            self._sinks[sink.name] = sink

    def __iter__(self) -> Iterator[SinkSpec]:
        return iter(self._sinks.values())

    def __len__(self) -> int:
        return len(self._sinks)

    def get(self, name: str) -> SinkSpec | None:
        return self._sinks.get(name)

    def check(self, request: OutboundRequest) -> SinkSpec:
        """Admit ``request``, or say why not.

        :returns: The sink it names.
        :raises OutboundRequestError: On the first rule it breaks.
        """
        sink = self._check_one(request)
        spec = sink.operation(request.operation)
        assert spec is not None  # checked above
        compensation = request.compensation
        if spec.compensation == NONE_POSSIBLE:
            if compensation is not None:
                raise OutboundRequestError(
                    f"{sink.name}.{spec.name} is declared impossible to undo, but the request "
                    f"carries a compensation",
                    reason="compensation",
                    sink=sink.name,
                )
            return sink
        if compensation is None:
            raise OutboundRequestError(
                f"{sink.name}.{spec.name} is undone by {spec.compensation}, and the request "
                f"carries no compensation: the undo is written down before the do (E4-3)",
                reason="compensation",
                sink=sink.name,
            )
        if compensation.sink != sink.name or compensation.operation != spec.compensation:
            raise OutboundRequestError(
                f"{sink.name}.{spec.name} is undone by {sink.name}.{spec.compensation}, not "
                f"{compensation.sink}.{compensation.operation}",
                reason="compensation",
                sink=sink.name,
            )
        if compensation.compensation is not None:
            raise OutboundRequestError(
                "a compensation does not carry a compensation of its own",
                reason="compensation",
                sink=sink.name,
            )
        self._check_one(compensation)
        return sink

    def _check_one(self, request: OutboundRequest) -> SinkSpec:
        sink = self._sinks.get(request.sink)
        if sink is None:
            raise OutboundRequestError(
                f"no sink named {request.sink!r} is registered", reason="unregistered_sink"
            )
        spec = sink.operation(request.operation)
        if spec is None:
            raise OutboundRequestError(
                f"sink {sink.name!r} registers no operation {request.operation!r}",
                reason="unregistered_operation",
                sink=sink.name,
            )
        size = len(request.canonical_payload)
        if size > sink.max_payload_bytes:
            raise OutboundRequestError(
                f"{sink.name}.{spec.name} payload is {size} bytes; the sink allows "
                f"{sink.max_payload_bytes}",
                reason="payload_size",
                sink=sink.name,
            )
        credential = _credential_field(request.payload, "$")
        if credential is not None:
            raise OutboundRequestError(
                f"{sink.name}.{spec.name} payload field {credential} is named like a "
                f"credential; the relay supplies credentials, a payload never does",
                reason="credential_field",
                sink=sink.name,
            )
        if spec.schema is not None:
            problems = schema_problems(request.payload, spec.schema)
            if problems:
                raise OutboundRequestError(
                    f"{sink.name}.{spec.name} payload does not match its schema: "
                    + "; ".join(problems[:5]),
                    reason="payload_schema",
                    sink=sink.name,
                )
        return sink


def _credential_field(value: Any, path: str) -> str | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            folded = re.sub(r"[^a-z0-9]", "", key.lower())
            if folded in _CREDENTIAL_NAMES or any(part in folded for part in _CREDENTIAL_PARTS):
                return f"{path}.{key}"
            found = _credential_field(item, f"{path}.{key}")
            if found is not None:
                return found
    elif isinstance(value, Sequence) and not isinstance(value, str):
        for index, item in enumerate(value):
            found = _credential_field(item, f"{path}[{index}]")
            if found is not None:
                return found
    return None


# --------------------------------------------------------------------------
# The JSON Schema subset
# --------------------------------------------------------------------------


def _check_schema(schema: Any, where: str) -> None:
    """Refuse a schema this validator would not fully enforce."""
    if not isinstance(schema, Mapping):
        raise ValueError(f"{where}: a schema is an object")
    unknown = sorted(set(schema) - _SCHEMA_KEYWORDS)
    if unknown:
        raise ValueError(
            f"{where}: unsupported keyword(s) {', '.join(unknown)}; they would be ignored, "
            f"not enforced"
        )
    kinds = schema.get("type")
    if kinds is not None:
        listed = [kinds] if isinstance(kinds, str) else kinds
        if not isinstance(listed, list) or not all(k in _TYPES for k in listed):
            raise ValueError(f"{where}: type must be one of {sorted(_TYPES)}, or a list of them")
    for key in ("properties",):
        if key in schema:
            if not isinstance(schema[key], Mapping):
                raise ValueError(f"{where}: {key} is an object")
            for name, sub in schema[key].items():
                _check_schema(sub, f"{where}.{name}")
    if "items" in schema:
        _check_schema(schema["items"], f"{where}[]")
    if "required" in schema and not (
        isinstance(schema["required"], list) and all(isinstance(r, str) for r in schema["required"])
    ):
        raise ValueError(f"{where}: required is a list of names")
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        raise ValueError(f"{where}: additionalProperties is true or false in this subset")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (re.error, TypeError) as exc:
            raise ValueError(f"{where}: pattern does not compile: {exc}") from exc
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        if key in schema and not (isinstance(schema[key], int) and schema[key] >= 0):
            raise ValueError(f"{where}: {key} is a non-negative integer")
    for key in ("minimum", "maximum"):
        if key in schema and (
            isinstance(schema[key], bool) or not isinstance(schema[key], int | str)
        ):
            raise ValueError(f"{where}: {key} is an integer, or a decimal string")
    if "enum" in schema and not isinstance(schema["enum"], list):
        raise ValueError(f"{where}: enum is a list")


def schema_problems(value: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    """Every way ``value`` breaks ``schema``, in document order.

    ``minimum`` and ``maximum`` compare integers exactly, and a decimal string
    (money) as a :class:`~decimal.Decimal`.
    """
    problems: list[str] = []
    kinds = schema.get("type")
    if kinds is not None:
        listed = [kinds] if isinstance(kinds, str) else list(kinds)
        if _type_of(value) not in listed:
            return [f"{path} is {_type_of(value)}, not {' or '.join(listed)}"]
    if "const" in schema and value != schema["const"]:
        problems.append(f"{path} is not the required constant")
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path} is not one of the allowed values")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            problems.append(f"{path} is shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            problems.append(f"{path} is longer than {schema['maxLength']}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            problems.append(f"{path} does not match its pattern")
    if "minimum" in schema or "maximum" in schema:
        number = _number(value)
        if number is None:
            problems.append(f"{path} is not a number or a decimal string")
        else:
            low, high = schema.get("minimum"), schema.get("maximum")
            if low is not None and number < Decimal(str(low)):
                problems.append(f"{path} is below its minimum")
            if high is not None and number > Decimal(str(high)):
                problems.append(f"{path} is above its maximum")
    if isinstance(value, Mapping):
        properties: Mapping[str, Any] = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"{path}.{name} is required")
        for name, item in value.items():
            if name in properties:
                problems += schema_problems(item, properties[name], f"{path}.{name}")
            elif schema.get("additionalProperties") is False:
                problems.append(f"{path}.{name} is not an allowed field")
    if isinstance(value, tuple | list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append(f"{path} has fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(f"{path} has more than {schema['maxItems']} items")
        if "items" in schema:
            for index, item in enumerate(value):
                problems += schema_problems(item, schema["items"], f"{path}[{index}]")
    return problems


def _type_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, tuple | list):
        return "array"
    return type(value).__name__


def _number(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        try:
            number = Decimal(value)
        except (InvalidOperation, ValueError):
            return None
        return number if number.is_finite() else None
    return None
