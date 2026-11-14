"""MCP tools as a sink: an agent's writes through an MCP server, escrowed.

A sink of kind ``mcp`` fronts one MCP server. Its operations are that
server's write tools, by name, each with the input schema the operator pins
for it (the server advertises one in ``tools/list``; configuration copies
it, so a server that changes its schema changes nothing the checks admit).
A request is one ``tools/call``: its operation is the tool, its payload the
tool's arguments. The plan that enqueues it is measured and judged as any
other, may be held for a warrant (``hold = true`` on the operation), and
commits the request to the outbox; the relay then makes the call.

**At most once.** MCP has no idempotency key: a call made twice acts twice.
So every ``mcp`` sink has ``idempotency = "none"`` and ``unknown_outcome =
"dead-letter"``, and no other: a call whose outcome is unknown is never made
again, and an operator settles it.

=================================  ==============  ================================
The server answered                Outcome
=================================  ==============  ================================
a result                           ``delivered``   the result's digest; its
                                                   ``structuredContent.id``, a
                                                   plain id, is the ``remote_ref``
a result with ``isError``          ``permanent``   the tool ran and said it failed
a JSON-RPC error                   ``permanent``   the server refused the call
nothing: it could not be reached   ``retryable``   nothing was sent
nothing, after the call was sent   ``unknown``     it may have acted: dead letter
=================================  ==============  ================================

The relay's adapter (:class:`McpAdapter`) makes the call through any
transport: a function ``call(tool, arguments, timeout)``. :class:`StdioServer`
is the one ``[[relay.endpoints]]`` configures: the server run as the relay's
child, speaking newline-delimited JSON-RPC on its standard streams::

    [[sinks]]
    name = "crm"
    type = "mcp"

    [[sinks.operations]]
    name = "close_ticket"
    schema = "schemas/close_ticket.json"
    hold = true                       # each call waits for a warrant

    [[relay.endpoints]]
    sink = "crm"
    command = ["crm-mcp-server", "--stdio"]
    # tools = { close_ticket = "closeTicket" }  # when a tool's name is no operation name
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import select
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import IO, Any, Final

from agentgov.receipts.canonical import loads_strict

from interlock.outbound import DEAD_LETTER, OperationSpec, SinkSpec, placeholders
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = [
    "LEGACY_VERSIONS",
    "MODERN_VERSIONS",
    "PROTOCOL_VERSION",
    "PROTOCOL_VERSIONS",
    "UNSUPPORTED_VERSION",
    "Era",
    "McpAdapter",
    "McpCallError",
    "McpRefusedError",
    "StdioServer",
    "classify",
    "decimals",
    "handshake",
    "mcp_sink",
    "modern_meta",
    "numbers_on_the_wire",
    "relay_adapter",
]

MODERN_VERSIONS: Final = ("2026-07-28",)
"""The MCP revisions with no ``initialize`` handshake, which carry their version, the
client's capabilities and its name in every request's ``_meta`` (1.9.0)."""
LEGACY_VERSIONS: Final = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
"""The MCP revisions that open with ``initialize``, newest first."""
PROTOCOL_VERSIONS: Final = MODERN_VERSIONS + LEGACY_VERSIONS
"""Every MCP revision spoken here, newest first."""
PROTOCOL_VERSION: Final = LEGACY_VERSIONS[0]
"""The revision a :class:`StdioServer` asks for in ``initialize``, when the server
turns out to be one that needs it."""
UNSUPPORTED_VERSION: Final = -32022
"""2026-07-28's ``UnsupportedProtocolVersionError``: its ``data.supported`` lists
the server's revisions."""
PROBE_SECONDS: Final = 2.0
"""How long a ``server/discover`` probe waits before taking a silent server for one
that needs ``initialize``."""
_META: Final = "io.modelcontextprotocol/"

CATALOG: Final = None
"""An MCP server's tools are its own: the operations come from configuration."""
IDEMPOTENCY: Final = "none"
"""MCP has no idempotency key: a call made twice acts twice."""
UNKNOWN_OUTCOME: Final = DEAD_LETTER
UNKNOWN_OUTCOMES: Final = (DEAD_LETTER,)
"""So a call whose outcome is unknown is never made again: at most once, always."""

_MAX_LINE: Final = 1 << 20
_REF: Final = 255


class McpCallError(Exception):
    """A ``tools/call`` that got no result.

    :ivar sent: Whether the request reached the server: when it did, the
        tool may have acted.
    """

    def __init__(self, message: str, *, sent: bool) -> None:
        super().__init__(message)
        self.sent = sent


class McpRefusedError(McpCallError):
    """The server answered the call with a JSON-RPC error: it did not run it.

    :ivar code: The error's code, when it had one.
    :ivar data: The error's ``data``, when it had any.
    """

    def __init__(self, message: str, *, code: int | None = None, data: Any = None) -> None:
        super().__init__(message, sent=True)
        self.code = code
        self.data = data


@dataclass(frozen=True, slots=True)
class Era:
    """How a server is spoken to (1.9.0): the revision agreed, and whether it is a
    modern one, whose every request carries :func:`modern_meta`."""

    version: str
    modern: bool

    def params(self, params: Mapping[str, Any], client: Mapping[str, str]) -> dict[str, Any]:
        """A request's ``params``, with the ``_meta`` a modern server requires."""
        out = dict(params)
        if self.modern:
            out["_meta"] = {**dict(out.get("_meta") or {}), **modern_meta(self.version, client)}
        return out


def modern_meta(version: str, client: Mapping[str, str]) -> dict[str, Any]:
    """The ``_meta`` every request to a modern server carries: its revision, the
    client's capabilities (none: a client of tools only) and its name."""
    return {
        _META + "protocolVersion": version,
        _META + "clientCapabilities": {},
        _META + "clientInfo": dict(client),
    }


Request = Callable[[str, Mapping[str, Any], float], Mapping[str, Any]]
"""Send one request and read its result: method, params, seconds. Raises
:class:`McpRefusedError` on an error response, :class:`McpCallError` on silence."""


def handshake(
    request: Request,
    notify: Callable[[str], None],
    client: Mapping[str, str],
    *,
    timeout: float,
    probe: float = PROBE_SECONDS,
) -> Era:
    """Agree on a revision with a server over stdio, as 2026-07-28's backward
    compatibility asks (1.9.0): probe with ``server/discover``. A result, or an
    ``UnsupportedProtocolVersionError``, is a modern server, spoken to in a revision
    both support. Any other error, or silence for ``probe`` seconds, is a server
    that needs ``initialize``: it is sent, asking for :data:`PROTOCOL_VERSION`, and
    the revision it answers with is used if it is one of :data:`LEGACY_VERSIONS`.
    With ``probe`` 0 it goes straight to ``initialize``: for a server the probe
    itself stopped.

    :raises McpCallError: When no revision is shared, or the server does not answer
        ``initialize``.
    """
    preferred = MODERN_VERSIONS[0]
    found: Mapping[str, Any] | None = None
    if probe > 0:
        try:
            found = request(
                "server/discover", {"_meta": modern_meta(preferred, client)}, min(probe, timeout)
            )
        except McpRefusedError as exc:
            if exc.code == UNSUPPORTED_VERSION:
                offered = exc.data.get("supported") if isinstance(exc.data, Mapping) else None
                return _modern(offered)
        except McpCallError as exc:
            if not exc.sent:
                raise
    if found is not None:
        return _modern(found.get("supportedVersions"))
    answer = request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": dict(client),
        },
        timeout,
    )
    # A server that leaves its revision out is taken at the one asked for.
    version = answer.get("protocolVersion", PROTOCOL_VERSION)
    if version not in LEGACY_VERSIONS:
        raise McpCallError(
            f"the server answered initialize with revision {version!r}, which this client "
            f"does not speak: {', '.join(LEGACY_VERSIONS)}",
            sent=False,
        )
    notify("notifications/initialized")
    return Era(str(version), modern=False)


def _modern(offered: object) -> Era:
    if isinstance(offered, list):
        for version in MODERN_VERSIONS:
            if version in offered:
                return Era(version, modern=True)
    raise McpCallError(
        f"the server speaks MCP {offered!r}, and none is a revision this client speaks: "
        f"{', '.join(PROTOCOL_VERSIONS)}",
        sent=False,
    )


DECIMAL: Final = r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?$"
"""A JSON number, as the string a binding holds it in: what a ``number`` argument is
recorded as, so that no float is ever hashed or signed (1.9.0)."""
_DECIMAL: Final = re.compile(DECIMAL)


def decimals(value: Any, paths: Sequence[str]) -> Any:
    """``value`` with each number at ``paths`` written as its decimal string: what is
    recorded and hashed (1.9.0). A path is dotted (``filters.min_price``), ``[]``
    for each item of an array (``lines[].qty``). A path that is absent is skipped;
    one that holds something other than a number is left for the schema to refuse."""
    return _convert(value, paths, _to_text)


def numbers_on_the_wire(value: Any, paths: Sequence[str]) -> Any:
    """:func:`decimals` undone: each decimal string at ``paths`` sent as the JSON
    number it records (1.9.0). An integer stays an integer; any other number is a
    float, as the model's own JSON number was."""
    return _convert(value, paths, _to_number)


def _to_text(item: Any) -> Any:
    if isinstance(item, bool) or not isinstance(item, (int, float, Decimal)):
        return item
    if isinstance(item, float) and not math.isfinite(item):
        return item
    text = format(Decimal(repr(item)) if isinstance(item, float) else Decimal(item), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text if text != "-0" else "0"


def _to_number(item: Any) -> Any:
    if not isinstance(item, str) or not _DECIMAL.match(item):
        return item
    exact = Decimal(item)
    if exact == exact.to_integral_value() and "." not in item and "e" not in item.lower():
        return int(exact)
    return float(exact)


def _convert(value: Any, paths: Sequence[str], change: Callable[[Any], Any]) -> Any:
    out = copy.deepcopy(value)
    for path in paths:
        out = _at(out, [p for p in path.split(".") if p], change)
    return out


def _at(value: Any, steps: list[str], change: Callable[[Any], Any]) -> Any:
    if not steps:
        return change(value)
    step, rest = steps[0], steps[1:]
    array = step.endswith("[]")
    key = step[:-2] if array else step
    if not isinstance(value, dict) or key not in value:
        return value
    if array:
        items = value[key]
        if isinstance(items, list):
            value[key] = [_at(item, rest, change) for item in items]
        return value
    value[key] = _at(value[key], rest, change)
    return value


def mcp_sink(
    name: str,
    tools: Mapping[str, Mapping[str, Any] | None],
    *,
    held: Sequence[str] = (),
    **settings: Any,
) -> SinkSpec:
    """A sink of kind ``mcp``: one operation per tool, with its pinned schema.

    :param tools: Each tool's operation name and its input schema (``None``
        for any object).
    :param held: The tools whose every call waits for a warrant.
    :param settings: Any other :class:`~interlock.outbound.SinkSpec` field.
    """
    unknown = sorted(set(held) - set(tools))
    if unknown:
        raise ValueError(f"sink {name!r}: holds {', '.join(unknown)}, which it does not list")
    return SinkSpec(
        name,
        tuple(
            OperationSpec(tool, schema=schema, hold=tool in held) for tool, schema in tools.items()
        ),
        kind="mcp",
        **settings,
    )


def payload_problem(operation: str, payload: Mapping[str, Any]) -> str | None:
    """None: a tool's arguments are held to the schema the operator pinned."""
    return None


def compensation_problem(
    operation: str, payload: Mapping[str, Any], compensation: Mapping[str, Any] | None
) -> str | None:
    """None: what undoes a tool, if anything does, is the operator's to declare."""
    return None


Call = Callable[[str, Mapping[str, Any], float], Mapping[str, Any]]
"""A ``tools/call``: the tool, its arguments and the seconds it may take, to
the call's ``result``. Raises :class:`McpCallError` when there is none."""


class McpAdapter:
    """Delivers an MCP sink's requests as ``tools/call``.

    :param call: The transport (:data:`Call`): a :class:`StdioServer`, or a
        client of the caller's own.
    :param tools: The upstream tool each operation calls, where its name is
        not the operation's.
    :param numbers: Each operation's arguments that the server takes as JSON
        numbers, by path (:func:`decimals`): recorded as decimal strings, sent as
        numbers (1.9.0).
    """

    __slots__ = ("_call", "_numbers", "_tools")

    def __init__(
        self,
        call: Call,
        *,
        tools: Mapping[str, str] | None = None,
        numbers: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self._call = call
        self._tools = dict(tools or {})
        self._numbers = {op: tuple(paths) for op, paths in (numbers or {}).items()}

    def send(self, delivery: Delivery) -> DeliveryResult:
        payload = loads_strict(delivery.payload)
        if not isinstance(payload, Mapping) or placeholders(payload):
            return DeliveryResult(
                PERMANENT,
                detail="the payload is no object of arguments, or holds an unbound placeholder",
            )
        tool = self._tools.get(delivery.operation, delivery.operation)
        paths = self._numbers.get(delivery.operation)
        arguments = numbers_on_the_wire(dict(payload), paths) if paths else payload
        try:
            result = self._call(tool, arguments, delivery.timeout)
        except McpRefusedError as exc:
            return DeliveryResult(PERMANENT, detail=f"the server refused {tool}: {exc}")
        except McpCallError as exc:
            if exc.sent:
                return DeliveryResult(
                    UNKNOWN, detail=f"no answer to {tool} after it was sent: {exc}"
                )
            return DeliveryResult(RETRYABLE, detail=f"{tool} was not sent: {exc}")
        except Exception as exc:
            return DeliveryResult(UNKNOWN, detail=f"{tool}: {type(exc).__name__}: {exc}")
        return classify(result)


def classify(result: Mapping[str, Any]) -> DeliveryResult:
    """A ``tools/call`` result, classified. A 2026-07-28 ``input_required`` result
    asks for input a relay cannot give: the tool did not finish, and is not called
    again (1.9.0)."""
    body = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    kind = result.get("resultType", "complete")
    if kind != "complete":
        return DeliveryResult(
            PERMANENT,
            response_digest=digest,
            detail=f"the tool asked for input a relay cannot give ({kind})",
            body=body.encode("utf-8"),
        )
    if result.get("isError") is True:
        return DeliveryResult(
            PERMANENT,
            response_digest=digest,
            detail="the tool reported an error",
            body=body.encode("utf-8"),
        )
    structured = result.get("structuredContent")
    ref = structured.get("id") if isinstance(structured, Mapping) else None
    plain = (isinstance(ref, str) and 0 < len(ref) <= _REF) or (
        isinstance(ref, int) and not isinstance(ref, bool)
    )
    return DeliveryResult(
        DELIVERED,
        response_digest=digest,
        remote_ref=str(ref) if plain else None,
        body=body.encode("utf-8"),
    )


class StdioServer:
    """An MCP server run as a child process, speaking newline-delimited
    JSON-RPC on its standard streams; a :data:`Call`.

    Started on the first call, and again after it dies. Calls are made one at
    a time.

    :param command: The server's command line.
    :param env: Its environment: the relay's own, when omitted, which is
        where the server's credentials live.
    """

    def __init__(self, command: Sequence[str], *, env: Mapping[str, str] | None = None) -> None:
        if not command or not all(isinstance(part, str) and part for part in command):
            raise ValueError("an MCP server's command is a non-empty list of strings")
        self._command = list(command)
        self._env = dict(env) if env is not None else None
        self._process: subprocess.Popen[bytes] | None = None
        self._lines: _Lines | None = None
        self._next = 0
        self._lock = threading.Lock()
        self._era: Era | None = None

    @property
    def era(self) -> Era | None:
        """The revision agreed with the running server (1.9.0); ``None`` before it starts."""
        return self._era

    def __call__(
        self, tool: str, arguments: Mapping[str, Any], timeout: float
    ) -> Mapping[str, Any]:
        with self._lock:
            process = self._started(timeout)
            era = self._era
            assert era is not None
            result = self._request(
                process,
                "tools/call",
                era.params({"name": tool, "arguments": dict(arguments)}, self._client()),
                timeout,
            )
            return result

    def _requester(self, process: subprocess.Popen[bytes]) -> Request:
        def request(method: str, params: Mapping[str, Any], seconds: float) -> Mapping[str, Any]:
            return self._live(process)._request(process, method, params, seconds)

        return request

    def _notifier(self, process: subprocess.Popen[bytes]) -> Callable[[str], None]:
        def notify(method: str) -> None:
            self._live(process)._write(process, {"jsonrpc": "2.0", "method": method})

        return notify

    def _live(self, process: subprocess.Popen[bytes]) -> StdioServer:
        """This server, if ``process`` is still the one it runs: a request to one
        that stopped is never sent."""
        if self._process is not process:
            raise McpCallError("the server stopped", sent=False)
        return self

    @staticmethod
    def _client() -> dict[str, str]:
        from interlock import __version__

        return {"name": "interlock-relay", "version": __version__}

    def close(self) -> None:
        with self._lock:
            self._stop()

    def _started(self, timeout: float) -> subprocess.Popen[bytes]:
        if self._process is not None and self._process.poll() is None:
            return self._process
        self._stop()
        for probe in (PROBE_SECONDS, 0.0):
            try:
                process = subprocess.Popen(  # noqa: S603 - the operator's own command
                    self._command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=None if self._env is None else {**os.environ, **self._env},
                )
            except OSError as exc:
                raise McpCallError(f"cannot run the server: {exc}", sent=False) from exc
            self._process = process
            assert process.stdout is not None
            self._lines = _Lines(process.stdout)
            try:
                self._era = handshake(
                    self._requester(process),
                    self._notifier(process),
                    self._client(),
                    timeout=timeout,
                    probe=probe,
                )
                return process
            except McpCallError as exc:
                died = self._process is None or process.poll() is not None
                self._stop()
                if probe and died:
                    continue  # the probe itself stopped it: start it again, and initialize
                # Nothing was asked of a tool yet, whatever the handshake did.
                raise McpCallError(f"the server did not start: {exc}", sent=False) from exc
        raise McpCallError("the server did not start", sent=False)  # pragma: no cover

    def _stop(self) -> None:
        process, self._process, self._lines = self._process, None, None
        if process is None:
            return
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    @staticmethod
    def _write(process: subprocess.Popen[bytes], message: Mapping[str, Any]) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        process.stdin.flush()

    def _request(
        self,
        process: subprocess.Popen[bytes],
        method: str,
        params: Mapping[str, Any],
        timeout: float,
    ) -> Mapping[str, Any]:
        self._next += 1
        ident = self._next
        try:
            self._write(
                process, {"jsonrpc": "2.0", "id": ident, "method": method, "params": params}
            )
        except OSError as exc:
            self._stop()
            raise McpCallError(f"the server's pipe is closed: {exc}", sent=False) from exc
        lines = self._lines
        assert lines is not None
        deadline = time.monotonic() + timeout
        while True:
            line = lines.readline(deadline - time.monotonic())
            if line is None:
                if method == "server/discover":
                    # A server that needs initialize may say nothing to a probe: it
                    # stays up, and the handshake falls back.
                    raise McpCallError(f"no answer to {method} within {timeout:g}s", sent=True)
                self._stop()
                raise McpCallError(f"no answer to {method} within {timeout:g}s", sent=True)
            if not line:
                self._stop()
                raise McpCallError(f"the server closed its pipe during {method}", sent=True)
            try:
                message = json.loads(line)
            except ValueError:
                continue  # not a message: a server's stray output
            if not isinstance(message, dict) or message.get("id") != ident:
                continue  # a notification, or a request of the server's own
            if "error" in message:
                error = message["error"]
                text = error.get("message") if isinstance(error, dict) else None
                code = error.get("code") if isinstance(error, dict) else None
                raise McpRefusedError(
                    str(text or "an error")[:200],
                    code=code if isinstance(code, int) else None,
                    data=error.get("data") if isinstance(error, dict) else None,
                )
            result = message.get("result")
            return result if isinstance(result, dict) else {}


class _Lines:
    """Lines read from a pipe by its descriptor. A buffered reader would take
    two lines into its buffer at once, and a ``select`` on the descriptor would
    then wait for a third that never comes."""

    def __init__(self, stream: IO[bytes]) -> None:
        self._fd = stream.fileno()
        self._buffer = b""

    def readline(self, seconds: float) -> bytes | None:
        """One line, ``b""`` at the end of the stream, or ``None`` when none
        came within ``seconds``."""
        deadline = time.monotonic() + seconds
        while b"\n" not in self._buffer:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready, _, _ = select.select([self._fd], [], [], left)
            if not ready:
                return None
            chunk = os.read(self._fd, 65536)
            if not chunk:
                line, self._buffer = self._buffer, b""
                return line
            self._buffer += chunk
            if len(self._buffer) > _MAX_LINE and b"\n" not in self._buffer:
                raise McpCallError("the server wrote a line too long to read", sent=True)
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line + b"\n"


def relay_adapter(endpoint: Any) -> McpAdapter:
    """The relay's adapter for an ``mcp`` sink's ``[[relay.endpoints]]``
    entry: its ``command``, ``tools`` where a tool's name is not its
    operation's, and ``numbers``, each operation's number arguments (1.9.0)."""
    settings: Mapping[str, Any] = endpoint.settings
    unknown = sorted(set(settings) - {"command", "tools", "numbers"})
    if unknown:
        raise ValueError(
            f"sink {endpoint.sink}: an mcp endpoint takes 'command', 'tools' and 'numbers', "
            f"not {', '.join(unknown)}"
        )
    command = settings.get("command")
    if not isinstance(command, list):
        raise ValueError(f"sink {endpoint.sink}: an mcp endpoint names its server's 'command'")
    tools = settings.get("tools", {})
    if not isinstance(tools, dict) or not all(isinstance(v, str) for v in tools.values()):
        raise ValueError(f"sink {endpoint.sink}: 'tools' maps an operation to a tool's name")
    numbers = settings.get("numbers", {})
    if not isinstance(numbers, dict) or not all(
        isinstance(v, list) and all(isinstance(p, str) for p in v) for v in numbers.values()
    ):
        raise ValueError(
            f"sink {endpoint.sink}: 'numbers' maps an operation to the paths of its number "
            f"arguments"
        )
    return McpAdapter(StdioServer(command), tools=tools, numbers=numbers)
