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

import hashlib
import json
import os
import select
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import IO, Any, Final

from agentgov.receipts.canonical import loads_strict

from interlock.outbound import DEAD_LETTER, OperationSpec, SinkSpec, placeholders
from interlock.relay import DELIVERED, PERMANENT, RETRYABLE, UNKNOWN, Delivery, DeliveryResult

__all__ = [
    "PROTOCOL_VERSION",
    "McpAdapter",
    "McpCallError",
    "McpRefusedError",
    "StdioServer",
    "classify",
    "mcp_sink",
    "relay_adapter",
]

PROTOCOL_VERSION: Final = "2025-06-18"
"""The MCP revision a :class:`StdioServer` asks for."""

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
    """The server answered the call with a JSON-RPC error: it did not run it."""

    def __init__(self, message: str) -> None:
        super().__init__(message, sent=True)


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
    """

    __slots__ = ("_call", "_tools")

    def __init__(self, call: Call, *, tools: Mapping[str, str] | None = None) -> None:
        self._call = call
        self._tools = dict(tools or {})

    def send(self, delivery: Delivery) -> DeliveryResult:
        payload = loads_strict(delivery.payload)
        if not isinstance(payload, Mapping) or placeholders(payload):
            return DeliveryResult(
                PERMANENT,
                detail="the payload is no object of arguments, or holds an unbound placeholder",
            )
        tool = self._tools.get(delivery.operation, delivery.operation)
        try:
            result = self._call(tool, payload, delivery.timeout)
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
    """A ``tools/call`` result, classified."""
    body = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if result.get("isError") is True:
        return DeliveryResult(
            PERMANENT, response_digest=digest, detail="the tool reported an error"
        )
    structured = result.get("structuredContent")
    ref = structured.get("id") if isinstance(structured, Mapping) else None
    plain = (isinstance(ref, str) and 0 < len(ref) <= _REF) or (
        isinstance(ref, int) and not isinstance(ref, bool)
    )
    return DeliveryResult(DELIVERED, response_digest=digest, remote_ref=str(ref) if plain else None)


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

    def __call__(
        self, tool: str, arguments: Mapping[str, Any], timeout: float
    ) -> Mapping[str, Any]:
        with self._lock:
            process = self._started(timeout)
            result = self._request(
                process, "tools/call", {"name": tool, "arguments": dict(arguments)}, timeout
            )
            return result

    def close(self) -> None:
        with self._lock:
            self._stop()

    def _started(self, timeout: float) -> subprocess.Popen[bytes]:
        if self._process is not None and self._process.poll() is None:
            return self._process
        self._stop()
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
        from interlock import __version__

        self._process = process
        assert process.stdout is not None
        self._lines = _Lines(process.stdout)
        try:
            self._request(
                process,
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "interlock-relay", "version": __version__},
                },
                timeout,
            )
            self._write(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        except McpCallError as exc:
            self._stop()
            # Nothing was asked of a tool yet, whatever the handshake did.
            raise McpCallError(f"the server did not start: {exc}", sent=False) from exc
        return process

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
                raise McpRefusedError(str(text or "an error")[:200])
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
    entry: its ``command``, and ``tools`` where a tool's name is not its
    operation's."""
    settings: Mapping[str, Any] = endpoint.settings
    unknown = sorted(set(settings) - {"command", "tools"})
    if unknown:
        raise ValueError(
            f"sink {endpoint.sink}: an mcp endpoint takes 'command' and 'tools', "
            f"not {', '.join(unknown)}"
        )
    command = settings.get("command")
    if not isinstance(command, list):
        raise ValueError(f"sink {endpoint.sink}: an mcp endpoint names its server's 'command'")
    tools = settings.get("tools", {})
    if not isinstance(tools, dict) or not all(isinstance(v, str) for v in tools.values()):
        raise ValueError(f"sink {endpoint.sink}: 'tools' maps an operation to a tool's name")
    return McpAdapter(StdioServer(command), tools=tools)
