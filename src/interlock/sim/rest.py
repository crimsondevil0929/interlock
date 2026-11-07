"""A JSON REST API on loopback, with the automation rules SaaS systems run (1.5.0).

Enough of the REST conventions ticketing, CRM and HR systems share for a class V substrate
(:mod:`interlock.rest`) to run against over the real wire protocol, with no vendor account:

- ``GET {base}/{collection}/{id}``: the resource, with a strong ``ETag`` of its ``version``;
- ``GET {base}/{collection}?field=value``: ``{"data": [...], "next": <url or null>}``, a page at a
  time (``page_size``, ``cursor``). A filter the collection does not declare is refused
  (``400``), never ignored: a list that silently matched everything would widen a read-back;
- ``PATCH {base}/{collection}/{id}``: a JSON merge patch (RFC 7386);
- ``PUT {base}/{collection}/{id}``: a full replacement, or a create at a client-assigned id
  (``If-None-Match: *`` refuses one that exists);
- ``POST {base}/{collection}``: a create at a server-assigned id;
- ``DELETE {base}/{collection}/{id}``;
- conditional writes: ``If-Match`` with the ``ETag`` read answers ``412 Precondition Failed`` when
  the resource has moved on; a body naming a stale ``version`` answers ``409 Conflict``. With
  ``require_if_match``, an unconditional update answers ``428``;
- every write stamps ``version``, ``updated_at`` and ``updated_by``, and ``last_request``: the
  ``X-Request-Id`` of the request that wrote it, as many APIs expose a request or change id. A
  rule's writes carry the id of the request that set the rule off;
- rules (:class:`Rule`): what the system does after a client's write, as a workflow automation
  does: escalate a ticket set to ``urgent``, close a parent's children, reassign on a field
  change. A rule's writes are the system's own (actor ``automation``);
- bearer tokens, each an actor;
- an audit log: one entry per write, refused writes too, as JSON lines
  (:meth:`LoopbackRestServer.audit_log`);
- faults: :meth:`LoopbackRestServer.fail_next` makes the next write to one resource fail.

Not modeled: authentication beyond bearer tokens, rate limits, field-level permissions, bulk
endpoints, webhooks. Everything lives in memory.
"""

from __future__ import annotations

import copy
import itertools
import json
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit

__all__ = [
    "AUTOMATION_ACTOR",
    "Change",
    "Collection",
    "LoopbackRestServer",
    "Rule",
    "RuleContext",
]

JSON = dict[str, Any]

AUTOMATION_ACTOR: Final = "automation"
"""The actor a rule's writes are logged under: the system itself."""

MANAGED: Final = ("version", "updated_at", "updated_by", "last_request")
"""The fields the server writes on every resource, whatever a client sends."""


@dataclass(frozen=True, slots=True)
class Collection:
    """One collection the server holds.

    :ivar name: Its URL segment: ``tickets``.
    :ivar filters: The fields a list may filter on, each a dotted path.
    :ivar prefix: What a server-assigned id starts with.
    """

    name: str
    filters: tuple[str, ...] = ()
    prefix: str = ""
    page_size: int = 50


@dataclass(frozen=True, slots=True)
class Change:
    """One write the server made: what a rule is shown.

    :ivar collection: The collection.
    :ivar before: The resource as it was, or ``None`` for a create.
    :ivar after: The resource as stored, or ``None`` for a deletion.
    :ivar actor: Who wrote it.
    :ivar request_id: The request's ``X-Request-Id``, if it sent one.
    """

    collection: str
    before: JSON | None
    after: JSON | None
    actor: str
    request_id: str | None


class RuleContext:
    """What a rule may do: read and list the server, and write as itself."""

    def __init__(self, server: LoopbackRestServer, change: Change) -> None:
        self._server = server
        self._change = change

    def get(self, collection: str, resource_id: str) -> JSON | None:
        return self._server.get(collection, resource_id)

    def find(self, collection: str, **filters: str) -> list[JSON]:
        return self._server.find(collection, **filters)

    def write(self, collection: str, resource: Mapping[str, Any]) -> JSON:
        """Store ``resource`` (an update, or a create when it has no id), as the system's own
        write, carrying the request that set the rule off."""
        return self._server._store(
            collection,
            dict(resource),
            actor=AUTOMATION_ACTOR,
            request_id=self._change.request_id,
            rules=False,
            method="RULE",
        )


Rule = Callable[[RuleContext, Change], None]
"""Run after each write a client made (not after a rule's own)."""


class _RefusedError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def body(self) -> JSON:
        return {"error": {"status": self.code, "message": self.message}}


def field_value(document: Any, path: str) -> Any:
    """The value at a dotted ``path``, or ``None``."""
    current = document
    for part in path.split("."):
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


def merge_patch(target: Any, patch: Any) -> Any:
    """RFC 7386 JSON Merge Patch."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result = copy.deepcopy(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = merge_patch(result.get(key), value)
    return result


@dataclass
class _Stored:
    versions: list[JSON] = field(default_factory=list)
    deleted: bool = False


class LoopbackRestServer:
    """The REST API (module docstring). Start it, use :attr:`url`, stop it.

    :param collections: What the server holds.
    :param tokens: Bearer token to actor. Empty admits anyone, as ``anonymous``.
    :param rules: What the server does after each client write, in order.
    :param require_if_match: Refuse an update or a deletion that names no version
        (``428 Precondition Required``).
    """

    def __init__(
        self,
        collections: Iterable[Collection],
        *,
        tokens: Mapping[str, str] | None = None,
        rules: Iterable[Rule] = (),
        require_if_match: bool = False,
    ) -> None:
        self._collections = {c.name: c for c in collections}
        self._tokens = dict(tokens or {})
        self._rules = list(rules)
        self._require_if_match = require_if_match
        self._resources: dict[tuple[str, str], _Stored] = {}
        self._ids = itertools.count(1)
        self._events = itertools.count(1)
        self._lock = threading.RLock()
        self._audit: list[JSON] = []
        self._faults: dict[tuple[str, str], int] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.requests: list[tuple[str, str]] = []
        """Every request served: method and path with query."""

    # -- running --------------------------------------------------------------

    def start(self) -> str:
        """Serve on a free loopback port; the base URL."""
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                code, answer, headers = server._handle(
                    self.command, self.path, body, dict(self.headers.items())
                )
                data = b"" if answer is None else json.dumps(answer).encode("utf-8")
                self.send_response(code)
                if answer is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                self._serve()

            def do_POST(self) -> None:
                self._serve()

            def do_PUT(self) -> None:
                self._serve()

            def do_PATCH(self) -> None:
                self._serve()

            def do_DELETE(self) -> None:
                self._serve()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("the loopback REST server is not started")
        host, port = self._server.server_address[:2]
        shown = host.decode() if isinstance(host, bytes) else host
        return f"http://{shown}:{port}/api"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> LoopbackRestServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- direct access, for seeding and for tests ------------------------------------

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            self._rules.append(rule)

    def seed(self, collection: str, resource: Mapping[str, Any]) -> JSON:
        """Store a resource as version 1, with no audit and no rule."""
        with self._lock:
            document = copy.deepcopy(dict(resource))
            if not document.get("id"):
                document["id"] = self._new_id(collection)
            stored = self._stamp(document, 1, "seed", None)
            self._resources[(collection, str(document["id"]))] = _Stored([stored])
            return copy.deepcopy(stored)

    def get(self, collection: str, resource_id: str) -> JSON | None:
        with self._lock:
            found = self._resources.get((collection, resource_id))
            if found is None or found.deleted:
                return None
            return copy.deepcopy(found.versions[-1])

    def history(self, collection: str, resource_id: str) -> list[JSON]:
        with self._lock:
            found = self._resources.get((collection, resource_id))
            return copy.deepcopy(found.versions) if found is not None else []

    def find(self, collection: str, **filters: str) -> list[JSON]:
        """Every resource of ``collection`` matching ``filters``, as the API's list answers."""
        with self._lock:
            return self._matching(collection, list(filters.items()))

    def write(self, collection: str, resource: Mapping[str, Any], *, actor: str = "person") -> JSON:
        """Store ``resource`` as a person using the vendor's own UI would: no request id, no
        rule."""
        with self._lock:
            return self._store(
                collection, dict(resource), actor=actor, request_id=None, rules=False, method="UI"
            )

    def fail_next(self, collection: str, resource_id: str, code: int = 500) -> None:
        with self._lock:
            self._faults[(collection, resource_id)] = code

    def audit_events(self) -> list[JSON]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def audit_log(self) -> str:
        """The audit log as JSON lines."""
        return "".join(json.dumps(e, sort_keys=True) + "\n" for e in self.audit_events())

    # -- the API ------------------------------------------------------------------------

    def _handle(
        self, method: str, raw_path: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[int, JSON | None, dict[str, str]]:
        self.requests.append((method, raw_path))
        given = {k.lower(): v for k, v in headers.items()}
        request_id = given.get("x-request-id") or None
        parts = urlsplit(raw_path)
        segments = [s for s in parts.path.split("/") if s]
        if segments[:1] == ["api"]:
            segments = segments[1:]
        try:
            actor = self._actor(given)
            if not segments or segments[0] not in self._collections or len(segments) > 2:
                raise _RefusedError(404, f"there is no {parts.path}")
            name = segments[0]
            target = segments[1] if len(segments) == 2 else None
            with self._lock:
                if method == "GET":
                    if target is None:
                        return 200, self._page(name, parts.query), {}
                    found = self.get(name, target)
                    if found is None:
                        raise _RefusedError(404, f"{name}/{target} is not known")
                    return 200, found, {"ETag": _etag(found)}
                if method == "DELETE":
                    if target is None:
                        raise _RefusedError(405, "DELETE names one resource")
                    current = self._precondition(name, target, given, method)
                    if current is None:
                        raise _RefusedError(404, f"{name}/{target} is not known")
                    self._delete(name, target, actor=actor, request_id=request_id)
                    return 204, None, {}
                if method not in ("PUT", "PATCH", "POST"):
                    raise _RefusedError(405, f"{method} is not supported here")
                try:
                    document = json.loads(body) if body else {}
                except json.JSONDecodeError as exc:
                    raise _RefusedError(400, f"the body is not JSON: {exc}") from None
                if not isinstance(document, dict):
                    raise _RefusedError(400, "the body is not a JSON object")
                if method == "POST":
                    if target is not None:
                        raise _RefusedError(405, f"POST creates at /{name}")
                    document.pop("id", None)
                    stored = self._client_store(name, None, document, actor, request_id, 201)
                    return (
                        201,
                        stored,
                        {"ETag": _etag(stored), "Location": f"{name}/{stored['id']}"},
                    )
                if target is None:
                    raise _RefusedError(405, f"{method} names one resource: /{name}/<id>")
                current = self._precondition(name, target, given, method)
                if method == "PATCH":
                    if current is None:
                        raise _RefusedError(404, f"{name}/{target} is not known")
                    self._stale_body(name, target, current, document)
                    document.pop("id", None)
                    merged = merge_patch(current, document)
                    merged["id"] = target
                    stored = self._client_store(name, target, merged, actor, request_id, 200)
                    return 200, stored, {"ETag": _etag(stored)}
                if document.get("id", target) != target:
                    raise _RefusedError(400, "a PUT names its resource's id in the URL and body")
                if current is not None:
                    self._stale_body(name, target, current, document)
                document["id"] = target
                code = 200 if current is not None else 201
                stored = self._client_store(name, target, document, actor, request_id, code)
                return code, stored, {"ETag": _etag(stored)}
        except _RefusedError as refused:
            return refused.code, refused.body(), {}

    def _client_store(
        self,
        name: str,
        target: str | None,
        document: JSON,
        actor: str,
        request_id: str | None,
        code: int,
    ) -> JSON:
        try:
            return self._store(
                name, document, actor=actor, request_id=request_id, rules=True, method="WRITE"
            )
        except _RefusedError as refused:
            self._log(name, target, "WRITE", actor, request_id, None, refused.code)
            raise

    def _actor(self, headers: Mapping[str, str]) -> str:
        if not self._tokens:
            return "anonymous"
        token = headers.get("authorization", "").removeprefix("Bearer ").strip()
        actor = self._tokens.get(token)
        if actor is None:
            raise _RefusedError(401, "a bearer token the server knows is required")
        return actor

    def _precondition(
        self, name: str, target: str, headers: Mapping[str, str], method: str
    ) -> JSON | None:
        """``If-Match`` and ``If-None-Match`` against what is stored: the current resource, or a
        refusal, which is audited."""
        current = self.get(name, target)
        if_match = headers.get("if-match")
        problem: _RefusedError | None = None
        if headers.get("if-none-match", "").strip() == "*" and current is not None:
            problem = _RefusedError(412, f"{name}/{target} already exists")
        elif if_match is not None:
            if current is None or if_match.strip() not in (_etag(current), "*"):
                found = "none" if current is None else _etag(current)
                problem = _RefusedError(
                    412,
                    f"{name}/{target} is at {found}, not {if_match.strip()}: it changed since "
                    f"it was read",
                )
        elif current is not None and self._require_if_match and method != "PUT-CREATE":
            problem = _RefusedError(428, f"a write to {name} names the version it read (If-Match)")
        if problem is not None:
            self._log(name, target, method, "", headers.get("x-request-id"), None, problem.code)
            raise problem
        return current

    def _stale_body(self, name: str, target: str, current: JSON, document: JSON) -> None:
        stated = document.get("version")
        if stated is not None and stated != current.get("version"):
            self._log(name, target, "WRITE", "", None, None, 409)
            raise _RefusedError(
                409,
                f"{name}/{target} is at version {current.get('version')}, not {stated}: it changed "
                f"since it was read",
            )

    def _new_id(self, name: str) -> str:
        prefix = self._collections[name].prefix or name[:3]
        return f"{prefix}-{next(self._ids)}"

    def _store(
        self,
        name: str,
        document: JSON,
        *,
        actor: str,
        request_id: str | None,
        rules: bool,
        method: str,
    ) -> JSON:
        if name not in self._collections:
            raise _RefusedError(400, f"the server holds no {name}")
        if not document.get("id"):
            document["id"] = self._new_id(name)
        key = (name, str(document["id"]))
        fault = self._faults.pop(key, None)
        if fault is not None:
            raise _RefusedError(fault, f"{name}/{document['id']} could not be written")
        stored_at = self._resources.setdefault(key, _Stored())
        before = (
            copy.deepcopy(stored_at.versions[-1])
            if stored_at.versions and not stored_at.deleted
            else None
        )
        version = (int(stored_at.versions[-1]["version"]) if stored_at.versions else 0) + 1
        stored = self._stamp(copy.deepcopy(document), version, actor, request_id)
        stored_at.versions.append(stored)
        stored_at.deleted = False
        self._log(name, key[1], method, actor, request_id, stored, 200 if before else 201)
        if rules:
            change = Change(name, before, copy.deepcopy(stored), actor, request_id)
            for rule in list(self._rules):
                rule(RuleContext(self, change), change)
        return copy.deepcopy(stored)

    def _delete(self, name: str, target: str, *, actor: str, request_id: str | None) -> None:
        stored_at = self._resources[(name, target)]
        before = copy.deepcopy(stored_at.versions[-1])
        stored_at.deleted = True
        self._log(name, target, "DELETE", actor, request_id, None, 204)
        change = Change(name, before, None, actor, request_id)
        for rule in list(self._rules):
            rule(RuleContext(self, change), change)

    @staticmethod
    def _stamp(document: JSON, version: int, actor: str, request_id: str | None) -> JSON:
        for name in MANAGED:
            document.pop(name, None)
        document["version"] = version
        document["updated_at"] = _now()
        document["updated_by"] = actor
        document["last_request"] = request_id
        return document

    def _page(self, name: str, query: str) -> JSON:
        pairs = parse_qsl(query, keep_blank_values=True)
        size = self._collections[name].page_size
        cursor = 0
        filters = []
        for key, value in pairs:
            if key == "page_size":
                size = max(1, min(int(value), 500))
            elif key == "cursor":
                cursor = int(value)
            else:
                filters.append((key, value))
        found = self._matching(name, filters)
        page = found[cursor : cursor + size]
        following = None
        if cursor + size < len(found):
            following = f"/{name}?" + urlencode(
                [*filters, ("page_size", size), ("cursor", cursor + size)]
            )
        return {"data": page, "next": following}

    def _matching(self, name: str, filters: Sequence[tuple[str, str]]) -> list[JSON]:
        allowed = set(self._collections[name].filters) | {"id"}
        found = [
            copy.deepcopy(s.versions[-1])
            for (kind, _), s in sorted(self._resources.items())
            if kind == name and not s.deleted
        ]
        for key, value in filters:
            if key not in allowed:
                raise _RefusedError(400, f"{name} cannot be filtered on {key!r}")
            wanted = value.split(",")
            found = [r for r in found if str(field_value(r, key)) in wanted]
        return found

    def _log(
        self,
        name: str,
        target: str | None,
        method: str,
        actor: str,
        request_id: str | None,
        stored: JSON | None,
        code: int,
    ) -> None:
        self._audit.append(
            {
                "id": f"evt-{next(self._events)}",
                "at": _now(),
                "actor": actor or "unknown",
                "action": method.lower(),
                "resource": f"{name}/{target}" if target else name,
                "version": None if stored is None else stored.get("version"),
                "status": code,
                "request_id": request_id,
            }
        )


def _etag(resource: Mapping[str, Any]) -> str:
    return f'"{resource.get("version")}"'


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
