"""A FHIR R4 server on loopback, with the rules a clinical system runs (1.4.0).

Enough of FHIR's RESTful API for a class V substrate (:mod:`interlock.fhir`)
to run against over the real wire protocol, with no EHR and no credentials:

- ``GET [base]/[type]/[id]``, with ``meta.versionId`` and a weak ``ETag``;
- ``GET [base]/[type]?param=value``: a ``searchset`` Bundle. Each type has
  the search parameters :data:`SEARCH` gives it (``_id`` for all); a
  reference parameter matches ``Type/id`` or the bare id; ``_has:T:ref:param``
  reverse-chains, as R4 defines it. An unknown parameter is refused (``400``),
  never ignored: a search that silently matched everything would resolve a
  conditional reference to the wrong patient;
- ``PUT [base]/[type]/[id]``: an update, or a create at a client-assigned id
  ("update as create"). ``If-Match: W/"<versionId>"`` makes it conditional:
  ``412 Precondition Failed`` when the resource has moved on;
- ``POST [base]/[type]``: a create at a server-assigned id;
- no ``DELETE``: ``405``. A clinical record is never deleted; a wrong one is
  marked ``entered-in-error``;
- rules (:class:`Rule`): what the server does after a write, as a clinical
  decision support hook or an interface engine would: stop a whole
  encounter's orders, open a pharmacy task. A rule's writes are the
  server's own (actor ``ehr-rules``), logged with the request that set them
  off;
- ``meta.source``: each version names the request that wrote it
  (``#<X-Request-Id>``), as HAPI FHIR records it; a rule's writes name the
  request that set the rule off;
- bearer tokens, each an actor;
- an audit log: one R4 ``AuditEvent`` per write, refused writes too (outcome
  ``4``), each entity carrying the request's ``X-Request-Id``, as NDJSON
  (:meth:`LoopbackFhirServer.audit_log`), which ``agentgov reconcile-actions
  --format fhir-auditevent`` reads;
- faults: :meth:`LoopbackFhirServer.fail_next` makes the next write to one
  resource fail.

Not modeled: ``_history`` over HTTP, transactions and batches, ``PATCH``,
paging (a search answers every match), profiles and validation beyond the
resource's type and id, SMART scopes. Every resource lives in memory.
"""

from __future__ import annotations

import copy
import itertools
import json
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final
from urllib.parse import parse_qsl, urlsplit

__all__ = [
    "RULES_ACTOR",
    "SEARCH",
    "Change",
    "LoopbackFhirServer",
    "Rule",
    "RuleContext",
]

JSON = dict[str, Any]

RULES_ACTOR: Final = "ehr-rules"
"""The actor a rule's writes are logged under: the server itself."""

SEARCH: Final[Mapping[str, Mapping[str, str]]] = {
    "Patient": {"identifier": "identifier.value"},
    "Organization": {"identifier": "identifier.value"},
    "Location": {"identifier": "identifier.value"},
    "Encounter": {
        "patient": "subject.reference",
        "subject": "subject.reference",
        "location": "location.location.reference",
        "status": "status",
        "service-provider": "serviceProvider.reference",
    },
    "MedicationRequest": {
        "patient": "subject.reference",
        "subject": "subject.reference",
        "encounter": "encounter.reference",
        "status": "status",
    },
    "MedicationAdministration": {
        "patient": "subject.reference",
        "subject": "subject.reference",
        "request": "request.reference",
        "status": "status",
    },
    "Task": {
        "patient": "for.reference",
        "subject": "for.reference",
        "focus": "focus.reference",
        "status": "status",
        "code": "code.coding.code",
    },
}
"""Each type's search parameters, and the path each reads (R4's own names).
A path through a list reads every item of it."""

_REFERENCE_PARAMS: Final = frozenset(
    {"patient", "subject", "location", "service-provider", "encounter", "request", "focus"}
)


@dataclass(frozen=True, slots=True)
class Change:
    """One write the server made: what a rule is shown.

    :ivar resource_type: The resource's type.
    :ivar before: The resource as it was, or ``None`` for a create.
    :ivar after: The resource as stored, ``meta`` included.
    :ivar actor: Who wrote it.
    :ivar request_id: The request's ``X-Request-Id``, if it sent one.
    """

    resource_type: str
    before: JSON | None
    after: JSON
    actor: str
    request_id: str | None


class RuleContext:
    """What a rule may do: read and search the server, and write as itself."""

    def __init__(self, server: LoopbackFhirServer, change: Change) -> None:
        self._server = server
        self._change = change

    def get(self, resource_type: str, resource_id: str) -> JSON | None:
        return self._server.get(resource_type, resource_id)

    def search(self, resource_type: str, **params: str) -> list[JSON]:
        return self._server.search(resource_type, **params)

    def write(self, resource: Mapping[str, Any]) -> JSON:
        """Store ``resource`` (an update, or a create when it has no id), as
        the server's own write, logged with the request that set the rule off."""
        return self._server._store(
            dict(resource),
            actor=RULES_ACTOR,
            request_id=self._change.request_id,
            rules=False,
        )


Rule = Callable[[RuleContext, Change], None]
"""Run after each write a client made (not after a rule's own)."""


class _RefusedError(Exception):
    def __init__(self, code: int, message: str, issue: str = "processing") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.issue = issue

    def outcome(self) -> JSON:
        return {
            "resourceType": "OperationOutcome",
            "issue": [{"severity": "error", "code": self.issue, "diagnostics": self.message}],
        }


def values(document: Any, path: str) -> list[Any]:
    """Every value at a dotted ``path``: a list on the way is read item by
    item, and a numeric segment indexes one."""
    found = [document]
    for part in path.split("."):
        step: list[Any] = []
        for item in found:
            if isinstance(item, list):
                if part.isdigit():
                    if int(part) < len(item):
                        step.append(item[int(part)])
                    continue
                step.extend(
                    i[part] for i in item if isinstance(i, Mapping) and i.get(part) is not None
                )
            elif isinstance(item, Mapping) and item.get(part) is not None:
                step.append(item[part])
        found = []
        for item in step:
            found.extend(item if isinstance(item, list) and not part.isdigit() else [item])
    return found


class LoopbackFhirServer:
    """The FHIR server (module docstring). Start it, use :attr:`url`, stop it.

    :param types: The resource types served.
    :param tokens: Bearer token to actor. Empty admits anyone, as ``anonymous``.
    :param rules: What the server does after each client write, in order.
    :param search: Each type's search parameters (:data:`SEARCH` by default).
    :param require_if_match: Refuse an update that names no version
        (``428 Precondition Required``), as a server that demands
        version-aware updates does.
    :param sources: Record the request that wrote each version in
        ``meta.source``. ``False`` is HAPI FHIR's default: no version says
        which request wrote it.
    """

    def __init__(
        self,
        types: Iterable[str] = (
            "Patient",
            "Organization",
            "Location",
            "Encounter",
            "MedicationRequest",
            "MedicationAdministration",
            "Task",
        ),
        *,
        tokens: Mapping[str, str] | None = None,
        rules: Iterable[Rule] = (),
        search: Mapping[str, Mapping[str, str]] = SEARCH,
        require_if_match: bool = False,
        sources: bool = True,
    ) -> None:
        self._types = frozenset(types)
        self._tokens = dict(tokens or {})
        self._rules = list(rules)
        self._search = {t: dict(search.get(t, {})) for t in self._types}
        self._require_if_match = require_if_match
        self._sources = sources
        self._resources: dict[tuple[str, str], list[JSON]] = {}
        self._ids = itertools.count(1)
        self._audits = itertools.count(1)
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
                data = json.dumps(answer).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/fhir+json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve  # noqa: N815

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("the loopback FHIR server is not started")
        host, port = self._server.server_address[:2]
        shown = host.decode() if isinstance(host, bytes) else host
        return f"http://{shown}:{port}/fhir"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> LoopbackFhirServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- direct access, for seeding and for tests -----------------------------------

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            self._rules.append(rule)

    def seed(self, resource: Mapping[str, Any]) -> JSON:
        """Store a resource as version 1, with no audit and no rule."""
        with self._lock:
            body = copy.deepcopy(dict(resource))
            kind = str(body.get("resourceType"))
            if kind not in self._types or not body.get("id"):
                raise ValueError(f"seed a served type with an id, not {kind}/{body.get('id')}")
            stored = self._stamp(body, 1)
            self._resources[(kind, str(body["id"]))] = [stored]
            return copy.deepcopy(stored)

    def get(self, resource_type: str, resource_id: str) -> JSON | None:
        with self._lock:
            found = self._resources.get((resource_type, resource_id))
            return copy.deepcopy(found[-1]) if found else None

    def history(self, resource_type: str, resource_id: str) -> list[JSON]:
        """Every version of a resource, oldest first."""
        with self._lock:
            return copy.deepcopy(self._resources.get((resource_type, resource_id), []))

    def search(self, resource_type: str, **params: str) -> list[JSON]:
        """What ``GET [type]?params`` would answer, as resources."""
        with self._lock:
            return self._matching(resource_type, list(params.items()))

    def write(
        self, resource: Mapping[str, Any], *, actor: str, request_id: str | None = None
    ) -> JSON:
        """A write by someone at the server, not through its API (a nurse at
        the bedside, an interface): stored, audited, and shown to the rules."""
        with self._lock:
            return self._store(dict(resource), actor=actor, request_id=request_id, rules=True)

    def fail_next(self, resource_type: str, resource_id: str, code: int = 500) -> None:
        """The next write to this resource fails with ``code``."""
        with self._lock:
            self._faults[(resource_type, resource_id)] = code

    def audit_events(self) -> list[JSON]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def audit_log(self) -> str:
        """The audit log as NDJSON: one ``AuditEvent`` per line."""
        return "".join(json.dumps(e, sort_keys=True) + "\n" for e in self.audit_events())

    # -- the API --------------------------------------------------------------------

    def _handle(
        self, method: str, raw_path: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[int, JSON, dict[str, str]]:
        self.requests.append((method, raw_path))
        given = {k.lower(): v for k, v in headers.items()}
        request_id = given.get("x-request-id") or None
        parts = urlsplit(raw_path)
        segments = [s for s in parts.path.split("/") if s]
        if segments[:1] == ["fhir"]:
            segments = segments[1:]
        try:
            actor = self._actor(given)
            if not segments or segments[0] not in self._types or len(segments) > 2:
                raise _RefusedError(404, f"the server has no {parts.path}", "not-found")
            kind = segments[0]
            target = segments[1] if len(segments) == 2 else None
            with self._lock:
                if method == "GET":
                    if target is None:
                        query = parse_qsl(parts.query, keep_blank_values=True)
                        found = self._matching(kind, query)
                        return 200, _bundle(found), {}
                    versions = self._resources.get((kind, target))
                    if not versions:
                        raise _RefusedError(404, f"{kind}/{target} is not known", "not-found")
                    return 200, copy.deepcopy(versions[-1]), {"ETag": _etag(versions[-1])}
                if method == "DELETE":
                    raise _RefusedError(
                        405,
                        "this server never deletes a clinical record: mark it "
                        "entered-in-error instead",
                        "not-supported",
                    )
                if method not in ("PUT", "POST"):
                    raise _RefusedError(405, f"{method} is not supported here", "not-supported")
                try:
                    document = json.loads(body) if body else {}
                except json.JSONDecodeError as exc:
                    raise _RefusedError(400, f"the body is not JSON: {exc}", "structure") from None
                if not isinstance(document, dict) or document.get("resourceType") != kind:
                    raise _RefusedError(400, f"the body is not a {kind}", "structure")
                if method == "POST":
                    if target is not None:
                        raise _RefusedError(405, "POST creates at [base]/[type]", "not-supported")
                    document.pop("id", None)
                elif target is None or document.get("id") != target:
                    raise _RefusedError(
                        400, "an update names its resource's id in the URL and body"
                    )
                code = self._precondition(kind, target, given.get("if-match"))
                try:
                    stored = self._store(document, actor=actor, request_id=request_id, rules=True)
                except _RefusedError as refused:
                    self._log(kind, target, method, actor, request_id, None, refused.code)
                    raise
                headers_out = {
                    "ETag": _etag(stored),
                    "Location": f"{kind}/{stored['id']}/_history/{stored['meta']['versionId']}",
                }
                return code, copy.deepcopy(stored), headers_out
        except _RefusedError as refused:
            return refused.code, refused.outcome(), {}

    def _actor(self, headers: Mapping[str, str]) -> str:
        if not self._tokens:
            return "anonymous"
        token = headers.get("authorization", "").removeprefix("Bearer ").strip()
        actor = self._tokens.get(token)
        if actor is None:
            raise _RefusedError(401, "a bearer token the server knows is required", "login")
        return actor

    def _precondition(self, kind: str, target: str | None, if_match: str | None) -> int:
        """``If-Match`` against the stored version: the status a write
        answers (``201`` for a create), or a refusal, which is audited."""
        stored = self._resources.get((kind, target)) if target is not None else None
        problem: _RefusedError | None = None
        if if_match is not None:
            if stored is None or if_match.strip() != _etag(stored[-1]):
                found = "none" if stored is None else _etag(stored[-1])
                problem = _RefusedError(
                    412,
                    f"{kind}/{target} is at version {found}, not {if_match.strip()}: it "
                    f"changed since it was read",
                    "conflict",
                )
        elif stored is not None and self._require_if_match:
            problem = _RefusedError(
                428, f"an update of {kind} names the version it read (If-Match)"
            )
        if problem is not None:
            self._log(kind, target, "PUT", "", None, None, problem.code)
            raise problem
        return 200 if stored is not None else 201

    def _store(self, document: JSON, *, actor: str, request_id: str | None, rules: bool) -> JSON:
        kind = str(document.get("resourceType"))
        if kind not in self._types:
            raise _RefusedError(400, f"the server does not hold {kind}")
        if not document.get("id"):
            document["id"] = f"{kind[:3].lower()}-{next(self._ids)}"
        key = (kind, str(document["id"]))
        fault = self._faults.pop(key, None)
        if fault is not None:
            raise _RefusedError(fault, f"{kind}/{document['id']} could not be written", "exception")
        versions = self._resources.setdefault(key, [])
        before = copy.deepcopy(versions[-1]) if versions else None
        stored = self._stamp(copy.deepcopy(document), len(versions) + 1)
        if self._sources:
            stored["meta"]["source"] = f"#{request_id or f'srv-{next(self._ids)}'}"
        versions.append(stored)
        method = "PUT" if before is not None else "POST"
        self._log(kind, key[1], method, actor, request_id, stored, 200 if before else 201)
        if rules:
            change = Change(kind, before, copy.deepcopy(stored), actor, request_id)
            for rule in list(self._rules):
                rule(RuleContext(self, change), change)
        return copy.deepcopy(stored)

    @staticmethod
    def _stamp(document: JSON, version: int) -> JSON:
        meta = dict(document.get("meta") or {})
        meta["versionId"] = str(version)
        meta["lastUpdated"] = _now()
        document["meta"] = meta
        return document

    def _matching(self, kind: str, query: Sequence[tuple[str, str]]) -> list[JSON]:
        if kind not in self._types:
            raise _RefusedError(404, f"the server has no {kind}", "not-found")
        found = [copy.deepcopy(v[-1]) for (k, _), v in sorted(self._resources.items()) if k == kind]
        for name, value in query:
            if name.startswith("_has:"):
                found = [r for r in found if self._has(kind, r, name, value)]
            else:
                found = [r for r in found if self._matches(kind, r, name, value)]
        return found

    def _matches(self, kind: str, resource: JSON, name: str, value: str) -> bool:
        if name in ("_count", "_sort", "_format"):
            return True
        if name == "_id":
            return str(resource.get("id")) in value.split(",")
        path = self._search.get(kind, {}).get(name)
        if path is None:
            raise _RefusedError(400, f"{kind} has no search parameter {name!r}", "not-supported")
        wanted = value.split(",")
        for found in values(resource, path):
            text = str(found)
            if name in _REFERENCE_PARAMS:
                if text in wanted or text.rsplit("/", 1)[-1] in wanted:
                    return True
            elif text in wanted:
                return True
        return False

    def _has(self, kind: str, resource: JSON, name: str, value: str) -> bool:
        """``_has:Type:reference:param=value``: some ``Type`` whose ``param``
        is ``value`` points at this resource through ``reference``."""
        parts = name.split(":")
        if len(parts) != 4 or parts[1] not in self._types:
            raise _RefusedError(
                400, f"{name} is not _has:Type:reference:parameter", "not-supported"
            )
        _, other, reference, parameter = parts
        path = self._search.get(other, {}).get(reference)
        if path is None:
            raise _RefusedError(
                400, f"{other} has no search parameter {reference!r}", "not-supported"
            )
        here = f"{kind}/{resource.get('id')}"
        for candidate in self._matching(other, [(parameter, value)]):
            if here in [str(v) for v in values(candidate, path)]:
                return True
        return False

    def _log(
        self,
        kind: str,
        target: str | None,
        method: str,
        actor: str,
        request_id: str | None,
        stored: JSON | None,
        code: int,
    ) -> None:
        created = method == "POST" or code == 201
        what = f"{kind}/{target}" if target else kind
        if stored is not None:
            what = f"{kind}/{stored['id']}/_history/{stored['meta']['versionId']}"
        entity: JSON = {"what": {"reference": what}}
        if request_id:
            entity["detail"] = [{"type": "X-Request-Id", "valueString": request_id}]
        self._audit.append(
            {
                "resourceType": "AuditEvent",
                "id": f"ae-{next(self._audits)}",
                "type": {
                    "system": "http://terminology.hl7.org/CodeSystem/audit-event-type",
                    "code": "rest",
                    "display": "RESTful Operation",
                },
                "subtype": [
                    {
                        "system": "http://hl7.org/fhir/restful-interaction",
                        "code": "create" if created else "update",
                    }
                ],
                "action": "C" if created else "U",
                "recorded": _now(),
                "outcome": "0" if code < 400 else "4",
                "agent": [
                    {"who": {"identifier": {"value": actor or "unknown"}}, "requestor": True}
                ],
                "source": {"observer": {"display": "interlock loopback FHIR server"}},
                "entity": [entity],
            }
        )


def _etag(resource: Mapping[str, Any]) -> str:
    return f'W/"{(resource.get("meta") or {}).get("versionId")}"'


def _bundle(resources: Sequence[JSON]) -> JSON:
    return {
        "resourceType": "Bundle",
        "type": "searchset",
        "total": len(resources),
        "entry": [
            {
                "fullUrl": f"{r['resourceType']}/{r['id']}",
                "resource": r,
                "search": {"mode": "match"},
            }
            for r in resources
        ],
    }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
