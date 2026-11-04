"""A Kubernetes API server on loopback, with admission webhooks (1.3.0).

Enough of the API for a plan-bound substrate to run against over the real wire
protocol, with no cluster and no credentials:

- namespaced resources under ``/api/v1`` and ``/apis/<group>/<version>``:
  ``GET`` (one or a list), ``POST``, ``PUT``, ``PATCH``
  (``application/merge-patch+json``) and ``DELETE``;
- ``?dryRun=All``: the whole admission chain runs and nothing is stored (a
  ``DELETE`` with a body takes ``dryRun`` from its ``DeleteOptions``, as the
  real API server does, and ignores the query);
- optimistic concurrency: a ``PUT`` whose ``metadata.resourceVersion`` is not
  the stored one, and a ``DELETE`` whose ``preconditions`` do not hold, answer
  ``409 Conflict``;
- defaults, then mutating webhooks, then immutable fields (``422 Invalid``),
  then validating webhooks. A webhook is called with an ``AdmissionReview``
  (``admission.k8s.io/v1``) over HTTP, at its URL or hosted on this server, and
  answers with a JSON Patch. A dry run that would reach a webhook whose
  ``sideEffects`` is ``Some`` or ``Unknown`` is refused, as the real API server
  refuses it;
- bearer tokens, each a user;
- an audit log (``audit.k8s.io/v1`` events, one per write, dry runs marked in
  ``requestURI``), as ``agentgov reconcile-actions --format k8s-audit-jsonl``
  reads it;
- faults: :meth:`LoopbackCluster.fail_next` makes the next write to one object
  fail, to exercise a partial apply.

Not modeled: controllers (no pod appears for a replica), watches, field
selectors, server-side apply, subresources. Every object lives in memory.
"""

from __future__ import annotations

import base64
import copy
import itertools
import json
import threading
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

__all__ = [
    "DEPLOYMENTS",
    "STATEFULSETS",
    "LoopbackCluster",
    "ResourceType",
    "Webhook",
    "apply_json_patch",
    "merge_patch",
]

JSON = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ResourceType:
    """One kind the server serves.

    :ivar plural: The URL segment (``deployments``).
    :ivar kind: The object's ``kind`` (``Deployment``).
    :ivar group: The API group, ``""`` for the core group.
    :ivar version: The API version.
    :ivar immutable: Dotted paths an update may not change (``spec.selector``).
    :ivar defaults: Dotted paths and the value each takes when absent.
    """

    plural: str
    kind: str
    group: str = ""
    version: str = "v1"
    immutable: tuple[str, ...] = ()
    defaults: Mapping[str, Any] = field(default_factory=dict)

    @property
    def api_version(self) -> str:
        return f"{self.group}/{self.version}" if self.group else self.version


DEPLOYMENTS = ResourceType(
    "deployments",
    "Deployment",
    group="apps",
    immutable=("spec.selector",),
    defaults={"spec.replicas": 1, "spec.strategy.type": "RollingUpdate"},
)
STATEFULSETS = ResourceType(
    "statefulsets",
    "StatefulSet",
    group="apps",
    immutable=("spec.selector", "spec.serviceName", "spec.volumeClaimTemplates"),
    defaults={"spec.replicas": 1, "spec.podManagementPolicy": "OrderedReady"},
)


@dataclass(frozen=True, slots=True)
class Webhook:
    """An admission webhook.

    :ivar name: Its name, as the API server reports it.
    :ivar mutating: A mutating webhook (its patch applies), or a validating one.
    :ivar resources: The plurals it is called for.
    :ivar operations: ``CREATE``, ``UPDATE``, ``DELETE``.
    :ivar side_effects: ``None``, ``NoneOnDryRun``, ``Some`` or ``Unknown``.
    :ivar match_labels: Only objects carrying every one of these labels.
    :ivar handler: Called with the ``AdmissionReview`` request; returns the
        response's ``allowed``, ``patch`` (a JSON Patch list) and ``message``.
        Hosted on the server itself and called over HTTP.
    :ivar url: Or the URL of a webhook served elsewhere.
    """

    name: str
    mutating: bool = True
    resources: tuple[str, ...] = ()
    operations: tuple[str, ...] = ("CREATE", "UPDATE")
    side_effects: str = "None"
    match_labels: Mapping[str, str] = field(default_factory=dict)
    handler: Callable[[JSON], JSON] | None = None
    url: str | None = None

    def applies(self, plural: str, operation: str, labels: Mapping[str, str]) -> bool:
        if self.resources and plural not in self.resources:
            return False
        if operation not in self.operations:
            return False
        return all(labels.get(k) == v for k, v in self.match_labels.items())


class _RefusedError(Exception):
    def __init__(self, code: int, reason: str, message: str, details: JSON | None = None):
        super().__init__(message)
        self.code = code
        self.reason = reason
        self.message = message
        self.details = details or {}

    def status(self) -> JSON:
        found: JSON = {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": self.message,
            "reason": self.reason,
            "code": self.code,
        }
        if self.details:
            found["details"] = self.details
        return found


def _get(document: Any, path: str) -> tuple[bool, Any]:
    current = document
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _set(document: JSON, path: str, value: Any) -> None:
    parts = path.split(".")
    current: Any = document
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


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


def apply_json_patch(document: JSON, operations: Sequence[Mapping[str, Any]]) -> JSON:
    """RFC 6902 JSON Patch: ``add``, ``replace`` and ``remove``."""
    result = copy.deepcopy(document)
    for op in operations:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in str(op["path"]).split("/")[1:]]
        parent: Any = result
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent.setdefault(part, {})
        last = parts[-1]
        kind = op["op"]
        if kind in ("add", "replace"):
            if isinstance(parent, list):
                index = len(parent) if last == "-" else int(last)
                if kind == "add":
                    parent.insert(index, copy.deepcopy(op["value"]))
                else:
                    parent[index] = copy.deepcopy(op["value"])
            else:
                parent[last] = copy.deepcopy(op["value"])
        elif kind == "remove":
            if isinstance(parent, list):
                parent.pop(int(last))
            else:
                parent.pop(last, None)
        else:
            raise ValueError(f"JSON Patch op {kind!r} is not supported here")
    return result


class LoopbackCluster:
    """The API server (module docstring). Start it, use :attr:`url`, stop it.

    :param resources: The kinds served.
    :param tokens: Bearer token to user name. Empty admits anyone, as
        ``system:anonymous``.
    :param webhooks: The admission chain, in order.
    """

    def __init__(
        self,
        resources: Iterable[ResourceType] = (DEPLOYMENTS, STATEFULSETS),
        *,
        tokens: Mapping[str, str] | None = None,
        webhooks: Iterable[Webhook] = (),
    ) -> None:
        self._types = {r.plural: r for r in resources}
        self._tokens = dict(tokens or {})
        self._webhooks = list(webhooks)
        self._objects: dict[tuple[str, str, str], JSON] = {}
        self._version = itertools.count(1000)
        self._lock = threading.RLock()
        self._audit: list[JSON] = []
        self._faults: dict[tuple[str, str, str], tuple[int, str]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.requests: list[tuple[str, str]] = []
        """Every request served: method and path with query."""

    # -- running --------------------------------------------------------------

    def start(self) -> str:
        """Serve on a free loopback port; the base URL."""
        cluster = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                code, answer = cluster._handle(
                    self.command, self.path, body, dict(self.headers.items())
                )
                data = json.dumps(answer).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
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
            raise RuntimeError("the loopback cluster is not started")
        host, port = self._server.server_address[:2]
        shown = host.decode() if isinstance(host, bytes) else host
        return f"http://{shown}:{port}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> LoopbackCluster:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- direct access, for seeding and for tests -----------------------------------

    def add_webhook(self, webhook: Webhook) -> None:
        with self._lock:
            self._webhooks.append(webhook)

    def seed(self, plural: str, manifest: JSON) -> JSON:
        """Store an object as if created, without admission or audit."""
        with self._lock:
            kind = self._types[plural]
            obj = copy.deepcopy(manifest)
            for path, value in kind.defaults.items():
                if not _get(obj, path)[0]:
                    _set(obj, path, copy.deepcopy(value))
            obj = self._stamp(kind, obj, None)
            meta = obj["metadata"]
            self._objects[(plural, meta["namespace"], meta["name"])] = obj
            return copy.deepcopy(obj)

    def get(self, plural: str, namespace: str, name: str) -> JSON | None:
        with self._lock:
            found = self._objects.get((plural, namespace, name))
            return copy.deepcopy(found) if found is not None else None

    def fail_next(self, plural: str, namespace: str, name: str, code: int = 500) -> None:
        """The next write (not a dry run) to this object fails with ``code``."""
        with self._lock:
            self._faults[(plural, namespace, name)] = (code, "InternalError")

    def audit_events(self) -> list[JSON]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def audit_log(self) -> str:
        """The audit log as JSON lines."""
        return "".join(json.dumps(e, sort_keys=True) + "\n" for e in self.audit_events())

    # -- the API --------------------------------------------------------------------

    def _handle(
        self, method: str, raw_path: str, body: bytes, headers: Mapping[str, str]
    ) -> tuple[int, JSON]:
        self.requests.append((method, raw_path))
        parts = urlsplit(raw_path)
        query = parse_qs(parts.query)
        if parts.path.startswith("/webhooks/"):
            return self._serve_webhook(parts.path.removeprefix("/webhooks/"), body)
        try:
            user = self._user(headers)
            plural, namespace, name = self._route(parts.path)
            dry = query.get("dryRun", [""])[0] == "All"
            with self._lock:
                if method == "GET":
                    return 200, self._read(plural, namespace, name)
                document = json.loads(body) if body else {}
                try:
                    code, answer = self._write(method, plural, namespace, name, document, dry, user)
                except _RefusedError as refused:
                    # The real API server audits a refused write too.
                    self._log(
                        method, raw_path, plural, namespace, name, document, user, refused.code
                    )
                    raise
            self._log(method, raw_path, plural, namespace, name, document, user, code)
            return code, answer
        except _RefusedError as refused:
            return refused.code, refused.status()
        except json.JSONDecodeError as exc:
            return 400, _RefusedError(400, "BadRequest", f"body is not JSON: {exc}").status()

    def _user(self, headers: Mapping[str, str]) -> str:
        if not self._tokens:
            return "system:anonymous"
        given = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
        token = given.removeprefix("Bearer ").strip()
        user = self._tokens.get(token)
        if user is None:
            raise _RefusedError(401, "Unauthorized", "Unauthorized")
        return user

    def _route(self, path: str) -> tuple[str, str, str | None]:
        segments = [s for s in path.split("/") if s]
        if segments[:2] == ["api", "v1"]:
            rest = segments[2:]
        elif segments[:1] == ["apis"] and len(segments) >= 3:
            rest = segments[3:]
        else:
            raise _RefusedError(404, "NotFound", f"the server could not find {path}")
        if len(rest) < 3 or rest[0] != "namespaces":
            raise _RefusedError(404, "NotFound", f"the server could not find {path}")
        namespace, plural = rest[1], rest[2]
        if plural not in self._types:
            raise _RefusedError(404, "NotFound", f"the server does not serve {plural}")
        name = rest[3] if len(rest) > 3 else None
        return plural, namespace, name

    def _read(self, plural: str, namespace: str, name: str | None) -> JSON:
        kind = self._types[plural]
        if name is None:
            items = [
                copy.deepcopy(o)
                for (p, ns, _), o in sorted(self._objects.items())
                if p == plural and ns == namespace
            ]
            return {
                "kind": f"{kind.kind}List",
                "apiVersion": kind.api_version,
                "metadata": {"resourceVersion": str(next(self._version))},
                "items": items,
            }
        found = self._objects.get((plural, namespace, name))
        if found is None:
            raise _RefusedError(
                404,
                "NotFound",
                f'{plural}.{kind.group or "core"} "{name}" not found',
                {"name": name, "kind": plural},
            )
        return copy.deepcopy(found)

    def _write(
        self,
        method: str,
        plural: str,
        namespace: str,
        name: str | None,
        document: JSON,
        dry: bool,
        user: str,
    ) -> tuple[int, JSON]:
        kind = self._types[plural]
        if method == "POST":
            meta = document.setdefault("metadata", {})
            name = meta.get("name")
            if not name and meta.get("generateName"):
                name = f"{meta.pop('generateName')}{uuid.uuid4().hex[:5]}"
                meta["name"] = name
            if not name:
                raise _RefusedError(422, "Invalid", "metadata.name: Required value")
        if name is None:
            raise _RefusedError(405, "MethodNotAllowed", f"{method} needs an object name")
        key = (plural, namespace, name)
        current = self._objects.get(key)
        if method == "DELETE":
            if document:
                # As the real API server does: a DELETE with a body takes its
                # options (dryRun among them) from the body, not the query.
                dry = document.get("dryRun") == ["All"]
            if current is None:
                raise _RefusedError(404, "NotFound", f'{plural} "{name}" not found')
            wanted = (document.get("preconditions") or {}).get("resourceVersion")
            if wanted is not None and wanted != current["metadata"]["resourceVersion"]:
                raise self._conflict(plural, name)
            self._admit("DELETE", kind, namespace, name, None, current, dry, user)
            if not dry:
                self._fault(key)
                del self._objects[key]
            return 200, copy.deepcopy(current)
        if method == "POST":
            if current is not None:
                raise _RefusedError(
                    409, "AlreadyExists", f'{plural} "{name}" already exists', {"name": name}
                )
            proposed = copy.deepcopy(document)
            operation = "CREATE"
        else:
            if current is None:
                raise _RefusedError(404, "NotFound", f'{plural} "{name}" not found')
            if method == "PATCH":
                proposed = merge_patch(current, document)
                wanted = (document.get("metadata") or {}).get("resourceVersion")
            else:
                proposed = copy.deepcopy(document)
                wanted = (document.get("metadata") or {}).get("resourceVersion")
            if wanted is not None and wanted != current["metadata"]["resourceVersion"]:
                raise self._conflict(plural, name)
            operation = "UPDATE"
        proposed.setdefault("metadata", {})
        proposed["metadata"]["namespace"] = namespace
        proposed["metadata"]["name"] = name
        proposed["apiVersion"] = kind.api_version
        proposed["kind"] = kind.kind
        for path, value in kind.defaults.items():
            if not _get(proposed, path)[0]:
                _set(proposed, path, copy.deepcopy(value))
        admitted = self._admit(operation, kind, namespace, name, proposed, current, dry, user)
        if current is not None:
            for path in kind.immutable:
                if _get(current, path) != _get(admitted, path):
                    raise _RefusedError(
                        422,
                        "Invalid",
                        f'{kind.kind}.{kind.group} "{name}" is invalid: {path}: Forbidden: '
                        f"field is immutable",
                        {
                            "name": name,
                            "kind": kind.kind,
                            "causes": [{"reason": "FieldValueForbidden", "field": path}],
                        },
                    )
        stored = self._stamp(kind, admitted, current, advance=not dry)
        if not dry:
            self._fault(key)
            self._objects[key] = stored
        return (201 if operation == "CREATE" else 200), copy.deepcopy(stored)

    def _conflict(self, plural: str, name: str) -> _RefusedError:
        return _RefusedError(
            409,
            "Conflict",
            f'Operation cannot be fulfilled on {plural} "{name}": the object has been modified; '
            f"please apply your changes to the latest version and try again",
            {"name": name, "kind": plural},
        )

    def _fault(self, key: tuple[str, str, str]) -> None:
        fault = self._faults.pop(key, None)
        if fault is not None:
            code, reason = fault
            raise _RefusedError(code, reason, f"injected fault writing {key[0]}/{key[2]}")

    def _stamp(
        self, kind: ResourceType, obj: JSON, current: JSON | None, *, advance: bool = True
    ) -> JSON:
        meta = obj.setdefault("metadata", {})
        meta.setdefault("namespace", "default")
        obj["apiVersion"] = kind.api_version
        obj["kind"] = kind.kind
        if current is not None:
            old = current["metadata"]
            meta["uid"] = old["uid"]
            meta["creationTimestamp"] = old["creationTimestamp"]
            generation = int(old.get("generation", 1))
            changed = current.get("spec") != obj.get("spec")
            meta["generation"] = generation + 1 if changed else generation
            meta["resourceVersion"] = (
                str(next(self._version)) if advance else old["resourceVersion"]
            )
        else:
            meta["uid"] = str(uuid.uuid4())
            meta["creationTimestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            meta["generation"] = 1
            meta["resourceVersion"] = str(next(self._version)) if advance else ""
        return obj

    # -- admission ------------------------------------------------------------------

    def _admit(
        self,
        operation: str,
        kind: ResourceType,
        namespace: str,
        name: str,
        proposed: JSON | None,
        current: JSON | None,
        dry: bool,
        user: str,
    ) -> JSON:
        obj = proposed
        for mutating in (True, False):
            for hook in self._webhooks:
                if hook.mutating is not mutating:
                    continue
                labels = ((obj or current or {}).get("metadata") or {}).get("labels") or {}
                if not hook.applies(kind.plural, operation, labels):
                    continue
                if dry and hook.side_effects in ("Some", "Unknown"):
                    raise _RefusedError(
                        400,
                        "BadRequest",
                        f'admission webhook "{hook.name}" does not support dry run',
                    )
                answer = self._call(hook, operation, kind, namespace, name, obj, current, dry, user)
                if not answer.get("allowed", False):
                    message = (answer.get("status") or {}).get("message") or "denied the request"
                    raise _RefusedError(
                        403 if mutating else 400,
                        "Forbidden" if mutating else "BadRequest",
                        f'admission webhook "{hook.name}" denied the request: {message}',
                    )
                patch = answer.get("patch")
                if mutating and patch and obj is not None:
                    operations = json.loads(base64.b64decode(patch))
                    obj = apply_json_patch(obj, operations)
        return obj if obj is not None else {}

    def _call(
        self,
        hook: Webhook,
        operation: str,
        kind: ResourceType,
        namespace: str,
        name: str,
        obj: JSON | None,
        current: JSON | None,
        dry: bool,
        user: str,
    ) -> JSON:
        review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": str(uuid.uuid4()),
                "kind": {"group": kind.group, "version": kind.version, "kind": kind.kind},
                "resource": {"group": kind.group, "version": kind.version, "resource": kind.plural},
                "namespace": namespace,
                "name": name,
                "operation": operation,
                "userInfo": {"username": user},
                "object": obj,
                "oldObject": current,
                "dryRun": dry,
            },
        }
        url = hook.url or f"{self.url}/webhooks/{hook.name}"
        request = urllib.request.Request(  # noqa: S310 - the operator's webhook URL
            url,
            data=json.dumps(review).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as reply:  # noqa: S310 - loopback
                answer = json.loads(reply.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise _RefusedError(
                500,
                "InternalError",
                f'Internal error occurred: failed calling webhook "{hook.name}": {exc}',
            ) from exc
        response = answer.get("response")
        if not isinstance(response, dict):
            raise _RefusedError(500, "InternalError", f'webhook "{hook.name}" answered no response')
        return response

    def _serve_webhook(self, name: str, body: bytes) -> tuple[int, JSON]:
        hook = next((h for h in self._webhooks if h.name == name and h.handler), None)
        if hook is None or hook.handler is None:
            return 404, {"error": f"no webhook {name}"}
        review = json.loads(body)
        request = review["request"]
        verdict = hook.handler(request)
        response: JSON = {"uid": request["uid"], "allowed": bool(verdict.get("allowed", True))}
        if verdict.get("patch"):
            response["patchType"] = "JSONPatch"
            response["patch"] = base64.b64encode(json.dumps(verdict["patch"]).encode()).decode()
        if verdict.get("message"):
            response["status"] = {"message": verdict["message"]}
        return 200, {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": response,
        }

    # -- the audit log ---------------------------------------------------------------

    def _log(
        self,
        method: str,
        raw_path: str,
        plural: str,
        namespace: str,
        name: str | None,
        document: JSON,
        user: str,
        code: int,
    ) -> None:
        kind = self._types[plural]
        verb = {"POST": "create", "PUT": "update", "PATCH": "patch", "DELETE": "delete"}[method]
        if name is None:
            name = (document.get("metadata") or {}).get("name")
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        event: JSON = {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "Request",
            "auditID": str(uuid.uuid4()),
            "stage": "ResponseComplete",
            "requestURI": raw_path,
            "verb": verb,
            "user": {"username": user},
            "objectRef": {
                "resource": plural,
                "namespace": namespace,
                "name": name,
                "apiGroup": kind.group,
                "apiVersion": kind.version,
            },
            "responseStatus": {"metadata": {}, "code": code},
            "requestReceivedTimestamp": now,
            "stageTimestamp": now,
        }
        if method != "DELETE" and document:
            event["requestObject"] = copy.deepcopy(document)
        with self._lock:
            self._audit.append(event)
