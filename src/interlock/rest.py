"""A JSON REST API as a class V substrate (1.5.0): predict a change, write it on the version
read, read it back, and put it back if it is not what was predicted.

This is the substrate for agents that work through a SaaS API: a support agent updating
tickets, a sales agent editing CRM accounts, an HR agent changing a record. Those systems have
no transaction a stage can hold open and no dry run. What most of them do have is a version on
every resource (an ``ETag``, or a ``version`` field) and conditional writes. The guarantee is
class V (:mod:`interlock.predicted`), as for :class:`~interlock.fhir.FhirSubstrate`:

- **Read the before image, and its neighbors.** Each resource an effect reaches is read live
  with its version. The first time a stage reaches a tenant (an account, an organization), it
  lists every resource of every observed type in that tenant: the scope the write is verified
  over.
- **Predict, and judge the prediction.** ``create`` builds a resource from a template; ``patch``
  applies a JSON merge patch to what was read. The diff is the prediction, so every checker,
  partition and rate window judges it before the API sees anything.
- **Write the undo first.** The before image of every resource the commit writes goes to the
  undo journal before the first write.
- **Write conditionally.** The scope is read again first: anything that moved since the stage
  read it (a person's edit while the plan waited for a warrant) refuses the commit, and nothing
  is written. Each write then carries the version read (``If-Match``, or the version field in
  the body), so a change in the last instant answers ``412`` or ``409``. Every write carries the
  stage's id in ``X-Request-Id`` (or the header you name), which vendor audit logs record.
- **Read back, and hold the API to the prediction.** The scope is read once more and each
  resource compared with what the plan predicted: the written ones as predicted, every other one
  unchanged. A difference (an automation rule that escalated the ticket and reassigned it, a
  field the API rewrote) is never accepted: everything the write changed is put back,
  conditional on the version read back, and the stage is recorded ``COMPENSATED``.

**Configuring a resource type** (:class:`RestResource`): its table, its collection path, the
columns a checker reads (each a dotted field path), the field holding its tenant and the list
parameter that filters on it, how it carries its version, which fields the API manages itself
(``updated_at``: never predicted, never compared), and how a create is undone (a ``void`` merge
patch such as ``{"status": "archived"}``, or ``delete``). With ``source`` naming the field where
the API records the request that last wrote a resource, a put-back can tell a rule your write set
off (put back) from someone else's change (left alone and named for a person).

Each resource is one :class:`~interlock.types.RowDelta`:

- **table**: the type's table; **primary key**: the resource's id; a created resource's id is
  assigned by the stage (``PUT`` with ``If-None-Match: *``), so the prediction names it;
- **tenant**: the value of the type's ``tenant`` field; other partitions likewise;
- **columns**: what the type names, and ``fingerprint``: a digest of the whole resource less the
  fields the API manages, so a change to a field no column names is still a change.

**Statements**, one operation each; a template is a JSON literal in which a string value
``":name"`` is replaced, whole, by that parameter. The parameters a template binds are listed
after it, so a reader sees them outside the literal::

    create <table> '<resource template>' [:name ...]
    patch <table> :id '<merge patch template>' [:name ...]
    expect-version <table> :id :version

**Compensations**: the substrate cannot roll back (``requires_compensation``), so each effect
carries the undo the plan declares: ``void <table>`` for a create, ``restore <table>`` for a
patch or ``expect-version``.

Outbound requests, rate windows and inbound facts live in a control database (SQLite), as for
the other non-SQL substrates (:mod:`interlock.control`).

What it cannot do: see an automation's consequence before the write. That is caught by the
read-back and put back, not refused before it, and the receipt says ``predicted``. An API must
accept client-assigned ids (or an external-id upsert path) for a create to be predicted exactly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import sqlite3
import ssl
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote, urlencode

from agentgov.receipts.canonical import canonical_bytes

from interlock.control import capture, durable_write, replay
from interlock.exceptions import (
    CommitUnsettledError,
    CompensatedError,
    ForbiddenStatementError,
    InboundFactError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.fhir import _canonical_safe, _json, _merge, _thaw, _tokens, parse_compensation
from interlock.planbound import UndoJournal
from interlock.predicted import PREDICTED
from interlock.substrate import SqliteSubstrate, TableSpec
from interlock.text import tally
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectKind,
    EffectOutcome,
    EffectPlan,
    InboundFact,
    OutboundDelta,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
    WindowMeasure,
)
from interlock.windows import WindowCharge

__all__ = [
    "COMPENSATIONS",
    "VERBS",
    "RestResource",
    "RestStatement",
    "RestSubstrate",
    "fingerprint",
    "merge_diff",
    "parse_statement",
    "rest_tables",
]

logger = logging.getLogger("interlock.rest")

ID: Final = "id"
"""Every type's primary key column: the resource's id."""

TENANT: Final = "tenant"
"""Every type's tenant column: the value of its ``tenant`` field."""

FINGERPRINT: Final = "fingerprint"
"""Every type's digest column: the resource less the fields the API manages."""

VERBS: Final = {
    "create": ("resource",),
    "patch": ("id", "patch"),
    "expect-version": ("id", "version"),
}
"""Each verb of the statement language, and its arguments in order."""

COMPENSATIONS: Final = {"create": "void", "patch": "restore", "expect-version": "restore"}
"""The undo each verb's effect declares."""

_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9_]*")
_RESOURCE_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_PATH: Final = re.compile(r"(?:/[A-Za-z0-9._~-]+)+")
_FIELD: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.(?:[A-Za-z_][A-Za-z0-9_-]*|\d+))*")
_PLACEHOLDER: Final = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_HEADER: Final = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")


# --------------------------------------------------------------------------
# fields, images and the fingerprint
# --------------------------------------------------------------------------


def field_value(document: Any, path: str) -> tuple[bool, Any]:
    """The value at a dotted ``path`` and whether it is there."""
    current = document
    for part in path.split("."):
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def _without(document: Mapping[str, Any], paths: Sequence[str]) -> dict[str, Any]:
    """``document`` less the fields at ``paths``."""
    body = copy.deepcopy(dict(document))
    for path in paths:
        parts = path.split(".")
        holder: Any = body
        for part in parts[:-1]:
            holder = holder.get(part) if isinstance(holder, dict) else None
        if isinstance(holder, dict):
            holder.pop(parts[-1], None)
    return body


def fingerprint(resource: Mapping[str, Any], managed: Sequence[str] = ()) -> str:
    """A digest of the resource less the fields the API manages."""
    return hashlib.sha256(canonical_bytes(_canonical_safe(_without(resource, managed)))).hexdigest()


def merge_diff(source: Any, target: Any) -> Any:
    """The RFC 7386 merge patch that turns ``source`` into ``target``. A key ``target`` drops is
    ``null``; an object is diffed key by key; anything else is replaced whole."""
    if not isinstance(source, dict) or not isinstance(target, dict):
        return copy.deepcopy(target)
    patch: dict[str, Any] = {}
    for key in source:
        if key not in target:
            patch[key] = None
    for key, value in target.items():
        if key not in source:
            patch[key] = copy.deepcopy(value)
        elif source[key] != value:
            patch[key] = (
                merge_diff(source[key], value)
                if isinstance(value, dict) and isinstance(source[key], dict)
                else copy.deepcopy(value)
            )
    return patch


@dataclass(frozen=True, slots=True)
class RestResource:
    """One resource type the substrate observes, as one table (module docstring).

    :ivar table: The table's name (an identifier): ``tickets``.
    :ivar path: The collection's path under the API's base: ``/tickets``. One resource is at
        ``{path}/{id}``.
    :ivar columns: Each column and the dotted field path of its value.
    :ivar tenant: The field holding the resource's tenant, or ``None`` for none.
    :ivar scope: The list parameter that filters a collection to one tenant: the tenant field's
        name by default. Every observed type with a tenant is listed by it.
    :ivar partitions: Each partition dimension beside the tenant, and its field.
    :ivar version: ``"etag"`` (the ``ETag`` header, sent back as ``If-Match``) or the field
        holding the version, sent back in the body of each write.
    :ivar managed: Fields the API writes itself (``updated_at``): never predicted, never
        compared, never written by a template.
    :ivar write: ``"patch"`` (a JSON merge patch) or ``"put"`` (the whole resource).
    :ivar void: The merge patch that voids a created resource (``{"status": "archived"}``), or
        ``None`` to undo a create with ``DELETE``.
    :ivar items: Where a list response holds its items: a field (``data``), or ``""`` for a
        top-level array.
    :ivar next: Where a list response names its next page (a path or URL), or ``""`` for none.
    :ivar source: The field where the API records the request that last wrote a resource.
    """

    table: str
    path: str
    columns: Mapping[str, str] = field(default_factory=dict)
    tenant: str | None = None
    scope: str | None = None
    partitions: Mapping[str, str] = field(default_factory=dict)
    version: str = "etag"
    managed: tuple[str, ...] = ()
    write: str = "patch"
    void: Mapping[str, Any] | None = None
    items: str = "data"
    next: str = "next"
    source: str | None = None

    def __post_init__(self) -> None:
        where = f"resource {self.table!r}"
        for name in [self.table, *self.columns, *self.partitions]:
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(f"{where}: {name!r} is not a lowercase identifier")
        if not _PATH.fullmatch(self.path):
            raise ValueError(f"{where}: path {self.path!r} is not /a/collection/path")
        clash = sorted({ID, TENANT, FINGERPRINT} & (set(self.columns) | set(self.partitions)))
        if clash:
            raise ValueError(f"{where}: {', '.join(clash)} are every type's own columns")
        if set(self.columns) & set(self.partitions):
            raise ValueError(f"{where}: a column and a partition share a name")
        fields = [*self.columns.values(), *self.partitions.values(), *self.managed]
        fields += [f for f in (self.tenant, self.source) if f]
        if self.version != "etag":
            fields.append(self.version)
        for path in fields:
            if not _FIELD.fullmatch(path):
                raise ValueError(f"{where}: {path!r} is not a dotted field path")
        if self.write not in ("patch", "put"):
            raise ValueError(f"{where}: write is 'patch' or 'put', not {self.write!r}")
        if self.scope is not None and not _IDENTIFIER.fullmatch(self.scope.replace(".", "_")):
            raise ValueError(f"{where}: scope {self.scope!r} is not a list parameter")

    @property
    def scope_parameter(self) -> str | None:
        return self.scope or self.tenant

    @property
    def ignored(self) -> tuple[str, ...]:
        """What a fingerprint leaves out: the managed fields, the version field, the source."""
        extra = [self.version] if self.version != "etag" else []
        return (*self.managed, *extra, *([self.source] if self.source else []))

    def spec(self) -> TableSpec:
        columns = [ID, TENANT, *self.columns, *self.partitions, FINGERPRINT]
        return TableSpec(
            self.table,
            primary_key=ID,
            columns=columns,
            tenant_column=TENANT if self.tenant else None,
            partitions={d: d for d in self.partitions} or None,
        )

    def tenant_of(self, resource: Mapping[str, Any]) -> str | None:
        if self.tenant is None:
            return None
        found, value = field_value(resource, self.tenant)
        return None if not found or value is None else str(value)

    def image(self, resource: Mapping[str, Any]) -> dict[str, Any]:
        """The resource's row: every column's value."""
        row: dict[str, Any] = {ID: resource.get("id"), TENANT: self.tenant_of(resource)}
        for column, path in self.columns.items():
            found, value = field_value(resource, path)
            if not found:
                row[column] = None
            elif isinstance(value, Mapping | list):
                row[column] = canonical_bytes(_canonical_safe(value)).decode("utf-8")
            else:
                row[column] = value
        for dimension, path in self.partitions.items():
            found, value = field_value(resource, path)
            row[dimension] = str(value) if found and value is not None else None
        row[FINGERPRINT] = fingerprint(resource, self.ignored)
        return row


def rest_tables(resources: Sequence[RestResource]) -> tuple[TableSpec, ...]:
    """A REST substrate's tables: one per resource type."""
    return tuple(r.spec() for r in resources)


# --------------------------------------------------------------------------
# the statement language
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RestStatement:
    """A parsed statement: its verb, its table, and each argument, a parameter name
    (``(":", name)``) or a literal (``("'", text)``); and the parameters its template binds."""

    verb: str
    table: str
    arguments: tuple[tuple[str, str], ...]
    binds: tuple[str, ...] = ()

    def bind(self, parameters: Mapping[str, object]) -> dict[str, object]:
        """Each argument's value, by the name the verb gives it.

        :raises ValueError: On a parameter the effect does not carry.
        """
        bound: dict[str, object] = {}
        for name, (kind, text) in zip(VERBS[self.verb], self.arguments, strict=True):
            if kind == "'":
                bound[name] = text
            elif text in parameters:
                bound[name] = parameters[text]
            else:
                raise ValueError(f"parameter :{text} is not bound")
        return bound


def parse_statement(statement: str) -> RestStatement:
    """Read a statement (module docstring).

    :raises ValueError: On anything else.
    """
    tokens = _tokens(statement)
    if len(tokens) < 2 or tokens[0][0] != "word" or tokens[1][0] != "word":
        raise ValueError("a statement is a verb, a table, then its arguments")
    verb, table = tokens[0][1], tokens[1][1]
    if verb not in VERBS:
        raise ValueError(f"the verbs are {', '.join(VERBS)}, not {verb!r}")
    arguments = tokens[2:]
    if any(kind == "word" for kind, _ in arguments):
        raise ValueError("an argument is a :parameter or a 'literal'")
    takes = len(VERBS[verb])
    listed = arguments[takes:]
    if len(arguments) < takes or (verb == "expect-version" and listed):
        raise ValueError(f"{verb} takes {' '.join(':' + a for a in VERBS[verb])}")
    if any(kind != ":" for kind, _ in listed):
        raise ValueError("after its template, a statement lists the :parameters it binds")
    return RestStatement(verb, table, tuple(arguments[:takes]), tuple(n for _, n in listed))


def _bound_by(template: Any) -> set[str]:
    if isinstance(template, Mapping):
        return {n for v in template.values() for n in _bound_by(v)}
    if isinstance(template, list):
        return {n for v in template for n in _bound_by(v)}
    if isinstance(template, str):
        whole = _PLACEHOLDER.fullmatch(template)
        return {whole.group(1)} if whole is not None else set()
    return set()


def _listed(statement: RestStatement, template: Any) -> str | None:
    used, listed = _bound_by(template), set(statement.binds)
    if used - listed:
        names = ", ".join(":" + n for n in sorted(used - listed))
        return f"the template binds {names}, which the statement does not list after it"
    if listed - used:
        names = ", ".join(":" + n for n in sorted(listed - used))
        return f"the statement lists {names}, which its template does not bind"
    return None


def _fill(template: Any, parameters: Mapping[str, object]) -> Any:
    """``template`` with each ``":name"`` value replaced by its parameter.

    :raises ValueError: On a parameter the effect does not carry.
    """
    if isinstance(template, Mapping):
        return {k: _fill(v, parameters) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, parameters) for v in template]
    if isinstance(template, str):
        whole = _PLACEHOLDER.fullmatch(template)
        if whole is not None:
            name = whole.group(1)
            if name not in parameters:
                raise ValueError(f"parameter :{name} is not bound")
            return _thaw(parameters[name])
    return template


# --------------------------------------------------------------------------
# the API
# --------------------------------------------------------------------------


class _RestError(Exception):
    def __init__(self, status: int, body: object) -> None:
        self.status = status
        self.body = body
        super().__init__(self.message)

    @property
    def message(self) -> str:
        body = self.body
        if isinstance(body, Mapping):
            error = body.get("error", body)
            if isinstance(error, Mapping):
                said = error.get("message") or error.get("detail") or error.get("title")
                if said:
                    return str(said)
            elif isinstance(error, str):
                return error
        return f"HTTP {self.status}"

    @property
    def conflict(self) -> bool:
        return self.status in (409, 412)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A write is never re-sent somewhere a redirect names."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


@dataclass(frozen=True, slots=True)
class _Reply:
    status: int
    body: Any
    etag: str | None


class _Api:
    """The API, over HTTPS (or HTTP on loopback), with a bearer token."""

    __slots__ = ("_context", "_opener", "_server", "_timeout", "_token")

    def __init__(
        self, server: str, *, token: str | None, ca_file: str | None, timeout: float
    ) -> None:
        self._server = server.rstrip("/")
        self._token = token
        self._timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if self._server.startswith("https://"):
            context = ssl.create_default_context(cafile=ca_file)
            handlers.append(urllib.request.HTTPSHandler(context=context))
        elif not re.match(r"http://(127\.0\.0\.1|localhost|\[::1\])(:|/|$)", self._server):
            raise SubstrateConfigurationError(
                f"the API {self._server} is reached over HTTPS; plain HTTP is for loopback only"
            )
        self._opener = urllib.request.build_opener(*handlers)

    @property
    def server(self) -> str:
        return self._server

    def call(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        content_type: str = "application/json",
    ) -> _Reply:
        sent = {"Accept": "application/json", **dict(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent["Content-Type"] = content_type
        if self._token:
            sent["Authorization"] = f"Bearer {self._token}"
        url = path if path.startswith(("http://", "https://")) else self._server + path
        if not url.startswith(self._server + "/"):
            raise StageError(f"{url} is not on the API {self._server}")
        request = urllib.request.Request(  # noqa: S310 - https, or loopback http
            url, data=data, headers=sent, method=method
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as reply:
                raw = reply.read()
                return _Reply(
                    int(reply.status), json.loads(raw) if raw else None, reply.headers.get("ETag")
                )
        except urllib.error.HTTPError as exc:
            try:
                answer = json.loads(exc.read() or b"null")
            except ValueError:
                answer = None
            raise _RestError(exc.code, answer) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SubstrateUnavailableError(f"cannot reach the API {self._server}: {exc}") from exc

    def read(
        self, kind: RestResource, resource_id: str
    ) -> tuple[dict[str, Any], str | None] | None:
        """A resource and its version, or ``None`` when there is none."""
        try:
            reply = self.call("GET", f"{kind.path}/{quote(resource_id, safe='')}")
        except _RestError as exc:
            if exc.status in (404, 410):
                return None
            raise
        if not isinstance(reply.body, dict):
            raise StageError(f"{kind.path}/{resource_id} did not answer a JSON object")
        return reply.body, _version_of(kind, reply.body, reply.etag)

    def find(
        self, kind: RestResource, parameter: str, value: str, *, limit: int
    ) -> list[dict[str, Any]]:
        """Every resource of ``kind`` whose ``parameter`` is ``value``, following next pages, at
        most ``limit``."""
        path: str | None = f"{kind.path}?{urlencode([(parameter, value)])}"
        found: list[dict[str, Any]] = []
        while path:
            reply = self.call("GET", path)
            items: Any = reply.body
            if kind.items:
                ok, items = field_value(reply.body, kind.items)
                if not ok:
                    raise StageError(f"a list of {kind.path} holds no {kind.items!r}")
            if not isinstance(items, list):
                raise StageError(f"a list of {kind.path} is not a list")
            found.extend(i for i in items if isinstance(i, dict))
            if len(found) > limit:
                raise StageError(f"listing {kind.path} found more than {limit} resources")
            following = field_value(reply.body, kind.next)[1] if kind.next else None
            path = str(following) if following else None
        return found


def _version_of(kind: RestResource, body: Mapping[str, Any], etag: str | None) -> str | None:
    if kind.version == "etag":
        return etag
    found, value = field_value(body, kind.version)
    return None if not found or value is None else str(value)


# --------------------------------------------------------------------------
# the substrate
# --------------------------------------------------------------------------


@dataclass
class _Resource:
    kind: RestResource
    resource_id: str
    live: dict[str, Any] | None
    version: str | None
    desired: dict[str, Any] | None = None
    staged: bool = False
    effects: list[str] = field(default_factory=list)
    written: str | None = None
    """The version the stage's own write made: a later one is someone else's."""

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind.table, self.resource_id)

    @property
    def action(self) -> str:
        return "create" if self.live is None else "update"

    def path(self) -> str:
        return f"{self.kind.path}/{quote(self.resource_id, safe='')}"


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    resources: dict[tuple[str, str], _Resource] = field(default_factory=dict)
    scope: dict[str, dict[tuple[str, str], dict[str, Any]]] = field(default_factory=dict)
    """Each tenant's resources as the stage first listed them."""
    savepoints: list[tuple[str, dict[tuple[str, str], _Resource]]] = field(default_factory=list)
    foreign: list[str] = field(default_factory=list)
    control: StageHandle | None = None
    undo: str | None = None
    measured: bool = False
    done: bool = False
    unsettled: bool = False
    committing: bool = False


class RestSubstrate:
    """Predicted and verified staging on a JSON REST API (module docstring).

    :param server: The API's base URL: ``https://...``, or ``http://127.0.0.1:...`` for a
        loopback one (:mod:`interlock.sim.rest`).
    :param resources: The resource types observed, each a table.
    :param journal: Where undos (and control redo records) are written.
    :param tenants: The tenants a plan may write. Empty: any.
    :param token: The bearer token the substrate acts with.
    :param ca_file: The CA bundle the server's certificate is checked against.
    :param request_header: The header each write carries the stage's id in.
    :param control: A SQLite file ``interlock install`` set up: the outbox, the inbox and rate
        windows' history.
    :param timeout: Seconds one API call may take.
    :raises SubstrateConfigurationError: On an API reached over plain HTTP other than loopback,
        or two types sharing a table.
    """

    __slots__ = (
        "_api",
        "_compensated",
        "_control",
        "_header",
        "_journal",
        "_max_rows",
        "_stage",
        "_stage_seconds",
        "_tenants",
        "_types",
        "_undone",
    )

    def __init__(
        self,
        server: str,
        *,
        resources: Sequence[RestResource],
        journal: str | Path,
        tenants: Sequence[str] = (),
        token: str | None = None,
        ca_file: str | None = None,
        request_header: str = "X-Request-Id",
        control: str | Path | None = None,
        timeout: float = 15.0,
        max_stage_seconds: float = 120.0,
        max_diff_rows: int = 50_000,
    ) -> None:
        tables = [r.table for r in resources]
        if not tables:
            raise SubstrateConfigurationError(
                "a REST substrate observes at least one resource type"
            )
        if len(set(tables)) != len(tables):
            raise SubstrateConfigurationError("each resource type is its own table")
        if len({r.path for r in resources}) != len(tables):
            raise SubstrateConfigurationError("each resource type has its own collection path")
        if not _HEADER.fullmatch(request_header):
            raise SubstrateConfigurationError(f"{request_header!r} is not a header name")
        self._types = {r.table: r for r in resources}
        self._tenants = frozenset(tenants)
        self._header = request_header
        self._api = _Api(server, token=token, ca_file=ca_file, timeout=timeout)
        self._journal = UndoJournal(journal)
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._control = (
            SqliteSubstrate(str(control), tables=(), max_stage_seconds=max_stage_seconds)
            if control is not None
            else None
        )
        self._stage: _Stage | None = None
        self._compensated: dict[uuid.UUID, str] = {}
        self._undone: set[uuid.UUID] = set()

    # -- what it is -----------------------------------------------------------

    @property
    def substrate_id(self) -> str:
        return "rest"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=False,
            row_level_diff=True,
            snapshot_isolation=False,
            requires_compensation=True,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            outbound=self._control is not None and self._control.capabilities.outbound,
            measurement=PREDICTED,
            predicted=True,
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        return frozenset(self._types)

    @property
    def table_specs(self) -> tuple[TableSpec, ...]:
        return rest_tables(tuple(self._types.values()))

    @property
    def commit_markers(self) -> bool:
        """Always: every write carries the stage's id."""
        return True

    @property
    def server(self) -> str:
        return self._api.server

    @property
    def control(self) -> str | None:
        return None if self._control is None else self._control.path

    def held_operations(self) -> dict[str, tuple[str, ...]]:
        return {} if self._control is None else self._control.held_operations()

    def transaction_id(self, handle: StageHandle) -> str | None:
        """``rest:<stage id>``: what the API's audit log records as each write's request id.
        ``None`` for a stage that writes no resource."""
        stage = self._stage
        if (
            stage is not None
            and stage.handle.stage_id == handle.stage_id
            and not self._writes(stage)
        ):
            return None
        return f"rest:{handle.stage_id}"

    # -- vetting ----------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from its statement and the undo it declares."""
        if effect.kind is EffectKind.ENQUEUE:
            return None
        try:
            statement = parse_statement(effect.statement)
            bound = statement.bind(effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        kind = self._types.get(statement.table)
        if kind is None:
            return f"table {statement.table!r} is no resource type this substrate observes"
        if effect.table and effect.table != statement.table:
            return f"the effect targets {effect.table!r} and its statement {statement.table!r}"
        if effect.compensation is None:
            return (
                f"a write to an API cannot be rolled back, so the effect declares its undo: "
                f"'{COMPENSATIONS[statement.verb]} {statement.table}'"
            )
        try:
            undo, table = parse_compensation(effect.compensation.statement)
        except ValueError as exc:
            return str(exc)
        if table != statement.table or undo != COMPENSATIONS[statement.verb]:
            return (
                f"{statement.verb} is undone by '{COMPENSATIONS[statement.verb]} "
                f"{statement.table}', not '{undo} {table}'"
            )
        if statement.verb == "create":
            template = _json(bound["resource"])
            if not isinstance(template, dict):
                return "create takes a resource template, a JSON object"
            return self._template_problem(kind, statement, template, effect)
        resource_id = bound["id"]
        if isinstance(resource_id, bool) or not isinstance(resource_id, str | int):
            return "a resource id is text or a whole number"
        if not _RESOURCE_ID.fullmatch(str(resource_id)):
            return f"{resource_id!r} is not a resource id"
        if statement.verb == "patch":
            patch = _json(bound["patch"])
            if not isinstance(patch, dict):
                return "patch takes a JSON merge patch, an object"
            return self._template_problem(kind, statement, patch, effect)
        return None

    @staticmethod
    def _template_problem(
        kind: RestResource, statement: RestStatement, template: dict[str, Any], effect: Effect
    ) -> str | None:
        set_here = sorted(p for p in (ID, *kind.ignored) if field_value(template, p)[0])
        if set_here:
            return (
                f"a template may not set {', '.join(set_here)}: the substrate or the API writes "
                f"them"
            )
        listed = _listed(statement, template)
        if listed is not None:
            return listed
        try:
            _fill(template, effect.parameters)
        except ValueError as exc:
            return str(exc)
        return None

    # -- lifecycle ----------------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Open a stage: nothing is read or written until an effect is applied.

        :raises StageConflictError: If a stage is already open here.
        """
        if self._stage is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage "
                f"{self._stage.handle.stage_id} open"
            )
        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=uuid.uuid4(),
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        self._stage = _Stage(handle, plan)
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        """Predict one resource's after image, reading what it needs live.

        :raises ForbiddenStatementError: On a statement :meth:`reject_reason` refuses.
        :raises StageConflictError: On ``expect-version`` naming another version.
        :raises StageError: On a resource that is not there, or a tenant a plan may not write.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            if self._control is None:
                raise OutboundRequestError(
                    f"effect {effect.effect_id!r} is an outbound request, and this REST "
                    f"substrate has no control database to hold an outbox",
                    reason="substrate",
                    sink=effect.request.sink if effect.request is not None else None,
                )
            return self._control.apply(self._control_stage(stage), effect)
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(
                f"effect {effect.effect_id!r} refused: {refusal}", reason="statement_kind"
            )
        statement = parse_statement(effect.statement)
        bound = statement.bind(effect.parameters)
        kind = self._types[statement.table]
        where = f"effect {effect.effect_id!r}"
        if statement.verb == "create":
            resource = dict(_fill(_json(bound["resource"]), effect.parameters))
            resource_id = self._new_id(stage, kind, effect.effect_id)
            resource[ID] = resource_id
            obj = _Resource(kind, resource_id, None, None, resource, True, [effect.effect_id])
            if obj.key in stage.resources:
                raise StageError(f"{where}: {kind.table}/{resource_id} is created twice")
            self._enter(stage, obj, resource, where)
            stage.resources[obj.key] = obj
        else:
            obj = self._read(stage, kind, str(bound["id"]), where)
            if statement.verb == "expect-version":
                if obj.version != str(bound["version"]):
                    raise StageConflictError(
                        f"{where}: {kind.table}/{obj.resource_id} is at version {obj.version}, "
                        f"not {bound['version']}, the version the plan names: the state it was "
                        f"approved on is gone"
                    )
                return EffectOutcome(effect.effect_id, 0, datetime.now(UTC))
            current = obj.desired if obj.staged else obj.live
            assert current is not None
            patch = _fill(_json(bound["patch"]), effect.parameters)
            desired = _merge(current, patch)
            desired[ID] = obj.resource_id
            for path in kind.ignored:
                found, value = field_value(current, path)
                if found:
                    desired = _merge(desired, _nested(path, value))
            self._enter(stage, obj, desired, where)
            obj.desired = desired
            obj.staged = True
            obj.effects.append(effect.effect_id)
        if self._control is not None:
            self._control.applied_elsewhere(self._control_stage(stage), effect)
        stage.measured = False
        return EffectOutcome(effect.effect_id, 1, datetime.now(UTC))

    def _new_id(self, stage: _Stage, kind: RestResource, effect_id: str) -> str:
        """A created resource's id, the stage's to assign: the same for the same effect of the
        same stage, so a retried write is the same write."""
        digest = hashlib.sha256(f"{stage.handle.stage_id}:{effect_id}".encode()).hexdigest()
        return f"{kind.table[:12]}-{digest[:16]}"

    def _read(self, stage: _Stage, kind: RestResource, resource_id: str, where: str) -> _Resource:
        key = (kind.table, resource_id)
        found = stage.resources.get(key)
        if found is not None:
            return found
        try:
            read = self._api.read(kind, resource_id)
        except _RestError as exc:
            raise StageError(f"{where}: cannot read {kind.table}/{resource_id}: {exc}") from exc
        if read is None:
            raise StageError(f"{where}: there is no {kind.table}/{resource_id}")
        live, version = read
        found = _Resource(kind, resource_id, live, version)
        self._enter(stage, found, live, where)
        scoped = next((s[key] for s in stage.scope.values() if key in s), None)
        if scoped is not None and fingerprint(scoped, kind.ignored) != fingerprint(
            live, kind.ignored
        ):
            raise StageConflictError(
                f"{where}: {kind.table}/{resource_id} changed while the stage read its tenant"
            )
        stage.resources[key] = found
        return found

    def _enter(
        self, stage: _Stage, obj: _Resource, resource: Mapping[str, Any], where: str
    ) -> None:
        """List the tenant ``resource`` is in, the first time the stage reaches it."""
        tenant = obj.kind.tenant_of(resource)
        if obj.kind.tenant is not None and tenant is None:
            raise StageError(
                f"{where}: {obj.kind.table}/{obj.resource_id} names no tenant "
                f"({obj.kind.tenant}), so its write cannot be verified against its neighbors"
            )
        if tenant is None:
            return
        if self._tenants and tenant not in self._tenants:
            raise StageError(f"{where}: tenant {tenant!r} is not one a plan may write")
        if tenant in stage.scope:
            return
        stage.scope[tenant] = self._list_tenant(tenant)

    def _list_tenant(self, tenant: str) -> dict[tuple[str, str], dict[str, Any]]:
        scope: dict[tuple[str, str], dict[str, Any]] = {}
        for kind in self._types.values():
            parameter = kind.scope_parameter
            if parameter is None:
                continue
            try:
                for found in self._api.find(kind, parameter, tenant, limit=self._max_rows):
                    scope[(kind.table, str(found.get(ID)))] = found
            except _RestError as exc:
                raise StageError(f"cannot list {kind.table} of tenant {tenant}: {exc}") from exc
        return scope

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Every resource the stage writes, as predicted: before (as read) and after (as the
        plan's operations make it)."""
        stage = self._require(handle)
        deltas = [self._delta(obj) for obj in self._writes(stage)]
        truncated = len(deltas) > self._max_rows
        outbound: tuple[OutboundDelta, ...] = ()
        facts: tuple[InboundFact, ...] = ()
        if self._control is not None and stage.control is not None:
            control = self._control.diff(stage.control)
            outbound, facts = control.outbound, control.facts
            truncated = truncated or control.truncated
        stage.measured = True
        return EffectDiff(
            plan_id=handle.plan_id,
            stage_id=handle.stage_id,
            substrate_id=self.substrate_id,
            computed_at=datetime.now(UTC),
            deltas=tuple(deltas[: self._max_rows]),
            truncated=truncated,
            outbound=outbound,
            facts=facts,
        )

    @staticmethod
    def _delta(obj: _Resource) -> RowDelta:
        kind = obj.kind
        before = kind.image(obj.live) if obj.live is not None else None
        assert obj.desired is not None
        after = kind.image(obj.desired)
        return RowDelta(
            table=kind.table,
            primary_key=obj.resource_id,
            before=before,
            after=after,
            tenant_id=after[TENANT],
            partitions={d: str(after[d]) for d in kind.partitions if after.get(d) is not None},
        )

    def _writes(self, stage: _Stage) -> list[_Resource]:
        """The resources a commit writes, in the order they were first changed."""
        found = []
        for obj in stage.resources.values():
            if not obj.staged or obj.desired is None:
                continue
            if obj.live is None or obj.kind.image(obj.live) != obj.kind.image(obj.desired):
                found.append(obj)
        return found

    # -- the control database ------------------------------------------------------

    def _control_stage(self, stage: _Stage) -> StageHandle:
        assert self._control is not None
        if stage.control is None:
            stage.control = self._control._open(stage.plan, stage.handle.stage_id)
        return stage.control

    def pending_facts(self, scope_id: str) -> tuple[InboundFact, ...]:
        return () if self._control is None else self._control.pending_facts(scope_id)

    def consume_facts(
        self, handle: StageHandle, fact_ids: Sequence[uuid.UUID], scope_id: str
    ) -> None:
        stage = self._require(handle)
        if self._control is None:
            raise InboundFactError(
                "this REST substrate has no control database, so no inbox to consume a fact from"
            )
        self._control.consume_facts(self._control_stage(stage), fact_ids, scope_id)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        stage = self._require(handle)
        if self._control is None:
            raise SubstrateConfigurationError(
                "rate windows keep their history in a control database, and this REST "
                "substrate has none"
            )
        return self._control.measure_windows(self._control_stage(stage), charges)

    # -- the undo, the commit, the read-back, and recovery ---------------------------

    def write_undo(self, handle: StageHandle) -> str:
        """Write each written resource's before image, and every tenant as the stage listed it,
        before the commit writes anything; the undo's SHA-256."""
        stage = self._require(handle)
        writes = [
            {
                "table": obj.kind.table,
                "id": obj.resource_id,
                "action": obj.action,
                "before": obj.live,
                "after": {FINGERPRINT: fingerprint(obj.desired or {}, obj.kind.ignored)},
            }
            for obj in self._writes(stage)
        ]
        scope = {
            tenant: [
                {
                    "table": table,
                    "id": resource_id,
                    "fingerprint": fingerprint(resource, self._types[table].ignored),
                }
                for (table, resource_id), resource in sorted(found.items())
            ]
            for tenant, found in sorted(stage.scope.items())
        }
        stage.undo = self._journal.write(
            handle.stage_id,
            {
                "stage_id": str(handle.stage_id),
                "server": self._api.server,
                "writes": writes,
                "scope": scope,
            },
        )
        return stage.undo

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Write each resource as predicted, on the version read, then read every tenant back
        against the prediction.

        :raises StageConflictError: If a tenant moved after it was read, or the first write's
            version is gone (``412``/``409``): nothing is written.
        :raises CompensatedError: If a later write failed, or the read-back was not the
            prediction: what was written is put back.
        :raises CommitUnsettledError: If the put-back failed too: the undo journal stays for
            recovery, and the intent stays open.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if not stage.measured:
            raise StageError(f"stage {handle.stage_id} is committed before it is measured")
        if stage.undo is None:
            raise StageError(
                f"stage {handle.stage_id}: a predicted commit needs its undo written first"
            )
        writes = self._writes(stage)
        redo = self._redo_path(handle.stage_id)
        stage.committing = True

        def run(conn: sqlite3.Connection | None) -> None:
            if conn is not None:
                record = {
                    "stage_id": str(handle.stage_id),
                    "tables": capture(conn, handle.stage_id),
                }
                durable_write(redo, json.dumps(record, sort_keys=True).encode("utf-8"))
            if writes:
                self._apply_all(stage, writes)

        try:
            if self._control is None:
                run(None)
            else:
                self._control._commit(self._control_stage(stage), run)
        except (StageConflictError, CompensatedError):
            redo.unlink(missing_ok=True)
            stage.committing = False
            raise
        except CommitUnsettledError:
            stage.unsettled = True
            raise
        redo.unlink(missing_ok=True)
        stage.committing = False
        stage.done = True
        return CommitReceipt(
            stage_id=handle.stage_id,
            plan_id=handle.plan_id,
            committed_at=datetime.now(UTC),
            diff_hash="",
            verdict_hash="",
            substrate_txn_id=f"rest:{handle.stage_id}" if writes else None,
        )

    def _headers(
        self, stage_id: uuid.UUID, kind: RestResource, version: str | None, *, create: bool
    ) -> dict[str, str]:
        headers = {self._header: str(stage_id)}
        if create:
            headers["If-None-Match"] = "*"
        elif kind.version == "etag" and version is not None:
            headers["If-Match"] = version
        return headers

    def _body(
        self,
        kind: RestResource,
        current: Mapping[str, Any] | None,
        desired: Mapping[str, Any],
        version: str | None,
    ) -> tuple[str, object, str]:
        """How to write ``desired`` over ``current``: the method, the body, its content type."""
        clean = _without(desired, kind.ignored)
        if current is None or kind.write == "put":
            body: dict[str, Any] = clean
            method, content_type = "PUT", "application/json"
        else:
            body = merge_diff(_without(current, kind.ignored), clean)
            body.pop(ID, None)
            method, content_type = "PATCH", "application/merge-patch+json"
        if current is not None and kind.version != "etag" and version is not None:
            body = _merge(body, _nested(kind.version, _number(version)))
        return method, body, content_type

    def _apply_all(self, stage: _Stage, writes: Sequence[_Resource]) -> None:
        undo = stage.undo or ""
        moved = self._moved(stage)
        if moved:
            raise StageConflictError(
                f"the tenant changed after the stage read it ({'; '.join(moved)}): nothing was "
                f"written"
            )
        applied: list[_Resource] = []
        for obj in writes:
            assert obj.desired is not None
            method, body, content_type = self._body(obj.kind, obj.live, obj.desired, obj.version)
            try:
                landed = self._api.call(
                    method,
                    obj.path(),
                    body,
                    headers=self._headers(
                        stage.handle.stage_id, obj.kind, obj.version, create=obj.live is None
                    ),
                    content_type=content_type,
                )
                obj.written = (
                    _version_of(obj.kind, landed.body, landed.etag)
                    if isinstance(landed.body, dict)
                    else landed.etag
                )
            except _RestError as exc:
                if not applied and exc.conflict:
                    raise StageConflictError(
                        f"{obj.kind.table}/{obj.resource_id} changed after it was measured "
                        f"(HTTP {exc.status}): nothing was written: {exc.message}"
                    ) from None
                self._put_back(stage, exc.message, applied)
                raise CompensatedError(
                    f"stage {stage.handle.stage_id}: writing {obj.kind.table}/{obj.resource_id} "
                    f"failed (HTTP {exc.status}: {exc.message}); every resource written before it "
                    f"was put back from undo {undo[:16]}",
                    applied=len(applied),
                    restored=len(applied),
                    undo=undo,
                ) from None
            applied.append(obj)
        found = self._discrepancies(stage)
        if found:
            restored = self._put_back(stage, "the read-back was not the prediction", applied)
            count = len(stage.foreign)
            left = (
                f"; {tally(count, 'change')} another request made "
                f"({', '.join(stage.foreign)}) {'was' if count == 1 else 'were'} left alone, "
                f"for a person to review"
                if stage.foreign
                else ""
            )
            raise CompensatedError(
                f"stage {stage.handle.stage_id}: what the API holds after the write is not what "
                f"was predicted ({'; '.join(found)}); every resource the write changed was put "
                f"back from undo {undo[:16]}{left}",
                applied=len(applied),
                restored=restored,
                undo=undo,
                discrepancies=tuple(found),
            )

    def _now(self, stage: _Stage) -> dict[tuple[str, str], dict[str, Any]]:
        """Every tenant the stage read, and every resource it writes, as the API holds them now."""
        current: dict[tuple[str, str], dict[str, Any]] = {}
        for tenant in stage.scope:
            current.update(self._list_tenant(tenant))
        for obj in self._writes(stage):
            if obj.key not in current:
                read = self._api.read(obj.kind, obj.resource_id)
                if read is not None:
                    current[obj.key] = read[0]
        return current

    def _before(self, stage: _Stage) -> dict[tuple[str, str], dict[str, Any]]:
        before: dict[tuple[str, str], dict[str, Any]] = {}
        for found in stage.scope.values():
            before.update(found)
        for obj in stage.resources.values():
            if obj.live is not None:
                before.setdefault(obj.key, obj.live)
        return before

    def _same(self, table: str, a: Mapping[str, Any] | None, b: Mapping[str, Any] | None) -> bool:
        if a is None or b is None:
            return a is b
        ignored = self._types[table].ignored
        return fingerprint(a, ignored) == fingerprint(b, ignored)

    def _moved(self, stage: _Stage) -> list[str]:
        """Each resource of the stage's tenants that is not as the stage read it. What the stage
        writes is left to the API's own check on each write."""
        before = self._before(stage)
        current = self._now(stage)
        written = {o.key for o in self._writes(stage)}
        moved = []
        for key in sorted((set(before) | set(current)) - written):
            then, now = before.get(key), current.get(key)
            if not self._same(key[0], then, now):
                state = "created" if then is None else "gone" if now is None else "changed"
                moved.append(f"{key[0]}/{key[1]} {state}")
        return moved

    def _discrepancies(self, stage: _Stage) -> list[str]:
        """What the API holds now that the prediction does not say: each written resource as
        predicted, every other one as it was read."""
        expected = self._before(stage)
        for obj in self._writes(stage):
            assert obj.desired is not None
            expected[obj.key] = obj.desired
        current = self._now(stage)
        written = {o.key for o in self._writes(stage)}
        found = []
        for key in sorted(set(expected) | set(current)):
            kind = self._types[key[0]]
            want, have = expected.get(key), current.get(key)
            named = f"{key[0]}/{key[1]}"
            if want is None:
                found.append(f"{named} was created, and the plan created no such resource")
            elif have is None:
                found.append(f"{named} is gone")
            else:
                wanted, held = kind.image(want), kind.image(have)
                if wanted != held:
                    changed = [
                        f"{c} {wanted.get(c)!r} -> {held.get(c)!r}"
                        for c in sorted(set(wanted) - {FINGERPRINT})
                        if wanted.get(c) != held.get(c)
                    ]
                    found.append(
                        f"{named}: "
                        + (", ".join(changed) if changed else "a field no column names")
                        + (
                            ", not as predicted"
                            if key in written
                            else ", which the plan did not change"
                        )
                    )
        return found

    def _put_back(self, stage: _Stage, why: str, applied: Sequence[_Resource]) -> int:
        """Put back everything the stage's writes changed, as it was read: a created resource
        voided. A change is the stage's when it wrote the resource (``applied``), or when the
        API's ``source`` field names the stage's request (a rule the write set off). Anything
        else changed since is someone else's, and is never put back: it is named for a person
        instead. A resource the stage wrote and someone wrote again since is never put back
        either. Each write is conditional on the version read back. How many were put back.

        :raises CommitUnsettledError: If any cannot be.
        """
        before = self._before(stage)
        current = self._now(stage)
        written = {o.key: o.written for o in applied}
        ours = str(stage.handle.stage_id)
        failures = []
        restored = 0
        for key in sorted(set(before) | set(current), reverse=True):
            then, now = before.get(key), current.get(key)
            if now is None or self._same(key[0], then, now):
                continue
            kind = self._types[key[0]]
            source = None
            if kind.source is not None:
                _, value = field_value(now, kind.source)
                source = None if value is None else str(value)
            if key in written:
                read = self._api.read(kind, key[1])
                version = None if read is None else read[1]
                rewritten = written[key] is not None and version != written[key]
                if (source is not None and source != ours) or (source is None and rewritten):
                    failures.append(
                        f"{key[0]}/{key[1]}: written again by someone else since the stage wrote it"
                    )
                    continue
            elif source != ours:
                stage.foreign.append(f"{key[0]}/{key[1]}")
                continue
            problem = self._restore(stage.handle.stage_id, kind, key[1], then)
            if problem is None:
                restored += 1
            else:
                failures.append(problem)
        if restored:
            self._undone.add(stage.handle.stage_id)
        if failures:
            stage.unsettled = True
            raise CommitUnsettledError(
                f"stage {stage.handle.stage_id}: {why}, and the undo could not put everything "
                f"back: {'; '.join(failures)}. The undo journal stays for recovery"
            )
        return restored

    def _restore(
        self,
        stage_id: uuid.UUID,
        kind: RestResource,
        resource_id: str,
        before: Mapping[str, Any] | None,
    ) -> str | None:
        """Put one resource back as ``before``, or void it when it was created; a problem, or
        ``None`` when it is back."""
        named = f"{kind.table}/{resource_id}"
        path = f"{kind.path}/{quote(resource_id, safe='')}"
        try:
            read = self._api.read(kind, resource_id)
            if read is None:
                return None if before is None else f"{named} is gone"
            now, version = read
            headers = self._headers(stage_id, kind, version, create=False)
            if before is None:
                if kind.void is None:
                    self._api.call("DELETE", path, headers=headers)
                    return None
                target = _merge(now, dict(kind.void))
            else:
                target = dict(before)
            method, body, content_type = self._body(kind, now, target, version)
            landed = self._api.call(method, path, body, headers=headers, content_type=content_type)
        except (_RestError, SubstrateUnavailableError) as exc:
            return f"{named}: {exc}"
        if (
            before is not None
            and isinstance(landed.body, dict)
            and not self._same(kind.table, landed.body, before)
        ):
            return f"{named} came back other than it was"
        return None

    def _redo_path(self, stage_id: uuid.UUID) -> Path:
        return self._journal.directory / f"{stage_id}.redo.json"

    def resolve_intent(self, stage_id: uuid.UUID, *, txid: str | None = None) -> bool | None:
        """Whether a stage a crash interrupted was written, from each resource as the API holds
        it now: as predicted, it was written; as it was read, it was not. All written, ``True``
        (and the control rows written again if they were lost); none, ``False``; some, put back
        from the undo, then ``False`` (and :meth:`compensated` names the undo). ``None`` when a
        resource is neither, or no undo of the stage is left: something else wrote it, and only
        an operator can say."""
        found = self._journal.read(stage_id)
        if found is None:
            return None
        document, digest = found
        states: list[tuple[RestResource, Mapping[str, Any], str]] = []
        for entry in document.get("writes", ()):
            kind = self._types.get(str(entry.get("table")))
            if kind is None:
                return None
            try:
                read = self._api.read(kind, str(entry["id"]))
            except (_RestError, SubstrateUnavailableError):
                return None
            current = None if read is None else read[0]
            state = self._state_of(kind, entry, current)
            if state is None:
                return None
            states.append((kind, entry, state))
        redo = self._redo_path(stage_id)
        if states and all(s == "applied" for _, _, s in states):
            if redo.exists() and self._control is not None:
                record = json.loads(redo.read_bytes())
                replay(
                    self._control.path,
                    str(record["stage_id"]),
                    record["tables"],
                    timeout=self._stage_seconds,
                )
            redo.unlink(missing_ok=True)
            self._journal.discard(stage_id)
            return True
        applied = [(k, e) for k, e, s in states if s == "applied"]
        if applied:
            problems = [
                p
                for kind, entry in reversed(applied)
                if (p := self._restore(stage_id, kind, str(entry["id"]), entry.get("before")))
                is not None
            ]
            if problems:
                logger.warning(
                    "stage %s: a partial write could not be put back yet: %s",
                    stage_id,
                    "; ".join(problems),
                )
                return None
            self._undone.add(stage_id)
        if stage_id in self._undone:
            self._undone.discard(stage_id)
            self._compensated[stage_id] = digest
        redo.unlink(missing_ok=True)
        self._journal.discard(stage_id)
        return False

    @staticmethod
    def _state_of(
        kind: RestResource, entry: Mapping[str, Any], current: Mapping[str, Any] | None
    ) -> str | None:
        """``applied``, ``untouched``, or ``None`` when the resource is neither as written nor as
        it was."""
        before = entry.get("before")
        if current is None:
            return "untouched" if entry.get("action") == "create" else None
        predicted = (entry.get("after") or {}).get(FINGERPRINT)
        if fingerprint(current, kind.ignored) == predicted:
            return "applied"
        if before is not None and fingerprint(current, kind.ignored) == fingerprint(
            before, kind.ignored
        ):
            return "untouched"
        return None

    def compensated(self, stage_id: uuid.UUID) -> str | None:
        """The undo recovery put a partial write back from, if it did."""
        return self._compensated.pop(stage_id, None)

    # -- savepoints ----------------------------------------------------------------

    def savepoint(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise ValueError(f"unsafe savepoint name: {name!r}")
        stage.savepoints.append((name, copy.deepcopy(stage.resources)))
        if self._control is not None:
            self._control.savepoint(self._control_stage(stage), name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        stage.resources = copy.deepcopy(self._savepoint(stage, name))
        stage.measured = False
        if self._control is not None:
            self._control.rollback_to(self._control_stage(stage), name)

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        self._savepoint(stage, name)
        index = max(i for i, (n, _) in enumerate(stage.savepoints) if n == name)
        del stage.savepoints[index:]
        if self._control is not None:
            self._control.release_savepoint(self._control_stage(stage), name)

    @staticmethod
    def _savepoint(stage: _Stage, name: str) -> dict[tuple[str, str], _Resource]:
        for found, resources in reversed(stage.savepoints):
            if found == name:
                return resources
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage ---------------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        """Discard the stage: nothing was written to the API (a stage only reads until it
        commits), and the control stage rolls back."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        stage.done = True
        if self._control is not None and stage.control is not None:
            self._control.abort(stage.control)

    def close(self, handle: StageHandle) -> None:
        """End the stage. Its undo is kept only while its outcome is unsettled."""
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        self.abort(handle)
        if self._control is not None and stage.control is not None:
            self._control.close(stage.control)
        if not (stage.unsettled or stage.committing):
            self._journal.discard(handle.stage_id)
        self._stage = None

    def _require(self, handle: StageHandle) -> _Stage:
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id or stage.done:
            raise StageError(f"stage {handle.stage_id} is not open on this substrate")
        return stage

    def _assert_live(self, handle: StageHandle) -> None:
        if datetime.now(UTC) > handle.expires_at:
            raise StageExpiredError(f"stage {handle.stage_id} expired at {handle.expires_at}")


def _nested(path: str, value: Any) -> dict[str, Any]:
    """``{"a": {"b": value}}`` for ``a.b``."""
    out: Any = value
    for part in reversed(path.split(".")):
        out = {part: out}
    return dict(out)


def _number(text: str) -> object:
    """A version as the API sent it: a whole number when it reads as one."""
    return int(text) if re.fullmatch(r"-?\d+", text) else text
