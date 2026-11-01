"""A FHIR R4 server as a class V substrate: predict a change, write it on the
version read, read it back, and put it back if it is not what was predicted
(1.4.0).

The guarantee is class V (:mod:`interlock.predicted`). A FHIR server has no
transaction a stage can hold open and no dry run, so the substrate builds the
measurement from what the API does have, a version on every resource and
conditional writes:

- **The before image, and the chart it belongs to.** Each resource an effect
  reaches is read live, with its ``meta.versionId``. The first time a stage
  reaches a patient, it reads that patient's whole compartment, every
  resource of every observed type (``[type]?patient=<id>``): the scope the
  write is verified over.
- **A prediction, judged before anything is written.** ``create`` builds a
  resource from its template, each conditional reference
  (``Encounter?location=:bed&status=in-progress``) resolved by a search that
  must find exactly one; ``patch`` applies a JSON merge patch to what was
  read. The diff is the prediction, so every checker, partition and window
  judges it, and a create for the wrong patient is refused before the server
  sees it.
- **The undo, written down first.** The before image of every resource the
  commit writes, and the compartments as read, go to the undo journal before
  the first write. A created resource is undone by marking it
  ``entered-in-error``; an updated one by writing its before image back. A
  clinical record is never deleted.
- **A conditional write.** Before writing, the compartments are read again:
  anything that moved since the stage read it (a clinician's edit while the
  plan waited for a warrant) refuses the commit, and nothing is written. Each
  update then carries ``If-Match`` on the version read, so a change in the
  last instant answers ``412 Precondition Failed``. Every write carries the
  stage's id, in ``meta.tag`` and in ``X-Request-Id``, which the server's
  ``AuditEvent`` log records.
- **A read-back, held to the prediction.** The compartments are read once
  more, and each resource compared with what the plan predicted it would be:
  the written ones as predicted, every other one unchanged. A difference (a
  rule on the server that stopped the encounter's other orders, a dose the
  server rewrote) is never accepted: everything the write changed is put
  back, conditional on the version read back, and the stage is recorded
  ``COMPENSATED``, its receipt's outcome ``compensated`` (ARC1 1.4).

Each resource is one :class:`~interlock.types.RowDelta`:

- **table**: the type's table (:class:`FhirType`), ``medicationrequests``;
- **primary key** (``id``): the resource's id; a created resource's id is
  assigned by the stage (``PUT`` as create), so the prediction names it;
- **tenant** (``patient``): the patient its compartment reference names
  (``subject.reference``); other partitions from references or fields;
- **columns**: what the type names, each a path (``status``,
  ``dosageInstruction.0.doseAndRate.0.doseQuantity.value``,
  ``extension('https://example.org/mme').valueInteger``), and
  ``fingerprint``, a digest of the whole resource less its bookkeeping
  (``meta.versionId``, ``meta.lastUpdated``, the stage tag, the narrative),
  so a change to a field no column names is still a change.

**Statements**, one operation each; a template is a JSON literal in which a
string value ``":name"`` is replaced, whole, by that parameter (and a query
value of a conditional reference likewise)::

    create <table> '<resource template>'
    patch <table> :id '<merge patch template>'
    expect-version <table> :id :version

**Compensations**: the substrate cannot roll back
(``requires_compensation``), so each effect carries the undo the plan
declares for it: ``void <table>`` for a create (``entered-in-error``),
``restore <table>`` for a patch or ``expect-version``.

Outbound requests, rate windows and inbound facts need a transactional home a
FHIR server does not have: a control database (SQLite), as for
:class:`~interlock.kubernetes.KubernetesSubstrate`, whose half of a stage is
redone after a crash (:mod:`interlock.control`).

What it cannot do: see a server rule's consequence before the write. That is
caught by the read-back and put back, not refused before it, and the receipt
says ``predicted``, not ``plan-bound``. A server must allow client-assigned
ids (update as create) for a create to be predicted exactly.
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
from urllib.parse import parse_qsl, quote, urlencode

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
from interlock.planbound import UndoJournal
from interlock.predicted import PREDICTED
from interlock.substrate import SqliteSubstrate, TableSpec
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
    "STAGE_TAG",
    "VERBS",
    "FhirStatement",
    "FhirSubstrate",
    "FhirType",
    "fhir_tables",
    "fingerprint",
    "parse_statement",
    "path_value",
]

logger = logging.getLogger("interlock.fhir")

ID: Final = "id"
"""Every type's primary key column: the resource's id."""

PATIENT: Final = "patient"
"""Every type's tenant column: the patient its compartment reference names."""

FINGERPRINT: Final = "fingerprint"
"""Every type's digest column: the resource less its bookkeeping."""

STAGE_TAG: Final = "https://interlock.dev/fhir/stage"
"""The ``meta.tag`` system of the marker every write carries: its code is the
stage's id. Recovery reads it; the server's audit log has the same id in each
write's ``X-Request-Id``."""

VERBS: Final = {
    "create": ("resource",),
    "patch": ("id", "patch"),
    "expect-version": ("id", "version"),
}
"""Each verb of the statement language, and its arguments in order."""

COMPENSATIONS: Final = {"create": "void", "patch": "restore", "expect-version": "restore"}
"""The undo each verb's effect declares: ``void`` marks a created resource
void (``entered-in-error``); ``restore`` writes the before image back."""

_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9_]*")
_TYPE: Final = re.compile(r"[A-Z][A-Za-z]{1,63}")
_RESOURCE_ID: Final = re.compile(r"[A-Za-z0-9\-.]{1,64}")
_SEGMENT: Final = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\('([^']*)'\))?|(\d+)")
_PLACEHOLDER: Final = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_PROTECTED: Final = ("id", "resourceType", "meta")
"""What a template may not set: the substrate's to write."""


# --------------------------------------------------------------------------
# paths, images and the fingerprint
# --------------------------------------------------------------------------


def _segments(path: str) -> list[tuple[str, str | None, int | None]]:
    """A path's segments: ``(name, url, None)`` or ``("", None, index)``.

    :raises ValueError: On a path that is not ``a.b.0.c`` or uses ``name('url')``.
    """
    found: list[tuple[str, str | None, int | None]] = []
    position = 0
    while True:
        match = _SEGMENT.match(path, position)
        if match is None:
            raise ValueError(f"{path!r} is not a path: name.name, a list index, name('url')")
        name, url, index = match.groups()
        found.append((name or "", url, int(index) if index is not None else None))
        position = match.end()
        if position == len(path):
            return found
        if path[position] != ".":
            raise ValueError(f"{path!r} is not a path: expected '.' at {position}")
        position += 1


def path_value(document: Any, path: str) -> tuple[bool, Any]:
    """The value at ``path`` and whether it is there. ``name('url')`` picks
    the item of the list ``name`` whose ``url`` is that (an extension)."""
    current = document
    for name, url, index in _segments(path):
        if index is not None:
            if not isinstance(current, list) or index >= len(current):
                return False, None
            current = current[index]
            continue
        if not isinstance(current, Mapping) or name not in current:
            return False, None
        current = current[name]
        if url is not None:
            if not isinstance(current, list):
                return False, None
            current = next(
                (i for i in current if isinstance(i, Mapping) and i.get("url") == url), None
            )
            if current is None:
                return False, None
    return True, current


def _reference_id(value: Any) -> str | None:
    """A reference's id: ``Patient/p-1`` and ``p-1`` are ``p-1``."""
    if not isinstance(value, str) or not value:
        return None
    return value.rsplit("/", 1)[-1]


def fingerprint(resource: Mapping[str, Any]) -> str:
    """A digest of the resource less its bookkeeping: its version, when it
    was updated, the stage's tag, and its generated narrative."""
    body = copy.deepcopy(dict(resource))
    body.pop("text", None)
    meta = dict(body.get("meta") or {})
    for key in ("versionId", "lastUpdated", "source"):
        meta.pop(key, None)
    tags = [
        t
        for t in meta.get("tag") or ()
        if not (isinstance(t, Mapping) and t.get("system") == STAGE_TAG)
    ]
    if tags:
        meta["tag"] = tags
    else:
        meta.pop("tag", None)
    if meta:
        body["meta"] = meta
    else:
        body.pop("meta", None)
    return hashlib.sha256(canonical_bytes(_canonical_safe(body))).hexdigest()


def _canonical_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _canonical_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canonical_safe(v) for v in value]
    if isinstance(value, float):
        return format(value, "g")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 2**53:
        return str(value)
    return value


def _version(resource: Mapping[str, Any] | None) -> str | None:
    if resource is None:
        return None
    found = (resource.get("meta") or {}).get("versionId")
    return str(found) if found is not None else None


@dataclass(frozen=True, slots=True)
class FhirType:
    """One resource type the substrate observes, as one table.

    :ivar table: The table's name (an identifier): ``medicationrequests``.
    :ivar resource_type: The FHIR type: ``MedicationRequest``.
    :ivar columns: Each column and the path of its value (module docstring).
    :ivar partitions: Each partition dimension beside the patient, and the
        path of its value; a reference contributes its id.
    :ivar tenant: The path of the reference to the patient whose compartment
        the resource is in (``subject.reference``; ``for.reference`` for a
        ``Task``).
    :ivar compartment: The search parameter that finds a patient's resources
        of this type (``patient``).
    :ivar void_status: The ``status`` that marks a resource of this type
        void, the undo of a create.
    """

    table: str
    resource_type: str
    columns: Mapping[str, str] = field(default_factory=dict)
    partitions: Mapping[str, str] = field(default_factory=dict)
    tenant: str = "subject.reference"
    compartment: str = "patient"
    void_status: str = "entered-in-error"

    def __post_init__(self) -> None:
        for name in [self.table, *self.columns, *self.partitions]:
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(
                    f"type {self.resource_type}: {name!r} is not a lowercase identifier"
                )
        if not _TYPE.fullmatch(self.resource_type):
            raise ValueError(f"{self.resource_type!r} is not a FHIR resource type")
        reserved = {ID, PATIENT, FINGERPRINT}
        clash = sorted(reserved & (set(self.columns) | set(self.partitions)))
        if clash:
            raise ValueError(
                f"type {self.resource_type}: {', '.join(clash)} are every type's own columns"
            )
        if set(self.columns) & set(self.partitions):
            raise ValueError(f"type {self.resource_type}: a column and a partition share a name")
        for path in [*self.columns.values(), *self.partitions.values(), self.tenant]:
            _segments(path)

    def spec(self) -> TableSpec:
        columns = [ID, PATIENT, *self.columns, *self.partitions, FINGERPRINT]
        return TableSpec(
            self.table,
            primary_key=ID,
            columns=columns,
            tenant_column=PATIENT,
            partitions={d: d for d in self.partitions} or None,
        )

    def patient(self, resource: Mapping[str, Any]) -> str | None:
        found, value = path_value(resource, self.tenant)
        return _reference_id(value) if found else None

    def image(self, resource: Mapping[str, Any]) -> dict[str, Any]:
        """The resource's row: every column's value."""
        row: dict[str, Any] = {ID: resource.get("id"), PATIENT: self.patient(resource)}
        for column, path in self.columns.items():
            found, value = path_value(resource, path)
            if not found:
                row[column] = None
            elif isinstance(value, Mapping | list):
                row[column] = canonical_bytes(_canonical_safe(value)).decode("utf-8")
            else:
                row[column] = value
        for dimension, path in self.partitions.items():
            found, value = path_value(resource, path)
            label = _reference_id(value) if isinstance(value, str) and "/" in value else value
            row[dimension] = str(label) if found and label is not None else None
        row[FINGERPRINT] = fingerprint(resource)
        return row


def fhir_tables(types: Sequence[FhirType]) -> tuple[TableSpec, ...]:
    """A FHIR substrate's tables: one per type."""
    return tuple(t.spec() for t in types)


# --------------------------------------------------------------------------
# the statement language
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FhirStatement:
    """A parsed statement: its verb, its table, and each argument, a
    parameter name (``(":", name)``) or a literal (``("'", text)``)."""

    verb: str
    table: str
    arguments: tuple[tuple[str, str], ...]

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


def _tokens(statement: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    text = statement.strip()
    position = 0
    while position < len(text):
        char = text[position]
        if char.isspace():
            position += 1
        elif char == ":":
            found = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)").match(text, position)
            if found is None:
                raise ValueError(f"a parameter is :name, at {position}")
            tokens.append((":", found.group(1)))
            position = found.end()
        elif char == "'":
            end = position + 1
            literal = []
            while True:
                if end >= len(text):
                    raise ValueError("a quoted literal is not closed")
                if text[end] == "'":
                    if end + 1 < len(text) and text[end + 1] == "'":
                        literal.append("'")
                        end += 2
                        continue
                    break
                literal.append(text[end])
                end += 1
            tokens.append(("'", "".join(literal)))
            position = end + 1
        else:
            found = re.compile(r"[a-z][a-z0-9_-]*").match(text, position)
            if found is None:
                raise ValueError(f"unexpected {char!r} at {position}")
            tokens.append(("word", found.group(0)))
            position = found.end()
    return tokens


def parse_statement(statement: str) -> FhirStatement:
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
    if len(arguments) != len(VERBS[verb]):
        raise ValueError(f"{verb} takes {' '.join(':' + a for a in VERBS[verb])}")
    return FhirStatement(verb, table, tuple(arguments))


def parse_compensation(statement: str) -> tuple[str, str]:
    """A compensation's undo and table: ``void <table>`` or ``restore <table>``.

    :raises ValueError: On anything else.
    """
    tokens = _tokens(statement)
    if len(tokens) != 2 or any(kind != "word" for kind, _ in tokens):
        raise ValueError("a compensation is 'void <table>' or 'restore <table>'")
    undo, table = tokens[0][1], tokens[1][1]
    if undo not in ("void", "restore"):
        raise ValueError(f"a compensation is void or restore, never {undo!r}")
    return undo, table


def _json(value: object) -> object:
    """A JSON argument: an object as bound, or JSON text."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    if isinstance(value, Mapping):
        return _thaw(value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_thaw(v) for v in value]
    return value


def _fill(template: Any, parameters: Mapping[str, object]) -> Any:
    """``template`` with each ``":name"`` value replaced by its parameter, and
    each query value of a conditional reference likewise, URL-encoded.

    :raises ValueError: On a parameter the effect does not carry.
    """
    if isinstance(template, Mapping):
        filled = {}
        for key, value in template.items():
            if key == "reference" and isinstance(value, str) and "?" in value:
                filled[key] = _fill_query(value, parameters)
            else:
                filled[key] = _fill(value, parameters)
        return filled
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


def _fill_query(reference: str, parameters: Mapping[str, object]) -> str:
    kind, _, query = reference.partition("?")
    pairs = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        whole = _PLACEHOLDER.fullmatch(value)
        if whole is not None:
            if whole.group(1) not in parameters:
                raise ValueError(f"parameter :{whole.group(1)} is not bound")
            value = str(parameters[whole.group(1)])
        pairs.append((name, value))
    return f"{kind}?{urlencode(pairs, quote_via=quote)}"


def _merge(target: Any, patch: Any) -> Any:
    """RFC 7386 JSON Merge Patch."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result = copy.deepcopy(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = _merge(result.get(key), value)
    return result


def _conditional(document: Any) -> list[str]:
    """Every conditional reference (``Type?query``) in ``document``."""
    if isinstance(document, Mapping):
        found = []
        for key, value in document.items():
            if key == "reference" and isinstance(value, str) and "?" in value:
                found.append(value)
            else:
                found.extend(_conditional(value))
        return found
    if isinstance(document, list):
        return [r for v in document for r in _conditional(v)]
    return []


def _resolved(document: Any, answers: Mapping[str, str]) -> Any:
    if isinstance(document, Mapping):
        return {
            k: answers.get(v, v)
            if k == "reference" and isinstance(v, str)
            else _resolved(v, answers)
            for k, v in document.items()
        }
    if isinstance(document, list):
        return [_resolved(v, answers) for v in document]
    return document


# --------------------------------------------------------------------------
# the API
# --------------------------------------------------------------------------


class _FhirError(Exception):
    def __init__(self, status: int, outcome: Mapping[str, Any]) -> None:
        self.status = status
        self.outcome = dict(outcome)
        super().__init__(self.message)

    @property
    def message(self) -> str:
        issues = self.outcome.get("issue") or []
        said = [
            str(i.get("diagnostics") or i.get("code") or "")
            for i in issues
            if isinstance(i, Mapping)
        ]
        return "; ".join(s for s in said if s) or f"HTTP {self.status}"

    @property
    def conflict(self) -> bool:
        return self.status in (409, 412)


class _Api:
    """The FHIR server, over HTTPS (or HTTP on loopback), with a bearer token."""

    __slots__ = ("_context", "_server", "_timeout", "_token")

    def __init__(
        self, server: str, *, token: str | None, ca_file: str | None, timeout: float
    ) -> None:
        self._server = server.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._context: ssl.SSLContext | None = None
        if self._server.startswith("https://"):
            self._context = ssl.create_default_context(cafile=ca_file)
        elif not re.match(r"http://(127\.0\.0\.1|localhost|\[::1\])(:|/|$)", self._server):
            raise SubstrateConfigurationError(
                f"the FHIR server {self._server} is reached over HTTPS; plain HTTP is for "
                f"loopback only"
            )

    @property
    def server(self) -> str:
        return self._server

    def call(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        sent = {"Accept": "application/fhir+json", **dict(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent["Content-Type"] = "application/fhir+json"
        if self._token:
            sent["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(  # noqa: S310 - https, or loopback http
            self._server + path, data=data, headers=sent, method=method
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - https, or loopback http
                request, timeout=self._timeout, context=self._context
            ) as reply:
                return dict(json.loads(reply.read() or b"{}"))
        except urllib.error.HTTPError as exc:
            try:
                answer = json.loads(exc.read() or b"{}")
            except ValueError:
                answer = {}
            raise _FhirError(exc.code, answer if isinstance(answer, dict) else {}) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SubstrateUnavailableError(
                f"cannot reach the FHIR server {self._server}: {exc}"
            ) from exc

    def read(self, resource_type: str, resource_id: str) -> dict[str, Any] | None:
        try:
            return self.call("GET", f"/{resource_type}/{quote(resource_id, safe='')}")
        except _FhirError as exc:
            if exc.status in (404, 410):
                return None
            raise

    def search(self, query: str, *, limit: int) -> list[dict[str, Any]]:
        """Every resource a search (``Type?params``) finds, following
        ``next`` links, at most ``limit``."""
        found: list[dict[str, Any]] = []
        path: str | None = "/" + query
        while path is not None:
            bundle = self.call("GET", path)
            for entry in bundle.get("entry") or ():
                resource = entry.get("resource") if isinstance(entry, Mapping) else None
                if isinstance(resource, dict):
                    found.append(resource)
            if len(found) > limit:
                raise StageError(f"the search {query} found more than {limit} resources")
            path = None
            for link in bundle.get("link") or ():
                if isinstance(link, Mapping) and link.get("relation") == "next":
                    url = str(link.get("url") or "")
                    path = url.removeprefix(self._server) or None
        return found


# --------------------------------------------------------------------------
# the substrate
# --------------------------------------------------------------------------


@dataclass
class _Resource:
    kind: FhirType
    resource_id: str
    live: dict[str, Any] | None
    desired: dict[str, Any] | None = None
    staged: bool = False
    effects: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind.table, self.resource_id)

    @property
    def version(self) -> str | None:
        return _version(self.live)

    @property
    def action(self) -> str:
        return "create" if self.live is None else "update"

    def path(self) -> str:
        return f"/{self.kind.resource_type}/{quote(self.resource_id, safe='')}"


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    resources: dict[tuple[str, str], _Resource] = field(default_factory=dict)
    scope: dict[str, dict[tuple[str, str], dict[str, Any]]] = field(default_factory=dict)
    """Each patient's compartment as the stage first read it."""
    savepoints: list[tuple[str, dict[tuple[str, str], _Resource]]] = field(default_factory=list)
    foreign: list[str] = field(default_factory=list)
    """What a put-back left alone: changed since the stage read it, by a
    request that was not the stage's."""
    control: StageHandle | None = None
    undo: str | None = None
    measured: bool = False
    done: bool = False
    unsettled: bool = False
    committing: bool = False


class FhirSubstrate:
    """Predicted and verified staging on a FHIR R4 server (module docstring).

    :param server: The server's base URL: ``https://...``, or
        ``http://127.0.0.1:...`` for a loopback one (:mod:`interlock.sim.fhir`).
    :param types: The resource types observed, each a table.
    :param journal: Where undos (and control redo records) are written.
    :param patients: The patients a plan may write. Empty: any.
    :param token: The bearer token the substrate acts with.
    :param ca_file: The CA bundle the server's certificate is checked against.
    :param control: A SQLite file ``interlock install`` set up: the outbox,
        the inbox and rate windows' history.
    :param timeout: Seconds one API call may take.
    :raises SubstrateConfigurationError: On a server reached over plain HTTP
        other than loopback, or two types sharing a table.
    """

    __slots__ = (
        "_api",
        "_compensated",
        "_control",
        "_journal",
        "_max_rows",
        "_patients",
        "_stage",
        "_stage_seconds",
        "_types",
        "_undone",
    )

    def __init__(
        self,
        server: str,
        *,
        types: Sequence[FhirType],
        journal: str | Path,
        patients: Sequence[str] = (),
        token: str | None = None,
        ca_file: str | None = None,
        control: str | Path | None = None,
        timeout: float = 15.0,
        max_stage_seconds: float = 120.0,
        max_diff_rows: int = 50_000,
    ) -> None:
        tables = [t.table for t in types]
        if not tables:
            raise SubstrateConfigurationError("a FHIR substrate observes at least one type")
        if len(set(tables)) != len(tables):
            raise SubstrateConfigurationError("each type is its own table")
        if len({t.resource_type for t in types}) != len(tables):
            raise SubstrateConfigurationError("each resource type is one table")
        self._types = {t.table: t for t in types}
        self._patients = frozenset(patients)
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
        return "fhir"

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
        return fhir_tables(tuple(self._types.values()))

    @property
    def commit_markers(self) -> bool:
        """Always: every resource written carries the stage's tag."""
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
        """``fhir:<stage id>``: what the server's audit log echoes, in each
        write's ``X-Request-Id``. ``None`` for a stage that writes no resource
        (its effect is its requests): the server never sees it."""
        stage = self._stage
        if (
            stage is not None
            and stage.handle.stage_id == handle.stage_id
            and not self._writes(stage)
        ):
            return None
        return f"fhir:{handle.stage_id}"

    # -- vetting ----------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from its statement and the
        undo it declares."""
        if effect.kind is EffectKind.ENQUEUE:
            return None
        try:
            statement = parse_statement(effect.statement)
            bound = statement.bind(effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        kind = self._types.get(statement.table)
        if kind is None:
            return f"table {statement.table!r} is no type this substrate observes"
        if effect.table and effect.table != statement.table:
            return f"the effect targets {effect.table!r} and its statement {statement.table!r}"
        if effect.compensation is None:
            return (
                f"a FHIR write cannot be rolled back, so the effect declares its undo: "
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
                + (": a created record is marked void, never deleted" if undo == "restore" else "")
            )
        if statement.verb == "create":
            template = _json(bound["resource"])
            if not isinstance(template, dict):
                return "create takes a resource template, a JSON object"
            if template.get("resourceType", kind.resource_type) != kind.resource_type:
                return f"the template is not a {kind.resource_type}, the type of {kind.table}"
            set_here = sorted(k for k in _PROTECTED if k in template and k != "resourceType")
            if set_here:
                return f"a template may not set {', '.join(set_here)}: the substrate writes them"
            try:
                _fill(template, effect.parameters)
            except ValueError as exc:
                return str(exc)
            return None
        resource_id = bound["id"]
        if isinstance(resource_id, bool) or not isinstance(resource_id, str | int):
            return "a resource id is text or a whole number"
        if not _RESOURCE_ID.fullmatch(str(resource_id)):
            return f"{resource_id!r} is not a FHIR resource id"
        if statement.verb == "patch":
            patch = _json(bound["patch"])
            if not isinstance(patch, dict):
                return "patch takes a JSON merge patch, an object"
            touched = sorted(k for k in _PROTECTED if k in patch)
            if touched:
                return f"a patch may not change {', '.join(touched)}: the substrate writes them"
            try:
                _fill(patch, effect.parameters)
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

        :raises ForbiddenStatementError: On a statement :meth:`reject_reason`
            refuses.
        :raises StageConflictError: On ``expect-version`` naming another
            version, or a resource that moved while it was read.
        :raises StageError: On a resource that is not there, a conditional
            reference that does not resolve to exactly one, or a patient a
            plan may not write.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            if self._control is None:
                raise OutboundRequestError(
                    f"effect {effect.effect_id!r} is an outbound request, and this FHIR "
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
            template = _fill(_json(bound["resource"]), effect.parameters)
            resource = self._resolve(dict(template), where)
            resource["resourceType"] = kind.resource_type
            resource_id = self._new_id(stage, kind, effect.effect_id)
            resource["id"] = resource_id
            obj = _Resource(kind, resource_id, None, resource, True, [effect.effect_id])
            if obj.key in stage.resources:
                raise StageError(f"{where}: {kind.resource_type}/{resource_id} is created twice")
            self._enter(stage, obj, resource, where)
            stage.resources[obj.key] = obj
        else:
            obj = self._read(stage, kind, str(bound["id"]), where)
            if statement.verb == "expect-version":
                if obj.version != str(bound["version"]):
                    raise StageConflictError(
                        f"{where}: {kind.resource_type}/{obj.resource_id} is at version "
                        f"{obj.version}, not {bound['version']}, the version the plan names: the "
                        f"state it was approved on is gone"
                    )
                return EffectOutcome(effect.effect_id, 0, datetime.now(UTC))
            current = obj.desired if obj.staged else obj.live
            assert current is not None
            patch = self._resolve(_fill(_json(bound["patch"]), effect.parameters), where)
            desired = _merge(current, patch)
            for key in _PROTECTED:
                if key in current:
                    desired[key] = copy.deepcopy(current[key])
            self._enter(stage, obj, desired, where)
            obj.desired = desired
            obj.staged = True
            obj.effects.append(effect.effect_id)
        if self._control is not None:
            self._control.applied_elsewhere(self._control_stage(stage), effect)
        stage.measured = False
        return EffectOutcome(effect.effect_id, 1, datetime.now(UTC))

    def _new_id(self, stage: _Stage, kind: FhirType, effect_id: str) -> str:
        """A created resource's id, the stage's to assign: the same for the
        same effect of the same stage, so a retried write is the same write."""
        digest = hashlib.sha256(f"{stage.handle.stage_id}:{effect_id}".encode()).hexdigest()
        return f"{kind.resource_type.lower()[:12]}-{digest[:16]}"

    def _resolve(self, document: dict[str, Any], where: str) -> dict[str, Any]:
        """``document`` with each conditional reference resolved to the one
        resource its search finds."""
        answers: dict[str, str] = {}
        for reference in _conditional(document):
            if reference in answers:
                continue
            target = reference.partition("?")[0]
            if not _TYPE.fullmatch(target):
                raise StageError(f"{where}: {reference!r} is not a conditional reference")
            try:
                found = self._api.search(reference, limit=2)
            except _FhirError as exc:
                raise StageError(f"{where}: the server cannot search {reference}: {exc}") from exc
            if len(found) != 1:
                raise StageError(
                    f"{where}: the conditional reference {reference} matches {len(found)} "
                    f"resources, not exactly one"
                )
            answers[reference] = f"{target}/{found[0].get('id')}"
        return _resolved(document, answers) if answers else document

    def _read(self, stage: _Stage, kind: FhirType, resource_id: str, where: str) -> _Resource:
        key = (kind.table, resource_id)
        found = stage.resources.get(key)
        if found is not None:
            return found
        try:
            live = self._api.read(kind.resource_type, resource_id)
        except _FhirError as exc:
            raise StageError(
                f"{where}: cannot read {kind.resource_type}/{resource_id}: {exc}"
            ) from exc
        if live is None:
            raise StageError(f"{where}: there is no {kind.resource_type}/{resource_id}")
        found = _Resource(kind, resource_id, live)
        self._enter(stage, found, live, where)
        scoped = next((s[key] for s in stage.scope.values() if key in s), None)
        if scoped is not None and _version(scoped) != found.version:
            raise StageConflictError(
                f"{where}: {kind.resource_type}/{resource_id} changed while the stage read its "
                f"chart (version {_version(scoped)}, then {found.version})"
            )
        stage.resources[key] = found
        return found

    def _enter(
        self, stage: _Stage, obj: _Resource, resource: Mapping[str, Any], where: str
    ) -> None:
        """Read the compartment of the patient ``resource`` is in, the first
        time the stage reaches it."""
        patient = obj.kind.patient(resource)
        if patient is None:
            raise StageError(
                f"{where}: {obj.kind.resource_type}/{obj.resource_id} names no patient "
                f"({obj.kind.tenant}), so its write cannot be verified against a chart"
            )
        if self._patients and patient not in self._patients:
            raise StageError(f"{where}: patient {patient!r} is not one a plan may write")
        if patient in stage.scope:
            return
        scope: dict[tuple[str, str], dict[str, Any]] = {}
        for kind in self._types.values():
            for found in self._compartment(kind, patient):
                scope[(kind.table, str(found.get("id")))] = found
        stage.scope[patient] = scope

    def _compartment(self, kind: FhirType, patient: str) -> list[dict[str, Any]]:
        query = f"{kind.resource_type}?{urlencode([(kind.compartment, patient)], quote_via=quote)}"
        try:
            return self._api.search(query, limit=self._max_rows)
        except _FhirError as exc:
            raise StageError(
                f"cannot read patient {patient}'s {kind.resource_type}: {exc}"
            ) from exc

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Every resource the stage writes, as predicted: before (as read)
        and after (as the plan's operations make it)."""
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
            tenant_id=after[PATIENT],
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
                "this FHIR substrate has no control database, so no inbox to consume a fact from"
            )
        self._control.consume_facts(self._control_stage(stage), fact_ids, scope_id)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        stage = self._require(handle)
        if self._control is None:
            raise SubstrateConfigurationError(
                "rate windows keep their history in a control database, and this FHIR "
                "substrate has none"
            )
        return self._control.measure_windows(self._control_stage(stage), charges)

    # -- the undo, the commit, the read-back, and recovery ---------------------------

    def write_undo(self, handle: StageHandle) -> str:
        """Write each written resource's before image, and every chart as the
        stage read it, before the commit writes anything; the undo's SHA-256."""
        stage = self._require(handle)
        writes = [
            {
                "table": obj.kind.table,
                "type": obj.kind.resource_type,
                "id": obj.resource_id,
                "action": obj.action,
                "before": obj.live,
                "after": {FINGERPRINT: fingerprint(obj.desired or {})},
            }
            for obj in self._writes(stage)
        ]
        scope = {
            patient: [
                {"table": table, "id": resource_id, "version": _version(resource)}
                for (table, resource_id), resource in sorted(found.items())
            ]
            for patient, found in sorted(stage.scope.items())
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
        """Write each resource as predicted, on the version read, then read
        every chart back against the prediction.

        With a control database the writes happen inside its stage's
        transaction, just before its ``COMMIT``, after a redo record of that
        transaction is on disk.

        :raises StageConflictError: If a chart moved after it was read, or the
            first write's version is gone (``412``): nothing is written.
        :raises CompensatedError: If a later write failed, or the read-back
            was not the prediction: what was written is put back.
        :raises CommitUnsettledError: If the put-back failed too: the undo
            journal stays for recovery, and the intent stays open.
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
            substrate_txn_id=f"fhir:{handle.stage_id}" if writes else None,
        )

    @staticmethod
    def _headers(stage_id: uuid.UUID, if_match: str | None) -> dict[str, str]:
        headers = {"X-Request-Id": str(stage_id)}
        if if_match is not None:
            headers["If-Match"] = f'W/"{if_match}"'
        return headers

    def _marked(self, stage: _Stage, resource: Mapping[str, Any]) -> dict[str, Any]:
        """``resource`` as written: the stage's tag in place of any other
        stage's, its version and update time the server's."""
        body = copy.deepcopy(dict(resource))
        meta = dict(body.get("meta") or {})
        meta.pop("versionId", None)
        meta.pop("lastUpdated", None)
        tags = [
            t
            for t in meta.get("tag") or ()
            if not (isinstance(t, Mapping) and t.get("system") == STAGE_TAG)
        ]
        tags.append({"system": STAGE_TAG, "code": str(stage.handle.stage_id)})
        meta["tag"] = tags
        body["meta"] = meta
        return body

    def _apply_all(self, stage: _Stage, writes: Sequence[_Resource]) -> None:
        undo = stage.undo or ""
        moved = self._moved(stage)
        if moved:
            raise StageConflictError(
                f"the chart changed after the stage read it ({'; '.join(moved)}): nothing was "
                f"written"
            )
        applied: list[_Resource] = []
        for obj in writes:
            assert obj.desired is not None
            try:
                self._api.call(
                    "PUT",
                    obj.path(),
                    self._marked(stage, obj.desired),
                    headers=self._headers(stage.handle.stage_id, obj.version),
                )
            except _FhirError as exc:
                if not applied and exc.conflict:
                    raise StageConflictError(
                        f"{obj.kind.resource_type}/{obj.resource_id} changed after it was "
                        f"measured (HTTP {exc.status}): nothing was written: {exc.message}"
                    ) from None
                self._put_back(stage, exc.message)
                raise CompensatedError(
                    f"stage {stage.handle.stage_id}: writing {obj.kind.resource_type}/"
                    f"{obj.resource_id} failed (HTTP {exc.status}: {exc.message}); every "
                    f"resource written before it was put back from undo {undo[:16]}",
                    applied=len(applied),
                    restored=len(applied),
                    undo=undo,
                ) from None
            applied.append(obj)
        found = self._discrepancies(stage)
        if found:
            restored = self._put_back(stage, "the read-back was not the prediction")
            left = (
                f"; {len(stage.foreign)} change(s) another request made "
                f"({', '.join(stage.foreign)}) were left as they are, for a person to review"
                if stage.foreign
                else ""
            )
            raise CompensatedError(
                f"stage {stage.handle.stage_id}: what the server holds after the write is not "
                f"what was predicted ({'; '.join(found)}); every resource the write changed was "
                f"put back from undo {undo[:16]}{left}",
                applied=len(applied),
                restored=restored,
                undo=undo,
                discrepancies=tuple(found),
            )

    def _now(self, stage: _Stage) -> dict[tuple[str, str], dict[str, Any]]:
        """Every chart the stage read, and every resource it writes, as the
        server holds them now."""
        current: dict[tuple[str, str], dict[str, Any]] = {}
        for patient in stage.scope:
            for kind in self._types.values():
                for found in self._compartment(kind, patient):
                    current[(kind.table, str(found.get("id")))] = found
        for obj in self._writes(stage):
            if obj.key not in current:
                live = self._api.read(obj.kind.resource_type, obj.resource_id)
                if live is not None:
                    current[obj.key] = live
        return current

    def _before(self, stage: _Stage) -> dict[tuple[str, str], dict[str, Any]]:
        before: dict[tuple[str, str], dict[str, Any]] = {}
        for found in stage.scope.values():
            before.update(found)
        for obj in stage.resources.values():
            if obj.live is not None:
                before.setdefault(obj.key, obj.live)
        return before

    def _moved(self, stage: _Stage) -> list[str]:
        """Each resource of the stage's charts whose version is not the one
        it read: a write since, or one created or gone. What the stage writes
        is left to the server's own check, ``If-Match`` on each write."""
        before = self._before(stage)
        current = self._now(stage)
        written = {o.key for o in self._writes(stage)}
        moved = []
        for key in sorted((set(before) | set(current)) - written):
            then, now = before.get(key), current.get(key)
            if _version(then) != _version(now):
                kind = self._types[key[0]]
                moved.append(
                    f"{kind.resource_type}/{key[1]} "
                    + (
                        "created"
                        if then is None
                        else "gone"
                        if now is None
                        else f"at version {_version(now)}, not {_version(then)}"
                    )
                )
        return moved

    def _discrepancies(self, stage: _Stage) -> list[str]:
        """What the server holds now that the prediction does not say: each
        written resource as predicted, every other one as it was read."""
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
            named = f"{kind.resource_type}/{key[1]}"
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

    def _put_back(self, stage: _Stage, why: str) -> int:
        """Put back everything the stage's writes changed, as it was read: a
        created resource marked void. A change is the stage's when it wrote
        the resource, or when the server says the request that wrote it was
        one of the stage's (``meta.source``, ``#<stage id>``): a rule the
        write set off. Anything else changed since is someone else's, and is
        never put back: it is named for a person instead. Each write is
        conditional on the version read back. How many were put back.

        :raises CommitUnsettledError: If any cannot be.
        """
        before = self._before(stage)
        current = self._now(stage)
        written = {o.key for o in self._writes(stage)}
        ours = f"#{stage.handle.stage_id}"
        failures = []
        restored = 0
        for key in sorted(set(before) | set(current), reverse=True):
            then, now = before.get(key), current.get(key)
            if now is None or _version(then) == _version(now):
                continue
            kind = self._types[key[0]]
            source = str((now.get("meta") or {}).get("source") or "")
            if key not in written and not source.endswith(ours):
                stage.foreign.append(f"{kind.resource_type}/{key[1]}")
                continue
            problem = self._restore(stage.handle.stage_id, kind, key[1], then, now)
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
        kind: FhirType,
        resource_id: str,
        before: Mapping[str, Any] | None,
        now: Mapping[str, Any],
    ) -> str | None:
        """Put one resource back as ``before``, or mark it void when it was
        created; a problem, or ``None`` when it is back."""
        named = f"{kind.resource_type}/{resource_id}"
        if before is None:
            if now.get("status") == kind.void_status:
                return None
            body = copy.deepcopy(dict(now))
            body["status"] = kind.void_status
        else:
            body = copy.deepcopy(dict(before))
        meta = dict(body.get("meta") or {})
        meta.pop("versionId", None)
        meta.pop("lastUpdated", None)
        body["meta"] = meta
        if not meta:
            body.pop("meta")
        try:
            landed = self._api.call(
                "PUT",
                f"/{kind.resource_type}/{quote(resource_id, safe='')}",
                body,
                headers=self._headers(stage_id, _version(now)),
            )
        except (_FhirError, SubstrateUnavailableError) as exc:
            return f"{named}: {exc}"
        if before is not None and kind.image(landed) != kind.image(before):
            return f"{named} came back other than it was"
        return None

    def _redo_path(self, stage_id: uuid.UUID) -> Path:
        return self._journal.directory / f"{stage_id}.redo.json"

    def resolve_intent(self, stage_id: uuid.UUID, *, txid: str | None = None) -> bool | None:
        """Whether a stage a crash interrupted was written, from each resource
        as the server holds it now: tagged with the stage and as predicted, it
        was written; at the version read, it was not. All written, ``True``
        (and the control rows written again if they were lost); none,
        ``False``; some, put back from the undo, then ``False`` (and
        :meth:`compensated` names the undo). ``None`` when a resource is
        neither, or no undo of the stage is left: something else wrote it,
        and only an operator can say. A rule's writes elsewhere in the chart
        are caught by the commit's read-back, not here."""
        found = self._journal.read(stage_id)
        if found is None:
            return None
        document, digest = found
        states: list[tuple[FhirType, Mapping[str, Any], str, dict[str, Any] | None]] = []
        for entry in document.get("writes", ()):
            kind = self._types.get(str(entry.get("table")))
            if kind is None:
                return None
            try:
                current = self._api.read(kind.resource_type, str(entry["id"]))
            except (_FhirError, SubstrateUnavailableError):
                return None
            state = self._state_of(entry, current, str(stage_id))
            if state is None:
                return None
            states.append((kind, entry, state, current))
        redo = self._redo_path(stage_id)
        if states and all(s == "applied" for _, _, s, _ in states):
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
        applied = [(k, e, c) for k, e, s, c in states if s == "applied"]
        if applied:
            problems = [
                p
                for kind, entry, current in reversed(applied)
                if current is not None
                and (
                    p := self._restore(
                        stage_id, kind, str(entry["id"]), entry.get("before"), current
                    )
                )
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
        entry: Mapping[str, Any], current: Mapping[str, Any] | None, marker: str
    ) -> str | None:
        """``applied``, ``untouched``, or ``None`` when the resource is
        neither as written nor as it was."""
        if current is None:
            return "untouched" if entry.get("action") == "create" else None
        tags = (current.get("meta") or {}).get("tag") or ()
        marked = any(
            isinstance(t, Mapping) and t.get("system") == STAGE_TAG and t.get("code") == marker
            for t in tags
        )
        predicted = (entry.get("after") or {}).get(FINGERPRINT)
        if marked and fingerprint(current) == predicted:
            return "applied"
        before = entry.get("before")
        if before is not None and _version(current) == _version(before):
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

    def _savepoint(self, stage: _Stage, name: str) -> dict[tuple[str, str], _Resource]:
        for found, resources in reversed(stage.savepoints):
            if found == name:
                return resources
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage ---------------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        """Discard the stage: nothing was written to the server (a stage only
        reads until it commits), and the control stage rolls back."""
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
