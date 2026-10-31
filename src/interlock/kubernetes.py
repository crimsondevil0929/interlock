"""Kubernetes as a plan-bound substrate: measure a change with the API server's
own dry run, then apply exactly that, on the versions measured (1.3.0).

The guarantee is class P (:mod:`interlock.planbound`): what was measured is the
plan that is applied, and the apply refuses if the cluster moved since. The API
server supplies what the engine needs:

- **A diff read from the system.** Each effect's object is read live (its
  ``resourceVersion`` with it), changed as the statement says, and sent with
  ``?dryRun=All``. The API server runs everything a real write would: defaults,
  every mutating admission webhook, immutable-field checks, every validating
  webhook. What it answers is the after image, so a webhook that turns 6
  replicas into 60 is measured as 60. A dry run that would reach a webhook
  declaring side effects (``sideEffects: Some`` or ``Unknown``) is refused by
  the API server, so a change whose admission cannot be measured is never
  staged.
- **A version the commit is conditional on.** Each write carries the
  ``metadata.resourceVersion`` the stage read (a delete, its precondition). If
  the object changed after it was measured, the API server answers
  ``409 Conflict``, and nothing of the plan is applied: a warrant can only
  execute on the state its approvers saw.
- **A marker recovery can read.** Every object written carries the annotation
  ``interlock.io/stage-id``, and the receipt's transaction id is
  ``kubernetes:<stage id>``, so the cluster's audit log ties each write to its
  receipt (``agentgov reconcile-actions --format k8s-audit-jsonl``).
- **An undo, written down first.** A plan of several objects is not applied
  atomically. Before the first write, the before image of every object goes to
  the undo journal; a write that fails part way puts back what was written,
  and the stage is recorded ``COMPENSATED``.

Each object is one :class:`~interlock.types.RowDelta`:

- **table**: the kind's table (:class:`KubeKind`), ``deployments``;
- **primary key** (``object``): ``<namespace>/<name>``;
- **tenant**: the namespace; other partitions from labels or fields;
- **columns**: what the kind names (``replicas`` at ``spec.replicas``, a
  product such as ``vcpu`` = replicas x CPU request), and ``fingerprint``, a
  digest of the whole object less its bookkeeping, so a change to a field no
  column names is still a change.

A change to an immutable field is refused by the API server. A kind marked
``replace_on_immutable`` (as a GitOps sync with ``Replace=true`` or
``kubectl apply --force`` would) measures it instead as a deletion and a
creation, which ``NoDelete`` sees: the hidden consequence of a forced
replacement is in the diff.

**Statements**, one operation each, with ``:parameters`` or ``'literals'``::

    scale <table> :namespace :name :replicas
    merge-patch <table> :namespace :name :patch     a JSON merge patch (an object)
    apply <table> :manifest                         create or replace the whole object
    delete <table> :namespace :name
    expect-version <table> :namespace :name :version

``expect-version`` pins a plan to the version its approvers saw.

Outbound requests, rate windows and inbound facts need a transactional home a
cluster does not have: a control database (SQLite), as for
:class:`~interlock.git_substrate.GitSubstrate`, whose half of a stage is redone
after a crash (:mod:`interlock.control`).
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
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Final

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
from interlock.planbound import PLAN_BOUND, STAGE_ANNOTATION, UndoJournal
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
    "VERBS",
    "KubeKind",
    "KubeStatement",
    "KubernetesSubstrate",
    "kubernetes_tables",
    "parse_statement",
    "quantity",
]

logger = logging.getLogger("interlock.kubernetes")

OBJECT: Final = "object"
"""Every kind's primary key column: ``<namespace>/<name>``."""

NAMESPACE: Final = "namespace"
"""Every kind's tenant column."""

FINGERPRINT: Final = "fingerprint"
"""Every kind's digest column: the object less its bookkeeping."""

VERBS: Final = {
    "scale": ("namespace", "name", "replicas"),
    "merge-patch": ("namespace", "name", "patch"),
    "apply": ("manifest",),
    "delete": ("namespace", "name"),
    "expect-version": ("namespace", "name", "version"),
}
"""Each verb of the statement language, and its arguments in order."""

_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9_]*")
_NAME: Final = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
_BOOKKEEPING: Final = ("resourceVersion", "generation", "uid", "creationTimestamp", "managedFields")
_SUFFIXES: Final = {
    "m": Decimal("0.001"),
    "k": Decimal(1000),
    "M": Decimal(1000) ** 2,
    "G": Decimal(1000) ** 3,
    "T": Decimal(1000) ** 4,
    "Ki": Decimal(1024),
    "Mi": Decimal(1024) ** 2,
    "Gi": Decimal(1024) ** 3,
    "Ti": Decimal(1024) ** 4,
}


def quantity(value: object) -> Decimal | None:
    """A Kubernetes quantity, exactly: ``2`` is 2, ``500m`` is 0.5, ``1Gi`` is
    1073741824. ``None`` for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if not isinstance(value, str):
        return None
    found = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(m|k|M|G|T|Ki|Mi|Gi|Ti)?", value.strip())
    if found is None:
        return None
    try:
        number = Decimal(found.group(1))
    except InvalidOperation:  # pragma: no cover - the pattern admits only numerals
        return None
    return number * _SUFFIXES[found.group(2)] if found.group(2) else number


def _at(document: Any, path: str) -> tuple[bool, Any]:
    current = document
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


@dataclass(frozen=True, slots=True)
class KubeKind:
    """One kind the substrate observes, as one table.

    :ivar table: The table's name (an identifier): ``deployments``.
    :ivar plural: The URL segment: ``deployments``.
    :ivar kind: The object's ``kind``: ``Deployment``.
    :ivar group: The API group (``apps``), ``""`` for the core group.
    :ivar version: The API version.
    :ivar columns: Each column and where its value is: a dotted path
        (``spec.replicas``, ``spec.template.spec.containers.0.image``), or a
        product of paths, each read as a quantity
        (``spec.replicas * spec.template.spec.containers.0.resources.requests.cpu``).
    :ivar partitions: Each partition dimension beside the namespace, and the
        path of its label (``metadata.labels.account``).
    :ivar replace_on_immutable: Measure a change to an immutable field as the
        deletion and re-creation a forced sync would do, rather than refuse it.
    """

    table: str
    plural: str
    kind: str
    group: str = ""
    version: str = "v1"
    columns: Mapping[str, str] = field(default_factory=dict)
    partitions: Mapping[str, str] = field(default_factory=dict)
    replace_on_immutable: bool = False

    def __post_init__(self) -> None:
        names = [self.table, *self.columns, *self.partitions]
        for name in names:
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(f"kind {self.kind}: {name!r} is not a lowercase identifier")
        reserved = {OBJECT, NAMESPACE, FINGERPRINT}
        clash = sorted(reserved & (set(self.columns) | set(self.partitions)))
        if clash:
            raise ValueError(f"kind {self.kind}: {', '.join(clash)} are every kind's own columns")
        if set(self.columns) & set(self.partitions):
            raise ValueError(f"kind {self.kind}: a column and a partition share a name")
        if not re.fullmatch(r"[a-z][a-z0-9]*", self.plural):
            raise ValueError(f"kind {self.kind}: plural {self.plural!r} is not a resource name")

    @property
    def api_version(self) -> str:
        return f"{self.group}/{self.version}" if self.group else self.version

    def collection(self, namespace: str) -> str:
        prefix = f"/apis/{self.group}/{self.version}" if self.group else "/api/v1"
        return f"{prefix}/namespaces/{namespace}/{self.plural}"

    def spec(self) -> TableSpec:
        columns = [OBJECT, NAMESPACE, *self.columns, *self.partitions, FINGERPRINT]
        return TableSpec(
            self.table,
            primary_key=OBJECT,
            columns=columns,
            tenant_column=NAMESPACE,
            partitions={d: d for d in self.partitions} or None,
        )

    def image(self, obj: Mapping[str, Any]) -> dict[str, Any]:
        """The object's row: every column's value."""
        meta = obj.get("metadata") or {}
        row: dict[str, Any] = {
            OBJECT: f"{meta.get('namespace')}/{meta.get('name')}",
            NAMESPACE: meta.get("namespace"),
        }
        for column, where in self.columns.items():
            row[column] = _value(obj, where)
        for dimension, where in self.partitions.items():
            found, value = _at(obj, where)
            row[dimension] = str(value) if found and value is not None else None
        row[FINGERPRINT] = fingerprint(obj)
        return row


def _value(obj: Mapping[str, Any], where: str) -> Any:
    if "*" in where:
        total = Decimal(1)
        for factor in (f.strip() for f in where.split("*")):
            found, raw = _at(obj, factor)
            number = quantity(raw) if found else None
            if number is None:
                return None
            total *= number
        normal = total.normalize()
        return int(normal) if normal == normal.to_integral_value() else format(normal, "f")
    found, value = _at(obj, where)
    if not found:
        return None
    if isinstance(value, Mapping | list):
        return canonical_bytes(value).decode("utf-8")
    return value


def fingerprint(obj: Mapping[str, Any]) -> str:
    """A digest of the object less its bookkeeping: its version, uid,
    generation, timestamps, status and the stage marker."""
    body = copy.deepcopy(dict(obj))
    body.pop("status", None)
    meta = dict(body.get("metadata") or {})
    for key in _BOOKKEEPING:
        meta.pop(key, None)
    annotations = dict(meta.get("annotations") or {})
    annotations.pop(STAGE_ANNOTATION, None)
    if annotations:
        meta["annotations"] = annotations
    else:
        meta.pop("annotations", None)
    body["metadata"] = meta
    return hashlib.sha256(canonical_bytes(_canonical_safe(body))).hexdigest()


def _canonical_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _canonical_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canonical_safe(v) for v in value]
    if isinstance(value, float):
        return format(value, "g")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 2**53:
        return str(value)
    return value


def kubernetes_tables(kinds: Sequence[KubeKind]) -> tuple[TableSpec, ...]:
    """A Kubernetes substrate's tables: one per kind."""
    return tuple(k.spec() for k in kinds)


# --------------------------------------------------------------------------
# the statement language
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KubeStatement:
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


def parse_statement(statement: str) -> KubeStatement:
    """Read a statement (module docstring).

    :raises ValueError: On anything else.
    """
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
    return KubeStatement(verb, table, tuple(arguments))


# --------------------------------------------------------------------------
# the API
# --------------------------------------------------------------------------


class _ApiError(Exception):
    def __init__(self, status: int, answer: Mapping[str, Any]) -> None:
        self.status = status
        self.answer = dict(answer)
        super().__init__(self.message)

    @property
    def message(self) -> str:
        return str(self.answer.get("message") or f"HTTP {self.status}")

    @property
    def reason(self) -> str:
        return str(self.answer.get("reason") or "")

    def immutable(self) -> bool:
        if self.status != 422:
            return False
        causes = (self.answer.get("details") or {}).get("causes") or []
        named = any(
            c.get("reason") == "FieldValueForbidden" or "immutable" in str(c.get("message", ""))
            for c in causes
        )
        return named or "field is immutable" in self.message


class _Api:
    """The API server, over HTTPS (or HTTP on loopback), with a bearer token."""

    __slots__ = ("_context", "_server", "_timeout", "_token")

    def __init__(
        self,
        server: str,
        *,
        token: str | None,
        ca_file: str | None,
        timeout: float,
    ) -> None:
        self._server = server.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._context: ssl.SSLContext | None = None
        if self._server.startswith("https://"):
            self._context = ssl.create_default_context(cafile=ca_file)
        elif not re.match(r"http://(127\.0\.0\.1|localhost|\[::1\])(:|/|$)", self._server):
            raise SubstrateConfigurationError(
                f"the API server {self._server} is reached over HTTPS; plain HTTP is for "
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
        dry: bool = False,
        merge: bool = False,
    ) -> dict[str, Any]:
        url = self._server + path + ("?dryRun=All" if dry else "")
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = (
                "application/merge-patch+json" if merge else "application/json"
            )
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310 - https, or loopback http
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
            raise _ApiError(exc.code, answer if isinstance(answer, dict) else {}) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SubstrateUnavailableError(
                f"cannot reach the API server {self._server}: {exc}"
            ) from exc


# --------------------------------------------------------------------------
# the substrate
# --------------------------------------------------------------------------


@dataclass
class _Object:
    kind: KubeKind
    namespace: str
    name: str
    live: dict[str, Any] | None
    desired: dict[str, Any] | None = None
    measured: dict[str, Any] | None = None
    replace: bool = False
    staged: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind.table, self.namespace, self.name)

    @property
    def version(self) -> str | None:
        if self.live is None:
            return None
        return str((self.live.get("metadata") or {}).get("resourceVersion") or "") or None

    @property
    def action(self) -> str:
        if self.replace:
            return "replace"
        if self.live is None:
            return "create"
        if self.desired is None:
            return "delete"
        return "update"

    def path(self) -> str:
        return f"{self.kind.collection(self.namespace)}/{self.name}"


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    objects: dict[tuple[str, str, str], _Object] = field(default_factory=dict)
    savepoints: list[tuple[str, dict[tuple[str, str, str], _Object]]] = field(default_factory=list)
    control: StageHandle | None = None
    undo: str | None = None
    measured: bool = False
    done: bool = False
    unsettled: bool = False
    committing: bool = False


class KubernetesSubstrate:
    """Plan-bound staging on a Kubernetes cluster (module docstring).

    :param server: The API server: ``https://...``, or ``http://127.0.0.1:...``
        for a loopback one (:mod:`interlock.sim.kubernetes`).
    :param kinds: The kinds observed, each a table.
    :param namespaces: The namespaces a plan may write. Empty: any.
    :param token: The bearer token the substrate acts with.
    :param ca_file: The CA bundle the server's certificate is checked against.
    :param journal: Where undos (and control redo records) are written.
    :param control: A SQLite file ``interlock install`` set up: the outbox,
        the inbox and rate windows' history.
    :param timeout: Seconds one API call may take.
    :raises SubstrateConfigurationError: On a server reached over plain HTTP
        other than loopback, or two kinds sharing a table.
    """

    __slots__ = (
        "_api",
        "_compensated",
        "_control",
        "_journal",
        "_kinds",
        "_max_rows",
        "_namespaces",
        "_stage",
        "_stage_seconds",
        "_undone",
    )

    def __init__(
        self,
        server: str,
        *,
        kinds: Sequence[KubeKind],
        journal: str | Path,
        namespaces: Sequence[str] = (),
        token: str | None = None,
        ca_file: str | None = None,
        control: str | Path | None = None,
        timeout: float = 15.0,
        max_stage_seconds: float = 120.0,
        max_diff_rows: int = 50_000,
    ) -> None:
        tables = [k.table for k in kinds]
        if not tables:
            raise SubstrateConfigurationError("a Kubernetes substrate observes at least one kind")
        if len(set(tables)) != len(tables):
            raise SubstrateConfigurationError("each kind is its own table")
        self._kinds = {k.table: k for k in kinds}
        self._namespaces = frozenset(namespaces)
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
        return "kubernetes"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=False,
            row_level_diff=True,
            snapshot_isolation=False,
            requires_compensation=False,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            outbound=self._control is not None and self._control.capabilities.outbound,
            measurement=PLAN_BOUND,
            plan_bound=True,
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        return frozenset(self._kinds)

    @property
    def table_specs(self) -> tuple[TableSpec, ...]:
        return kubernetes_tables(tuple(self._kinds.values()))

    @property
    def commit_markers(self) -> bool:
        """Always: every object written carries the stage annotation."""
        return True

    @property
    def server(self) -> str:
        return self._api.server

    @property
    def control(self) -> str | None:
        return None if self._control is None else self._control.path

    def held_operations(self) -> dict[str, tuple[str, ...]]:
        return {} if self._control is None else self._control.held_operations()

    def transaction_id(self, handle: StageHandle) -> str:
        """``kubernetes:<stage id>``: what the cluster's audit log echoes, in
        the annotation every write carries."""
        return f"kubernetes:{handle.stage_id}"

    # -- vetting ----------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        """Why this effect cannot be staged, read from its statement."""
        if effect.kind is EffectKind.ENQUEUE:
            return None
        try:
            statement = parse_statement(effect.statement)
            bound = statement.bind(effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        kind = self._kinds.get(statement.table)
        if kind is None:
            return f"table {statement.table!r} is no kind this substrate observes"
        if effect.table and effect.table != statement.table:
            return f"the effect targets {effect.table!r} and its statement {statement.table!r}"
        try:
            namespace, name = self._names(kind, statement.verb, bound)
        except ValueError as exc:
            return str(exc)
        if self._namespaces and namespace not in self._namespaces:
            return f"namespace {namespace!r} is not one a plan may write"
        if not _NAME.fullmatch(name) or not _NAME.fullmatch(namespace):
            return f"{namespace!r}/{name!r} is not an object name"
        if statement.verb == "scale":
            replicas = bound["replicas"]
            if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 0:
                return "scale takes a whole, non-negative number of replicas"
        if statement.verb == "merge-patch" and not isinstance(_json(bound["patch"]), dict):
            return "merge-patch takes a JSON object"
        return None

    def _names(self, kind: KubeKind, verb: str, bound: Mapping[str, object]) -> tuple[str, str]:
        if verb == "apply":
            manifest = _json(bound["manifest"])
            if not isinstance(manifest, dict):
                raise ValueError("apply takes a manifest, a JSON object")
            if manifest.get("kind") != kind.kind or manifest.get("apiVersion") != kind.api_version:
                raise ValueError(
                    f"the manifest is not a {kind.api_version} {kind.kind}, the kind of "
                    f"table {kind.table}"
                )
            meta = manifest.get("metadata") or {}
            return str(meta.get("namespace") or ""), str(meta.get("name") or "")
        return str(bound["namespace"]), str(bound["name"])

    # -- lifecycle ----------------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Open a stage: nothing is read or written until an effect is applied.
        With a control database, first finish what a crash left there.

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
        """Change one object in the stage, and measure it with a dry run.

        :raises ForbiddenStatementError: On a statement :meth:`reject_reason`
            refuses.
        :raises StageConflictError: On ``expect-version`` naming another
            version, or an object that moved between its read and its dry run.
        :raises StageError: On a change the API server refuses, or whose
            admission cannot be measured.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            if self._control is None:
                raise OutboundRequestError(
                    f"effect {effect.effect_id!r} is an outbound request, and this Kubernetes "
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
        kind = self._kinds[statement.table]
        namespace, name = self._names(kind, statement.verb, bound)
        where = f"effect {effect.effect_id!r}"
        obj = self._object(stage, kind, namespace, name)
        if statement.verb == "expect-version":
            if obj.version != str(bound["version"]):
                raise StageConflictError(
                    f"{where}: {kind.table} {namespace}/{name} is at version {obj.version}, not "
                    f"{bound['version']}, the version the plan names: the state it was approved "
                    f"on is gone"
                )
            return EffectOutcome(effect.effect_id, 0, datetime.now(UTC))
        current = obj.desired if obj.staged else obj.live
        if statement.verb == "delete":
            if current is None:
                raise StageError(f"{where}: there is no {kind.table} {namespace}/{name} to delete")
            obj.desired = None
        elif statement.verb == "apply":
            manifest = copy.deepcopy(_json(bound["manifest"]))
            assert isinstance(manifest, dict)
            obj.desired = manifest
        else:
            if current is None:
                raise StageError(f"{where}: there is no {kind.table} {namespace}/{name}")
            if statement.verb == "scale":
                changed = copy.deepcopy(current)
                changed.setdefault("spec", {})["replicas"] = bound["replicas"]
                obj.desired = changed
            else:
                patch = _json(bound["patch"])
                obj.desired = _merge(current, patch)
        obj.staged = True
        obj.replace = False
        self._dry_run(stage, obj, where)
        if self._control is not None:
            self._control.applied_elsewhere(self._control_stage(stage), effect)
        stage.measured = False
        return EffectOutcome(effect.effect_id, 1, datetime.now(UTC))

    def _object(self, stage: _Stage, kind: KubeKind, namespace: str, name: str) -> _Object:
        key = (kind.table, namespace, name)
        found = stage.objects.get(key)
        if found is None:
            path = f"{kind.collection(namespace)}/{name}"
            try:
                live: dict[str, Any] | None = self._api.call("GET", path)
            except _ApiError as exc:
                if exc.status != 404:
                    raise StageError(f"cannot read {kind.table} {namespace}/{name}: {exc}") from exc
                live = None
            found = _Object(kind, namespace, name, live)
            stage.objects[key] = found
        return found

    def _marked(self, stage: _Stage, obj: _Object) -> dict[str, Any]:
        """The desired object, stamped with the stage's marker and the
        version it was measured on, its bookkeeping the server's."""
        assert obj.desired is not None
        body = copy.deepcopy(obj.desired)
        meta = body.setdefault("metadata", {})
        meta["namespace"] = obj.namespace
        meta["name"] = obj.name
        body["apiVersion"] = obj.kind.api_version
        body["kind"] = obj.kind.kind
        for key in ("uid", "creationTimestamp", "generation", "managedFields"):
            meta.pop(key, None)
        meta.pop("resourceVersion", None)
        if obj.version is not None and not obj.replace:
            meta["resourceVersion"] = obj.version
        annotations = dict(meta.get("annotations") or {})
        annotations[STAGE_ANNOTATION] = str(stage.handle.stage_id)
        meta["annotations"] = annotations
        body.pop("status", None)
        return body

    def _dry_run(self, stage: _Stage, obj: _Object, where: str) -> None:
        kind = obj.kind
        try:
            if obj.desired is None:
                if obj.live is None:
                    raise StageError(f"{where}: {kind.table} {obj.namespace}/{obj.name} is absent")
                self._api.call(
                    "DELETE",
                    obj.path(),
                    {"kind": "DeleteOptions", "preconditions": {"resourceVersion": obj.version}},
                    dry=True,
                )
                obj.measured = None
            elif obj.live is None:
                obj.measured = self._api.call(
                    "POST", kind.collection(obj.namespace), self._marked(stage, obj), dry=True
                )
            else:
                try:
                    obj.measured = self._api.call(
                        "PUT", obj.path(), self._marked(stage, obj), dry=True
                    )
                except _ApiError as exc:
                    if not (exc.immutable() and kind.replace_on_immutable):
                        raise
                    obj.replace = True
                    self._api.call(
                        "DELETE",
                        obj.path(),
                        {
                            "kind": "DeleteOptions",
                            "preconditions": {"resourceVersion": obj.version},
                        },
                        dry=True,
                    )
                    # The object it replaces still exists, so its re-creation
                    # is dry-run under a generated name: admission runs as on
                    # the real create, and the image keeps the real name.
                    body = self._marked(stage, obj)
                    body["metadata"].pop("name", None)
                    body["metadata"]["generateName"] = f"{obj.name}-"
                    measured = self._api.call(
                        "POST", kind.collection(obj.namespace), body, dry=True
                    )
                    meta = measured.setdefault("metadata", {})
                    meta["name"] = obj.name
                    meta.pop("generateName", None)
                    obj.measured = measured
        except _ApiError as exc:
            raise self._refusal(where, obj, exc) from None

    def _refusal(self, where: str, obj: _Object, exc: _ApiError) -> StageError:
        named = f"{obj.kind.table} {obj.namespace}/{obj.name}"
        if exc.status == 409:
            return StageConflictError(f"{where}: {named} changed while it was measured: {exc}")
        if "does not support dry run" in exc.message:
            return StageError(
                f"{where}: the API server cannot dry-run {named}: {exc.message}. That webhook "
                f"declares side effects, so its admission cannot be measured, and a change that "
                f"cannot be measured is not staged"
            )
        if exc.immutable():
            return StageError(
                f"{where}: {named} cannot be changed in place: {exc.message}. The kind is not "
                f"marked replace_on_immutable, so the change is refused"
            )
        return StageError(f"{where}: the API server refuses the change to {named}: {exc.message}")

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Every object the stage changed, as the API server's dry runs
        measured it: before (as read) and after (as admission left it)."""
        stage = self._require(handle)
        deltas: list[RowDelta] = []
        for obj in stage.objects.values():
            if not obj.staged:
                continue
            kind = obj.kind
            before = kind.image(obj.live) if obj.live is not None else None
            after = kind.image(obj.measured) if obj.measured is not None else None
            if obj.replace:
                deltas.append(self._delta(kind, obj, before, None))
                deltas.append(self._delta(kind, obj, None, after))
            elif before != after:
                deltas.append(self._delta(kind, obj, before, after))
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
    def _delta(
        kind: KubeKind,
        obj: _Object,
        before: Mapping[str, Any] | None,
        after: Mapping[str, Any] | None,
    ) -> RowDelta:
        image = after if after is not None else before
        assert image is not None
        return RowDelta(
            table=kind.table,
            primary_key=f"{obj.namespace}/{obj.name}",
            before=before,
            after=after,
            tenant_id=obj.namespace,
            partitions={d: str(image[d]) for d in kind.partitions if image.get(d) is not None},
        )

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
                "this Kubernetes substrate has no control database, so no inbox to consume a "
                "fact from"
            )
        self._control.consume_facts(self._control_stage(stage), fact_ids, scope_id)

    def measure_windows(
        self, handle: StageHandle, charges: Sequence[WindowCharge]
    ) -> tuple[WindowMeasure, ...]:
        stage = self._require(handle)
        if self._control is None:
            raise SubstrateConfigurationError(
                "rate windows keep their history in a control database, and this Kubernetes "
                "substrate has none"
            )
        return self._control.measure_windows(self._control_stage(stage), charges)

    # -- the undo, the commit, and recovery --------------------------------------------

    def write_undo(self, handle: StageHandle) -> str:
        """Write every changed object's before image down, before the commit
        writes anything; the undo's SHA-256 (:mod:`interlock.planbound`)."""
        stage = self._require(handle)
        objects = [
            {
                "table": obj.kind.table,
                "namespace": obj.namespace,
                "name": obj.name,
                "action": obj.action,
                "before": obj.live,
                "after": None if obj.measured is None else {FINGERPRINT: fingerprint(obj.measured)},
            }
            for obj in self._writes(stage)
        ]
        stage.undo = self._journal.write(
            handle.stage_id,
            {"stage_id": str(handle.stage_id), "server": self._api.server, "objects": objects},
        )
        return stage.undo

    def _writes(self, stage: _Stage) -> list[_Object]:
        """The objects a commit writes, in the order they were first changed."""
        found = []
        for obj in stage.objects.values():
            if not obj.staged:
                continue
            before = obj.kind.image(obj.live) if obj.live is not None else None
            after = obj.kind.image(obj.measured) if obj.measured is not None else None
            if obj.replace or before != after:
                found.append(obj)
        return found

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Apply each changed object as measured, on the version measured.

        With a control database the writes happen inside its stage's
        transaction, just before its ``COMMIT``, after a redo record of that
        transaction is on disk.

        :raises StageConflictError: If the first object changed since it was
            measured: nothing is applied.
        :raises CompensatedError: If a later write failed, or an object did not
            land as measured: what was applied is put back.
        :raises CommitUnsettledError: If the put-back failed too: the undo
            journal stays for recovery, and the intent stays open.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if not stage.measured:
            raise StageError(f"stage {handle.stage_id} is committed before it is measured")
        if stage.undo is None:
            raise StageError(
                f"stage {handle.stage_id}: a plan-bound commit needs its undo written first"
            )
        writes = self._writes(stage)
        redo = self._redo_path(handle.stage_id)
        # From here until the outcome is known, the undo is kept, whatever
        # interrupts the commit: close() discards it only once settled.
        stage.committing = True

        def run(conn: sqlite3.Connection | None) -> None:
            if conn is not None:
                record = {
                    "stage_id": str(handle.stage_id),
                    "tables": capture(conn, handle.stage_id),
                }
                durable_write(redo, json.dumps(record, sort_keys=True).encode("utf-8"))
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
            substrate_txn_id=self.transaction_id(handle),
        )

    def _apply_all(self, stage: _Stage, writes: Sequence[_Object]) -> None:
        applied: list[_Object] = []
        undo = stage.undo or ""
        for obj in writes:
            try:
                landed = self._write(stage, obj)
            except _ApiError as exc:
                if not applied and exc.status == 409:
                    raise StageConflictError(
                        f"{obj.kind.table} {obj.namespace}/{obj.name} changed after it was "
                        f"measured: nothing was applied: {exc.message}"
                    ) from None
                applied.append(obj)  # a replace may have deleted before it failed
                self._put_back(stage, applied, exc.message)
                raise CompensatedError(
                    f"stage {stage.handle.stage_id}: writing {obj.kind.table} {obj.namespace}/"
                    f"{obj.name} failed ({exc.message}); every object written before it was put "
                    f"back from undo {undo[:16]}",
                    applied=len(applied) - 1,
                    restored=len(applied),
                    undo=undo,
                ) from None
            applied.append(obj)
            if landed is not None and obj.measured is not None:
                if obj.kind.image(landed) != obj.kind.image(obj.measured):
                    self._put_back(stage, applied, "it did not land as measured")
                    raise CompensatedError(
                        f"stage {stage.handle.stage_id}: {obj.kind.table} {obj.namespace}/"
                        f"{obj.name} did not land as it was measured (admission answered "
                        f"otherwise on the real write); every object written was put back "
                        f"from undo {undo[:16]}",
                        applied=len(applied),
                        restored=len(applied),
                        undo=undo,
                    )

    def _write(self, stage: _Stage, obj: _Object) -> dict[str, Any] | None:
        """One object's write, conditional on its measured version."""
        kind = obj.kind
        if obj.action == "delete":
            self._api.call(
                "DELETE",
                obj.path(),
                {"kind": "DeleteOptions", "preconditions": {"resourceVersion": obj.version}},
            )
            return None
        if obj.action == "create":
            return self._api.call("POST", kind.collection(obj.namespace), self._marked(stage, obj))
        if obj.action == "replace":
            self._api.call(
                "DELETE",
                obj.path(),
                {"kind": "DeleteOptions", "preconditions": {"resourceVersion": obj.version}},
            )
            return self._api.call("POST", kind.collection(obj.namespace), self._marked(stage, obj))
        return self._api.call("PUT", obj.path(), self._marked(stage, obj))

    def _put_back(self, stage: _Stage, applied: Sequence[_Object], why: str) -> None:
        """Restore every object in ``applied`` to its before image, last first.

        :raises CommitUnsettledError: If any cannot be.
        """
        failures = []
        for obj in reversed(applied):
            problem = self._restore(
                obj.kind, obj.namespace, obj.name, obj.live, stage.handle.stage_id
            )
            if problem is not None:
                failures.append(problem)
        if len(failures) < len(applied):
            self._undone.add(stage.handle.stage_id)
        if failures:
            stage.unsettled = True
            raise CommitUnsettledError(
                f"stage {stage.handle.stage_id}: {why}, and the undo could not put everything "
                f"back: {'; '.join(failures)}. The undo journal stays for recovery"
            )

    def _restore(
        self,
        kind: KubeKind,
        namespace: str,
        name: str,
        before: Mapping[str, Any] | None,
        stage_id: uuid.UUID,
    ) -> str | None:
        """Put one object back as ``before`` (``None``: absent); a problem, or
        ``None`` when it is back."""
        path = f"{kind.collection(namespace)}/{name}"
        try:
            try:
                current: dict[str, Any] | None = self._api.call("GET", path)
            except _ApiError as exc:
                if exc.status != 404:
                    raise
                current = None
            if before is None:
                if current is not None:
                    self._api.call("DELETE", path)
                return None
            body = copy.deepcopy(dict(before))
            meta = body.setdefault("metadata", {})
            for key in ("uid", "creationTimestamp", "generation", "managedFields"):
                meta.pop(key, None)
            body.pop("status", None)
            if current is None:
                meta.pop("resourceVersion", None)
                landed = self._api.call("POST", kind.collection(namespace), body)
            else:
                meta["resourceVersion"] = (current.get("metadata") or {}).get("resourceVersion")
                landed = self._api.call("PUT", path, body)
            if kind.image(landed) != kind.image(before):
                return f"{kind.table} {namespace}/{name} came back other than it was"
            return None
        except (_ApiError, SubstrateUnavailableError) as exc:
            return f"{kind.table} {namespace}/{name}: {exc}"

    def _redo_path(self, stage_id: uuid.UUID) -> Path:
        return self._journal.directory / f"{stage_id}.redo.json"

    def resolve_intent(self, stage_id: uuid.UUID, *, txid: str | None = None) -> bool | None:
        """Whether a stage a crash interrupted was applied, from each object as
        the cluster holds it now: marked with the stage, it was written; as
        its before image, it was not. All written, ``True`` (and the control
        rows written again if they were lost); none, ``False``; some, put back
        from the undo, then ``False`` (and :meth:`compensated` names the undo).
        ``None`` when an object is neither, or no undo of the stage is left:
        something else wrote it, and only an operator can say."""
        found = self._journal.read(stage_id)
        if found is None:
            return None
        document, digest = found
        states: list[tuple[KubeKind, Mapping[str, Any], str]] = []
        for entry in document.get("objects", ()):
            kind = self._kinds.get(str(entry.get("table")))
            if kind is None:
                return None
            state = self._state_of(kind, entry, str(stage_id))
            if state is None:
                return None
            states.append((kind, entry, state))
        applied = [s for _, _, s in states if s != "untouched"]
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
        if applied:
            problems = [
                p
                for kind, entry, state in reversed(states)
                if state != "untouched"
                and (
                    p := self._restore(
                        kind, entry["namespace"], entry["name"], entry.get("before"), stage_id
                    )
                )
                is not None
            ]
            if problems:
                logger.warning(
                    "stage %s: a partial apply could not be put back yet: %s",
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

    def _state_of(self, kind: KubeKind, entry: Mapping[str, Any], marker: str) -> str | None:
        """``applied``, ``untouched``, ``partial`` (a replacement deleted and
        not yet created), or ``None`` when the object is neither as written
        nor as it was."""
        path = f"{kind.collection(entry['namespace'])}/{entry['name']}"
        try:
            current: dict[str, Any] | None = self._api.call("GET", path)
        except _ApiError as exc:
            if exc.status != 404:
                return None
            current = None
        except SubstrateUnavailableError:
            return None
        before = entry.get("before")
        meta = (current or {}).get("metadata") or {}
        marked = (meta.get("annotations") or {}).get(STAGE_ANNOTATION) == marker
        same = (
            current is not None
            and before is not None
            and fingerprint(current) == fingerprint(before)
            and meta.get("uid") == ((before.get("metadata") or {}).get("uid"))
        )
        action = entry.get("action")
        if action == "delete":
            if current is None or meta.get("uid") != ((before or {}).get("metadata") or {}).get(
                "uid"
            ):
                return "applied"
            return "untouched" if same else None
        if action == "create":
            if current is None:
                return "untouched"
            return "applied" if marked else None
        if action == "replace":
            if current is None:
                return "partial"
            if marked:
                return "applied"
            return "untouched" if same else None
        if current is None:
            return None
        if marked:
            return "applied"
        return "untouched" if same else None

    def compensated(self, stage_id: uuid.UUID) -> str | None:
        """The undo recovery put a partial apply back from, if it did."""
        return self._compensated.pop(stage_id, None)

    # -- savepoints ----------------------------------------------------------------

    def savepoint(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise ValueError(f"unsafe savepoint name: {name!r}")
        stage.savepoints.append((name, copy.deepcopy(stage.objects)))
        if self._control is not None:
            self._control.savepoint(self._control_stage(stage), name)

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        stage.objects = copy.deepcopy(self._savepoint(stage, name))
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

    def _savepoint(self, stage: _Stage, name: str) -> dict[tuple[str, str, str], _Object]:
        for found, objects in reversed(stage.savepoints):
            if found == name:
                return objects
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage ---------------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        """Discard the stage: nothing was written to the cluster (dry runs store
        nothing), and the control stage rolls back."""
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
