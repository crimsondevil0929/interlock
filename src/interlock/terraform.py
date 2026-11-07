"""Terraform and OpenTofu as a plan-bound substrate: measure a change with a
saved plan, then apply exactly that plan, on the state measured (1.3.0).

The guarantee is class P (:mod:`interlock.planbound`):

- **A diff read from the system.** A plan's effects set the configuration's
  input variables; the stage runs ``terraform plan -out`` with them and reads
  the saved plan back with ``terraform show -json``. Each entry of
  ``resource_changes`` is a :class:`~interlock.types.RowDelta`: the table is
  the resource type's (:class:`TfResource`), the key the resource address, the
  images the attributes before and after. A replacement (``delete`` and
  ``create``) is a deletion and an insertion, so ``NoDelete`` catches the
  forced replacement of a database that a change to one attribute brings.
  A resource of a type no :class:`TfResource` names is measured too, in the
  ``resources`` table: nothing a plan changes goes unmeasured.
- **What cannot be measured is said.** An observed attribute the provider only
  knows after the apply (``after_unknown``) is an
  :class:`~interlock.types.UnknownValue` on the diff, which ``TruncationGuard``
  refuses unless the mandate acknowledges that column.
- **A state the apply is conditional on.** The stage records the state's
  ``serial`` and ``lineage``; the commit checks both again, and applies the
  saved plan, which Terraform itself refuses once the state has moved
  (``Saved plan is stale``). Nothing is applied on a state the plan did not
  measure.
- **A marker recovery can read.** The stage's id is passed as the variable
  ``interlock_stage_id``, which the configuration writes to an output of the
  same name: present in the state, the apply finished.
- **An undo, written down first.** The inputs before the plan, and the state's
  serial and lineage, go to the undo journal before the apply. An apply that
  fails part way is followed by an apply of the previous inputs, and the stage
  is recorded ``COMPENSATED``. An undo restores configuration, not data: a
  database a replacement destroyed comes back empty, which is why the
  replacement is refused before it is applied.

**Statements**::

    set :name :value              set one input variable (any JSON value)
    expect-serial :serial         refuse unless the state is at that serial

Outbound requests, inbound facts and rate windows are not staged here: a plan
that needs them runs on a substrate with a control database.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from agentgov.receipts.canonical import canonical_bytes

from interlock.control import durable_write
from interlock.exceptions import (
    CommitUnsettledError,
    CompensatedError,
    ForbiddenStatementError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    StageExpiredError,
    SubstrateConfigurationError,
    SubstrateUnavailableError,
)
from interlock.planbound import PLAN_BOUND, UndoJournal
from interlock.substrate import TableSpec
from interlock.text import tally
from interlock.types import (
    CommitReceipt,
    Effect,
    EffectDiff,
    EffectKind,
    EffectOutcome,
    EffectPlan,
    RowDelta,
    StageHandle,
    SubstrateCapabilities,
    UnknownValue,
)

__all__ = [
    "FALLBACK_TABLE",
    "MARKER_VARIABLE",
    "TerraformSubstrate",
    "TfResource",
    "terraform_tables",
]

logger = logging.getLogger("interlock.terraform")

ADDRESS: Final = "address"
TYPE: Final = "type"
TENANT_COLUMN: Final = "tenant"
FINGERPRINT: Final = "fingerprint"
FALLBACK_TABLE: Final = "resources"
"""The table of every resource whose type no :class:`TfResource` names."""
MARKER_VARIABLE: Final = "interlock_stage_id"
"""The input variable, and output, that carry the stage's id into the state."""

_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9_]*")
_VARIABLE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REPLACE: Final = (["delete", "create"], ["create", "delete"])


@dataclass(frozen=True, slots=True)
class TfResource:
    """One resource type the substrate observes, as one table.

    :ivar table: The table's name: ``db_instances``.
    :ivar type: The resource type: ``aws_db_instance``.
    :ivar columns: Each column and its attribute path (``instance_class``,
        ``tags.env``, ``scaling_config.0.desired_size``).
    :ivar tenant: The attribute path of its tenant label (``tags.env``).
    :ivar partitions: More partition dimensions, each an attribute path.
    """

    table: str
    type: str
    columns: Mapping[str, str] = field(default_factory=dict)
    tenant: str | None = None
    partitions: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (self.table, *self.columns, *self.partitions):
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(f"resource {self.type}: {name!r} is not a lowercase identifier")
        reserved = {ADDRESS, TYPE, TENANT_COLUMN, FINGERPRINT}
        clash = sorted(reserved & (set(self.columns) | set(self.partitions)))
        if clash:
            raise ValueError(f"resource {self.type}: {', '.join(clash)} are every table's own")

    def spec(self) -> TableSpec:
        return TableSpec(
            self.table,
            primary_key=ADDRESS,
            columns=[ADDRESS, TYPE, TENANT_COLUMN, *self.columns, *self.partitions, FINGERPRINT],
            tenant_column=TENANT_COLUMN,
            partitions={d: d for d in self.partitions} or None,
        )


_FALLBACK: Final = TfResource(FALLBACK_TABLE, "*")


def terraform_tables(resources: Sequence[TfResource]) -> tuple[TableSpec, ...]:
    """A Terraform substrate's tables: one per resource type, and the
    fallback."""
    return (*(r.spec() for r in resources), _FALLBACK.spec())


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


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping | list):
        return canonical_bytes(_safe(value)).decode("utf-8")
    if isinstance(value, float):
        return format(value, "g")
    return value


def _safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe(v) for v in value]
    if isinstance(value, float):
        return format(value, "g")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 2**53:
        return str(value)
    return value


def _statement(text: str) -> tuple[str, list[tuple[str, str]]]:
    """``set :name :value`` or ``expect-serial :serial``: the verb, and each
    argument a ``(":", parameter)`` or a ``("'", literal)``."""
    found = re.fullmatch(
        r"\s*(set|expect-serial)((?:\s+(?::[A-Za-z_][A-Za-z0-9_]*|'(?:[^']|'')*'))*)\s*", text
    )
    if found is None:
        raise ValueError("a statement is set :name :value, or expect-serial :serial")
    arguments = [
        (":", t[1:]) if t.startswith(":") else ("'", t[1:-1].replace("''", "'"))
        for t in re.findall(r":[A-Za-z_][A-Za-z0-9_]*|'(?:[^']|'')*'", found.group(2))
    ]
    wanted = 2 if found.group(1) == "set" else 1
    if len(arguments) != wanted:
        raise ValueError(f"{found.group(1)} takes {tally(wanted, 'argument')}")
    return found.group(1), arguments


def _bind(arguments: Sequence[tuple[str, str]], parameters: Mapping[str, object]) -> list[object]:
    bound: list[object] = []
    for kind, text in arguments:
        if kind == "'":
            bound.append(text)
        elif text in parameters:
            bound.append(_thaw(parameters[text]))
        else:
            raise ValueError(f"parameter :{text} is not bound")
    return bound


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_thaw(v) for v in value]
    return value


@dataclass
class _Stage:
    handle: StageHandle
    plan: EffectPlan
    root: Path
    serial: int
    lineage: str
    inputs: dict[str, Any]
    before: dict[str, Any]
    savepoints: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    measured: bool = False
    undo: str | None = None
    done: bool = False
    unsettled: bool = False
    committing: bool = False


class TerraformSubstrate:
    """Plan-bound staging over a Terraform or OpenTofu configuration (module
    docstring).

    :param directory: The configuration's working directory, initialized.
    :param resources: The resource types observed, each a table.
    :param journal: Where undos and stages' plan files are written.
    :param executable: The command: ``("terraform",)``, ``("tofu",)``, or a
        stand-in (:mod:`interlock.sim.terraform`).
    :param inputs: The file, in ``directory``, holding the inputs the last
        commit applied (``-var-file``); created on the first commit.
    :param variables: The input variables a plan may set. Empty: any but
        :data:`MARKER_VARIABLE`.
    :param workspace: The tenant of a resource whose type names no tenant path.
    :param timeout: Seconds a ``plan`` or an ``apply`` may take.
    """

    __slots__ = (
        "_by_type",
        "_compensated",
        "_directory",
        "_executable",
        "_inputs",
        "_journal",
        "_max_rows",
        "_resources",
        "_stage",
        "_stage_seconds",
        "_timeout",
        "_variables",
        "_workspace",
    )

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        resources: Sequence[TfResource],
        journal: str | os.PathLike[str],
        executable: Sequence[str] = ("terraform",),
        inputs: str = "interlock.tfvars.json",
        variables: Sequence[str] = (),
        workspace: str = "default",
        timeout: float = 600.0,
        max_stage_seconds: float = 900.0,
        max_diff_rows: int = 50_000,
    ) -> None:
        self._directory = Path(directory).resolve()
        if not self._directory.is_dir():
            raise SubstrateConfigurationError(f"{self._directory} is not a directory")
        if not executable:
            raise SubstrateConfigurationError("the Terraform command is named")
        tables = [r.table for r in resources]
        types = [r.type for r in resources]
        if len(set(tables)) != len(tables) or FALLBACK_TABLE in tables:
            raise SubstrateConfigurationError(
                f"each resource type is its own table, and none is {FALLBACK_TABLE!r}"
            )
        if len(set(types)) != len(types):
            raise SubstrateConfigurationError("each resource type is observed once")
        if MARKER_VARIABLE in variables:
            raise SubstrateConfigurationError(f"{MARKER_VARIABLE} is the stage's, not a plan's")
        self._resources = tuple(resources)
        self._by_type = {r.type: r for r in resources}
        self._executable = tuple(executable)
        self._journal = UndoJournal(journal)
        self._inputs = self._directory / inputs
        self._variables = frozenset(variables)
        self._workspace = workspace
        self._timeout = timeout
        self._stage_seconds = max_stage_seconds
        self._max_rows = max_diff_rows
        self._stage: _Stage | None = None
        self._compensated: dict[uuid.UUID, str] = {}

    # -- what it is -------------------------------------------------------------------

    @property
    def substrate_id(self) -> str:
        return "terraform"

    @property
    def capabilities(self) -> SubstrateCapabilities:
        return SubstrateCapabilities(
            transactional=False,
            row_level_diff=True,
            snapshot_isolation=False,
            requires_compensation=False,
            max_stage_seconds=self._stage_seconds,
            max_diff_rows=self._max_rows,
            measurement=PLAN_BOUND,
            plan_bound=True,
        )

    @property
    def observed_tables(self) -> frozenset[str]:
        return frozenset({*(r.table for r in self._resources), FALLBACK_TABLE})

    @property
    def table_specs(self) -> tuple[TableSpec, ...]:
        return terraform_tables(self._resources)

    @property
    def commit_markers(self) -> bool:
        return True

    @property
    def directory(self) -> Path:
        return self._directory

    def transaction_id(self, handle: StageHandle) -> str:
        return f"terraform:{handle.stage_id}"

    # -- the command --------------------------------------------------------------------

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": os.environ.get("HOME", str(self._directory)),
            "LANG": "C.UTF-8",
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            **{k: v for k, v in os.environ.items() if k.startswith(("TF_", "PYTHON"))},
        }
        try:
            done = subprocess.run(  # noqa: S603 - operator-configured command, no shell
                [*self._executable, *args],
                cwd=self._directory,
                env=env,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise StageError(f"terraform {args[0]} ran past its {self._timeout}s") from exc
        except OSError as exc:
            raise SubstrateUnavailableError(f"cannot run {self._executable[0]}: {exc}") from exc
        if check and done.returncode != 0:
            raise StageError(
                f"terraform {args[0]} failed ({done.returncode}): "
                + done.stderr.decode("utf-8", "replace").strip()[:800]
            )
        return done

    def state(self) -> dict[str, Any]:
        """The state, as ``terraform state pull`` reads it."""
        raw = self._run("state", "pull").stdout
        try:
            state = json.loads(raw or b"{}")
        except ValueError as exc:
            raise SubstrateUnavailableError(
                f"terraform state pull answered no JSON: {exc}"
            ) from exc
        if not isinstance(state, dict):
            raise SubstrateUnavailableError("terraform state pull answered no state")
        return state

    def _committed(self) -> dict[str, Any]:
        try:
            found = json.loads(self._inputs.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise SubstrateUnavailableError(f"cannot read {self._inputs}: {exc}") from exc
        return found if isinstance(found, dict) else {}

    # -- vetting ----------------------------------------------------------------------------

    def reject_reason(self, effect: Effect) -> str | None:
        if effect.kind is EffectKind.ENQUEUE:
            return "a Terraform substrate stages no outbound request: it has no control database"
        try:
            verb, arguments = _statement(effect.statement)
            bound = _bind(arguments, effect.parameters)
        except ValueError as exc:
            return f"not a statement this substrate stages: {exc}"
        if verb == "set":
            name = bound[0]
            if not isinstance(name, str) or not _VARIABLE.fullmatch(name):
                return f"{name!r} is not an input variable's name"
            if name == MARKER_VARIABLE:
                return f"{MARKER_VARIABLE} is the stage's own variable"
            if self._variables and name not in self._variables:
                return f"input variable {name!r} is not one a plan may set"
        else:
            serial = bound[0]
            if isinstance(serial, bool) or not (
                isinstance(serial, int) or (isinstance(serial, str) and serial.isdigit())
            ):
                return "expect-serial takes the state's serial, a whole number"
        return None

    # -- lifecycle ------------------------------------------------------------------------------

    def open(self, plan: EffectPlan) -> StageHandle:
        """Read the state's serial and lineage, and the inputs last applied."""
        if self._stage is not None:
            raise StageConflictError(
                f"substrate {self.substrate_id!r} already has stage "
                f"{self._stage.handle.stage_id} open"
            )
        state = self.state()
        opened = datetime.now(UTC)
        handle = StageHandle(
            stage_id=uuid.uuid4(),
            plan_id=plan.plan_id,
            substrate_id=self.substrate_id,
            opened_at=opened,
            expires_at=opened + timedelta(seconds=self._stage_seconds),
        )
        root = self._journal.directory / str(handle.stage_id)
        try:
            root.mkdir(parents=True)
        except OSError as exc:
            raise SubstrateUnavailableError(f"cannot create {root}: {exc}") from exc
        committed = self._committed()
        self._stage = _Stage(
            handle,
            plan,
            root,
            int(state.get("serial", 0)),
            str(state.get("lineage", "")),
            dict(committed),
            dict(committed),
        )
        return handle

    def apply(self, handle: StageHandle, effect: Effect) -> EffectOutcome:
        stage = self._require(handle)
        self._assert_live(handle)
        if effect.kind is EffectKind.ENQUEUE:
            raise OutboundRequestError(
                f"effect {effect.effect_id!r} is an outbound request, and a Terraform "
                f"substrate has no outbox",
                reason="substrate",
                sink=effect.request.sink if effect.request is not None else None,
            )
        refusal = self.reject_reason(effect)
        if refusal is not None:
            raise ForbiddenStatementError(
                f"effect {effect.effect_id!r} refused: {refusal}", reason="statement_kind"
            )
        verb, arguments = _statement(effect.statement)
        bound = _bind(arguments, effect.parameters)
        if verb == "expect-serial":
            if int(str(bound[0])) != stage.serial:
                raise StageConflictError(
                    f"effect {effect.effect_id!r}: the state is at serial {stage.serial}, not "
                    f"{bound[0]}, the serial the plan names: the state it was approved on is gone"
                )
            return EffectOutcome(effect.effect_id, 0, datetime.now(UTC))
        stage.inputs[str(bound[0])] = copy.deepcopy(bound[1])
        stage.measured = False
        return EffectOutcome(effect.effect_id, 1, datetime.now(UTC))

    def _plan_file(self, stage: _Stage) -> Path:
        return stage.root / "stage.tfplan"

    def diff(self, handle: StageHandle) -> EffectDiff:
        """Plan with the stage's inputs, save the plan, and read it back."""
        stage = self._require(handle)
        variables = stage.root / "inputs.tfvars.json"
        variables.write_text(json.dumps(stage.inputs, sort_keys=True))
        plan = self._plan_file(stage)
        self._run(
            "plan",
            "-input=false",
            "-no-color",
            f"-out={plan}",
            f"-var-file={variables}",
            f"-var={MARKER_VARIABLE}={handle.stage_id}",
        )
        shown = self._run("show", "-json", str(plan)).stdout
        try:
            document = json.loads(shown)
        except ValueError as exc:
            raise StageError(f"terraform show -json answered no JSON: {exc}") from exc
        deltas, unknowns = self._rows(document)
        truncated = len(deltas) > self._max_rows
        stage.measured = True
        return EffectDiff(
            plan_id=handle.plan_id,
            stage_id=handle.stage_id,
            substrate_id=self.substrate_id,
            computed_at=datetime.now(UTC),
            deltas=tuple(deltas[: self._max_rows]),
            truncated=truncated,
            unknowns=tuple(unknowns),
        )

    def _rows(self, document: Mapping[str, Any]) -> tuple[list[RowDelta], list[UnknownValue]]:
        deltas: list[RowDelta] = []
        unknowns: list[UnknownValue] = []
        for change in document.get("resource_changes") or ():
            if change.get("mode", "managed") != "managed":
                continue
            body = change.get("change") or {}
            actions = list(body.get("actions") or ())
            if actions in (["no-op"], ["read"], []):
                continue
            resource = self._by_type.get(str(change.get("type")), _FALLBACK)
            address = str(change.get("address"))
            before = body.get("before")
            after = body.get("after")
            unknown = body.get("after_unknown") or {}
            before_row = self._image(resource, change, before, {}) if before is not None else None
            after_row = self._image(resource, change, after, unknown) if after is not None else None
            if after_row is not None:
                for column, path in resource.columns.items():
                    if _at(unknown, path)[1] is True:
                        unknowns.append(UnknownValue(resource.table, address, column))
            if actions in _REPLACE:
                deltas.append(self._delta(resource, address, before_row, None))
                deltas.append(self._delta(resource, address, None, after_row))
            else:
                deltas.append(self._delta(resource, address, before_row, after_row))
        return deltas, unknowns

    def _image(
        self,
        resource: TfResource,
        change: Mapping[str, Any],
        attributes: Mapping[str, Any],
        unknown: Mapping[str, Any],
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            ADDRESS: str(change.get("address")),
            TYPE: str(change.get("type")),
        }
        tenant = None
        if resource.tenant is not None:
            found, value = _at(attributes, resource.tenant)
            tenant = str(value) if found and value is not None else None
        row[TENANT_COLUMN] = tenant if tenant is not None else self._workspace
        for column, path in resource.columns.items():
            if _at(unknown, path)[1] is True:
                row[column] = None
                continue
            found, value = _at(attributes, path)
            row[column] = _plain(value) if found else None
        for dimension, path in resource.partitions.items():
            found, value = _at(attributes, path)
            row[dimension] = str(value) if found and value is not None else None
        known = {k: v for k, v in attributes.items() if unknown.get(k) is not True}
        row[FINGERPRINT] = hashlib.sha256(canonical_bytes(_safe(known))).hexdigest()
        return row

    @staticmethod
    def _delta(
        resource: TfResource,
        address: str,
        before: Mapping[str, Any] | None,
        after: Mapping[str, Any] | None,
    ) -> RowDelta:
        image = after if after is not None else before
        assert image is not None
        return RowDelta(
            table=resource.table,
            primary_key=address,
            before=before,
            after=after,
            tenant_id=str(image[TENANT_COLUMN]),
            partitions={d: str(image[d]) for d in resource.partitions if image.get(d) is not None},
        )

    # -- the undo, the commit, and recovery -----------------------------------------------------

    def write_undo(self, handle: StageHandle) -> str:
        """Write the inputs before the plan, and the state it was measured
        on, down before the apply; the undo's SHA-256."""
        stage = self._require(handle)
        stage.undo = self._journal.write(
            handle.stage_id,
            {
                "stage_id": str(handle.stage_id),
                "directory": str(self._directory),
                "serial": stage.serial,
                "lineage": stage.lineage,
                "inputs_before": stage.before,
                "inputs_after": stage.inputs,
            },
        )
        return stage.undo

    def commit(self, handle: StageHandle) -> CommitReceipt:
        """Apply the saved plan, if the state is still the one it measured.

        :raises StageConflictError: If the state moved: nothing is applied.
        :raises CompensatedError: If the apply failed part way, and the
            previous inputs were applied back.
        :raises CommitUnsettledError: If applying them back failed too.
        """
        stage = self._require(handle)
        self._assert_live(handle)
        if not stage.measured:
            raise StageError(f"stage {handle.stage_id} is committed before it is measured")
        if stage.undo is None:
            raise StageError(
                f"stage {handle.stage_id}: a plan-bound commit needs its undo written first"
            )
        state = self.state()
        if (int(state.get("serial", 0)), str(state.get("lineage", ""))) != (
            stage.serial,
            stage.lineage,
        ):
            raise StageConflictError(
                f"stage {handle.stage_id}: the state moved from serial {stage.serial} to "
                f"{state.get('serial')} since it was measured: nothing was applied"
            )
        stage.committing = True
        done = self._run(
            "apply",
            "-input=false",
            "-auto-approve",
            "-no-color",
            str(self._plan_file(stage)),
            check=False,
        )
        if done.returncode != 0:
            error = done.stderr.decode("utf-8", "replace").strip()[:500]
            # Terraform refuses a plan whose state moved before applying any
            # of it: someone else's apply moved the serial, and putting
            # "back" would undo theirs.
            if "Saved plan is stale" in error:
                stage.committing = False
                raise StageConflictError(
                    f"stage {handle.stage_id}: terraform refused the saved plan, its state moved "
                    f"since it was measured: nothing was applied"
                )
            after = self.state()
            if int(after.get("serial", 0)) == stage.serial:
                stage.committing = False
                raise StageConflictError(
                    f"stage {handle.stage_id}: terraform applied nothing: {error}"
                )
            self._put_back(stage, error)
            stage.committing = False
            raise CompensatedError(
                f"stage {handle.stage_id}: the apply stopped part way ({error}); the inputs "
                f"before it were applied back, from undo {stage.undo[:16]}",
                applied=1,
                restored=1,
                undo=stage.undo,
            )
        durable_write(self._inputs, json.dumps(stage.inputs, sort_keys=True).encode("utf-8"))
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

    def _put_back(self, stage: _Stage, why: str) -> None:
        if not self._apply_inputs(stage.root, stage.before):
            stage.unsettled = True
            raise CommitUnsettledError(
                f"stage {stage.handle.stage_id}: {why}, and applying the inputs before it back "
                f"failed too. The undo journal stays for recovery"
            )

    def _apply_inputs(self, root: Path, inputs: Mapping[str, Any]) -> bool:
        before = root / "inputs.before.tfvars.json"
        before.parent.mkdir(parents=True, exist_ok=True)
        before.write_text(json.dumps(dict(inputs), sort_keys=True))
        back = self._run(
            "apply",
            "-input=false",
            "-auto-approve",
            "-no-color",
            f"-var-file={before}",
            f"-var={MARKER_VARIABLE}=",
            check=False,
        )
        return back.returncode == 0

    def resolve_intent(self, stage_id: uuid.UUID, *, txid: str | None = None) -> bool | None:
        """Whether a stage a crash interrupted was applied: its marker in the
        state's outputs, ``True``; the state still at the serial measured,
        ``False``; moved without the marker, a partial apply, put back, then
        ``False`` (and :meth:`compensated` names the undo). ``None`` when the
        lineage changed, or no undo of the stage is left."""
        found = self._journal.read(stage_id)
        if found is None:
            return None
        document, digest = found
        state = self.state()
        if str(state.get("lineage", "")) != document.get("lineage"):
            return None
        marker = ((state.get("outputs") or {}).get(MARKER_VARIABLE) or {}).get("value")
        if marker == str(stage_id):
            durable_write(
                self._inputs,
                json.dumps(document["inputs_after"], sort_keys=True).encode("utf-8"),
            )
            self._journal.discard(stage_id)
            return True
        if int(state.get("serial", 0)) != int(document["serial"]):
            if not self._apply_inputs(
                self._journal.directory / str(stage_id), document["inputs_before"]
            ):
                logger.warning("stage %s: a partial apply could not be put back yet", stage_id)
                return None
            self._compensated[stage_id] = digest
        self._journal.discard(stage_id)
        return False

    def compensated(self, stage_id: uuid.UUID) -> str | None:
        return self._compensated.pop(stage_id, None)

    # -- savepoints -------------------------------------------------------------------------------

    def savepoint(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise ValueError(f"unsafe savepoint name: {name!r}")
        stage.savepoints.append((name, copy.deepcopy(stage.inputs)))

    def rollback_to(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        stage.inputs = copy.deepcopy(self._savepoint(stage, name))
        stage.measured = False

    def release_savepoint(self, handle: StageHandle, name: str) -> None:
        stage = self._require(handle)
        self._savepoint(stage, name)
        index = max(i for i, (n, _) in enumerate(stage.savepoints) if n == name)
        del stage.savepoints[index:]

    def _savepoint(self, stage: _Stage, name: str) -> dict[str, Any]:
        for found, inputs in reversed(stage.savepoints):
            if found == name:
                return inputs
        raise StageError(f"stage {stage.handle.stage_id} has no savepoint {name!r}")

    # -- ending a stage ----------------------------------------------------------------------------

    def abort(self, handle: StageHandle) -> None:
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        stage.done = True

    def close(self, handle: StageHandle) -> None:
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id:
            return
        stage.done = True
        if not (stage.unsettled or stage.committing):
            self._journal.discard(handle.stage_id)
            for path in sorted(stage.root.glob("*"), reverse=True):
                path.unlink(missing_ok=True)
            if stage.root.exists():
                stage.root.rmdir()
        self._stage = None

    def _require(self, handle: StageHandle) -> _Stage:
        stage = self._stage
        if stage is None or stage.handle.stage_id != handle.stage_id or stage.done:
            raise StageError(f"stage {handle.stage_id} is not open on this substrate")
        return stage

    def _assert_live(self, handle: StageHandle) -> None:
        if datetime.now(UTC) > handle.expires_at:
            raise StageExpiredError(f"stage {handle.stage_id} expired at {handle.expires_at}")
