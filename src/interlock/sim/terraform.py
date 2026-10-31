"""A ``terraform`` command over a local model, for tests and demos (1.3.0).

Run it as ``python -m interlock.sim.terraform <command> ...`` in a working
directory holding ``model.json``. It speaks the parts of the real CLI a
plan-bound substrate uses, in the real formats:

- ``init``;
- ``plan -input=false -no-color -out=PLAN [-var-file=F]... [-var=K=V]...``;
- ``show -json PLAN``: the plan's JSON representation (``format_version``
  ``1.2``): ``resource_changes`` with ``actions``, ``before``, ``after``,
  ``after_unknown`` and ``replace_paths``;
- ``apply -input=false -auto-approve PLAN``, refusing a plan whose state moved
  (``Saved plan is stale``), or ``apply ... -var-file=F`` with no plan;
- ``state pull``: the state, with its ``serial`` and ``lineage``;
- ``output -json``.

``model.json`` is the configuration: ``variables`` (each with a ``default``),
``resources`` (each an ``address``, a ``type``, its ``attributes``, which may
name ``${var.NAME}``, the attributes that force a replacement
``force_new``, and those the provider ``computed`` only on apply) and
``outputs``. The state is ``terraform.tfstate``. ``faults.json``, if present,
names resource addresses whose next apply fails (``{"fail_apply": [...]}``),
after the ones before them are applied: a partial apply.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

__all__ = ["main"]

_VAR = re.compile(r"\$\{var\.([A-Za-z_][A-Za-z0-9_]*)\}")


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def _render(value: Any, variables: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        whole = _VAR.fullmatch(value)
        if whole:
            return copy.deepcopy(variables[whole.group(1)])
        return _VAR.sub(lambda m: str(variables[m.group(1)]), value)
    if isinstance(value, list):
        return [_render(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, variables) for k, v in value.items()}
    return value


def _state(directory: Path) -> dict[str, Any]:
    state: dict[str, Any] = _load(
        directory / "terraform.tfstate",
        {"version": 4, "serial": 0, "lineage": str(uuid.uuid4()), "outputs": {}, "resources": []},
    )
    return state


def _instances(state: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    found = {}
    for resource in state.get("resources", ()):
        address = f"{resource['type']}.{resource['name']}"
        found[address] = resource["instances"][0]["attributes"]
    return found


def _variables(directory: Path, args: Sequence[str]) -> dict[str, Any]:
    model = _load(directory / "model.json", {})
    variables = {k: v.get("default") for k, v in model.get("variables", {}).items()}
    for arg in args:
        if arg.startswith("-var-file="):
            variables.update(json.loads(Path(arg.removeprefix("-var-file=")).read_text()))
        elif arg.startswith("-var="):
            name, _, value = arg.removeprefix("-var=").partition("=")
            variables[name] = value
    unknown = sorted(set(variables) - set(model.get("variables", {})))
    if unknown:
        raise SystemExit(f"Error: Value for undeclared variable: {', '.join(unknown)}")
    return variables


def _changes(directory: Path, variables: Mapping[str, Any]) -> list[dict[str, Any]]:
    model = _load(directory / "model.json", {})
    current = _instances(_state(directory))
    changes = []
    for resource in model.get("resources", ()):
        address = resource["address"]
        desired = _render(resource.get("attributes", {}), variables)
        computed = list(resource.get("computed", ()))
        before = current.get(address)
        if before is None:
            actions = ["create"]
            after = desired
            unknown = dict.fromkeys(computed, True)
            replace: list[list[str]] = []
        else:
            planned = {**{k: before.get(k) for k in computed}, **desired}
            moved = sorted(k for k in desired if before.get(k) != desired[k])
            forced = [k for k in moved if k in resource.get("force_new", ())]
            if forced:
                actions = ["delete", "create"]
                after = desired
                unknown = dict.fromkeys(computed, True)
                replace = [[k] for k in forced]
            elif moved:
                actions = ["update"]
                after = planned
                unknown = {}
                replace = []
            else:
                actions = ["no-op"]
                after = planned
                unknown = {}
                replace = []
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource["type"],
                "name": address.split(".", 1)[1],
                "provider_name": "registry.terraform.io/hashicorp/sim",
                "change": {
                    "actions": actions,
                    "before": before,
                    "after": after,
                    "after_unknown": unknown,
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "replace_paths": replace,
                },
                "computed": computed,
            }
        )
    for address, attributes in sorted(current.items()):
        if address not in {r["address"] for r in model.get("resources", ())}:
            changes.append(
                {
                    "address": address,
                    "mode": "managed",
                    "type": address.split(".", 1)[0],
                    "name": address.split(".", 1)[1],
                    "change": {
                        "actions": ["delete"],
                        "before": attributes,
                        "after": None,
                        "after_unknown": {},
                        "replace_paths": [],
                    },
                    "computed": [],
                }
            )
    return changes


def _plan(directory: Path, args: Sequence[str]) -> int:
    out = next((a.removeprefix("-out=") for a in args if a.startswith("-out=")), None)
    if out is None:
        print("Error: -out is required here", file=sys.stderr)
        return 1
    variables = _variables(directory, args)
    state = _state(directory)
    plan = {
        "sim": "plan",
        "serial": state["serial"],
        "lineage": state["lineage"],
        "variables": variables,
        "changes": _changes(directory, variables),
    }
    Path(out).write_text(json.dumps(plan, sort_keys=True))
    counts = {"create": 0, "update": 0, "delete": 0}
    for change in plan["changes"]:
        for action in change["change"]["actions"]:
            if action in counts:
                counts[action] += 1
    print(
        f"Plan: {counts['create']} to add, {counts['update']} to change, "
        f"{counts['delete']} to destroy."
    )
    return 0


def _show(directory: Path, args: Sequence[str]) -> int:
    if "-json" not in args:
        print("Error: only show -json is supported", file=sys.stderr)
        return 1
    path = next(a for a in args if not a.startswith("-"))
    plan = json.loads(Path(path).read_text())
    shown = {
        "format_version": "1.2",
        "terraform_version": "1.9.0-sim",
        "variables": {k: {"value": v} for k, v in plan["variables"].items()},
        "resource_changes": [
            {k: v for k, v in change.items() if k != "computed"} for change in plan["changes"]
        ],
        "prior_state": {"format_version": "1.0"},
    }
    print(json.dumps(shown))
    return 0


def _save(directory: Path, state: Mapping[str, Any]) -> None:
    target = directory / "terraform.tfstate"
    partial = target.with_suffix(".partial")
    partial.write_text(json.dumps(state, sort_keys=True, indent=1))
    partial.replace(target)


def _apply(directory: Path, args: Sequence[str]) -> int:
    path = next((a for a in args if not a.startswith("-")), None)
    state = _state(directory)
    if path is not None:
        plan = json.loads(Path(path).read_text())
        if plan["serial"] != state["serial"] or plan["lineage"] != state["lineage"]:
            print(
                "Error: Saved plan is stale\n\nThe given plan file can no longer be applied "
                "because the state was changed by another operation after the plan was created.",
                file=sys.stderr,
            )
            return 1
        variables, changes = plan["variables"], plan["changes"]
    else:
        variables = _variables(directory, args)
        changes = _changes(directory, variables)
    faults = _load(directory / "faults.json", {})
    failing = set(faults.get("fail_apply", ()))
    resources = {f"{r['type']}.{r['name']}": r for r in state["resources"]}
    for change in changes:
        actions = change["change"]["actions"]
        if actions in (["no-op"], ["read"]):
            continue
        address = change["address"]
        if address in failing:
            faults["fail_apply"] = [a for a in faults["fail_apply"] if a != address]
            (directory / "faults.json").write_text(json.dumps(faults))
            state["serial"] += 1
            state["resources"] = list(resources.values())
            _save(directory, state)
            print(f"Error: creating or updating {address}: injected fault", file=sys.stderr)
            return 1
        if change["change"]["after"] is None:
            resources.pop(address, None)
            continue
        attributes = copy.deepcopy(change["change"]["after"])
        for name in change.get("computed", ()):
            if change["change"]["after_unknown"].get(name) or name not in attributes:
                digest = hashlib.sha256(f"{address}:{uuid.uuid4()}".encode()).hexdigest()[:10]
                attributes[name] = f"{change['name']}-{digest}.sim.internal"
        resources[address] = {
            "mode": "managed",
            "type": change["type"],
            "name": change["name"],
            "instances": [{"attributes": attributes}],
        }
    model = _load(directory / "model.json", {})
    state["serial"] += 1
    state["resources"] = list(resources.values())
    state["outputs"] = {
        k: {"value": _render(v, variables), "type": "string"}
        for k, v in model.get("outputs", {}).items()
    }
    _save(directory, state)
    print("Apply complete!")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    directory = Path.cwd()
    if not args:
        print("Usage: terraform <command> [args]", file=sys.stderr)
        return 1
    command, rest = args[0], args[1:]
    if command == "init":
        if not (directory / "terraform.tfstate").exists():
            _save(directory, _state(directory))
        print("Terraform has been successfully initialized!")
        return 0
    if command == "plan":
        return _plan(directory, rest)
    if command == "show":
        return _show(directory, rest)
    if command == "apply":
        return _apply(directory, rest)
    if command == "state" and rest[:1] == ["pull"]:
        print(json.dumps(_state(directory)))
        return 0
    if command == "output" and "-json" in rest:
        print(json.dumps(_state(directory).get("outputs", {})))
        return 0
    print(f"Error: {command} is not a command this stand-in knows", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - run as a command
    sys.exit(main())
