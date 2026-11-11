"""The Kubernetes substrate against a real API server (a ``kind`` cluster).

``scripts/kind-setup.sh`` prepares the cluster and prints the environment
(``INTERLOCK_TEST_K8S_SERVER``, ``_TOKEN``, ``_CA``). The substrate acts as a
service account that can edit the namespace ``interlock-test`` and nothing
else. What the API server does here is its own: defaults, a
``MutatingAdmissionPolicy`` that multiplies a labelled deployment's replicas by
ten, a ``ValidatingAdmissionPolicy`` ceiling, immutable fields,
``resourceVersion`` preconditions answered with ``409 Conflict``.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from interlock import (
    BlastRadius,
    ColumnValueGuard,
    CompensatedError,
    EscrowChain,
    EscrowEngine,
    KubeKind,
    KubernetesSubstrate,
    NoDelete,
    PlanBuilder,
)
from interlock.chain import RecordType
from interlock.exceptions import StageConflictError, StageError
from interlock.planbound import STAGE_ANNOTATION
from interlock.types import EffectDiff, EffectKind

from .real_systems import need

NS = "interlock-test"

KINDS = (
    KubeKind(
        "deployments",
        "deployments",
        "Deployment",
        group="apps",
        columns={
            "replicas": "spec.replicas",
            "image": "spec.template.spec.containers.0.image",
            "vcpu": "spec.replicas * spec.template.spec.containers.0.resources.requests.cpu",
        },
        partitions={"account": "metadata.labels.account"},
    ),
    KubeKind(
        "statefulsets",
        "statefulsets",
        "StatefulSet",
        group="apps",
        columns={
            "replicas": "spec.replicas",
            "storage": "spec.volumeClaimTemplates.0.spec.resources.requests.storage",
        },
        replace_on_immutable=True,
    ),
)


class _Cluster:
    """The API server, as the test's own client: the same service account."""

    def __init__(self, server: str, token: str, ca: str) -> None:
        self.server, self.token, self.ca = server.rstrip("/"), token, ca
        self.context = ssl.create_default_context(cafile=ca)

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - the test's own cluster URL
            self.server + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as reply:  # noqa: S310
                return reply.status, json.loads(reply.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"null")

    def path(self, plural: str, name: str = "") -> str:
        return f"/apis/apps/v1/namespaces/{NS}/{plural}" + (f"/{name}" if name else "")

    def get(self, plural: str, name: str) -> dict[str, Any]:
        status, found = self.call("GET", self.path(plural, name))
        assert status == 200, found
        return dict(found)

    def create(self, plural: str, body: dict[str, Any]) -> None:
        status, found = self.call("POST", self.path(plural), body)
        assert status == 201, found

    def delete(self, plural: str, name: str) -> None:
        self.call("DELETE", self.path(plural, name), {"propagationPolicy": "Background"})

    def change(self, plural: str, name: str, edit: Callable[[dict[str, Any]], None]) -> None:
        """Another writer's change, as a client makes one: read, edit, write on the version
        read, and read again when the cluster moved in between. The Deployment controller
        writes status on its own schedule, so a single read-then-write is sometimes refused
        with 409 (it was, in CI, about once in a few dozen runs)."""
        for _ in range(20):
            current = self.get(plural, name)
            edit(current)
            status, found = self.call("PUT", self.path(plural, name), current)
            if status == 200:
                return
            assert status == 409, found
        raise AssertionError(f"{plural}/{name} was refused with 409 twenty times in a row")


@pytest.fixture
def cluster() -> _Cluster:
    server, token, ca = need(
        "INTERLOCK_TEST_K8S_SERVER", "INTERLOCK_TEST_K8S_TOKEN", "INTERLOCK_TEST_K8S_CA"
    )
    return _Cluster(server, token, ca)


@pytest.fixture
def names(cluster: _Cluster) -> Iterator[dict[str, str]]:
    """Fresh object names for one test, deleted afterwards."""
    suffix = uuid.uuid4().hex[:6]
    made = {k: f"{k}-{suffix}" for k in ("cart", "checkout", "api", "orders")}
    yield made
    for key, name in made.items():
        cluster.delete("statefulsets" if key == "orders" else "deployments", name)


def deployment(name: str, replicas: int, *, x10: bool = False) -> dict[str, Any]:
    labels = {"app": name, "account": "acct-prod"}
    if x10:
        labels["interlock.io/x10"] = "true"
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": NS, "labels": labels},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "image": "registry.k8s.io/pause:3.10",
                            "resources": {"requests": {"cpu": "500m"}},
                        }
                    ]
                },
            },
        },
    }


def statefulset(name: str, storage: str) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": name, "namespace": NS},
        "spec": {
            "replicas": 0,
            "serviceName": name,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "db", "image": "registry.k8s.io/pause:3.10"}]},
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": storage}},
                    },
                }
            ],
        },
    }


class _Kube(KubernetesSubstrate):
    """The substrate, its methods replaceable for a test."""


def substrate(cluster: _Cluster, tmp_path: Path) -> KubernetesSubstrate:
    return _Kube(
        cluster.server,
        kinds=KINDS,
        journal=tmp_path / "journal",
        namespaces=(NS,),
        token=cluster.token,
        ca_file=cluster.ca,
    )


def scale(name: str, replicas: int) -> tuple[str, dict[str, Any], str]:
    return (
        "scale deployments :namespace :name :replicas",
        {"namespace": NS, "name": name, "replicas": replicas},
        "deployments",
    )


def plan(*statements: tuple[str, dict[str, Any], str]) -> Any:
    builder = PlanBuilder("sre-remediator", intent="remediate")
    for statement, parameters, table in statements:
        builder.add(
            EffectKind.APPLY,
            table=f"kubernetes:{table}",
            statement=statement,
            parameters=parameters,
            tenant_id=NS,
        )
    return builder.build()


def engine(sub: KubernetesSubstrate, tmp_path: Path, *checkers: Any) -> EscrowEngine:
    return EscrowEngine(
        sub,
        checkers=list(checkers) or [BlastRadius(10)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
    )


def diff(result: Any) -> EffectDiff:
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def test_a_scale_commits_on_the_version_measured(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    cluster.create("deployments", deployment(names["checkout"], 3))
    before = cluster.get("deployments", names["checkout"])
    result = engine(substrate(cluster, tmp_path), tmp_path).execute(
        plan(scale(names["checkout"], 4))
    )
    assert result.committed
    (delta,) = diff(result).deltas
    assert (delta.table, delta.primary_key, delta.tenant_id) == (
        "deployments",
        f"{NS}/{names['checkout']}",
        NS,
    )
    assert delta.before is not None and delta.after is not None
    assert (delta.before["replicas"], delta.after["replicas"]) == (3, 4)
    assert (delta.before["vcpu"], delta.after["vcpu"]) == ("1.5", 2)
    assert delta.partitions == {"account": "acct-prod"}
    live = cluster.get("deployments", names["checkout"])
    assert live["spec"]["replicas"] == 4
    assert live["metadata"]["annotations"][STAGE_ANNOTATION] == str(diff(result).stage_id)
    assert live["metadata"]["resourceVersion"] != before["metadata"]["resourceVersion"]


def test_admission_is_measured_and_judged(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    """The cluster's own mutating policy turns 6 replicas into 60 in the dry
    run; the measure says 60, and the guard refuses it before anything is written."""
    cluster.create("deployments", deployment(names["api"], 4, x10=True))
    guard = ColumnValueGuard(
        "deployments", "replicas", max_drop_fraction=1.0, max_rise_fraction=2.0
    )
    result = engine(substrate(cluster, tmp_path), tmp_path, guard).execute(
        plan(scale(names["api"], 6))
    )
    (delta,) = diff(result).deltas
    assert delta.before is not None and delta.after is not None
    assert (delta.before["replicas"], delta.after["replicas"]) == (4, 60)
    assert not result.committed
    assert result.verdict is not None
    assert [v.invariant for v in result.verdict.blocking] == [
        "column_value_guard:deployments.replicas"
    ]
    assert cluster.get("deployments", names["api"])["spec"]["replicas"] == 4


def test_a_validating_policy_refuses_the_dry_run(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    cluster.create("deployments", deployment(names["cart"], 2))
    with pytest.raises(StageError, match="at most 100 replicas"):
        engine(substrate(cluster, tmp_path), tmp_path).execute(plan(scale(names["cart"], 500)))
    assert cluster.get("deployments", names["cart"])["spec"]["replicas"] == 2


def test_defaults_are_measured(cluster: _Cluster, names: dict[str, str], tmp_path: Path) -> None:
    """A manifest applied without replicas: the API server defaults it to 1,
    and the measure is the defaulted object, not the manifest."""
    manifest = deployment(names["cart"], 1)
    del manifest["spec"]["replicas"]
    builder = PlanBuilder("sre-remediator", intent="create")
    builder.add(
        EffectKind.APPLY,
        table="kubernetes:deployments",
        statement="apply deployments :manifest",
        parameters={"manifest": manifest},
        tenant_id=NS,
    )
    result = engine(substrate(cluster, tmp_path), tmp_path).execute(builder.build())
    assert result.committed
    (delta,) = diff(result).deltas
    assert delta.operation == "insert" and delta.after is not None
    assert delta.after["replicas"] == 1
    live = cluster.get("deployments", names["cart"])
    assert live["spec"]["progressDeadlineSeconds"] == 600  # a default no one wrote
    assert live["metadata"]["annotations"][STAGE_ANNOTATION] == str(diff(result).stage_id)


def test_a_cluster_that_moved_fails_closed(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    cluster.create("deployments", deployment(names["checkout"], 3))
    sub = substrate(cluster, tmp_path)
    original = sub.commit

    def raced(handle: Any) -> Any:
        cluster.change(
            "deployments", names["checkout"], lambda found: found["spec"].update(replicas=9)
        )
        return original(handle)

    sub.commit = raced  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="nothing was applied"):
        engine(sub, tmp_path).execute(plan(scale(names["checkout"], 4)))
    assert cluster.get("deployments", names["checkout"])["spec"]["replicas"] == 9
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.ABORTED


def test_a_partial_apply_is_put_back(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    """The first write lands; then someone changes the second object, and the
    API server answers its write 409 on the version measured. The first is put
    back from the undo written before any write."""
    cluster.create("deployments", deployment(names["cart"], 2))
    cluster.create("deployments", deployment(names["checkout"], 3))
    sub = substrate(cluster, tmp_path)
    original = sub._write
    written: list[str] = []

    def write(stage: Any, obj: Any) -> Any:
        found = original(stage, obj)
        written.append(obj.name)
        if len(written) == 1:
            other = names["checkout"] if obj.name == names["cart"] else names["cart"]
            cluster.change(
                "deployments",
                other,
                lambda found: found["metadata"].setdefault("labels", {}).update(touched="yes"),
            )
        return found

    sub._write = write  # type: ignore[method-assign]
    with pytest.raises(CompensatedError):
        engine(sub, tmp_path).execute(plan(scale(names["cart"], 5), scale(names["checkout"], 4)))
    assert cluster.get("deployments", names["cart"])["spec"]["replicas"] == 2
    assert cluster.get("deployments", names["checkout"])["spec"]["replicas"] == 3
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED


def test_an_immutable_field_is_a_replacement_and_is_refused(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    cluster.create("statefulsets", statefulset(names["orders"], "10Gi"))
    patch = {
        "spec": {
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "1Ti"}},
                    },
                }
            ]
        }
    }
    resize = (
        "merge-patch statefulsets :namespace :name :patch",
        {"namespace": NS, "name": names["orders"], "patch": patch},
        "statefulsets",
    )
    result = engine(substrate(cluster, tmp_path), tmp_path, NoDelete(()), BlastRadius(10)).execute(
        plan(resize)
    )
    assert [d.operation for d in diff(result).deltas] == ["delete", "insert"]
    assert result.verdict is not None
    assert [v.invariant for v in result.verdict.blocking] == ["no_delete"]
    live = cluster.get("statefulsets", names["orders"])
    assert "1Ti" not in json.dumps(live)
    fixed = (KINDS[0], KubeKind("statefulsets", "statefulsets", "StatefulSet", group="apps"))
    strict = KubernetesSubstrate(
        cluster.server,
        kinds=fixed,
        journal=tmp_path / "j2",
        token=cluster.token,
        ca_file=cluster.ca,
    )
    (tmp_path / "s").mkdir()
    with pytest.raises(StageError, match="cannot be changed in place"):
        engine(strict, tmp_path / "s").execute(plan(resize))


def test_recovery_reads_the_stage_annotation(
    cluster: _Cluster, names: dict[str, str], tmp_path: Path
) -> None:
    cluster.create("deployments", deployment(names["checkout"], 3))
    sub = substrate(cluster, tmp_path)
    run = engine(sub, tmp_path)
    whole = sub._apply_all

    def crash_after(stage: Any, objects: Any) -> None:
        whole(stage, objects)
        raise SystemExit("crash after every write")

    sub._apply_all = crash_after  # type: ignore[method-assign,assignment]
    with pytest.raises(SystemExit):
        run.execute(plan(scale(names["checkout"], 7)))
    (intent,) = run.chain.unresolved_intents()
    run.chain.close()
    (record,) = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED and record.stage_id == intent.stage_id
    assert cluster.get("deployments", names["checkout"])["spec"]["replicas"] == 7
