"""The Kubernetes substrate (1.3.0): plan-bound staging over the API server's
own dry run, on a loopback API server with admission webhooks."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from agentgov.receipts import HmacKey, ReceiptLog

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
from interlock.exceptions import (
    CommitUnsettledError,
    ForbiddenStatementError,
    OutboundRequestError,
    StageConflictError,
    StageError,
    SubstrateConfigurationError,
)
from interlock.kubernetes import fingerprint, kubernetes_tables, parse_statement, quantity
from interlock.outbound import OperationSpec, SinkRegistry, SinkSpec
from interlock.planbound import STAGE_ANNOTATION, UndoJournal
from interlock.receipts import ReceiptIssuer
from interlock.sim.kubernetes import (
    DEPLOYMENTS,
    STATEFULSETS,
    LoopbackCluster,
    ResourceType,
    Webhook,
    apply_json_patch,
    merge_patch,
)
from interlock.sqlite_outbox import install_sqlite_outbox
from interlock.types import EffectDiff, EffectKind, Verdict

TOKEN = "remediator-token"
AGENT = "system:serviceaccount:sre:remediator"
NS = "prod-east"

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


def measured(result: Any) -> EffectDiff:
    """A result's diff, which every staged plan has."""
    assert result.diff is not None
    found: EffectDiff = result.diff
    return found


def judged(result: Any) -> Verdict:
    """A result's verdict, which every staged plan has."""
    assert result.verdict is not None
    found: Verdict = result.verdict
    return found


def image(row: Any) -> dict[str, Any]:
    """A row image, present."""
    assert row is not None
    return dict(row)


def _x10(request: dict[str, Any]) -> dict[str, Any]:
    """The mutating policy: a change of replicas on a labeled deployment is
    multiplied by ten."""
    obj, old = request["object"], request.get("oldObject") or {}
    replicas = obj["spec"].get("replicas", 1)
    if (old.get("spec") or {}).get("replicas") != replicas and replicas % 10:
        return {
            "allowed": True,
            "patch": [{"op": "replace", "path": "/spec/replicas", "value": replicas * 10}],
        }
    return {"allowed": True}


def deployment(name: str, replicas: int, *, labels: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": NS,
            "labels": {"account": "acct-prod", **(labels or {})},
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": f"reg/{name}:1",
                            "resources": {"requests": {"cpu": "500m"}},
                        }
                    ]
                }
            },
        },
    }


def database(storage: str = "500Gi") -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "orders-pg", "namespace": NS},
        "spec": {
            "replicas": 1,
            "serviceName": "orders-pg",
            "selector": {"matchLabels": {"app": "orders-pg"}},
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {"resources": {"requests": {"storage": storage}}},
                }
            ],
        },
    }


@pytest.fixture
def cluster() -> Iterator[LoopbackCluster]:
    found = LoopbackCluster(
        (DEPLOYMENTS, STATEFULSETS),
        tokens={TOKEN: AGENT, "admin-token": "kubernetes-admin"},
        webhooks=[
            Webhook(
                "scale-x10",
                resources=("deployments",),
                match_labels={"policy": "scale-x10"},
                handler=_x10,
            )
        ],
    )
    found.start()
    found.seed("deployments", deployment("api", 4, labels={"policy": "scale-x10"}))
    found.seed("deployments", deployment("checkout", 3))
    found.seed("deployments", deployment("cart", 2))
    found.seed("statefulsets", database())
    yield found
    found.stop()


class _Kube(KubernetesSubstrate):
    """The substrate, its methods replaceable for a test (no ``__slots__``)."""


def substrate(cluster: LoopbackCluster, tmp_path: Path, **kwargs: Any) -> KubernetesSubstrate:
    return _Kube(cluster.url, kinds=KINDS, journal=tmp_path / "journal", token=TOKEN, **kwargs)


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


def scale(name: str, replicas: int) -> tuple[str, dict[str, Any], str]:
    return (
        "scale deployments :namespace :name :replicas",
        {"namespace": NS, "name": name, "replicas": replicas},
        "deployments",
    )


def resize(storage: str) -> tuple[str, dict[str, Any], str]:
    patch = {
        "spec": {
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {"resources": {"requests": {"storage": storage}}},
                }
            ]
        }
    }
    return (
        "merge-patch statefulsets :namespace :name :patch",
        {"namespace": NS, "name": "orders-pg", "patch": patch},
        "statefulsets",
    )


def engine(sub: KubernetesSubstrate, tmp_path: Path, *checkers: Any, **kwargs: Any) -> EscrowEngine:
    return EscrowEngine(
        sub,
        checkers=list(checkers) or [BlastRadius(10)],
        chain=EscrowChain(tmp_path / "chain.ilok1"),
        **kwargs,
    )


# -- the statement language, and what a kind reads ---------------------------------------


def test_statements_parse_each_verb_and_refuse_anything_else() -> None:
    found = parse_statement("scale deployments :ns 'api' :n")
    assert (found.verb, found.table) == ("scale", "deployments")
    assert found.bind({"ns": NS, "n": 3}) == {"namespace": NS, "name": "api", "replicas": 3}
    assert parse_statement("apply deployments :m").verb == "apply"
    assert parse_statement("delete deployments :a :b").verb == "delete"
    assert parse_statement("expect-version deployments :a :b 'it''s'").arguments[2] == ("'", "it's")
    for bad, message in [
        ("drop deployments :a :b", "verbs"),
        ("scale", "verb, a table"),
        ("scale deployments :a :b", "takes"),
        ("scale deployments :a :b word", "argument"),
        ("scale deployments :a :b 'open", "not closed"),
        ("scale deployments : :b :c", "parameter"),
        ("scale deployments ;", "unexpected"),
    ]:
        with pytest.raises(ValueError, match=message):
            parse_statement(bad)
    with pytest.raises(ValueError, match="not bound"):
        parse_statement("scale deployments :a :b :c").bind({"a": 1})


def test_quantities_and_columns_are_read_exactly() -> None:
    assert quantity(2) == 2
    assert quantity("500m") == Decimal("0.5")
    assert quantity("1Gi") == 1024**3
    assert quantity("1.5k") == 1500
    for bad in ("", "lots", True, 1.5, None):
        assert quantity(bad) is None
    image = KINDS[0].image(deployment("api", 6))
    assert image["vcpu"] == 3 and image["replicas"] == 6 and image["account"] == "acct-prod"
    assert KINDS[0].image({"metadata": {"name": "x", "namespace": NS}})["vcpu"] is None
    half = deployment("api", 1)
    assert KINDS[0].image(half)["vcpu"] == "0.5"
    listed = KubeKind("d", "deployments", "Deployment", columns={"selector": "spec.selector"})
    assert listed.image(deployment("api", 1))["selector"] == '{"matchLabels":{"app":"api"}}'


def test_a_fingerprint_ignores_bookkeeping_and_sees_every_field() -> None:
    first = deployment("api", 4)
    second = json.loads(json.dumps(first))
    second["metadata"].update(resourceVersion="9", uid="u", generation=3)
    second["metadata"]["annotations"] = {STAGE_ANNOTATION: "s"}
    second["status"] = {"replicas": 4}
    assert fingerprint(first) == fingerprint(second)
    second["metadata"]["annotations"]["team"] = "sre"
    assert fingerprint(first) != fingerprint(second)
    second["metadata"]["annotations"] = {}
    second["spec"]["template"]["spec"]["containers"][0]["image"] = "reg/api:2"
    assert fingerprint(first) != fingerprint(second)


def test_kinds_and_tables_are_checked() -> None:
    specs = kubernetes_tables(KINDS)
    assert [s.name for s in specs] == ["deployments", "statefulsets"]
    assert specs[0].tenant_column == "namespace" and specs[0].primary_key == "object"
    with pytest.raises(ValueError, match="identifier"):
        KubeKind("Deployments", "deployments", "Deployment")
    with pytest.raises(ValueError, match="own columns"):
        KubeKind("d", "deployments", "Deployment", columns={"namespace": "x"})
    with pytest.raises(ValueError, match="share a name"):
        KubeKind("d", "deployments", "D", columns={"a": "x"}, partitions={"a": "y"})
    with pytest.raises(ValueError, match="resource name"):
        KubeKind("d", "Deploy-ments", "D")
    assert KubeKind("pods", "pods", "Pod").collection("x") == "/api/v1/namespaces/x/pods"


def test_the_substrate_is_checked(tmp_path: Path) -> None:
    with pytest.raises(SubstrateConfigurationError, match="HTTPS"):
        KubernetesSubstrate("http://10.0.0.1:6443", kinds=KINDS, journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="at least one"):
        KubernetesSubstrate("http://127.0.0.1:1", kinds=(), journal=tmp_path)
    with pytest.raises(SubstrateConfigurationError, match="own table"):
        KubernetesSubstrate("http://127.0.0.1:1", kinds=(KINDS[0], KINDS[0]), journal=tmp_path)
    sub = KubernetesSubstrate(
        "https://cluster.example:6443", kinds=KINDS, journal=tmp_path, namespaces=(NS,)
    )
    caps = sub.capabilities
    assert (caps.measurement, caps.plan_bound, caps.transactional, caps.outbound) == (
        "plan-bound",
        True,
        False,
        False,
    )
    assert sub.observed_tables == {"deployments", "statefulsets"}
    assert sub.commit_markers and sub.control is None and sub.held_operations() == {}
    assert sub.server == "https://cluster.example:6443"


def test_vetting_reads_the_statement(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path, namespaces=(NS,))

    def reason(
        statement: str, parameters: dict[str, Any], table: str = "deployments"
    ) -> str | None:
        (effect,) = plan((statement, parameters, table)).effects
        return sub.reject_reason(effect)

    assert reason("scale deployments :a :b :c", {"a": NS, "b": "api", "c": 2}) is None
    assert "no kind" in str(reason("scale pods :a :b :c", {"a": NS, "b": "x", "c": 1}, "pods"))
    assert "targets" in str(
        reason("scale statefulsets :a :b :c", {"a": NS, "b": "x", "c": 1}, "deployments")
    )
    assert "not one a plan" in str(
        reason("scale deployments :a :b :c", {"a": "kube-system", "b": "x", "c": 1})
    )
    assert "object name" in str(
        sub_any(cluster, tmp_path).reject_reason(
            plan(
                ("scale deployments :a :b :c", {"a": NS, "b": "Bad_Name", "c": 1}, "deployments")
            ).effects[0]
        )
    )
    assert "non-negative" in str(
        reason("scale deployments :a :b :c", {"a": NS, "b": "api", "c": -1})
    )
    assert "non-negative" in str(
        reason("scale deployments :a :b :c", {"a": NS, "b": "api", "c": "6"})
    )
    assert "JSON object" in str(
        reason("merge-patch deployments :a :b :p", {"a": NS, "b": "api", "p": "[1]"})
    )
    assert "not a apps/v1" in str(
        reason("apply deployments :m", {"m": {"apiVersion": "v1", "kind": "Pod", "metadata": {}}})
    )
    assert "manifest" in str(reason("apply deployments :m", {"m": "not json"}))
    assert "not a statement" in str(reason("scale deployments :a :b", {"a": 1, "b": 2}))
    enqueue = (
        PlanBuilder("s").enqueue(sink="cloud", operation="x", payload={"a": 1}).build().effects[0]
    )
    assert sub.reject_reason(enqueue) is None


def sub_any(cluster: LoopbackCluster, tmp_path: Path) -> KubernetesSubstrate:
    return substrate(cluster, tmp_path / "any")


# -- staging and committing -------------------------------------------------------


def test_a_scale_commits_on_the_version_measured(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    log = ReceiptLog("k8s", HmacKey(b"k" * 32), path=tmp_path / "receipts.jsonl")
    result = engine(sub, tmp_path, receipts=ReceiptIssuer(log, row_secret=b"r" * 32)).execute(
        plan(scale("checkout", 4))
    )
    assert result.committed
    (delta,) = measured(result).deltas
    assert (delta.table, delta.primary_key, delta.tenant_id) == (
        "deployments",
        f"{NS}/checkout",
        NS,
    )
    assert (image(delta.before)["replicas"], image(delta.after)["replicas"]) == (3, 4)
    assert delta.partitions == {"account": "acct-prod"}
    live = cluster.get("deployments", NS, "checkout")
    assert live is not None and live["spec"]["replicas"] == 4
    assert live["metadata"]["annotations"][STAGE_ANNOTATION] == str(measured(result).stage_id)
    receipt = result.receipt
    assert receipt is not None
    assert receipt.coverage.measurement == "plan-bound"
    assert receipt.outcome.substrate_txid == f"kubernetes:{measured(result).stage_id}"
    puts = [e for e in cluster.audit_events() if e["verb"] == "update"]
    assert [("dryRun=All" in e["requestURI"]) for e in puts] == [True, False]
    assert (
        puts[1]["requestObject"]["metadata"]["resourceVersion"]
        == puts[0]["requestObject"]["metadata"]["resourceVersion"]
    )
    intent = next(
        r
        for r in EscrowChain.load(tmp_path / "chain.ilok1").records()
        if r.record_type is RecordType.COMMIT_INTENT
    )
    assert "; undo " in intent.note and intent.note.endswith("; commit marker armed")
    assert not list((tmp_path / "journal").glob("*.json"))


def test_the_webhook_is_measured_and_judged(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    guard = ColumnValueGuard(
        "deployments", "replicas", max_drop_fraction=1.0, max_rise_fraction=2.0
    )
    result = engine(sub, tmp_path, guard, BlastRadius(10)).execute(plan(scale("api", 6)))
    (delta,) = measured(result).deltas
    assert (image(delta.before)["replicas"], image(delta.after)["replicas"]) == (4, 60)
    assert (image(delta.before)["vcpu"], image(delta.after)["vcpu"]) == (2, 30)
    assert not result.committed
    assert [v.invariant for v in judged(result).blocking] == [
        "column_value_guard:deployments.replicas"
    ]
    live = cluster.get("deployments", NS, "api")
    assert live is not None and live["spec"]["replicas"] == 4
    assert "annotations" not in live["metadata"]


def test_a_forced_replacement_is_a_deletion(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    result = engine(sub, tmp_path, NoDelete(()), BlastRadius(10)).execute(plan(resize("1Ti")))
    assert [d.operation for d in measured(result).deltas] == ["delete", "insert"]
    assert image(measured(result).deltas[1].after)["storage"] == "1Ti"
    assert [v.invariant for v in judged(result).blocking] == ["no_delete"]
    live = cluster.get("statefulsets", NS, "orders-pg")
    assert live is not None and "1Ti" not in json.dumps(live)
    granted = engine(
        substrate(cluster, tmp_path / "g"), tmp_path / "g", NoDelete(("statefulsets",))
    )
    (tmp_path / "g").mkdir(exist_ok=True)
    replaced = granted.execute(plan(resize("1Ti")))
    assert replaced.committed
    new = cluster.get("statefulsets", NS, "orders-pg")
    assert new is not None and new["metadata"]["uid"] != live["metadata"]["uid"]
    assert (
        new["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "1Ti"
    )


def test_an_immutable_change_is_refused_unless_replaceable(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    fixed = (KINDS[0], KubeKind("statefulsets", "statefulsets", "StatefulSet", group="apps"))
    sub = KubernetesSubstrate(cluster.url, kinds=fixed, journal=tmp_path / "j", token=TOKEN)
    with pytest.raises(StageError, match="cannot be changed in place"):
        engine(sub, tmp_path).execute(plan(resize("1Ti")))


def test_a_webhook_with_side_effects_cannot_be_measured(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    cluster.add_webhook(
        Webhook("ticketing", resources=("deployments",), side_effects="Some", handler=lambda r: {})
    )
    with pytest.raises(StageError, match="declares side effects"):
        engine(substrate(cluster, tmp_path), tmp_path).execute(plan(scale("checkout", 4)))
    live = cluster.get("deployments", NS, "checkout")
    assert live is not None and live["spec"]["replicas"] == 3


def test_admission_refusals_and_absent_objects_refuse_the_stage(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    cluster.add_webhook(
        Webhook(
            "no-latest",
            mutating=False,
            resources=("deployments",),
            handler=lambda r: {"allowed": False, "message": "latest tags are not allowed"},
            match_labels={"guard": "on"},
        )
    )
    cluster.seed("deployments", deployment("guarded", 1, labels={"guard": "on"}))
    with pytest.raises(StageError, match="latest tags"):
        engine(substrate(cluster, tmp_path), tmp_path).execute(plan(scale("guarded", 2)))
    with pytest.raises(StageError, match="there is no deployments"):
        engine(substrate(cluster, tmp_path / "a"), tmp_path).execute(plan(scale("ghost", 2)))
    with pytest.raises(StageError, match="to delete"):
        engine(substrate(cluster, tmp_path / "b"), tmp_path).execute(
            plan(("delete deployments :a :b", {"a": NS, "b": "ghost"}, "deployments"))
        )


def test_create_apply_and_delete(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    run = engine(sub, tmp_path, NoDelete(("deployments",)), BlastRadius(10))
    created = run.execute(
        plan(("apply deployments :manifest", {"manifest": deployment("search", 2)}, "deployments"))
    )
    assert created.committed and [d.operation for d in measured(created).deltas] == ["insert"]
    search = cluster.get("deployments", NS, "search")
    assert search is not None and search["spec"]["strategy"]["type"] == "RollingUpdate"
    replaced = run.execute(
        plan(("apply deployments :manifest", {"manifest": deployment("search", 3)}, "deployments"))
    )
    assert replaced.committed and image(measured(replaced).deltas[0].after)["replicas"] == 3
    deleted = run.execute(
        plan(("delete deployments :a :b", {"a": NS, "b": "search"}, "deployments"))
    )
    assert deleted.committed and [d.operation for d in measured(deleted).deltas] == ["delete"]
    assert cluster.get("deployments", NS, "search") is None


def test_an_unchanged_object_is_no_row(cluster: LoopbackCluster, tmp_path: Path) -> None:
    result = engine(substrate(cluster, tmp_path), tmp_path).execute(plan(scale("checkout", 3)))
    assert result.committed and measured(result).deltas == ()
    assert [e["verb"] for e in cluster.audit_events() if "dryRun" not in e["requestURI"]] == []


def test_two_effects_on_one_object_compose(cluster: LoopbackCluster, tmp_path: Path) -> None:
    patch = (
        "merge-patch deployments :a :b :p",
        {"a": NS, "b": "checkout", "p": {"metadata": {"labels": {"tier": "web"}}}},
        "deployments",
    )
    result = engine(substrate(cluster, tmp_path), tmp_path).execute(
        plan(scale("checkout", 5), patch)
    )
    assert result.committed
    live = cluster.get("deployments", NS, "checkout")
    assert (
        live is not None
        and live["spec"]["replicas"] == 5
        and live["metadata"]["labels"]["tier"] == "web"
    )


def test_expect_version_pins_the_approved_state(cluster: LoopbackCluster, tmp_path: Path) -> None:
    version = cluster.get("deployments", NS, "checkout")["metadata"]["resourceVersion"]  # type: ignore[index]
    pin = (
        "expect-version deployments :a :b :v",
        {"a": NS, "b": "checkout", "v": version},
        "deployments",
    )
    assert (
        engine(substrate(cluster, tmp_path), tmp_path)
        .execute(plan(pin, scale("checkout", 4)))
        .committed
    )
    with pytest.raises(StageConflictError, match="approved on is gone"):
        engine(substrate(cluster, tmp_path / "x"), tmp_path).execute(
            plan(pin, scale("checkout", 5))
        )


def test_a_cluster_that_moved_fails_closed(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    original = sub.commit

    def raced(handle: Any) -> Any:
        current = cluster.get("deployments", NS, "checkout")
        assert current is not None
        current["spec"]["replicas"] = 9
        cluster.seed("deployments", current)  # someone else wrote it
        return original(handle)

    sub.commit = raced  # type: ignore[method-assign]
    with pytest.raises(StageConflictError, match="nothing was applied"):
        engine(sub, tmp_path).execute(plan(scale("checkout", 4)))
    live = cluster.get("deployments", NS, "checkout")
    assert live is not None and live["spec"]["replicas"] == 9
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.ABORTED


# -- a partial apply ------------------------------------------------------------


def test_a_partial_apply_is_put_back(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    cluster.fail_next("deployments", NS, "checkout")
    run = engine(sub, tmp_path, BlastRadius(10))
    with pytest.raises(CompensatedError) as raised:
        run.execute(plan(scale("cart", 5), scale("checkout", 4)))
    assert (raised.value.applied, raised.value.restored) == (1, 2)
    cart = cluster.get("deployments", NS, "cart")
    assert cart is not None and cart["spec"]["replicas"] == 2
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED
    assert "restored from undo" in records[-1].note


def test_a_landing_that_differs_from_the_measure_is_put_back(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    calls = {"n": 0}

    def shifty(request: dict[str, Any]) -> dict[str, Any]:
        """Answers a dry run one way and the first real write another."""
        if request["dryRun"]:
            return {"allowed": True}
        calls["n"] += 1
        if calls["n"] > 1:
            return {"allowed": True}
        return {"allowed": True, "patch": [{"op": "replace", "path": "/spec/replicas", "value": 7}]}

    cluster.add_webhook(
        Webhook(
            "shifty",
            resources=("deployments",),
            side_effects="NoneOnDryRun",
            handler=shifty,
            match_labels={"app": "x"},
        )
    )
    cluster.seed(
        "deployments",
        {
            **deployment("odd", 1),
            "metadata": {"name": "odd", "namespace": NS, "labels": {"app": "x"}},
        },
    )
    with pytest.raises(CompensatedError, match="did not land"):
        engine(substrate(cluster, tmp_path), tmp_path).execute(plan(scale("odd", 2)))
    assert calls["n"] >= 1


def test_an_undo_that_fails_leaves_the_intent_open_for_recovery(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    sub = substrate(cluster, tmp_path)
    cluster.fail_next("deployments", NS, "checkout")
    sub._restore = lambda *args: "the API server refused"  # type: ignore[method-assign]
    run = engine(sub, tmp_path)
    with pytest.raises(CommitUnsettledError, match="undo journal stays"):
        run.execute(plan(scale("cart", 5), scale("checkout", 4)))
    assert list((tmp_path / "journal").glob("*.undo.json"))
    run.chain.close()
    recovered = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert [r.record_type for r in recovered] == [RecordType.COMPENSATED]
    cart = cluster.get("deployments", NS, "cart")
    assert cart is not None and cart["spec"]["replicas"] == 2


def test_an_undo_that_fails_once_is_retried_at_once(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    sub = substrate(cluster, tmp_path)
    cluster.fail_next("deployments", NS, "checkout")
    original = sub._restore
    calls = {"n": 0}

    def restore(*args: Any) -> str | None:
        calls["n"] += 1
        return "refused" if calls["n"] == 1 else original(*args)

    sub._restore = restore  # type: ignore[method-assign,assignment]
    with pytest.raises(CompensatedError, match="undone from undo"):
        engine(sub, tmp_path).execute(plan(scale("cart", 5), scale("checkout", 4)))
    records = EscrowChain.load(tmp_path / "chain.ilok1").records()
    assert records[-1].record_type is RecordType.COMPENSATED


# -- recovery -------------------------------------------------------------------


def _crashed(cluster: LoopbackCluster, tmp_path: Path, *steps: Any, writes: int) -> uuid.UUID:
    """A stage measured, its undo written and ``writes`` of its objects
    applied (all of them, when more), then the process gone: the intent open
    on the chain."""
    sub = substrate(cluster, tmp_path)
    run = engine(sub, tmp_path)
    original, whole = sub._write, sub._apply_all
    done = {"n": 0}

    def write(stage: Any, obj: Any) -> Any:
        if done["n"] == writes:
            raise SystemExit("crash")
        done["n"] += 1
        return original(stage, obj)

    def apply_all(stage: Any, objects: Any) -> None:
        whole(stage, objects)
        raise SystemExit("crash after every write")

    sub._write = write  # type: ignore[method-assign]
    sub._apply_all = apply_all  # type: ignore[method-assign,assignment]
    with pytest.raises(SystemExit):
        run.execute(plan(*steps))
    (intent,) = run.chain.unresolved_intents()
    run.chain.close()
    assert intent.stage_id is not None
    return intent.stage_id


def test_recovery_cannot_say_for_an_object_another_wrote(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    _crashed(cluster, tmp_path, scale("checkout", 4), writes=0)
    moved = cluster.get("deployments", NS, "checkout")
    assert moved is not None
    moved["spec"]["replicas"] = 9
    cluster.seed("deployments", moved)
    assert engine(substrate(cluster, tmp_path), tmp_path).recover() == ()


def test_recovery_finds_a_whole_apply(cluster: LoopbackCluster, tmp_path: Path) -> None:
    stage = _crashed(cluster, tmp_path, scale("checkout", 4), writes=99)
    (record,) = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED and record.stage_id == stage


def test_recovery_finds_nothing_applied(cluster: LoopbackCluster, tmp_path: Path) -> None:
    _crashed(cluster, tmp_path, scale("checkout", 4), writes=0)
    (record,) = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.ABORTED


def test_recovery_puts_a_partial_apply_back(cluster: LoopbackCluster, tmp_path: Path) -> None:
    _crashed(cluster, tmp_path, scale("cart", 5), scale("checkout", 4), writes=1)
    (record,) = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMPENSATED
    for name, replicas in (("cart", 2), ("checkout", 3)):
        live = cluster.get("deployments", NS, name)
        assert live is not None and live["spec"]["replicas"] == replicas


def test_recovery_of_a_deletion(cluster: LoopbackCluster, tmp_path: Path) -> None:
    _crashed(
        cluster,
        tmp_path,
        ("delete deployments :a :b", {"a": NS, "b": "checkout"}, "deployments"),
        writes=99,
    )
    (record,) = engine(substrate(cluster, tmp_path), tmp_path).recover()
    assert record.record_type is RecordType.COMMITTED


def test_recovery_without_an_undo_cannot_say(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    assert sub.resolve_intent(uuid.uuid4()) is None
    journal = UndoJournal(tmp_path / "journal")
    stage = uuid.uuid4()
    journal.write(
        stage, {"objects": [{"table": "pods", "namespace": NS, "name": "x", "action": "update"}]}
    )
    assert sub.resolve_intent(stage) is None


# -- the control database: an outbox, and its redo ------------------------------------------


def _control(tmp_path: Path) -> Path:
    path = tmp_path / "control.db"
    install_sqlite_outbox(str(path), SINKS)
    return path


SINKS = (SinkSpec("cloud", (OperationSpec("securitygroup.update", hold=True),)),)


def test_a_request_commits_with_the_cluster_writes(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    control = _control(tmp_path)
    sub = substrate(cluster, tmp_path, control=control)
    assert sub.capabilities.outbound and sub.held_operations() == {
        "cloud": ("securitygroup.update",)
    }
    builder = PlanBuilder("sre-remediator", intent="open and scale")
    builder.add(
        EffectKind.APPLY,
        table="kubernetes:deployments",
        statement="scale deployments :a :b :c",
        parameters={"a": NS, "b": "checkout", "c": 4},
        tenant_id=NS,
    )
    builder.enqueue(
        sink="cloud",
        operation="securitygroup.update",
        payload={"group": "edge", "port": 22},
        tenant_id=NS,
    )
    result = engine(sub, tmp_path, BlastRadius(10), sinks=SinkRegistry(SINKS)).execute(
        builder.build()
    )
    assert result.committed and len(measured(result).outbound) == 1
    with sqlite3.connect(control) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone() == (1,)
    assert not list((tmp_path / "journal").glob("*.redo.json"))


def test_a_request_without_a_control_database_is_refused(
    cluster: LoopbackCluster, tmp_path: Path
) -> None:
    sub = substrate(cluster, tmp_path)
    handle = sub.open(plan(scale("checkout", 4)))
    enqueue = (
        PlanBuilder("s").enqueue(sink="cloud", operation="x", payload={"a": 1}).build().effects[0]
    )
    with pytest.raises(OutboundRequestError, match="no control database"):
        sub.apply(handle, enqueue)
    with pytest.raises(Exception, match="control database"):
        sub.measure_windows(handle, ())
    with pytest.raises(Exception, match="no inbox"):
        sub.consume_facts(handle, (), "s")
    assert sub.pending_facts("s") == ()
    sub.close(handle)


def test_recovery_redoes_the_control_half(cluster: LoopbackCluster, tmp_path: Path) -> None:
    control = _control(tmp_path)
    sub = substrate(cluster, tmp_path, control=control)
    builder = PlanBuilder("sre-remediator", intent="open and scale")
    builder.add(
        EffectKind.APPLY,
        table="kubernetes:deployments",
        statement="scale deployments :a :b :c",
        parameters={"a": NS, "b": "checkout", "c": 4},
        tenant_id=NS,
    )
    builder.enqueue(
        sink="cloud",
        operation="securitygroup.update",
        payload={"group": "edge", "port": 22},
        tenant_id=NS,
    )
    original = sub._apply_all

    def crash(stage: Any, writes: Any) -> None:
        original(stage, writes)
        raise SystemExit("crash after the cluster, before the control database")

    sub._apply_all = crash  # type: ignore[method-assign]
    run = engine(sub, tmp_path, sinks=SinkRegistry(SINKS))
    with pytest.raises(SystemExit):
        run.execute(builder.build())
    run.chain.close()
    with sqlite3.connect(control) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone() == (0,)
    (record,) = engine(
        substrate(cluster, tmp_path, control=control), tmp_path, sinks=SinkRegistry(SINKS)
    ).recover()
    assert record.record_type is RecordType.COMMITTED
    with sqlite3.connect(control) as conn:
        assert conn.execute("SELECT count(*) FROM _interlock_outbox").fetchone() == (1,)


# -- savepoints, and the stage's own rules ------------------------------------------------


def test_savepoints_roll_the_stage_back(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    (first, second) = plan(scale("checkout", 4), scale("api", 10)).effects
    handle = sub.open(plan(scale("checkout", 4)))
    sub.apply(handle, first)
    sub.savepoint(handle, "one")
    sub.apply(handle, second)
    assert len(sub.diff(handle).deltas) == 2
    with pytest.raises(StageError, match="undo written first"):
        sub.commit(handle)
    sub.rollback_to(handle, "one")
    with pytest.raises(StageError, match="before it is measured"):
        sub.commit(handle)
    assert [d.primary_key for d in sub.diff(handle).deltas] == [f"{NS}/checkout"]
    sub.release_savepoint(handle, "one")
    with pytest.raises(StageError, match="no savepoint"):
        sub.rollback_to(handle, "one")
    with pytest.raises(ValueError, match="unsafe"):
        sub.savepoint(handle, "1; drop")
    sub.abort(handle)
    sub.close(handle)


def test_one_stage_at_a_time_and_its_undo_first(cluster: LoopbackCluster, tmp_path: Path) -> None:
    sub = substrate(cluster, tmp_path)
    (effect,) = plan(scale("checkout", 4)).effects
    handle = sub.open(plan(scale("checkout", 4)))
    with pytest.raises(StageConflictError, match="already has stage"):
        sub.open(plan(scale("checkout", 4)))
    sub.apply(handle, effect)
    sub.diff(handle)
    with pytest.raises(StageError, match="undo written first"):
        sub.commit(handle)
    assert sub.transaction_id(handle) == f"kubernetes:{handle.stage_id}"
    with pytest.raises(ForbiddenStatementError):
        sub.apply(handle, plan(("drop it :a", {}, "deployments")).effects[0])
    sub.close(handle)
    sub.close(handle)
    with pytest.raises(StageError, match="not open"):
        sub.apply(handle, effect)


def test_a_sql_substrate_refuses_an_apply_effect(tmp_path: Path) -> None:
    from interlock import SqliteSubstrate, TableSpec

    sub = SqliteSubstrate(str(tmp_path / "x.db"), tables=[TableSpec("t", columns=["id"])])
    (effect,) = plan(("scale deployments :a :b :c", {"a": 1, "b": 2, "c": 3}, "t")).effects
    assert "own statement language" in str(sub.reject_reason(effect))


# -- the loopback API server itself ----------------------------------------------------------


def test_the_loopback_server_speaks_the_api(cluster: LoopbackCluster) -> None:
    import urllib.error
    import urllib.request

    def call(
        method: str, path: str, body: Any = None, token: str | None = TOKEN
    ) -> tuple[int, Any]:
        request = urllib.request.Request(
            cluster.url + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "Content-Type": "application/merge-patch+json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request) as reply:
                return reply.status, json.loads(reply.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    base = f"/apis/apps/v1/namespaces/{NS}/deployments"
    assert call("GET", base + "/checkout", token=None)[0] == 401
    status, listed = call("GET", base)
    assert status == 200 and {i["metadata"]["name"] for i in listed["items"]} == {
        "api",
        "cart",
        "checkout",
    }
    assert call("GET", base + "/ghost")[0] == 404
    assert call("GET", "/apis/apps/v1/namespaces/x/pods")[0] == 404
    assert call("GET", "/nowhere")[0] == 404
    assert call("POST", base, {"metadata": {}})[0] == 422
    assert call("POST", base, deployment("checkout", 1))[0] == 409
    status, patched = call("PATCH", base + "/checkout", {"spec": {"replicas": 8}})
    assert (
        status == 200
        and patched["spec"]["replicas"] == 8
        and patched["metadata"]["generation"] == 2
    )
    assert call("PATCH", base + "/checkout", {"metadata": {"resourceVersion": "1"}})[0] == 409
    assert call("DELETE", base + "/checkout", {"preconditions": {"resourceVersion": "1"}})[0] == 409
    assert call("PUT", base + "/ghost", deployment("ghost", 1))[0] == 404
    assert call("DELETE", base + "/ghost")[0] == 404
    assert call("PUT", base, deployment("x", 1))[0] == 405
    assert call("DELETE", base + "/checkout")[0] == 200
    events = cluster.audit_events()
    assert {e["user"]["username"] for e in events} == {AGENT}
    assert any(e["responseStatus"]["code"] == 409 for e in events)
    assert cluster.audit_log().count("\n") == len(events)


def test_patches_merge_and_apply() -> None:
    assert merge_patch({"a": {"b": 1, "c": 2}}, {"a": {"b": None, "d": 3}}) == {
        "a": {"c": 2, "d": 3}
    }
    assert merge_patch({"a": 1}, [1]) == [1]
    doc = {"a": [1, 2], "b": {"c": 1}}
    assert apply_json_patch(
        doc,
        [
            {"op": "add", "path": "/a/-", "value": 3},
            {"op": "replace", "path": "/a/0", "value": 0},
            {"op": "add", "path": "/a/1", "value": 9},
            {"op": "remove", "path": "/a/3"},
            {"op": "remove", "path": "/b/c"},
            {"op": "add", "path": "/e~1f", "value": 1},
        ],
    ) == {"a": [0, 9, 2], "b": {}, "e/f": 1}
    with pytest.raises(ValueError, match="not supported"):
        apply_json_patch(doc, [{"op": "move", "path": "/a"}])


def test_a_webhook_served_elsewhere_and_a_broken_one(tmp_path: Path) -> None:
    hosted = LoopbackCluster((ResourceType("configmaps", "ConfigMap"),))
    hosted.start()
    try:
        hosted.add_webhook(
            Webhook(
                "label",
                resources=("configmaps",),
                handler=lambda r: {
                    "allowed": True,
                    "patch": [{"op": "add", "path": "/metadata/labels", "value": {"seen": "yes"}}],
                },
            )
        )
        outer = LoopbackCluster(
            (ResourceType("configmaps", "ConfigMap"),),
            webhooks=[
                Webhook("label", resources=("configmaps",), url=f"{hosted.url}/webhooks/label")
            ],
        )
        outer.start()
        try:
            kind = KubeKind(
                "configmaps", "configmaps", "ConfigMap", columns={"seen": "metadata.labels.seen"}
            )
            sub = KubernetesSubstrate(outer.url, kinds=(kind,), journal=tmp_path / "j")
            manifest = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "c", "namespace": NS},
                "data": {"k": "v"},
            }
            result = EscrowEngine(sub, checkers=[BlastRadius(5)]).execute(
                plan(("apply configmaps :m", {"m": manifest}, "configmaps"))
            )
            assert result.committed and image(measured(result).deltas[0].after)["seen"] == "yes"
            outer.add_webhook(
                Webhook("gone", resources=("configmaps",), url="http://127.0.0.1:9/x")
            )
            with pytest.raises(StageError, match="failed calling webhook"):
                EscrowEngine(sub, checkers=[BlastRadius(5)]).execute(
                    plan(
                        (
                            "apply configmaps :m",
                            {"m": {**manifest, "data": {"k": "w"}}},
                            "configmaps",
                        )
                    )
                )
        finally:
            outer.stop()
    finally:
        hosted.stop()
    with pytest.raises(RuntimeError, match="not started"):
        _ = LoopbackCluster().url
