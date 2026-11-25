import json

import pytest

from agentic_aiops.offline_topology import build_topology, main


def obj(kind, name, uid, **meta):
    return {"kind": kind, "metadata": {"name": name, "uid": uid, "namespace": "demo", **meta}}


def owner(kind, name, uid):
    return {"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}


def snapshot():
    service = obj("Service", "checkout", "svc")
    service["spec"] = {"selector": {"app": "checkout"}}
    return {
        "service": service,
        "pods": {"kind": "PodList", "items": [
            obj("Pod", "checkout-1", "pod", labels={"app": "checkout"}, ownerReferences=[owner("ReplicaSet", "checkout-rs", "rs")]),
            obj("Pod", "other", "other", labels={"app": "other"}),
        ]},
        "replica_sets": {"kind": "ReplicaSetList", "items": [
            obj("ReplicaSet", "checkout-rs", "rs", ownerReferences=[owner("Deployment", "checkout", "dep")]),
        ]},
        "deployments": {"kind": "DeploymentList", "items": [obj("Deployment", "checkout", "dep")]},
    }


def test_topology_links_selector_and_exact_controller_identity():
    result = build_topology(snapshot())
    assert result["schema_version"] == "offline-service-topology/v1"
    assert {e["entity_id"] for e in result["entities"]} == {"svc", "pod", "rs", "dep"}
    assert {(e["source"], e["target"], e["relation"]) for e in result["edges"]} == {
        ("svc", "pod", "selector_matches"), ("pod", "rs", "controller_reference"), ("rs", "dep", "controller_reference")
    }
    assert result["unresolved"] == []
    assert result["source_authenticated"] is result["execution_authorized"] is False


def test_same_name_different_uid_is_not_an_owner():
    data = snapshot()
    data["replica_sets"]["items"][0]["metadata"]["uid"] = "replacement"
    result = build_topology(data)
    assert {e["entity_id"] for e in result["entities"]} == {"svc", "pod"}
    assert result["unresolved"] == [{"entity_id": "pod", "reason": "controller_not_resolved"}]


def test_selectorless_service_abstains():
    data = snapshot()
    data["service"]["spec"]["selector"] = {}
    result = build_topology(data)
    assert result["edges"] == []
    assert result["unresolved"] == [{"entity_id": "svc", "reason": "selector_absent"}]


@pytest.mark.parametrize("fault", ["cross_namespace", "duplicate_uid", "duplicate_name", "paginated", "wrong_kind", "bad_labels", "multiple_controllers"])
def test_inconsistent_inventory_is_rejected(fault):
    data = snapshot()
    pod = data["pods"]["items"][0]
    if fault == "cross_namespace":
        pod["metadata"]["namespace"] = "other"
    elif fault == "duplicate_uid":
        data["deployments"]["items"][0]["metadata"]["uid"] = "pod"
    elif fault == "duplicate_name":
        data["pods"]["items"][1]["metadata"]["name"] = "checkout-1"
    elif fault == "paginated":
        data["pods"]["metadata"] = {"continue": "more"}
    elif fault == "wrong_kind":
        pod["kind"] = "Secret"
    elif fault == "bad_labels":
        pod["metadata"]["labels"] = {"app": True}
    else:
        pod["metadata"]["ownerReferences"].append(owner("ReplicaSet", "other", "another"))
    with pytest.raises(ValueError):
        build_topology(data)


def test_cli_renders_and_rejects_invalid_json(tmp_path, capsys):
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot()), encoding="utf-8")
    main([str(path)])
    assert len(json.loads(capsys.readouterr().out)["edges"]) == 3
    path.write_text('{"service":{},"service":{}}', encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([str(path)])
    output = capsys.readouterr()
    assert exc.value.code == 2
    assert not output.out
    assert "invalid topology snapshot" in output.err


@pytest.mark.parametrize("version", [None, "custom.example/v1"])
def test_owner_api_group_must_be_explicit(version):
    data = snapshot()
    ref = data["pods"]["items"][0]["metadata"]["ownerReferences"][0]
    if version is None:
        del ref["apiVersion"]
    else:
        ref["apiVersion"] = version
    result = build_topology(data)
    assert result["unresolved"] == [{"entity_id": "pod", "reason": "controller_not_resolved"}]


def test_no_matches_is_an_unresolved_observation_not_outage_proof():
    data = snapshot()
    data["service"]["spec"]["selector"] = {"app": "missing"}
    result = build_topology(data)
    assert result["edges"] == []
    assert result["unresolved"] == [{"entity_id": "svc", "reason": "no_selector_matches"}]
    assert result["independently_verified"] is False


def test_native_typed_list_may_omit_item_kind():
    data = snapshot()
    del data["pods"]["items"][0]["kind"]
    assert len(build_topology(data)["edges"]) == 3
    data["pods"]["kind"] = "List"
    with pytest.raises(ValueError):
        build_topology(data)


def test_deployment_observation_preserves_explicit_counts_and_generation():
    data = snapshot()
    deployment = data["deployments"]["items"][0]
    deployment["metadata"]["generation"] = 5
    deployment["spec"] = {"replicas": 3}
    deployment["status"] = {"observedGeneration": 5, "replicas": 2, "readyReplicas": 0, "availableReplicas": 0, "updatedReplicas": 1}
    result = build_topology(data)
    assert result["deployment_observations"] == [{
        "entity_id": "dep", "desired_replicas": 3, "replicas": 2,
        "ready_replicas": 0, "available_replicas": 0, "updated_replicas": 1,
        "generation": 5, "observed_generation": 5, "generation_status": "matches",
    }]
    assert result["independently_verified"] is False


@pytest.mark.parametrize("generation,observed,expected", [(5, 4, "stale"), (5, 6, "inconsistent"), (None, 5, "unknown"), (5, None, "unknown")])
def test_deployment_generation_and_missing_counts(generation, observed, expected):
    data = snapshot()
    deployment = data["deployments"]["items"][0]
    if generation is not None:
        deployment["metadata"]["generation"] = generation
    if observed is not None:
        deployment["status"] = {"observedGeneration": observed}
    item, = build_topology(data)["deployment_observations"]
    assert item["generation_status"] == expected
    assert all(item[key] is None for key in ("desired_replicas", "replicas", "ready_replicas", "available_replicas", "updated_replicas"))


@pytest.mark.parametrize("bad", [True, -1, "2", 2.5])
def test_malformed_deployment_count_is_not_coerced(bad):
    data = snapshot()
    data["deployments"]["items"][0]["status"] = {"availableReplicas": bad}
    with pytest.raises(ValueError):
        build_topology(data)


def test_unlinked_deployment_does_not_supply_observation():
    data = snapshot()
    data["pods"]["items"] = []
    assert build_topology(data)["deployment_observations"] == []


def test_pod_observation_preserves_reported_readiness_and_container_states():
    data = snapshot()
    pod = data["pods"]["items"][0]
    pod["status"] = {
        "phase": "Running",
        "conditions": [{"type": "Ready", "status": "False"}, {"type": "PodScheduled", "status": "True"}],
        "containerStatuses": [
            {"name": "app", "ready": False, "restartCount": 3, "state": {"waiting": {"reason": "CrashLoopBackOff"}}},
            {"name": "sidecar", "ready": True, "restartCount": 0, "state": {"running": {}}},
        ],
    }
    pod["spec"] = {"containers": [{"name": "app", "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}}}, {"name": "sidecar"}]}
    result = build_topology(data)
    assert result["pod_observations"] == [{
        "entity_id": "pod", "phase": "Running", "ready_condition": "False", "scheduled_condition": "True",
        "container_statuses": [
            {"name": "app", "ready": False, "restart_count": 3, "state": "waiting", "reason": "CrashLoopBackOff"},
            {"name": "sidecar", "ready": True, "restart_count": 0, "state": "running", "reason": None},
        ],
        "readiness_probe_presence": [{"name": "app", "configured": True}, {"name": "sidecar", "configured": False}],
    }]
    assert result["independently_verified"] is False


def test_missing_pod_status_is_unknown_not_unready():
    item, = build_topology(snapshot())["pod_observations"]
    assert item == {"entity_id": "pod", "phase": None, "ready_condition": None, "scheduled_condition": None,
                    "container_statuses": None, "readiness_probe_presence": None}


def test_explicit_empty_status_lists_and_unknown_condition_are_preserved():
    data = snapshot()
    data["pods"]["items"][0]["status"] = {"conditions": [{"type": "Ready", "status": "Unknown"}], "containerStatuses": []}
    item, = build_topology(data)["pod_observations"]
    assert item["ready_condition"] == "Unknown"
    assert item["container_statuses"] == []


@pytest.mark.parametrize("bad", ["duplicate_condition", "invalid_condition", "boolean_restart", "negative_restart", "bad_ready", "duplicate_container", "multiple_states", "invalid_phase", "invalid_probe"])
def test_malformed_pod_observation_is_rejected(bad):
    data = snapshot()
    pod = data["pods"]["items"][0]
    condition = {"type": "Ready", "status": "False"}
    container = {"name": "app", "ready": False, "restartCount": 0, "state": {"waiting": {}}}
    pod["status"] = {"phase": "Running", "conditions": [condition], "containerStatuses": [container]}
    if bad == "duplicate_condition":
        pod["status"]["conditions"].append(dict(condition))
    elif bad == "invalid_condition":
        condition["status"] = False
    elif bad == "boolean_restart":
        container["restartCount"] = True
    elif bad == "negative_restart":
        container["restartCount"] = -1
    elif bad == "bad_ready":
        container["ready"] = "false"
    elif bad == "duplicate_container":
        pod["status"]["containerStatuses"].append(dict(container))
    elif bad == "multiple_states":
        container["state"]["running"] = {}
    elif bad == "invalid_phase":
        pod["status"]["phase"] = "Healthy"
    else:
        pod["spec"] = {"containers": [{"name": "app", "readinessProbe": True}]}
    with pytest.raises(ValueError):
        build_topology(data)


def test_unmatched_pod_observations_are_not_included():
    data = snapshot()
    data["service"]["spec"]["selector"] = {"app": "missing"}
    assert build_topology(data)["pod_observations"] == []
