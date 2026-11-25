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
