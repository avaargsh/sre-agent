"""Reject incomplete inventory even when the continuation token is empty."""
import hashlib
import json

import pytest

from agentic_aiops.offline_topology import load_topology_snapshot, main


@pytest.fixture
def snapshot():
    return {
        "service": {"kind": "Service", "metadata": {"namespace": "demo", "name": "checkout", "uid": "svc"},
                    "spec": {"selector": {"app": "checkout"}}},
        "pods": {"kind": "PodList", "items": []},
        "replica_sets": {"kind": "ReplicaSetList", "items": []},
        "deployments": {"kind": "DeploymentList", "items": []},
    }


@pytest.mark.parametrize("field", ["pods", "replica_sets", "deployments"])
@pytest.mark.parametrize("remaining", [1, -1, False, True, 0.0, "0", None])
def test_incomplete_inventory_rejected_by_cli(tmp_path, capsys, snapshot, field, remaining):
    snapshot[field]["metadata"] = {"continue": "", "remainingItemCount": remaining}
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main([str(path)])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "invalid topology snapshot" in output.err


@pytest.mark.parametrize("metadata", [{}, {"continue": "", "remainingItemCount": 0}])
def test_complete_inventory_preserves_digest(tmp_path, snapshot, metadata):
    for field in ("pods", "replica_sets", "deployments"):
        snapshot[field]["metadata"] = metadata
    path = tmp_path / "snapshot.json"
    raw = json.dumps(snapshot).encode("utf-8")
    path.write_bytes(raw)
    report = load_topology_snapshot(path)
    assert report["snapshot_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["unresolved"] == [{"entity_id": "svc", "reason": "no_selector_matches"}]
    assert report["source_authenticated"] is report["execution_authorized"] is False
