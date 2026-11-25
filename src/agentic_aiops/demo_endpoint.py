"""Deterministic synthetic examples for the offline Endpoint RCA CLI."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .endpoint_report import attach_topology_context, render_endpoint_rca, summarize_endpoint_capture

MAX_FIXTURE_BYTES = 20 << 20


def _object(kind, name, uid):
    return {"kind": kind, "metadata": {"namespace": "demo", "name": name, "uid": uid}}


def _owner(kind, name, uid):
    return {"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _fixture(case):
    if case not in ("scale-zero", "readiness"):
        raise ValueError("unknown demo case")
    scaled = case == "scale-zero"
    labels = {"app": "checkout"}
    service = _object("Service", "checkout", "demo-service")
    service["apiVersion"] = "v1"
    service["metadata"]["resourceVersion"] = "19"
    service["spec"] = {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]}
    target = {key: service["metadata"][key] for key in ("namespace", "name", "uid")}
    deployment = _object("Deployment", "checkout", "demo-deployment")
    deployment["metadata"]["generation"] = 2
    deployment["spec"] = {"replicas": 0 if scaled else 1, "template": {"metadata": {"labels": labels}}}
    deployment["status"] = {"observedGeneration": 2, "replicas": 0 if scaled else 1,
                            "readyReplicas": 0, "availableReplicas": 0, "updatedReplicas": 0 if scaled else 1}
    slices = {"kind": "EndpointSliceList", "metadata": {"resourceVersion": "25", "continue": ""}, "items": []}
    pods, replica_sets = [], []
    if not scaled:
        rs = _object("ReplicaSet", "checkout-rs", "demo-rs")
        rs["metadata"]["ownerReferences"] = [_owner("Deployment", "checkout", "demo-deployment")]
        pod = _object("Pod", "checkout-pod", "demo-pod")
        pod["metadata"].update(labels=labels, ownerReferences=[_owner("ReplicaSet", "checkout-rs", "demo-rs")])
        pod["spec"] = {"containers": [{"name": "app", "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}}}]}
        pod["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"},
                         {"type": "PodScheduled", "status": "True"}], "containerStatuses": [
                             {"name": "app", "ready": False, "restartCount": 0, "state": {"running": {}}}]}
        pods.append(pod)
        replica_sets.append(rs)
        endpoint_slice = _object("EndpointSlice", "checkout-slice", "demo-slice")
        endpoint_slice["metadata"].update(labels={"kubernetes.io/service-name": "checkout",
            "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"},
            ownerReferences=[{"apiVersion": "v1", "kind": "Service", "name": "checkout", "uid": "demo-service"}])
        endpoint_slice.update(addressType="IPv4", endpoints=[{"addresses": ["192.0.2.10"], "conditions": {"ready": False}}])
        slices["items"].append(endpoint_slice)
    topology = {"service": service, "pods": {"kind": "PodList", "items": pods},
                "replica_sets": {"kind": "ReplicaSetList", "items": replica_sets},
                "deployments": {"kind": "DeploymentList", "items": [deployment]}}
    report = {"schema_version": "sre.service-endpoints/v3", "target": target,
              "classification": "NO_READY_ENDPOINTS_OBSERVED", "ready_endpoints": 0,
              "source_authenticated": False, "collection_started_at": "2026-01-01T00:00:00Z",
              "observed_at": "2026-01-01T00:00:03Z"}
    capture = {"schema_version": "sre.service-endpoints-capture/v1", "report": report}
    for field, source in (("service_before", service), ("endpoint_slices", slices), ("service_after", service)):
        raw = _bytes(source)
        capture[field + "_raw"] = base64.b64encode(raw).decode("ascii")
        report[field + "_sha256"] = hashlib.sha256(raw).hexdigest()
    # Match the native collector's report envelope, with a fixed synthetic
    # timeline rather than claiming any actual Kubernetes API reads.
    report.update(expected_target_port=8080, expected_selector=dict(labels),
                  service_resource_version="19", endpoint_slice_list_resource_version="25")
    timeline = []
    for i, (name, field, version) in enumerate((
        ("service_get_before", "service_before", "19"),
        ("endpoint_slice_list", "endpoint_slices", "25"),
        ("service_get_after", "service_after", "19"),
    )):
        read = {"name": name, "started_at": f"2026-01-01T00:00:0{i}Z",
                "completed_at": f"2026-01-01T00:00:0{i + 1}Z",
                "response_resource_version": version,
                "response_sha256": report[field + "_sha256"]}
        if field == "endpoint_slices":
            read.update(request_consistency="MOST_RECENT",
                        request_label_selector="kubernetes.io/service-name=checkout", request_limit=129)
        timeline.append(read)
    report["read_timeline"] = timeline
    return capture, topology


def export_demo_fixture(case: str) -> dict:
    """Export both local inputs in an explicitly synthetic envelope."""
    capture, topology = _fixture(case)
    return {"schema_version": "endpoint-offline-fixture/v1", "synthetic": True,
            "case": case, "capture": capture, "topology": topology}


def _render_fixture(case: str, capture: dict, topology: dict) -> dict:
    """Run the ordinary offline report path against synthetic local snapshots."""
    with TemporaryDirectory(prefix="sre-endpoint-demo-") as directory:
        capture_path = Path(directory) / "capture.json"
        topology_path = Path(directory) / "topology.json"
        capture_path.write_bytes(_bytes(capture))
        topology_path.write_bytes(_bytes(topology))
        report = attach_topology_context(render_endpoint_rca(summarize_endpoint_capture(capture_path)), topology_path)
    return {"schema_version": "endpoint-offline-demo/v1", "synthetic": True, "case": case, "report": report}


def render_demo(case: str) -> dict:
    capture, topology = _fixture(case)
    return _render_fixture(case, capture, topology)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture JSON key")
        result[key] = value
    return result


def render_exported_fixture(path: str | Path) -> dict:
    """Render supplied synthetic inputs and bind the exact fixture file bytes."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FIXTURE_BYTES + 1)
    if len(raw) > MAX_FIXTURE_BYTES:
        raise ValueError("oversized fixture")
    fixture = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if (not isinstance(fixture, dict)
            or set(fixture) != {"schema_version", "synthetic", "case", "capture", "topology"}
            or fixture["schema_version"] != "endpoint-offline-fixture/v1"
            or fixture["synthetic"] is not True
            or fixture["case"] not in ("scale-zero", "readiness")
            or not isinstance(fixture["capture"], dict)
            or not isinstance(fixture["topology"], dict)):
        raise ValueError("invalid synthetic fixture envelope")
    result = _render_fixture(fixture["case"], fixture["capture"], fixture["topology"])
    return {**result, "fixture_sha256": hashlib.sha256(raw).hexdigest()}
