"""Deterministic synthetic examples for the offline Endpoint RCA CLI."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .endpoint_report import attach_topology_context, render_endpoint_rca, summarize_endpoint_capture


def _object(kind, name, uid):
    return {"kind": kind, "metadata": {"namespace": "demo", "name": name, "uid": uid}}


def _owner(kind, name, uid):
    return {"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
    return capture, topology


def render_demo(case: str) -> dict:
    """Run the ordinary offline report path against synthetic local snapshots."""
    capture, topology = _fixture(case)
    with TemporaryDirectory(prefix="sre-endpoint-demo-") as directory:
        capture_path = Path(directory) / "capture.json"
        topology_path = Path(directory) / "topology.json"
        capture_path.write_bytes(_bytes(capture))
        topology_path.write_bytes(_bytes(topology))
        report = attach_topology_context(render_endpoint_rca(summarize_endpoint_capture(capture_path)), topology_path)
    return {"schema_version": "endpoint-offline-demo/v1", "synthetic": True, "case": case, "report": report}
