"""Offline display of a Go Endpoint capture, not an independent replay."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

MAX_CAPTURE_BYTES = 10 << 20
MAX_SOURCE_BYTES = 2 << 20
_SOURCE_FIELDS = ("service_before", "endpoint_slices", "service_after")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _slice_membership(slices: dict, target: dict) -> dict:
    """Check archived slice scope and reported owner identity, not readiness."""
    metadata = slices.get("metadata", {})
    if (not isinstance(metadata, dict) or metadata.get("continue", "") != ""
            or type(metadata.get("remainingItemCount", 0)) is not int
            or metadata.get("remainingItemCount", 0) != 0 or len(slices["items"]) > 128):
        raise ValueError("incomplete or oversized EndpointSlice list")
    seen_uids = set()
    seen_names = set()
    owner_matches = 0
    for item in slices["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
            raise ValueError("invalid EndpointSlice metadata")
        meta = item["metadata"]
        uid, name = meta.get("uid"), meta.get("name")
        labels = meta.get("labels")
        if (not isinstance(uid, str) or not uid.strip() or uid in seen_uids
                or not isinstance(name, str) or not name.strip() or len(name.encode("utf-8")) > 253
                or name in seen_names or meta.get("namespace") != target["namespace"]
                or not isinstance(labels, dict) or not all(isinstance(value, str) for value in labels.values())
                or labels.get("kubernetes.io/service-name") != target["name"]):
            raise ValueError("invalid or off-scope EndpointSlice identity")
        seen_uids.add(uid)
        seen_names.add(name)
        refs = meta.get("ownerReferences", [])
        if refs is None:
            refs = []  # Native Go decoder permits null/absent ownerReferences.
        if not isinstance(refs, list) or any(not isinstance(ref, dict) for ref in refs):
            raise ValueError("invalid EndpointSlice owner references")
        owners = [ref for ref in refs if ref.get("kind") == "Service"]
        if len(owners) > 1 or any(
            ref.get("apiVersion") != "v1" or ref.get("name") != target["name"]
            or ref.get("uid") != target["uid"] for ref in owners
        ):
            raise ValueError("EndpointSlice Service owner identity mismatch")
        if labels.get("endpointslice.kubernetes.io/managed-by") == "endpointslice-controller.k8s.io" and not owners:
            raise ValueError("controller-managed EndpointSlice missing Service owner")
        owner_matches += len(owners)
    return {"slice_count": len(seen_uids), "service_owner_uid_matches": owner_matches,
            "label_only": len(seen_uids) - owner_matches}


def summarize_endpoint_capture(path: str | Path) -> dict:
    """Check byte/digest binding and display explicitly unverified claims."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("oversized capture")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    report = capture["report"]
    if (capture["schema_version"] != "sre.service-endpoints-capture/v1"
            or report["schema_version"] != "sre.service-endpoints/v3"
            or report["source_authenticated"] is not False):
        raise ValueError("invalid capture schema or authentication claim")
    target = {key: report["target"][key] for key in ("namespace", "name", "uid")}
    if not all(isinstance(value, str) and value.strip() for value in target.values()):
        raise ValueError("invalid reported target")
    classification = report["classification"]
    count = report["ready_endpoints"]
    if (classification not in ("READY_ENDPOINTS_OBSERVED", "NO_READY_ENDPOINTS_OBSERVED", "UNKNOWN")
            or type(count) is not int or count < 0):
        raise ValueError("invalid reported observation")
    timestamps = {key: report[key] for key in ("collection_started_at", "observed_at")}
    if not all(isinstance(value, str) and value.strip() for value in timestamps.values()):
        raise ValueError("invalid reported timestamps")
    sources = {}
    digests = {}
    for field in _SOURCE_FIELDS:
        encoded = capture[field + "_raw"]
        if not isinstance(encoded, str):
            raise ValueError("invalid source encoding")
        source = base64.b64decode(encoded, validate=True)
        if not 0 < len(source) <= MAX_SOURCE_BYTES:
            raise ValueError("empty or oversized source")
        digest = _digest(source)
        if digest != report[field + "_sha256"]:
            raise ValueError("source digest mismatch")
        sources[field] = source
        digests[field] = digest
    if sources["service_before"] != sources["service_after"]:
        raise ValueError("Service snapshots differ")
    service = json.loads(sources["service_before"].decode("utf-8"), object_pairs_hook=_unique_object)
    slices = json.loads(sources["endpoint_slices"].decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(service, dict) or service.get("kind", "Service") != "Service":
        raise ValueError("invalid archived Service kind")
    metadata = service.get("metadata")
    if not isinstance(metadata, dict) or any(metadata.get(key) != value for key, value in target.items()):
        raise ValueError("archived Service identity mismatch")
    if (not isinstance(slices, dict) or slices.get("kind") != "EndpointSliceList"
            or not isinstance(slices.get("items"), list)):
        raise ValueError("invalid archived EndpointSliceList envelope")
    return {
        "schema_version": "endpoint-observation-summary/v1",
        "capture_sha256": _digest(raw),
        "target": target,
        "reported_classification": classification,
        "reported_ready_endpoints": count,
        "reported_collection_started_at": timestamps["collection_started_at"],
        "reported_observed_at": timestamps["observed_at"],
        "source_sha256": digests,
        "source_bytes_match_report_digests": True,
        "source_service_identity_matches_report": True,
        "slice_membership": _slice_membership(slices, target),
        "source_authenticated": False,
        "independently_verified": False,
        "root_cause_verified": False,
        "execution_authorized": False,
    }


def render_endpoint_rca(summary: dict) -> dict:
    """Project a local capture summary into an unverified RCA report."""
    from .report import render_rca_json

    digest = summary["capture_sha256"]
    target = summary["target"]
    classification = summary["reported_classification"]
    count = summary["reported_ready_endpoints"]
    evidence_id = "endpoint-observation-" + digest
    observation = f"Capture reports {classification} and {count} ready endpoints; not independently verified."
    hypotheses = []
    checks = []
    if classification == "NO_READY_ENDPOINTS_OBSERVED" and count == 0:
        for key, statement, required_evidence, question in (
            (
                "replicas", "Backend replica availability may be insufficient.",
                ["workload_owner_identity", "desired_and_available_replicas", "pod_phase_and_scheduling"],
                "Does the independently identified backend have insufficient available replicas?",
            ),
            (
                "readiness", "Backend readiness checks may not be passing.",
                ["pod_readiness_conditions", "container_status", "readiness_probe_configuration"],
                "Do backend readiness conditions explain the reported observation?",
            ),
            (
                "reconciliation", "Service selection or EndpointSlice reconciliation may need investigation.",
                ["service_selector", "pod_labels_and_identity", "endpointslice_owner_and_readiness"],
                "Do independently collected Service, Pod and EndpointSlice records agree?",
            ),
        ):
            hypothesis_id = "endpoint-" + key
            hypotheses.append({
                "hypothesis_id": hypothesis_id,
                "statement": statement,
                "evidence_ids": [evidence_id],
                "status": "unverified",
            })
            checks.append({
                "hypothesis_id": hypothesis_id,
                "evidence_ids": [evidence_id],
                "status": "pending_evidence",
                "read_only": True,
                "required_evidence": required_evidence,
                "verification_question": question,
            })
    payload = {
        "incident": {
            "incident_id": "endpoint-" + digest,
            "summary": observation,
            "severity": "unknown",
            "scope": target["namespace"] + "/" + target["name"],
        },
        "evidence": [{
            "evidence_id": evidence_id,
            "source": "archived-endpoint-observation",
            "observation": observation,
            "timestamp": summary["reported_observed_at"],
            "attributes": {"capture_sha256": digest},
        }],
        "hypotheses": hypotheses,
    }
    result = json.loads(render_rca_json(payload))
    result["endpoint_observation"] = summary
    result["investigation_plan"] = {
        "schema_version": "endpoint-investigation-plan/v1",
        "capture_sha256": digest,
        "reported_target": dict(target),
        "target_verified": False,
        "collection_authorized": False,
        "execution_authorized": False,
        "checks": checks,
    }
    return result


def _investigation_coverage(plan: dict, topology: dict) -> dict:
    """Describe fields present in supplied context, never evidence sufficiency."""
    prefix = "/topology_context/snapshot/"
    edges = topology["edges"]
    deployments = topology["deployment_observations"]
    candidates = topology["deployment_candidates"]
    pods = topology["pod_observations"]
    coverage = {}

    def record(requirement, refs, complete=False):
        coverage[requirement] = {
            "requirement": requirement,
            "status": "provided" if refs and complete else "partial" if refs else "missing",
            "report_refs": refs,
        }

    def fields(requirement, rows, section, keys, complete=None):
        refs = [prefix + section + "/" + str(i) for i, row in enumerate(rows)
                if any(row[key] is not None for key in keys)]
        full = bool(rows) and all(all(row[key] is not None for key in keys)
                                  and (complete is None or complete(row)) for row in rows)
        record(requirement, refs, full)

    owner_refs = [prefix + "edges/" + str(i) for i, edge in enumerate(edges)
                  if edge["relation"] == "controller_reference"]
    candidate_refs = [prefix + "deployment_candidates/" + str(i) for i in range(len(candidates))]
    record("workload_owner_identity", owner_refs + candidate_refs,
           bool(deployments) and not topology["unresolved"] and not candidates)
    keys = ("desired_replicas", "available_replicas")
    fields("desired_and_available_replicas", deployments, "deployment_observations", keys,
           lambda row: row["generation_status"] == "matches")
    if candidates:
        refs = [prefix + "deployment_candidates/" + str(i) + "/observation"
                for i, row in enumerate(candidates) if any(row["observation"][key] is not None for key in keys)]
        record("desired_and_available_replicas", refs)
    fields("pod_phase_and_scheduling", pods, "pod_observations", ("phase", "scheduled_condition"))
    fields("pod_readiness_conditions", pods, "pod_observations", ("ready_condition",),
           lambda row: row["ready_condition"] in ("True", "False"))
    def complete_containers(row):
        statuses = row["container_statuses"]
        declared = row["readiness_probe_presence"]
        return (bool(statuses) and bool(declared)
                and {item["name"] for item in statuses} == {item["name"] for item in declared}
                and all(all(item[key] is not None for key in ("ready", "restart_count", "state"))
                        for item in statuses))

    fields("container_status", pods, "pod_observations", ("container_statuses",), complete_containers)
    record("readiness_probe_configuration", [prefix + "pod_observations/" + str(i) + "/readiness_probe_presence"
                                               for i, row in enumerate(pods) if row["readiness_probe_presence"] is not None])
    selector_refs = [prefix + "edges/" + str(i) for i, edge in enumerate(edges)
                     if edge["relation"] == "selector_matches"]
    record("service_selector", selector_refs + candidate_refs)
    record("pod_labels_and_identity", selector_refs)
    record("endpointslice_owner_and_readiness", ["/endpoint_observation/reported_ready_endpoints"])
    return {**plan, "checks": [
        {**check, "evidence_coverage": [coverage.get(requirement, {
            "requirement": requirement, "status": "missing", "report_refs": [],
        }) for requirement in check["required_evidence"]]}
        for check in plan["checks"]
    ]}


def _replica_assessment(topology: dict) -> dict:
    """Compare supplied replica fields without asserting a live root cause."""
    observations = []

    def assess(row, association, ref):
        desired = row["desired_replicas"]
        available = row["available_replicas"]
        ready = row["ready_replicas"]
        total = row["replicas"]
        if row["generation_status"] != "matches":
            status = "unknown_generation"
        elif desired is None or available is None:
            status = "missing_counts"
        elif ((ready is not None and available > ready)
              or (total is not None and (available > total or (ready is not None and ready > total)))):
            status = "inconsistent_counts"
        elif desired == 0:
            status = "zero_desired_and_available" if available == 0 else "zero_desired_with_available"
        elif available < desired:
            status = "availability_shortfall"
        else:
            status = "desired_availability_met"
        observations.append({"entity_id": row["entity_id"], "association": association,
                             "status": status, "report_ref": ref})

    prefix = "/topology_context/snapshot/"
    for i, row in enumerate(topology["deployment_observations"]):
        assess(row, "owner_chain", prefix + "deployment_observations/" + str(i))
    for i, candidate in enumerate(topology["deployment_candidates"]):
        assess(candidate["observation"], "template_candidate",
               prefix + "deployment_candidates/" + str(i) + "/observation")
    return {
        "schema_version": "offline-replica-assessment/v1",
        "observations": observations,
        "independently_verified": False,
        "root_cause_verified": False,
        "execution_authorized": False,
    }


def _readiness_assessment(topology: dict) -> dict:
    """Compare reported Pod conditions with regular container observations."""
    observations = []
    for i, row in enumerate(topology["pod_observations"]):
        containers = row["container_statuses"]
        declared = row["readiness_probe_presence"]
        condition = row["ready_condition"]
        unready = sorted(item["name"] for item in containers or [] if item["ready"] is False)
        inconsistent = any(item["ready"] is True and item["state"] in ("waiting", "terminated")
                           for item in containers or [])
        if condition == "True":
            inconsistent = inconsistent or bool(unready) or row["scheduled_condition"] == "False" or row["phase"] in ("Pending", "Succeeded", "Failed")
        if inconsistent:
            status = "inconsistent_status"
        elif condition == "True":
            status = "reported_ready"
        elif condition == "False":
            status = "reported_not_ready"
        else:
            status = "unknown_readiness"
        if containers is None:
            detail = "missing"
        elif (containers and declared
              and {item["name"] for item in containers} == {item["name"] for item in declared}
              and all(all(item[key] is not None for key in ("ready", "restart_count", "state"))
                      for item in containers)):
            detail = "provided"
        else:
            detail = "partial"
        observations.append({
            "entity_id": row["entity_id"], "status": status,
            "container_detail": detail, "reported_unready_containers": unready,
            "report_ref": "/topology_context/snapshot/pod_observations/" + str(i),
        })
    return {
        "schema_version": "offline-readiness-assessment/v1",
        "observations": observations,
        "independently_verified": False,
        "root_cause_verified": False,
        "execution_authorized": False,
    }


def attach_topology_context(report: dict, snapshot_path: str | Path) -> dict:
    """Attach a separate local inventory only if its Service identity agrees."""
    from .offline_topology import load_topology_snapshot

    topology = load_topology_snapshot(snapshot_path)
    observation = report["endpoint_observation"]
    target = observation["target"]
    services = [item for item in topology["entities"] if item["kind"] == "Service"]
    if len(services) != 1:
        raise ValueError("expected one Service")
    service = services[0]
    if (service["entity_id"] != target["uid"] or service["name"] != target["name"]
            or service["attributes"]["namespace"] != target["namespace"]):
        raise ValueError("reported Service identity mismatch")
    return {
        **report,
        "investigation_plan": _investigation_coverage(report["investigation_plan"], topology),
        "topology_context": {
            "capture_sha256": observation["capture_sha256"],
            "snapshot": topology,
            "replica_assessment": _replica_assessment(topology),
            "readiness_assessment": _readiness_assessment(topology),
            "reported_service_identity_matches": True,
            "independently_verified": False,
            "collection_authorized": False,
            "execution_authorized": False,
        },
    }
