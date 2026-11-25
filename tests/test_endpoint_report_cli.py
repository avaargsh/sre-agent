import base64
import hashlib
import json

import pytest

from agentic_aiops.cli import main


def capture():
    service = b'{"kind":"Service","metadata":{"name":"checkout-api","namespace":"demo","uid":"service-uid-1"}}'
    slices = b'{"kind":"EndpointSliceList","items":[]}'
    sources = {"service_before": service, "endpoint_slices": slices, "service_after": service}
    report = {
        "schema_version": "sre.service-endpoints/v3",
        "target": {"namespace": "demo", "name": "checkout-api", "uid": "service-uid-1"},
        "classification": "NO_READY_ENDPOINTS_OBSERVED",
        "ready_endpoints": 0,
        "source_authenticated": False,
        "collection_started_at": "2026-11-25T05:00:00Z",
        "observed_at": "2026-11-25T05:00:01Z",
    }
    data = {"schema_version": "sre.service-endpoints-capture/v1", "report": report}
    for field, raw in sources.items():
        data[field + "_raw"] = base64.b64encode(raw).decode("ascii")
        report[field + "_sha256"] = hashlib.sha256(raw).hexdigest()
    return data


def run_cli(path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path)])
    main()


def test_endpoint_summary_preserves_reported_observation_without_authority(tmp_path, monkeypatch, capsys):
    path = tmp_path / "capture.json"
    data = capture()
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    run_cli(path, monkeypatch)
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert not out.err
    assert result["schema_version"] == "endpoint-observation-summary/v1"
    assert result["capture_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["target"] == data["report"]["target"]
    assert result["reported_classification"] == "NO_READY_ENDPOINTS_OBSERVED"
    assert result["reported_ready_endpoints"] == 0
    assert result["source_bytes_match_report_digests"] is True
    for key in ("source_authenticated", "independently_verified", "root_cause_verified", "execution_authorized"):
        assert result[key] is False
    assert "service_before_raw" not in result
    assert path.read_bytes() == raw


@pytest.mark.parametrize("fault", ["digest", "base64", "schema", "authentication", "boolean_count", "service_drift", "duplicate_key"])
def test_endpoint_summary_rejects_invalid_capture_without_partial_output(tmp_path, monkeypatch, capsys, fault):
    data = capture()
    if fault == "digest":
        data["report"]["endpoint_slices_sha256"] = "0" * 64
    elif fault == "base64":
        data["endpoint_slices_raw"] = "!"
    elif fault == "schema":
        data["report"]["schema_version"] = "unknown"
    elif fault == "authentication":
        data["report"]["source_authenticated"] = True
    elif fault == "boolean_count":
        data["report"]["ready_endpoints"] = True
    elif fault == "service_drift":
        raw = b'{"kind":"Service"}'
        data["service_after_raw"] = base64.b64encode(raw).decode("ascii")
        data["report"]["service_after_sha256"] = hashlib.sha256(raw).hexdigest()
    raw = json.dumps(data)
    if fault == "duplicate_key":
        raw = '{"schema_version":"other",' + raw[1:]
    path = tmp_path / "capture.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        run_cli(path, monkeypatch)
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert not out.out
    assert "invalid endpoint capture" in out.err
    assert "Traceback" not in out.err


@pytest.mark.parametrize("classification,count,expected_candidates", [
    ("NO_READY_ENDPOINTS_OBSERVED", 0, 3),
    ("READY_ENDPOINTS_OBSERVED", 1, 0),
    ("UNKNOWN", 0, 0),
    ("NO_READY_ENDPOINTS_OBSERVED", 1, 0),
    ("READY_ENDPOINTS_OBSERVED", 0, 0),
])
def test_endpoint_rca_preserves_observation_and_abstains(tmp_path, monkeypatch, capsys, classification, count, expected_candidates):
    data = capture()
    data["report"].update(classification=classification, ready_endpoints=count)
    path = tmp_path / "capture.json"
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path), "--format", "rca-json"])
    main()
    out = capsys.readouterr()
    report = json.loads(out.out)
    assert not out.err
    assert report["schema_version"] == "rca-report/v1"
    assert report["incident"]["severity"] == "unknown"
    assert report["endpoint_observation"]["capture_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["endpoint_observation"]["reported_classification"] == classification
    assert report["endpoint_observation"]["reported_ready_endpoints"] == count
    assert len(report["hypotheses"]) == expected_candidates
    assert all(item["supplied_status"] == "unverified" and item["references_resolved"] for item in report["hypotheses"])
    assert report["timeline"][0]["timestamp"] == data["report"]["observed_at"]
    assert report["timeline"][0]["event_id"] == report["evidence"][0]["evidence_id"]
    assert report["independently_verified"] is False
    assert report["execution_authorized"] is False
    assert "service_before_raw" not in out.out
    assert path.read_bytes() == raw


def test_endpoint_rca_rejects_digest_mismatch(tmp_path, monkeypatch, capsys):
    data = capture()
    data["report"]["endpoint_slices_sha256"] = "0" * 64
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path), "--format", "rca-json"])
    with pytest.raises(SystemExit) as exc:
        main()
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert not out.out
    assert "invalid endpoint capture" in out.err


@pytest.mark.parametrize("classification,count,expected_ids", [
    ("NO_READY_ENDPOINTS_OBSERVED", 0, ["endpoint-replicas", "endpoint-readiness", "endpoint-reconciliation"]),
    ("READY_ENDPOINTS_OBSERVED", 1, []),
    ("UNKNOWN", 0, []),
    ("NO_READY_ENDPOINTS_OBSERVED", 1, []),
    ("READY_ENDPOINTS_OBSERVED", 0, []),
])
def test_endpoint_rca_requests_evidence_without_authorizing_collection(tmp_path, monkeypatch, capsys, classification, count, expected_ids):
    data = capture()
    data["report"].update(classification=classification, ready_endpoints=count)
    path = tmp_path / "capture.json"
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path), "--format", "rca-json"])
    main()
    report = json.loads(capsys.readouterr().out)
    plan = report["investigation_plan"]
    assert plan["schema_version"] == "endpoint-investigation-plan/v1"
    assert plan["capture_sha256"] == hashlib.sha256(raw).hexdigest()
    assert plan["reported_target"] == data["report"]["target"]
    assert plan["target_verified"] is False
    assert plan["collection_authorized"] is False
    assert plan["execution_authorized"] is False
    assert [item["hypothesis_id"] for item in plan["checks"]] == expected_ids
    assert [item["hypothesis_id"] for item in report["hypotheses"]] == expected_ids
    for check in plan["checks"]:
        assert check["status"] == "pending_evidence"
        assert check["read_only"] is True
        assert check["evidence_ids"] == [report["evidence"][0]["evidence_id"]]
        assert check["required_evidence"]
        assert check["verification_question"]
        assert not ({"command", "url", "arguments", "tool_call"} & check.keys())
    assert path.read_bytes() == raw


def test_endpoint_plan_distinguishes_required_evidence_for_each_candidate(tmp_path, monkeypatch, capsys):
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture()), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path), "--format", "rca-json"])
    main()
    checks = json.loads(capsys.readouterr().out)["investigation_plan"]["checks"]
    assert [item["required_evidence"] for item in checks] == [
        ["workload_owner_identity", "desired_and_available_replicas", "pod_phase_and_scheduling"],
        ["pod_readiness_conditions", "container_status", "readiness_probe_configuration"],
        ["service_selector", "pod_labels_and_identity", "endpointslice_owner_and_readiness"],
    ]


@pytest.mark.parametrize("fault", [None, "uid", "name", "namespace", "duplicate", "missing", "summary_mode"])
def test_endpoint_rca_topology_snapshot_binding(tmp_path, monkeypatch, capsys, fault):
    from test_offline_topology import snapshot

    data = capture()
    path = tmp_path / "capture.json"
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    graph = snapshot()
    root = graph["service"]["metadata"]
    root.update(data["report"]["target"])
    if fault in ("uid", "name", "namespace"):
        root[fault] = "different"
    topology = tmp_path / "topology.json"
    graph_raw = json.dumps(graph).encode()
    if fault == "duplicate":
        graph_raw = b'{"service":{},' + graph_raw[1:]
    if fault != "missing":
        topology.write_bytes(graph_raw)
    argv = ["agentic-aiops", "render-endpoint-capture", str(path), "--topology-snapshot", str(topology)]
    if fault != "summary_mode":
        argv.extend(["--format", "rca-json"])
    monkeypatch.setattr("sys.argv", argv)
    if fault is not None:
        with pytest.raises(SystemExit) as exc:
            main()
        out = capsys.readouterr()
        assert exc.value.code == 2
        assert not out.out
        assert ("requires --format rca-json" if fault == "summary_mode" else "invalid or mismatched topology snapshot") in out.err
        assert "Traceback" not in out.err
        return
    main()
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert not out.err
    context = result["topology_context"]
    assert context["capture_sha256"] == hashlib.sha256(raw).hexdigest()
    assert context["snapshot"]["snapshot_sha256"] == hashlib.sha256(graph_raw).hexdigest()
    assert context["reported_service_identity_matches"] is True
    assert len(context["snapshot"]["edges"]) == 3
    assert context["independently_verified"] is False
    assert context["collection_authorized"] is False
    assert context["execution_authorized"] is False
    assert result["investigation_plan"]["target_verified"] is False
    assert all(h["supplied_status"] == "unverified" for h in result["hypotheses"])
    assert path.read_bytes() == raw
    assert topology.read_bytes() == graph_raw


def _coverage_report(tmp_path, monkeypatch, capsys, graph, classification="NO_READY_ENDPOINTS_OBSERVED", count=0):
    data = capture()
    data["report"].update(classification=classification, ready_endpoints=count)
    graph["service"]["metadata"].update(data["report"]["target"])
    path = tmp_path / "capture.json"
    topology = tmp_path / "topology.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    topology.write_text(json.dumps(graph), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-endpoint-capture", str(path), "--format", "rca-json", "--topology-snapshot", str(topology)])
    main()
    return json.loads(capsys.readouterr().out)


def _coverage(report):
    checks = report["investigation_plan"]["checks"]
    result = {}
    for check in checks:
        assert check["status"] == "pending_evidence"
        entries = check["evidence_coverage"]
        assert [entry["requirement"] for entry in entries] == check["required_evidence"]
        for entry in entries:
            assert entry["status"] in ("provided", "partial", "missing")
            assert bool(entry["report_refs"]) == (entry["status"] != "missing")
            for ref in entry["report_refs"]:
                target = report
                for part in ref[1:].split("/"):
                    target = target[int(part)] if isinstance(target, list) else target[part]
            result[entry["requirement"]] = entry["status"]
    assert report["independently_verified"] is False
    assert report["investigation_plan"]["target_verified"] is False
    assert report["investigation_plan"]["collection_authorized"] is False
    assert all(h["supplied_status"] == "unverified" for h in report["hypotheses"])
    return result


def test_topology_evidence_coverage_preserves_explicit_zero_and_false(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    graph = snapshot()
    dep = graph["deployments"]["items"][0]
    dep["metadata"]["generation"] = 2
    dep["spec"] = {"replicas": 2}
    dep["status"] = {"observedGeneration": 2, "availableReplicas": 0}
    pod = graph["pods"]["items"][0]
    pod["status"] = {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}, {"type": "PodScheduled", "status": "True"}], "containerStatuses": [{"name": "app", "ready": False, "restartCount": 0, "state": {"running": {}}}]}
    pod["spec"] = {"containers": [{"name": "app", "readinessProbe": {}}]}
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    assert _coverage(report) == {
        "workload_owner_identity": "provided", "desired_and_available_replicas": "provided", "pod_phase_and_scheduling": "provided",
        "pod_readiness_conditions": "provided", "container_status": "provided", "readiness_probe_configuration": "partial",
        "service_selector": "partial", "pod_labels_and_identity": "partial", "endpointslice_owner_and_readiness": "partial",
    }


def test_topology_evidence_coverage_missing_fields(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    coverage = _coverage(_coverage_report(tmp_path, monkeypatch, capsys, snapshot()))
    assert coverage["desired_and_available_replicas"] == "missing"
    assert coverage["pod_phase_and_scheduling"] == "missing"
    assert coverage["pod_readiness_conditions"] == "missing"
    assert coverage["container_status"] == "missing"
    assert coverage["readiness_probe_configuration"] == "missing"


@pytest.mark.parametrize("generation,observed", [(2, 1), (2, None)])
def test_stale_or_unknown_generation_is_partial(tmp_path, monkeypatch, capsys, generation, observed):
    from test_offline_topology import snapshot
    graph = snapshot()
    dep = graph["deployments"]["items"][0]
    dep["metadata"]["generation"] = generation
    dep["spec"] = {"replicas": 2}
    dep["status"] = {"availableReplicas": 0}
    if observed is not None:
        dep["status"]["observedGeneration"] = observed
    assert _coverage(_coverage_report(tmp_path, monkeypatch, capsys, graph))["desired_and_available_replicas"] == "partial"


def test_zero_pod_candidate_is_partial_not_resolved_owner(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    graph = snapshot()
    graph["pods"]["items"] = []
    dep = graph["deployments"]["items"][0]
    dep["spec"] = {"replicas": 0, "template": {"metadata": {"labels": {"app": "checkout"}}}}
    dep["status"] = {"availableReplicas": 0}
    coverage = _coverage(_coverage_report(tmp_path, monkeypatch, capsys, graph))
    assert coverage["workload_owner_identity"] == "partial"
    assert coverage["desired_and_available_replicas"] == "partial"
    assert coverage["pod_readiness_conditions"] == "missing"


def test_topology_coverage_does_not_create_checks_for_abstained_report(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    report = _coverage_report(tmp_path, monkeypatch, capsys, snapshot(), "UNKNOWN", 0)
    assert report["investigation_plan"]["checks"] == []


@pytest.mark.parametrize("desired,available,generation,observed,ready,expected", [
    (3, 1, 2, 2, 1, "availability_shortfall"),
    (3, 3, 2, 2, 3, "desired_availability_met"),
    (3, 4, 2, 2, 4, "desired_availability_met"),
    (0, 0, 2, 2, 0, "zero_desired_and_available"),
    (0, 1, 2, 2, 1, "zero_desired_with_available"),
    (3, 0, 2, 1, 0, "unknown_generation"),
    (3, 0, 2, 3, 0, "unknown_generation"),
    (3, 0, 2, None, 0, "unknown_generation"),
    (3, None, 2, 2, 0, "missing_counts"),
    (3, 2, 2, 2, 1, "inconsistent_counts"),
])
def test_replica_assessment_is_snapshot_local(tmp_path, monkeypatch, capsys, desired, available, generation, observed, ready, expected):
    from test_offline_topology import snapshot
    graph = snapshot()
    dep = graph["deployments"]["items"][0]
    dep["metadata"]["generation"] = generation
    dep["spec"] = {"replicas": desired}
    dep["status"] = {"readyReplicas": ready}
    if available is not None:
        dep["status"]["availableReplicas"] = available
    if observed is not None:
        dep["status"]["observedGeneration"] = observed
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    assessment = report["topology_context"]["replica_assessment"]
    assert assessment["schema_version"] == "offline-replica-assessment/v1"
    assert assessment["independently_verified"] is False
    assert assessment["root_cause_verified"] is False
    assert assessment["execution_authorized"] is False
    item, = assessment["observations"]
    assert item == {"entity_id": "dep", "association": "owner_chain", "status": expected,
                    "report_ref": "/topology_context/snapshot/deployment_observations/0"}
    _coverage(report)


def test_replica_assessment_retains_unresolved_candidates(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    graph = snapshot()
    graph["pods"]["items"] = []
    dep = graph["deployments"]["items"][0]
    dep["metadata"]["generation"] = 2
    dep["spec"] = {"replicas": 0, "template": {"metadata": {"labels": {"app": "checkout"}}}}
    dep["status"] = {"observedGeneration": 2, "availableReplicas": 0}
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    item, = report["topology_context"]["replica_assessment"]["observations"]
    assert item == {"entity_id": "dep", "association": "template_candidate", "status": "zero_desired_and_available",
                    "report_ref": "/topology_context/snapshot/deployment_candidates/0/observation"}
    assert _coverage(report)["workload_owner_identity"] == "partial"


def test_replica_assessment_does_not_invent_unresolved_workload(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    graph = snapshot()
    graph["pods"]["items"] = []
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    assert report["topology_context"]["replica_assessment"]["observations"] == []
    assert _coverage(report)["desired_and_available_replicas"] == "missing"


@pytest.mark.parametrize("condition,phase,scheduled,container_ready,state,expected", [
    ("True", "Running", "True", True, "running", "reported_ready"),
    ("False", "Running", "True", False, "waiting", "reported_not_ready"),
    ("False", "Running", "True", True, "running", "reported_not_ready"),
    ("Unknown", "Running", "True", False, "waiting", "unknown_readiness"),
    (None, "Running", "True", True, "running", "unknown_readiness"),
    ("True", "Running", "True", False, "running", "inconsistent_status"),
    ("True", "Failed", "True", True, "running", "inconsistent_status"),
    ("True", "Running", "False", True, "running", "inconsistent_status"),
    ("False", "Running", "True", True, "terminated", "inconsistent_status"),
])
def test_readiness_assessment_distinguishes_reported_conditions(tmp_path, monkeypatch, capsys, condition, phase, scheduled, container_ready, state, expected):
    from test_offline_topology import snapshot
    graph = snapshot()
    pod = graph["pods"]["items"][0]
    conditions = [{"type": "PodScheduled", "status": scheduled}]
    if condition is not None:
        conditions.append({"type": "Ready", "status": condition})
    pod["status"] = {"phase": phase, "conditions": conditions, "containerStatuses": [
        {"name": "app", "ready": container_ready, "restartCount": 0, "state": {state: {}}},
    ]}
    pod["spec"] = {"containers": [{"name": "app"}]}
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    assessment = report["topology_context"]["readiness_assessment"]
    assert assessment["schema_version"] == "offline-readiness-assessment/v1"
    assert assessment["independently_verified"] is assessment["root_cause_verified"] is assessment["execution_authorized"] is False
    item, = assessment["observations"]
    assert item == {"entity_id": "pod", "status": expected,
                    "container_detail": "provided", "reported_unready_containers": [] if container_ready else ["app"],
                    "report_ref": "/topology_context/snapshot/pod_observations/0"}
    _coverage(report)


@pytest.mark.parametrize("statuses,expected", [(None, "missing"), ([], "partial"), ([{"name": "app", "ready": True}], "partial"), ([{"name": "other", "ready": True, "restartCount": 0, "state": {"running": {}}}], "partial")])
def test_readiness_assessment_preserves_incomplete_container_detail(tmp_path, monkeypatch, capsys, statuses, expected):
    from test_offline_topology import snapshot
    graph = snapshot()
    pod = graph["pods"]["items"][0]
    pod["spec"] = {"containers": [{"name": "app"}]}
    pod["status"] = {"conditions": [{"type": "Ready", "status": "True"}]}
    if statuses is not None:
        pod["status"]["containerStatuses"] = statuses
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    item, = report["topology_context"]["readiness_assessment"]["observations"]
    assert item["status"] == "reported_ready"
    assert item["container_detail"] == expected


def test_readiness_assessment_abstains_without_matching_pods(tmp_path, monkeypatch, capsys):
    from test_offline_topology import snapshot
    graph = snapshot()
    graph["pods"]["items"] = []
    report = _coverage_report(tmp_path, monkeypatch, capsys, graph)
    assert report["topology_context"]["readiness_assessment"]["observations"] == []
    assert _coverage(report)["pod_readiness_conditions"] == "missing"


@pytest.mark.parametrize("fault", ["uid", "namespace", "name", "service_kind", "metadata", "service_json", "duplicate_service_key", "slice_kind", "slice_items", "duplicate_slice_key"])
def test_capture_rejects_rehashed_inconsistent_source_identity(tmp_path, monkeypatch, capsys, fault):
    data = capture()
    service = json.loads(base64.b64decode(data["service_before_raw"]))
    slices = json.loads(base64.b64decode(data["endpoint_slices_raw"]))
    if fault in ("uid", "namespace", "name"):
        service["metadata"][fault] = "different"
    elif fault == "service_kind":
        service["kind"] = "Pod"
    elif fault == "metadata":
        service["metadata"] = []
    elif fault == "slice_kind":
        slices["kind"] = "PodList"
    elif fault == "slice_items":
        slices["items"] = {}
    service_raw = json.dumps(service).encode()
    slice_raw = json.dumps(slices).encode()
    if fault == "service_json":
        service_raw = b"not json"
    elif fault == "duplicate_service_key":
        service_raw = b'{"kind":"Pod",' + service_raw[1:]
    elif fault == "duplicate_slice_key":
        slice_raw = b'{"items":{},' + slice_raw[1:]
    for field, raw in (("service_before", service_raw), ("service_after", service_raw), ("endpoint_slices", slice_raw)):
        data[field + "_raw"] = base64.b64encode(raw).decode("ascii")
        data["report"][field + "_sha256"] = hashlib.sha256(raw).hexdigest()
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        run_cli(path, monkeypatch)
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert not out.out
    assert "invalid endpoint capture" in out.err


def test_capture_reports_source_identity_agreement_not_authentication(tmp_path, monkeypatch, capsys):
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture()), encoding="utf-8")
    run_cli(path, monkeypatch)
    result = json.loads(capsys.readouterr().out)
    assert result["source_service_identity_matches_report"] is True
    assert result["source_authenticated"] is False
    assert result["independently_verified"] is False
