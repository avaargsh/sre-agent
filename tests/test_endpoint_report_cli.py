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
