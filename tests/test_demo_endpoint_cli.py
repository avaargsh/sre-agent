import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" if (ROOT / "src").exists() else ROOT


def run_demo(tmp_path, *args):
    env = dict(os.environ, PYTHONPATH=str(SOURCE))
    return subprocess.run(
        [sys.executable, "-m", "agentic_aiops.cli", "demo-endpoint", *args],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15,
    )


@pytest.mark.parametrize("case,association,replica,readiness", [
    ("scale-zero", "template_candidate", "zero_desired_and_available", None),
    ("readiness", "owner_chain", "availability_shortfall", "reported_not_ready"),
])
def test_demo_exercises_real_offline_cli(tmp_path, case, association, replica, readiness):
    proc = run_demo(tmp_path, "--case", case)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr
    demo = json.loads(proc.stdout)
    assert demo["schema_version"] == "endpoint-offline-demo/v1"
    assert demo["synthetic"] is True
    assert demo["case"] == case
    report = demo["report"]
    assert report["schema_version"] == "rca-report/v1"
    assert report["endpoint_observation"]["reported_ready_endpoints"] == 0
    assert report["endpoint_observation"]["source_authenticated"] is False
    assert report["independently_verified"] is report["execution_authorized"] is False
    assert report["topology_context"]["reported_service_identity_matches"] is True
    assert len(report["hypotheses"]) == len(report["investigation_plan"]["checks"]) == 3
    assert all(h["supplied_status"] == "unverified" for h in report["hypotheses"])
    assert all(c["status"] == "pending_evidence" for c in report["investigation_plan"]["checks"])
    observed, = report["topology_context"]["replica_assessment"]["observations"]
    assert (observed["association"], observed["status"]) == (association, replica)
    pods = report["topology_context"]["readiness_assessment"]["observations"]
    assert [p["status"] for p in pods] == ([] if readiness is None else [readiness])
    assert not list(tmp_path.iterdir())


def test_demo_default_is_deterministic(tmp_path):
    one = run_demo(tmp_path)
    two = run_demo(tmp_path, "--case", "scale-zero")
    assert one.returncode == two.returncode == 0
    assert one.stdout == two.stdout


def test_unknown_demo_case_fails_without_report(tmp_path):
    proc = run_demo(tmp_path, "--case", "unknown")
    assert proc.returncode == 2
    assert not proc.stdout
    assert "invalid choice" in proc.stderr


@pytest.mark.parametrize("case", ["scale-zero", "readiness"])
def test_exported_fixture_round_trips_and_contains_native_replay_metadata(tmp_path, case):
    import base64
    import hashlib

    proc = run_demo(tmp_path, "--case", case, "--format", "fixture")
    assert proc.returncode == 0, proc.stderr
    fixture = json.loads(proc.stdout)
    assert fixture["schema_version"] == "endpoint-offline-fixture/v1"
    assert fixture["synthetic"] is True
    assert fixture["case"] == case
    capture, topology = fixture["capture"], fixture["topology"]
    report = capture["report"]
    assert report["expected_target_port"] == 8080
    assert report["expected_selector"] == {"app": "checkout"}
    assert report["service_resource_version"] == "19"
    assert report["endpoint_slice_list_resource_version"] == "25"
    assert report["source_authenticated"] is False
    timeline = report["read_timeline"]
    assert [r["name"] for r in timeline] == ["service_get_before", "endpoint_slice_list", "service_get_after"]
    assert [r["response_resource_version"] for r in timeline] == ["19", "25", "19"]
    for read, field in zip(timeline, ("service_before", "endpoint_slices", "service_after")):
        raw = base64.b64decode(capture[field + "_raw"], validate=True)
        assert hashlib.sha256(raw).hexdigest() == read["response_sha256"] == report[field + "_sha256"]
        assert report["collection_started_at"] <= read["started_at"] <= read["completed_at"] <= report["observed_at"]
    assert all(a["completed_at"] <= b["started_at"] for a, b in zip(timeline, timeline[1:]))
    assert timeline[1]["request_consistency"] == "MOST_RECENT"
    assert timeline[1]["request_label_selector"] == "kubernetes.io/service-name=checkout"
    assert timeline[1]["request_limit"] == 129
    assert "request_resource_version" not in timeline[1]
    assert "request_resource_version_match" not in timeline[1]
    assert not list(tmp_path.iterdir())
    capture_path = tmp_path / "capture.json"
    topology_path = tmp_path / "topology.json"
    for path, value in ((capture_path, capture), (topology_path, topology)):
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    rendered = subprocess.run([sys.executable, "-m", "agentic_aiops.cli", "render-endpoint-capture",
                               str(capture_path), "--format", "rca-json", "--topology-snapshot", str(topology_path)],
                              cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(SOURCE)),
                              capture_output=True, text=True, timeout=15)
    assert rendered.returncode == 0, rendered.stderr
    assert json.loads(rendered.stdout) == json.loads(run_demo(tmp_path, "--case", case).stdout)["report"]


def test_unknown_demo_format_rejected(tmp_path):
    proc = run_demo(tmp_path, "--format", "unknown")
    assert proc.returncode == 2
    assert not proc.stdout
    assert "invalid choice" in proc.stderr
