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


def run_fixture(tmp_path, path):
    return subprocess.run(
        [sys.executable, "-m", "agentic_aiops.cli", "render-endpoint-fixture", str(path)],
        cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(SOURCE)),
        capture_output=True, text=True, timeout=15,
    )


@pytest.mark.parametrize("case", ["scale-zero", "readiness"])
def test_render_fixture_preserves_synthetic_wrapper_and_input_digest(tmp_path, case):
    import hashlib

    raw = run_demo(tmp_path, "--case", case, "--format", "fixture").stdout.encode()
    path = tmp_path / "fixture.json"
    path.write_bytes(raw)
    result = run_fixture(tmp_path, path)
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    replayed = json.loads(result.stdout)
    assert replayed.pop("fixture_sha256") == hashlib.sha256(raw).hexdigest()
    assert replayed == json.loads(run_demo(tmp_path, "--case", case).stdout)
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("fault", ["wrong_schema", "not_synthetic", "bad_case", "extra_field", "bad_capture", "bad_topology", "digest", "target", "duplicate", "nan"])
def test_render_fixture_rejects_invalid_input_without_report(tmp_path, fault):
    fixture = json.loads(run_demo(tmp_path, "--format", "fixture").stdout)
    if fault == "wrong_schema":
        fixture["schema_version"] = "unknown"
    elif fault == "not_synthetic":
        fixture["synthetic"] = 1
    elif fault == "bad_case":
        fixture["case"] = "unknown"
    elif fault == "extra_field":
        fixture["extra"] = True
    elif fault == "bad_capture":
        fixture["capture"] = []
    elif fault == "bad_topology":
        fixture["topology"] = []
    elif fault == "digest":
        fixture["capture"]["report"]["service_before_sha256"] = "0" * 64
    elif fault == "target":
        fixture["topology"]["service"]["metadata"]["uid"] = "other"
    elif fault == "nan":
        fixture["topology"]["service"]["metadata"]["extra"] = float("nan")
    raw = json.dumps(fixture)
    if fault == "duplicate":
        raw = '{"synthetic":false,' + raw[1:]
    path = tmp_path / "fixture.json"
    path.write_text(raw, encoding="utf-8")
    proc = run_fixture(tmp_path, path)
    assert proc.returncode == 2
    assert not proc.stdout
    assert "invalid synthetic Endpoint fixture" in proc.stderr


def test_render_fixture_rejects_oversized_file(tmp_path):
    path = tmp_path / "fixture.json"
    with path.open("wb") as stream:
        stream.truncate(20 * 1024 * 1024 + 1)
    proc = run_fixture(tmp_path, path)
    assert proc.returncode == 2
    assert not proc.stdout
    assert "invalid synthetic Endpoint fixture" in proc.stderr


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"),
                    reason="requires safe POSIX file-open flags")
@pytest.mark.parametrize("kind", ["symlink", "fifo"])
@pytest.mark.parametrize("entrypoint", ["fixture", "capture", "topology"])
def test_offline_endpoint_entrypoints_reject_special_files(tmp_path, kind, entrypoint):
    raw = run_demo(tmp_path, "--format", "fixture")
    assert raw.returncode == 0, raw.stderr
    fixture = json.loads(raw.stdout)
    path = tmp_path / "input.json"
    source = tmp_path / "source.json"
    value = fixture if entrypoint == "fixture" else fixture[entrypoint]
    source.write_text(json.dumps(value), encoding="utf-8")
    if kind == "symlink":
        path.symlink_to(source)
    else:
        os.mkfifo(path)
    if entrypoint == "fixture":
        args = ["render-endpoint-fixture", str(path)]
    elif entrypoint == "capture":
        args = ["render-endpoint-capture", str(path)]
    else:
        capture = tmp_path / "capture.json"
        capture.write_text(json.dumps(fixture["capture"]), encoding="utf-8")
        args = ["render-endpoint-capture", str(capture), "--format", "rca-json",
                "--topology-snapshot", str(path)]
    result = subprocess.run([sys.executable, "-m", "agentic_aiops.cli", *args],
                            cwd=tmp_path, env=dict(os.environ, PYTHONPATH=str(SOURCE)),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2, result.stderr
    assert not result.stdout
