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
