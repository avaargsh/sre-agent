"""Exercise the lab evidence inventory against real files and CLI processes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/incident_manifest.py"
COMMON = [f"{phase}-{suffix}" for phase in ("before", "during", "after")
          for suffix in ("service.json", "endpointslices.json", "probes.txt")] + [
    "observer-capture.json", "observer-capture.sha256", "observer-replay.json",
    "observed-service.json", "observed-endpointslices.json", "observed-service-after.json",
    "observer-report.json", "episode.json", "prediction.json", "evaluation.json",
]
FAULT = ["zero-pods.json", "convergence-probes.txt"] + [
    f"forged-{variant}{suffix}" for variant in ("count", "recovery", "digest")
    for suffix in (".json", "-log.txt")
]


@pytest.fixture
def root(tmp_path):
    for scenario, names in (("control", COMMON), ("no-ready", COMMON + FAULT)):
        directory = tmp_path / scenario
        directory.mkdir()
        for name in names:
            (directory / name).write_bytes(f"{scenario}/{name}\n".encode())
    return tmp_path


def invoke(root, mode="build"):
    return subprocess.run([sys.executable, "-O", str(SCRIPT), mode, str(root)],
                          capture_output=True, timeout=5)


def test_inventory_is_deterministic_and_binds_every_required_file(root):
    first = invoke(root)
    assert first.returncode == 0, first.stderr
    assert first.stdout == invoke(root).stdout
    manifest = json.loads(first.stdout)
    assert manifest["schema_version"] == "sre.endpoint-lab-manifest/v1"
    assert manifest["source_authenticated"] is manifest["causality_verified"] is manifest["execution_authorized"] is False
    paths = sorted(str(p.relative_to(root)) for p in root.glob("*/*"))
    assert [entry["path"] for entry in manifest["artifacts"]] == paths
    for entry in manifest["artifacts"]:
        raw = (root / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
        assert entry["size_bytes"] == len(raw)
    (root / "incident-manifest.json").write_bytes(first.stdout)
    assert invoke(root, "verify").returncode == 0
    (root / "no-ready/after-probes.txt").write_bytes(b"changed")
    result = invoke(root, "verify")
    assert result.returncode == 3 and not result.stdout


@pytest.mark.parametrize("fault", ["missing", "empty", "oversized", "symlink", "fifo", "directory", "scenario_symlink"])
def test_invalid_evidence_fails_closed(root, fault):
    target = root / "control/observer-capture.json"
    if fault == "scenario_symlink":
        (root / "control").rename(root / "real-control")
        (root / "control").symlink_to(root / "real-control", target_is_directory=True)
    else:
        target.unlink()
        if fault == "empty":
            target.touch()
        elif fault == "oversized":
            with target.open("wb") as stream:
                stream.truncate((16 << 20) + 1)
        elif fault == "symlink":
            target.symlink_to(root / "no-ready/observer-capture.json")
        elif fault == "fifo":
            os.mkfifo(target)
        elif fault == "directory":
            target.mkdir()
    result = invoke(root)
    assert result.returncode == 3 and not result.stdout
    assert result.stderr.startswith(b"UNKNOWN:")


def test_verification_rejects_forged_manifest(root):
    result = invoke(root)
    assert result.returncode == 0
    manifest = json.loads(result.stdout)
    manifest["execution_authorized"] = True
    (root / "incident-manifest.json").write_text(json.dumps(manifest))
    rejected = invoke(root, "verify")
    assert rejected.returncode == 3 and not rejected.stdout


def test_inventory_rejects_unlisted_artifacts(root):
    (root / "control/unexpected-debug.log").write_text("not in the frozen evidence contract")
    result = invoke(root)
    assert result.returncode == 3 and not result.stdout
    assert result.stderr.startswith(b"UNKNOWN:")
