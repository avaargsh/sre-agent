"""CPU-only paired scoring CLI contracts; fixtures are synthetic, not benchmarks."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare_sre_shadow_holdout.py"


def write(path, rows):
    raw = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def inputs(tmp_path):
    dataset = tmp_path / "episodes.jsonl"
    inkling = tmp_path / "inkling.jsonl"
    cloud = tmp_path / "cloud.jsonl"
    ds_pin = write(dataset, [{
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": "unknown-case", "fault_family": "synthetic-unresolved",
        "split": "test", "alert": "Unresolved synthetic alert",
        "observations": [{"evidence_id": "ev1", "tool": "prometheus.query",
                          "text": "Insufficient observation"}],
        "oracle": {"answerable": False, "root_cause_id": "unknown",
                   "required_evidence_ids": []},
    }])
    good = json.dumps({"root_cause_id": "unknown", "evidence_ids": [],
                       "stop_reason": "insufficient_evidence"})
    i_pin = write(inkling, [{"episode_id": "unknown-case", "completion": good}])
    c_pin = write(cloud, [{"episode_id": "unknown-case", "completion": "not JSON"}])
    return dataset, inkling, cloud, ds_pin, i_pin, c_pin


def run(dataset, inkling, cloud, ds_pin, i_pin, c_pin):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--dataset", str(dataset),
         "--dataset-sha256", ds_pin, "--inkling", str(inkling),
         "--inkling-sha256", i_pin, "--cloud", str(cloud),
         "--cloud-sha256", c_pin],
        capture_output=True, text=True, check=False, timeout=30,
    )


def test_complete_pair_is_descriptive_and_never_promotes(tmp_path):
    result = run(*inputs(tmp_path))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["inkling"]["exact_success_rate"] == 1.0
    assert report["cloud"]["exact_success_rate"] == 0.0
    assert report["paired"]["win"] == 1
    assert report["admission"] == "HOLD"
    for key in ("model_attribution_verified", "superiority_claim_authorized",
                "production_eligible"):
        assert report[key] is False


@pytest.mark.parametrize("failure", [
    "pin", "missing", "hardlink", "symlink", "parent-symlink", "fifo",
])
def test_invalid_pair_fails_without_report(tmp_path, failure):
    dataset, inkling, cloud, ds_pin, i_pin, c_pin = inputs(tmp_path)
    if failure == "pin":
        c_pin = "0" * 64
    elif failure == "missing":
        c_pin = write(cloud, [{"episode_id": "wrong-case", "completion": "{}"}])
    elif failure == "parent-symlink":
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        real_cloud = real_parent / "cloud.jsonl"
        cloud.replace(real_cloud)
        alias_parent = tmp_path / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        cloud = alias_parent / "cloud.jsonl"
    else:
        cloud.unlink()
        if failure == "hardlink":
            os.link(inkling, cloud)
        elif failure == "symlink":
            cloud.symlink_to(inkling)
        else:
            os.mkfifo(cloud)
        c_pin = i_pin
    result = run(dataset, inkling, cloud, ds_pin, i_pin, c_pin)
    assert result.returncode == 3, result.stderr
    assert not result.stdout.strip()
    assert "HOLD" in result.stderr


def test_stale_symlink_lstat_cannot_admit_comparator(tmp_path, monkeypatch, capsys):
    # Source content remains SHA-pinned, but the path must not be followed
    # after a stale preflight pathname check. Run actual CLI main in-process
    # to emulate a source swapping to a symlink before its subsequent open.
    import importlib.util

    dataset, inkling, cloud, ds_pin, i_pin, c_pin = inputs(tmp_path)
    alternate = tmp_path / "swapped-model-output.jsonl"
    alternate.write_bytes(cloud.read_bytes())
    cloud.unlink()
    cloud.symlink_to(alternate)
    original = Path.is_symlink

    def stale_check(path):
        return False if path == cloud else original(path)

    spec = importlib.util.spec_from_file_location("shadow_compare_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(Path, "is_symlink", stale_check)
    monkeypatch.setattr(sys, "argv", [
        str(SCRIPT), "--dataset", str(dataset),
        "--dataset-sha256", ds_pin, "--inkling", str(inkling),
        "--inkling-sha256", i_pin, "--cloud", str(cloud),
        "--cloud-sha256", c_pin,
    ])
    assert module.main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "HOLD" in captured.err
