"""Synthetic offline contracts only, never real inference measurements."""
import hashlib
import json
import os

import pytest

from agentic_aiops.model_holdout import compare_model_holdout


def write(path, rows):
    raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def artifacts(tmp_path):
    dataset = tmp_path / "dataset.jsonl"
    episodes = []
    for eid, family, answerable in (("a", "oom", True), ("b", "unclear", False)):
        episodes.append({
            "schema_version": "sre.grpo.episode/v1", "episode_id": eid,
            "fault_family": family, "split": "test", "alert": family,
            "observations": [{"evidence_id": "ev1", "tool": "prometheus.query",
                              "text": family}],
            "oracle": {"answerable": answerable,
                       "root_cause_id": family if answerable else "unknown",
                       "required_evidence_ids": ["ev1"] if answerable else []},
        })
    ds_pin = write(dataset, episodes)
    good = json.dumps({"root_cause_id": "oom", "evidence_ids": ["ev1"],
                       "stop_reason": "verified"})
    abstain = json.dumps({"root_cause_id": "unknown", "evidence_ids": [],
                          "stop_reason": "insufficient_evidence"})
    files, pins = {}, {}
    for label, answers in (("inkling", [good, abstain]),
                           ("qwen", [good, "{}"]), ("cloud", ["{}", abstain])):
        files[label] = tmp_path / (label + ".jsonl")
        pins[label] = write(files[label], [
            {"episode_id": eid, "completion": answer}
            for eid, answer in zip(("a", "b"), answers)
        ])
    return dataset, ds_pin, files, pins


def compare(artifacts, split="test"):
    dataset, ds_pin, files, pins = artifacts
    return compare_model_holdout(dataset, expected_dataset_sha256=ds_pin,
                                 prediction_files=files,
                                 expected_prediction_sha256=pins, split=split)


def test_complete_triple_is_descriptive_only(artifacts):
    report = compare(artifacts)
    assert report["cases"] == 2
    assert report["models"]["inkling"]["exact_success_rate"] == 1.0
    assert report["models"]["qwen"]["correct_abstention_rate"] == 0.0
    assert report["paired"]["inkling_vs_cloud"]["win"] == 1
    assert report["paired"]["qwen_vs_cloud"]["loss"] == 1
    assert report["admission"] == "HOLD"
    for key in ("model_runtime_verified", "model_attribution_verified",
                "data_issuer_authenticated", "superiority_claim_authorized",
                "training_admission_authorized", "production_eligible",
                "routing_authorized"):
        assert report[key] is False


@pytest.mark.parametrize("failure", ["missing_label", "bad_pin", "missing_case",
                                     "extra_case", "duplicate", "hardlink",
                                     "symlink", "parent-symlink", "fifo", "empty"])
def test_invalid_third_arm_holds(artifacts, failure):
    dataset, ds_pin, files, pins = artifacts
    path = files["qwen"]
    if failure == "missing_label":
        del files["qwen"]
    elif failure == "bad_pin":
        pins["qwen"] = "0" * 64
    elif failure == "parent-symlink":
        real_parent = path.parent / "real-qwen"
        real_parent.mkdir()
        real_path = real_parent / path.name
        path.replace(real_path)
        alias_parent = path.parent / "alias-qwen"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        files["qwen"] = alias_parent / path.name
    elif failure in ("hardlink", "symlink", "fifo"):
        path.unlink()
        if failure == "hardlink":
            os.link(files["cloud"], path)
        elif failure == "symlink":
            path.symlink_to(files["cloud"])
        else:
            os.mkfifo(path)
        pins["qwen"] = pins["cloud"]
    else:
        ids = {"missing_case": ["a"], "extra_case": ["a", "b", "extra"],
               "duplicate": ["a", "a", "b"], "empty": []}[failure]
        pins["qwen"] = write(path, [
            {"episode_id": eid, "completion": "{}"} for eid in ids
        ])
    with pytest.raises((ValueError, OSError)):
        compare((dataset, ds_pin, files, pins))


def test_training_split_is_not_holdout(artifacts):
    with pytest.raises(ValueError):
        compare(artifacts, split="train")


def test_same_content_distinct_files_is_not_attribution(artifacts):
    dataset, ds_pin, files, pins = artifacts
    files["qwen"].write_bytes(files["inkling"].read_bytes())
    pins["qwen"] = pins["inkling"]
    report = compare((dataset, ds_pin, files, pins))
    assert report["paired"]["inkling_vs_qwen"]["tie_both_correct"] == 2
    assert report["model_attribution_verified"] is False
    assert report["admission"] == "HOLD"


def test_cli_complete_or_invalid_inputs(artifacts):
    import subprocess
    import sys
    from pathlib import Path

    dataset, ds_pin, files, pins = artifacts
    script = Path(__file__).resolve().parents[1] / "scripts/compare_sre_model_holdout.py"
    command = [sys.executable, str(script), "--dataset", str(dataset),
               "--dataset-sha256", ds_pin]
    for label in ("inkling", "qwen", "cloud"):
        command.extend(["--" + label, str(files[label]),
                        "--" + label + "-sha256", pins[label]])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["admission"] == "HOLD"

    command[command.index("--qwen-sha256") + 1] = "0" * 64
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 3
    assert not result.stdout.strip()
    assert "HOLD" in result.stderr
