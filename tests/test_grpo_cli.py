"""CLI smoke tests require no GPU, TRL, model weights or live cluster."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks/grpo/synthetic-episodes.jsonl"
PREDICTIONS = ROOT / "benchmarks/grpo/synthetic-predictions.jsonl"


def invoke(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )


def test_grpo_inspect_does_not_start_training_or_leak_oracle():
    result = invoke("train_sre_grpo.py", "--dataset", DATASET)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == "inspect"
    assert report["train_rows"] == 1
    assert report["test_rows"] == 1
    assert report["oracle_in_model_prompt"] is False
    assert "oom_killed" not in result.stdout


def test_grpo_execute_has_explicit_preflight_gates(tmp_path):
    no_model = invoke("train_sre_grpo.py", "--execute", "--dataset", DATASET)
    assert no_model.returncode != 0
    assert "--model" in no_model.stderr

    tiny = invoke(
        "train_sre_grpo.py", "--execute", "--lab-only", "--dataset", DATASET,
        "--model", "nonexistent/model", "--output-dir", tmp_path,
    )
    assert tiny.returncode != 0
    assert "at least 8 train episodes" in tiny.stderr
    assert not (tmp_path / "sre-grpo-run-manifest.json").exists()


def test_independent_synthetic_holdout_replay():
    result = invoke(
        "eval_sre_grpo.py", "--dataset", DATASET,
        "--predictions", PREDICTIONS, "--split", "test",
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == "sre.grpo.holdout-eval/v1"
    assert report["metrics"]["cases"] == 1
    assert report["metrics"]["exact_success_rate"] == 1.0
    assert report["model_runtime_verified"] is False
    assert len(report["dataset_sha256"]) == 64
    assert len(report["predictions_sha256"]) == 64


def test_train_execute_never_silently_promotes_to_nonlab(tmp_path):
    result = invoke(
        "train_sre_grpo.py", "--execute", "--allow-tiny-lab",
        "--dataset", DATASET, "--model", "nonexistent/model",
        "--output-dir", tmp_path,
    )
    assert result.returncode != 0
    assert "--lab-only" in result.stderr
    assert not (tmp_path / "sre-grpo-run-manifest.json").exists()


def test_non_tiny_lab_requires_externally_pinned_baseline(tmp_path):
    # More than one train row cannot bypass the baseline/preflight audit;
    # this has to fail before the optional GPU/TRL dependency import.
    rows = []
    for i in range(8):
        rows.append({
            "schema_version": "sre.grpo.episode/v1",
            "episode_id": f"train-{i}",
            "fault_family": f"fault-{i}",
            "split": "train",
            "alert": f"alert {i}",
            "observations": [{
                "evidence_id": "e1", "tool": "prometheus.query",
                "text": f"metric anomaly {i}",
            }],
            "oracle": {
                "answerable": True, "root_cause_id": f"cause_{i}",
                "required_evidence_ids": ["e1"],
            },
        })
    dataset = tmp_path / "eight-episodes.jsonl"
    dataset.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    result = invoke(
        "train_sre_grpo.py", "--execute", "--lab-only",
        "--dataset", dataset, "--model", "nonexistent/model",
        "--output-dir", tmp_path,
    )
    assert result.returncode != 0
    assert "--baseline-rollouts" in result.stderr
    assert not (tmp_path / "sre-grpo-run-manifest.json").exists()

    # This escape hatch is only for truly tiny smoke data, not a way to
    # silently skip a reward-collapse audit on a full-size dataset.
    bypass = invoke(
        "train_sre_grpo.py", "--execute", "--lab-only", "--allow-tiny-lab",
        "--dataset", dataset, "--model", "nonexistent/model",
        "--output-dir", tmp_path,
    )
    assert bypass.returncode != 0
    assert "--allow-tiny-lab" in bypass.stderr
    assert "fewer than 8" in bypass.stderr
    assert not (tmp_path / "sre-grpo-run-manifest.json").exists()


def test_frozen_sha_applies_even_to_inspect_mode():
    result = invoke(
        "train_sre_grpo.py", "--dataset", DATASET,
        "--expected-dataset-sha256", "0" * 64,
    )
    assert result.returncode != 0
    assert "dataset_sha256" in result.stderr


def test_cuda_training_refuses_mutable_model_revision_before_dependencies(tmp_path):
    base = (
        "--execute", "--lab-only", "--allow-tiny-lab", "--dataset", DATASET,
        "--model", "Qwen/Qwen3-0.6B", "--output-dir", tmp_path / "experiment",
    )
    missing = invoke("train_sre_grpo.py", *base)
    assert missing.returncode != 0
    assert "--model-revision" in missing.stderr
    assert not (tmp_path / "experiment").exists()
    mutable = invoke("train_sre_grpo.py", *base, "--model-revision", "main")
    assert mutable.returncode != 0
    assert "40" in mutable.stderr or "revision" in mutable.stderr.lower()
    assert not (tmp_path / "experiment").exists()


def test_lab_training_cannot_use_existing_output_directory(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    (output / "marker").write_text("protected")
    result = invoke(
        "train_sre_grpo.py", "--execute", "--lab-only", "--allow-tiny-lab",
        "--dataset", DATASET, "--model", "Qwen/Qwen3-0.6B",
        "--model-revision", "a" * 40, "--output-dir", output,
    )
    assert result.returncode != 0
    assert "output" in result.stderr.lower() or "exist" in result.stderr.lower()
    assert (output / "marker").read_text() == "protected"
