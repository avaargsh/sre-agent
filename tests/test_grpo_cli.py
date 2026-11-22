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
        "train_sre_grpo.py", "--execute", "--dataset", DATASET,
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
