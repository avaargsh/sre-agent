"""Independent holdout evaluation is not a trainer reward self-report."""

import json

import pytest

from agentic_aiops.grpo_training import load_episodes
from agentic_aiops.grpo_eval import evaluate_holdout, load_predictions


def make_episode(eid, family, split, answerable):
    return {
        "schema_version": "sre.grpo.episode/v1", "episode_id": eid,
        "fault_family": family, "split": split, "alert": f"Synthetic alert {family}",
        "observations": [
            {"evidence_id": "ev1", "tool": "prometheus.query", "text": "error counter rising"}
        ],
        "oracle": {
            "answerable": answerable,
            "root_cause_id": "error_spike" if answerable else "unknown",
            "required_evidence_ids": ["ev1"] if answerable else [],
        },
    }


def fixture(tmp_path):
    path = tmp_path / "holdout.jsonl"
    records = [
        make_episode("train-1", "cpu", "train", True),
        make_episode("test-1", "errors", "test", True),
        make_episode("test-2", "unresolved", "test", False),
    ]
    path.write_text("".join(json.dumps(x) + "\n" for x in records),
                    encoding="utf-8")
    return load_episodes(path)


def completion(cause, refs, stop):
    return json.dumps({
        "root_cause_id": cause, "evidence_ids": refs, "stop_reason": stop
    })


def test_holdout_complete_and_bounded(tmp_path):
    episodes = fixture(tmp_path)
    result = evaluate_holdout(episodes, {
        "test-1": completion("error_spike", ["ev1"], "verified"),
        "test-2": completion("unknown", [], "insufficient_evidence"),
    }, split="test")
    assert result == {
        "split": "test",
        "cases": 2,
        "mean_reward": 1.0,
        "exact_success_rate": 1.0,
        "correct_abstention_rate": 1.0,
    }


def test_missing_extra_and_train_predictions_are_rejected(tmp_path):
    episodes = fixture(tmp_path)
    with pytest.raises(ValueError, match="missing"):
        evaluate_holdout(episodes, {
            "test-1": completion("error_spike", ["ev1"], "verified")
        }, split="test")
    with pytest.raises(ValueError, match="unexpected"):
        evaluate_holdout(episodes, {"train-1": completion("error_spike", ["ev1"],
                                                          "verified")}, split="test")
    with pytest.raises(ValueError, match="holdout"):
        evaluate_holdout(episodes, {}, split="train")


def test_hallucination_lowers_independent_score(tmp_path):
    episodes = fixture(tmp_path)
    result = evaluate_holdout(episodes, {
        "test-1": completion("error_spike", ["ev1", "fabricated"], "verified"),
        "test-2": completion("error_spike", ["ev1"], "verified"),
    }, split="test")
    assert result["mean_reward"] == -1.0
    assert result["exact_success_rate"] == 0.0
    assert result["correct_abstention_rate"] == 0.0


def test_prediction_parser_rejects_duplicate_json_and_rows(tmp_path):
    path = tmp_path / "predictions.jsonl"
    row = {"episode_id": "test-1", "completion": completion("error_spike", ["ev1"], "verified")}
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate episode_id"):
        load_predictions(path)
    path.write_text('{"episode_id":"test-1","episode_id":"test-2","completion":"x"}\n',
                    encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_predictions(path)


def test_prediction_parser_rejects_unencodable_completion_as_value_error(tmp_path):
    path = tmp_path / "surrogate-prediction.jsonl"
    row = {"episode_id": "test-1", "completion": "\ud800"}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid prediction completion"):
        load_predictions(path)


def test_legacy_holdout_cli_supports_external_byte_pins(tmp_path):
    import hashlib
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    ds = tmp_path / "holdout.jsonl"
    records = [
        make_episode("train-1", "train-case", "train", True),
        make_episode("test-1", "test-case", "test", True),
    ]
    ds.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    preds = tmp_path / "predictions.jsonl"
    preds.write_text(json.dumps({
        "episode_id": "test-1",
        "completion": completion("error_spike", ["ev1"], "verified"),
    }) + "\n", encoding="utf-8")
    pinned_ds = hashlib.sha256(ds.read_bytes()).hexdigest()
    pinned_preds = hashlib.sha256(preds.read_bytes()).hexdigest()

    base = [
        sys.executable, str(root / "scripts/eval_sre_grpo.py"),
        "--dataset", str(ds), "--predictions", str(preds),
        "--expected-dataset-sha256", pinned_ds,
        "--expected-predictions-sha256", pinned_preds,
    ]
    ok = subprocess.run(base, text=True, capture_output=True, cwd=root)
    assert ok.returncode == 0, ok.stderr
    result = json.loads(ok.stdout)
    assert result["dataset_sha256"] == pinned_ds
    assert result["predictions_sha256"] == pinned_preds
    assert result["model_runtime_verified"] is False
    bad = base[:]
    bad[bad.index("--expected-predictions-sha256") + 1] = "0" * 64
    fail = subprocess.run(bad, text=True, capture_output=True, cwd=root)
    assert fail.returncode == 3
    assert "predictions_sha256" in fail.stderr
