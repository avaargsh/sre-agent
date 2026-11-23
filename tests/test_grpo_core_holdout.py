"""Independent CPU-only holdout evaluation, without GPU/model or CLI paths."""

import json
from dataclasses import replace

import pytest

from agentic_aiops.grpo_eval import (
    evaluate_holdout,
    load_predictions,
    load_predictions_bytes,
)
from agentic_aiops.grpo_training import load_episodes_bytes


def episode(episode_id, split, answerable):
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": episode_id,
        "fault_family": f"fault-{episode_id}",
        "split": split,
        "alert": f"Synthetic alert for {episode_id}",
        "observations": [
            {"evidence_id": "ev1", "tool": "kubernetes.get_pods",
             "text": "Frozen read-only pod status"},
        ],
        "oracle": {
            "answerable": answerable,
            "root_cause_id": "pod_failure" if answerable else "unknown",
            "required_evidence_ids": ["ev1"] if answerable else [],
        },
    }


def fixtures():
    records = [
        episode("train-1", "train", True),
        episode("holdout-1", "test", True),
        episode("holdout-2", "test", False),
    ]
    raw = "".join(json.dumps(record) + "\n" for record in records).encode()
    episodes = load_episodes_bytes(raw)
    predictions = {
        "holdout-1": json.dumps({
            "root_cause_id": "pod_failure",
            "evidence_ids": ["ev1"], "stop_reason": "verified",
        }),
        "holdout-2": json.dumps({
            "root_cause_id": "unknown",
            "evidence_ids": [], "stop_reason": "insufficient_evidence",
        }),
    }
    return episodes, predictions


def test_complete_cpu_holdout_scoring():
    episodes, predictions = fixtures()
    result = evaluate_holdout(episodes, predictions, split="test")
    assert result == {
        "split": "test", "cases": 2,
        "mean_reward": 1.0, "exact_success_rate": 1.0,
        "correct_abstention_rate": 1.0,
    }


def test_reject_duplicate_holdout_identity():
    episodes, predictions = fixtures()
    with pytest.raises(ValueError, match="duplicate.*episode_id"):
        evaluate_holdout((*episodes, episodes[1]), predictions, split="test")


def test_reject_duplicate_identity_crossing_train_test():
    episodes, predictions = fixtures()
    with pytest.raises(ValueError, match="duplicate.*episode_id"):
        evaluate_holdout(
            (*episodes, replace(episodes[0], episode_id="holdout-1")),
            predictions, split="test",
        )


def test_reject_missing_and_out_of_split_predictions():
    episodes, predictions = fixtures()
    with pytest.raises(ValueError, match="missing"):
        evaluate_holdout(episodes, {"holdout-1": predictions["holdout-1"]})
    with pytest.raises(ValueError, match="unexpected"):
        evaluate_holdout(episodes, {**predictions, "train-1": "fake"})
    with pytest.raises(ValueError, match="holdout"):
        evaluate_holdout(episodes, predictions, split="train")


def test_reject_duplicate_prediction_json_and_rows():
    line = json.dumps({
        "episode_id": "holdout-1", "completion": "a",
    })
    with pytest.raises(ValueError, match="duplicate episode_id"):
        load_predictions_bytes((line + "\n" + line + "\n").encode())
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_predictions_bytes(
            b'{"episode_id":"holdout-1","episode_id":"holdout-2","completion":"a"}\n'
        )


def test_prediction_input_is_bounded_before_file_read(tmp_path, monkeypatch):
    source = tmp_path / "predictions.jsonl"
    with source.open("wb") as file:
        file.truncate(4 * 1024 * 1024 + 2)

    def disallow_read_bytes(_path):
        raise AssertionError("unbounded read_bytes used")

    monkeypatch.setattr(type(source), "read_bytes", disallow_read_bytes)
    with pytest.raises(ValueError, match="oversized"):
        load_predictions(source)
