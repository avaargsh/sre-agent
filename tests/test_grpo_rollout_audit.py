"""SRE GRPO group-reward collapse audit (CPU-only, no trainer imports)."""

import hashlib
import json

import pytest

from agentic_aiops.grpo_rollout_audit import audit_rollout_groups


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def example(eid, split="train", fault="memory", alert="OOM restarts"):
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": eid,
        "fault_family": fault,
        "split": split,
        "alert": alert,
        "observations": [
            {"evidence_id": "e1", "tool": "kubernetes.get_pods",
             "text": "termination reason OOMKilled"}
        ],
        "oracle": {
            "answerable": True, "root_cause_id": "oom_killed",
            "required_evidence_ids": ["e1"],
        },
    }


def answer(root="oom_killed", evidence=None, **extra):
    return json.dumps({
        "root_cause_id": root,
        "evidence_ids": ["e1"] if evidence is None else evidence,
        "stop_reason": "verified",
        **extra,
    })


def setup(tmp_path, completions=None):
    dataset = tmp_path / "episodes.jsonl"
    rollouts = tmp_path / "rollouts.jsonl"
    dataset_sha = write_jsonl(dataset, [
        example("train-1"),
        example("holdout-1", split="test", fault="dns", alert="DNS failures"),
    ])
    rollout_sha = write_jsonl(rollouts, [{
        "episode_id": "train-1",
        "completions": completions if completions is not None else [
            answer(), answer(root="dns_failure"), answer(evidence=[]), answer()
        ],
    }])
    return dataset, rollouts, dataset_sha, rollout_sha


def inspect(tmp_path, completions=None, *, group_size=4, min_signal=0.25):
    dataset, rollouts, dataset_sha, rollout_sha = setup(tmp_path, completions)
    return audit_rollout_groups(
        dataset, rollouts, expected_dataset_sha256=dataset_sha,
        expected_rollouts_sha256=rollout_sha,
        group_size=group_size, min_signal_fraction=min_signal,
    )


def test_mixed_rewards_have_gradient_signal_but_not_training_proof(tmp_path):
    report = inspect(tmp_path)
    assert report["schema_version"] == "sre.grpo.rollout-audit/v1"
    assert report["groups"] == 1
    assert report["nonconstant_reward_groups"] == 1
    assert report["constant_reward_groups"] == 0
    assert report["mean_reward"] == pytest.approx(-0.125)
    assert report["signal_fraction"] == pytest.approx(1.0)
    assert report["readiness"] == "GRADIENT_SIGNAL_PRESENT_NOT_TRAINING_PROOF"
    assert report["model_runtime_verified"] is False
    assert report["reward_hacking_verified_absent"] is False
    assert report["dataset_sha256"] != report["rollouts_sha256"]


def test_all_correct_group_is_still_zero_advantage(tmp_path):
    report = inspect(tmp_path, [answer()] * 4)
    assert report["constant_reward_groups"] == 1
    assert report["all_correct_groups"] == 1
    assert report["signal_fraction"] == 0
    assert report["readiness"] == "NO_GRADIENT_SIGNAL"
    assert report["mean_reward"] == 1.0


def test_all_wrong_and_cosmetic_text_diversity_cannot_fake_variance(tmp_path):
    report = inspect(tmp_path, [
        answer(root="network_failure"),
        answer(root="dns_failure"),
        answer(root="db_failure"),
        answer(root="upstream_failure"),
    ])
    assert report["all_incorrect_groups"] == 1
    assert report["readiness"] == "NO_GRADIENT_SIGNAL"


def test_refuses_unequal_group_size_and_missing_train_rows(tmp_path):
    with pytest.raises(ValueError, match="group_size"):
        inspect(tmp_path, [answer()] * 3)
    with pytest.raises(ValueError, match="group_size"):
        inspect(tmp_path, [answer()] * 4, group_size=1)
    with pytest.raises(ValueError, match="min_signal_fraction"):
        inspect(tmp_path, min_signal=1.5)


def test_refuses_broken_input_digests_or_duplicate_group(tmp_path):
    dataset, rollouts, dataset_sha, rollout_sha = setup(tmp_path)
    with pytest.raises(ValueError, match="dataset_sha256"):
        audit_rollout_groups(dataset, rollouts, expected_dataset_sha256="0" * 64,
                             expected_rollouts_sha256=rollout_sha)
    with pytest.raises(ValueError, match="rollouts_sha256"):
        audit_rollout_groups(dataset, rollouts, expected_dataset_sha256=dataset_sha,
                             expected_rollouts_sha256="0" * 64)
    row = json.loads(rollouts.read_text())
    rollout_sha = write_jsonl(rollouts, [row, row])
    with pytest.raises(ValueError, match="duplicate"):
        audit_rollout_groups(dataset, rollouts, expected_dataset_sha256=dataset_sha,
                             expected_rollouts_sha256=rollout_sha)


def test_holdout_prediction_and_unknown_episode_fail_closed(tmp_path):
    dataset, rollouts, dataset_sha, _ = setup(tmp_path)
    for eid in ("holdout-1", "forged-episode"):
        sha = write_jsonl(rollouts, [
            {"episode_id": eid, "completions": [answer()] * 4},
        ])
        with pytest.raises(ValueError, match="train episode"):
            audit_rollout_groups(dataset, rollouts,
                expected_dataset_sha256=dataset_sha, expected_rollouts_sha256=sha)


def test_invalid_json_completion_does_not_provide_fake_positive_reward(tmp_path):
    report = inspect(tmp_path, [
        answer(),
        answer(tool_calls=0),
        answer(evidence=["fabricated"]),
        answer(),
    ])
    assert report["nonconstant_reward_groups"] == 1
    assert report["mean_reward"] == pytest.approx(0.0)


def test_no_model_data_is_accepted_as_model_runtime_proof(tmp_path):
    report = inspect(tmp_path)
    assert report["model_runtime_verified"] is False
    assert "training_accuracy" not in report


def test_strict_json_rejects_duplicate_top_level_keys(tmp_path):
    dataset, rollouts, dataset_sha, _ = setup(tmp_path)
    rollouts.write_text(
        '{"episode_id":"train-1","episode_id":"train-2","completions":[]}' + "\n",
        encoding="utf-8",
    )
    sha = hashlib.sha256(rollouts.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate"):
        audit_rollout_groups(dataset, rollouts, expected_dataset_sha256=dataset_sha,
                             expected_rollouts_sha256=sha)
