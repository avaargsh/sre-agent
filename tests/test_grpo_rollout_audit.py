"""SRE GRPO group-reward collapse audit (CPU-only, no trainer imports)."""

import hashlib
import json
import os
from pathlib import Path

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
    assert report["mean_reward"] == pytest.approx(0.125)
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


def test_complete_coverage_rejects_cherry_picked_train_group(tmp_path):
    dataset, rollouts, _, _ = setup(tmp_path)
    records = [example("train-1"), example(
        "train-2", fault="network", alert="upstream ingress errors"
    )]
    dataset_sha = write_jsonl(dataset, records)
    row = {"episode_id": "train-1", "completions": [answer()] * 4}
    rollouts_sha = write_jsonl(rollouts, [row])
    with pytest.raises(ValueError, match="missing train episode"):
        audit_rollout_groups(
            dataset, rollouts, expected_dataset_sha256=dataset_sha,
            expected_rollouts_sha256=rollouts_sha
        )


def test_cli_signal_gate_returns_nonzero_for_reward_collapse(tmp_path):
    import subprocess
    import sys

    dataset, rollouts, dataset_sha, rollouts_sha = setup(
        tmp_path, [answer()] * 4
    )
    script = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "scripts/audit_sre_grpo_rollouts.py"
    )
    args = [sys.executable, str(script),
            "--dataset", str(dataset), "--rollouts", str(rollouts),
            "--expected-dataset-sha256", dataset_sha,
            "--expected-rollouts-sha256", rollouts_sha, "--require-signal"]
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    assert result.returncode == 3
    assert "NO_GRADIENT_SIGNAL" in result.stdout
    assert "UNKNOWN" in result.stderr

    rollouts_sha = write_jsonl(rollouts, [{
        "episode_id": "train-1",
        "completions": [answer(), answer(root="dns_failure"),
                        answer(evidence=[]), answer()],
    }])
    args[args.index("--expected-rollouts-sha256") + 1] = rollouts_sha
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["model_runtime_verified"] is False
    assert report["nonconstant_reward_groups"] == 1


def test_reward_audit_scores_exactly_the_verified_dataset_bytes(
    tmp_path, monkeypatch
):
    """A mutable dataset must not be reopened after digest validation."""
    dataset, rollouts, dataset_sha, rollout_sha = setup(tmp_path)
    original_open = Path.open
    reads = []

    def spy_open(path, *args, **kwargs):
        if path == dataset:
            reads.append(args[0] if args else kwargs.get("mode", "r"))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spy_open)
    result = audit_rollout_groups(
        dataset, rollouts, expected_dataset_sha256=dataset_sha,
        expected_rollouts_sha256=rollout_sha, group_size=4,
    )
    assert result["groups"] == 1
    assert reads == ["rb"], "Oracle bytes must be opened once for hash and scoring"



@pytest.mark.parametrize("source", ["dataset", "rollouts"])
def test_oversized_source_rejected_before_unbounded_read(tmp_path, monkeypatch, source):
    dataset, rollouts, dataset_sha, rollouts_sha = setup(tmp_path)
    target = dataset if source == "dataset" else rollouts
    with target.open("wb") as output:
        output.truncate(4 * 1024 * 1024 + 1)

    def forbid_unbounded(_path):
        raise AssertionError("Path.read_bytes would allocate entire untrusted file")

    monkeypatch.setattr(Path, "read_bytes", forbid_unbounded)
    with pytest.raises(ValueError, match="oversized"):
        audit_rollout_groups(
            dataset, rollouts, expected_dataset_sha256=dataset_sha,
            expected_rollouts_sha256=rollouts_sha,
        )


def test_unicode_line_separator_inside_jsonl_completion_is_not_new_row(tmp_path):
    dataset, rollouts, dataset_sha, _ = setup(tmp_path)
    rows = [{"episode_id": "train-1", "completions": [
        answer(), "unverified\u2028response", answer(root="dns_failure"), answer(),
    ]}]
    rollouts.write_bytes((
        json.dumps(rows[0], ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8"))
    pin = hashlib.sha256(rollouts.read_bytes()).hexdigest()
    result = audit_rollout_groups(
        dataset, rollouts, expected_dataset_sha256=dataset_sha,
        expected_rollouts_sha256=pin,
    )
    assert result["groups"] == 1
    assert result["nonconstant_reward_groups"] == 1
    assert result["model_runtime_verified"] is False


@pytest.mark.parametrize("source", ["dataset", "rollouts"])
def test_symlinked_input_is_rejected_despite_correct_external_pin(tmp_path, source):
    dataset, rollouts, dataset_sha, rollouts_sha = setup(tmp_path)
    target = dataset if source == "dataset" else rollouts
    other = target.with_suffix(".frozen")
    target.rename(other)
    target.symlink_to(other)
    with pytest.raises(ValueError, match="symlink"):
        audit_rollout_groups(
            dataset, rollouts, expected_dataset_sha256=dataset_sha,
            expected_rollouts_sha256=rollouts_sha,
        )


def test_same_inode_dataset_and_rollouts_cannot_alias(tmp_path):
    dataset, rollouts, dataset_sha, _ = setup(tmp_path)
    rollouts.unlink()
    os.link(dataset, rollouts)
    with pytest.raises(ValueError, match="distinct|inode|hardlink"):
        audit_rollout_groups(
            dataset, rollouts, expected_dataset_sha256=dataset_sha,
            expected_rollouts_sha256=dataset_sha,
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO test requires POSIX")
def test_fifo_is_rejected_before_any_bounded_read(tmp_path, monkeypatch):
    dataset, rollouts, dataset_sha, rollouts_sha = setup(tmp_path)
    rollouts.unlink()
    os.mkfifo(rollouts)
    original_open = Path.open

    def reject_fifo_open(path, *args, **kwargs):
        if path == rollouts:
            raise AssertionError("attempted blocking FIFO read")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", reject_fifo_open)
    with pytest.raises(ValueError, match="regular"):
        audit_rollout_groups(
            dataset, rollouts, expected_dataset_sha256=dataset_sha,
            expected_rollouts_sha256=rollouts_sha,
        )
