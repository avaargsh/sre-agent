"""CPU-only audit of grouped SRE GRPO diagnostic rewards.

Rejects partial or mixed-split rollouts and makes the zero-advantage failure
explicit. This never authenticates a model runtime or authorizes training.
"""

from __future__ import annotations

import math
import stat
from pathlib import Path
from typing import Any

from .grpo_import import _verify_pin
from .grpo_training import (
    _fields, _id, _strict_json, _read_bounded_bytes, _jsonl_lines,
    load_episodes_bytes, score_completion,
)

_MAX_ROLLOUT_FILE_BYTES = 4 * 1024 * 1024
_MAX_ROLLOUT_LINE_BYTES = 128 * 1024
_MAX_GROUPS = 2048
_MAX_GENERATIONS = 64


def audit_rollout_groups(
    dataset_path: str | Path,
    rollout_path: str | Path,
    *,
    expected_dataset_sha256: str,
    expected_rollouts_sha256: str,
    group_size: int = 4,
    min_signal_fraction: float = 0.25,
) -> dict[str, Any]:
    """Require complete train-only groups, then independently re-score candidates.

    The data owner must pin both exact input byte digests *outside* the files.
    Pinned byte equality is only a reproducibility check, not provenance,
    model identity, Oracle independence, or quality evidence.
    """
    if type(group_size) is not int or not 2 <= group_size <= _MAX_GENERATIONS:
        raise ValueError("group_size must be between 2 and 64")
    if (type(min_signal_fraction) not in (float, int)
            or not math.isfinite(min_signal_fraction)
            or not 0 < min_signal_fraction <= 1):
        raise ValueError("min_signal_fraction must be finite and in (0,1]")

    inputs = (Path(dataset_path), Path(rollout_path))
    if inputs[0].resolve() == inputs[1].resolve():
        raise ValueError("dataset and rollouts must be distinct")
    identities: set[tuple[int, int]] = set()
    for path in inputs:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlinked dataset or rollouts source rejected")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("dataset and rollouts must be regular files")
        inode = (info.st_dev, info.st_ino)
        if inode in identities:
            raise ValueError("dataset and rollouts inodes must be distinct")
        identities.add(inode)

    dataset_raw = _read_bounded_bytes(
        dataset_path, limit=_MAX_ROLLOUT_FILE_BYTES, name="episode dataset",
    )
    dataset_sha = _verify_pin(dataset_raw, expected_dataset_sha256, "dataset_sha256")
    episodes = load_episodes_bytes(dataset_raw)
    training = {ep.episode_id: ep for ep in episodes if ep.split == "train"}
    if not training:
        raise ValueError("no train episodes to audit")
    if len(training) > _MAX_GROUPS:
        raise ValueError("too many train groups for bounded audit")

    raw = _read_bounded_bytes(
        rollout_path, limit=_MAX_ROLLOUT_FILE_BYTES, name="rollouts file",
    )
    rollout_sha = _verify_pin(raw, expected_rollouts_sha256, "rollouts_sha256")
    try:
        records = _jsonl_lines(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("rollouts file not valid UTF-8") from exc

    seen: set[str] = set()
    nonconstant = 0
    all_correct = 0
    all_incorrect = 0
    total_reward = 0.0
    count = 0
    for line in records:
        if not line.strip() or len(line.encode("utf-8")) > _MAX_ROLLOUT_LINE_BYTES:
            raise ValueError("blank or oversized rollouts record")
        row = _fields(_strict_json(line), {"episode_id", "completions"}, "rollout")
        key = _id(row["episode_id"], "episode_id")
        if key not in training:
            raise ValueError(f"non-train episode or unknown train episode_id: {key}")
        if key in seen:
            raise ValueError(f"duplicate episode_id in rollout groups: {key}")
        seen.add(key)
        completions = row["completions"]
        if type(completions) is not list or len(completions) != group_size:
            raise ValueError(f"group_size mismatch for {key}")
        for item in completions:
            if type(item) is not str:
                raise ValueError(f"invalid or oversized completion for {key}")
            try:
                encoded_length = len(item.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ValueError(f"invalid Unicode completion for {key}") from exc
            if encoded_length > 8192:
                raise ValueError(f"invalid or oversized completion for {key}")
        rewards = [score_completion(training[key], item) for item in completions]
        nonconstant += int(max(rewards) != min(rewards))
        all_correct += int(all(value == 1.0 for value in rewards))
        all_incorrect += int(all(value == -1.0 for value in rewards))
        total_reward += sum(rewards)
        count += len(rewards)

    missing = set(training) - seen
    if missing:
        raise ValueError(f"missing train episode rollout groups: {sorted(missing)}")
    groups = len(seen)
    fraction = nonconstant / groups
    if nonconstant == 0:
        readiness = "NO_GRADIENT_SIGNAL"
    elif fraction < min_signal_fraction:
        readiness = "INSUFFICIENT_SIGNAL"
    else:
        readiness = "GRADIENT_SIGNAL_PRESENT_NOT_TRAINING_PROOF"

    return {
        "schema_version": "sre.grpo.rollout-audit/v1",
        "dataset_sha256": dataset_sha,
        "rollouts_sha256": rollout_sha,
        "groups": groups,
        "group_size": group_size,
        "constant_reward_groups": groups - nonconstant,
        "nonconstant_reward_groups": nonconstant,
        "all_correct_groups": all_correct,
        "all_incorrect_groups": all_incorrect,
        "signal_fraction": round(fraction, 6),
        "mean_reward": round(total_reward / count, 6),
        "readiness": readiness,
        "model_runtime_verified": False,
        "reward_hacking_verified_absent": False,
        "external_provenance_authenticated": False,
    }
