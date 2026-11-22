"""Independent, complete-set offline SRE GRPO holdout scorer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .grpo_training import (
    SREEpisode,
    _fields,
    _id,
    _strict_json,
    score_completion,
)

_MAX_PREDICTIONS = 4 * 1024 * 1024


def load_predictions(path: str | Path) -> dict[str, str]:
    raw = Path(path).read_bytes()
    if not raw or len(raw) > _MAX_PREDICTIONS:
        raise ValueError("empty or oversized prediction file")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 prediction file") from exc
    result: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            raise ValueError("blank prediction record")
        row = _fields(_strict_json(line), {"episode_id", "completion"}, "prediction")
        key = _id(row["episode_id"], "episode_id")
        if key in result:
            raise ValueError(f"duplicate episode_id in predictions: {key}")
        completion = row["completion"]
        if type(completion) is not str or len(completion.encode("utf-8")) > 8192:
            raise ValueError("invalid prediction completion")
        result[key] = completion
    return result


def evaluate_holdout(
    episodes: Sequence[SREEpisode],
    predictions: Mapping[str, str],
    *,
    split: str = "test",
) -> dict[str, Any]:
    if split not in ("test", "validation"):
        raise ValueError("only independent holdout splits can be scored")
    selected = {ep.episode_id: ep for ep in episodes if ep.split == split}
    if not selected:
        raise ValueError("empty holdout split")
    unexpected = set(predictions) - set(selected)
    if unexpected:
        raise ValueError(f"unexpected prediction episode_id: {sorted(unexpected)}")
    missing = set(selected) - set(predictions)
    if missing:
        raise ValueError(f"missing prediction episode_id: {sorted(missing)}")

    scores = [
        score_completion(ep, predictions[eid]) for eid, ep in selected.items()
    ]
    abstain_ids = [
        eid for eid, ep in selected.items() if not ep.oracle.answerable
    ]
    correct_abstentions = sum(
        score_completion(selected[eid], predictions[eid]) == 1.0
        for eid in abstain_ids
    )
    return {
        "split": split,
        "cases": len(selected),
        "mean_reward": round(sum(scores) / len(scores), 6),
        "exact_success_rate": round(sum(score == 1.0 for score in scores) / len(scores), 6),
        "correct_abstention_rate": (
            round(correct_abstentions / len(abstain_ids), 6)
            if abstain_ids else None
        ),
    }
