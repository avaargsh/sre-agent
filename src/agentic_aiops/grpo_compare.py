"""Independent, pinned Base/SFT/GRPO paired holdout scoring (no model import).

Frozen predictions are compared on the same exact Episode IDs and Oracle
records. Reward is recomputed, not read from model-produced metrics.
This descriptive report cannot independently authenticate a model run,
prove better training, or authorize production use.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any, Mapping

from .grpo_eval import evaluate_holdout, load_predictions_bytes
from .grpo_import import _verify_pin
from .grpo_training import load_episodes_bytes, score_completion

_MODELS = ("Base", "SFT", "GRPO")
_MAX_DATA = 4 * 1024 * 1024
_MAX_PREDICTIONS = 4 * 1024 * 1024


def _pinned_file(path: str | Path, expected: str, name: str, limit: int) -> bytes:
    raw = Path(path).read_bytes()
    if not 0 < len(raw) <= limit:
        raise ValueError(f"empty or oversized {name}")
    _verify_pin(raw, expected, name)
    return raw


def _paired_sign_p_value(wins: int, losses: int) -> float:
    """Exact two-sided paired sign test; ties excluded, descriptive only."""
    n = wins + losses
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(wins, losses) + 1))
    return round(min(1.0, 2 * tail / 2**n), 6)


def _paired_result(
    episodes: dict[str, Any],
    a: Mapping[str, str],
    b: Mapping[str, str],
) -> dict[str, Any]:
    wins = losses = both_good = both_bad = 0
    for eid, ep in episodes.items():
        a_good = score_completion(ep, a[eid]) == 1.0
        b_good = score_completion(ep, b[eid]) == 1.0
        # The first argument is the challenger, second is baseline.
        if a_good and not b_good:
            wins += 1
        elif b_good and not a_good:
            losses += 1
        elif a_good:
            both_good += 1
        else:
            both_bad += 1
    n = len(episodes)
    return {
        "win": wins,
        "loss": losses,
        "tie_both_correct": both_good,
        "tie_both_incorrect": both_bad,
        "discordant_cases": wins + losses,
        "exact_success_rate_delta": round((wins - losses) / n, 6),
        "paired_sign_test_p_value": _paired_sign_p_value(wins, losses),
    }


def compare_pinned_holdout(
    dataset: str | Path,
    *,
    prediction_files: Mapping[str, str | Path],
    expected_dataset_sha256: str,
    expected_prediction_sha256: Mapping[str, str],
    split: str = "test",
) -> dict[str, Any]:
    """Score the same complete holdout against 3 distinct pinned input files.

    SHA256 only shows consistency with externally pinned bytes. The labels
    Base/SFT/GRPO do not independently prove which model generated a file.
    """
    if split not in ("test", "validation"):
        raise ValueError("only validation/test holdout splits may be compared")
    if (type(prediction_files) is not dict
            or set(prediction_files) != set(_MODELS)
            or type(expected_prediction_sha256) is not dict
            or set(expected_prediction_sha256) != set(_MODELS)):
        raise ValueError("required model labels: Base, SFT, GRPO (exactly)")
    inputs = [Path(dataset).resolve()] + [
        Path(prediction_files[name]).resolve() for name in _MODELS
    ]
    if len(set(inputs)) != 4:
        raise ValueError("dataset and Base/SFT/GRPO prediction paths must be distinct")

    raw_dataset = _pinned_file(dataset, expected_dataset_sha256,
                               "dataset_sha256", _MAX_DATA)
    episodes = load_episodes_bytes(raw_dataset)
    selected = {ep.episode_id: ep for ep in episodes if ep.split == split}
    if not selected:
        raise ValueError("empty independent holdout split")
    predictions: dict[str, dict[str, str]] = {}
    model_results: dict[str, dict[str, Any]] = {}
    prediction_hashes: dict[str, str] = {}
    for name in _MODELS:
        raw = _pinned_file(
            prediction_files[name], expected_prediction_sha256[name],
            f"{name} predictions_sha256", _MAX_PREDICTIONS,
        )
        prediction_hashes[name] = hashlib.sha256(raw).hexdigest()
        parsed = load_predictions_bytes(raw)
        scores = evaluate_holdout(episodes, parsed, split=split)
        predictions[name] = parsed
        model_results[name] = {
            **scores,
            "exact_successes": sum(
                score_completion(selected[eid], parsed[eid]) == 1.0
                for eid in selected
            ),
        }

    paired = {
        "GRPO_vs_Base": _paired_result(selected, predictions["GRPO"], predictions["Base"]),
        "GRPO_vs_SFT": _paired_result(selected, predictions["GRPO"], predictions["SFT"]),
        "SFT_vs_Base": _paired_result(selected, predictions["SFT"], predictions["Base"]),
    }
    return {
        "schema_version": "sre.grpo.paired-holdout/v1",
        "dataset_sha256": hashlib.sha256(raw_dataset).hexdigest(),
        "predictions_sha256": prediction_hashes,
        "split": split,
        "cases": len(selected),
        "models": model_results,
        "paired": paired,
        "evaluation_scope": "DESCRIPTIVE_OFFLINE_EVIDENCE_GATED",
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "data_issuer_authenticated": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
    }
