"""Offline descriptive comparison of three model-labelled, pinned predictions."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .secure_file import read_pinned_regular
from .grpo_compare import _paired_result
from .grpo_eval import evaluate_holdout, load_predictions_bytes
from .grpo_import import _verify_pin
from .grpo_training import load_episodes_bytes

_MODELS = ("inkling", "qwen", "cloud")
_MAX_BYTES = 4 * 1024 * 1024
_MAX_CASES = 2048


def _read_pinned(path, pin, name, identities):
    """Bind path components, type, identity, bytes and digest to one open inode."""
    raw, _identity = read_pinned_regular(
        path, limit=_MAX_BYTES, label=name, identities=identities,
    )
    digest = _verify_pin(raw, pin, name)
    return raw, digest


def compare_model_holdout(
    dataset: str | Path,
    *,
    expected_dataset_sha256: str,
    prediction_files: dict[str, str | Path],
    expected_prediction_sha256: dict[str, str],
    split: str = "test",
) -> dict[str, Any]:
    """Require full case coverage in all three arms; never authenticate labels."""
    if split not in ("test", "validation"):
        raise ValueError("only independent holdout splits")
    if (type(prediction_files) is not dict or set(prediction_files) != set(_MODELS)
            or type(expected_prediction_sha256) is not dict
            or set(expected_prediction_sha256) != set(_MODELS)):
        raise ValueError("exactly inkling, qwen, cloud files and pins required")
    identities = set()
    raw, ds_hash = _read_pinned(dataset, expected_dataset_sha256,
                                "dataset_sha256", identities)
    episodes = load_episodes_bytes(raw)
    selected = {ep.episode_id: ep for ep in episodes if ep.split == split}
    if not 1 <= len(selected) <= _MAX_CASES:
        raise ValueError("invalid holdout case count")
    predictions, hashes, models = {}, {}, {}
    for name in _MODELS:
        raw, hashes[name] = _read_pinned(
            prediction_files[name], expected_prediction_sha256[name],
            name + "_sha256", identities,
        )
        predictions[name] = load_predictions_bytes(raw)
        models[name] = evaluate_holdout(episodes, predictions[name], split=split)
    pairs = (("inkling", "cloud"), ("qwen", "cloud"), ("inkling", "qwen"))
    return {
        "schema_version": "sre.model.paired-holdout/v1",
        "dataset_sha256": ds_hash, "predictions_sha256": hashes,
        "split": split, "cases": len(selected), "models": models,
        "paired": {a + "_vs_" + b: _paired_result(
            selected, predictions[a], predictions[b]) for a, b in pairs},
        "evaluation_scope": "DESCRIPTIVE_OFFLINE_EVIDENCE_GATED",
        "admission": "HOLD", "model_runtime_verified": False,
        "model_attribution_verified": False, "data_issuer_authenticated": False,
        "superiority_claim_authorized": False, "training_admission_authorized": False,
        "production_eligible": False, "routing_authorized": False,
    }
