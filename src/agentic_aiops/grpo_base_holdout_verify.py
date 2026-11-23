"""CPU-only audit of five independently pinned Base Holdout artifacts.

Checks exact content relationships and capture *claims*, not whether the
claimed model or tokenizer actually ran. No GPU, Agent, Adapter or write paths.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from .grpo_eval import load_predictions_bytes
from .grpo_holdout_projection import verify_holdout_projection
from .grpo_import import _verify_pin
from .grpo_training import _fields, _strict_json, _read_bounded_bytes

_REPO = re.compile(r"Qwen/Qwen3-[A-Za-z0-9._-]+\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 32 * 1024
_MAX_CASES = 2048
_CAPTURE_FIELDS = {
    "schema_version", "source_classification", "prompts_sha256",
    "predictions_sha256", "prompt_sha256", "cases", "split", "model",
    "model_revision", "tokenizer_revision", "seed", "max_new_tokens",
    "decoding", "thinking_disabled", "oracle_in_sampler_input",
    "model_runtime_verified", "model_attribution_verified",
    "superiority_claim_authorized", "training_admission_authorized",
    "production_eligible",
}
_FALSE_CLAIMS = (
    "oracle_in_sampler_input", "model_runtime_verified",
    "model_attribution_verified", "superiority_claim_authorized",
    "training_admission_authorized", "production_eligible",
)


def _pinned(path: str | Path, expected: str, name: str, limit: int) -> tuple[bytes, str]:
    raw = _read_bounded_bytes(path, limit=limit, name=name)
    return raw, _verify_pin(raw, expected, name)


def verify_base_holdout_chain(
    *,
    dataset: str | Path,
    prompts: str | Path,
    projection_manifest: str | Path,
    predictions: str | Path,
    capture_manifest: str | Path,
    expected_dataset_sha256: str,
    expected_prompts_sha256: str,
    expected_projection_manifest_sha256: str,
    expected_predictions_sha256: str,
    expected_capture_manifest_sha256: str,
    model: str,
    model_revision: str,
    split: str = "test",
) -> dict[str, Any]:
    """Verify full Base-only data binding; never authorize model attribution.

    The external SHA pins must be obtained independently of the candidate.
    Tokenizer-rendered prompt_sha256 is shape-checked but **cannot** be
    recalculated from these five files alone; report this boundary explicitly.
    """
    if type(split) is not str or split not in ("test", "validation"):
        raise ValueError("Base Holdout split must be test or validation")
    if type(model) is not str or not _REPO.fullmatch(model):
        raise ValueError("model must be an explicit Qwen/Qwen3-* ID")
    if type(model_revision) is not str or not _SHA40.fullmatch(model_revision):
        raise ValueError("model_revision must be a pinned lowercase 40-hex commit")
    inputs = [Path(p) for p in (
        dataset, prompts, projection_manifest, predictions, capture_manifest,
    )]
    seen_inodes: set[tuple[int, int]] = set()
    for path in inputs:
        if path.is_symlink() or not path.is_file():
            raise ValueError("five Holdout sources must be regular non-symlink files")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Holdout source must be a regular file")
        identity = (info.st_dev, info.st_ino)
        if identity in seen_inodes:
            raise ValueError("five Holdout files must not alias the same inode")
        seen_inodes.add(identity)
    if len({path.resolve() for path in inputs}) != 5:
        raise ValueError("five Holdout evidence paths must be distinct")

    first = verify_holdout_projection(
        dataset, prompts, projection_manifest,
        expected_dataset_sha256=expected_dataset_sha256,
        expected_prompts_sha256=expected_prompts_sha256,
        expected_manifest_sha256=expected_projection_manifest_sha256,
    )
    if first["split"] != split:
        raise ValueError("projection split does not match requested Holdout split")
    count = first["cases"]
    if type(count) is not int or not 1 <= count <= _MAX_CASES:
        raise ValueError("invalid Holdout case count")

    # Independently pin re-read projection bytes to guard against changed files
    # between the initial projection audit and this capture audit.
    prompt_raw, _ = _pinned(
        prompts, expected_prompts_sha256, "prompts_sha256", _MAX_FILE_BYTES,
    )
    try:
        prompt_lines = prompt_raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 projected prompts") from exc
    if len(prompt_lines) != count:
        raise ValueError("projected Holdout count changed")
    projected_ids = [
        _fields(_strict_json(line), {"episode_id", "prompt"}, "projected prompt")
        ["episode_id"] for line in prompt_lines
    ]
    if len(set(projected_ids)) != count:
        raise ValueError("duplicate projected episode IDs")

    predictions_raw, predictions_sha = _pinned(
        predictions, expected_predictions_sha256,
        "predictions_sha256", _MAX_FILE_BYTES,
    )
    parsed = load_predictions_bytes(predictions_raw)
    if len(parsed) != count or list(parsed) != projected_ids:
        raise ValueError("predictions must preserve all projected episode IDs in order")
    capture_raw, capture_sha = _pinned(
        capture_manifest, expected_capture_manifest_sha256,
        "capture_manifest_sha256", _MAX_MANIFEST_BYTES,
    )
    try:
        manifest = _fields(
            _strict_json(capture_raw.decode("utf-8")),
            _CAPTURE_FIELDS, "Base capture manifest",
        )
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 capture manifest") from exc
    fixed = {
        "schema_version": "sre.grpo.holdout-capture/v1",
        "source_classification": "UNVERIFIED_MODEL_HOLDOUT_CAPTURE",
        "prompts_sha256": expected_prompts_sha256,
        "predictions_sha256": predictions_sha,
        "cases": count,
        "split": split,
        "model": model,
        "model_revision": model_revision,
        "tokenizer_revision": model_revision,
        "decoding": {"do_sample": False},
        "thinking_disabled": True,
        **{claim: False for claim in _FALSE_CLAIMS},
    }
    for key, expected in fixed.items():
        if type(manifest[key]) is not type(expected) or manifest[key] != expected:
            raise ValueError(f"capture manifest field {key} inconsistent or unauthorized")
    decoding = manifest["decoding"]
    if (type(decoding) is not dict or set(decoding) != {"do_sample"}
            or decoding["do_sample"] is not False):
        raise ValueError("capture decoding.do_sample must be strictly false")
    prompt_hash = manifest["prompt_sha256"]
    if type(prompt_hash) is not str or not _SHA256.fullmatch(prompt_hash):
        raise ValueError("capture prompt_sha256 malformed")
    for field, lower, upper in (("seed", 0, 2**31 - 1), ("max_new_tokens", 32, 192)):
        value = manifest[field]
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"capture {field} out of bounds")
    if manifest["seed"] + count - 1 > 2**31 - 1:
        raise ValueError("capture seed range overflows")
    return {
        "schema_version": "sre.grpo.base-holdout-chain-audit/v1",
        "checkpoint_role": "Base",
        "dataset_sha256": first["dataset_sha256"],
        "prompts_sha256": first["prompts_sha256"],
        "projection_manifest_sha256": first["manifest_sha256"],
        "predictions_sha256": predictions_sha,
        "capture_manifest_sha256": capture_sha,
        "split": split,
        "cases": count,
        "model": model,
        "model_revision": model_revision,
        "projected_prompts_match_oracle_free_dataset": True,
        "predictions_cover_exact_projected_episodes_in_order": True,
        "capture_claims_content_consistent": True,
        "tokenizer_rendering_digest_independently_verified": False,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "data_issuer_authenticated": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
    }
