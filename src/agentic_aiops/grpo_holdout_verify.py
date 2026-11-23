"""Independent five-artifact holdout content-chain consistency verification.

Oracle-bearing dataset and projection are compared only by the verifier,
never by the inference sampler. SHA256 pins do NOT authenticate a dataset
issuer, GPU model, adapter weights, or claimed Base/SFT/GRPO identity.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .grpo_eval import load_predictions_bytes
from .grpo_holdout_capture import _MAX_CASES, _MAX_FILE_BYTES, _MAX_PROMPT_BYTES
from .grpo_rollout_capture import _REPO, _SHA40
from .grpo_import import _verify_pin, _sha
from .grpo_adapter import load_pinned_adapter, validate_adapter_receipt
from .grpo_adapter_effect import validate_local_effect_receipt
from .grpo_training import (
    _fields, _id, _strict_json, build_prompt, load_episodes_bytes,
)

_MAX_MANIFEST_BYTES = 32 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _pinned_bytes(path: str | Path, expected: str, name: str, max_bytes: int) -> tuple[bytes, str]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"{name} requires a regular non-symlink file")
    if not 0 < source.stat().st_size <= max_bytes:
        raise ValueError(f"{name} empty or oversized")
    raw = source.read_bytes()
    if not 0 < len(raw) <= max_bytes:
        raise ValueError(f"{name} empty or oversized")
    return raw, _verify_pin(raw, expected, name)


def _manifest(raw: bytes, expected: set[str], schema: str, name: str) -> dict[str, Any]:
    try:
        obj = _fields(_strict_json(raw.decode("utf-8")), expected, name)
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid UTF-8 {name}") from exc
    if obj["schema_version"] != schema:
        raise ValueError(f"invalid {name} schema_version")
    return obj


def verify_holdout_chain(
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
    checkpoint_role: str = "Base",
    expected_adapter_config_sha256: str | None = None,
    expected_adapter_weights_sha256: str | None = None,
    require_local_effect_probe: bool = False,
    require_reenable_probe: bool = False,
    adapter_dir: str | Path | None = None,
    require_adapter_files: bool = False,
) -> dict[str, Any]:
    """Prove raw-content bindings from private Oracle source to predictions.

    Independent external pins are required for all five files, but these pins
    alone do not imply authentic provenance of any model or source.
    """
    if split not in ("test", "validation"):
        raise ValueError("only independent test/validation splits are auditable")
    if type(model) is not str or not _REPO.fullmatch(model):
        raise ValueError("model must be an explicit Qwen/Qwen3-* repository ID")
    if type(model_revision) is not str or not _SHA40.fullmatch(model_revision):
        raise ValueError("model_revision must be pinned lowercase 40-character commit")
    if checkpoint_role not in ("Base", "SFT", "GRPO"):
        raise ValueError("checkpoint_role must be Base, SFT or GRPO")
    if type(require_local_effect_probe) is not bool:
        raise ValueError("require_local_effect_probe must be boolean")
    if type(require_reenable_probe) is not bool:
        raise ValueError("require_reenable_probe must be boolean")
    if type(require_adapter_files) is not bool:
        raise ValueError("require_adapter_files must be boolean")
    if checkpoint_role == "Base" and (require_local_effect_probe or require_reenable_probe):
        raise ValueError("Base cannot require local effect probe or reenable evidence")
    if checkpoint_role == "Base":
        if (adapter_dir is not None or require_adapter_files
                or expected_adapter_config_sha256 is not None
                or expected_adapter_weights_sha256 is not None):
            raise ValueError("Base cannot accept adapter files, pins or strict audit")
    else:
        _sha(expected_adapter_config_sha256, "adapter_config_sha256")
        _sha(expected_adapter_weights_sha256, "adapter_weights_sha256")
        if require_adapter_files and adapter_dir is None:
            raise ValueError("required adapter files: --adapter-dir is missing")
    sources = [dataset, prompts, projection_manifest, predictions, capture_manifest]
    if len({Path(p).resolve() for p in sources}) != len(sources):
        raise ValueError("five holdout evidence paths must be distinct")

    dataset_raw, dataset_sha = _pinned_bytes(
        dataset, expected_dataset_sha256, "dataset_sha256", _MAX_FILE_BYTES,
    )
    prompts_raw, prompts_sha = _pinned_bytes(
        prompts, expected_prompts_sha256, "prompts_sha256", _MAX_FILE_BYTES,
    )
    episodes = load_episodes_bytes(dataset_raw)
    selected = [ep for ep in episodes if ep.split == split]
    if not 1 <= len(selected) <= _MAX_CASES:
        raise ValueError("holdout case count must be in [1,2048]")
    try:
        lines = prompts_raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 prompts") from exc
    if len(lines) != len(selected):
        raise ValueError("projected prompts do not match dataset holdout count")
    # Exact ordering and content intentionally matter. No ability to swap
    # predicted labels or pick only favorable episodes after sampling.
    for source_line, episode in zip(lines, selected):
        if not source_line.strip() or len(source_line.encode("utf-8")) > 128*1024:
            raise ValueError("empty/oversized projected prompts")
        row = _fields(
            _strict_json(source_line), {"episode_id", "prompt"}, "projected prompt",
        )
        if (row["episode_id"] != episode.episode_id
                or row["prompt"] != build_prompt(episode)):
            raise ValueError("projected prompts diverge from pinned dataset")
        if len(row["prompt"].encode("utf-8")) > _MAX_PROMPT_BYTES:
            raise ValueError("projected prompt exceeds bound")

    projection_raw, proj_manifest_sha = _pinned_bytes(
        projection_manifest, expected_projection_manifest_sha256,
        "projection_manifest_sha256", _MAX_MANIFEST_BYTES,
    )
    proj = _manifest(projection_raw, {
        "schema_version", "dataset_sha256", "prompts_sha256", "split", "cases",
        "oracle_in_projection", "model_runtime_verified",
        "training_admission_authorized", "source_classification",
    }, "sre.grpo.holdout-projection/v1", "projection manifest")
    if proj["dataset_sha256"] != dataset_sha or proj["prompts_sha256"] != prompts_sha:
        raise ValueError("projection manifest dataset_sha256/prompts_sha256 mismatch")
    if proj["split"] != split:
        raise ValueError("projection manifest split mismatch")
    if type(proj["cases"]) is not int or proj["cases"] != len(selected):
        raise ValueError("projection manifest case count mismatch")
    if proj["source_classification"] != "UNVERIFIED_HOLDOUT_PROJECTION":
        raise ValueError("projection classification cannot be promoted")
    for field in ("oracle_in_projection", "model_runtime_verified",
                  "training_admission_authorized"):
        if proj[field] is not False:
            raise ValueError(f"untrusted projection must not claim {field}")

    predictions_raw, preds_sha = _pinned_bytes(
        predictions, expected_predictions_sha256,
        "predictions_sha256", _MAX_FILE_BYTES,
    )
    parsed_predictions = load_predictions_bytes(predictions_raw)
    selected_ids = {ep.episode_id for ep in selected}
    if set(parsed_predictions) != selected_ids:
        raise ValueError("predictions must cover exact dataset holdout episode IDs")

    capture_raw, capture_manifest_sha = _pinned_bytes(
        capture_manifest, expected_capture_manifest_sha256,
        "capture_manifest_sha256", _MAX_MANIFEST_BYTES,
    )
    expected_fields = {
        "schema_version", "source_classification", "prompts_sha256",
        "predictions_sha256", "prompt_sha256", "cases", "split", "model",
        "model_revision", "tokenizer_revision", "seed", "max_new_tokens",
        "decoding", "thinking_disabled", "oracle_in_sampler_input",
        "model_runtime_verified", "model_attribution_verified",
        "superiority_claim_authorized", "training_admission_authorized",
        "production_eligible",
    }
    local_effect = None
    if checkpoint_role != "Base":
        expected_fields |= {"checkpoint_role", "adapter"}
    try:
        candidate = _strict_json(capture_raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 capture manifest") from exc
    if type(candidate) is not dict:
        raise ValueError("capture manifest must be a JSON object")
    has_probe = "local_effect_probe" in candidate
    if has_probe:
        if checkpoint_role == "Base":
            raise ValueError("Base capture cannot claim local effect probe")
        expected_fields.add("local_effect_probe")
        local_effect = validate_local_effect_receipt(candidate["local_effect_probe"])
        is_aba = local_effect["schema_version"] == "sre.grpo.local-adapter-effect/v2"
        version = ("sre.grpo.holdout-capture/v4" if is_aba
                   else "sre.grpo.holdout-capture/v3")
        if require_reenable_probe and not is_aba:
            raise ValueError("required LoRA reenable A-B-A probe is missing")
    else:
        if require_local_effect_probe or require_reenable_probe:
            raise ValueError("required local effect probe / reenable evidence is missing")
        version = ("sre.grpo.holdout-capture/v1" if checkpoint_role == "Base"
                   else "sre.grpo.holdout-capture/v2")
    cap = _fields(candidate, expected_fields, "capture manifest")
    if cap["schema_version"] != version:
        raise ValueError("capture manifest schema_version invalid")
    adapter = None
    if checkpoint_role != "Base":
        if cap["checkpoint_role"] != checkpoint_role:
            raise ValueError("capture checkpoint_role mismatch")
        adapter = validate_adapter_receipt(
            cap["adapter"], base_model=model, base_revision=model_revision,
        )
        if adapter["adapter_config_sha256"] != expected_adapter_config_sha256:
            raise ValueError("capture adapter_config_sha256 mismatch")
        if adapter["adapter_weights_sha256"] != expected_adapter_weights_sha256:
            raise ValueError("capture adapter_weights_sha256 mismatch")
    physical_adapter_verified = False
    if adapter_dir is not None:
        # The auditor itself reads the two immutable-by-digest Adapter files.
        # The producer's embedded receipt is treated as an untrusted claim:
        # every structural metadata field must match the independently
        # reconstructed result, not merely its copied SHA256 fields.
        physical = load_pinned_adapter(
            adapter_dir, base_model=model, base_revision=model_revision,
            expected_adapter_config_sha256=expected_adapter_config_sha256,
            expected_adapter_weights_sha256=expected_adapter_weights_sha256,
        )
        if adapter != physical.receipt:
            raise ValueError(
                "adapter metadata in capture differs from physical adapter files"
            )
        physical_adapter_verified = True
    if cap["source_classification"] != "UNVERIFIED_MODEL_HOLDOUT_CAPTURE":
        raise ValueError("capture classification cannot be promoted")
    if cap["prompts_sha256"] != prompts_sha:
        raise ValueError("capture prompts_sha256 mismatch")
    if cap["predictions_sha256"] != preds_sha:
        raise ValueError("capture predictions_sha256 mismatch")
    if type(cap["cases"]) is not int or cap["cases"] != len(selected):
        raise ValueError("capture cases mismatch")
    if cap["split"] != split:
        raise ValueError("capture split mismatch")
    if cap["model"] != model:
        raise ValueError("capture model mismatch")
    if cap["model_revision"] != model_revision:
        raise ValueError("capture model_revision mismatch")
    if cap["tokenizer_revision"] != model_revision:
        raise ValueError("capture tokenizer_revision mismatch")
    if (type(cap["prompt_sha256"]) is not str
            or not _SHA.fullmatch(cap["prompt_sha256"])):
        raise ValueError("capture prompt_sha256 invalid")
    if (type(cap["seed"]) is not int or type(cap["max_new_tokens"]) is not int
            or not 0 <= cap["seed"] <= 2**31-1
            or not 32 <= cap["max_new_tokens"] <= 192):
        raise ValueError("capture seed/max_new_tokens invalid")
    if cap["decoding"] != {"do_sample": False} or cap["thinking_disabled"] is not True:
        raise ValueError("capture decoding/thinking settings invalid")
    for field in (
        "oracle_in_sampler_input", "model_runtime_verified",
        "model_attribution_verified", "superiority_claim_authorized",
        "training_admission_authorized", "production_eligible",
    ):
        if cap[field] is not False:
            raise ValueError(f"unverified capture cannot claim {field}")
    return {
        "schema_version": "sre.grpo.holdout-chain-audit/v1",
        "checkpoint_role": checkpoint_role,
        "adapter_files_content_verified": physical_adapter_verified,
        "adapter_metadata_matches_files": physical_adapter_verified,
        "local_effect_probe_content_consistent": local_effect is not None,
        "local_reenable_probe_content_consistent": bool(
            local_effect is not None
            and local_effect["schema_version"] == "sre.grpo.local-adapter-effect/v2"
        ),
        **({
            "adapter_config_sha256": adapter["adapter_config_sha256"],
            "adapter_weights_sha256": adapter["adapter_weights_sha256"],
        } if adapter is not None else {}),
        "dataset_sha256": dataset_sha,
        "prompts_sha256": prompts_sha,
        "projection_manifest_sha256": proj_manifest_sha,
        "predictions_sha256": preds_sha,
        "capture_manifest_sha256": capture_manifest_sha,
        "model": model,
        "model_revision": model_revision,
        "split": split,
        "cases": len(selected),
        "projected_prompts_match_oracle_free_dataset": True,
        "capture_prediction_binding_consistent": True,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "data_issuer_authenticated": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
    }
