"""Bind Qwen3 rollout data to an exact capture manifest, without trust promotion.

This verifies only consistency of independently pinned bytes and metadata.
Neither SHA256 nor a manifest that a runner writes can certify model origin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .grpo_import import _verify_pin
from .grpo_rollout_audit import audit_rollout_groups
from .grpo_rollout_capture import prepare_capture
from .grpo_training import _fields, _strict_json

_MAX_MANIFEST_BYTES = 32 * 1024
_MANIFEST_FIELDS = {
    "schema_version", "source_classification", "model", "model_revision",
    "tokenizer_revision", "dataset_sha256", "rollouts_sha256",
    "prompt_sha256", "groups", "group_size", "sample_count", "seed",
    "max_new_tokens", "sampling", "thinking_disabled",
    "model_runtime_independently_verified", "training_admission_authorized",
    "production_release_authorized", "oracle_exposed_to_sampler",
}


def verify_capture_binding(
    dataset: str | Path,
    rollouts: str | Path,
    manifest: str | Path,
    *,
    expected_dataset_sha256: str,
    expected_rollouts_sha256: str,
    expected_manifest_sha256: str,
    model: str,
    model_revision: str,
    group_size: int = 4,
) -> dict[str, Any]:
    """Fail closed on a mismatched or self-promoting rollout capture manifest."""
    paths = [Path(dataset).resolve(), Path(rollouts).resolve(),
             Path(manifest).resolve()]
    if len(set(paths)) != 3:
        raise ValueError("dataset, rollouts and manifest must be distinct files")
    manifest_path = Path(manifest)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("capture manifest must be a regular non-symlink file")
    if not 0 < manifest_path.stat().st_size <= _MAX_MANIFEST_BYTES:
        raise ValueError("capture manifest size invalid")
    raw = manifest_path.read_bytes()
    manifest_sha = _verify_pin(raw, expected_manifest_sha256, "manifest_sha256")
    try:
        decoded = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 capture manifest") from exc
    m = _fields(decoded, _MANIFEST_FIELDS, "capture manifest")
    if m["schema_version"] != "sre.grpo.capture-manifest/v1":
        raise ValueError("unsupported capture manifest schema_version")
    if m["source_classification"] != "unverified-model-capture":
        raise ValueError("unexpected capture source_classification")
    if m["model"] != model:
        raise ValueError("capture model does not match expected model")
    if m["model_revision"] != model_revision:
        raise ValueError("capture model_revision does not match expected commit")
    if m["tokenizer_revision"] != model_revision:
        raise ValueError("tokenizer_revision differs from model_revision")
    for name in (
        "model_runtime_independently_verified",
        "training_admission_authorized",
        "production_release_authorized", "oracle_exposed_to_sampler",
    ):
        if m[name] is not False:
            raise ValueError(f"untrusted capture must not claim {name}")
    if m["thinking_disabled"] is not True:
        raise ValueError("thinking_disabled must be true")
    if m["group_size"] != group_size or type(m["group_size"]) is not int:
        raise ValueError("capture group_size mismatch")
    if type(m["sample_count"]) is not int or type(m["groups"]) is not int:
        raise ValueError("capture group/sample counts must be integer")
    if type(m["max_new_tokens"]) is not int or type(m["seed"]) is not int:
        raise ValueError("capture seed and max_new_tokens must be integer")
    if m["sampling"] != {"do_sample": True, "temperature": 0.7,
                         "top_p": 0.8, "top_k": 20}:
        raise ValueError("capture sampling parameters mismatch")
    if (type(m["prompt_sha256"]) is not str
            or len(m["prompt_sha256"]) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in m["prompt_sha256"])):
        raise ValueError("capture prompt_sha256 invalid")

    # Reuse capture's strict numeric/config validator without allowing it
    # to create or overwrite a file. The temporary paths below are checked
    # but never opened; they are not trusted as actual capture outputs.
    selected, dataset_sha = prepare_capture(
        dataset,
        expected_dataset_sha256=expected_dataset_sha256,
        model=model, model_revision=model_revision,
        group_size=group_size, seed=m["seed"],
        max_new_tokens=m["max_new_tokens"],
        output=manifest_path.with_name(manifest_path.name + ".verify-unwritten-output"),
        manifest=manifest_path.with_name(manifest_path.name + ".verify-unwritten-manifest"),
    )
    raw_rollouts = Path(rollouts).read_bytes()
    rollout_sha = _verify_pin(
        raw_rollouts, expected_rollouts_sha256, "rollouts_sha256"
    )
    if m["dataset_sha256"] != dataset_sha:
        raise ValueError("capture dataset_sha256 mismatch")
    if m["rollouts_sha256"] != rollout_sha:
        raise ValueError("capture rollouts_sha256 mismatch")
    if m["groups"] != len(selected) or m["sample_count"] != len(selected) * group_size:
        raise ValueError("capture group/sample count differs from train episodes")

    # The independent reward audit checks all train rows are present exactly
    # once, rejects holdout IDs, and forbids extra or incomplete groups.
    replay = audit_rollout_groups(
        dataset, rollouts,
        expected_dataset_sha256=expected_dataset_sha256,
        expected_rollouts_sha256=expected_rollouts_sha256,
        group_size=group_size,
    )
    if replay["groups"] != m["groups"]:
        raise ValueError("capture audit groups do not match manifest")
    return {
        "schema_version": "sre.grpo.capture-binding/v1",
        "manifest_sha256": manifest_sha,
        "dataset_sha256": dataset_sha,
        "rollouts_sha256": rollout_sha,
        "model": model,
        "model_revision": model_revision,
        "groups": replay["groups"],
        "group_size": group_size,
        "binding_consistent": True,
        "model_runtime_independently_verified": False,
        "training_admission_authorized": False,
        "production_release_authorized": False,
    }
