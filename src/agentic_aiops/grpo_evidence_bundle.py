"""CPU-only cross-stage evidence bundle for experimental SRE GRPO.

This ties independently pinned *contents* of the dataset, local training
claims, physical LoRA adapter, and independently re-evaluated Holdout.
It does NOT authenticate who trained the weights, whether the saved weights
came from the reported optimizer step, or whether any GPU ran.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .grpo_adapter import load_pinned_adapter
from .grpo_holdout_verify import verify_holdout_chain
from .grpo_import import _verify_pin
from .grpo_rollout_capture import _REPO, _SHA40
from .grpo_train_proof import verify_local_lora_update
from .grpo_training import _fields, _strict_json, load_episodes_bytes

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECEIPT_BYTES = 128 * 1024
_HOLDOUT_FIELDS = {
    "prompts", "projection_manifest", "predictions", "capture_manifest",
    "expected_prompts_sha256", "expected_projection_manifest_sha256",
    "expected_predictions_sha256", "expected_capture_manifest_sha256", "split",
}
_TRAIN_RECEIPT_FIELDS = {
    "schema_version", "dataset_sha256", "model", "model_revision",
    "tokenizer_revision", "local_lora_update", "training_scope",
    "model_runtime_independently_verified", "data_issuer_authenticated",
    "training_admission_authorized", "production_eligible",
}
_UPDATE_FIELDS = {
    "schema_version", "status", "before", "after", "global_step", "max_steps",
    "local_lora_changed", "model_runtime_independently_verified",
    "training_admission_authorized", "production_eligible",
}
_SNAPSHOT_FIELDS = {
    "schema_version", "trainable_tensors", "trainable_elements",
    "trainable_names_sha256", "layout_sha256", "fingerprint_sha256",
}


def _read_json(path: str | Path, pin: str, *, label: str) -> dict[str, Any]:
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    size = file.stat().st_size
    if not 0 < size <= _MAX_RECEIPT_BYTES:
        raise ValueError(f"{label} empty or oversized")
    raw = file.read_bytes()
    if not 0 < len(raw) <= _MAX_RECEIPT_BYTES:
        raise ValueError(f"{label} empty or oversized")
    _verify_pin(raw, pin, label)
    try:
        payload = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid UTF-8 {label}") from exc
    if type(payload) is not dict:
        raise ValueError(f"{label} must be an object")
    return payload


def _validate_snapshot(value: Any, *, label: str) -> dict[str, Any]:
    snapshot = _fields(value, _SNAPSHOT_FIELDS, label)
    if snapshot["schema_version"] != "sre.grpo.local-lora-snapshot/v1":
        raise ValueError(f"invalid {label} schema_version")
    for k in ("trainable_tensors", "trainable_elements"):
        if type(snapshot[k]) is not int or snapshot[k] <= 0:
            raise ValueError(f"invalid {label} {k}")
    for k in (
        "trainable_names_sha256", "layout_sha256", "fingerprint_sha256",
    ):
        if type(snapshot[k]) is not str or not _SHA256.fullmatch(snapshot[k]):
            raise ValueError(f"invalid {label} {k}")
    return snapshot


def _validate_run_and_delta(
    run: dict[str, Any], receipt: dict[str, Any],
    *, dataset_sha: str, train_count: int,
) -> tuple[str, str, dict[str, Any]]:
    if run.get("dataset_sha256") != dataset_sha:
        raise ValueError("run manifest dataset_sha256 mismatch")
    if receipt.get("dataset_sha256") != dataset_sha:
        raise ValueError("train receipt dataset_sha256 mismatch")
    if (run.get("training_status") != "started_not_verified"
            or run.get("training_scope") != "LAB_ONLY_UNVERIFIED"):
        raise ValueError("run manifest training_status/training_scope invalid")
    if receipt.get("training_scope") != "LAB_ONLY_UNVERIFIED":
        raise ValueError("train receipt training_scope invalid")
    for flag in (
        "data_issuer_authenticated", "training_admission_authorized",
    ):
        if run.get(flag) is not False or receipt.get(flag) is not False:
            raise ValueError(f"training {flag} cannot be promoted")
    if run.get("eligible_for_production") is not False:
        raise ValueError("run manifest eligible_for_production cannot be promoted")
    for flag in ("model_runtime_independently_verified", "production_eligible"):
        if receipt.get(flag) is not False:
            raise ValueError(f"training {flag} cannot be promoted")
    if type(run.get("train_rows", train_count)) is not int or run.get(
        "train_rows", train_count
    ) != train_count:
        raise ValueError("run manifest train_rows inconsistent with pinned dataset")
    model, revision = run.get("model"), run.get("model_revision")
    if type(model) is not str or not _REPO.fullmatch(model):
        raise ValueError("invalid run model")
    if type(revision) is not str or not _SHA40.fullmatch(revision):
        raise ValueError("invalid run model_revision")
    for name in ("model", "model_revision", "tokenizer_revision"):
        expected = model if name == "model" else revision
        if run.get(name) != expected or receipt.get(name) != expected:
            raise ValueError(f"train receipt/run manifest {name} mismatch")
    if receipt.get("schema_version") != "sre.grpo.local-training-receipt/v1":
        raise ValueError("invalid local training receipt schema_version")
    _fields(receipt, _TRAIN_RECEIPT_FIELDS, "local training receipt")

    update = _fields(
        receipt["local_lora_update"], _UPDATE_FIELDS, "local_lora_update",
    )
    before = _validate_snapshot(
        update["before"], label="local_lora_update.before",
    )
    after = _validate_snapshot(
        update["after"], label="local_lora_update.after",
    )
    run_before = _validate_snapshot(
        run.get("before_lora_snapshot"), label="before_lora_snapshot",
    )
    if run_before != before:
        raise ValueError("before_lora_snapshot differs from local_lora_update.before")
    if (type(run.get("max_steps")) is not int
            or run["max_steps"] != update["max_steps"]):
        raise ValueError("run manifest max_steps differs from local_lora_update")
    replayed = verify_local_lora_update(
        before, after, global_step=update["global_step"],
        max_steps=update["max_steps"],
    )
    if replayed != update:
        raise ValueError("local_lora_update is internally inconsistent or promoted")
    return model, revision, update


def _publish_create_only(path: Path, document: dict[str, Any]) -> None:
    """Use staged + fsynced bytes and no-replace hard link to publish once.

    A crash before the link can leave only an orphan staging file, which
    cannot serve as the required final evidence-package path. On exceptions
    the staging file is cleaned up. External pins are needed for identity.
    """
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"evidence output already exists: {path}")
    payload = (json.dumps(
        document, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")
    if len(payload) > _MAX_RECEIPT_BYTES:
        raise ValueError("experiment evidence package oversized")
    stage: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".staging-", dir=path.parent, delete=False,
        ) as stream:
            stage = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, path)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


def build_grpo_evidence_bundle(
    *,
    dataset: str | Path,
    expected_dataset_sha256: str,
    run_manifest: str | Path,
    expected_run_manifest_sha256: str,
    train_receipt: str | Path,
    expected_train_receipt_sha256: str,
    adapter_dir: str | Path,
    expected_adapter_config_sha256: str,
    expected_adapter_weights_sha256: str,
    holdout: Mapping[str, Any],
    output: str | Path,
) -> dict[str, Any]:
    """Re-verify source facts before create-only publication.

    A bundle does not authorize training or release and explicitly cannot
    establish that the exported adapter equals the in-memory post-step
    snapshot. The producer can self-report a plausible tensor delta.
    """
    holdout = _fields(holdout, _HOLDOUT_FIELDS, "holdout inputs")
    if holdout["split"] not in ("test", "validation"):
        raise ValueError("bundle holdout split must be test/validation")
    sources = [
        dataset, run_manifest, train_receipt,
        *(holdout[name] for name in (
            "prompts", "projection_manifest", "predictions",
            "capture_manifest",
        )),
        Path(adapter_dir)/"adapter_config.json",
        Path(adapter_dir)/"adapter_model.safetensors",
        output,
    ]
    if len({Path(item).resolve() for item in sources}) != len(sources):
        raise ValueError("experiment evidence input/output paths must be distinct")
    result_path = Path(output)
    if result_path.exists() or result_path.is_symlink():
        raise FileExistsError(f"evidence output already exists: {result_path}")
    data_path = Path(dataset)
    if data_path.is_symlink() or not data_path.is_file():
        raise ValueError("dataset must be a regular non-symlink file")
    if not 0 < data_path.stat().st_size <= 4*1024*1024:
        raise ValueError("dataset empty or oversized")
    raw_dataset = data_path.read_bytes()
    dataset_sha = _verify_pin(
        raw_dataset, expected_dataset_sha256, "dataset_sha256",
    )
    episodes = load_episodes_bytes(raw_dataset)
    train_count = sum(ep.split == "train" for ep in episodes)
    if train_count < 1:
        raise ValueError("no train episodes in pinned dataset")
    run = _read_json(
        run_manifest, expected_run_manifest_sha256,
        label="training_manifest_sha256",
    )
    receipt = _read_json(
        train_receipt, expected_train_receipt_sha256,
        label="training_receipt_sha256",
    )
    model, revision, local_delta = _validate_run_and_delta(
        run, receipt, dataset_sha=dataset_sha, train_count=train_count,
    )
    physical_adapter = load_pinned_adapter(
        adapter_dir, base_model=model, base_revision=revision,
        expected_adapter_config_sha256=expected_adapter_config_sha256,
        expected_adapter_weights_sha256=expected_adapter_weights_sha256,
    )
    # IMPORTANT: do not trust a previously exported holdout audit JSON:
    # independently re-run the five-file + physical adapter verification.
    audit = verify_holdout_chain(
        dataset=dataset, expected_dataset_sha256=dataset_sha,
        prompts=holdout["prompts"],
        projection_manifest=holdout["projection_manifest"],
        predictions=holdout["predictions"],
        capture_manifest=holdout["capture_manifest"],
        expected_prompts_sha256=holdout["expected_prompts_sha256"],
        expected_projection_manifest_sha256=holdout[
            "expected_projection_manifest_sha256"
        ],
        expected_predictions_sha256=holdout["expected_predictions_sha256"],
        expected_capture_manifest_sha256=holdout[
            "expected_capture_manifest_sha256"
        ],
        model=model, model_revision=revision, split=holdout["split"],
        checkpoint_role="GRPO",
        adapter_dir=adapter_dir, require_adapter_files=True,
        expected_adapter_config_sha256=expected_adapter_config_sha256,
        expected_adapter_weights_sha256=expected_adapter_weights_sha256,
        require_reenable_probe=True,
    )
    if (audit["adapter_files_content_verified"] is not True
            or audit["adapter_metadata_matches_files"] is not True
            or audit["capture_prediction_binding_consistent"] is not True
            or audit["local_reenable_probe_content_consistent"] is not True
            or audit["dataset_sha256"] != dataset_sha):
        raise ValueError("independent holdout/adapter evidence inconsistent")
    if (physical_adapter.receipt["adapter_config_sha256"]
            != audit["adapter_config_sha256"]
            or physical_adapter.receipt["adapter_weights_sha256"]
            != audit["adapter_weights_sha256"]):
        raise ValueError("adapter digest changed across independent audit")

    bundle = {
        "schema_version": "sre.grpo.experiment-evidence/v1",
        "status": "CONTENT_LINKED_NOT_EXECUTION_ATTESTED",
        "dataset_sha256": dataset_sha,
        "training_manifest_sha256": expected_run_manifest_sha256,
        "training_receipt_sha256": expected_train_receipt_sha256,
        "model": model,
        "model_revision": revision,
        "adapter_config_sha256": audit["adapter_config_sha256"],
        "adapter_weights_sha256": audit["adapter_weights_sha256"],
        "holdout_prompts_sha256": audit["prompts_sha256"],
        "holdout_capture_sha256": audit["capture_manifest_sha256"],
        "holdout_predictions_sha256": audit["predictions_sha256"],
        "split": audit["split"],
        "holdout_cases": audit["cases"],
        "local_lora_update_global_step": local_delta["global_step"],
        "before_lora_fingerprint_sha256": local_delta["before"]["fingerprint_sha256"],
        "after_lora_fingerprint_sha256": local_delta["after"]["fingerprint_sha256"],
        "training_snapshot_delta_consistent": True,
        "saved_adapter_content_verified": True,
        "independent_holdout_content_verified": True,
        "saved_weights_equal_posttraining_snapshot_verified": False,
        "training_execution_independently_verified": False,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "data_issuer_authenticated": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
    }
    _publish_create_only(result_path, bundle)
    return bundle
