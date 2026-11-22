"""CPU-only per-tensor link from a claimed post-step LoRA snapshot to saved Safetensors.

This proves content consistency *conditional on* the producer-supplied tensor
map and externally pinned Adapter bytes. It does not authenticate the model,
the trainer, optimizer steps, issuer identity, or GPU execution.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import struct
from pathlib import Path
from typing import Any, Callable, Mapping

from .grpo_adapter import FrozenAdapter, _LORA_KEY, load_pinned_adapter
from .grpo_import import _sha, _verify_pin
from .grpo_train_proof import _encode, snapshot_lora_parameters, verify_local_lora_update
from .grpo_training import _fields, _strict_json

_SCHEMA = "sre.grpo.post-save-tensor-map/v1"
_MAX_TENSORS = 4096
_MAX_MANIFEST = 1024 * 1024
_DTYPES = {"torch.float16": ("F16", 2),
           "torch.bfloat16": ("BF16", 2),
           "torch.float32": ("F32", 4)}
_FIELDS = {
    "schema_version", "base_model", "base_model_revision",
    "adapter_config_sha256", "adapter_weights_sha256", "post_snapshot",
    "tensors", "local_saved_weights_equal_claimed_post_snapshot",
    "training_execution_independently_verified",
    "optimizer_step_independently_verified", "production_eligible",
}
_ROW_FIELDS = {
    "runtime_name", "save_name", "shape", "dtype", "byte_sha256",
}


def _saved_name(name: Any) -> str:
    if type(name) is not str or not 1 <= len(name) <= 512:
        raise ValueError("invalid runtime_name")
    match = _LORA_KEY.fullmatch(name)
    if match is None:
        raise ValueError(f"not a supported LoRA runtime_name: {name[:80]}")
    prefix, kind = match.groups()
    # PEFT runtime usually includes ".default", whereas exported
    # checkpoints omit it. Accept either form while requiring a unique
    # canonical saved slot (aliases may not double-count an A/B tensor).
    return f"{prefix}.lora_{kind}.weight"


def _validate_entries(rows: Any) -> tuple[list[list[Any]], list[list[str]], list[str]]:
    if type(rows) is not list or not 2 <= len(rows) <= _MAX_TENSORS:
        raise ValueError("invalid LoRA tensor set size")
    layouts: list[list[Any]] = []
    samples: list[list[str]] = []
    saved_names: list[str] = []
    runtime_names: list[str] = []
    for payload in rows:
        row = _fields(payload, _ROW_FIELDS, "LoRA tensor map row")
        original = row["runtime_name"]
        saved = _saved_name(original)
        if row["save_name"] != saved:
            raise ValueError("invalid LoRA save_name mapping")
        dims = row["shape"]
        if (type(dims) is not list or len(dims) != 2
                or any(type(n) is not int or not 1 <= n <= 65536 for n in dims)):
            raise ValueError("invalid LoRA tensor shape")
        dtype = row["dtype"]
        if type(dtype) is not str or dtype not in _DTYPES:
            raise ValueError("invalid LoRA tensor dtype")
        digest = _sha(row["byte_sha256"], "LoRA tensor byte_sha256")
        runtime_names.append(original)
        saved_names.append(saved)
        layouts.append([original, dims, dtype, math.prod(dims)])
        samples.append([original, digest])
    if (len(set(runtime_names)) != len(rows)
            or len(set(saved_names)) != len(rows)):
        raise ValueError("duplicate semantic LoRA tensor slot")
    if saved_names != sorted(saved_names):
        raise ValueError("LoRA tensor map must use sorted save_name order")
    # Require both A and B for each target, not merely two arbitrary rows.
    groups: dict[str, set[str]] = {}
    for saved in saved_names:
        match = _LORA_KEY.fullmatch(saved)
        assert match is not None
        prefix, kind = match.groups()
        groups.setdefault(prefix, set()).add(kind)
    if any(kinds != {"A", "B"} for kinds in groups.values()):
        raise ValueError("LoRA tensor set must contain A/B pairs")
    layouts.sort(key=lambda row: row[0])
    samples.sort(key=lambda row: row[0])
    return layouts, samples, saved_names


def _expected_snapshot(
    layouts: list[list[Any]], samples: list[list[str]],
) -> dict[str, Any]:
    return {
        "schema_version": "sre.grpo.local-lora-snapshot/v1",
        "trainable_tensors": len(layouts),
        "trainable_elements": sum(row[3] for row in layouts),
        "trainable_names_sha256": hashlib.sha256(
            _encode([row[0] for row in layouts])
        ).hexdigest(),
        "layout_sha256": hashlib.sha256(_encode(layouts)).hexdigest(),
        "fingerprint_sha256": hashlib.sha256(
            _encode([layouts, samples])
        ).hexdigest(),
    }


def capture_posttraining_tensor_map(
    model: Any, *, base_model: str, base_revision: str,
    post_snapshot: dict[str, Any], adapter_config_sha256: str,
    adapter_weights_sha256: str,
    tensor_bytes: Callable[[Any], bytes],
) -> dict[str, Any]:
    """Record exact in-memory LoRA bytes after a reported optimizer step.

    Only trainable named LoRA parameters are admitted. This map has no
    positive saved-weight verification flag until a separate physical file
    inspection, which must be performed before any local receipt publication.
    """
    _sha(adapter_config_sha256, "adapter_config_sha256")
    _sha(adapter_weights_sha256, "adapter_weights_sha256")
    computed = snapshot_lora_parameters(model, tensor_bytes=tensor_bytes)
    if computed != post_snapshot:
        raise ValueError("post_snapshot changed before tensor map capture")
    rows = []
    for name, tensor in model.named_parameters():
        if tensor.requires_grad is not True:
            continue
        save_name = _saved_name(name)
        dims = list(tensor.shape)
        dtype = str(tensor.dtype)
        raw = tensor_bytes(tensor)
        if (dtype not in _DTYPES
                or type(raw) is not bytes or len(dims) != 2
                or len(raw) != math.prod(dims) * _DTYPES[dtype][1]):
            raise ValueError("invalid LoRA tensor dtype/shape/bytes")
        rows.append({
            "runtime_name": name,
            "save_name": save_name,
            "shape": dims,
            "dtype": dtype,
            "byte_sha256": hashlib.sha256(raw).hexdigest(),
        })
    rows.sort(key=lambda row: row["save_name"])
    layouts, samples, _ = _validate_entries(rows)
    if _expected_snapshot(layouts, samples) != post_snapshot:
        raise ValueError("post_snapshot mismatch across repeated tensor reads")
    return {
        "schema_version": _SCHEMA,
        "base_model": base_model,
        "base_model_revision": base_revision,
        "adapter_config_sha256": adapter_config_sha256,
        "adapter_weights_sha256": adapter_weights_sha256,
        "post_snapshot": post_snapshot,
        "tensors": rows,
        "local_saved_weights_equal_claimed_post_snapshot": False,
        "training_execution_independently_verified": False,
        "optimizer_step_independently_verified": False,
        "production_eligible": False,
    }


def verify_posttraining_tensor_map(
    manifest: Any, frozen: FrozenAdapter, *,
    expected_post_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compare the exact pinned saved weight bytes to each claimed tensor.

    The post-optimizer snapshot is itself producer-supplied. Matching its
    map to saved files is *not* proof the optimizer actually updated them.
    """
    if not isinstance(frozen, FrozenAdapter):
        raise ValueError("pinned physical Adapter is required")
    data = _fields(manifest, _FIELDS, "post-save tensor manifest")
    if data["schema_version"] != _SCHEMA:
        raise ValueError("unsupported post-save tensor manifest schema")
    for name in (
        "training_execution_independently_verified",
        "optimizer_step_independently_verified", "production_eligible",
        "local_saved_weights_equal_claimed_post_snapshot",
    ):
        if data[name] is not False:
            raise ValueError(f"tensor manifest authority/status {name} must remain false")
    if data["base_model"] != frozen.receipt["base_model"]:
        raise ValueError("base_model does not match saved Adapter")
    if data["base_model_revision"] != frozen.receipt["base_model_revision"]:
        raise ValueError("base_model_revision does not match saved Adapter")
    for field in ("adapter_config_sha256", "adapter_weights_sha256"):
        if data[field] != frozen.receipt[field]:
            raise ValueError(f"{field} differs from saved Adapter")
    layouts, samples, names = _validate_entries(data["tensors"])
    computed = _expected_snapshot(layouts, samples)
    if data["post_snapshot"] != computed or expected_post_snapshot != computed:
        raise ValueError("post_snapshot fingerprint inconsistent with tensor map")
    weights = frozen.weights_raw
    header_len = struct.unpack("<Q", weights[:8])[0]
    head = _strict_json(weights[8:8+header_len].decode("utf-8"))
    source_names = set(head) - {"__metadata__"}
    if source_names != set(names):
        raise ValueError("saved LoRA tensor set differs from post-training map")
    payload_offset = 8+header_len
    for row in data["tensors"]:
        hdr = head[row["save_name"]]
        if hdr["shape"] != row["shape"] or hdr["dtype"] != _DTYPES[row["dtype"]][0]:
            raise ValueError("saved LoRA tensor shape/dtype differs from post snapshot")
        start, end = hdr["data_offsets"]
        digest = hashlib.sha256(weights[payload_offset+start:payload_offset+end]).hexdigest()
        if not hmac.compare_digest(digest, row["byte_sha256"]):
            raise ValueError("saved LoRA tensor bytes differ from post snapshot byte digest")
    return {
        "schema_version": "sre.grpo.post-save-tensor-audit/v1",
        "adapter_weights_sha256": frozen.receipt["adapter_weights_sha256"],
        "post_snapshot_fingerprint_sha256": computed["fingerprint_sha256"],
        "tensors_compared": len(names),
        "local_saved_weights_equal_claimed_post_snapshot": True,
        "training_execution_independently_verified": False,
        "optimizer_step_independently_verified": False,
        "model_attribution_verified": False,
        "production_eligible": False,
    }


def verify_pinned_tensor_map(
    path: str | Path, *, expected_manifest_sha256: str,
    adapter_dir: str | Path,
    expected_adapter_config_sha256: str,
    expected_adapter_weights_sha256: str,
    base_model: str, base_revision: str,
    expected_post_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Offline audit with external file pins, no torch/PEFT/CUDA imports."""
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("tensor manifest must be a regular non-symlink file")
    if not 0 < file.stat().st_size <= _MAX_MANIFEST:
        raise ValueError("tensor manifest empty or oversized")
    raw = file.read_bytes()
    if not 0 < len(raw) <= _MAX_MANIFEST:
        raise ValueError("tensor manifest empty or oversized")
    _verify_pin(raw, expected_manifest_sha256, "tensor_manifest_sha256")
    try:
        doc = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid tensor manifest UTF-8") from exc
    frozen = load_pinned_adapter(
        adapter_dir, base_model=base_model, base_revision=base_revision,
        expected_adapter_config_sha256=expected_adapter_config_sha256,
        expected_adapter_weights_sha256=expected_adapter_weights_sha256,
    )
    return verify_posttraining_tensor_map(
        doc, frozen, expected_post_snapshot=expected_post_snapshot,
    )


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


def verify_pinned_tensor_map_with_training_receipt(
    *, tensor_map: str | Path, expected_tensor_map_sha256: str,
    train_receipt: str | Path, expected_train_receipt_sha256: str,
    expected_dataset_sha256: str,
    adapter_dir: str | Path,
    expected_adapter_config_sha256: str,
    expected_adapter_weights_sha256: str,
    base_model: str, base_revision: str,
) -> dict[str, Any]:
    """CPU-only cross-check of pinned local train claim vs saved LoRA bytes.

    This can disprove a claimed train-output link. It cannot prove a real
    optimizer step ran: producer controls the training receipt and tensor map.
    """
    digest = _sha(expected_dataset_sha256, "dataset_sha256")
    path = Path(train_receipt)
    if path.is_symlink() or not path.is_file():
        raise ValueError("training receipt must be a regular non-symlink file")
    if not 0 < path.stat().st_size <= _MAX_MANIFEST:
        raise ValueError("training receipt empty or oversized")
    raw = path.read_bytes()
    if not 0 < len(raw) <= _MAX_MANIFEST:
        raise ValueError("training receipt empty or oversized")
    _verify_pin(raw, expected_train_receipt_sha256, "training_receipt_sha256")
    try:
        doc = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid training receipt UTF-8") from exc
    receipt = _fields(doc, _TRAIN_RECEIPT_FIELDS, "training receipt")
    if receipt["schema_version"] != "sre.grpo.local-training-receipt/v1":
        raise ValueError("invalid training receipt schema")
    if receipt["dataset_sha256"] != digest:
        raise ValueError("dataset_sha256 differs from local train receipt")
    if receipt["model"] != base_model:
        raise ValueError("model differs from local train receipt")
    if (receipt["model_revision"] != base_revision
            or receipt["tokenizer_revision"] != base_revision):
        raise ValueError("model_revision differs from local train receipt")
    if receipt["training_scope"] != "LAB_ONLY_UNVERIFIED":
        raise ValueError("training scope cannot be promoted")
    for field in ("model_runtime_independently_verified",
                  "data_issuer_authenticated", "training_admission_authorized",
                  "production_eligible"):
        if receipt[field] is not False:
            raise ValueError(f"train receipt authority {field} cannot be promoted")
    update = _fields(receipt["local_lora_update"], _UPDATE_FIELDS, "local_lora_update")
    claimed = verify_local_lora_update(
        update["before"], update["after"],
        global_step=update["global_step"], max_steps=update["max_steps"],
    )
    if claimed != update:
        raise ValueError("local_lora_update fields do not match recomputed delta")
    audit = verify_pinned_tensor_map(
        tensor_map, expected_manifest_sha256=expected_tensor_map_sha256,
        adapter_dir=adapter_dir,
        expected_adapter_config_sha256=expected_adapter_config_sha256,
        expected_adapter_weights_sha256=expected_adapter_weights_sha256,
        base_model=base_model, base_revision=base_revision,
        expected_post_snapshot=update["after"],
    )
    return {
        **audit,
        "schema_version": "sre.grpo.post-save-train-link-audit/v1",
        "training_receipt_sha256": expected_train_receipt_sha256,
        "tensor_map_sha256": expected_tensor_map_sha256,
        "dataset_sha256": digest,
        "training_receipt_content_consistent": True,
        "training_execution_independently_verified": False,
        "optimizer_step_independently_verified": False,
        "production_eligible": False,
    }
