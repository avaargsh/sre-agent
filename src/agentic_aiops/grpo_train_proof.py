"""Bounded offline GRPO data and local LoRA weight-delta evidence.

A digest difference is only a locally observed tensor change. It cannot
authenticate model identity, independent execution, source provenance,
real SRE performance, or release approval.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_training import SREEpisode, load_episodes_bytes


def freeze_train_dataset(
    path: str | Path, *, expected_dataset_sha256: str | None = None,
) -> tuple[tuple[SREEpisode, ...], str]:
    """Parse only the dataset bytes used for the reported/external digest."""
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_dataset_sha256 is not None:
        digest = _verify_pin(raw, expected_dataset_sha256, "dataset_sha256")
    return load_episodes_bytes(raw), digest


def _encode(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def snapshot_lora_parameters(
    model: Any, *, tensor_bytes: Callable[[Any], bytes],
) -> dict[str, Any]:
    """Digest only PEFT LoRA trainable parameters, no weight bytes in receipt.

    The caller supplies the tensor raw-byte serializer so this module stays
    independent of torch in CPU-only unit tests. In a CUDA experiment this
    must serialize the exact contiguous raw tensor bytes, not repr or values
    rounded through float16 conversion.
    """
    layouts: list[list[Any]] = []
    samples: list[list[str]] = []
    trainable_count = 0
    total_elements = 0
    names: set[str] = set()
    for name, tensor in model.named_parameters():
        if type(name) is not str or not name:
            raise ValueError("invalid parameter name")
        if name in names:
            raise ValueError("duplicate parameter names")
        names.add(name)
        if tensor.requires_grad is not True:
            continue
        trainable_count += 1
        if not any(part.startswith("lora_") for part in name.split(".")):
            raise ValueError(f"non-LoRA trainable parameter: {name}")
        shape = tuple(tensor.shape)
        if not shape or any(type(n) is not int or n <= 0 for n in shape):
            raise ValueError(f"invalid LoRA parameter shape: {name}")
        elements = tensor.numel()
        if type(elements) is not int or elements != math.prod(shape):
            raise ValueError(f"invalid LoRA element count: {name}")
        dtype = str(tensor.dtype)
        if not dtype or len(dtype) > 64:
            raise ValueError(f"invalid LoRA parameter dtype: {name}")
        payload = tensor_bytes(tensor)
        if type(payload) is not bytes or not payload:
            raise ValueError(f"empty or invalid LoRA parameter bytes: {name}")
        layouts.append([name, list(shape), dtype, elements])
        samples.append([name, hashlib.sha256(payload).hexdigest()])
        total_elements += elements
    if trainable_count == 0:
        raise ValueError("no trainable LoRA adapter parameters")
    layouts.sort(key=lambda row: row[0])
    samples.sort(key=lambda row: row[0])
    return {
        "schema_version": "sre.grpo.local-lora-snapshot/v1",
        "trainable_tensors": trainable_count,
        "trainable_elements": total_elements,
        "trainable_names_sha256": hashlib.sha256(
            _encode([item[0] for item in layouts])
        ).hexdigest(),
        "layout_sha256": hashlib.sha256(_encode(layouts)).hexdigest(),
        "fingerprint_sha256": hashlib.sha256(
            _encode([layouts, samples])
        ).hexdigest(),
    }


def verify_local_lora_update(
    before: dict[str, Any], after: dict[str, Any],
    *, global_step: int, max_steps: int,
) -> dict[str, Any]:
    """Fail closed when the trainer returned without a real adapter delta."""
    if (type(global_step) is not int or type(max_steps) is not int
            or not 1 <= global_step <= max_steps):
        raise ValueError("invalid global_step relative to max_steps")
    if before.get("schema_version") != "sre.grpo.local-lora-snapshot/v1":
        raise ValueError("invalid pre-training LoRA snapshot")
    if after.get("schema_version") != "sre.grpo.local-lora-snapshot/v1":
        raise ValueError("invalid post-training LoRA snapshot")
    for field in ("trainable_tensors", "trainable_elements",
                  "trainable_names_sha256"):
        if before.get(field) != after.get(field):
            raise ValueError("LoRA trainable parameter set changed")
    if before.get("layout_sha256") != after.get("layout_sha256"):
        raise ValueError("LoRA parameter layout changed")
    if before.get("fingerprint_sha256") == after.get("fingerprint_sha256"):
        raise ValueError("LoRA tensors unchanged after optimizer step")
    return {
        "schema_version": "sre.grpo.local-lora-update/v1",
        "status": "LOCAL_LORA_DELTA_OBSERVED_NOT_INDEPENDENTLY_VERIFIED",
        "before": before,
        "after": after,
        "global_step": global_step,
        "max_steps": max_steps,
        "local_lora_changed": True,
        "model_runtime_independently_verified": False,
        "training_admission_authorized": False,
        "production_eligible": False,
    }
