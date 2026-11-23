"""Bounded offline GRPO data and local LoRA weight-delta evidence.

A digest difference is only a locally observed tensor change. It cannot
authenticate model identity, independent execution, source provenance,
real SRE performance, or release approval.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_training import SREEpisode, _MAX_FILE_BYTES, _read_bounded_bytes, load_episodes_bytes

_LORA_NAME = re.compile(r"(.+)\\.lora_([AB])(?:\\.default)?\\.weight\\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\\Z")
_DTYPE_BYTES = {"torch.float16": 2, "torch.bfloat16": 2, "torch.float32": 4}
_MAX_LORA_TENSORS = 4096
_SNAPSHOT_FIELDS = {
    "schema_version", "trainable_tensors", "trainable_elements",
    "trainable_names_sha256", "layout_sha256", "fingerprint_sha256",
}


def freeze_train_dataset(
    path: str | Path, *, expected_dataset_sha256: str | None = None,
) -> tuple[tuple[SREEpisode, ...], str]:
    """Parse only the dataset bytes used for the reported/external digest."""
    source = Path(path)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("train dataset must be a regular non-symlink file")
    raw = _read_bounded_bytes(source, limit=_MAX_FILE_BYTES, name="train dataset")
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
    slots: set[str] = set()
    pairs: dict[str, set[str]] = {}
    for name, tensor in model.named_parameters():
        if type(name) is not str or not name:
            raise ValueError("invalid parameter name")
        if name in names:
            raise ValueError("duplicate parameter names")
        names.add(name)
        if tensor.requires_grad is not True:
            continue
        trainable_count += 1
        if trainable_count > _MAX_LORA_TENSORS:
            raise ValueError("too many trainable LoRA tensors")
        slot = _LORA_NAME.fullmatch(name)
        if slot is None:
            raise ValueError(f"non-LoRA trainable parameter: {name}")
        prefix, kind = slot.groups()
        canonical = f"{prefix}.lora_{kind}.weight"
        if canonical in slots:
            raise ValueError(f"duplicate or aliased LoRA parameter: {name}")
        slots.add(canonical)
        pairs.setdefault(prefix, set()).add(kind)
        shape = tuple(tensor.shape)
        if not shape or any(type(n) is not int or n <= 0 for n in shape):
            raise ValueError(f"invalid LoRA parameter shape: {name}")
        elements = tensor.numel()
        if type(elements) is not int or elements != math.prod(shape):
            raise ValueError(f"invalid LoRA element count: {name}")
        dtype = str(tensor.dtype)
        if dtype not in _DTYPE_BYTES:
            raise ValueError(f"invalid or unsupported LoRA parameter dtype: {name}")
        payload = tensor_bytes(tensor)
        if type(payload) is not bytes or len(payload) != elements * _DTYPE_BYTES[dtype]:
            raise ValueError(f"LoRA tensor byte length mismatch for {name}")
        layouts.append([name, list(shape), dtype, elements])
        samples.append([name, hashlib.sha256(payload).hexdigest()])
        total_elements += elements
    if trainable_count == 0:
        raise ValueError("no trainable LoRA adapter parameters")
    if any(kinds != {"A", "B"} for kinds in pairs.values()):
        raise ValueError("missing LoRA A/B parameter pair")
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



def _validate_snapshot(value: Any, name: str) -> dict[str, Any]:
    """Validate local tensor receipt shape before comparing claimed hashes."""
    if type(value) is not dict or set(value) != _SNAPSHOT_FIELDS:
        raise ValueError(f"invalid {name} LoRA snapshot fields")
    if value["schema_version"] != "sre.grpo.local-lora-snapshot/v1":
        raise ValueError(f"invalid {name} LoRA snapshot version")
    count = value["trainable_tensors"]
    elements = value["trainable_elements"]
    if (type(count) is not int or not 2 <= count <= _MAX_LORA_TENSORS
            or type(elements) is not int or elements < count):
        raise ValueError(f"invalid {name} LoRA snapshot tensor counts")
    for key in ("trainable_names_sha256", "layout_sha256", "fingerprint_sha256"):
        digest = value[key]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ValueError(f"invalid {name} LoRA snapshot SHA256: {key}")
    return value


def verify_local_lora_update(
    before: dict[str, Any], after: dict[str, Any],
    *, global_step: int, max_steps: int,
) -> dict[str, Any]:
    """Fail closed when the trainer returned without a real adapter delta."""
    if (type(global_step) is not int or type(max_steps) is not int
            or not 1 <= global_step <= max_steps):
        raise ValueError("invalid global_step relative to max_steps")
    before = _validate_snapshot(before, "pre-training")
    after = _validate_snapshot(after, "post-training")
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
