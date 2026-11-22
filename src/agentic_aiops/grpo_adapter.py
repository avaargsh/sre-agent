"""Externally pinned local PEFT LoRA safetensors, copied before model loading.

This is a narrow LAB-only contract for unmerged, single-file LoRA adapters.
It rejects pickle weights, symlinks, remote code mapping, arbitrary saved
modules and mutable/unpinned model revision aliases. Local hash validation
is not a model provenance attestation or production authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import stat
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .grpo_import import _verify_pin, _sha
from .grpo_rollout_capture import _REPO, _SHA40
from .grpo_training import _strict_json, _fields

_MAX_CONFIG = 64 * 1024
_MAX_WEIGHTS = 256 * 1024 * 1024
_MAX_HEADER = 1024 * 1024
_DTYPE_BYTES = {"F16": 2, "BF16": 2, "F32": 4}
_LORA_KEY = re.compile(r"(.+)\.lora_([AB])(?:\.default)?\.weight\Z")


@dataclass(frozen=True)
class FrozenAdapter:
    config_raw: bytes
    weights_raw: bytes
    receipt: dict[str, Any]


def _read_regular(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"adapter symlink rejected: {path.name}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError(f"invalid adapter file size or type: {path.name}")
    raw = path.read_bytes()
    if not 0 < len(raw) <= limit:
        raise ValueError(f"invalid adapter file bytes: {path.name}")
    return raw


def _validate_config(raw: bytes, *, base_model: str, base_revision: str) -> dict[str, Any]:
    try:
        config = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid adapter_config UTF-8") from exc
    if type(config) is not dict:
        raise ValueError("adapter_config must be a JSON object")
    if config.get("peft_type") != "LORA":
        raise ValueError("adapter peft_type must be LORA")
    if config.get("task_type") != "CAUSAL_LM":
        raise ValueError("adapter task_type must be CAUSAL_LM")
    if config.get("base_model_name_or_path") != base_model:
        raise ValueError("adapter base_model_name_or_path mismatch")
    revision = config.get("revision")
    if revision is not None and revision != base_revision:
        raise ValueError("adapter revision does not match pinned base model")
    if config.get("auto_mapping") is not None:
        raise ValueError("adapter auto_mapping is not allowed")
    if config.get("modules_to_save") not in (None, []):
        raise ValueError("adapter modules_to_save is not allowed")
    modules = config.get("target_modules")
    if (type(modules) is not list or not modules
            or any(type(m) is not str or m not in {"q_proj", "v_proj"}
                   for m in modules)
            or len(set(modules)) != len(modules)):
        raise ValueError("adapter target_modules must be q_proj and/or v_proj")
    rank = config.get("r")
    if type(rank) is not int or not 1 <= rank <= 128:
        raise ValueError("adapter rank r must be in [1,128]")
    alpha = config.get("lora_alpha")
    if type(alpha) not in (int, float) or not 0 < alpha <= 512:
        raise ValueError("adapter lora_alpha out of bounds")
    for field in ("rank_pattern", "alpha_pattern", "megatron_config",
                  "target_parameters", "trainable_token_indices", "layer_replication"):
        if config.get(field) not in (None, {}, []):
            raise ValueError(f"unsupported adapter {field}")
    for field in ("use_dora", "use_qalora", "lora_bias"):
        if config.get(field) not in (None, False):
            raise ValueError(f"unsupported adapter {field}")
    if config.get("bias") not in (None, "none"):
        raise ValueError("unsupported LoRA bias")
    return config


def _validate_safetensors(raw: bytes) -> tuple[int, tuple[str, ...]]:
    """Inspect self-describing safetensors header without importing torch."""
    if len(raw) < 9:
        raise ValueError("invalid safetensors header")
    header_len = struct.unpack("<Q", raw[:8])[0]
    if not 2 <= header_len <= _MAX_HEADER or 8 + header_len >= len(raw):
        raise ValueError("invalid safetensors header length")
    try:
        header = _strict_json(raw[8:8+header_len].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid safetensors UTF-8 header") from exc
    if type(header) is not dict:
        raise ValueError("safetensors header must be an object")
    payload_length = len(raw) - 8 - header_len
    ranges = []
    groups: dict[str, set[str]] = {}
    count = 0
    for key, value in header.items():
        if key == "__metadata__":
            if (type(value) is not dict
                    or any(type(k) is not str or type(v) is not str
                           for k, v in value.items())):
                raise ValueError("invalid safetensors metadata")
            continue
        matched = _LORA_KEY.fullmatch(key)
        if matched is None:
            raise ValueError(f"non-LoRA tensor found: {key[:80]}")
        prefix, kind = matched.groups()
        groups.setdefault(prefix, set()).add(kind)
        if (type(value) is not dict
                or set(value) != {"dtype", "shape", "data_offsets"}):
            raise ValueError("invalid safetensors tensor header")
        dtype, shape, offsets = value["dtype"], value["shape"], value["data_offsets"]
        if dtype not in _DTYPE_BYTES:
            raise ValueError("unsupported safetensors LoRA dtype")
        if (type(shape) is not list or not shape
                or any(type(x) is not int or not 1 <= x <= 65536 for x in shape)
                or math.prod(shape) > 100_000_000):
            raise ValueError("invalid safetensors tensor shape")
        if (type(offsets) is not list or len(offsets) != 2
                or any(type(x) is not int for x in offsets)):
            raise ValueError("invalid safetensors data_offsets")
        start, end = offsets
        if (start < 0 or end <= start or end > payload_length
                or end - start != math.prod(shape) * _DTYPE_BYTES[dtype]):
            raise ValueError("invalid safetensors tensor offset or length")
        ranges.append((start, end))
        count += 1
        if count > 4096:
            raise ValueError("too many safetensors LoRA tensors")
    if not groups or any(types != {"A", "B"} for types in groups.values()):
        raise ValueError("LoRA A/B parameter pairs required")
    cursor = 0
    for start, end in sorted(ranges):
        if start != cursor:
            raise ValueError("safetensors tensor offsets must cover payload exactly")
        cursor = end
    if cursor != payload_length:
        raise ValueError("safetensors unaccounted payload bytes")
    return count, tuple(sorted(groups))


def load_pinned_adapter(
    directory: str | Path, *, base_model: str, base_revision: str,
    expected_adapter_config_sha256: str,
    expected_adapter_weights_sha256: str,
) -> FrozenAdapter:
    """Read two pinned files once; do not trust or load additional sidecars."""
    if type(base_model) is not str or not _REPO.fullmatch(base_model):
        raise ValueError("adapter base_model must be an explicit Qwen/Qwen3-* ID")
    if type(base_revision) is not str or not _SHA40.fullmatch(base_revision):
        raise ValueError("adapter base_revision must be pinned lowercase 40-character commit")
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("adapter directory cannot be a symlink or missing")
    allowed = {"adapter_config.json", "adapter_model.safetensors", "README.md"}
    actual = {part.name for part in directory.iterdir()}
    if not {"adapter_config.json", "adapter_model.safetensors"}.issubset(actual):
        raise ValueError("missing pinned adapter_config.json or adapter_model.safetensors")
    if actual - allowed:
        raise ValueError(f"unexpected adapter files: {sorted(actual - allowed)}")
    config_raw = _read_regular(directory/"adapter_config.json", limit=_MAX_CONFIG)
    weights_raw = _read_regular(directory/"adapter_model.safetensors", limit=_MAX_WEIGHTS)
    config_sha = _verify_pin(config_raw, expected_adapter_config_sha256,
                             "adapter_config_sha256")
    weights_sha = _verify_pin(weights_raw, expected_adapter_weights_sha256,
                              "adapter_weights_sha256")
    config = _validate_config(
        config_raw, base_model=base_model, base_revision=base_revision,
    )
    tensor_count, modules = _validate_safetensors(weights_raw)
    receipt = {
        "schema_version": "sre.grpo.pinned-lora-adapter/v1",
        "adapter_config_sha256": config_sha,
        "adapter_weights_sha256": weights_sha,
        "base_model": base_model,
        "base_model_revision": base_revision,
        "lora_tensor_count": tensor_count,
        "lora_modules": list(modules),
        "target_modules": sorted(config["target_modules"]),
        "model_attribution_verified": False,
        "training_admission_authorized": False,
        "production_eligible": False,
    }
    return FrozenAdapter(
        config_raw=config_raw, weights_raw=weights_raw, receipt=receipt,
    )


@contextmanager
def staged_pinned_adapter(frozen: FrozenAdapter) -> Iterator[Path]:
    """Copy verified in-memory bytes into a private local PEFT load directory.

    A TOCTOU modification of original input files no longer changes what
    PEFT reads. The local temporary directory itself is not attested against
    same-UID modification or malicious host access.
    """
    if not isinstance(frozen, FrozenAdapter):
        raise ValueError("adapter must be a frozen pinned bundle")
    with tempfile.TemporaryDirectory(prefix="sre-grpo-lora-") as dirname:
        path = Path(dirname)
        for name, raw in (
            ("adapter_config.json", frozen.config_raw),
            ("adapter_model.safetensors", frozen.weights_raw),
        ):
            with (path/name).open("xb") as stream:
                stream.write(raw)
        yield path


_ADAPTER_RECEIPT_FIELDS = {
    "schema_version", "adapter_config_sha256", "adapter_weights_sha256",
    "base_model", "base_model_revision", "lora_tensor_count",
    "lora_modules", "target_modules", "model_attribution_verified",
    "training_admission_authorized", "production_eligible",
}


def validate_adapter_receipt(
    payload: Any, *, base_model: str, base_revision: str,
) -> dict[str, Any]:
    """Validate a capture-supplied adapter receipt without trusting its claims.

    An independent verifier must additionally require externally pinned
    config and weight digests; a self-authored JSON receipt is not proof.
    """
    receipt = _fields(payload, _ADAPTER_RECEIPT_FIELDS, "adapter receipt")
    if receipt["schema_version"] != "sre.grpo.pinned-lora-adapter/v1":
        raise ValueError("unsupported adapter receipt schema_version")
    if receipt["base_model"] != base_model:
        raise ValueError("adapter receipt base_model mismatch")
    if receipt["base_model_revision"] != base_revision:
        raise ValueError("adapter receipt base_model_revision mismatch")
    _sha(receipt["adapter_config_sha256"], "adapter_config_sha256")
    _sha(receipt["adapter_weights_sha256"], "adapter_weights_sha256")
    count = receipt["lora_tensor_count"]
    if type(count) is not int or not 2 <= count <= 4096:
        raise ValueError("adapter lora_tensor_count invalid")
    modules = receipt["lora_modules"]
    if (type(modules) is not list or not modules or len(modules)>2048
            or any(type(x) is not str or not x or len(x)>512 for x in modules)
            or len(set(modules)) != len(modules)):
        raise ValueError("adapter lora_modules invalid")
    target_modules = receipt["target_modules"]
    if (type(target_modules) is not list or not target_modules
            or any(type(x) is not str or x not in {"q_proj", "v_proj"}
                   for x in target_modules)
            or len(set(target_modules)) != len(target_modules)):
        raise ValueError("adapter target_modules invalid")
    for name in ("model_attribution_verified", "training_admission_authorized",
                 "production_eligible"):
        if receipt[name] is not False:
            raise ValueError(f"unverified adapter cannot claim {name}")
    return receipt


def verify_loaded_adapter_weights(
    frozen: FrozenAdapter, adapter_state_dict: Mapping[str, Any],
    status: Any, *, tensor_bytes: Callable[[Any], bytes],
) -> dict[str, Any]:
    """Compare all *loaded* PEFT LoRA tensor bytes with pinned Safetensors.

    The caller must pass peft.get_peft_model_state_dict(model,
    adapter_name="default", save_embedding_layers=False). That public API
    strips the runtime adapter name from keys, matching the save format.
    Use autocast_adapter_dtype=False during load, or dtype conversion
    would make a byte-for-byte check meaningless.

    Runtime and model identity are still NOT independently attested.
    """
    if not isinstance(frozen, FrozenAdapter):
        raise ValueError("frozen adapter required")
    _validate_safetensors(frozen.weights_raw)
    if (getattr(status, "enabled", None) is not True
            or getattr(status, "active_adapters", None) != ["default"]
            or getattr(status, "merged_adapters", None) != []
            or getattr(status, "peft_types", None) != {"default": "LORA"}
            or type(getattr(status, "num_adapter_layers", None)) is not int
            or status.num_adapter_layers < 1
            or type(getattr(status, "trainable_params", None)) is not int
            or status.trainable_params != 0):
        raise ValueError("adapter status not single active unmerged frozen LoRA")
    if not isinstance(adapter_state_dict, Mapping):
        raise ValueError("loaded LoRA tensor set must be a mapping")
    raw = frozen.weights_raw
    header_size = struct.unpack("<Q", raw[:8])[0]
    header = _strict_json(raw[8:8+header_size].decode("utf-8"))
    source_names = {k for k in header if k != "__metadata__"}
    if set(adapter_state_dict) != source_names:
        raise ValueError("loaded LoRA tensor set differs from pinned checkpoint")
    types = {"F16": "torch.float16", "BF16": "torch.bfloat16",
             "F32": "torch.float32"}
    for name in sorted(source_names):
        expected = header[name]
        actual = adapter_state_dict[name]
        if str(getattr(actual, "dtype", None)) != types[expected["dtype"]]:
            raise ValueError(f"loaded LoRA dtype differs for {name}")
        if tuple(getattr(actual, "shape", ())) != tuple(expected["shape"]):
            raise ValueError(f"loaded LoRA shape differs for {name}")
        content = tensor_bytes(actual)
        start, end = expected["data_offsets"]
        if type(content) is not bytes or not hmac.compare_digest(
            content, raw[8+header_size+start:8+header_size+end],
        ):
            raise ValueError(f"loaded LoRA weight bytes differ for {name}")
    return {
        "schema_version": "sre.grpo.local-loaded-lora/v1",
        "adapter_weights_sha256": frozen.receipt["adapter_weights_sha256"],
        "lora_tensors_checked": len(source_names),
        "local_loaded_weights_equal_pinned": True,
        "model_runtime_independently_verified": False,
        "model_attribution_verified": False,
        "production_eligible": False,
    }
