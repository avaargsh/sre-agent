"""Verify *loaded PEFT state* against pinned safetensors, not just a load call.

All tests are CPU fixtures and do not attest real GPU inference.
"""
from types import SimpleNamespace

import pytest

from agentic_aiops.grpo_adapter import (
    load_pinned_adapter,
    verify_loaded_adapter_weights,
)
from test_grpo_adapter import MODEL, REV, create_adapter


class FakeTensor:
    def __init__(self, raw, *, dtype="torch.float16", shape=(2, 2)):
        self.raw = raw
        self.dtype = dtype
        self.shape = shape


def setup(tmp_path):
    adapter_dir, pins = create_adapter(tmp_path)
    frozen = load_pinned_adapter(
        adapter_dir, base_model=MODEL, base_revision=REV, **pins
    )
    prefix = "base_model.model.model.layers.0.self_attn.q_proj"
    tensors = {
        prefix + ".lora_A.weight": FakeTensor(bytes(range(8))),
        prefix + ".lora_B.weight": FakeTensor(bytes(range(8, 16))),
    }
    status = SimpleNamespace(
        enabled=True,
        active_adapters=["default"],
        merged_adapters=[],
        peft_types={"default": "LORA"},
        num_adapter_layers=1,
        trainable_params=0,
    )
    return frozen, tensors, status


def check(frozen, tensors, status):
    return verify_loaded_adapter_weights(
        frozen, tensors, status, tensor_bytes=lambda value: value.raw
    )


def test_exact_local_loaded_lora_bits_are_equal_to_frozen_checkpoint(tmp_path):
    frozen, tensors, status = setup(tmp_path)
    result = check(frozen, tensors, status)
    assert result["schema_version"] == "sre.grpo.local-loaded-lora/v1"
    assert result["lora_tensors_checked"] == 2
    assert result["adapter_weights_sha256"] == frozen.receipt["adapter_weights_sha256"]
    assert result["local_loaded_weights_equal_pinned"] is True
    assert result["model_runtime_independently_verified"] is False
    assert result["model_attribution_verified"] is False


def test_wrong_lora_bytes_even_if_peft_reported_success_rejected(tmp_path):
    frozen, tensors, status = setup(tmp_path)
    tensors[next(iter(tensors))].raw = b"wrong123"
    with pytest.raises(ValueError, match="weight bytes"):
        check(frozen, tensors, status)


def test_missing_or_extra_lora_key_rejected(tmp_path):
    frozen, tensors, status = setup(tmp_path)
    tensors.pop(next(iter(tensors)))
    with pytest.raises(ValueError, match="tensor set"):
        check(frozen, tensors, status)
    second = tmp_path / "second"
    second.mkdir()
    _, tensors, status = setup(second)
    tensors["base_model.model.extra.lora_A.weight"] = FakeTensor(b"extra123")
    with pytest.raises(ValueError, match="tensor set"):
        check(frozen, tensors, status)


@pytest.mark.parametrize("field,value", [
    ("enabled", False),
    ("enabled", "irregular"),
    ("active_adapters", []),
    ("active_adapters", ["other"]),
    ("merged_adapters", ["default"]),
    ("peft_types", {"default": "OTHER"}),
    ("num_adapter_layers", 0),
    ("trainable_params", 1),
])
def test_inactive_merged_unexpected_or_trainable_adapter_rejected(
    tmp_path, field, value
):
    frozen, tensors, status = setup(tmp_path)
    setattr(status, field, value)
    with pytest.raises(ValueError, match="adapter status"):
        check(frozen, tensors, status)


def test_wrong_lora_dtype_or_shape_rejected(tmp_path):
    frozen, tensors, status = setup(tmp_path)
    next(iter(tensors.values())).dtype = "torch.float32"
    with pytest.raises(ValueError, match="dtype"):
        check(frozen, tensors, status)
    second = tmp_path / "second"
    second.mkdir()
    _, tensors, status = setup(second)
    next(iter(tensors.values())).shape = (4, 1)
    with pytest.raises(ValueError, match="shape"):
        check(frozen, tensors, status)


def test_peft_loader_returned_no_adapter_weights_fails_closed(tmp_path):
    frozen, _, status = setup(tmp_path)
    with pytest.raises(ValueError, match="tensor set"):
        check(frozen, {}, status)
