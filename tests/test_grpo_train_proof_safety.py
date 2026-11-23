"""Fail-closed CPU-only GRPO local LoRA evidence edge cases.

These tests assert shape/dtype/byte integrity of caller-supplied snapshots,
not real training provenance.
"""
import hashlib
from pathlib import Path

import pytest

from agentic_aiops.grpo_train_proof import (
    freeze_train_dataset, snapshot_lora_parameters, verify_local_lora_update,
)
from test_grpo_train_proof import Parameter, Model, capture, dataset


def lora_model(a=b"12345678", b=b"abcdefgh", *, dtype="torch.float16",
               shape=(2, 2), name="model.layers.0.q_proj"):
    return Model([
        (f"{name}.lora_A.default.weight",
         Parameter(a, dtype=dtype, shape=shape)),
        (f"{name}.lora_B.default.weight",
         Parameter(b, dtype=dtype, shape=shape)),
    ])


def snapshot(model):
    return snapshot_lora_parameters(model, tensor_bytes=lambda p: p.content)


@pytest.mark.parametrize("payload", [b"short", b"too-long-12345", b""])
def test_snapshot_rejects_incorrect_raw_tensor_byte_length(payload):
    with pytest.raises(ValueError, match="tensor bytes|byte length"):
        snapshot(lora_model(a=payload))


@pytest.mark.parametrize("dtype", ["torch.float64", "untyped", "torch.int8"])
def test_snapshot_rejects_unsupported_dtype(dtype):
    with pytest.raises(ValueError, match="dtype"):
        snapshot(lora_model(dtype=dtype))


def test_snapshot_accepts_exact_raw_tensor_size_and_proves_only_local_delta():
    before = snapshot(lora_model())
    after = snapshot(lora_model(b=b"abcdefg!"))
    assert before["fingerprint_sha256"] != after["fingerprint_sha256"]
    receipt = verify_local_lora_update(before, after, global_step=1, max_steps=1)
    assert receipt["local_lora_changed"] is True
    assert receipt["model_runtime_independently_verified"] is False
    assert receipt["training_admission_authorized"] is False
    assert receipt["production_eligible"] is False


@pytest.mark.parametrize("name", [
    "model.layers.0.q_proj.lora_fake.default.weight",
    "model.layers.0.q_proj.lora_A.default.bias",
    "lora_A.default.weight",
])
def test_nonstandard_trainable_lora_parameter_cannot_forge_snapshot(name):
    m = Model([(name, Parameter(b"12345678")),
               ("model.layers.0.q_proj.lora_B.default.weight",
                Parameter(b"abcdefgh"))])
    with pytest.raises(ValueError, match="LoRA|parameter"):
        snapshot(m)


def test_aliasing_same_lora_slot_rejected():
    m = lora_model()
    m.params.append(("model.layers.0.q_proj.lora_A.weight",
                     Parameter(b"87654321")))
    with pytest.raises(ValueError, match="duplicate|alias"):
        snapshot(m)


def test_missing_lora_a_or_b_matrix_rejected():
    m = lora_model()
    m.params.pop()
    with pytest.raises(ValueError, match="pair|LoRA"):
        snapshot(m)


@pytest.mark.parametrize("field,value", [
    ("fingerprint_sha256", "A" * 64),
    ("fingerprint_sha256", 10),
    ("fingerprint_sha256", "not-a-sha"),
    ("trainable_tensors", True),
    ("trainable_elements", 0),
    ("trainable_names_sha256", "f" * 63),
    ("layout_sha256", "x" * 64),
])
def test_malformed_local_snapshot_never_authorizes_delta(field, value):
    before = capture()
    after = capture(changed=True)
    before[field] = value
    with pytest.raises(ValueError, match="snapshot|SHA|LoRA"):
        verify_local_lora_update(before, after, global_step=1, max_steps=1)


def test_unknown_snapshot_field_rejected():
    before = capture()
    after = capture(changed=True)
    before["production_eligible"] = True
    with pytest.raises(ValueError, match="snapshot|fields"):
        verify_local_lora_update(before, after, global_step=1, max_steps=1)


def test_freeze_rejects_symlinked_train_dataset(tmp_path):
    path, digest = dataset(tmp_path)
    link = tmp_path / "aliased.jsonl"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symlink|regular"):
        freeze_train_dataset(link, expected_dataset_sha256=digest)


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX only")
def test_freeze_rejects_fifo_without_blocking(tmp_path):
    import os
    fake = tmp_path / "train-pipe.jsonl"
    os.mkfifo(fake)
    with pytest.raises(ValueError, match="regular"):
        freeze_train_dataset(fake, expected_dataset_sha256="a" * 64)


def test_oversized_train_input_rejected_before_unbounded_read(tmp_path, monkeypatch):
    target = tmp_path / "too-big.jsonl"
    with target.open("wb") as stream:
        stream.truncate(4 * 1024 * 1024 + 1)
    def unbounded(_path):
        raise AssertionError("unbounded Path.read_bytes used")
    monkeypatch.setattr(Path, "read_bytes", unbounded)
    with pytest.raises(ValueError, match="oversized"):
        freeze_train_dataset(target, expected_dataset_sha256="a" * 64)
