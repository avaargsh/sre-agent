"""CPU-only training input and LoRA update evidence contracts.

No torch, GPU, PEFT, TRL, model weights, or Kubernetes required here.
"""
import hashlib
import json
from pathlib import Path

import pytest

from agentic_aiops.grpo_train_proof import (
    freeze_train_dataset,
    snapshot_lora_parameters,
    verify_local_lora_update,
)
from test_grpo_training import episode


def dataset(tmp_path):
    path = tmp_path / "train.jsonl"
    path.write_text(json.dumps(episode()) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_data_is_parsed_from_same_pinned_bytes_without_reopening(tmp_path, monkeypatch):
    path, sha = dataset(tmp_path)
    orig = Path.read_bytes
    reads = []

    def read_once(p):
        if p == path:
            reads.append(p)
        return orig(p)

    monkeypatch.setattr(Path, "read_bytes", read_once)
    episodes, found_sha = freeze_train_dataset(
        path, expected_dataset_sha256=sha,
    )
    assert found_sha == sha
    assert len(episodes) == 1
    assert episodes[0].oracle.root_cause_id == "oom_killed"
    assert len(reads) == 1


def test_bad_external_sha_fails_before_training(tmp_path):
    path, _ = dataset(tmp_path)
    with pytest.raises(ValueError, match="dataset_sha256"):
        freeze_train_dataset(path, expected_dataset_sha256="0" * 64)
    _, sha = freeze_train_dataset(path)
    assert len(sha) == 64


class Parameter:
    def __init__(self, content, *, requires_grad=True, dtype="torch.float16",
                 shape=(2, 2)):
        self.content = content
        self.requires_grad = requires_grad
        self.dtype = dtype
        self.shape = shape
        self.numel_value = 4

    def numel(self):
        return self.numel_value


class Model:
    def __init__(self, params):
        self.params = params

    def named_parameters(self):
        return iter(self.params)


def capture(changed=False):
    params = [
        ("base.weight", Parameter(b"base", requires_grad=False)),
        ("model.layers.0.q_proj.lora_A.default.weight", Parameter(b"first")),
        ("model.layers.0.q_proj.lora_B.default.weight",
         Parameter(b"second+" if changed else b"second")),
    ]
    return snapshot_lora_parameters(
        Model(params), tensor_bytes=lambda param: param.content,
    )


def test_local_change_is_reported_but_never_promoted_to_proof():
    before, after = capture(), capture(changed=True)
    assert before["trainable_tensors"] == 2
    assert before["trainable_elements"] == 8
    assert before["fingerprint_sha256"] != after["fingerprint_sha256"]
    assert before["trainable_names_sha256"] == after["trainable_names_sha256"]
    report = verify_local_lora_update(
        before, after, global_step=1, max_steps=10
    )
    assert report["status"] == "LOCAL_LORA_DELTA_OBSERVED_NOT_INDEPENDENTLY_VERIFIED"
    assert report["local_lora_changed"] is True
    assert report["model_runtime_independently_verified"] is False
    assert report["training_admission_authorized"] is False
    assert report["production_eligible"] is False


def test_trainer_return_without_any_lora_change_is_fail_closed():
    with pytest.raises(ValueError, match="unchanged"):
        verify_local_lora_update(capture(), capture(), global_step=10, max_steps=10)
    with pytest.raises(ValueError, match="global_step"):
        verify_local_lora_update(capture(), capture(changed=True), global_step=0, max_steps=10)
    with pytest.raises(ValueError, match="global_step"):
        verify_local_lora_update(capture(), capture(changed=True), global_step=True, max_steps=10)
    with pytest.raises(ValueError, match="global_step"):
        verify_local_lora_update(capture(), capture(changed=True), global_step=11, max_steps=10)


def test_no_trainable_lora_weights_or_non_adapter_weights_rejected():
    for params, reason in [
        ([("base.weight", Parameter(b"0", requires_grad=False))], "LoRA"),
        ([("base.weight", Parameter(b"0"))], "non-LoRA"),
        ([("model.q.lora_A.default.weight", Parameter(b"0")),
          ("model.q.lora_A.default.weight", Parameter(b"1"))], "duplicate"),
    ]:
        with pytest.raises(ValueError, match=reason):
            snapshot_lora_parameters(
                Model(params), tensor_bytes=lambda param: param.content
            )


def test_different_lora_parameter_names_or_shapes_cannot_fake_delta():
    before = capture()
    params = [
        ("model.layers.0.q_proj.lora_A.default.weight", Parameter(b"first")),
        ("model.layers.0.v_proj.lora_B.default.weight", Parameter(b"second+")),
    ]
    after = snapshot_lora_parameters(
        Model(params), tensor_bytes=lambda param: param.content
    )
    with pytest.raises(ValueError, match="parameter set"):
        verify_local_lora_update(before, after, global_step=1, max_steps=10)
    params = [
        ("model.layers.0.q_proj.lora_A.default.weight", Parameter(b"first", shape=(4, 1))),
        ("model.layers.0.q_proj.lora_B.default.weight", Parameter(b"second+")),
    ]
    after = snapshot_lora_parameters(
        Model(params), tensor_bytes=lambda param: param.content
    )
    with pytest.raises(ValueError, match="parameter layout"):
        verify_local_lora_update(before, after, global_step=1, max_steps=10)
