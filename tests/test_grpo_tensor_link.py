"""CPU-only tensor-level LoRA post-save integrity; NOT optimizer attestation."""

import hashlib
import json
import struct

import pytest

from agentic_aiops.grpo_tensor_link import (
    capture_posttraining_tensor_map,
    verify_posttraining_tensor_map,
    verify_pinned_tensor_map,
)
from agentic_aiops.grpo_adapter import load_pinned_adapter
from agentic_aiops.grpo_train_proof import snapshot_lora_parameters
from test_grpo_adapter import MODEL, REV, create_adapter, safetensors_bytes


PREFIX = "base_model.model.model.layers.0.self_attn.q_proj"


class Tensor:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.requires_grad = True
        self.dtype = "torch.float16"
        self.shape = (2, 2)

    def numel(self):
        return 4


class Model:
    def __init__(self, *, mutate=False, missing=False, duplicate=False):
        self.params = [
            (f"{PREFIX}.lora_A.default.weight",
             Tensor(bytes(range(8)) if not mutate else b"badbytes")),
            (f"{PREFIX}.lora_B.default.weight", Tensor(bytes(range(8, 16)))),
        ]
        if missing:
            self.params.pop()
        if duplicate:
            self.params.append((
                f"{PREFIX}.lora_A.weight", Tensor(bytes(range(8))),
            ))

    def named_parameters(self):
        return iter(self.params)


def setup(tmp_path, **model_changes):
    directory, pins = create_adapter(tmp_path)
    frozen = load_pinned_adapter(
        directory, base_model=MODEL, base_revision=REV, **pins,
    )
    model = Model(**model_changes)
    post = snapshot_lora_parameters(
        model, tensor_bytes=lambda tensor: tensor.payload,
    )
    manifest = capture_posttraining_tensor_map(
        model,
        base_model=MODEL, base_revision=REV,
        post_snapshot=post,
        adapter_config_sha256=pins["expected_adapter_config_sha256"],
        adapter_weights_sha256=pins["expected_adapter_weights_sha256"],
        tensor_bytes=lambda tensor: tensor.payload,
    )
    return directory, pins, frozen, model, post, manifest


def test_exact_tensor_map_links_runtime_name_and_saved_safetensors_bytes(tmp_path):
    _, pins, frozen, _, post, manifest = setup(tmp_path)
    assert manifest["schema_version"] == "sre.grpo.post-save-tensor-map/v1"
    assert len(manifest["tensors"]) == 2
    assert manifest["post_snapshot"] == post
    assert all(row["runtime_name"].endswith(".default.weight") for row in manifest["tensors"])
    assert all(row["save_name"].endswith(".weight")
               and ".default." not in row["save_name"] for row in manifest["tensors"])
    result = verify_posttraining_tensor_map(
        manifest, frozen,
        expected_post_snapshot=post,
    )
    assert result["local_saved_weights_equal_claimed_post_snapshot"] is True
    assert result["tensors_compared"] == 2
    assert result["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    assert result["training_execution_independently_verified"] is False
    assert result["optimizer_step_independently_verified"] is False
    assert result["production_eligible"] is False


def test_wrong_tensor_bytes_rejected_despite_perfect_manifest_metadata(tmp_path):
    _, _, frozen, _, post, manifest = setup(tmp_path, mutate=True)
    with pytest.raises(ValueError, match="tensor bytes|weight bytes|byte digest"):
        verify_posttraining_tensor_map(
            manifest, frozen, expected_post_snapshot=post,
        )


def test_missing_or_duplicate_semantic_slot_rejected_during_capture(tmp_path):
    for changes, match in [
        ({"missing": True}, "tensor set"),
        ({"duplicate": True}, "duplicate"),
    ]:
        p = tmp_path / str(len(list(tmp_path.iterdir())))
        p.mkdir()
        directory, pins = create_adapter(p)
        model = Model(**changes)
        post = snapshot_lora_parameters(model, tensor_bytes=lambda t: t.payload)
        with pytest.raises(ValueError, match=match):
            capture_posttraining_tensor_map(
                model, base_model=MODEL, base_revision=REV,
                post_snapshot=post,
                adapter_config_sha256=pins["expected_adapter_config_sha256"],
                adapter_weights_sha256=pins["expected_adapter_weights_sha256"],
                tensor_bytes=lambda t: t.payload,
            )


def test_rehashed_forged_tensor_digest_and_alias_rejected(tmp_path):
    _, _, frozen, _, post, original = setup(tmp_path)
    forged = json.loads(json.dumps(original))
    forged["tensors"][0]["byte_sha256"] = "0"*64
    with pytest.raises(ValueError, match="tensor bytes|byte digest"):
        verify_posttraining_tensor_map(forged, frozen, expected_post_snapshot=post)
    forged = json.loads(json.dumps(original))
    forged["tensors"][0]["save_name"] = forged["tensors"][1]["save_name"]
    with pytest.raises(ValueError, match="duplicate|tensor set|save_name"):
        verify_posttraining_tensor_map(forged, frozen, expected_post_snapshot=post)


@pytest.mark.parametrize("field,value", [
    ("production_eligible", True),
    ("training_execution_independently_verified", True),
    ("optimizer_step_independently_verified", True),
    ("local_saved_weights_equal_claimed_post_snapshot", True),
])
def test_manifest_cannot_promote_local_observation_to_authenticated_proof(
    tmp_path, field, value
):
    _, _, frozen, _, post, original = setup(tmp_path)
    forged = {**original, field: value}
    with pytest.raises(ValueError, match="authority|status|manifest"):
        verify_posttraining_tensor_map(forged, frozen, expected_post_snapshot=post)


def test_wrong_declared_model_or_revision_rejected(tmp_path):
    _, _, frozen, _, post, original = setup(tmp_path)
    for k, v in [("base_model_revision", "b"*40), ("base_model", "Qwen/Qwen3-Other")]:
        with pytest.raises(ValueError, match="base_model"):
            verify_posttraining_tensor_map(
                {**original, k: v}, frozen, expected_post_snapshot=post,
            )


def test_pinned_manifest_from_disk_rechecked_with_physical_adapter(tmp_path):
    directory, pins, _, _, post, manifest = setup(tmp_path)
    path = tmp_path/"post-map.json"
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    result = verify_pinned_tensor_map(
        path, expected_manifest_sha256=digest, adapter_dir=directory,
        expected_adapter_config_sha256=pins["expected_adapter_config_sha256"],
        expected_adapter_weights_sha256=pins["expected_adapter_weights_sha256"],
        base_model=MODEL, base_revision=REV,
        expected_post_snapshot=post,
    )
    assert result["local_saved_weights_equal_claimed_post_snapshot"] is True
    path.write_bytes(raw+b"tamper")
    with pytest.raises(ValueError, match="sha256"):
        verify_pinned_tensor_map(
            path, expected_manifest_sha256=digest, adapter_dir=directory,
            expected_adapter_config_sha256=pins["expected_adapter_config_sha256"],
            expected_adapter_weights_sha256=pins["expected_adapter_weights_sha256"],
            base_model=MODEL, base_revision=REV, expected_post_snapshot=post,
        )


def test_non_lora_parameter_and_bad_dtype_rejected_in_capture(tmp_path):
    _, pins = create_adapter(tmp_path)
    model = Model()
    model.params[0] = ("base_model.model.lm_head.weight", model.params[0][1])
    with pytest.raises(ValueError, match="LoRA|runtime_name"):
        capture_posttraining_tensor_map(
            model, base_model=MODEL, base_revision=REV,
            post_snapshot={"schema_version": "fake"},
            adapter_config_sha256=pins["expected_adapter_config_sha256"],
            adapter_weights_sha256=pins["expected_adapter_weights_sha256"],
            tensor_bytes=lambda t:t.payload,
        )
