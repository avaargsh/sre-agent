"""Independent CPU CLI binds the real saved LoRA tensor map to a train receipt.

No CUDA, PEFT, or model execution; no actual optimizer proof.
"""
import hashlib
import json
import subprocess
import sys

import pytest

from agentic_aiops.grpo_train_proof import (
    snapshot_lora_parameters, verify_local_lora_update,
)
from agentic_aiops.grpo_tensor_link import (
    verify_pinned_tensor_map_with_training_receipt,
)
from test_grpo_tensor_link import MODEL, REV, Model, setup
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path):
    adapter, pins, _, _, after, tensor_map = setup(tmp_path)
    before = snapshot_lora_parameters(
        Model(mutate=True), tensor_bytes=lambda value: value.payload,
    )
    delta = verify_local_lora_update(
        before, after, global_step=2, max_steps=10,
    )
    receipt = {
        "schema_version": "sre.grpo.local-training-receipt/v1",
        "dataset_sha256": "c"*64,
        "model": MODEL, "model_revision": REV, "tokenizer_revision": REV,
        "local_lora_update": delta, "training_scope": "LAB_ONLY_UNVERIFIED",
        "model_runtime_independently_verified": False,
        "data_issuer_authenticated": False,
        "training_admission_authorized": False,
        "production_eligible": False,
    }
    rpath = tmp_path/"train-receipt.json"
    mpath = tmp_path/"tensor-map.json"
    rpath.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    mpath.write_text(json.dumps(tensor_map, sort_keys=True) + "\n")
    return {
        "tensor_map": mpath,
        "expected_tensor_map_sha256": sha(mpath),
        "train_receipt": rpath,
        "expected_train_receipt_sha256": sha(rpath),
        "expected_dataset_sha256": receipt["dataset_sha256"],
        "adapter_dir": adapter,
        "expected_adapter_config_sha256": pins["expected_adapter_config_sha256"],
        "expected_adapter_weights_sha256": pins["expected_adapter_weights_sha256"],
        "base_model": MODEL,
        "base_revision": REV,
    }


def test_cpu_verified_post_step_tensor_link_against_local_training_receipt(tmp_path):
    args = fixture(tmp_path)
    report = verify_pinned_tensor_map_with_training_receipt(**args)
    assert report["local_saved_weights_equal_claimed_post_snapshot"] is True
    assert report["training_receipt_content_consistent"] is True
    assert report["tensors_compared"] == 2
    assert report["training_execution_independently_verified"] is False
    assert report["optimizer_step_independently_verified"] is False
    assert report["production_eligible"] is False


def test_rehashed_forged_train_receipt_no_execution_promotion(tmp_path):
    args = fixture(tmp_path)
    path = args["train_receipt"]
    receipt = json.loads(path.read_text())
    receipt["local_lora_update"]["optimizer_step_verified"] = True
    path.write_text(json.dumps(receipt) + "\n")
    args["expected_train_receipt_sha256"] = sha(path)
    with pytest.raises(ValueError, match="local_lora_update|fields"):
        verify_pinned_tensor_map_with_training_receipt(**args)


def test_train_receipt_after_snapshot_conflicts_with_verified_safetensors(tmp_path):
    args = fixture(tmp_path)
    path = args["train_receipt"]
    receipt = json.loads(path.read_text())
    receipt["local_lora_update"]["after"]["fingerprint_sha256"] = "0"*64
    path.write_text(json.dumps(receipt)+"\n")
    args["expected_train_receipt_sha256"] = sha(path)
    with pytest.raises(ValueError, match="post_snapshot|fingerprint"):
        verify_pinned_tensor_map_with_training_receipt(**args)


def test_wrong_train_dataset_and_model_identity_rejected(tmp_path):
    args = fixture(tmp_path)
    with pytest.raises(ValueError, match="dataset_sha256"):
        verify_pinned_tensor_map_with_training_receipt(
            **{**args,"expected_dataset_sha256":"f"*64},
        )
    path = args["train_receipt"]
    receipt = json.loads(path.read_text())
    receipt["model_revision"] = "d"*40
    path.write_text(json.dumps(receipt)+"\n")
    args["expected_train_receipt_sha256"] = sha(path)
    with pytest.raises(ValueError, match="model_revision"):
        verify_pinned_tensor_map_with_training_receipt(**args)


def cmd(args):
    return [
        sys.executable, str(ROOT/"scripts/verify_sre_grpo_tensor_link.py"),
        "--tensor-map", str(args["tensor_map"]),
        "--expected-tensor-map-sha256", args["expected_tensor_map_sha256"],
        "--train-receipt", str(args["train_receipt"]),
        "--expected-train-receipt-sha256", args["expected_train_receipt_sha256"],
        "--expected-dataset-sha256", args["expected_dataset_sha256"],
        "--adapter-dir", str(args["adapter_dir"]),
        "--expected-adapter-config-sha256", args["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", args["expected_adapter_weights_sha256"],
        "--model", MODEL, "--revision", REV,
    ]


def test_standalone_cpu_cli_accepts_and_fail_closed_rejects_tamper(tmp_path):
    args = fixture(tmp_path)
    ok = subprocess.run(cmd(args),cwd=ROOT,capture_output=True,text=True)
    assert ok.returncode == 0, ok.stderr
    result = json.loads(ok.stdout)
    assert result["local_saved_weights_equal_claimed_post_snapshot"] is True
    assert result["training_execution_independently_verified"] is False
    target = args["adapter_dir"]/"adapter_model.safetensors"
    target.write_bytes(target.read_bytes()+b"altered")
    failed = subprocess.run(cmd(args),cwd=ROOT,capture_output=True,text=True)
    assert failed.returncode == 3
    assert "UNKNOWN" in failed.stderr


@pytest.mark.parametrize("field", ["tensor_map", "train_receipt", "adapter_dir"])
def test_cli_refuses_parent_directory_traversal_for_every_pinned_input(tmp_path, field):
    args = fixture(tmp_path)
    path = args[field]
    # This path resolves to the same inode, but must not escape and re-enter
    # through a caller-controlled parent traversal component.
    args[field] = path.parent / ".." / path.parent.name / path.name
    result = subprocess.run(cmd(args), cwd=ROOT, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 3, result.stderr
    assert "UNKNOWN" in result.stderr
    assert not result.stdout


@pytest.mark.parametrize("field", ["tensor_map", "train_receipt", "adapter_dir"])
def test_cli_refuses_parent_directory_symlink_for_every_pinned_input(tmp_path, field):
    args = fixture(tmp_path)
    path = args[field]
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)

    if field == "adapter_dir":
        destination = real_parent / "adapter"
        path.rename(destination)
        args[field] = alias_parent / "adapter"
    else:
        destination = real_parent / path.name
        path.rename(destination)
        args[field] = alias_parent / path.name

    # The last path component is a regular file/directory, not a symlink.
    # Only a component-by-component no-follow open can reject this alias.
    result = subprocess.run(cmd(args), cwd=ROOT, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 3, result.stderr
    assert "UNKNOWN" in result.stderr
    assert not result.stdout


@pytest.mark.parametrize("field", ["tensor_map", "train_receipt"])
@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversized"])
def test_cli_refuses_unsafe_evidence_file(tmp_path, field, kind):
    import os

    args = fixture(tmp_path)
    path = args[field]
    original = path.with_suffix(".original")
    path.rename(original)
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(path)
    else:
        path.write_bytes(b"x" * (1024 * 1024 + 1))
    result = subprocess.run(cmd(args), cwd=ROOT, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 3, result.stderr
    assert "UNKNOWN" in result.stderr
    assert not result.stdout


@pytest.mark.parametrize("field", [
    "model_runtime_independently_verified", "data_issuer_authenticated",
    "training_admission_authorized", "production_eligible",
])
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_rehashed_receipt_authority_must_be_literal_false(tmp_path, field, value):
    args = fixture(tmp_path)
    path = args["train_receipt"]
    receipt = json.loads(path.read_text())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    args["expected_train_receipt_sha256"] = sha(path)
    with pytest.raises(ValueError, match="authority"):
        verify_pinned_tensor_map_with_training_receipt(**args)


@pytest.mark.parametrize("field,value", [
    ("model_runtime_independently_verified", 0),
    ("training_admission_authorized", 0),
    ("production_eligible", 0),
    ("local_lora_changed", 1),
])
def test_nested_delta_boolean_types_are_strict(tmp_path, field, value):
    args = fixture(tmp_path)
    path = args["train_receipt"]
    receipt = json.loads(path.read_text())
    receipt["local_lora_update"][field] = value
    path.write_text(json.dumps(receipt))
    args["expected_train_receipt_sha256"] = sha(path)
    with pytest.raises(ValueError, match="local_lora_update"):
        verify_pinned_tensor_map_with_training_receipt(**args)


@pytest.mark.parametrize("field", ["tensor_map", "train_receipt"])
@pytest.mark.parametrize("raw", [
    b'{"schema_version":"a","schema_version":"b"}',
    b'{"value":NaN}',
    b'{"value":Infinity}',
    b'{"value":-Infinity}',
    b'{"value":1e999}',
    b'\xff',
    b'[' * 200 + b'0' + b']' * 200,
])
def test_cli_rejects_malformed_evidence_even_with_matching_pin(tmp_path, field, raw):
    args = fixture(tmp_path)
    path = args[field]
    path.write_bytes(raw)
    args["expected_" + field + "_sha256"] = sha(path)
    result = subprocess.run(cmd(args), cwd=ROOT, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 3, result.stderr
    assert "UNKNOWN" in result.stderr
    assert not result.stdout
