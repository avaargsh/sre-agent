"""Independent CPU-only holdout auditor must read real LoRA files, not trust receipts."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_holdout_verify import verify_holdout_chain
from test_grpo_adapter import MODEL, REV, create_adapter
from test_grpo_adapter_holdout import prepare
from test_grpo_holdout_capture import ROOT


def audit(tmp_path, *, require=True, **changes):
    paths, pins, capture = prepare(tmp_path, aba=True)
    options = {
        **paths, **pins,
        "adapter_dir": tmp_path / "adapter",
        "require_adapter_files": require,
        "require_reenable_probe": True,
    }
    options.update(changes)
    return options, capture


def test_independent_auditor_rehashes_both_adapter_files_and_rechecks_structure(tmp_path):
    args, capture = audit(tmp_path)
    result = verify_holdout_chain(**args)
    assert result["adapter_files_content_verified"] is True
    assert result["adapter_config_sha256"] == args["expected_adapter_config_sha256"]
    assert result["adapter_weights_sha256"] == args["expected_adapter_weights_sha256"]
    assert result["adapter_metadata_matches_files"] is True
    assert result["model_attribution_verified"] is False
    assert result["model_runtime_verified"] is False
    assert result["production_eligible"] is False


def test_legacy_metadata_only_audit_stays_explicitly_unverified(tmp_path):
    args, _ = audit(tmp_path)
    args.pop("adapter_dir")
    args["require_adapter_files"] = False
    report = verify_holdout_chain(**args)
    assert report["adapter_files_content_verified"] is False
    assert report["adapter_metadata_matches_files"] is False
    args["require_adapter_files"] = True
    with pytest.raises(ValueError, match="adapter.*files|adapter_dir"):
        verify_holdout_chain(**args)


@pytest.mark.parametrize("file_name", [
    "adapter_config.json", "adapter_model.safetensors",
])
def test_mutated_real_adapter_rejected_even_if_capture_receipt_is_unchanged(
    tmp_path, file_name
):
    args, _ = audit(tmp_path)
    target = args["adapter_dir"] / file_name
    target.write_bytes(target.read_bytes() + b"forged")
    with pytest.raises(ValueError, match="sha256"):
        verify_holdout_chain(**args)


def test_forged_capture_metadata_and_rehashed_manifest_rejected_by_real_files(tmp_path):
    args, _ = audit(tmp_path)
    manifest = args["capture_manifest"]
    capture = json.loads(manifest.read_text())
    # This claim is well-formed and would pass metadata-only verification.
    capture["adapter"]["target_modules"] = ["v_proj"]
    manifest.write_text(json.dumps(capture) + "\n", encoding="utf-8")
    args["expected_capture_manifest_sha256"] = hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()
    metadata_only = verify_holdout_chain(**{**args, "adapter_dir": None,
                                            "require_adapter_files": False})
    assert metadata_only["adapter_files_content_verified"] is False
    with pytest.raises(ValueError, match="adapter.*metadata|adapter.*target_modules"):
        verify_holdout_chain(**args)


def test_rehashing_config_and_receipt_cannot_hide_incompatible_rank(tmp_path):
    args, _ = audit(tmp_path)
    config_path = args["adapter_dir"] / "adapter_config.json"
    config = json.loads(config_path.read_text())
    config["r"] = 3  # actual A and B are 2x2
    config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    args["expected_adapter_config_sha256"] = hashlib.sha256(
        config_path.read_bytes()
    ).hexdigest()
    manifest = args["capture_manifest"]
    capture = json.loads(manifest.read_text())
    capture["adapter"]["adapter_config_sha256"] = args["expected_adapter_config_sha256"]
    manifest.write_text(json.dumps(capture) + "\n", encoding="utf-8")
    args["expected_capture_manifest_sha256"] = hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="rank"):
        verify_holdout_chain(**args)


def test_symlinked_adapter_directory_or_weight_file_rejected(tmp_path):
    args, _ = audit(tmp_path)
    original = args["adapter_dir"]
    alias = tmp_path / "adapter-alias"
    alias.symlink_to(original, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        verify_holdout_chain(**{**args, "adapter_dir": alias})
    weights = original / "adapter_model.safetensors"
    moved = tmp_path / "original-weights"
    weights.rename(moved)
    weights.symlink_to(moved)
    with pytest.raises(ValueError, match="symlink"):
        verify_holdout_chain(**args)


def test_base_rejects_strict_adapter_file_requirement(tmp_path):
    from agentic_aiops.grpo_holdout_capture import capture_holdout_predictions
    from test_grpo_holdout_capture import projection, FakeTokenizer
    source, prompts, projected_manifest, projected = projection(tmp_path)
    predictions = tmp_path/"base.jsonl"
    receipt = tmp_path/"base-capture.json"
    capture_holdout_predictions(
        prompts, expected_prompts_sha256=projected["prompts_sha256"],
        output=predictions, manifest=receipt,
        tokenizer=FakeTokenizer(), sampler=lambda prompt, seed: "{}",
        model=MODEL, model_revision=REV, checkpoint_role="Base",
    )
    args = {
        "dataset": source,
        "prompts": prompts,
        "projection_manifest": projected_manifest,
        "predictions": predictions,
        "capture_manifest": receipt,
        "expected_dataset_sha256": projected["dataset_sha256"],
        "expected_prompts_sha256": projected["prompts_sha256"],
        "expected_projection_manifest_sha256": hashlib.sha256(
            projected_manifest.read_bytes()
        ).hexdigest(),
        "expected_predictions_sha256": hashlib.sha256(predictions.read_bytes()).hexdigest(),
        "expected_capture_manifest_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "model": MODEL, "model_revision": REV,
        "checkpoint_role": "Base",
        "require_adapter_files": True,
    }
    with pytest.raises(ValueError, match="Base.*adapter"):
        verify_holdout_chain(**args)


def test_adapted_auditor_reads_each_real_adapter_file_once(tmp_path, monkeypatch):
    args, _ = audit(tmp_path)
    watched = {
        args["adapter_dir"]/"adapter_config.json",
        args["adapter_dir"]/"adapter_model.safetensors",
    }
    count = {path: 0 for path in watched}
    original = Path.read_bytes

    def trace(path):
        if path in count:
            count[path] += 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", trace)
    assert verify_holdout_chain(**args)["adapter_files_content_verified"] is True
    assert all(n == 1 for n in count.values())


def test_cli_exposes_strict_physical_adapter_audit_without_torch(tmp_path):
    args, _ = audit(tmp_path)
    cmd = [
        sys.executable, str(ROOT/"scripts/verify_sre_grpo_holdout.py"),
        "--dataset", str(args["dataset"]), "--prompts", str(args["prompts"]),
        "--projection-manifest", str(args["projection_manifest"]),
        "--predictions", str(args["predictions"]),
        "--capture-manifest", str(args["capture_manifest"]),
        "--expected-dataset-sha256", args["expected_dataset_sha256"],
        "--expected-prompts-sha256", args["expected_prompts_sha256"],
        "--expected-projection-manifest-sha256",
        args["expected_projection_manifest_sha256"],
        "--expected-predictions-sha256", args["expected_predictions_sha256"],
        "--expected-capture-manifest-sha256",
        args["expected_capture_manifest_sha256"],
        "--expected-adapter-config-sha256",
        args["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256",
        args["expected_adapter_weights_sha256"],
        "--model", MODEL, "--revision", REV, "--checkpoint-role", "GRPO",
        "--require-reenable-probe", "--adapter-dir", str(args["adapter_dir"]),
        "--require-adapter-files",
    ]
    valid = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert valid.returncode == 0, valid.stderr
    report = json.loads(valid.stdout)
    assert report["adapter_files_content_verified"] is True
    assert report["model_runtime_verified"] is False

    missing = cmd[:]
    missing.pop(missing.index("--adapter-dir") + 1)
    missing.remove("--adapter-dir")
    failed = subprocess.run(missing, cwd=ROOT, capture_output=True, text=True)
    assert failed.returncode == 3
    assert "UNKNOWN" in failed.stderr
    assert "adapter" in failed.stderr.lower()
