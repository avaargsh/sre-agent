"""Pinned adapter SFT/GRPO holdout capture and independent metadata verification."""

import hashlib
import json
import subprocess
import sys

import pytest

from agentic_aiops.grpo_adapter import load_pinned_adapter
from agentic_aiops.grpo_holdout_capture import capture_holdout_predictions
from agentic_aiops.grpo_holdout_verify import verify_holdout_chain
from test_grpo_adapter import create_adapter, MODEL, REV
from test_grpo_holdout_capture import FakeTokenizer, ROOT, projection


def prepare(tmp_path, role="GRPO"):
    adapter_dir, adapter_pins = create_adapter(tmp_path)
    frozen = load_pinned_adapter(
        adapter_dir, base_model=MODEL, base_revision=REV, **adapter_pins
    )
    dataset, prompts, projection_manifest, p = projection(tmp_path)
    predictions, capture_manifest = tmp_path/"predictions.jsonl", tmp_path/"capture.json"
    result = capture_holdout_predictions(
        prompts, expected_prompts_sha256=p["prompts_sha256"],
        output=predictions, manifest=capture_manifest,
        tokenizer=FakeTokenizer(), sampler=lambda prompt, seed: "{}",
        model=MODEL, model_revision=REV,
        checkpoint_role=role, adapter_receipt=frozen.receipt,
    )
    paths = dict(
        dataset=dataset, prompts=prompts, projection_manifest=projection_manifest,
        predictions=predictions, capture_manifest=capture_manifest,
    )
    pins = dict(
        expected_dataset_sha256=p["dataset_sha256"],
        expected_prompts_sha256=p["prompts_sha256"],
        expected_projection_manifest_sha256=hashlib.sha256(
            projection_manifest.read_bytes()
        ).hexdigest(),
        expected_predictions_sha256=result["predictions_sha256"],
        expected_capture_manifest_sha256=hashlib.sha256(
            capture_manifest.read_bytes()
        ).hexdigest(),
        model=MODEL, model_revision=REV, checkpoint_role=role,
        **adapter_pins,
    )
    return paths, pins, result


def test_grpo_adapter_is_pinned_in_holdout_capture_and_independent_verification(tmp_path):
    paths, pins, receipt = prepare(tmp_path)
    assert receipt["schema_version"] == "sre.grpo.holdout-capture/v2"
    assert receipt["checkpoint_role"] == "GRPO"
    assert receipt["adapter"]["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    report = verify_holdout_chain(**paths, **pins)
    assert report["checkpoint_role"] == "GRPO"
    assert report["adapter_config_sha256"] == pins["expected_adapter_config_sha256"]
    assert report["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    assert report["model_runtime_verified"] is False
    assert report["model_attribution_verified"] is False


def test_sft_is_a_distinct_label_not_evidence_of_model_identity(tmp_path):
    paths, pins, receipt = prepare(tmp_path, "SFT")
    assert receipt["checkpoint_role"] == "SFT"
    report = verify_holdout_chain(**paths, **pins)
    assert report["checkpoint_role"] == "SFT"
    assert report["model_attribution_verified"] is False
    assert report["superiority_claim_authorized"] is False


def test_wrong_external_adapter_sha_or_role_rejected(tmp_path):
    paths, pins, _ = prepare(tmp_path)
    with pytest.raises(ValueError, match="adapter_weights_sha256"):
        verify_holdout_chain(**paths, **{**pins, "expected_adapter_weights_sha256": "0"*64})
    with pytest.raises(ValueError, match="checkpoint_role"):
        verify_holdout_chain(**paths, **{**pins, "checkpoint_role": "SFT"})


def test_forged_adapter_provenance_flags_rejected_even_after_rehash(tmp_path):
    paths, pins, _ = prepare(tmp_path)
    original = json.loads(paths["capture_manifest"].read_text())
    original["adapter"]["model_attribution_verified"] = True
    paths["capture_manifest"].write_text(json.dumps(original) + "\n")
    new_sha = hashlib.sha256(paths["capture_manifest"].read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="model_attribution_verified"):
        verify_holdout_chain(**paths, **{
            **pins, "expected_capture_manifest_sha256": new_sha,
        })


def test_base_rejects_adapter_and_adapter_roles_require_receipt(tmp_path):
    _, prompts, _, p = projection(tmp_path)
    options = dict(
        expected_prompts_sha256=p["prompts_sha256"],
        output=tmp_path/"pred.jsonl", manifest=tmp_path/"cap.json",
        tokenizer=FakeTokenizer(), sampler=lambda prompt, seed: "{}",
        model=MODEL, model_revision=REV,
    )
    adapter_dir, pins = create_adapter(tmp_path)
    adapter = load_pinned_adapter(
        adapter_dir, base_model=MODEL, base_revision=REV, **pins
    )
    with pytest.raises(ValueError, match="Base.*adapter"):
        capture_holdout_predictions(prompts, checkpoint_role="Base",
                                    adapter_receipt=adapter.receipt, **options)
    with pytest.raises(ValueError, match="adapter"):
        capture_holdout_predictions(prompts, checkpoint_role="GRPO",
                                    adapter_receipt=None, **options)
    assert not (tmp_path/"pred.jsonl").exists()


def test_cli_adapter_preflight_fails_before_cuda_import(tmp_path):
    _, prompts, _, p = projection(tmp_path)
    script = ROOT / "scripts/sample_sre_grpo_holdout.py"
    base = [
        sys.executable, str(script), "--execute", "--lab-only",
        "--checkpoint-role", "GRPO", "--prompts", str(prompts),
        "--expected-prompts-sha256", p["prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--output", str(tmp_path/"pred.jsonl"),
        "--manifest", str(tmp_path/"cap.json"),
    ]
    missing = subprocess.run(base, cwd=ROOT, capture_output=True, text=True)
    assert missing.returncode != 0
    assert "--adapter-dir" in missing.stderr or "adapter" in missing.stderr.lower()
    adapter_dir, pins = create_adapter(tmp_path)
    bad = subprocess.run([
        *base, "--adapter-dir", str(adapter_dir),
        "--expected-adapter-config-sha256", pins["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", "0"*64,
    ], cwd=ROOT, capture_output=True, text=True)
    assert bad.returncode != 0
    assert "adapter_weights_sha256" in bad.stderr
    assert not (tmp_path/"pred.jsonl").exists()
