"""CPU-only independent replay of a published GRPO evidence bundle.

All rows are synthetic. File-and-receipt consistency is NOT attestation of
GPU training, saved weight provenance, or model quality.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_evidence_bundle import (
    build_grpo_evidence_bundle, verify_grpo_evidence_bundle,
)
from test_grpo_evidence_bundle import fixture, sha
from test_grpo_holdout_capture import ROOT


def arrange(tmp_path):
    args = fixture(tmp_path)
    issued = build_grpo_evidence_bundle(**args)
    digest = sha(args["output"])
    replay_args = {
        **{k: v for k, v in args.items() if k != "output"},
        "evidence_bundle": args["output"],
        "expected_evidence_bundle_sha256": digest,
    }
    return replay_args, issued


def test_readonly_replay_recomputes_every_input_and_matches_exact_bundle(tmp_path):
    args, issued = arrange(tmp_path)
    before = {
        p: (p.stat().st_mtime_ns, p.read_bytes())
        for p in [
            args["evidence_bundle"], args["dataset"], args["run_manifest"],
            args["train_receipt"], *(
                args["holdout"][name] for name in (
                    "prompts", "projection_manifest", "predictions", "capture_manifest"
                )
            ),
        ]
    }
    result = verify_grpo_evidence_bundle(**args)
    assert result["schema_version"] == "sre.grpo.experiment-replay/v1"
    assert result["status"] == "CONTENT_REPLAY_CONSISTENT_NOT_EXECUTION_ATTESTED"
    assert result["evidence_bundle_sha256"] == args["expected_evidence_bundle_sha256"]
    assert result["dataset_sha256"] == issued["dataset_sha256"]
    assert result["source_content_reverified"] is True
    assert result["exact_bundle_fields_match_recomputed"] is True
    assert result["saved_weights_equal_posttraining_snapshot_verified"] is False
    assert result["training_execution_independently_verified"] is False
    assert result["model_runtime_verified"] is False
    assert result["model_attribution_verified"] is False
    assert result["superiority_claim_authorized"] is False
    assert result["production_eligible"] is False
    assert all((p.stat().st_mtime_ns, p.read_bytes()) == value for p, value in before.items())
    assert sorted(p.name for p in tmp_path.iterdir() if ".staging-" in p.name) == []


@pytest.mark.parametrize("source", [
    "dataset", "run_manifest", "train_receipt", "capture_manifest",
    "adapter_config", "adapter_weights",
])
def test_modified_or_removed_original_source_fails_replay(tmp_path, source):
    args, _ = arrange(tmp_path)
    target = {
        "dataset": args["dataset"],
        "run_manifest": args["run_manifest"],
        "train_receipt": args["train_receipt"],
        "capture_manifest": args["holdout"]["capture_manifest"],
        "adapter_config": args["adapter_dir"] / "adapter_config.json",
        "adapter_weights": args["adapter_dir"] / "adapter_model.safetensors",
    }[source]
    target.write_bytes(target.read_bytes() + b"changed-after-publication")
    with pytest.raises((ValueError, OSError), match="sha256|mismatch|invalid"):
        verify_grpo_evidence_bundle(**args)


def test_missing_source_cannot_replay_published_bundle(tmp_path):
    args, _ = arrange(tmp_path)
    args["holdout"]["predictions"].unlink()
    with pytest.raises((OSError, ValueError)):
        verify_grpo_evidence_bundle(**args)


def test_bundle_external_sha_required_and_wrong_pin_rejected(tmp_path):
    args, _ = arrange(tmp_path)
    args["expected_evidence_bundle_sha256"] = "0"*64
    with pytest.raises(ValueError, match="evidence_bundle_sha256"):
        verify_grpo_evidence_bundle(**args)


@pytest.mark.parametrize("field,value", [
    ("production_eligible", True),
    ("model_attribution_verified", True),
    ("saved_weights_equal_posttraining_snapshot_verified", True),
    ("holdout_cases", 999),
    ("status", "PRODUCTION_READY"),
])
def test_rehashed_forged_bundle_is_rejected_by_independent_recompute(
    tmp_path, field, value
):
    args, _ = arrange(tmp_path)
    path = args["evidence_bundle"]
    content = json.loads(path.read_text())
    content[field] = value
    path.write_text(json.dumps(content, sort_keys=True) + "\n")
    args["expected_evidence_bundle_sha256"] = sha(path)
    with pytest.raises(ValueError, match="bundle.*recomputed|bundle.*match"):
        verify_grpo_evidence_bundle(**args)


def test_rehashed_bundle_with_unknown_fields_or_duplicate_keys_rejected(tmp_path):
    args, _ = arrange(tmp_path)
    path = args["evidence_bundle"]
    original = json.loads(path.read_text())
    original["reviewer_signature_verified"] = True
    path.write_text(json.dumps(original) + "\n")
    args["expected_evidence_bundle_sha256"] = sha(path)
    with pytest.raises(ValueError, match="bundle"):
        verify_grpo_evidence_bundle(**args)
    # Try a duplicate key that JSON normally silently overwrites.
    encoded = path.read_text().strip()
    path.write_text(encoded[:-1] + ', "status": "OTHER"}\n')
    args["expected_evidence_bundle_sha256"] = sha(path)
    with pytest.raises(ValueError, match="duplicate|bundle"):
        verify_grpo_evidence_bundle(**args)


def test_symlinked_bundle_and_input_output_aliases_rejected(tmp_path):
    args, _ = arrange(tmp_path)
    link = tmp_path / "bundle-link.json"
    link.symlink_to(args["evidence_bundle"])
    with pytest.raises(ValueError, match="symlink"):
        verify_grpo_evidence_bundle(**{**args, "evidence_bundle": link})
    with pytest.raises(ValueError, match="distinct|alias"):
        verify_grpo_evidence_bundle(**{
            **args, "evidence_bundle": args["train_receipt"],
            "expected_evidence_bundle_sha256": sha(args["train_receipt"]),
        })


def test_replay_is_never_publication_and_never_overwrites_bundle(tmp_path):
    args, _ = arrange(tmp_path)
    path = args["evidence_bundle"]
    before = path.read_bytes()
    verify_grpo_evidence_bundle(**args)
    verify_grpo_evidence_bundle(**args)
    assert path.read_bytes() == before
    assert not (tmp_path / "evidence-bundle.replayed.json").exists()


def replay_cli_args(args):
    h = args["holdout"]
    return [
        sys.executable, str(ROOT / "scripts/verify_sre_grpo_evidence.py"),
        "--evidence-bundle", str(args["evidence_bundle"]),
        "--expected-evidence-bundle-sha256", args["expected_evidence_bundle_sha256"],
        "--dataset", str(args["dataset"]),
        "--expected-dataset-sha256", args["expected_dataset_sha256"],
        "--run-manifest", str(args["run_manifest"]),
        "--expected-run-manifest-sha256", args["expected_run_manifest_sha256"],
        "--train-receipt", str(args["train_receipt"]),
        "--expected-train-receipt-sha256", args["expected_train_receipt_sha256"],
        "--adapter-dir", str(args["adapter_dir"]),
        "--expected-adapter-config-sha256", args["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", args["expected_adapter_weights_sha256"],
        "--prompts", str(h["prompts"]),
        "--projection-manifest", str(h["projection_manifest"]),
        "--predictions", str(h["predictions"]),
        "--capture-manifest", str(h["capture_manifest"]),
        "--expected-prompts-sha256", h["expected_prompts_sha256"],
        "--expected-projection-manifest-sha256", h["expected_projection_manifest_sha256"],
        "--expected-predictions-sha256", h["expected_predictions_sha256"],
        "--expected-capture-manifest-sha256", h["expected_capture_manifest_sha256"],
        "--split", h["split"],
    ]


def test_cli_replay_returns_verified_metadata_only_and_unknown_on_failure(tmp_path):
    args, _ = arrange(tmp_path)
    command = replay_cli_args(args)
    ok = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    reply = json.loads(ok.stdout)
    assert reply["source_content_reverified"] is True
    assert reply["training_execution_independently_verified"] is False
    assert not (tmp_path / "replay-output.json").exists()
    args["holdout"]["predictions"].unlink()
    failed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    assert failed.returncode == 3
    assert "UNKNOWN" in failed.stderr
