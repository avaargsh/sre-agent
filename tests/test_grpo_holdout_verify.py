"""Independent Oracle-free projection/holdout capture binding tests."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_holdout_verify import verify_holdout_chain
from agentic_aiops.grpo_holdout_capture import capture_holdout_predictions
from test_grpo_holdout_capture import ROOT, REVISION, FakeTokenizer, projection


def make_chain(tmp_path):
    dataset, prompts, projected_manifest, pr = projection(tmp_path)
    predictions = tmp_path / "predictions.jsonl"
    captured_manifest = tmp_path / "capture.json"
    cr = capture_holdout_predictions(
        prompts, expected_prompts_sha256=pr["prompts_sha256"],
        output=predictions, manifest=captured_manifest,
        tokenizer=FakeTokenizer(),
        sampler=lambda text, seed: "{}" if seed == 43 else
            '{"root_cause_id":"unknown","evidence_ids":[],"stop_reason":"insufficient_evidence"}',
        model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        split="test", seed=42,
    )
    files = dict(
        dataset=dataset, prompts=prompts,
        projection_manifest=projected_manifest,
        predictions=predictions, capture_manifest=captured_manifest,
    )
    pins = dict(
        expected_dataset_sha256=pr["dataset_sha256"],
        expected_prompts_sha256=pr["prompts_sha256"],
        expected_projection_manifest_sha256=hashlib.sha256(projected_manifest.read_bytes()).hexdigest(),
        expected_predictions_sha256=cr["predictions_sha256"],
        expected_capture_manifest_sha256=hashlib.sha256(captured_manifest.read_bytes()).hexdigest(),
        model="Qwen/Qwen3-0.6B", model_revision=REVISION, split="test",
    )
    return files, pins


def test_full_independent_chain_binds_projected_prompts_and_predictions(tmp_path):
    paths, pins = make_chain(tmp_path)
    report = verify_holdout_chain(**paths, **pins)
    assert report["schema_version"] == "sre.grpo.holdout-chain-audit/v1"
    assert report["projected_prompts_match_oracle_free_dataset"] is True
    assert report["capture_prediction_binding_consistent"] is True
    assert report["cases"] == 2
    assert report["model_runtime_verified"] is False
    assert report["model_attribution_verified"] is False
    assert report["data_issuer_authenticated"] is False
    assert report["superiority_claim_authorized"] is False


def test_different_projected_prompt_with_all_hashes_recomputed_still_rejected(tmp_path):
    paths, pins = make_chain(tmp_path)
    rows = [json.loads(x) for x in paths["prompts"].read_text().splitlines()]
    rows[0]["prompt"] += "\nOracle: private_gold_disk_fault"
    paths["prompts"].write_text(
        "".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8",
    )
    pins["expected_prompts_sha256"] = hashlib.sha256(paths["prompts"].read_bytes()).hexdigest()
    # A digest signed by no one only proves self-consistency. In addition
    # compare projected prompts to independently pinned Oracle dataset.
    with pytest.raises(ValueError, match="projection.*dataset|prompts.*dataset"):
        verify_holdout_chain(**paths, **pins)


def test_forged_manifest_approval_is_never_accepted(tmp_path):
    paths, pins = make_chain(tmp_path)
    for name, field in (
        ("projection_manifest", "oracle_in_projection"),
        ("capture_manifest", "model_runtime_verified"),
        ("capture_manifest", "model_attribution_verified"),
        ("capture_manifest", "superiority_claim_authorized"),
    ):
        source = paths[name]
        original = source.read_bytes()
        data = json.loads(original)
        data[field] = True
        source.write_text(json.dumps(data) + "\n")
        updated = dict(pins)
        updated[
            "expected_projection_manifest_sha256" if name == "projection_manifest"
            else "expected_capture_manifest_sha256"
        ] = hashlib.sha256(source.read_bytes()).hexdigest()
        with pytest.raises(ValueError, match=field):
            verify_holdout_chain(**paths, **updated)
        source.write_bytes(original)


def test_swapped_prediction_file_rejected_even_when_new_digest_supplied(tmp_path):
    paths, pins = make_chain(tmp_path)
    rows = [json.loads(x) for x in paths["predictions"].read_text().splitlines()]
    rows[0]["completion"] = "other answer"
    paths["predictions"].write_text(
        "".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8",
    )
    pins["expected_predictions_sha256"] = hashlib.sha256(
        paths["predictions"].read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="predictions_sha256"):
        verify_holdout_chain(**paths, **pins)


def test_wrong_model_or_revision_and_missing_episode_fail_closed(tmp_path):
    paths, pins = make_chain(tmp_path)
    with pytest.raises(ValueError, match="model_revision"):
        verify_holdout_chain(**paths, **{**pins, "model_revision": "b"*40})
    with pytest.raises(ValueError, match="model"):
        verify_holdout_chain(**paths, **{**pins, "model": "Qwen/Qwen3-1.7B"})
    rows = [json.loads(x) for x in paths["predictions"].read_text().splitlines()]
    paths["predictions"].write_text(json.dumps(rows[0]) + "\n")
    new_sha = hashlib.sha256(paths["predictions"].read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="predictions_sha256|missing|holdout episode IDs"):
        verify_holdout_chain(
            **paths, **{**pins, "expected_predictions_sha256": new_sha}
        )


def test_cli_checks_pinned_chain_before_independent_evaluation(tmp_path):
    paths, pins = make_chain(tmp_path)
    script = ROOT / "scripts/verify_sre_grpo_holdout.py"
    args = [
        sys.executable, str(script),
        "--dataset", str(paths["dataset"]),
        "--prompts", str(paths["prompts"]),
        "--projection-manifest", str(paths["projection_manifest"]),
        "--predictions", str(paths["predictions"]),
        "--capture-manifest", str(paths["capture_manifest"]),
        "--expected-dataset-sha256", pins["expected_dataset_sha256"],
        "--expected-prompts-sha256", pins["expected_prompts_sha256"],
        "--expected-projection-manifest-sha256",
        pins["expected_projection_manifest_sha256"],
        "--expected-predictions-sha256", pins["expected_predictions_sha256"],
        "--expected-capture-manifest-sha256",
        pins["expected_capture_manifest_sha256"],
        "--model", pins["model"], "--revision", pins["model_revision"],
        "--split", "test",
    ]
    passed = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    assert passed.returncode == 0, passed.stderr
    result = json.loads(passed.stdout)
    assert result["projected_prompts_match_oracle_free_dataset"] is True
    assert result["model_runtime_verified"] is False
    args[args.index("--expected-capture-manifest-sha256")+1] = "0"*64
    failed = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    assert failed.returncode == 3
    assert "UNKNOWN" in failed.stderr


def test_rehashed_mutable_model_alias_does_not_pass_binding(tmp_path):
    paths, pins = make_chain(tmp_path)
    capture = json.loads(paths["capture_manifest"].read_text())
    capture["model_revision"] = "main"
    capture["tokenizer_revision"] = "main"
    paths["capture_manifest"].write_text(json.dumps(capture) + "\n")
    new_sha = hashlib.sha256(paths["capture_manifest"].read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="model_revision"):
        verify_holdout_chain(
            **paths, **{
                **pins,
                "expected_capture_manifest_sha256": new_sha,
                "model_revision": "main",
            },
        )


def test_rehashed_unapproved_model_id_does_not_pass_binding(tmp_path):
    paths, pins = make_chain(tmp_path)
    capture = json.loads(paths["capture_manifest"].read_text())
    capture["model"] = "other-org/untrusted"
    paths["capture_manifest"].write_text(json.dumps(capture) + "\n")
    sha = hashlib.sha256(paths["capture_manifest"].read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="model"):
        verify_holdout_chain(
            **paths, **{
                **pins, "expected_capture_manifest_sha256": sha,
                "model": "other-org/untrusted",
            },
        )
