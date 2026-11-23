"""Complete synthetic three-model holdout capture → independent verification → comparison.

No model weights are loaded; the three model names here label fake samplers
only, and the comparison must never authorize superiority.
"""

import hashlib
import json

from agentic_aiops.grpo_compare import compare_pinned_holdout
from agentic_aiops.grpo_holdout_capture import capture_holdout_predictions
from agentic_aiops.grpo_holdout_verify import verify_holdout_chain
from test_grpo_holdout_capture import FakeTokenizer, REVISION, projection


def test_complete_three_way_pipeline_stays_unverified_with_synthetic_samplers(tmp_path):
    dataset, prompts, projected_manifest, projected = projection(tmp_path)
    proj_digest = hashlib.sha256(projected_manifest.read_bytes()).hexdigest()
    outputs = {}
    predictions_sha = {}
    for role in ("Base", "SFT", "GRPO"):
        prediction_file = tmp_path / f"{role}.jsonl"
        receipt_file = tmp_path / f"{role}.json"
        def fake_sample(prompt, seed, *, role=role):
            # Deliberately fabricated responses for contract verification
            # ONLY. Different outcomes exercise the paired Oracle scorer.
            if "disk_fault" in prompt and role != "Base":
                return json.dumps({
                    "root_cause_id": "private_gold_disk_fault",
                    "evidence_ids": ["e1"], "stop_reason": "verified",
                })
            if "ambiguous_fault" in prompt and role == "GRPO":
                return json.dumps({
                    "root_cause_id": "unknown", "evidence_ids": [],
                    "stop_reason": "insufficient_evidence",
                })
            return "bad-model-answer"

        capture = capture_holdout_predictions(
            prompts, expected_prompts_sha256=projected["prompts_sha256"],
            output=prediction_file, manifest=receipt_file,
            tokenizer=FakeTokenizer(), sampler=fake_sample,
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
            split="test", seed=50,
        )
        proof = verify_holdout_chain(
            dataset=dataset, prompts=prompts,
            projection_manifest=projected_manifest,
            predictions=prediction_file, capture_manifest=receipt_file,
            expected_dataset_sha256=projected["dataset_sha256"],
            expected_prompts_sha256=projected["prompts_sha256"],
            expected_projection_manifest_sha256=proj_digest,
            expected_predictions_sha256=capture["predictions_sha256"],
            expected_capture_manifest_sha256=hashlib.sha256(
                receipt_file.read_bytes()
            ).hexdigest(),
            model="Qwen/Qwen3-0.6B", model_revision=REVISION, split="test",
        )
        assert proof["capture_prediction_binding_consistent"] is True
        assert proof["model_attribution_verified"] is False
        outputs[role] = prediction_file
        predictions_sha[role] = capture["predictions_sha256"]
    comparison = compare_pinned_holdout(
        dataset, prediction_files=outputs,
        expected_dataset_sha256=projected["dataset_sha256"],
        expected_prediction_sha256=predictions_sha,
        split="test",
    )
    assert comparison["cases"] == 2
    assert comparison["models"]["Base"]["exact_successes"] == 0
    assert comparison["models"]["SFT"]["exact_successes"] == 1
    assert comparison["models"]["GRPO"]["exact_successes"] == 2
    assert comparison["paired"]["GRPO_vs_Base"]["win"] == 2
    assert comparison["paired"]["GRPO_vs_Base"]["loss"] == 0
    assert comparison["model_attribution_verified"] is False
    assert comparison["superiority_claim_authorized"] is False
