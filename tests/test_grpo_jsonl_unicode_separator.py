"""U+0085/U+2028/U+2029 inside JSON strings are not JSONL record breaks."""

import hashlib
import json

import pytest

from agentic_aiops.grpo_training import _jsonl_lines, load_episodes_bytes
from agentic_aiops.grpo_eval import load_predictions_bytes
from agentic_aiops.grpo_holdout_projection import project_holdout_prompts
from agentic_aiops.grpo_base_holdout_verify import verify_base_holdout_chain


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def episode(separator):
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": "unicode-episode-001",
        "fault_family": "unicode-record",
        "split": "test",
        "alert": "Alert" + separator + "continued",
        "observations": [{
            "evidence_id": "event-1",
            "tool": "kubernetes.get_events",
            "text": "Snapshot" + separator + "one",
        }],
        "oracle": {
            "answerable": False, "root_cause_id": "unknown",
            "required_evidence_ids": [],
        },
    }


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_unicode_separator_inside_json_fields_is_not_record_break(separator):
    raw = (json.dumps(episode(separator), ensure_ascii=False) + "\n").encode("utf-8")
    parsed, = load_episodes_bytes(raw)
    assert parsed.alert == "Alert" + separator + "continued"
    prediction = {"episode_id": parsed.episode_id,
                  "completion": "invalid" + separator + "raw response"}
    pred_raw = (json.dumps(prediction, ensure_ascii=False) + "\n").encode("utf-8")
    assert load_predictions_bytes(pred_raw)[parsed.episode_id] == prediction["completion"]
    assert len(_jsonl_lines(pred_raw.decode("utf-8"))) == 1


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_unicode_separator_passes_independent_five_file_base_holdout(tmp_path, separator):
    dataset = tmp_path / "episodes.jsonl"
    dataset.write_bytes((json.dumps(episode(separator), ensure_ascii=False) + "\n").encode())
    prompts = tmp_path / "prompts.jsonl"
    projected = tmp_path / "projection.json"
    project_holdout_prompts(
        dataset, expected_dataset_sha256=digest(dataset),
        output=prompts, manifest=projected, split="test",
    )
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_bytes((json.dumps({
        "episode_id": "unicode-episode-001",
        "completion": "raw" + separator + "invalid candidate",
    }, ensure_ascii=False) + "\n").encode())
    capture = tmp_path / "capture.json"
    revision = "a" * 40
    capture.write_text(json.dumps({
        "schema_version": "sre.grpo.holdout-capture/v1",
        "source_classification": "UNVERIFIED_MODEL_HOLDOUT_CAPTURE",
        "prompts_sha256": digest(prompts),
        "predictions_sha256": digest(predictions),
        "prompt_sha256": "b" * 64,
        "cases": 1,
        "split": "test",
        "model": "Qwen/Qwen3-0.6B",
        "model_revision": revision,
        "tokenizer_revision": revision,
        "seed": 42,
        "max_new_tokens": 192,
        "decoding": {"do_sample": False},
        "thinking_disabled": True,
        "oracle_in_sampler_input": False,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "superiority_claim_authorized": False,
        "training_admission_authorized": False,
        "production_eligible": False,
    }) + "\n", encoding="utf-8")
    audited = verify_base_holdout_chain(
        dataset=dataset, prompts=prompts, projection_manifest=projected,
        predictions=predictions, capture_manifest=capture,
        expected_dataset_sha256=digest(dataset),
        expected_prompts_sha256=digest(prompts),
        expected_projection_manifest_sha256=digest(projected),
        expected_predictions_sha256=digest(predictions),
        expected_capture_manifest_sha256=digest(capture),
        model="Qwen/Qwen3-0.6B", model_revision=revision,
    )
    assert audited["cases"] == 1
    assert audited["capture_claims_content_consistent"] is True
    assert audited["model_runtime_verified"] is False


def test_empty_jsonl_middle_record_remains_rejected():
    one = json.dumps(episode("\u2028"), ensure_ascii=False)
    with pytest.raises(ValueError, match="blank JSONL"):
        load_episodes_bytes((one + "\n\n").encode("utf-8"))
    row = json.dumps({"episode_id": "test", "completion": "response\u2028content"},
                     ensure_ascii=False)
    with pytest.raises(ValueError, match="blank prediction record"):
        load_predictions_bytes((row + "\n\n").encode("utf-8"))


def test_lf_only_wire_boundary():
    assert _jsonl_lines('{"text":"a\u2028b"}\n') == ['{"text":"a\u2028b"}']
    assert _jsonl_lines('{"x":1}\n\n') == ['{"x":1}', ""]
