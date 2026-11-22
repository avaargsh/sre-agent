"""Capture receipt is metadata integrity, never independent model provenance."""

import hashlib
import json

import pytest

from agentic_aiops.grpo_capture_verify import verify_capture_binding
from agentic_aiops.grpo_rollout_audit import audit_rollout_groups
from agentic_aiops.grpo_rollout_capture import capture_rollout_groups

from test_grpo_rollout_capture import ToyTokenizer, dataset_file, REV


def make_capture(tmp_path):
    ds, digest = dataset_file(tmp_path)
    out = tmp_path / "rollouts.jsonl"
    meta = tmp_path / "capture.json"
    completions = iter([
        '{"root_cause_id":"oom_killed","evidence_ids":["e1"],"stop_reason":"verified"}',
        '{"root_cause_id":"wrong","evidence_ids":[],"stop_reason":"verified"}',
        "invalid-response",
        '{"root_cause_id":"oom_killed","evidence_ids":["e1"],"stop_reason":"verified"}',
    ])
    receipt = capture_rollout_groups(
        ds, expected_dataset_sha256=digest, output=out, manifest=meta,
        tokenizer=ToyTokenizer(), sampler=lambda prompt, seed: next(completions),
        model="Qwen/Qwen3-0.6B", model_revision=REV,
    )
    return ds, out, meta, digest, receipt


def binding(tmp_path):
    ds, out, meta, sha, receipt = make_capture(tmp_path)
    digest = hashlib.sha256(meta.read_bytes()).hexdigest()
    result = verify_capture_binding(
        ds, out, meta,
        expected_dataset_sha256=sha,
        expected_rollouts_sha256=receipt["rollouts_sha256"],
        expected_manifest_sha256=digest,
        model="Qwen/Qwen3-0.6B",
        model_revision=REV,
        group_size=4,
    )
    return ds, out, meta, sha, receipt, digest, result


def test_capture_manifest_binds_data_model_revision_and_train_groups(tmp_path):
    ds, out, meta, sha, receipt, digest, verified = binding(tmp_path)
    assert verified["schema_version"] == "sre.grpo.capture-binding/v1"
    assert verified["binding_consistent"] is True
    assert verified["model_runtime_independently_verified"] is False
    assert verified["training_admission_authorized"] is False
    assert verified["manifest_sha256"] == digest
    assert verified["groups"] == 1
    audit = audit_rollout_groups(
        ds, out, expected_dataset_sha256=sha,
        expected_rollouts_sha256=receipt["rollouts_sha256"],
    )
    assert audit["nonconstant_reward_groups"] == 1
    assert audit["model_runtime_verified"] is False


def test_changed_raw_rollouts_refused_even_if_caller_recomputes_the_hash(tmp_path):
    ds, out, meta, sha, receipt, manifest_sha, _ = binding(tmp_path)
    raw = out.read_bytes().replace(b"invalid-response", b"other-response")
    out.write_bytes(raw)
    new_raw_sha = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="rollouts_sha256"):
        verify_capture_binding(
            ds, out, meta, expected_dataset_sha256=sha,
            expected_rollouts_sha256=new_raw_sha,
            expected_manifest_sha256=manifest_sha,
            model="Qwen/Qwen3-0.6B", model_revision=REV, group_size=4,
        )


def test_modified_metadata_cannot_reuse_old_pinned_manifest_sha(tmp_path):
    ds, out, meta, sha, receipt, manifest_sha, _ = binding(tmp_path)
    content = json.loads(meta.read_text())
    content["model_revision"] = "b" * 40
    meta.write_text(json.dumps(content) + "\n")
    with pytest.raises(ValueError, match="manifest_sha256"):
        verify_capture_binding(
            ds, out, meta, expected_dataset_sha256=sha,
            expected_rollouts_sha256=receipt["rollouts_sha256"],
            expected_manifest_sha256=manifest_sha,
            model="Qwen/Qwen3-0.6B", model_revision=REV, group_size=4,
        )


def test_wrong_model_or_group_size_fails_closed(tmp_path):
    ds, out, meta, sha, receipt, manifest_sha, _ = binding(tmp_path)
    values = dict(
        expected_dataset_sha256=sha,
        expected_rollouts_sha256=receipt["rollouts_sha256"],
        expected_manifest_sha256=manifest_sha, group_size=4,
        model="Qwen/Qwen3-0.6B", model_revision=REV,
    )
    with pytest.raises(ValueError, match="model_revision"):
        verify_capture_binding(ds, out, meta, **{**values, "model_revision":"b"*40})
    with pytest.raises(ValueError, match="group_size"):
        verify_capture_binding(ds, out, meta, **{**values, "group_size":8})
    with pytest.raises(ValueError, match="model"):
        verify_capture_binding(ds, out, meta, **{**values, "model":"Qwen/Qwen3-8B"})


def test_even_rehashed_manifest_cannot_claim_verified_model_or_admission(tmp_path):
    ds, out, meta, sha, receipt, _, _ = binding(tmp_path)
    for field in ("model_runtime_independently_verified", "training_admission_authorized"):
        data = json.loads(meta.read_text())
        data[field] = True
        meta.write_text(json.dumps(data, sort_keys=True) + "\n")
        manifest_sha = hashlib.sha256(meta.read_bytes()).hexdigest()
        with pytest.raises(ValueError, match=field):
            verify_capture_binding(
                ds, out, meta,
                expected_dataset_sha256=sha,
                expected_rollouts_sha256=receipt["rollouts_sha256"],
                expected_manifest_sha256=manifest_sha,
                model="Qwen/Qwen3-0.6B", model_revision=REV, group_size=4,
            )
        meta.write_text(json.dumps(receipt, sort_keys=True) + "\n")


def test_duplicate_json_keys_in_manifest_fail_closed(tmp_path):
    ds, out, meta, sha, receipt, _, _ = binding(tmp_path)
    text = meta.read_text().rstrip()
    meta.write_text(text[:-1] + ', "model_revision":"b" }\n')
    manifest_sha = hashlib.sha256(meta.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate"):
        verify_capture_binding(
            ds, out, meta,
            expected_dataset_sha256=sha,
            expected_rollouts_sha256=receipt["rollouts_sha256"],
            expected_manifest_sha256=manifest_sha,
            model="Qwen/Qwen3-0.6B", model_revision=REV, group_size=4,
        )
