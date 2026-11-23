import hashlib
import json
from pathlib import Path

import pytest

from agentic_aiops.grpo_holdout_projection import project_holdout_prompts
from agentic_aiops.grpo_base_holdout_verify import verify_base_holdout_chain

REV = "a" * 40
MODEL = "Qwen/Qwen3-0.6B"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make(tmp_path):
    ds = tmp_path / "dataset.jsonl"
    records = []
    for eid in ("first", "second"):
        records.append({"schema_version": "sre.grpo.episode/v1", "episode_id": eid,
                        "split": "test", "fault_family": f"fault-{eid}", "alert": f"Alert {eid}",
                        "observations": [{"evidence_id": "e1", "tool": "kubernetes.get_pods", "text": "read-only evidence"}],
                        "oracle": {"answerable": False, "root_cause_id": "unknown", "required_evidence_ids": []}})
    ds.write_bytes(("\n".join(json.dumps(r) for r in records)+"\n").encode())
    p, pm = tmp_path / "prompts.jsonl", tmp_path / "projection.json"
    receipt = project_holdout_prompts(ds, expected_dataset_sha256=sha(ds), split="test", output=p, manifest=pm)
    pred = tmp_path / "predictions.jsonl"
    pred.write_bytes(("\n".join(json.dumps({"episode_id": eid, "completion": "{}"}) for eid in ("first", "second"))+"\n").encode())
    cap = tmp_path / "capture.json"
    meta = {"schema_version": "sre.grpo.holdout-capture/v1", "source_classification": "UNVERIFIED_MODEL_HOLDOUT_CAPTURE",
            "prompts_sha256": sha(p), "predictions_sha256": sha(pred),
            "prompt_sha256": "b" * 64, "cases": 2, "split": "test", "model": MODEL,
            "model_revision": REV, "tokenizer_revision": REV,
            "seed": 42, "max_new_tokens": 192, "decoding": {"do_sample": False}, "thinking_disabled": True,
            "oracle_in_sampler_input": False, "model_runtime_verified": False, "model_attribution_verified": False,
            "superiority_claim_authorized": False, "training_admission_authorized": False, "production_eligible": False}
    cap.write_bytes((json.dumps(meta) + "\n").encode())
    args = dict(dataset=ds,prompts=p,projection_manifest=pm,predictions=pred,capture_manifest=cap,
                expected_dataset_sha256=sha(ds),expected_prompts_sha256=sha(p),
                expected_projection_manifest_sha256=sha(pm),expected_predictions_sha256=sha(pred),
                expected_capture_manifest_sha256=sha(cap),model=MODEL,model_revision=REV)
    return args

def test_happy_path(tmp_path):
    assert verify_base_holdout_chain(**make(tmp_path))["cases"] == 2

@pytest.mark.parametrize("field,value",[
    ("cases", True), ("thinking_disabled", 1), ("model_runtime_verified", 0),
    ("oracle_in_sampler_input", 0), ("decoding", {"do_sample": 0}),
    ("model_attribution_verified", True), ("production_eligible", True),
    ("seed", True), ("max_new_tokens", 191.0), ("checkpoint_role", "GRPO"),
    ("model_revision", "main"), ("tokenizer_revision", "main"),
])
def test_forged_capture_manifest_rejected(tmp_path,field,value):
    args=make(tmp_path)
    data=json.loads(args['capture_manifest'].read_text()); data[field]=value
    args['capture_manifest'].write_text(json.dumps(data)+'\n')
    args['expected_capture_manifest_sha256']=sha(args['capture_manifest'])
    with pytest.raises(ValueError): verify_base_holdout_chain(**args)

def test_reordered_predictions_rejected_even_after_repin(tmp_path):
    args=make(tmp_path)
    rows=args['predictions'].read_text().splitlines()
    args['predictions'].write_text('\n'.join(reversed(rows))+'\n')
    args['expected_predictions_sha256']=sha(args['predictions'])
    cap=json.loads(args['capture_manifest'].read_text())
    cap['predictions_sha256']=args['expected_predictions_sha256']
    args['capture_manifest'].write_text(json.dumps(cap)+'\n')
    args['expected_capture_manifest_sha256']=sha(args['capture_manifest'])
    with pytest.raises(ValueError, match='in order'):
        verify_base_holdout_chain(**args)

def test_overlarge_prediction_does_not_read_all(tmp_path,monkeypatch):
    args=make(tmp_path)
    with args['predictions'].open('wb') as f: f.truncate(4*1024*1024+1)
    from pathlib import Path
    def forbid(_): raise AssertionError('unbounded read')
    monkeypatch.setattr(Path,'read_bytes',forbid)
    with pytest.raises(ValueError,match='oversized'):
        verify_base_holdout_chain(**args)

def test_invalid_split_rejected(tmp_path):
    args=make(tmp_path);args['split']='train'
    with pytest.raises(ValueError,match='split'):
        verify_base_holdout_chain(**args)

def test_alias_rejected(tmp_path):
    args=make(tmp_path)
    args['predictions'].unlink()
    import os
    os.link(args['prompts'],args['predictions'])
    with pytest.raises(ValueError,match='alias'):
        verify_base_holdout_chain(**args)
