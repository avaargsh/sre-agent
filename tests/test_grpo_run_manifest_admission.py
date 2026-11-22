"""Run manifests must prove train-row count explicitly, never default to truth.

The offline bundle builder must not infer a missing producer field from the
independent dataset and then advertise the incomplete run as consistent.
"""
import hashlib
import json

import pytest

from agentic_aiops.grpo_evidence_bundle import build_grpo_evidence_bundle
from test_grpo_evidence_bundle import fixture


def rewrite_manifest(args, *, delete_rows=False, rows=1):
    path = args["run_manifest"]
    report = json.loads(path.read_text(encoding="utf-8"))
    if delete_rows:
        report.pop("train_rows", None)
    else:
        report["train_rows"] = rows
    path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    args["expected_run_manifest_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()


def test_full_run_manifest_can_be_bound_to_exact_training_dataset(tmp_path):
    args = fixture(tmp_path)
    rewrite_manifest(args, rows=1)
    report = build_grpo_evidence_bundle(**args)
    assert report["training_snapshot_delta_consistent"] is True


def test_missing_run_train_rows_must_fail_before_experiment_publication(tmp_path):
    args = fixture(tmp_path)
    rewrite_manifest(args, delete_rows=True)
    with pytest.raises(ValueError, match="train_rows"):
        build_grpo_evidence_bundle(**args)
    assert not args["output"].exists()


@pytest.mark.parametrize("value", [0, -1, 2, None, "1", True])
def test_noncanonical_or_mismatched_train_rows_is_rejected(tmp_path, value):
    args = fixture(tmp_path)
    rewrite_manifest(args, rows=value)
    with pytest.raises(ValueError, match="train_rows"):
        build_grpo_evidence_bundle(**args)
    assert not args["output"].exists()
