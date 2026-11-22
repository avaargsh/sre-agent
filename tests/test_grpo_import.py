"""Scenario -> GRPO Episode import must pin an independent Oracle receipt."""

import hashlib
import json
from pathlib import Path

import pytest

from agentic_aiops.grpo_import import import_scenario_episode
from agentic_aiops.grpo_training import build_prompt, load_episodes


ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "benchmarks/scenarios/checkout-latency.json"


def write_payload(path, payload):
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def approval_for(scenario_file, *, family="db-pool", split="train"):
    return {
        "schema_version": "sre.grpo.import-approval/v1",
        "case_id": "checkout-latency-001",
        "episode_id": "checkout-synthetic-001",
        "fault_family": family,
        "split": split,
        "source_sha256": hashlib.sha256(scenario_file.read_bytes()).hexdigest(),
        "evidence_tools": {
            "e-metrics-1": "prometheus.query",
            "e-k8s-1": "kubernetes.get_pods",
        },
        "oracle": {
            "answerable": True,
            "root_cause_id": "db_pool_saturation",
            "required_evidence_ids": ["e-metrics-1"],
        },
    }


def inputs(tmp_path):
    source = tmp_path / "scenario.json"
    source.write_bytes(SCENARIO.read_bytes())
    manifest = tmp_path / "approval.json"
    sha = write_payload(manifest, approval_for(source))
    return source, manifest, sha


def run_import(source, approval, digest, output):
    return import_scenario_episode(
        source, approval, expected_approval_sha256=digest, output=output
    )


def test_import_existing_frozen_scenario_without_trusting_hypotheses(tmp_path):
    source, manifest, digest = inputs(tmp_path)
    outfile = tmp_path / "out.jsonl"
    receipt = run_import(source, manifest, digest, outfile)
    ep, = load_episodes(outfile)
    assert ep.episode_id == "checkout-synthetic-001"
    assert ep.oracle.root_cause_id == "db_pool_saturation"
    assert [item.tool for item in ep.observations] == [
        "prometheus.query", "kubernetes.get_pods"
    ]
    assert receipt["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert receipt["approval_sha256"] == digest
    assert receipt["episode_sha256"] == hashlib.sha256(outfile.read_bytes()).hexdigest()
    assert receipt["source_classification"] == "synthetic-regression"
    assert receipt["independent_issuer_verified"] is False
    prompt = build_prompt(ep)
    assert "db_pool_saturation" not in prompt
    assert "database connection pool saturation contributes" not in prompt
    assert "recovered" not in prompt
    assert "human_review" not in prompt


def test_source_tamper_and_approval_tamper_fail_closed(tmp_path):
    source, manifest, digest = inputs(tmp_path)
    outfile = tmp_path / "out.jsonl"
    raw = json.loads(source.read_text())
    raw["bundle"]["evidence"][0]["observation"] = "replaced evidence"
    write_payload(source, raw)
    with pytest.raises(ValueError, match="source_sha256"):
        run_import(source, manifest, digest, outfile)
    assert not outfile.exists()

    manifest_data = approval_for(source)
    new_digest = write_payload(manifest, manifest_data)
    with pytest.raises(ValueError, match="approval_sha256"):
        run_import(source, manifest, digest, outfile)
    assert not outfile.exists()
    receipt = run_import(source, manifest, new_digest, outfile)
    assert receipt["approval_sha256"] == new_digest


def test_missing_independent_pin_rejected(tmp_path):
    source, manifest, digest = inputs(tmp_path)
    output = tmp_path / "out.jsonl"
    for bad in ("", "a" * 64, "0" * 32, "F" * 64):
        with pytest.raises(ValueError, match="approval_sha256"):
            run_import(source, manifest, bad, output)
        assert not output.exists()
    assert digest != "a" * 64


@pytest.mark.parametrize("mutate,problem", [
    (lambda a: a.update(case_id="wrong-case"), "case_id"),
    (lambda a: a["evidence_tools"].update({"unknown": "prometheus.query"}), "evidence_tools"),
    (lambda a: a["evidence_tools"].update({"e-k8s-1": "prometheus.query"}), "tool source"),
    (lambda a: a["evidence_tools"].update({"e-k8s-1": "kubernetes.delete_pod"}), "read-only"),
    (lambda a: a["oracle"].update(required_evidence_ids=["missing"]), "required_evidence_ids"),
    (lambda a: a.update(oracle={"answerable": False, "root_cause_id": "unknown",
                                "required_evidence_ids": ["e-metrics-1"]}), "unknown"),
    (lambda a: a.update(approved_by_model=True), "fields"),
])
def test_manifest_boundaries(tmp_path, mutate, problem):
    source, manifest, _ = inputs(tmp_path)
    payload = approval_for(source)
    mutate(payload)
    digest = write_payload(manifest, payload)
    output = tmp_path / "out.jsonl"
    with pytest.raises(ValueError, match=problem):
        run_import(source, manifest, digest, output)
    assert not output.exists()


def test_duplicate_json_and_unrecognized_source_fail_closed(tmp_path):
    source, manifest, digest = inputs(tmp_path)
    output = tmp_path / "out.jsonl"
    manifest.write_text('{"case_id":"a","case_id":"b"}\n', encoding="utf-8")
    newdigest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate"):
        run_import(source, manifest, newdigest, output)
    manifest_digest = write_payload(manifest, approval_for(source))
    bad = json.loads(source.read_text())
    bad["bundle"]["evidence"][0]["source"] = "shell"
    newsource = write_payload(source, bad)
    newapproval = approval_for(source)
    newapproval["source_sha256"] = newsource
    newapproval_digest = write_payload(manifest, newapproval)
    with pytest.raises(ValueError, match="source"):
        run_import(source, manifest, newapproval_digest, output)
    assert not output.exists()


def test_exclusive_output_and_no_partial_write(tmp_path):
    source, manifest, digest = inputs(tmp_path)
    output = tmp_path / "out.jsonl"
    run_import(source, manifest, digest, output)
    snapshot = output.read_bytes()
    with pytest.raises(FileExistsError):
        run_import(source, manifest, digest, output)
    assert output.read_bytes() == snapshot
