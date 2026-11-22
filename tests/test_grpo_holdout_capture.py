"""Holdout projection and prediction capture: Oracle is not in sampler input.

CPU-only tests inject a fake tokenizer/sampler. These are NOT live model runs.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_holdout_capture import (
    capture_holdout_predictions,
    project_holdout_prompts,
)


ROOT = Path(__file__).resolve().parents[1]
REVISION = "a" * 40


def episode(eid, family, split, *, answerable=True):
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": eid,
        "fault_family": family,
        "split": split,
        "alert": f"Alert for {family}",
        "observations": [
            {"evidence_id": "e1", "tool": "kubernetes.get_events",
             "text": f"Read-only event {family}"},
        ],
        "oracle": {
            "answerable": answerable,
            "root_cause_id": f"private_gold_{family}" if answerable else "unknown",
            "required_evidence_ids": ["e1"] if answerable else [],
        },
    }


def write_rows(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dataset(tmp_path):
    path = tmp_path / "episodes.jsonl"
    digest = write_rows(path, [
        episode("train-1", "train_fault", "train"),
        episode("test-1", "disk_fault", "test"),
        episode("test-2", "ambiguous_fault", "test", answerable=False),
        episode("validation-1", "dns_fault", "validation"),
    ])
    return path, digest


def projection(tmp_path, *, split="test", digest=None):
    data, pinned = dataset(tmp_path)
    prompts = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "projection.json"
    result = project_holdout_prompts(
        data, expected_dataset_sha256=digest or pinned,
        split=split, output=prompts, manifest=manifest,
    )
    return data, prompts, manifest, result


class FakeTokenizer:
    def __init__(self):
        self.messages = []

    def apply_chat_template(self, messages, **kwargs):
        self.messages.extend(messages)
        assert kwargs["enable_thinking"] is False
        assert kwargs["add_generation_prompt"] is True
        assert kwargs["tokenize"] is False
        assert len(messages) == 1 and messages[0]["role"] == "user"
        return "QWEN3 CHAT " + messages[0]["content"]

    def __call__(self, text, **kwargs):
        assert kwargs["add_special_tokens"] is False
        return {"input_ids": text.split()}


def test_projection_contains_no_oracle_and_excludes_train_and_validation(tmp_path):
    dataset_file, prompts, manifest, report = projection(tmp_path)
    raw = prompts.read_bytes()
    rows = [json.loads(x) for x in raw.decode().splitlines()]
    assert [r["episode_id"] for r in rows] == ["test-1", "test-2"]
    assert all(set(r) == {"episode_id", "prompt"} for r in rows)
    for secret in ("private_gold_", '"oracle"', '"split"', "train-1",
                   "validation-1", "required_evidence_ids", "answerable"):
        assert secret not in raw.decode()
    assert report["schema_version"] == "sre.grpo.holdout-projection/v1"
    assert report["dataset_sha256"] == hashlib.sha256(dataset_file.read_bytes()).hexdigest()
    assert report["prompts_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["oracle_in_projection"] is False
    assert report["model_runtime_verified"] is False
    assert report["training_admission_authorized"] is False
    assert json.loads(manifest.read_text()) == report


def test_capture_reads_only_oracle_free_prompt_file_and_preserves_raw_invalid_answers(
    tmp_path, monkeypatch
):
    data, prompts, projection_manifest, projection_report = projection(tmp_path)
    data.rename(tmp_path / "original-dataset-is-now-unavailable")
    projection_manifest.unlink()
    tokenizer = FakeTokenizer()
    calls = []

    def sample(prompt, seed):
        calls.append((prompt, seed))
        return "{invalid raw\n response}" if seed == 55 else json.dumps({
            "root_cause_id": "unknown", "evidence_ids": [],
            "stop_reason": "insufficient_evidence",
        })

    predictions = tmp_path / "model-predictions.jsonl"
    manifest = tmp_path / "model-capture.json"
    result = capture_holdout_predictions(
        prompts,
        expected_prompts_sha256=projection_report["prompts_sha256"],
        output=predictions, manifest=manifest,
        tokenizer=tokenizer, sampler=sample,
        model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        split="test", seed=55, max_new_tokens=128,
    )
    assert [seed for _, seed in calls] == [55, 56]
    assert all("private_gold_" not in p for p, _ in calls)
    assert all("required_evidence_ids" not in p for p, _ in calls)
    assert all("private_gold_" not in m["content"] for m in tokenizer.messages)
    rows = [json.loads(s) for s in predictions.read_text().splitlines()]
    assert [r["episode_id"] for r in rows] == ["test-1", "test-2"]
    assert rows[0]["completion"] == "{invalid raw\n response}"
    assert set(rows[0]) == {"episode_id", "completion"}
    assert result["predictions_sha256"] == hashlib.sha256(predictions.read_bytes()).hexdigest()
    assert result["prompts_sha256"] == projection_report["prompts_sha256"]
    assert result["model_revision"] == REVISION
    assert result["model_runtime_verified"] is False
    assert result["model_attribution_verified"] is False
    assert result["superiority_claim_authorized"] is False


def test_wrong_dataset_or_prompts_pin_fails_without_publishing(tmp_path):
    data, sha = dataset(tmp_path)
    with pytest.raises(ValueError, match="dataset_sha256"):
        project_holdout_prompts(
            data, expected_dataset_sha256="0"*64, split="test",
            output=tmp_path / "prompts.jsonl", manifest=tmp_path / "projection.json",
        )
    assert not (tmp_path / "prompts.jsonl").exists()
    _, prompts, _, receipt = projection(tmp_path)
    with pytest.raises(ValueError, match="prompts_sha256"):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256="0"*64,
            output=tmp_path / "predictions.jsonl", manifest=tmp_path / "capture.json",
            tokenizer=FakeTokenizer(),
            sampler=lambda prompt, seed: pytest.fail("sampler invoked"),
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        )
    assert not (tmp_path / "predictions.jsonl").exists()


def test_projection_and_capture_fail_closed_on_split_and_revision(tmp_path):
    data, sha = dataset(tmp_path)
    with pytest.raises(ValueError, match="split"):
        project_holdout_prompts(
            data, expected_dataset_sha256=sha, split="train",
            output=tmp_path / "out.jsonl", manifest=tmp_path / "manifest.json",
        )
    _, prompts, _, receipt = projection(tmp_path)
    with pytest.raises(ValueError, match="model_revision"):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=receipt["prompts_sha256"],
            output=tmp_path / "pred.jsonl", manifest=tmp_path / "cap.json",
            tokenizer=FakeTokenizer(), sampler=lambda p, seed: "{}",
            model="Qwen/Qwen3-0.6B", model_revision="main",
        )
    with pytest.raises(ValueError, match="split"):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=receipt["prompts_sha256"],
            output=tmp_path / "pred.jsonl", manifest=tmp_path / "cap.json",
            tokenizer=FakeTokenizer(), sampler=lambda p, seed: "{}",
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
            split="train",
        )


def test_prompt_injection_by_extra_oracle_field_fails_before_sampler(tmp_path):
    _, prompts, _, receipt = projection(tmp_path)
    rows = [json.loads(r) for r in prompts.read_text().splitlines()]
    rows[0]["oracle"] = {"root_cause_id": "stolen"}
    sha = write_rows(prompts, rows)
    with pytest.raises(ValueError, match="fields"):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=sha,
            output=tmp_path / "pred.jsonl", manifest=tmp_path / "cap.json",
            tokenizer=FakeTokenizer(),
            sampler=lambda p, seed: pytest.fail("sampler invoked"),
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        )


def test_incomplete_or_oversized_sampler_output_leaves_no_final_artifacts(tmp_path):
    _, prompts, _, receipt = projection(tmp_path)
    out, manifest = tmp_path/"predictions.jsonl", tmp_path/"capture.json"
    with pytest.raises(ValueError, match="completion"):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=receipt["prompts_sha256"],
            output=out, manifest=manifest, tokenizer=FakeTokenizer(),
            sampler=lambda p, seed: "x"*9000 if seed==43 else "{}",
            model="Qwen/Qwen3-0.6B", model_revision=REVISION, seed=42,
        )
    assert not out.exists() and not manifest.exists()


def test_existing_output_and_manifest_never_overwritten(tmp_path):
    _, prompts, _, receipt = projection(tmp_path)
    out, manifest = tmp_path/"predictions.jsonl", tmp_path/"capture.json"
    out.write_bytes(b"do not overwrite")
    with pytest.raises(FileExistsError):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=receipt["prompts_sha256"],
            output=out, manifest=manifest, tokenizer=FakeTokenizer(),
            sampler=lambda p, seed: "{}",
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        )
    assert out.read_bytes() == b"do not overwrite"
    out.unlink()
    manifest.write_bytes(b"no replace")
    with pytest.raises(FileExistsError):
        capture_holdout_predictions(
            prompts, expected_prompts_sha256=receipt["prompts_sha256"],
            output=out, manifest=manifest, tokenizer=FakeTokenizer(),
            sampler=lambda p, seed: "{}",
            model="Qwen/Qwen3-0.6B", model_revision=REVISION,
        )
    assert manifest.read_bytes() == b"no replace" and not out.exists()


def test_project_cli_and_capture_cli_both_refuse_unsafe_defaults(tmp_path):
    data, sha = dataset(tmp_path)
    project = ROOT / "scripts/project_sre_grpo_holdout.py"
    target = tmp_path / "p.jsonl"
    manifest = tmp_path / "projection.json"
    cmd = [
        sys.executable, str(project), "--dataset", str(data),
        "--expected-dataset-sha256", sha, "--split", "test",
        "--output", str(target), "--manifest", str(manifest),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["prompts_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    script = ROOT / "scripts/sample_sre_grpo_holdout.py"
    base = [
        sys.executable, str(script), "--prompts", str(target),
        "--expected-prompts-sha256", receipt["prompts_sha256"],
        "--model", "Qwen/Qwen3-0.6B", "--revision", REVISION,
        "--output", str(tmp_path / "pred.jsonl"),
        "--manifest", str(tmp_path / "cap.json"),
    ]
    no_execute = subprocess.run(base, capture_output=True, text=True, cwd=ROOT)
    assert no_execute.returncode != 0
    assert "--execute" in no_execute.stderr
    no_lab = subprocess.run(base+["--execute"], capture_output=True, text=True, cwd=ROOT)
    assert no_lab.returncode != 0
    assert "--lab-only" in no_lab.stderr
    wrong_model = subprocess.run(
        base+["--execute","--lab-only","--revision","main"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert wrong_model.returncode != 0
    assert "revision" in wrong_model.stderr.lower()
    assert not (tmp_path / "pred.jsonl").exists()
