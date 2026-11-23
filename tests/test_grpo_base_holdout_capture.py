"""Base Holdout capture is a CPU-checkable content contract, not model proof."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_aiops.grpo_holdout_projection as projection
from agentic_aiops.grpo_base_holdout_capture import (
    capture_base_holdout_predictions,
    validate_holdout_prompts,
)
from agentic_aiops.grpo_base_holdout_verify import verify_base_holdout_chain
from agentic_aiops.grpo_holdout_projection import project_holdout_prompts

ROOT = Path(__file__).resolve().parents[1]
MODEL = "Qwen/Qwen3-0.6B"
REV = "a" * 40


class ToyTokenizer:
    def __init__(self):
        self.messages = []

    def apply_chat_template(self, messages, **kw):
        assert kw == {
            "tokenize": False,
            "add_generation_prompt": True,
            "enable_thinking": False,
        }
        self.messages.extend(messages)
        assert len(messages) == 1 and messages[0]["role"] == "user"
        return "QWEN3 CHAT: " + messages[0]["content"]

    def __call__(self, text, **kw):
        assert kw == {"add_special_tokens": False}
        return {"input_ids": text.split()}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path):
    dataset = tmp_path / "private-episodes.jsonl"
    rows = []
    for eid in ("holdout-1", "holdout-2"):
        rows.append({
            "schema_version": "sre.grpo.episode/v1",
            "episode_id": eid, "fault_family": eid,
            "split": "test", "alert": f"alert for {eid}",
            "observations": [{
                "evidence_id": "e1", "tool": "kubernetes.get_pods",
                "text": f"Read-only status for {eid}",
            }],
            "oracle": {
                "answerable": False, "root_cause_id": "unknown",
                "required_evidence_ids": [],
            },
        })
    dataset.write_bytes((
        "\n".join(json.dumps(row, sort_keys=True) for row in rows)+"\n"
    ).encode())
    prompts = tmp_path / "prompts.jsonl"
    projection_manifest = tmp_path / "projection.json"
    projection_report = project_holdout_prompts(
        dataset, expected_dataset_sha256=sha(dataset),
        output=prompts, manifest=projection_manifest, split="test",
    )
    return dataset, prompts, projection_manifest, projection_report


def capture(tmp_path, sampler=None, tokenizer=None, **overrides):
    ds, prompts, proj_manifest, projection_report = fixture(tmp_path)
    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    kw = {
        "expected_prompts_sha256": projection_report["prompts_sha256"],
        "output": output, "manifest": manifest,
        "tokenizer": tokenizer if tokenizer is not None else ToyTokenizer(),
        "sampler": sampler if sampler is not None else (lambda _prompt, _seed: "{}"),
        "model": MODEL, "model_revision": REV,
        "split": "test", "seed": 42, "max_new_tokens": 192,
    }
    kw.update(overrides)
    return ds, prompts, proj_manifest, output, manifest, kw


def test_fake_sampler_receipt_is_compatible_with_real_five_file_verifier(tmp_path):
    token = ToyTokenizer()
    calls = []
    def sample(chat, seed):
        calls.append((chat, seed))
        return "{invalid raw response}" if seed == 42 else json.dumps({
            "root_cause_id": "unknown", "evidence_ids": [],
            "stop_reason": "insufficient_evidence",
        })
    ds, prompts, proj, output, manifest, kw = capture(
        tmp_path, sampler=sample, tokenizer=token,
    )
    receipt = capture_base_holdout_predictions(prompts, **kw)
    assert [seed for _,seed in calls] == [42,43]
    assert all("oracle" not in text.lower() for text, _ in calls)
    assert len(token.messages) == 2
    rows = [json.loads(row) for row in output.read_text().splitlines()]
    assert [row["episode_id"] for row in rows] == ["holdout-1","holdout-2"]
    assert rows[0]["completion"] == "{invalid raw response}"
    assert set(rows[0]) == {"episode_id", "completion"}
    assert receipt["schema_version"] == "sre.grpo.holdout-capture/v1"
    assert receipt["source_classification"] == "UNVERIFIED_MODEL_HOLDOUT_CAPTURE"
    assert receipt["model_runtime_verified"] is False
    assert receipt["production_eligible"] is False
    assert receipt == json.loads(manifest.read_text())
    audited = verify_base_holdout_chain(
        dataset=ds, prompts=prompts, projection_manifest=proj,
        predictions=output, capture_manifest=manifest,
        expected_dataset_sha256=sha(ds),
        expected_prompts_sha256=sha(prompts),
        expected_projection_manifest_sha256=sha(proj),
        expected_predictions_sha256=sha(output),
        expected_capture_manifest_sha256=sha(manifest),
        model=MODEL, model_revision=REV,
    )
    assert audited["capture_claims_content_consistent"] is True
    assert audited["model_runtime_verified"] is False


def test_capture_does_not_reopen_private_dataset(tmp_path):
    ds, prompts, proj, output, manifest, kw = capture(tmp_path)
    ds.unlink()
    proj.unlink()
    assert capture_base_holdout_predictions(prompts, **kw)["cases"] == 2


def test_oversized_prompt_file_fails_before_unbounded_read(tmp_path, monkeypatch):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    with prompts.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 1)
    def unsafe_read(_path):
        raise AssertionError("unbounded Path.read_bytes called")
    monkeypatch.setattr(Path, "read_bytes", unsafe_read)
    with pytest.raises(ValueError, match="oversized"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()


def test_symlink_projected_input_is_rejected(tmp_path):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    link = tmp_path / "prompts-symlink.jsonl"
    link.symlink_to(prompts)
    with pytest.raises(ValueError, match="non-symlink"):
        capture_base_holdout_predictions(link, **kw)
    assert not output.exists() and not manifest.exists()


def test_oracle_injected_into_projection_rejected_even_if_hash_recomputed(tmp_path):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    rows = [json.loads(line) for line in prompts.read_text().splitlines()]
    rows[0]["oracle"] = {"root_cause_id": "stolen"}
    prompts.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
    kw["expected_prompts_sha256"] = sha(prompts)
    with pytest.raises(ValueError, match="fields"):
        capture_base_holdout_predictions(
            prompts, **{**kw, "sampler": lambda *_: pytest.fail("sampler invoked")}
        )
    assert not output.exists() and not manifest.exists()


@pytest.mark.parametrize("bad", [None, 15, "\ud800", "x" * 8193])
def test_invalid_completion_cannot_publish(tmp_path, bad):
    _, prompts, _, output, manifest, kw = capture(
        tmp_path, sampler=lambda *_: bad,
    )
    with pytest.raises((ValueError, UnicodeEncodeError), match="completion"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()


def test_sampler_failure_keeps_both_destinations_absent(tmp_path):
    _, prompts, _, output, manifest, kw = capture(
        tmp_path, sampler=lambda *_: (_ for _ in ()).throw(RuntimeError("sampler failed")),
    )
    with pytest.raises(RuntimeError, match="sampler failed"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()


def test_publication_second_link_failure_rolls_back_owned_output(tmp_path, monkeypatch):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    original_link = projection.os.link
    def fail_second(src, dst, *args, **kwargs):
        if Path(dst) == manifest:
            raise OSError("simulated manifest link failed")
        return original_link(src, dst, *args, **kwargs)
    monkeypatch.setattr(projection.os, "link", fail_second)
    with pytest.raises(OSError, match="simulated manifest link"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()
    assert not list(tmp_path.glob(".sre-grpo-*.stage"))


def test_existing_prediction_or_manifest_never_overwritten(tmp_path):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    output.write_bytes(b"reviewed")
    with pytest.raises(FileExistsError):
        capture_base_holdout_predictions(prompts, **kw)
    assert output.read_bytes() == b"reviewed"
    output.unlink()
    manifest.write_bytes(b"reviewed manifest")
    with pytest.raises(FileExistsError):
        capture_base_holdout_predictions(prompts, **kw)
    assert manifest.read_bytes() == b"reviewed manifest"


@pytest.mark.parametrize("model,revision", [
    ("another-org/Qwen3", REV), (MODEL, "main"), (MODEL, "b" * 39),
])
def test_unpinned_or_unapproved_model_preflight_fails(tmp_path,model,revision):
    _, prompts, _, output, manifest, kw = capture(
        tmp_path, model=model, model_revision=revision,
        sampler=lambda *_: pytest.fail("sampler invoked"),
    )
    with pytest.raises(ValueError, match="model|revision"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()


def test_seed_range_and_tokenizer_length_fail_before_sampler(tmp_path):
    _, prompts, _, output, manifest, kw = capture(
        tmp_path, seed=2**31 - 1,
        sampler=lambda *_: pytest.fail("sampler invoked"),
    )
    with pytest.raises(ValueError, match="seed range"):
        capture_base_holdout_predictions(prompts, **kw)

    class ExcessTokens(ToyTokenizer):
        def __call__(self, text, **kw):
            return {"input_ids": [1] * 1025}

    kw["seed"] = 42
    kw["tokenizer"] = ExcessTokens()
    with pytest.raises(ValueError, match="truncated"):
        capture_base_holdout_predictions(prompts, **kw)
    assert not output.exists() and not manifest.exists()


def test_real_gpu_cli_requires_explicit_flags_and_preflights_revision(tmp_path):
    _, prompts, _, output, manifest, kw = capture(tmp_path)
    cmd = [
        sys.executable,
        str(ROOT / "scripts/sample_sre_grpo_base_holdout.py"),
        "--prompts", str(prompts),
        "--expected-prompts-sha256", kw["expected_prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--output", str(output), "--manifest", str(manifest),
    ]
    no_gate = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    assert no_gate.returncode != 0
    assert "--execute" in no_gate.stderr and "--lab-only" in no_gate.stderr
    bad_revision = subprocess.run(
        cmd + ["--execute", "--lab-only", "--revision", "main"],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert bad_revision.returncode == 3
    assert "revision" in bad_revision.stderr
    assert not output.exists() and not manifest.exists()


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_unicode_projection_to_base_capture_to_five_file_replay(tmp_path, separator):
    dataset = tmp_path / "unicode-episodes.jsonl"
    record = {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": "unicode-001", "fault_family": "unicode-alert",
        "split": "test", "alert": "alert" + separator + "continued",
        "observations": [{
            "evidence_id": "event1", "tool": "kubernetes.get_events",
            "text": "read-only" + separator + "observation",
        }],
        "oracle": {
            "answerable": False, "root_cause_id": "unknown",
            "required_evidence_ids": [],
        },
    }
    dataset.write_bytes((json.dumps(record, ensure_ascii=False) + "\n").encode())
    prompts, projected = tmp_path / "prompts.jsonl", tmp_path / "projection.json"
    project_holdout_prompts(
        dataset, expected_dataset_sha256=sha(dataset),
        output=prompts, manifest=projected, split="test",
    )
    assert separator in prompts.read_text()
    predictions, captured = tmp_path / "predictions.jsonl", tmp_path / "capture.json"
    report = capture_base_holdout_predictions(
        prompts, expected_prompts_sha256=sha(prompts),
        output=predictions, manifest=captured,
        tokenizer=ToyTokenizer(),
        sampler=lambda *_: "raw" + separator + "invalid",
        model=MODEL, model_revision=REV,
    )
    assert report["cases"] == 1
    audited = verify_base_holdout_chain(
        dataset=dataset, prompts=prompts, projection_manifest=projected,
        predictions=predictions, capture_manifest=captured,
        expected_dataset_sha256=sha(dataset),
        expected_prompts_sha256=sha(prompts),
        expected_projection_manifest_sha256=sha(projected),
        expected_predictions_sha256=sha(predictions),
        expected_capture_manifest_sha256=sha(captured),
        model=MODEL, model_revision=REV,
    )
    assert audited["capture_claims_content_consistent"] is True
    assert audited["model_attribution_verified"] is False
