"""Qwen3 offline rollout capture contract; fake model used only in CPU tests."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_rollout_capture import capture_rollout_groups


ROOT = Path(__file__).resolve().parents[1]
REV = "a" * 40


def episode(eid="oom-01", *, split="train", family="memory-oom"):
    return {
        "schema_version": "sre.grpo.episode/v1", "episode_id": eid,
        "fault_family": family, "split": split,
        "alert": "Pod restart count rising",
        "observations": [
            {"evidence_id": "e1", "tool": "kubernetes.get_pods",
             "text": "Container termination OOMKilled"},
        ],
        "oracle": {
            "answerable": True, "root_cause_id": "oom_killed",
            "required_evidence_ids": ["e1"],
        },
    }


def dataset_file(tmp_path):
    path = tmp_path / "dataset.jsonl"
    rows = [episode(), episode("heldout", split="test", family="dns-outage")]
    rows[1]["alert"] = "DNS failure"
    rows[1]["observations"][0]["text"] = "DNS NXDOMAIN"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


class ToyTokenizer:
    def apply_chat_template(self, messages, **kwargs):
        assert kwargs["enable_thinking"] is False
        assert kwargs["add_generation_prompt"] is True
        return "[chat] " + messages[0]["content"] + "\n[assistant]"

    def __call__(self, text, **kwargs):
        assert kwargs.get("add_special_tokens") is False
        return {"input_ids": text.split()}


def capture(tmp_path, sampler, *, digest=None, revision=REV, size=4,
            out=None, manifest=None):
    data, pinned = dataset_file(tmp_path)
    return capture_rollout_groups(
        data,
        expected_dataset_sha256=pinned if digest is None else digest,
        output=out or tmp_path / "out.jsonl",
        manifest=manifest or tmp_path / "capture-manifest.json",
        tokenizer=ToyTokenizer(),
        sampler=sampler,
        model="Qwen/Qwen3-0.6B",
        model_revision=revision,
        group_size=size,
        seed=101,
        max_new_tokens=192,
    )


def test_exact_train_group_raw_output_and_model_revision_manifest(tmp_path):
    calls = []

    def sampler(prompt, seed):
        calls.append((prompt, seed))
        return '{"root_cause_id":"unknown","evidence_ids":[],"stop_reason":"insufficient_evidence"}'

    report = capture(tmp_path, sampler)
    assert [seed for _, seed in calls] == [101, 102, 103, 104]
    assert all("oom_killed" not in prompt for prompt, _ in calls)
    assert all("required_evidence_ids" not in prompt for prompt, _ in calls)
    assert all("heldout" not in prompt for prompt, _ in calls)
    raw = (tmp_path / "out.jsonl").read_bytes()
    row, = [json.loads(line) for line in raw.decode().splitlines()]
    assert set(row) == {"episode_id", "completions"}
    assert row["episode_id"] == "oom-01"
    assert len(row["completions"]) == 4
    assert report["rollouts_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["model_revision"] == REV
    assert report["model_runtime_independently_verified"] is False
    assert report["training_admission_authorized"] is False
    assert report["source_classification"] == "unverified-model-capture"
    assert report["prompt_sha256"] != report["rollouts_sha256"]
    assert json.loads((tmp_path / "capture-manifest.json").read_text()) == report


def test_bad_dataset_digest_aborts_before_model_call_and_no_outputs(tmp_path):
    calls = []
    with pytest.raises(ValueError, match="dataset_sha256"):
        capture(tmp_path, lambda p, s: calls.append(s), digest="0" * 64)
    assert not calls
    assert not (tmp_path / "out.jsonl").exists()
    assert not (tmp_path / "capture-manifest.json").exists()


@pytest.mark.parametrize("revision", ["main", "deadbeef", "A" * 40, "../local", ""])
def test_unpinned_revision_rejected_before_sampling(tmp_path, revision):
    with pytest.raises(ValueError, match="model_revision"):
        capture(tmp_path, lambda p, s: pytest.fail("model called"), revision=revision)


def test_missing_or_incomplete_group_does_not_publish_partial_file(tmp_path):
    count = 0

    def broken(prompt, seed):
        nonlocal count
        count += 1
        return None if count == 3 else "{}"

    with pytest.raises(ValueError, match="completion"):
        capture(tmp_path, broken)
    assert not (tmp_path / "out.jsonl").exists()
    assert not (tmp_path / "capture-manifest.json").exists()


def test_invalid_completion_rejected_but_original_newlines_preserved(tmp_path):
    with pytest.raises(ValueError, match="completion"):
        capture(tmp_path, lambda p, seed: "x" * 9000)
    # The model may output malformed or pretty-printed JSON. Keep the exact
    # decoded content for independent scoring instead of cherry-picking.
    capture(tmp_path, lambda p, seed: "{\\n invalid JSON \\n}")
    row = json.loads((tmp_path / "out.jsonl").read_text())
    assert row["completions"] == ["{\\n invalid JSON \\n}"] * 4


def test_output_and_manifest_are_create_only_and_no_overwrite(tmp_path):
    target = tmp_path / "out.jsonl"
    target.write_text("protected", encoding="utf-8")
    with pytest.raises(FileExistsError):
        capture(tmp_path, lambda p, s: "{}", out=target)
    assert target.read_text() == "protected"
    target.unlink()
    m = tmp_path / "capture-manifest.json"
    m.write_text("protected", encoding="utf-8")
    with pytest.raises(FileExistsError):
        capture(tmp_path, lambda p, s: "{}", manifest=m)
    assert m.read_text() == "protected"
    assert not target.exists()


def test_bounds_and_generation_settings_fail_before_sampling(tmp_path):
    with pytest.raises(ValueError, match="group_size"):
        capture(tmp_path, lambda p, s: pytest.fail("model called"), size=1)
    with pytest.raises(ValueError, match="group_size"):
        capture(tmp_path, lambda p, s: pytest.fail("model called"), size=65)


def test_cli_never_loads_model_without_explicit_lab_flag_or_revision(tmp_path):
    dataset, sha = dataset_file(tmp_path)
    script = ROOT / "scripts/sample_sre_grpo.py"
    args = [
        sys.executable, str(script),
        "--execute", "--dataset", str(dataset),
        "--expected-dataset-sha256", sha,
        "--model", "Qwen/Qwen3-0.6B",
        "--revision", REV,
        "--output", str(tmp_path / "capture.jsonl"),
        "--manifest", str(tmp_path / "capture.json"),
    ]
    rejected = subprocess.run(args, capture_output=True, text=True, cwd=ROOT)
    assert rejected.returncode != 0
    assert "--lab-only" in rejected.stderr
    assert not (tmp_path / "capture.jsonl").exists()
    missing_revision = subprocess.run(
        [*args[:], "--lab-only", "--revision", "main"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert missing_revision.returncode != 0
    assert "revision" in missing_revision.stderr.lower()


def test_capture_parses_exactly_the_bytes_that_pass_the_external_hash(
    tmp_path, monkeypatch
):
    """Data changes between verification and parsing must not be usable."""
    from pathlib import Path
    from agentic_aiops.grpo_rollout_capture import validate_capture_inputs

    dataset, pinned = dataset_file(tmp_path)
    original_read = Path.read_bytes
    reads = []

    def spy_read(path):
        if path == dataset:
            reads.append(1)
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", spy_read)
    selected, digest = validate_capture_inputs(
        dataset, expected_dataset_sha256=pinned,
        model="Qwen/Qwen3-0.6B", model_revision=REV,
        group_size=4, seed=42, max_new_tokens=192,
    )
    assert len(selected) == 1
    assert digest == pinned
    assert len(reads) == 1, "untrusted dataset was re-read after its SHA pin"


def test_capture_does_not_publish_a_partial_output_when_write_fails(
    tmp_path, monkeypatch
):
    """Injected filesystem write failure must leave no final output/manifest."""
    from agentic_aiops.grpo_rollout_capture import capture_rollout_groups

    data, pinned = dataset_file(tmp_path)
    output = tmp_path / "out.jsonl"
    manifest = tmp_path / "capture.json"
    original_open = Path.open

    class FailingWriter:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

        def write(self, value):
            self.wrapped.write(value[:3])
            raise OSError("injected disk full")

    def broken_open(path, mode="r", *args, **kwargs):
        wrapped = original_open(path, mode, *args, **kwargs)
        if mode == "xb" and (
            path == output or path.name.startswith(".sre-grpo-")
        ):
            return FailingWriter(wrapped)
        return wrapped

    monkeypatch.setattr(Path, "open", broken_open)
    with pytest.raises(OSError, match="disk full"):
        capture_rollout_groups(
            data, expected_dataset_sha256=pinned, output=output,
            manifest=manifest, tokenizer=ToyTokenizer(),
            sampler=lambda p, s: "not json",
            model="Qwen/Qwen3-0.6B", model_revision=REV,
        )
    assert not output.exists(), "partial rollout was published under final path"
    assert not manifest.exists()
