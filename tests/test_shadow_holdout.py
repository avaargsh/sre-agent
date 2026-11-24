from pathlib import Path
import hashlib
import json

import pytest

from agentic_aiops.shadow_holdout import capture_shadow_holdout, request_local_completion


def fixture(tmp_path):
    source = tmp_path / "prompts.jsonl"
    source.write_text('{"episode_id":"one","prompt":"Read-only observation"}\n')
    return source, hashlib.sha256(source.read_bytes()).hexdigest()


def capture(tmp_path, sampler, pin=None):
    source, digest = fixture(tmp_path)
    return capture_shadow_holdout(
        source, expected_prompts_sha256=pin or digest,
        output=tmp_path / "predictions.jsonl",
        manifest=tmp_path / "capture.json", model="thinkingmachines/Inkling-2-Mini",
        revision="a" * 40, engine="test-fixture", quantization="test-fixture",
        max_tokens=512, seed=42, sample=sampler,
    )


def test_preserves_invalid_completion_without_claiming_model_truth(tmp_path):
    calls = []
    def sample(payload):
        calls.append(payload)
        return {"model":payload["model"], "choices":[{"finish_reason":"stop",
                "message":{"role":"assistant","content":"not valid diagnosis JSON"}}],
                "usage":{"prompt_tokens":12,"completion_tokens":7}}
    report = capture(tmp_path, sample)
    assert len(calls) == 1
    assert "tools" not in calls[0]
    assert calls[0]["messages"] == [{"role":"user","content":"Read-only observation"}]
    assert json.loads((tmp_path / "predictions.jsonl").read_text()) == {
        "episode_id":"one","completion":"not valid diagnosis JSON"}
    assert report["production_eligible"] is False
    assert report["model_attribution_verified"] is False
    assert report["cases"][0]["completion_tokens"] == 7


def test_bad_pin_never_calls_endpoint(tmp_path):
    def sample(_):
        pytest.fail("unapproved data must not be sent")
    with pytest.raises(ValueError):
        capture(tmp_path, sample, "0" * 64)
    assert not (tmp_path / "predictions.jsonl").exists()


def test_parent_symlinked_projection_is_rejected_before_endpoint(tmp_path):
    source, digest = fixture(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)

    def sample(_):
        pytest.fail("symlinked projection must not reach the model endpoint")

    with pytest.raises(ValueError, match="symlink|component"):
        capture_shadow_holdout(
            alias / source.name,
            expected_prompts_sha256=digest,
            output=tmp_path / "predictions.jsonl",
            manifest=tmp_path / "capture.json",
            model="thinkingmachines/Inkling-2-Mini",
            revision="a" * 40,
            engine="test-fixture",
            quantization="test-fixture",
            max_tokens=512,
            seed=42,
            sample=sample,
        )
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not (tmp_path / "capture.json").exists()


def test_model_mismatch_fails_without_publishing(tmp_path):
    def sample(_):
        return {"model":"other", "choices":[{"finish_reason":"stop",
                "message":{"content":"{}"}}]}
    with pytest.raises(ValueError):
        capture(tmp_path, sample)
    assert not (tmp_path / "predictions.jsonl").exists()


def test_tool_call_response_is_rejected(tmp_path):
    def sample(payload):
        return {"model":payload["model"], "choices":[{"finish_reason":"tool_calls",
                "message":{"role":"assistant","content":None,"tool_calls":[{"id":"x"}]}}]}
    with pytest.raises(ValueError):
        capture(tmp_path, sample)
    assert not (tmp_path / "capture.json").exists()


def test_non_loopback_url_cannot_be_supplied():
    with pytest.raises(ValueError):
        request_local_completion("https://example.org/v1", {}, timeout=1)


@pytest.mark.parametrize("usage", [False, 0, [], "", {"prompt_tokens": True}])
def test_malformed_usage_fails_without_publishing(tmp_path, usage):
    def sample(payload):
        return {"model": payload["model"], "choices": [{"finish_reason": "stop",
                "message": {"role": "assistant", "content": "{}"}}], "usage": usage}
    with pytest.raises(ValueError):
        capture(tmp_path, sample)
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not (tmp_path / "capture.json").exists()


def test_manifest_collision_leaves_only_untrusted_orphan_prediction(
    tmp_path, monkeypatch
):
    import os

    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    original_open = os.open

    def open_with_competing_manifest(path, flags, *args, **kwargs):
        # Simulate another writer winning the create-only manifest name after
        # the prediction has been durably published.
        if (os.fspath(path) == manifest.name
                and flags & os.O_CREAT and flags & os.O_EXCL):
            descriptor = original_open(path, flags, *args, **kwargs)
            try:
                os.write(descriptor, b"competing manifest")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise FileExistsError("competing manifest")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_with_competing_manifest)

    def sample(payload):
        return {"model": payload["model"], "choices": [{"finish_reason": "stop",
                "message": {"role": "assistant", "content": "{}"}}]}

    with pytest.raises(FileExistsError):
        capture(tmp_path, sample)
    assert output.is_file()  # orphan is not an admitted capture
    assert output.stat().st_mode & 0o777 == 0o600
    assert manifest.read_bytes() == b"competing manifest"


@pytest.mark.parametrize("finish,extra", [
    ("length", {}),
    ("stop", {"tool_calls": []}),
    ("stop", {"function_call": {}}),
    ("stop", {"role": "tool"}),
])
def test_truncated_or_tool_shaped_responses_fail_without_publication(
    tmp_path, finish, extra
):
    # A syntactically valid truncated JSON completion cannot become a score.
    # Explicit tool-call fields, even when empty, are not text-only evidence.
    def sample(payload):
        return {"model": payload["model"], "choices": [{
            "finish_reason": finish, "message": {"role": "assistant", "content": "{}", **extra},
        }]}
    with pytest.raises(ValueError):
        capture(tmp_path, sample)
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not (tmp_path / "capture.json").exists()


def test_pure_text_response_with_assistant_role_remains_accepted(tmp_path):
    def sample(payload):
        return {"model": payload["model"], "choices": [{
            "finish_reason": "stop", "message": {
                "role": "assistant", "content": "not valid diagnosis JSON"
            }
        }]}
    report = capture(tmp_path, sample)
    assert report["model_attribution_verified"] is False
    assert (tmp_path / "predictions.jsonl").exists()


def test_stale_symlink_check_cannot_admit_projection(tmp_path, monkeypatch):
    # Emulate a pathname becoming a symlink *after* a previous lstat check.
    # Matching bytes/pin alone cannot authorize following an alternate inode.
    source = tmp_path / "prompts.jsonl"
    alternate = tmp_path / "alternate.jsonl"
    alternate.write_text('{"episode_id":"one","prompt":"Read-only observation"}\n')
    source.symlink_to(alternate)
    digest = hashlib.sha256(alternate.read_bytes()).hexdigest()

    real_is_symlink = Path.is_symlink

    def stale_is_symlink(path):
        return False if path == source else real_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", stale_is_symlink)

    def sampler(_):
        pytest.fail("swapped source inode must not reach sampler")

    with pytest.raises((OSError, ValueError)):
        capture_shadow_holdout(
            source, expected_prompts_sha256=digest,
            output=tmp_path / "predictions.jsonl",
            manifest=tmp_path / "capture.json",
            model="thinkingmachines/Inkling-2-Mini", revision="a" * 40,
            engine="lab", quantization="lab", max_tokens=512, seed=42,
            sample=sampler,
        )
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not (tmp_path / "capture.json").exists()


def test_special_fifo_projection_rejected_before_sampler(tmp_path):
    import os
    source = tmp_path / "prompts.jsonl"
    os.mkfifo(source)

    def sampler(_):
        pytest.fail("non-regular source cannot be sampled")

    with pytest.raises((OSError, ValueError)):
        capture_shadow_holdout(
            source, expected_prompts_sha256="0" * 64,
            output=tmp_path / "predictions.jsonl",
            manifest=tmp_path / "capture.json",
            model="thinkingmachines/Inkling-2-Mini", revision="a" * 40,
            engine="lab", quantization="lab", max_tokens=512, seed=42,
            sample=sampler,
        )


@pytest.mark.parametrize("message", [
    {"content": "not valid diagnosis JSON"},
    {"role": "assistant", "content": "text", "refusal": "policy refusal"},
    {"role": "assistant", "content": "text", "audio": {"data": "ignored"}},
])
def test_noncanonical_message_shape_is_rejected_without_publication(tmp_path, message):
    def sample(payload):
        return {"model": payload["model"], "choices": [{
            "finish_reason": "stop", "message": message,
        }]}
    with pytest.raises(ValueError):
        capture(tmp_path, sample)
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not (tmp_path / "capture.json").exists()
