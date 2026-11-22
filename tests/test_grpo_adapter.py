"""Pinned, locally frozen PEFT LoRA adapter input security tests (CPU only)."""

import hashlib
import json
import struct
from pathlib import Path

import pytest

from agentic_aiops.grpo_adapter import (
    load_pinned_adapter, staged_pinned_adapter,
)


MODEL = "Qwen/Qwen3-0.6B"
REV = "a" * 40


def safetensors_bytes(*, corrupt_offsets=False, rogue_tensor=False):
    rows = {}
    offset = 0
    for suffix in ("lora_A.weight", "lora_B.weight"):
        name = f"base_model.model.model.layers.0.self_attn.q_proj.{suffix}"
        if rogue_tensor:
            name = name.replace("lora_B.weight", "embed_tokens.weight")
        start, end = offset, offset + 8
        rows[name] = {
            "dtype": "F16", "shape": [2, 2],
            "data_offsets": [start, 200 if corrupt_offsets else end],
        }
        offset = end
    header = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()
    return struct.pack("<Q", len(header)) + header + bytes(range(offset))


def create_adapter(tmp_path, *, config_change=None, weights=None):
    directory = tmp_path / "adapter"
    directory.mkdir()
    config = {
        "peft_type": "LORA",
        "task_type": "CAUSAL_LM",
        "base_model_name_or_path": MODEL,
        "revision": REV,
        "target_modules": ["q_proj"],
        "r": 2,
        "lora_alpha": 16,
        "auto_mapping": None,
        "modules_to_save": None,
    }
    if config_change:
        config.update(config_change)
    c = directory / "adapter_config.json"
    w = directory / "adapter_model.safetensors"
    c.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    w.write_bytes(safetensors_bytes() if weights is None else weights)
    pins = {
        "expected_adapter_config_sha256": hashlib.sha256(c.read_bytes()).hexdigest(),
        "expected_adapter_weights_sha256": hashlib.sha256(w.read_bytes()).hexdigest(),
    }
    return directory, pins


def load(directory, pins, **kwargs):
    return load_pinned_adapter(
        directory, base_model=MODEL, base_revision=REV,
        **pins, **kwargs,
    )


def test_valid_pinned_adapter_is_frozen_and_staged_without_original_reopen(tmp_path):
    directory, pins = create_adapter(tmp_path)
    frozen = load(directory, pins)
    assert frozen.receipt["adapter_config_sha256"] == pins["expected_adapter_config_sha256"]
    assert frozen.receipt["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    assert frozen.receipt["base_model_revision"] == REV
    assert frozen.receipt["lora_tensor_count"] == 2
    assert frozen.receipt["model_attribution_verified"] is False
    old_raw = (directory / "adapter_model.safetensors").read_bytes()
    with staged_pinned_adapter(frozen) as staged:
        assert (Path(staged) / "adapter_model.safetensors").read_bytes() == old_raw
        assert (Path(staged) / "adapter_config.json").read_bytes() == (
            directory / "adapter_config.json"
        ).read_bytes()
        assert list(sorted(p.name for p in Path(staged).iterdir())) == [
            "adapter_config.json", "adapter_model.safetensors"
        ]
        (directory / "adapter_model.safetensors").write_bytes(b"corrupted later")
        assert (Path(staged) / "adapter_model.safetensors").read_bytes() == old_raw
    assert not Path(staged).exists()


def test_wrong_pin_fails_closed(tmp_path):
    directory, pins = create_adapter(tmp_path)
    for name in pins:
        with pytest.raises(ValueError, match="sha256"):
            load(directory, {**pins, name: "0"*64})


@pytest.mark.parametrize("config_change,match", [
    ({"base_model_name_or_path": "other/Qwen"}, "base_model"),
    ({"revision": "main"}, "revision"),
    ({"peft_type": "PROMPT_TUNING"}, "peft_type"),
    ({"task_type": "SEQ_2_SEQ_LM"}, "task_type"),
    ({"auto_mapping": {"parent_library": "malicious"}}, "auto_mapping"),
    ({"modules_to_save": ["lm_head"]}, "modules_to_save"),
    ({"target_modules": ["q_proj", "bad_module"]}, "target_modules"),
])
def test_rejects_untrusted_adapter_config(tmp_path, config_change, match):
    directory, pins = create_adapter(tmp_path, config_change=config_change)
    with pytest.raises(ValueError, match=match):
        load(directory, pins)


@pytest.mark.parametrize("weights,match", [
    (b"pickle-serialized", "safetensors"),
    (safetensors_bytes(corrupt_offsets=True), "offset"),
    (safetensors_bytes(rogue_tensor=True), "LoRA"),
])
def test_rejects_pickle_invalid_offsets_and_nonlora_weights(tmp_path, weights, match):
    directory, pins = create_adapter(tmp_path, weights=weights)
    with pytest.raises(ValueError, match=match):
        load(directory, pins)


def test_symlinks_or_unexpected_executable_files_rejected(tmp_path):
    directory, pins = create_adapter(tmp_path)
    (directory / "setup.py").write_text("raise SystemExit('arbitrary code')\n")
    with pytest.raises(ValueError, match="unexpected"):
        load(directory, pins)
    (directory / "setup.py").unlink()
    (directory / "adapter_model.safetensors").rename(tmp_path / "real.safetensors")
    (directory / "adapter_model.safetensors").symlink_to(tmp_path / "real.safetensors")
    with pytest.raises(ValueError, match="symlink"):
        load(directory, pins)


def test_adapter_files_read_only_once_and_never_reopened_after_pin(tmp_path, monkeypatch):
    directory, pins = create_adapter(tmp_path)
    watched = {
        directory/"adapter_config.json", directory/"adapter_model.safetensors",
    }
    calls = {p: 0 for p in watched}
    original = Path.read_bytes

    def trace(path):
        if path in calls:
            calls[path] += 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", trace)
    frozen = load(directory, pins)
    with staged_pinned_adapter(frozen) as staged:
        assert (Path(staged)/"adapter_model.safetensors").is_file()
    assert calls == {path: 1 for path in watched}
