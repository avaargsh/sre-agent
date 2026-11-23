"""CPU-only tests for bounded Adapter files and frozen-byte integrity."""

from dataclasses import replace
from pathlib import Path
import os

import pytest

from agentic_aiops import grpo_adapter as adapter
from agentic_aiops.grpo_adapter import (
    FrozenAdapter, load_pinned_adapter, staged_pinned_adapter,
)
from test_grpo_adapter import MODEL, REV, create_adapter


def load(directory, pins):
    return load_pinned_adapter(
        directory, base_model=MODEL, base_revision=REV, **pins,
    )


def test_regular_sources_read_once_without_path_read_bytes(tmp_path, monkeypatch):
    directory, pins = create_adapter(tmp_path)
    watched = {directory/"adapter_config.json", directory/"adapter_model.safetensors"}
    originally = Path.read_bytes

    def unsafe_read(path):
        if path in watched:
            raise AssertionError("unbounded Path.read_bytes called on Adapter evidence")
        return originally(path)

    monkeypatch.setattr(Path, "read_bytes", unsafe_read)
    frozen = load(directory, pins)
    assert frozen.receipt["lora_tensor_count"] == 2


def test_prevalidated_source_cannot_escape_size_limit_after_open(tmp_path, monkeypatch):
    # Faked fstat metadata represents a source that expanded or was swapped
    # after its path was inspected; the bounded stream read must enforce limit.
    target = tmp_path / "adapter_model.safetensors"
    target.write_bytes(b"0123456789")
    real_fstat = adapter.os.fstat

    class Stat:
        st_mode = 0o100644
        st_size = 2

    monkeypatch.setattr(adapter.os, "fstat", lambda fd: Stat())
    with pytest.raises(ValueError, match="size|oversized|bytes"):
        adapter._read_regular(target, limit=4)
    monkeypatch.setattr(adapter.os, "fstat", real_fstat)


def test_staging_cannot_accept_forged_frozen_config_or_weight_hash(tmp_path):
    directory, pins = create_adapter(tmp_path)
    valid = load(directory, pins)
    for field in ("adapter_config_sha256", "adapter_weights_sha256"):
        forged = replace(valid, receipt={**valid.receipt, field: "0"*64})
        with pytest.raises(ValueError, match="sha256|digest|mismatch|receipt"):
            with staged_pinned_adapter(forged):
                pytest.fail("unverified bytes were staged")


def test_staging_cannot_accept_forged_inmemory_weight_bytes(tmp_path):
    directory, pins = create_adapter(tmp_path)
    valid = load(directory, pins)
    forged = replace(valid, weights_raw=b"arbitrary model bytes")
    with pytest.raises(ValueError):
        with staged_pinned_adapter(forged):
            pytest.fail("mutated weights were staged")


def test_staging_rejects_forged_tensor_count_even_if_raw_digests_match(tmp_path):
    directory, pins = create_adapter(tmp_path)
    valid = load(directory, pins)
    forged = replace(
        valid, receipt={**valid.receipt, "lora_tensor_count": 4},
    )
    with pytest.raises(ValueError, match="receipt|tensor"):
        with staged_pinned_adapter(forged):
            pytest.fail("forged tensor count accepted")


@pytest.mark.parametrize("field", ["use_dora", "use_qalora", "lora_bias"])
def test_json_zero_cannot_impersonate_false_disabled_flags(tmp_path, field):
    directory, pins = create_adapter(tmp_path, config_change={field: 0})
    with pytest.raises(ValueError, match=field):
        load(directory, pins)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO test requires POSIX")
def test_adapter_fifo_source_rejected_before_opening_and_reading(tmp_path):
    directory, pins = create_adapter(tmp_path)
    target = directory / "adapter_model.safetensors"
    target.unlink()
    os.mkfifo(target)
    with pytest.raises(ValueError, match="size|type|regular"):
        load(directory, pins)


def test_pinned_frozen_adapter_stage_stays_exact_and_private(tmp_path):
    directory, pins = create_adapter(tmp_path)
    frozen = load(directory, pins)
    with staged_pinned_adapter(frozen) as path:
        assert (path/"adapter_config.json").read_bytes() == frozen.config_raw
        assert (path/"adapter_model.safetensors").read_bytes() == frozen.weights_raw
        assert not (path/"README.md").exists()
        assert (path.stat().st_mode & 0o777) == 0o700
    assert not path.exists()
