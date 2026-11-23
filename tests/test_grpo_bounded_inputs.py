"""Avoid unbounded file reads before GRPO ingestion size checks.

These CPU-only cases exercise the actual file entrypoints. In particular,
4 MiB is an admission bound, not just a post-allocation rejection limit.
"""

from pathlib import Path

import pytest

from agentic_aiops.grpo_eval import load_predictions
from agentic_aiops.grpo_import import _load_json
from agentic_aiops.grpo_train_proof import freeze_train_dataset
from agentic_aiops.grpo_training import (
    _read_bounded_bytes,
    load_episodes,
)


@pytest.mark.parametrize("kind", ["episode", "prediction", "frozen-train", "approval"])
def test_oversized_inputs_are_rejected_without_unbounded_read_bytes(
    tmp_path, monkeypatch, kind,
):
    path = tmp_path / "oversized-untrusted-input.jsonl"
    with path.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 10)

    # Path.read_bytes reads the ENTIRE source before checking any size cap.
    # It must not be used by any of these bounded ingress paths.
    def forbid_read_bytes(_path):
        raise AssertionError("unbounded Path.read_bytes called")

    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)
    with pytest.raises(ValueError, match="oversized"):
        if kind == "episode":
            load_episodes(path)
        elif kind == "prediction":
            load_predictions(path)
        elif kind == "frozen-train":
            freeze_train_dataset(path)
        else:
            _load_json(path, name="approval")


def test_bounded_reader_enforces_empty_and_limit_plus_one(tmp_path):
    path = tmp_path / "source"
    path.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        _read_bounded_bytes(path, limit=16, name="dataset")
    path.write_bytes(b"a" * 16)
    assert _read_bounded_bytes(path, limit=16, name="dataset") == b"a" * 16
    path.write_bytes(b"a" * 17)
    with pytest.raises(ValueError, match="oversized"):
        _read_bounded_bytes(path, limit=16, name="dataset")


def test_bounded_reader_does_not_request_unlimited_read(tmp_path, monkeypatch):
    path = tmp_path / "source"
    path.write_bytes(b"valid bytes")
    original_open = Path.open
    read_sizes = []

    class AuditedReader:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

        def read(self, n=-1):
            read_sizes.append(n)
            return self.wrapped.read(n)

    def audited_open(self, *args, **kwargs):
        opened = original_open(self, *args, **kwargs)
        return AuditedReader(opened) if self == path else opened

    monkeypatch.setattr(Path, "open", audited_open)
    assert _read_bounded_bytes(path, limit=32, name="source") == b"valid bytes"
    assert read_sizes == [33]
