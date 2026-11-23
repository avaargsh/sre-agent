"""Fail-closed, create-only publication of pinned read-only Episode imports.

The final Episode path must never contain a partially written JSONL record,
even if a staging write/fsync/link fails. The original scenario and manifest
remain untrusted unless separately SHA-pinned by the reviewer.
"""

from pathlib import Path

import pytest

import agentic_aiops.grpo_import as importer
from test_grpo_import import inputs, run_import


def test_import_never_writes_directly_to_final_path(tmp_path, monkeypatch):
    source, approval, pin = inputs(tmp_path)
    output = tmp_path / "imported.jsonl"
    original = Path.open

    def forbid_final_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == output and mode in {"x", "xb", "w", "wb", "a", "ab"}:
            raise AssertionError("direct write to final Episode path")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", forbid_final_open)
    receipt = run_import(source, approval, pin, output)
    assert output.read_bytes().endswith(b"\n")
    assert receipt["episode_sha256"]
    assert not list(tmp_path.glob(".sre-episode-stage-*"))


def test_failed_atomic_link_never_publishes_partial_episode(tmp_path, monkeypatch):
    source, approval, pin = inputs(tmp_path)
    output = tmp_path / "imported.jsonl"

    def failed_link(_source, _target):
        raise OSError("simulated link failure")

    monkeypatch.setattr(importer.os, "link", failed_link)
    with pytest.raises(OSError, match="simulated link failure"):
        run_import(source, approval, pin, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".sre-episode-stage-*"))


def test_failed_staging_fsync_never_publishes_partial_episode(tmp_path, monkeypatch):
    source, approval, pin = inputs(tmp_path)
    output = tmp_path / "imported.jsonl"

    def failed_fsync(_fd):
        raise OSError("simulated staging fsync failure")

    monkeypatch.setattr(importer.os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="simulated staging fsync failure"):
        run_import(source, approval, pin, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".sre-episode-stage-*"))


def test_import_preserves_existing_final_file(tmp_path):
    source, approval, pin = inputs(tmp_path)
    output = tmp_path / "imported.jsonl"
    output.write_bytes(b"previous reviewed dataset")
    with pytest.raises(FileExistsError):
        run_import(source, approval, pin, output)
    assert output.read_bytes() == b"previous reviewed dataset"
    assert not list(tmp_path.glob(".sre-episode-stage-*"))
