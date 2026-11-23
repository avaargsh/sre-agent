"""Fail closed when publishing the offline three-scope CI consistency report.

The report cannot overwrite independently captured evidence or follow a
symlink. These tests use the actual verifier, but never assert CI authenticity.
"""
import argparse
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_ci_evidence_bundle.py"
spec = importlib.util.spec_from_file_location("ci_evidence_report", SCRIPT)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def hold_args(output: Path) -> argparse.Namespace:
    # An invalid SHA short-circuits input scanning, but still exercises
    # precisely the report-publication path used after real evidence checks.
    return argparse.Namespace(expected_sha="not-a-commit", out=output)


def test_report_symlink_cannot_overwrite_external_bytes(tmp_path):
    outside = tmp_path / "independent.log"
    outside.write_bytes(b"DO-NOT-CHANGE")
    output = tmp_path / "result.json"
    output.symlink_to(outside)

    with pytest.raises(OSError):
        verifier.verify(hold_args(output))

    assert outside.read_bytes() == b"DO-NOT-CHANGE"
    assert output.is_symlink()


def test_existing_report_cannot_be_silently_overwritten(tmp_path):
    output = tmp_path / "result.json"
    output.write_bytes(b"already-published")

    with pytest.raises(FileExistsError):
        verifier.verify(hold_args(output))

    assert output.read_bytes() == b"already-published"


def test_new_report_is_private_and_preserves_hold_semantics(tmp_path):
    output = tmp_path / "result.json"

    assert verifier.verify(hold_args(output)) == 3

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "HOLD"
    assert report["production_eligible"] is False
    assert report["github_run_identity_verified"] is False
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_competing_symlink_placed_at_final_publication_is_rejected(tmp_path, monkeypatch):
    outside = tmp_path / "independent.log"
    outside.write_bytes(b"DO-NOT-CHANGE")
    output = tmp_path / "result.json"
    real_link = os.link
    changed = []

    def race_link(source, destination, *args, **kwargs):
        if Path(destination) == output and not changed:
            changed.append(True)
            output.symlink_to(outside)
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", race_link)
    with pytest.raises(FileExistsError):
        verifier.verify(hold_args(output))

    assert changed, "report must be published with exclusive hard-link creation"
    assert outside.read_bytes() == b"DO-NOT-CHANGE"
    assert output.is_symlink()
    assert not list(tmp_path.glob(".sre-ci-report-*.stage"))


def test_fsync_failure_does_not_publish_partial_report(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    actual_fsync = os.fsync
    failed = []

    def fail_file_fsync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            failed.append(True)
            raise OSError("injected report fsync failure")
        return actual_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_file_fsync)
    with pytest.raises(OSError, match="injected report fsync failure"):
        verifier.verify(hold_args(output))
    assert failed, "test must actually reach staged data fsync"
    assert not output.exists(), "unflushed report must never be published"
    assert not list(tmp_path.glob(".sre-ci-report-*.stage"))


def test_serialization_failure_leaves_no_final_report(tmp_path, monkeypatch):
    output = tmp_path / "result.json"

    def fail_dumps(*args, **kwargs):
        raise ValueError("injected JSON serialization failure")

    monkeypatch.setattr(verifier.json, "dumps", fail_dumps)
    with pytest.raises(ValueError, match="injected JSON serialization failure"):
        verifier.verify(hold_args(output))
    assert not output.exists()
    assert not list(tmp_path.glob(".sre-ci-report-*.stage"))


def test_competing_regular_report_is_preserved_at_publish(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    real_link = os.link
    raced = []

    def race_link(source, destination, *args, **kwargs):
        if Path(destination) == output and not raced:
            raced.append(True)
            output.write_bytes(b"independent-result")
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", race_link)
    with pytest.raises(FileExistsError):
        verifier.verify(hold_args(output))
    assert raced
    assert output.read_bytes() == b"independent-result"
    assert not list(tmp_path.glob(".sre-ci-report-*.stage"))


def test_report_becomes_visible_only_after_staged_bytes_are_flushed(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    real_link = os.link
    staged_bytes = []

    def observe_link(source, destination, *args, **kwargs):
        assert Path(destination) == output
        assert not output.exists()
        staged_bytes.append(Path(source).read_bytes())
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", observe_link)
    assert verifier.verify(hold_args(output)) == 3
    assert len(staged_bytes) == 1
    assert output.read_bytes() == staged_bytes[0]
    assert not list(tmp_path.glob(".sre-ci-report-*.stage"))
