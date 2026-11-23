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


def test_competing_symlink_placed_at_report_open_is_rejected(tmp_path, monkeypatch):
    outside = tmp_path / "independent.log"
    outside.write_bytes(b"DO-NOT-CHANGE")
    output = tmp_path / "result.json"
    real_open = os.open
    changed = []

    def swap(path, flags, *args, **kwargs):
        if Path(path) == output and not changed:
            changed.append(True)
            output.symlink_to(outside)
            assert flags & os.O_EXCL
            assert flags & os.O_NOFOLLOW
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    with pytest.raises(OSError):
        verifier.verify(hold_args(output))

    assert changed, "report publication must use an exclusive fd open"
    assert outside.read_bytes() == b"DO-NOT-CHANGE"
