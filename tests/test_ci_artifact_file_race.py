"""Adversarial admission tests for CI evidence file descriptor binding.

These tests run the exact production helper from scripts/verify_ci_evidence_bundle.py,
not a copy of its implementation. They do not authenticate CI runner identity.
"""
import importlib.util
import os
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_ci_evidence_bundle.py"
spec = importlib.util.spec_from_file_location("sre_ci_evidence_reader", SCRIPT)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def test_symlink_replacement_at_descriptor_open_is_rejected(tmp_path, monkeypatch):
    proof = tmp_path / "python-pytest.log"
    proof.write_bytes(b"original")
    outside = tmp_path / "forged.log"
    outside.write_bytes(b"untrusted")
    original_open = os.open
    replaced = []

    def swap_at_open(path, flags, *args, **kwargs):
        if Path(path) == proof and not replaced:
            replaced.append(True)
            proof.unlink()
            proof.symlink_to(outside)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_at_open)
    with pytest.raises((OSError, ValueError)):
        verifier.read_regular(proof, 1024, "Python proof")
    assert replaced, "reader must open a no-follow descriptor, not trust a prior pathname check"


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="requires POSIX FIFO and nonblocking file descriptor",
)
def test_fifo_replacement_at_descriptor_open_cannot_hang_or_pass(
    tmp_path, monkeypatch,
):
    proof = tmp_path / "go-race.log"
    proof.write_bytes(b"original")
    original_open = os.open
    replaced = []

    def swap_at_open(path, flags, *args, **kwargs):
        if Path(path) == proof and not replaced:
            replaced.append(True)
            proof.unlink()
            os.mkfifo(proof)
            assert flags & os.O_NONBLOCK, "a swapped FIFO must never block CI verification"
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_at_open)
    with pytest.raises((OSError, ValueError)):
        verifier.read_regular(proof, 1024, "Go proof")
    assert replaced


def test_reader_preserves_empty_and_nonempty_log_support(tmp_path):
    proof = tmp_path / "log.txt"
    for data in (b"", b"ok\\n"):
        proof.write_bytes(data)
        assert verifier.read_regular(proof, 1024, "test log") == data


def test_reader_rejects_oversized_regular_file(tmp_path):
    proof = tmp_path / "log.txt"
    proof.write_bytes(b"a" * 17)
    with pytest.raises(ValueError, match="oversized"):
        verifier.read_regular(proof, 16, "test log")
