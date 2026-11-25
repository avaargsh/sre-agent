"""Validate the lab's offline replay receipt against frozen input and prediction."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/check_replay.py"


@pytest.fixture
def evidence(tmp_path):
    archive = tmp_path / "capture.json"
    archive.write_bytes(b'{"capture":"lab fixture"}\n')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pin = tmp_path / "archive.sha256"
    pin.write_text(digest + "\n", encoding="ascii")
    receipt = tmp_path / "receipt.json"
    prediction = tmp_path / "prediction.json"
    body = {
        "schema_version": "sre.service-endpoints-replay/v1",
        "status": "REPLAYED", "archive_sha256": digest,
        "classification": "READY_ENDPOINTS_OBSERVED", "ready_endpoints": 2,
        "source_authenticated": False, "causality_verified": False,
        "execution_authorized": False,
    }
    pred = {"schema_version": "sre.endpoint-observation/v1",
            "classification": "READY_ENDPOINTS_OBSERVED", "ready_endpoints": 2}
    receipt.write_text(json.dumps(body), encoding="utf-8")
    prediction.write_text(json.dumps(pred), encoding="utf-8")
    return archive, pin, receipt, prediction, body, pred


def invoke(*args):
    return subprocess.run([sys.executable, "-O", str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=5)


def test_pin_exact_bytes(evidence):
    archive, pin, *_ = evidence
    result = invoke("pin", archive)
    assert result.returncode == 0, result.stderr
    assert result.stdout == pin.read_text(encoding="ascii")


@pytest.mark.parametrize("mode", ["healthy", "zero", "tamper_archive", "tamper_pin",
    "wrong_digest", "wrong_count", "bool_count", "unknown", "auth", "causal",
    "execute", "extra", "missing", "duplicate", "prediction_count", "prediction_bool",
    "prediction_schema", "prediction_extra", "prediction_missing", "receipt_symlink", "receipt_fifo", "oversized_archive"])
def test_verify_receipt(evidence, mode):
    archive, pin, receipt, prediction, body, pred = evidence
    if mode == "zero":
        for value in (body, pred):
            value.update(classification="NO_READY_ENDPOINTS_OBSERVED", ready_endpoints=0)
    elif mode == "tamper_archive":
        archive.write_bytes(archive.read_bytes() + b" ")
    elif mode == "tamper_pin":
        pin.write_text("0" * 64 + "\n", encoding="ascii")
    elif mode == "wrong_digest":
        body["archive_sha256"] = "0" * 64
    elif mode == "wrong_count":
        body["ready_endpoints"] = 3
    elif mode == "bool_count":
        body["ready_endpoints"] = True
    elif mode == "unknown":
        body["classification"] = pred["classification"] = "UNKNOWN"
    elif mode in ("auth", "causal", "execute"):
        body[{"auth": "source_authenticated", "causal": "causality_verified",
              "execute": "execution_authorized"}[mode]] = True
    elif mode == "extra":
        body["extra"] = False
    elif mode == "missing":
        del body["source_authenticated"]
    elif mode == "prediction_count":
        pred["ready_endpoints"] = 1
    elif mode == "prediction_bool":
        pred["ready_endpoints"] = True
    elif mode == "prediction_schema":
        pred["schema_version"] = "other"
    elif mode == "prediction_extra":
        pred["unexpected"] = False
    elif mode == "prediction_missing":
        del pred["classification"]
    elif mode == "oversized_archive":
        archive.write_bytes(b"x" * ((10 << 20) + 1))
    receipt.write_text(json.dumps(body), encoding="utf-8")
    prediction.write_text(json.dumps(pred), encoding="utf-8")
    if mode == "duplicate":
        receipt.write_text('{"status":"REPLAYED",' + json.dumps(body)[1:], encoding="utf-8")
    elif mode == "receipt_symlink":
        target = receipt.with_suffix(".real")
        receipt.rename(target)
        receipt.symlink_to(target)
    elif mode == "receipt_fifo":
        receipt.unlink()
        os.mkfifo(receipt)
    result = invoke("verify", archive, pin, receipt, prediction)
    if mode in ("healthy", "zero"):
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("PASS:")
    else:
        assert result.returncode == 3, result.stdout + result.stderr
        assert result.stdout == ""
        assert result.stderr.startswith("UNKNOWN:")

@pytest.mark.parametrize("field", ["archive", "pin", "receipt", "prediction"])
@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_verify_rejects_nonregular_or_aliased_evidence(evidence, field, kind):
    archive, pin, receipt, prediction, *_ = evidence
    paths = {"archive": archive, "pin": pin, "receipt": receipt, "prediction": prediction}
    target = paths[field]
    if kind == "symlink":
        real = target.with_suffix(target.suffix + ".real")
        target.rename(real)
        target.symlink_to(real)
    else:
        target.unlink()
        os.mkfifo(target)
    result = invoke("verify", archive, pin, receipt, prediction)
    assert result.returncode == 3, result.stdout + result.stderr
    assert result.stdout == ""
    assert result.stderr.startswith("UNKNOWN:")


@pytest.mark.parametrize("mutation", ["grow", "shrink", "same_size"])
def test_bounded_reader_rejects_file_mutated_after_initial_stat(tmp_path, monkeypatch, mutation):
    spec = importlib.util.spec_from_file_location("endpoint_check_replay", SCRIPT)
    checker = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(checker)

    target = tmp_path / "capture.json"
    original = b'{"capture":"stable"}'
    target.write_bytes(original)
    real_fstat = os.fstat
    calls = 0

    def mutate_after_first_stat(fd):
        nonlocal calls
        info = real_fstat(fd)
        calls += 1
        if calls == 1:
            if mutation == "grow":
                target.write_bytes(original + b" ")
            elif mutation == "shrink":
                target.write_bytes(original[:-1])
            else:
                target.write_bytes(b"X" * len(original))
                os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return info

    monkeypatch.setattr(checker.os, "fstat", mutate_after_first_stat)
    with pytest.raises(ValueError, match="changed during read"):
        checker.read_bounded(target, 1024)
    assert calls >= 2
