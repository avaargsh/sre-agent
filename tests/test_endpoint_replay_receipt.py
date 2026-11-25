"""Validate the lab's offline replay receipt against frozen input and prediction."""
import hashlib
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
    "prediction_schema", "receipt_symlink", "receipt_fifo", "oversized_archive"])
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
