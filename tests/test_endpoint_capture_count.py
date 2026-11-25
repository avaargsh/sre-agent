"""Malformed reported counts must fail before publishing any lab evidence."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/verify_capture.py"
UID = "test-service-uid"


def capture_fixture():
    service = {"kind": "Service", "metadata": {"namespace": "golden-demo", "name": "checkout-api", "uid": UID, "resourceVersion": "10"}}
    slices = {"kind": "EndpointSliceList", "metadata": {"resourceVersion": "20"}, "items": []}
    report = {"schema_version": "sre.service-endpoints/v3", "source_authenticated": False,
              "target": {"namespace": "golden-demo", "name": "checkout-api", "uid": UID},
              "expected_target_port": 8080, "expected_selector": {"app": "checkout-api"},
              "service_resource_version": "10", "endpoint_slice_list_resource_version": "20",
              "classification": "NO_READY_ENDPOINTS_OBSERVED", "ready_endpoints": 0,
              "collection_started_at": "2026-01-01T00:00:00Z", "observed_at": "2026-01-01T00:00:01Z",
              "read_timeline": []}
    capture = {"schema_version": "sre.service-endpoints-capture/v1", "report": report}
    for field, name, version, source in (("service_before", "service_get_before", "10", service),
                                         ("endpoint_slices", "endpoint_slice_list", "20", slices),
                                         ("service_after", "service_get_after", "10", service)):
        raw = json.dumps(source).encode()
        digest = hashlib.sha256(raw).hexdigest()
        capture[field + "_raw"] = base64.b64encode(raw).decode()
        report[field + "_sha256"] = digest
        report["read_timeline"].append({"name": name, "response_resource_version": version,
                                         "response_sha256": digest, "started_at": report["collection_started_at"],
                                         "completed_at": report["collection_started_at"]})
    report["read_timeline"][1].update(request_consistency="MOST_RECENT", request_label_selector="kubernetes.io/service-name=checkout-api", request_limit=129)
    return capture


@pytest.mark.parametrize("count", ["missing", None, False, True, -1, 0.0, "0", 32769])
def test_invalid_reported_count_never_publishes(tmp_path, count):
    capture = capture_fixture()
    if count == "missing":
        del capture["report"]["ready_endpoints"]
    else:
        capture["report"]["ready_endpoints"] = count
    source = tmp_path / "capture.json"
    source.write_text(json.dumps(capture), encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    result = subprocess.run([sys.executable, "-O", str(SCRIPT), str(source), str(output), UID],
                            capture_output=True, text=True, timeout=5)
    assert list(output.iterdir()) == [], "invalid input published evidence"
    assert result.returncode == 3, result.stdout + result.stderr
    assert not result.stdout
    assert result.stderr.startswith("UNKNOWN:")


def test_valid_zero_count_publishes_complete_set(tmp_path):
    capture = capture_fixture()
    source = tmp_path / "capture.json"
    source.write_text(json.dumps(capture), encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    result = subprocess.run([sys.executable, "-O", str(SCRIPT), str(source), str(output), UID],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert {p.name for p in output.iterdir()} == {"observed-service.json", "observed-endpointslices.json",
                                                 "observed-service-after.json", "observer-report.json"}
    assert json.loads((output / "observer-report.json").read_text()) == capture["report"]
