"""Lab Capture input admission must fail closed before publishing any evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo" / "go-endpoint" / "verify_capture.py"
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


@pytest.mark.skipif(not (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK")),
                    reason="requires POSIX no-follow/nonblocking input support")
@pytest.mark.parametrize("kind", ["valid", "symlink", "fifo", "directory", "empty", "oversized"])
def test_capture_input_is_bounded_nonblocking_regular_file(tmp_path, kind):
    input_path = tmp_path / "capture.json"
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    if kind in ("valid", "symlink"):
        real_path = tmp_path / "real-capture.json"
        real_path.write_text(json.dumps(capture_fixture()), encoding="utf-8")
        if kind == "valid":
            input_path.write_bytes(real_path.read_bytes())
        else:
            input_path.symlink_to(real_path)
    elif kind == "fifo":
        os.mkfifo(input_path)
    elif kind == "directory":
        input_path.mkdir()
    elif kind == "empty":
        input_path.touch()
    else:
        with input_path.open("wb") as stream:
            stream.truncate((10 << 20) + 1)
    result = subprocess.run([sys.executable, "-O", str(SCRIPT), str(input_path), str(output), UID],
                            capture_output=True, text=True, timeout=3)
    if kind == "valid":
        assert result.returncode == 0, result.stderr
        assert {item.name for item in output.iterdir()} == {
            "observed-service.json", "observed-endpointslices.json",
            "observed-service-after.json", "observer-report.json"}
    else:
        assert result.returncode == 3, result.stdout + result.stderr
        assert not result.stdout
        assert result.stderr.startswith("UNKNOWN:")
        assert list(output.iterdir()) == []


@pytest.mark.parametrize(("field", "value"), [
    ("expected_target_port", 8080.0),
    ("slice_request_limit", 129.0),
    ("service_request_limit", 0.0),
])
def test_capture_rejects_float_where_go_report_requires_integer(tmp_path, field, value):
    capture = capture_fixture()
    if field == "expected_target_port":
        capture["report"]["expected_target_port"] = value
    elif field == "slice_request_limit":
        capture["report"]["read_timeline"][1]["request_limit"] = value
    else:
        capture["report"]["read_timeline"][0]["request_limit"] = value
    input_path = tmp_path / "capture.json"
    input_path.write_text(json.dumps(capture), encoding="utf-8")
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    result = subprocess.run(
        [sys.executable, "-O", str(SCRIPT), str(input_path), str(output), UID],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 3, result.stdout + result.stderr
    assert not result.stdout
    assert result.stderr.startswith("UNKNOWN:")
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("bad_value", [float("nan"), "\ud800"])
@pytest.mark.parametrize("location", ["source", "report"])
def test_capture_rejects_nonstandard_or_unpaired_json(tmp_path, bad_value, location):
    capture = capture_fixture()
    if location == "source":
        service = json.loads(base64.b64decode(capture["service_before_raw"]))
        service["untrusted_extension"] = bad_value
        raw = json.dumps(service).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        encoded = base64.b64encode(raw).decode("ascii")
        for field, read_index in (("service_before", 0), ("service_after", 2)):
            capture[field + "_raw"] = encoded
            capture["report"][field + "_sha256"] = digest
            capture["report"]["read_timeline"][read_index]["response_sha256"] = digest
    else:
        capture["report"]["untrusted_extension"] = bad_value
    input_path = tmp_path / "capture.json"
    input_path.write_text(json.dumps(capture), encoding="utf-8")
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    result = subprocess.run(
        [sys.executable, "-O", str(SCRIPT), str(input_path), str(output), UID],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 3, result.stdout + result.stderr
    assert not result.stdout
    assert result.stderr.startswith("UNKNOWN:")
    assert list(output.iterdir()) == []
