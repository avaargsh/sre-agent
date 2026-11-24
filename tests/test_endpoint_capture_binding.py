"""Exercise the lab capture unpacker with local source fixtures only."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/verify_capture.py"
UID = "test-service-uid"


def fixture():
    service = json.dumps({"kind": "Service", "metadata": {"namespace": "golden-demo", "name": "checkout-api", "uid": UID, "resourceVersion": "10"}}).encode()
    slices = json.dumps({"kind": "EndpointSliceList", "metadata": {"resourceVersion": "20"}, "items": []}).encode()
    capture = {"schema_version": "sre.service-endpoints-capture/v1"}
    report = {"schema_version": "sre.service-endpoints/v3", "source_authenticated": False,
              "target": {"namespace": "golden-demo", "name": "checkout-api", "uid": UID},
              "expected_target_port": 8080, "expected_selector": {"app": "checkout-api"},
              "service_resource_version": "10", "endpoint_slice_list_resource_version": "20",
              "classification": "NO_READY_ENDPOINTS_OBSERVED", "ready_endpoints": 0,
              "collection_started_at": "2026-11-24T00:00:00Z", "observed_at": "2026-11-24T00:00:01Z",
              "read_timeline": []}
    capture["report"] = report
    for field, name, version, raw in (("service_before", "service_get_before", "10", service),
                                       ("endpoint_slices", "endpoint_slice_list", "20", slices),
                                       ("service_after", "service_get_after", "10", service)):
        digest = hashlib.sha256(raw).hexdigest()
        capture[field + "_raw"] = base64.b64encode(raw).decode()
        report[field + "_sha256"] = digest
        report["read_timeline"].append({"name": name, "response_resource_version": version,
                                         "response_sha256": digest, "started_at": report["collection_started_at"],
                                         "completed_at": report["collection_started_at"]})
    report["read_timeline"][1].update(request_consistency="MOST_RECENT", request_label_selector="kubernetes.io/service-name=checkout-api", request_limit=129)
    return capture


@pytest.mark.parametrize("mutation", ["none", "digest", "timeline_digest", "version", "uid", "changed_service"])
def test_capture_binding(tmp_path, mutation):
    capture = fixture()
    report = capture["report"]
    if mutation == "digest":
        report["service_before_sha256"] = "0" * 64
    elif mutation == "timeline_digest":
        report["read_timeline"][2]["response_sha256"] = "0" * 64
    elif mutation == "version":
        report["service_resource_version"] = "999"
    elif mutation == "uid":
        report["target"]["uid"] = "other"
    elif mutation == "changed_service":
        raw = base64.b64decode(capture["service_after_raw"]) + b" "
        capture["service_after_raw"] = base64.b64encode(raw).decode()
        report["service_after_sha256"] = hashlib.sha256(raw).hexdigest()
        report["read_timeline"][2]["response_sha256"] = report["service_after_sha256"]
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(src), str(tmp_path), UID], capture_output=True, text=True, timeout=10)
    if mutation == "none":
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "observed-endpointslices.json").read_bytes() == base64.b64decode(capture["endpoint_slices_raw"])
    else:
        assert result.returncode != 0, result.stdout
        assert not (tmp_path / "observed-service.json").exists()
