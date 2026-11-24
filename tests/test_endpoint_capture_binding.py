"""Exercise the lab capture unpacker with local source fixtures only."""
import base64
import hashlib
import json
from pathlib import Path
import stat
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


@pytest.mark.parametrize("mutation", ["none", "digest", "timeline_digest", "version", "uid", "changed_service", "offset_time", "noncanonical_fraction", "canonical_nanoseconds"])
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
    elif mutation == "offset_time":
        report["collection_started_at"] = "2026-11-24T00:00:00+00:00"
        report["observed_at"] = "2026-11-24T00:00:01+00:00"
        for read in report["read_timeline"]:
            read["started_at"] = "2026-11-24T00:00:00+00:00"
            read["completed_at"] = "2026-11-24T00:00:00+00:00"
    elif mutation == "noncanonical_fraction":
        report["collection_started_at"] = "2026-11-24T00:00:00.100Z"
        report["observed_at"] = "2026-11-24T00:00:01.100Z"
        for read in report["read_timeline"]:
            read["started_at"] = "2026-11-24T00:00:00.100Z"
            read["completed_at"] = "2026-11-24T00:00:00.100Z"
    elif mutation == "canonical_nanoseconds":
        report["collection_started_at"] = "2026-11-24T00:00:00.123456789Z"
        report["observed_at"] = "2026-11-24T00:00:01.123456789Z"
        for read in report["read_timeline"]:
            read["started_at"] = "2026-11-24T00:00:00.123456789Z"
            read["completed_at"] = "2026-11-24T00:00:00.123456789Z"
    elif mutation == "changed_service":
        raw = base64.b64decode(capture["service_after_raw"]) + b" "
        capture["service_after_raw"] = base64.b64encode(raw).decode()
        report["service_after_sha256"] = hashlib.sha256(raw).hexdigest()
        report["read_timeline"][2]["response_sha256"] = report["service_after_sha256"]
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(src), str(tmp_path), UID], capture_output=True, text=True, timeout=10)
    if mutation in ("none", "canonical_nanoseconds"):
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "observed-endpointslices.json").read_bytes() == base64.b64decode(capture["endpoint_slices_raw"])
    else:
        assert result.returncode != 0, result.stdout
        assert not (tmp_path / "observed-service.json").exists()


@pytest.mark.parametrize("destination", [
    "observed-service.json",
    "observed-endpointslices.json",
    "observed-service-after.json",
    "observer-report.json",
])
def test_unpack_never_overwrites_existing_destination(tmp_path, destination):
    capture = fixture()
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")
    sentinel = b"preserve-existing-evidence"
    existing = tmp_path / destination
    existing.write_bytes(sentinel)

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(src), str(tmp_path), UID],
        capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert existing.read_bytes() == sentinel
    for name in (
        "observed-service.json",
        "observed-endpointslices.json",
        "observed-service-after.json",
        "observer-report.json",
    ):
        if name != destination:
            assert not (tmp_path / name).exists()


def test_unpack_does_not_follow_symlink_destination(tmp_path):
    capture = fixture()
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")
    victim = tmp_path / "victim.bin"
    sentinel = b"must-not-be-modified"
    victim.write_bytes(sentinel)
    destination = tmp_path / "observed-service.json"
    destination.symlink_to(victim)

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(src), str(tmp_path), UID],
        capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert destination.is_symlink()
    assert victim.read_bytes() == sentinel
    assert not (tmp_path / "observed-endpointslices.json").exists()


def test_unpack_publishes_private_files(tmp_path):
    capture = fixture()
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(src), str(tmp_path), UID],
        capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    for name in (
        "observed-service.json",
        "observed-endpointslices.json",
        "observed-service-after.json",
        "observer-report.json",
    ):
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o600



def test_unpack_rejects_symlinked_output_directory(tmp_path):
    capture = fixture()
    src = tmp_path / "capture.json"
    src.write_text(json.dumps(capture), encoding="utf-8")
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    output_link = tmp_path / "output-link"
    output_link.symlink_to(real_output, target_is_directory=True)

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(src), str(output_link), UID],
        capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert list(real_output.iterdir()) == []
