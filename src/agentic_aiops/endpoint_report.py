"""Offline display of a Go Endpoint capture, not an independent replay."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

MAX_CAPTURE_BYTES = 10 << 20
MAX_SOURCE_BYTES = 2 << 20
_SOURCE_FIELDS = ("service_before", "endpoint_slices", "service_after")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def summarize_endpoint_capture(path: str | Path) -> dict:
    """Check byte/digest binding and display explicitly unverified claims."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("oversized capture")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    report = capture["report"]
    if (capture["schema_version"] != "sre.service-endpoints-capture/v1"
            or report["schema_version"] != "sre.service-endpoints/v3"
            or report["source_authenticated"] is not False):
        raise ValueError("invalid capture schema or authentication claim")
    target = {key: report["target"][key] for key in ("namespace", "name", "uid")}
    if not all(isinstance(value, str) and value.strip() for value in target.values()):
        raise ValueError("invalid reported target")
    classification = report["classification"]
    count = report["ready_endpoints"]
    if (classification not in ("READY_ENDPOINTS_OBSERVED", "NO_READY_ENDPOINTS_OBSERVED", "UNKNOWN")
            or type(count) is not int or count < 0):
        raise ValueError("invalid reported observation")
    timestamps = {key: report[key] for key in ("collection_started_at", "observed_at")}
    if not all(isinstance(value, str) and value.strip() for value in timestamps.values()):
        raise ValueError("invalid reported timestamps")
    sources = {}
    digests = {}
    for field in _SOURCE_FIELDS:
        encoded = capture[field + "_raw"]
        if not isinstance(encoded, str):
            raise ValueError("invalid source encoding")
        source = base64.b64decode(encoded, validate=True)
        if not 0 < len(source) <= MAX_SOURCE_BYTES:
            raise ValueError("empty or oversized source")
        digest = _digest(source)
        if digest != report[field + "_sha256"]:
            raise ValueError("source digest mismatch")
        sources[field] = source
        digests[field] = digest
    if sources["service_before"] != sources["service_after"]:
        raise ValueError("Service snapshots differ")
    return {
        "schema_version": "endpoint-observation-summary/v1",
        "capture_sha256": _digest(raw),
        "target": target,
        "reported_classification": classification,
        "reported_ready_endpoints": count,
        "reported_collection_started_at": timestamps["collection_started_at"],
        "reported_observed_at": timestamps["observed_at"],
        "source_sha256": digests,
        "source_bytes_match_report_digests": True,
        "source_authenticated": False,
        "independently_verified": False,
        "root_cause_verified": False,
        "execution_authorized": False,
    }
