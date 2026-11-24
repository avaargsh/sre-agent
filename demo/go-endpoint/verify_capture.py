"""Check disposable Kind capture binding before unpacking source files.

This validates report/byte consistency, not source authentication or readiness.
"""
import base64
import calendar
import datetime
import hashlib
import json
import re
from pathlib import Path
import sys


FIELDS = (("service_before", "observed-service.json", "Service", "service_resource_version"),
          ("endpoint_slices", "observed-endpointslices.json", "EndpointSliceList", "endpoint_slice_list_resource_version"),
          ("service_after", "observed-service-after.json", "Service", "service_resource_version"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


_TIME_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.([0-9]{0,8}[1-9]))?Z$"
)


def parse_time(value):
    require(type(value) is str, "invalid capture timestamp type")
    match = _TIME_RE.fullmatch(value)
    require(match is not None, "capture timestamp must be canonical UTC RFC3339Nano")
    try:
        whole = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError("invalid capture timestamp") from exc
    seconds = calendar.timegm(whole.timetuple())
    fraction = (match.group(2) or "").ljust(9, "0")
    return seconds * 1_000_000_000 + (int(fraction) if fraction else 0)


def unpack(capture, directory, uid):
    require(capture["schema_version"] == "sre.service-endpoints-capture/v1", "invalid capture schema")
    report = capture["report"]
    require(report["schema_version"] == "sre.service-endpoints/v3" and report["source_authenticated"] is False, "invalid report schema or authentication claim")
    target = {"namespace": "golden-demo", "name": "checkout-api", "uid": uid}
    require(bool(uid) and report["target"] == target, "report target mismatch")
    require(report["expected_target_port"] == 8080 and report["expected_selector"] == {"app": "checkout-api"}, "lab baseline mismatch")
    reads = report["read_timeline"]
    require([r["name"] for r in reads] == ["service_get_before", "endpoint_slice_list", "service_get_after"], "invalid read timeline")
    collection_start = parse_time(report["collection_started_at"])
    previous = collection_start
    for i, read in enumerate(reads):
        require(read.get("request_resource_version", "") == "" and read.get("request_resource_version_match", "") == "", "unexpected request resourceVersion")
        require(read.get("request_consistency", "") == ("MOST_RECENT" if i == 1 else ""), "invalid request consistency")
        require(read.get("request_label_selector", "") == ("kubernetes.io/service-name=checkout-api" if i == 1 else ""), "invalid selector")
        require(read.get("request_limit", 0) == (129 if i == 1 else 0), "invalid request limit")
        started, completed = parse_time(read["started_at"]), parse_time(read["completed_at"])
        require(previous <= started <= completed, "invalid read interval")
        previous = completed
    end = parse_time(report["observed_at"])
    require(previous <= end and end - collection_start <= 30_000_000_000, "invalid collection window")
    require(report["classification"] in ("READY_ENDPOINTS_OBSERVED", "NO_READY_ENDPOINTS_OBSERVED", "UNKNOWN"), "invalid classification")
    sources = []
    for read, (field, name, kind, version_field) in zip(reads, FIELDS):
        raw = base64.b64decode(capture[field + "_raw"], validate=True)
        require(0 < len(raw) <= 2 << 20, "empty or oversized source")
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == report[field + "_sha256"] == read["response_sha256"], "source digest mismatch")
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        require(obj["kind"] == kind, "unexpected source kind")
        meta = obj["metadata"]
        version = meta["resourceVersion"]
        require(isinstance(version, str) and version not in ("", "0") and len(version.encode("utf-8")) <= 256, "invalid source resourceVersion")
        require(version == report[version_field] == read["response_resource_version"], "source resourceVersion mismatch")
        if kind == "Service":
            require(all(meta[key] == value for key, value in target.items()), "source Service identity mismatch")
        sources.append((name, raw))
    require(sources[0][1] == sources[2][1], "Service changed during capture")
    # No output is published before all source bindings have been checked.
    for name, raw in sources:
        (directory / name).write_bytes(raw)
    (directory / "observer-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("PASS: lab capture byte binding", report["classification"], "reported ready endpoints", report["ready_endpoints"])


def main(argv):
    try:
        source, directory, uid = argv
        with Path(source).open("rb") as stream:
            raw = stream.read((10 << 20) + 1)
        require(len(raw) <= 10 << 20, "oversized capture")
        unpack(json.loads(raw.decode("utf-8"), object_pairs_hook=unique), Path(directory), uid)
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError):
        print("UNKNOWN: invalid lab capture binding", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
