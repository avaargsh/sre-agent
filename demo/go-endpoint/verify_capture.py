"""Check disposable Kind capture binding before unpacking source files.

This validates report/byte consistency, not source authentication or readiness.
"""
import base64
import calendar
import datetime
import hashlib
import json
import math
import os
import re
import secrets
import stat
from pathlib import Path
import sys

from check_replay import MAX_ARCHIVE, read_bounded


FIELDS = (("service_before", "observed-service.json", "Service", "service_resource_version"),
          ("endpoint_slices", "observed-endpointslices.json", "EndpointSliceList", "endpoint_slice_list_resource_version"),
          ("service_after", "observed-service-after.json", "Service", "service_resource_version"))


CAPTURE_FIELDS = {
    "schema_version", "report", "service_before_raw",
    "endpoint_slices_raw", "service_after_raw",
}
REPORT_FIELDS = {
    "schema_version", "target", "expected_target_port", "expected_selector",
    "service_resource_version", "endpoint_slice_list_resource_version",
    "ready_endpoints", "classification", "service_before_sha256",
    "endpoint_slices_sha256", "service_after_sha256",
    "collection_started_at", "read_timeline", "observed_at",
    "source_authenticated",
}
READ_REQUIRED_FIELDS = {
    "name", "started_at", "completed_at",
    "response_resource_version", "response_sha256",
}
READ_OPTIONAL_FIELDS = {
    "request_consistency", "request_resource_version",
    "request_resource_version_match", "request_label_selector", "request_limit",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("non-finite JSON number")


def validate_json_strings(value):
    """Reject unpaired Unicode surrogates and exponent-overflow nonfinite floats."""
    if type(value) is float and not math.isfinite(value):
        raise ValueError("non-finite JSON number from exponent overflow")
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, list):
        for item in value:
            validate_json_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            validate_json_strings(item)


def strict_json(raw):
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    validate_json_strings(value)
    return value


_TIME_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{0,8}[1-9]))?Z$"
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


def open_directory_nofollow(directory):
    """Open a publisher-owned directory without following symlinks."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("safe no-follow directory opens unavailable")
    absolute = os.path.abspath(os.fspath(directory))
    parts = Path(absolute).parts
    if not parts or parts[0] != os.sep:
        raise OSError("output directory must be absolute")
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        identity = os.fstat(descriptor)
        if identity.st_uid != os.geteuid() or identity.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise OSError("evidence output directory must be owned and writable only by the publisher")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def publish_create_only(directory, outputs):
    """Publish a complete artifact set without following or replacing paths.

    Files are staged as private, exclusive inodes in the already-open output
    directory. Final names are create-only hard links. If any publication
    fails, remove only final links that still identify this invocation's inode.
    """
    directory_fd = open_directory_nofollow(directory)
    staged = []
    published = []
    try:
        for final_name, payload in outputs:
            if (type(final_name) is not str or not final_name
                    or Path(final_name).name != final_name
                    or final_name in (".", "..")):
                raise ValueError("invalid output filename")
            if type(payload) is not bytes:
                raise ValueError("output payload must be bytes")
            temporary_name = f".verify-capture-{secrets.token_hex(16)}.tmp"
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                identity = os.fstat(descriptor)
                if not stat.S_ISREG(identity.st_mode):
                    raise OSError("staging output is not a regular file")
                staged.append((temporary_name, final_name, identity.st_dev, identity.st_ino))
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short write while staging evidence")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        for temporary_name, final_name, device, inode in staged:
            current = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (device, inode) or not stat.S_ISREG(current.st_mode):
                raise OSError("staging file identity changed")
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            published.append((final_name, device, inode))
        os.fsync(directory_fd)
    except Exception as original_error:
        rollback_errors = []
        for final_name, device, inode in reversed(published):
            try:
                current = os.stat(final_name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (device, inode):
                    os.unlink(final_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                rollback_errors.append(exc)
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            rollback_errors.append(exc)
        if rollback_errors:
            raise OSError("evidence publication failed and rollback was incomplete") from rollback_errors[0]
        raise original_error
    finally:
        try:
            for temporary_name, _final_name, device, inode in staged:
                try:
                    current = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (device, inode):
                        os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    # A leftover staging inode remains private (0600); never
                    # replace or remove a path whose identity cannot be proven.
                    pass
        finally:
            os.close(directory_fd)


def unpack(capture, directory, uid):
    require(type(capture) is dict and set(capture) == CAPTURE_FIELDS,
            "invalid capture envelope fields")
    require(capture["schema_version"] == "sre.service-endpoints-capture/v1", "invalid capture schema")
    report = capture["report"]
    require(type(report) is dict and set(report) == REPORT_FIELDS,
            "invalid capture report fields")
    require(report["schema_version"] == "sre.service-endpoints/v3" and report["source_authenticated"] is False, "invalid report schema or authentication claim")
    target = {"namespace": "golden-demo", "name": "checkout-api", "uid": uid}
    require(bool(uid) and report["target"] == target, "report target mismatch")
    require(type(report["expected_target_port"]) is int and report["expected_target_port"] == 8080
            and report["expected_selector"] == {"app": "checkout-api"}, "lab baseline mismatch")
    reads = report["read_timeline"]
    require(type(reads) is list and len(reads) == 3, "invalid read timeline")
    for read in reads:
        require(type(read) is dict
                and READ_REQUIRED_FIELDS <= set(read)
                and set(read) <= READ_REQUIRED_FIELDS | READ_OPTIONAL_FIELDS,
                "invalid read timeline fields")
    require([r["name"] for r in reads] == ["service_get_before", "endpoint_slice_list", "service_get_after"], "invalid read timeline")
    collection_start = parse_time(report["collection_started_at"])
    previous = collection_start
    for i, read in enumerate(reads):
        require(read.get("request_resource_version", "") == "" and read.get("request_resource_version_match", "") == "", "unexpected request resourceVersion")
        require(read.get("request_consistency", "") == ("MOST_RECENT" if i == 1 else ""), "invalid request consistency")
        require(read.get("request_label_selector", "") == ("kubernetes.io/service-name=checkout-api" if i == 1 else ""), "invalid selector")
        request_limit = read.get("request_limit", 0)
        require(type(request_limit) is int and request_limit == (129 if i == 1 else 0), "invalid request limit")
        started, completed = parse_time(read["started_at"]), parse_time(read["completed_at"])
        require(previous <= started <= completed, "invalid read interval")
        previous = completed
    end = parse_time(report["observed_at"])
    require(previous <= end and end - collection_start <= 30_000_000_000, "invalid collection window")
    require(report["classification"] in ("READY_ENDPOINTS_OBSERVED", "NO_READY_ENDPOINTS_OBSERVED", "UNKNOWN"), "invalid classification")
    count = report.get("ready_endpoints")
    require(type(count) is int and 0 <= count <= 128 * 256, "invalid reported ready endpoint count")
    sources = []
    for read, (field, name, kind, version_field) in zip(reads, FIELDS):
        raw = base64.b64decode(capture[field + "_raw"], validate=True)
        require(0 < len(raw) <= 2 << 20, "empty or oversized source")
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == report[field + "_sha256"] == read["response_sha256"], "source digest mismatch")
        obj = strict_json(raw.decode("utf-8"))
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
    outputs = [(name, raw) for name, raw in sources]
    report_bytes = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    outputs.append(("observer-report.json", report_bytes))
    publish_create_only(directory, outputs)
    print("PASS: lab capture byte binding", report["classification"], "reported ready endpoints", count)


def main(argv):
    try:
        source, directory, uid = argv
        raw = read_bounded(source, MAX_ARCHIVE)
        unpack(strict_json(raw.decode("utf-8")), Path(directory), uid)
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError):
        print("UNKNOWN: invalid lab capture binding", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
