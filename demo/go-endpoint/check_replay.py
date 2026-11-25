#!/usr/bin/env python3
"""Bind a disposable-lab replay receipt to its frozen archive and prediction.

The lab pin establishes local byte continuity, not source authentication.
"""
import hashlib
import json
import os
import re
import stat
import sys

MAX_ARCHIVE = 10 << 20
MAX_PREDICTION = 6 << 20
MAX_RECEIPT = 4096
RECEIPT_KEYS = {
    "schema_version", "status", "archive_sha256", "classification",
    "ready_endpoints", "source_authenticated", "causality_verified",
    "execution_authorized",
}


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("invalid evidence file")
        if not 0 < info.st_size <= limit:
            raise ValueError("invalid evidence size")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        before_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(data) != info.st_size or before_identity != after_identity:
            raise ValueError("evidence changed during read")
    finally:
        if fd >= 0:
            os.close(fd)
    if not data or len(data) > limit:
        raise ValueError("invalid evidence size")
    return data


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("invalid JSON constant")


def read_object(path, limit):
    obj = json.loads(read_bounded(path, limit).decode("utf-8"),
                     object_pairs_hook=unique, parse_constant=reject_constant)
    if type(obj) is not dict:
        raise ValueError("expected JSON object")
    return obj


def archive_digest(path):
    return hashlib.sha256(read_bounded(path, MAX_ARCHIVE)).hexdigest()


def observation(obj):
    count = obj.get("ready_endpoints")
    if type(count) is not int or not 0 <= count <= 128 * 256:
        raise ValueError("invalid endpoint count")
    classification = obj.get("classification")
    if classification != ("READY_ENDPOINTS_OBSERVED" if count else "NO_READY_ENDPOINTS_OBSERVED"):
        raise ValueError("invalid endpoint classification")
    return classification, count


def verify(archive, pin, receipt, prediction):
    expected = read_bounded(pin, 65).decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}\n", expected):
        raise ValueError("invalid archive pin")
    digest = archive_digest(archive)
    if digest + "\n" != expected:
        raise ValueError("archive changed after pinning")
    claim = read_object(receipt, MAX_RECEIPT)
    pred = read_object(prediction, MAX_PREDICTION)
    if (set(claim) != RECEIPT_KEYS or
            claim["schema_version"] != "sre.service-endpoints-replay/v1" or
            claim["status"] != "REPLAYED" or claim["archive_sha256"] != digest or
            any(claim[key] is not False for key in (
                "source_authenticated", "causality_verified", "execution_authorized")) or
            pred.get("schema_version") != "sre.endpoint-observation/v1" or
            observation(claim) != observation(pred)):
        raise ValueError("replay receipt does not match frozen prediction")


def main(args):
    if len(args) == 2 and args[0] == "pin":
        print(archive_digest(args[1]))
        return 0
    if len(args) == 5 and args[0] == "verify":
        verify(*args[1:])
        print("PASS: pinned archive replay agrees with endpoint prediction")
        return 0
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, RecursionError):
        print("UNKNOWN: invalid endpoint replay evidence", file=sys.stderr)
        sys.exit(3)
