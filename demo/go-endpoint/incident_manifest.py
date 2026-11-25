#!/usr/bin/env python3
"""Inventory required disposable Endpoint lab artifacts; not an acceptance verdict."""
import hashlib
import json
import os
import stat
import sys

MAX_FILE = 16 << 20
COMMON = tuple(f"{phase}-{suffix}" for phase in ("before", "during", "after")
               for suffix in ("service.json", "endpointslices.json", "probes.txt")) + (
    "observer-capture.json", "observer-capture.sha256", "observer-replay.json",
    "observed-service.json", "observed-endpointslices.json", "observed-service-after.json",
    "observer-report.json", "episode.json", "prediction.json", "evaluation.json",
)
FAULT = ("zero-pods.json", "convergence-probes.txt") + tuple(
    f"forged-{variant}{suffix}" for variant in ("count", "recovery", "digest")
    for suffix in (".json", "-log.txt")
)


def read_file(directory, name, limit=MAX_FILE):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("invalid artifact type or size")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or len(raw) > limit or
                (info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("artifact changed during read")
        return raw
    finally:
        if fd >= 0:
            os.close(fd)


def build(root):
    artifacts = []
    for scenario, names in (("control", COMMON), ("no-ready", COMMON + FAULT)):
        directory = os.open(scenario, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            expected_names = set(names)
            before = os.fstat(directory)
            if set(os.listdir(directory)) != expected_names:
                raise ValueError("unexpected or missing artifact in scenario directory")
            for name in sorted(names):
                raw = read_file(directory, name)
                artifacts.append({"path": f"{scenario}/{name}",
                                  "sha256": hashlib.sha256(raw).hexdigest(),
                                  "size_bytes": len(raw)})
            after = os.fstat(directory)
            before_identity = (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            after_identity = (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
            if before_identity != after_identity or set(os.listdir(directory)) != expected_names:
                raise ValueError("scenario artifact directory changed during inventory")
        finally:
            os.close(directory)
    manifest = {"schema_version": "sre.endpoint-lab-manifest/v1", "artifacts": artifacts,
                "source_authenticated": False, "causality_verified": False,
                "execution_authorized": False}
    return (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")


def main(args):
    if len(args) != 2 or args[0] not in ("build", "verify"):
        print("usage: incident_manifest.py build|verify ROOT", file=sys.stderr)
        return 2
    try:
        # The operator selects a trusted parent directory and a quiescent run.
        root = os.open(args[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            expected = build(root)
            if args[0] == "verify":
                if read_file(root, "incident-manifest.json", 65536) != expected:
                    raise ValueError("manifest mismatch")
                print("PASS: required artifact bytes match the lab manifest")
            else:
                sys.stdout.buffer.write(expected)
        finally:
            os.close(root)
        return 0
    except (OSError, ValueError, AttributeError):
        print("UNKNOWN: invalid or changed lab evidence inventory", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
