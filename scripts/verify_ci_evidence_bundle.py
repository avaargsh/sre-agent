#!/usr/bin/env python3
"""Read-only cross-check of three exact-head Python/Go CI evidence artifacts.

This verifies *content consistency*, not GitHub run identity or source
attestation. External approval must still authenticate the Actions run IDs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from typing import Any

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_MANIFEST = 256 * 1024
MAX_LOG = 32 * 1024 * 1024
SCOPES = (
    ("python-3.11", "python", "3.11", "python311"),
    ("python-3.12", "python", "3.12", "python312"),
    ("go", "go", "3.12", "go"),
)
GO_NAMES = ["go-race", "go-vet", "go-build", "go-bundle-contract"]
GO_SCENARIO = ("benchmarks", "scenarios", "checkout-latency.json")


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: Path, limit: int, description: str) -> bytes:
    """Bind type, size, and bounded read to one no-follow opened inode.

    A preflight Path.is_symlink/stat followed by Path.open is unsafe: the
    pathname can be replaced by a symlink or FIFO between those calls.
    This hardens the final component, not an adversarial mutable parent
    directory or an untrusted CI issuer.
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError(f"secure no-follow/nonblocking open unavailable for {description}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(f"invalid or oversized {description}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        before_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(raw) != info.st_size or before_identity != after_identity:
            raise ValueError(f"{description} changed during read")
        if len(raw) > limit:
            raise ValueError(f"oversized {description}")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def ensure(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


# Pinned synthetic checkout fixture digest, also tested in
# internal/evidence/bundle_test.go. Rotate together with that fixture.
CHECKOUT_BUNDLE_SHA256 = "0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3"


def validate_go_bundle_receipt(raw: bytes) -> None:
    """Reject a successful Go process without its pinned JSON contract receipt."""
    if not 0 < len(raw) <= 4096:
        raise ValueError("missing or oversized Go bundle receipt")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate Go bundle receipt field")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("nonfinite Go bundle receipt number")

    try:
        result = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError("Go bundle receipt nesting exceeds decoder limit") from exc
    if (type(result) is not dict or set(result) != {
            "status", "bundle_sha256", "evidence_count", "supported_hypotheses"}
            or result["status"] != "STRUCTURALLY_VALID"
            or type(result["bundle_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", result["bundle_sha256"]) is None
            or result["bundle_sha256"] != CHECKOUT_BUNDLE_SHA256
            or type(result["evidence_count"]) is not int
            or result["evidence_count"] != 2
            or type(result["supported_hypotheses"]) is not int
            or result["supported_hypotheses"] != 1):
        raise ValueError("invalid Go bundle receipt shape or fixture results")


def valid_command(scope: str, name: str, argv: Any) -> bool:
    if type(argv) is not list or not all(type(x) is str for x in argv):
        return False
    if scope == "python":
        return (name == "python-pytest" and len(argv) == 4
                and Path(argv[0]).is_absolute() and argv[1:] == ["-m", "pytest", "-q"])
    if name == "go-race":
        return argv == ["go", "test", "-race", "./..."]
    if name == "go-vet":
        return argv == ["go", "vet", "./..."]
    if name == "go-build":
        return len(argv) == 5 and argv[:3] == ["go", "build", "-o"] and argv[4] == "./cmd/sre-agent" and Path(argv[3]).is_absolute() and Path(argv[3]).name == "sre-agent"
    if name == "go-bundle-contract":
        return (len(argv) == 5 and Path(argv[0]).is_absolute()
                and Path(argv[0]).name == "sre-agent"
                and argv[1:4] == ["verify-bundle", "--scenario", "--file"]
                and Path(argv[4]).is_absolute()
                and Path(argv[4]).parts[-3:] == GO_SCENARIO
                and ".." not in Path(argv[4]).parts)
    return False


def check_scope(folder: Path, label: str, scope: str, python_version: str,
                expected_sha: str) -> dict[str, Any]:
    manifest_path = folder / "manifest.json"
    raw = read_regular(manifest_path, MAX_MANIFEST, "manifest")
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid JSON manifest: {exc}") from exc
    ensure(type(manifest) is dict, "manifest must be JSON object")
    expected = {
        "schema_version": "sre.exact-tree-verification/v1",
        "scope": scope, "expected_sha": expected_sha,
        "actual_sha": expected_sha, "post_run_sha": expected_sha,
        "tracked_tree_clean": True, "post_run_tree_clean": True,
        "python_version": python_version, "status": "PASS",
        "production_eligible": False,
    }
    for key, value in expected.items():
        got = manifest.get(key)
        ensure(type(got) is type(value) and got == value,
               f"{label}: {key} mismatched or invalid")
    checks = manifest.get("checks")
    names = ["python-pytest"] if scope == "python" else GO_NAMES
    ensure(type(checks) is list and len(checks) == len(names),
           f"{label}: incomplete command coverage")
    logs = []
    for step, name in zip(checks, names):
        ensure(type(step) is dict and step.get("name") == name,
               f"{label}: wrong step order/name")
        ensure(type(step.get("return_code")) is int and step["return_code"] == 0,
               f"{label}: {name} did not exit successfully")
        ensure("error" not in step, f"{label}: {name} contains an error")
        ensure(type(step.get("duration_ms")) is int and step["duration_ms"] >= 0,
               f"{label}: invalid duration for {name}")
        ensure(valid_command(scope, name, step.get("argv")),
               f"{label}: expected command not executed for {name}")
        if name == "go-bundle-contract":
            ensure(step["argv"][0] == checks[2]["argv"][3],
                   f"{label}: smoke did not execute the recorded build output")
        digest = step.get("log_sha256")
        ensure(type(digest) is str and DIGEST.fullmatch(digest) is not None,
               f"{label}: invalid {name} log digest")
        filename = step.get("log_path")
        ensure(type(filename) is str and filename == name + ".log",
               f"{label}: unexpected log path {filename!r}")
        limit = 4096 if name == "go-bundle-contract" else MAX_LOG
        log = read_regular(folder / filename, limit, f"{label} {name} log")
        actual = hashlib.sha256(log).hexdigest()
        ensure(actual == digest, f"{label}: {name} log content does not match SHA256")
        if name == "go-bundle-contract":
            validate_go_bundle_receipt(log)
        logs.append({"name": name, "sha256": actual, "bytes": len(log)})
    return {"scope_label": label, "scope": scope, "python_version": python_version,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(), "steps": logs}


def publish_report(target: Path, report: dict[str, Any]) -> None:
    """Publish only complete, synced bytes under a create-only final name.

    A direct O_EXCL final open prevents overwrites but can leave a truncated
    "official" report on ENOSPC, write, or fsync failure. Stage a private file
    in the same directory, sync it, then hard-link it into the final name.
    The hard link refuses concurrent writers without replacing their files.
    This assumes an operator-owned parent directory; it is not runner proof.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("secure report staging unavailable")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = target.with_name(".sre-ci-report-" + uuid.uuid4().hex + ".stage")
    descriptor = os.open(
        stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, target, follow_symlinks=False)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        stage.unlink(missing_ok=True)


def verify(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "schema_version": "sre.ci-evidence-consistency/v1",
        "expected_sha": args.expected_sha, "scope_count": 0,
        "status": "HOLD", "reason": "not all evidence has been validated",
        "scopes": [], "source_authenticity_verified": False,
        "github_run_identity_verified": False, "production_eligible": False,
    }
    code = 3
    try:
        ensure(type(args.expected_sha) is str and SHA.fullmatch(args.expected_sha) is not None,
               "expected_sha must be 40 lowercase hex characters")
        folders = [args.python311.resolve(), args.python312.resolve(), args.go.resolve()]
        ensure(len(set(folders)) == 3, "three input artifacts must be distinct directories")
        for (label, scope, version, _), folder in zip(SCOPES, folders):
            evidence = check_scope(folder, label, scope, version, args.expected_sha)
            report["scopes"].append(evidence)
        report["scope_count"] = len(report["scopes"])
        report["status"] = "EVIDENCE_CONSISTENT"
        report["reason"] = "three sets of contents and source SHA are consistent; runner identity not attested"
        code = 0
    except (ValueError, OSError, TypeError) as exc:
        report["status"] = "HOLD"
        report["reason"] = str(exc)
    finally:
        publish_report(args.out, report)
        print(f"{report['status']}: {report['reason']}", file=sys.stderr)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--python-311", dest="python311", type=Path, required=True)
    parser.add_argument("--python-312", dest="python312", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return verify(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
