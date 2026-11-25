#!/usr/bin/env python3
"""Fail-closed, exact-commit Python/Go contract verification with evidence.

Does not assert production release eligibility. Each invocation verifies only
its requested suite; a release gate must aggregate evidence for all suites.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

# Reuse the already-reviewed same-directory staged, fsynced, create-only
# report publisher. Both entrypoints are executed from scripts/ by CI.
from verify_ci_evidence_bundle import publish_report


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise ValueError(f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def hidden_index_entries(repo: Path) -> bool:
    """Reject index flags that can suppress tracked worktree changes.

    git ls-files -v uses lowercase tags for assume-unchanged entries
    and S for skip-worktree. NUL separation preserves unusual filenames.
    """
    entries = git(repo, "ls-files", "-v", "-z").split("\0")
    return any(entry and (entry[0].islower() or entry[0] == "S")
               for entry in entries)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()



# Pinned synthetic checkout fixture digest, also tested in
# internal/evidence/bundle_test.go. Rotate together with that fixture.
CHECKOUT_BUNDLE_SHA256 = "0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3"


def validate_go_bundle_log(path: Path) -> None:
    """Reject a successful Go process without its pinned JSON contract receipt."""
    raw = path.read_bytes()
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

    result = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
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


def record_command(name: str, argv: list[str], repo: Path,
                   out_dir: Path, timeout: int, *, cwd: Path | None = None) -> dict[str, object]:
    log_name = f"{name}.log"
    log_file = out_dir / log_name
    start = time.monotonic()
    return_code: int | None = None
    error: str | None = None
    # The test log is part of the evidence record. Never truncate an
    # existing proof or follow a supplied symlink to unrelated source data.
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("secure no-follow log creation unavailable")
    descriptor = os.open(
        log_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            try:
                result = subprocess.run(
                    argv, cwd=cwd if cwd is not None else repo, stdout=stream, stderr=subprocess.STDOUT,
                    check=False, timeout=timeout,
                )
                return_code = result.returncode
            except FileNotFoundError as exc:
                error = f"executable unavailable: {exc.filename}"
                stream.write((error + "\n").encode("utf-8"))
            except subprocess.TimeoutExpired:
                error = f"timeout after {timeout} seconds"
                stream.write((error + "\n").encode("utf-8"))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    receipt: dict[str, object] = {
        "name": name,
        "argv": argv,
        "return_code": return_code,
        "log_path": log_name,
        "log_sha256": file_sha256(log_file),
        "duration_ms": round((time.monotonic() - start) * 1000),
    }
    if error:
        receipt["error"] = error
    return receipt


def verify(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, object] = {
        "schema_version": "sre.exact-tree-verification/v1",
        "scope": args.scope,
        "expected_sha": args.expected_sha,
        "actual_sha": None,
        "tracked_tree_clean": False,
        "post_run_sha": None,
        "post_run_tree_clean": None,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "started_at_utc": now_utc(),
        "completed_at_utc": None,
        "checks": [],
        "status": "HOLD",
        "reason": "verification did not complete",
        "production_eligible": False,
    }
    code = 2
    try:
        if re.fullmatch(r"[0-9a-f]{40}", args.expected_sha) is None:
            raise ValueError("expected SHA must be a full lowercase 40-character Git commit")
        actual = git(repo, "rev-parse", "HEAD")
        result["actual_sha"] = actual
        if actual != args.expected_sha:
            raise ValueError("Git HEAD SHA differs from the requested exact SHA")
        if hidden_index_entries(repo):
            raise ValueError("Git index contains assume-unchanged or skip-worktree entries; cannot certify exact committed bytes")
        if git(repo, "status", "--porcelain", "--untracked-files=normal"):
            raise ValueError("dirty Git worktree or untracked files; cannot certify exact committed bytes")
        result["tracked_tree_clean"] = True
        if (args.scope == "python" and args.expected_python is not None
                and result["python_version"] != args.expected_python):
            raise ValueError("Python interpreter version does not match expected Python matrix")
        if args.scope == "python":
            commands = [("python-pytest", [sys.executable, "-m", "pytest", "-q"])]
        else:
            commands = [
                ("go-race", ["go", "test", "-race", "./..."]),
                ("go-vet", ["go", "vet", "./..."]),
                ("go-build", ["go", "build", "-o", str(out_dir / "sre-agent"), "./cmd/sre-agent"]),
                ("go-bundle-contract", [str(out_dir / "sre-agent"), "verify-bundle", "--scenario", "--file", str(repo / "benchmarks/scenarios/checkout-latency.json")]),
            ]
        for name, argv in commands:
            receipt = record_command(name, argv, repo, out_dir, args.timeout_seconds,
                                     cwd=out_dir if name == "go-bundle-contract" else repo)
            if name == "go-bundle-contract" and receipt["return_code"] == 0:
                try:
                    validate_go_bundle_log(out_dir / "go-bundle-contract.log")
                except (OSError, ValueError, UnicodeError) as exc:
                    receipt["error"] = f"invalid Go bundle receipt: {exc}"
            result["checks"].append(receipt)
            if receipt["return_code"] != 0 or "error" in receipt:
                result["status"] = "FAIL"
                result["reason"] = f"{name} failed, timed out or could not start"
                code = 1
                break
        else:
            result["status"] = "PASS"
            result["reason"] = "all requested scope checks passed on exact tracked Git HEAD"
            code = 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = str(exc)
        if result["checks"]:
            # The repository was verified initially; execution failure or
            # a subsequent Git inspection error cannot certify that run.
            result["status"] = "FAIL"
            code = 1
    finally:
        # Command success is not an exact-commit proof if that command changed
        # tracked files, created untracked files, or advanced HEAD afterwards.
        # Recheck on both PASS and FAIL paths; retain this post-run evidence.
        if result["checks"]:
            try:
                post_sha = git(repo, "rev-parse", "HEAD")
                post_clean = not hidden_index_entries(repo) and not bool(git(
                    repo, "status", "--porcelain", "--untracked-files=normal",
                ))
                result["post_run_sha"] = post_sha
                result["post_run_tree_clean"] = post_clean
                if post_sha != args.expected_sha or not post_clean:
                    result["status"] = "FAIL"
                    result["reason"] = (
                        "Git HEAD or worktree changed during verification; "
                        "exact committed bytes are no longer established"
                    )
                    code = 1
            except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                result["status"] = "FAIL"
                result["reason"] = f"post-run Git verification unavailable: {exc}"
                code = 1
        result["completed_at_utc"] = now_utc()
        # An exact-tree receipt must never replace another run's artifact.
        # Stage, fsync and create-only publish using the same guarded
        # primitive as the three-scope offline consistency summary.
        publish_report(out_dir / "manifest.json", result)
        print(f"exact-tree {result['status']}: {result['reason']}", file=sys.stderr)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--scope", choices=("python", "go"), required=True)
    parser.add_argument("--expected-python", help="exact Python major.minor, e.g. 3.11")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 3600:
        parser.error("--timeout-seconds must be between 1 and 3600")
    if args.scope != "python" and args.expected_python is not None:
        parser.error("--expected-python is only valid for --scope python")
    return verify(args)


if __name__ == "__main__":
    sys.exit(main())
