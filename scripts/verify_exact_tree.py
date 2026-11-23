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
from pathlib import Path
import re
import subprocess
import sys
import time


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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record_command(name: str, argv: list[str], repo: Path,
                   out_dir: Path, timeout: int) -> dict[str, object]:
    log_name = f"{name}.log"
    log_file = out_dir / log_name
    start = time.monotonic()
    return_code: int | None = None
    error: str | None = None
    with log_file.open("wb") as stream:
        try:
            result = subprocess.run(
                argv, cwd=repo, stdout=stream, stderr=subprocess.STDOUT,
                check=False, timeout=timeout,
            )
            return_code = result.returncode
        except FileNotFoundError as exc:
            error = f"executable unavailable: {exc.filename}"
            stream.write((error + "\n").encode("utf-8"))
        except subprocess.TimeoutExpired:
            error = f"timeout after {timeout} seconds"
            stream.write((error + "\n").encode("utf-8"))
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
                ("go-bundle-contract", ["go", "run", "./cmd/sre-agent", "verify-bundle", "--scenario", "--file", "benchmarks/scenarios/checkout-latency.json"]),
            ]
        for name, argv in commands:
            receipt = record_command(name, argv, repo, out_dir, args.timeout_seconds)
            result["checks"].append(receipt)
            if receipt["return_code"] != 0:
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
    finally:
        result["completed_at_utc"] = now_utc()
        (out_dir / "manifest.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
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
