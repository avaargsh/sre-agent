#!/usr/bin/env python3
"""Smoke-check an operator-selected Endpoint CLI outside the source tree.

This checks behavior, not the origin or installation method of the executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(cli: Path) -> dict:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update(PYTHONNOUSERSITE="1", PYTHONSAFEPATH="1")
    with TemporaryDirectory(prefix="endpoint-cli-smoke-") as work:
        def command(*args, text=True):
            return subprocess.run([str(cli), *args], cwd=work,
                                  env=env, capture_output=True, text=text, timeout=15)

        def run(*args):
            return command("demo-endpoint", *args)

        cases = (
            ("scale-zero", "template_candidate", "zero_desired_and_available", []),
            ("readiness", "owner_chain", "availability_shortfall", ["reported_not_ready"]),
        )
        scale_output = None
        for case, association, replica_status, pod_statuses in cases:
            result = run("--case", case)
            require(result.returncode == 0 and not result.stderr, f"{case}: command failed")
            demo = json.loads(result.stdout)
            require(demo["schema_version"] == "endpoint-offline-demo/v1"
                    and demo["synthetic"] is True and demo["case"] == case,
                    f"{case}: wrong demo envelope")
            report = demo["report"]
            require(report["schema_version"] == "rca-report/v1"
                    and report["independently_verified"] is False
                    and report["execution_authorized"] is False,
                    f"{case}: wrong RCA schema or authority flags")
            endpoint = report["endpoint_observation"]
            require(endpoint["reported_classification"] == "NO_READY_ENDPOINTS_OBSERVED"
                    and type(endpoint["reported_ready_endpoints"]) is int
                    and endpoint["reported_ready_endpoints"] == 0
                    and endpoint["source_authenticated"] is False,
                    f"{case}: wrong endpoint observation")
            context = report["topology_context"]
            replica, = context["replica_assessment"]["observations"]
            require(replica["association"] == association and replica["status"] == replica_status,
                    f"{case}: wrong replica assessment")
            require([item["status"] for item in context["readiness_assessment"]["observations"]]
                    == pod_statuses, f"{case}: wrong readiness assessment")
            require(len(report["hypotheses"]) == 3
                    and all(item["supplied_status"] == "unverified" for item in report["hypotheses"]),
                    f"{case}: unexpected hypothesis status")
            plan = report["investigation_plan"]
            require(plan["collection_authorized"] is False and plan["execution_authorized"] is False
                    and len(plan["checks"]) == 3
                    and all(item["status"] == "pending_evidence" for item in plan["checks"]),
                    f"{case}: unexpected investigation status")
            exported = command("demo-endpoint", "--case", case, "--format", "fixture", text=False)
            require(exported.returncode == 0 and not exported.stderr, f"{case}: export failed")
            fixture = json.loads(exported.stdout)
            require(set(fixture) == {"schema_version", "synthetic", "case", "capture", "topology"}
                    and fixture["schema_version"] == "endpoint-offline-fixture/v1"
                    and fixture["synthetic"] is True and fixture["case"] == case
                    and isinstance(fixture["capture"], dict) and isinstance(fixture["topology"], dict),
                    f"{case}: wrong fixture envelope")
            path = Path(work) / "fixture.json"
            with path.open("xb") as stream:
                stream.write(exported.stdout)
            replayed = command("render-endpoint-fixture", str(path))
            require(replayed.returncode == 0 and not replayed.stderr, f"{case}: replay failed")
            replay = json.loads(replayed.stdout)
            require(replay.pop("fixture_sha256") == hashlib.sha256(exported.stdout).hexdigest()
                    and replay == demo, f"{case}: replay does not match exported bytes and demo")
            require(path.read_bytes() == exported.stdout, f"{case}: replay changed the fixture")
            path.unlink()
            fixture["synthetic"] = False
            with path.open("x", encoding="utf-8") as stream:
                json.dump(fixture, stream)
            rejected = command("render-endpoint-fixture", str(path))
            require(rejected.returncode == 2 and not rejected.stdout, f"{case}: invalid fixture accepted")
            path.unlink()
            if case == "scale-zero":
                scale_output = result.stdout
        default = run()
        require(default.returncode == 0 and not default.stderr and default.stdout == scale_output,
                "default case is not deterministic")
        invalid = run("--case", "unknown")
        require(invalid.returncode == 2 and not invalid.stdout, "invalid case did not fail closed")
        require(not list(Path(work).iterdir()), "CLI left files in its working directory")
    return {"schema_version": "endpoint-cli-smoke/v1", "status": "PASS",
            "cases": [case[0] for case in cases], "production_eligible": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path, help="absolute path to a trusted CLI executable")
    args = parser.parse_args()
    try:
        require(args.cli.is_absolute(), "--cli must be an absolute path")
        result = verify(args.cli)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired, RecursionError) as exc:
        print(f"endpoint CLI smoke failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
