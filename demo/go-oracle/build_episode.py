#!/usr/bin/env python3
"""Disposable CI admin-only fault Oracle packager.

Does NOT infer the fault label from model output. The caller must supply
an operator/test-admin scenario and real before/during/after probe records.
This package is NOT a signed source of production truth.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def make_snapshot(path: Path) -> dict:
    raw = path.read_bytes()
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError(f"Invalid service snapshot size: {path}")
    return {
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_response_base64": base64.b64encode(raw).decode("ascii"),
    }


def probe_codes(path: Path) -> list[int]:
    values = [int(line.strip()) for line in path.read_text().splitlines() if line.strip()]
    if len(values) != 3 or any(value < 0 or value > 599 for value in values):
        raise ValueError(f"Three concrete HTTP probe codes required: {path}")
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--episode-id", required=True)
    parser.add_argument(
        "--scenario", required=True,
        choices=("NO_FAULT", "SERVICE_TARGETPORT_MISROUTED")
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    base = args.dir
    before = json.loads((base / "before.json").read_text())
    identity = before["metadata"]
    episode = {
        "schema_version": "sre.fault-oracle/v1",
        "episode_id": args.episode_id,
        "scenario": args.scenario,
        "namespace": identity["namespace"],
        "service": identity["name"],
        "service_uid": identity["uid"],
        "expected_target_port": 8080,
        "before": make_snapshot(base / "before.json"),
        "during": make_snapshot(base / "during.json"),
        "after": make_snapshot(base / "after.json"),
        "probes": {
            label: probe_codes(base / f"{label}-probes.txt")
            for label in ("before", "during", "after")
        },
    }
    args.out.write_text(json.dumps(episode, sort_keys=True, indent=2) + "\n")
    print(f"Packed test-admin Oracle episode: {args.episode_id}")


if __name__ == "__main__":
    main()
