#!/usr/bin/env python3
"""Freeze an independently administered, short-lived NetworkPolicy lab record.

This admin packager is deliberately kept separate from SRE observer output.
SHA-256 binds source bytes only; it does NOT certify the admin or CNI origin.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

MAX_SOURCE_BYTES = 2 * 1024 * 1024

def snapshot(path: Path):
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError(f"Invalid frozen source size: {path}")
    return {
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_response_base64": base64.b64encode(raw).decode("ascii"),
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    root = args.directory
    evidence = {
        "schema_version": "sre.networkpolicy-oracle/v1",
        "episode_id": "np-calico-egress-001",
    }
    mapping = {
        "pod": "pod.json",
        "probe": "admin.log",
        "service": "service.json",
        "endpoint_slices": "endpoint-slices.json",
        "network_policy_list": "network-policies.json",
    }
    for phase in ("before", "during", "after"):
        evidence[phase] = {
            field: snapshot(root / f"{phase}-{suffix}")
            for field, suffix in mapping.items()
        }
    (root / "episode.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print("PASS: 15 independent CI-admin phase sources frozen with SHA256")

if __name__ == "__main__":
    main()
