#!/usr/bin/env python3
"""Package independent CI-admin DNS fault witness, NOT a signed truth source."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

MAX_SOURCE = 2 * 1024 * 1024


def evidence(path: Path):
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SOURCE:
        raise ValueError(f"invalid frozen input size for {path}")
    return {
        "raw_response_base64": base64.b64encode(raw).decode("ascii"),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    d = args.directory
    episode = {
        "schema_version": "sre.dns-oracle/v1",
        "episode_id": "dns-isolated-001",
        "service": evidence(d / "admin-service.json"),
        "healthy_pod": evidence(d / "admin-dns-good-pod.json"),
        "broken_pod": evidence(d / "admin-dns-bad-pod.json"),
        "healthy_probe": evidence(d / "admin-dns-good.log"),
        "broken_probe": evidence(d / "admin-dns-bad.log"),
    }
    (d / "episode.json").write_text(
        json.dumps(episode, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("PASS: independent test-admin witness frozen before evaluator reads it")


if __name__ == "__main__":
    main()
