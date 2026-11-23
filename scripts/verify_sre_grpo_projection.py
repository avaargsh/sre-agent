#!/usr/bin/env python3
"""Read-only independent replay of a frozen Oracle-free Holdout projection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_holdout_projection import verify_holdout_projection


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay pinned source Episodes against exact Oracle-free projected bytes",
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--expected-prompts-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        report = verify_holdout_projection(
            args.dataset, args.prompts, args.manifest,
            expected_dataset_sha256=args.expected_dataset_sha256,
            expected_prompts_sha256=args.expected_prompts_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: Holdout projection replay rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
