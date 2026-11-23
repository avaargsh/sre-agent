#!/usr/bin/env python3
"""Project held-out SRE prompts without Oracle into an immutable JSONL artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_holdout_capture import project_holdout_prompts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Oracle-free holdout input for an isolated model runner"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    try:
        receipt = project_holdout_prompts(
            args.dataset, expected_dataset_sha256=args.expected_dataset_sha256,
            split=args.split, output=args.output, manifest=args.manifest,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: holdout projection rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
