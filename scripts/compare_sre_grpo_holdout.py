#!/usr/bin/env python3
"""Compare pinned Base/SFT/GRPO holdout outputs without self-reported rewards."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_compare import compare_pinned_holdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exact-digest three-way offline paired SRE holdout comparison"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--sft", type=Path, required=True)
    parser.add_argument("--sft-sha256", required=True)
    parser.add_argument("--grpo", type=Path, required=True)
    parser.add_argument("--grpo-sha256", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    args = parser.parse_args()
    try:
        report = compare_pinned_holdout(
            args.dataset, split=args.split,
            expected_dataset_sha256=args.expected_dataset_sha256,
            prediction_files={"Base": args.base, "SFT": args.sft, "GRPO": args.grpo},
            expected_prediction_sha256={
                "Base": args.base_sha256,
                "SFT": args.sft_sha256,
                "GRPO": args.grpo_sha256,
            },
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: paired holdout rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
