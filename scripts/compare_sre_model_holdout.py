#!/usr/bin/env python3
"""Compare externally pinned Inkling/Qwen/cloud predictions; no model execution."""
import argparse
import json
import sys

from agentic_aiops.model_holdout import compare_model_holdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--dataset-sha256", required=True)
    labels = ("inkling", "qwen", "cloud")
    for label in labels:
        parser.add_argument("--" + label, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
    parser.add_argument("--split", choices=("validation", "test"), default="test")
    args = parser.parse_args()
    try:
        result = compare_model_holdout(
            args.dataset, expected_dataset_sha256=args.dataset_sha256,
            prediction_files={label: getattr(args, label) for label in labels},
            expected_prediction_sha256={
                label: getattr(args, label + "_sha256") for label in labels},
            split=args.split,
        )
    except (OSError, ValueError, UnicodeError):
        print("HOLD: invalid three-model holdout inputs", file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
