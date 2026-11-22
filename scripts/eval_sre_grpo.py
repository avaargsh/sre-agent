#!/usr/bin/env python3
"""Replay frozen SRE predictions against an independent, read-only holdout Oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_eval import evaluate_holdout, load_predictions_bytes
from agentic_aiops.grpo_train_proof import freeze_train_dataset
from agentic_aiops.grpo_import import _verify_pin


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent SRE GRPO holdout evaluation")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--split", choices=("validation", "test"), default="test")
    parser.add_argument("--expected-dataset-sha256")
    parser.add_argument("--expected-predictions-sha256")
    args = parser.parse_args()
    try:
        episodes, dataset_sha = freeze_train_dataset(
            args.dataset, expected_dataset_sha256=args.expected_dataset_sha256,
        )
        raw_predictions = args.predictions.read_bytes()
        if args.expected_predictions_sha256 is not None:
            predictions_sha = _verify_pin(
                raw_predictions, args.expected_predictions_sha256, "predictions_sha256"
            )
        else:
            predictions_sha = hashlib.sha256(raw_predictions).hexdigest()
        predictions = load_predictions_bytes(raw_predictions)
        metrics = evaluate_holdout(episodes, predictions, split=args.split)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: holdout evaluation rejected: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc
    report = {
        "schema_version": "sre.grpo.holdout-eval/v1",
        "dataset_sha256": dataset_sha,
        "predictions_sha256": predictions_sha,
        "metrics": metrics,
        "model_runtime_verified": False,
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
