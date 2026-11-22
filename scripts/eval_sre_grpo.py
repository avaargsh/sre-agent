#!/usr/bin/env python3
"""Replay frozen SRE predictions against an independent, read-only holdout Oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentic_aiops.grpo_eval import evaluate_holdout, load_predictions
from agentic_aiops.grpo_training import load_episodes


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent SRE GRPO holdout evaluation")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--split", choices=("validation", "test"), default="test")
    args = parser.parse_args()
    episodes = load_episodes(args.dataset)
    predictions = load_predictions(args.predictions)
    metrics = evaluate_holdout(episodes, predictions, split=args.split)
    report = {
        "schema_version": "sre.grpo.holdout-eval/v1",
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "predictions_sha256": hashlib.sha256(args.predictions.read_bytes()).hexdigest(),
        "metrics": metrics,
        "model_runtime_verified": False,
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
