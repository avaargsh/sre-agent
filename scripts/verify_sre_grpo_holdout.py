#!/usr/bin/env python3
"""Independently verify exact pinned holdout projection + inference artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_holdout_verify import verify_holdout_chain


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed five-artifact GRPO holdout content binding audit"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--projection-manifest", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--capture-manifest", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--expected-prompts-sha256", required=True)
    parser.add_argument("--expected-projection-manifest-sha256", required=True)
    parser.add_argument("--expected-predictions-sha256", required=True)
    parser.add_argument("--expected-capture-manifest-sha256", required=True)
    parser.add_argument("--checkpoint-role", choices=("Base", "SFT", "GRPO"), default="Base")
    parser.add_argument("--expected-adapter-config-sha256")
    parser.add_argument("--expected-adapter-weights-sha256")
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    args = parser.parse_args()
    try:
        report = verify_holdout_chain(
            dataset=args.dataset,
            prompts=args.prompts,
            projection_manifest=args.projection_manifest,
            predictions=args.predictions,
            capture_manifest=args.capture_manifest,
            expected_dataset_sha256=args.expected_dataset_sha256,
            expected_prompts_sha256=args.expected_prompts_sha256,
            expected_projection_manifest_sha256=args.expected_projection_manifest_sha256,
            expected_predictions_sha256=args.expected_predictions_sha256,
            expected_capture_manifest_sha256=args.expected_capture_manifest_sha256,
            model=args.model, model_revision=args.revision,
            split=args.split, checkpoint_role=args.checkpoint_role,
            expected_adapter_config_sha256=args.expected_adapter_config_sha256,
            expected_adapter_weights_sha256=args.expected_adapter_weights_sha256,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: independent holdout binding rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
