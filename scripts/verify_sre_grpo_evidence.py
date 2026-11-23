#!/usr/bin/env python3
"""Read-only independently recheck a published SRE GRPO evidence package.

No GPU or model dependencies. Validates independently pinned source files;
does NOT attest training execution or the saved weights' optimizer origin.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_evidence_bundle import verify_grpo_evidence_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CPU-only read-only replay of published SRE GRPO evidence package"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--run-manifest", type=Path, required=True)
    parser.add_argument("--expected-run-manifest-sha256", required=True)
    parser.add_argument("--train-receipt", type=Path, required=True)
    parser.add_argument("--expected-train-receipt-sha256", required=True)
    parser.add_argument("--adapter-dir", type=Path, required=True)
    parser.add_argument("--expected-adapter-config-sha256", required=True)
    parser.add_argument("--expected-adapter-weights-sha256", required=True)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--projection-manifest", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--capture-manifest", type=Path, required=True)
    parser.add_argument("--expected-prompts-sha256", required=True)
    parser.add_argument("--expected-projection-manifest-sha256", required=True)
    parser.add_argument("--expected-predictions-sha256", required=True)
    parser.add_argument("--expected-capture-manifest-sha256", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    parser.add_argument("--evidence-bundle", type=Path, required=True)
    parser.add_argument("--expected-evidence-bundle-sha256", required=True)
    args = parser.parse_args()
    try:
        bundle = verify_grpo_evidence_bundle(
            evidence_bundle=args.evidence_bundle,
            expected_evidence_bundle_sha256=args.expected_evidence_bundle_sha256,
            dataset=args.dataset,
            expected_dataset_sha256=args.expected_dataset_sha256,
            run_manifest=args.run_manifest,
            expected_run_manifest_sha256=args.expected_run_manifest_sha256,
            train_receipt=args.train_receipt,
            expected_train_receipt_sha256=args.expected_train_receipt_sha256,
            adapter_dir=args.adapter_dir,
            expected_adapter_config_sha256=args.expected_adapter_config_sha256,
            expected_adapter_weights_sha256=args.expected_adapter_weights_sha256,
            holdout={
                "prompts": args.prompts,
                "projection_manifest": args.projection_manifest,
                "predictions": args.predictions,
                "capture_manifest": args.capture_manifest,
                "expected_prompts_sha256": args.expected_prompts_sha256,
                "expected_projection_manifest_sha256": args.expected_projection_manifest_sha256,
                "expected_predictions_sha256": args.expected_predictions_sha256,
                "expected_capture_manifest_sha256": args.expected_capture_manifest_sha256,
                "split": args.split,
            },
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: independent SRE GRPO evidence replay rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(bundle, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
