#!/usr/bin/env python3
"""Offline CPU-only verification of claimed GRPO post-step vs saved LoRA bytes.

A file-to-file content match is NOT an authenticated optimizer step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_tensor_link import verify_pinned_tensor_map_with_training_receipt


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CPU-only independent per-tensor GRPO train-to-save file consistency"
    )
    parser.add_argument("--tensor-map", type=Path, required=True)
    parser.add_argument("--expected-tensor-map-sha256", required=True)
    parser.add_argument("--train-receipt", type=Path, required=True)
    parser.add_argument("--expected-train-receipt-sha256", required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--adapter-dir", type=Path, required=True)
    parser.add_argument("--expected-adapter-config-sha256", required=True)
    parser.add_argument("--expected-adapter-weights-sha256", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()

    try:
        report = verify_pinned_tensor_map_with_training_receipt(
            tensor_map=args.tensor_map,
            expected_tensor_map_sha256=args.expected_tensor_map_sha256,
            train_receipt=args.train_receipt,
            expected_train_receipt_sha256=args.expected_train_receipt_sha256,
            expected_dataset_sha256=args.expected_dataset_sha256,
            adapter_dir=args.adapter_dir,
            expected_adapter_config_sha256=args.expected_adapter_config_sha256,
            expected_adapter_weights_sha256=args.expected_adapter_weights_sha256,
            base_model=args.model, base_revision=args.revision,
        )
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"UNKNOWN: GRPO saved tensor link refused: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
