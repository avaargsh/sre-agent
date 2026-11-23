#!/usr/bin/env python3
"""Independently replay pinned Qwen3 capture metadata and SRE Oracle reward.

A verified binding is NOT proof of model execution, authenticated provenance,
safe training, or model quality. Optional --require-signal rejects reward collapse.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_capture_verify import verify_capture_binding
from agentic_aiops.grpo_rollout_audit import audit_rollout_groups


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify pinned raw Qwen3 capture")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--rollouts", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--expected-rollouts-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--require-signal", action="store_true")
    args = parser.parse_args()
    try:
        binding = verify_capture_binding(
            args.dataset, args.rollouts, args.manifest,
            expected_dataset_sha256=args.expected_dataset_sha256,
            expected_rollouts_sha256=args.expected_rollouts_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
            model=args.model, model_revision=args.revision,
            group_size=args.group_size,
        )
        audit = audit_rollout_groups(
            args.dataset, args.rollouts,
            expected_dataset_sha256=args.expected_dataset_sha256,
            expected_rollouts_sha256=args.expected_rollouts_sha256,
            group_size=args.group_size,
        )
    except (OSError, ValueError) as exc:
        print(f"UNKNOWN: capture verification rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps({"capture_binding": binding, "reward_audit": audit},
                     sort_keys=True))
    if args.require_signal and (
        audit["readiness"] != "GRADIENT_SIGNAL_PRESENT_NOT_TRAINING_PROOF"
    ):
        print("UNKNOWN: reward group has insufficient nonconstant signal",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
