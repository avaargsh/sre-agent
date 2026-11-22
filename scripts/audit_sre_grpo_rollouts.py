#!/usr/bin/env python3
"""Offline GRPO reward-variance audit (never claims real model training)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_rollout_audit import audit_rollout_groups


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit group-level SRE GRPO reward collapse")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--rollouts", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--expected-rollouts-sha256", required=True)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--min-signal-fraction", type=float, default=0.25)
    parser.add_argument("--require-signal", action="store_true")
    args = parser.parse_args()

    try:
        report = audit_rollout_groups(
            args.dataset, args.rollouts,
            expected_dataset_sha256=args.expected_dataset_sha256,
            expected_rollouts_sha256=args.expected_rollouts_sha256,
            group_size=args.group_size,
            min_signal_fraction=args.min_signal_fraction,
        )
    except (ValueError, OSError) as exc:
        print(f"UNKNOWN: rollout audit rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    if args.require_signal and (
        report["readiness"] != "GRADIENT_SIGNAL_PRESENT_NOT_TRAINING_PROOF"
    ):
        print("UNKNOWN: no sufficient GRPO group reward variance", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
