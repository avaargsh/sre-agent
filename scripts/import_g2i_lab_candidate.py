#!/usr/bin/env python3
"""Import G2i Calico-kind proof as an UNKNOWN-only Observer holdout candidate.

This is not a CI provenance verifier, trusted admission, or model training.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentic_aiops.grpo_lab_intake import import_networkpolicy_lab_candidate


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage a G2i read-only lab candidate")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--expected-approval-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = import_networkpolicy_lab_candidate(
        args.root,
        args.approval,
        expected_approval_sha256=args.expected_approval_sha256,
        output=args.output,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
