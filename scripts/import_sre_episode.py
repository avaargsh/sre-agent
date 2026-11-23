#!/usr/bin/env python3
"""Export a frozen read-only AIOps scenario into a single GRPO Episode.

Requires a separately authored Oracle manifest and a trusted out-of-band
manifest SHA256. Integrity check is not proof of signer identity.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentic_aiops.grpo_import import import_scenario_episode


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a frozen SRE Episode")
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--expected-approval-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = import_scenario_episode(
        args.scenario,
        args.approval,
        expected_approval_sha256=args.expected_approval_sha256,
        output=args.output,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
