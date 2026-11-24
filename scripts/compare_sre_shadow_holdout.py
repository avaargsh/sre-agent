#!/usr/bin/env python3
"""Independent descriptive comparison of two externally pinned prediction files."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from agentic_aiops.secure_file import read_pinned_regular
from agentic_aiops.grpo_compare import _paired_result
from agentic_aiops.grpo_import import _verify_pin
from agentic_aiops.grpo_eval import evaluate_holdout, load_predictions_bytes
from agentic_aiops.grpo_training import load_episodes_bytes


_MAX_PINNED_FILE_BYTES = 4 * 1024 * 1024


def _read_pinned_regular(path: Path, pin: str, label: str, identities: set) -> bytes:
    """Read/pin one bounded regular inode through component-safe descriptors."""
    raw, _identity = read_pinned_regular(
        path, limit=_MAX_PINNED_FILE_BYTES, label=label,
        identities=identities,
    )
    _verify_pin(raw, pin, label)
    return raw


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("dataset", "dataset-sha256", "inkling", "inkling-sha256",
                  "cloud", "cloud-sha256"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--split", choices=("test", "validation"), default="test")
    a = p.parse_args()
    try:
        paths = [Path(x) for x in (a.dataset, a.inkling, a.cloud)]
        identities = set()
        dataset, inkling, cloud = [
            _read_pinned_regular(path, pin, label, identities)
            for path, pin, label in zip(paths, (a.dataset_sha256, a.inkling_sha256,
                                              a.cloud_sha256), ("dataset", "inkling", "cloud"))
        ]
        episodes = load_episodes_bytes(dataset)
        selected = {ep.episode_id: ep for ep in episodes if ep.split == a.split}
        if not 1 <= len(selected) <= 2048:
            raise ValueError("invalid holdout case count")
        left, right = load_predictions_bytes(inkling), load_predictions_bytes(cloud)
        report = {
            "schema_version": "sre.shadow.paired-holdout/v1",
            "dataset_sha256": hashlib.sha256(dataset).hexdigest(),
            "predictions_sha256": {"inkling": hashlib.sha256(inkling).hexdigest(),
                                   "cloud": hashlib.sha256(cloud).hexdigest()},
            "split": a.split,
            "inkling": evaluate_holdout(episodes, left, split=a.split),
            "cloud": evaluate_holdout(episodes, right, split=a.split),
            "paired": _paired_result(selected, left, right),
            "admission": "HOLD", "model_attribution_verified": False,
            "superiority_claim_authorized": False, "production_eligible": False,
        }
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"HOLD: invalid paired inputs ({type(exc).__name__})", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
