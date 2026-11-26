#!/usr/bin/env python3
"""Explicit LAB-only capture from a local OpenAI-compatible server."""
import argparse
import json
import sys
from functools import partial

from agentic_aiops.shadow_holdout import capture_shadow_holdout, request_local_completion


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--lab-only", action="store_true")
    for field in ("prompts", "expected-prompts-sha256", "output", "manifest",
                  "model", "revision", "engine", "quantization", "base-url"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--max-tokens", type=int, default=512)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--timeout", type=float, default=120)
    a = p.parse_args()
    if not a.execute or not a.lab_only:
        p.error("requires --execute and --lab-only")
    try:
        report = capture_shadow_holdout(
            a.prompts, expected_prompts_sha256=a.expected_prompts_sha256,
            output=a.output, manifest=a.manifest, model=a.model,
            revision=a.revision, engine=a.engine, quantization=a.quantization,
            max_tokens=a.max_tokens, seed=a.seed,
            sample=partial(request_local_completion, a.base_url, timeout=a.timeout),
        )
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        print(f"HOLD: incomplete local capture ({type(exc).__name__})", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
