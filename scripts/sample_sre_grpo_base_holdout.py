#!/usr/bin/env python3
"""Explicit LAB-only Base Qwen3 inference on Oracle-free pinned Holdout prompts.

Real CUDA/model loading is delayed until all read-only artifact and destination
checks succeed. Synthetic callback tests do not establish model provenance.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_base_holdout_capture import (
    capture_base_holdout_predictions,
    validate_holdout_prompts,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Explicit LAB-only Base Qwen3 Holdout capture (no Adapter)",
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--lab-only", action="store_true")
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--expected-prompts-sha256", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    parser.add_argument("--model", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-new-tokens", type=int, default=192)
    args = parser.parse_args()

    # Inference must never be activated by simply passing a data path.
    if not args.execute or not args.lab_only:
        parser.error("Base CUDA inference requires --execute and --lab-only")

    try:
        validate_holdout_prompts(
            args.prompts,
            expected_prompts_sha256=args.expected_prompts_sha256,
            model=args.model, model_revision=args.revision,
            seed=args.seed, max_new_tokens=args.max_new_tokens,
            split=args.split, output=args.output, manifest=args.manifest,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: Base Holdout preflight rejected: {exc}", file=sys.stderr)
        return 3

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        print(f"UNKNOWN: missing CUDA/Transformers dependency: {exc}", file=sys.stderr)
        return 3
    if not torch.cuda.is_available():
        print("UNKNOWN: CUDA GPU required; no CPU model fallback", file=sys.stderr)
        return 3

    try:
        tokenizer = AutoTokenizer.from_pretrained(
            args.model, revision=args.revision, trust_remote_code=False,
        )
        dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        model = AutoModelForCausalLM.from_pretrained(
            args.model, revision=args.revision, trust_remote_code=False,
            dtype=dtype,
        )
        model.to("cuda")
        model.eval()

        def sample(chat_prompt: str, seed: int) -> str:
            torch.manual_seed(seed)
            torch.cuda.manual_seed_all(seed)
            tokens = tokenizer(
                chat_prompt, add_special_tokens=False, return_tensors="pt",
            ).to("cuda")
            with torch.inference_mode():
                generated = model.generate(
                    **tokens, max_new_tokens=args.max_new_tokens,
                    do_sample=False, pad_token_id=tokenizer.eos_token_id,
                )
            raw_tokens = generated[0][tokens["input_ids"].shape[-1]:]
            return tokenizer.decode(
                raw_tokens, skip_special_tokens=True,
                clean_up_tokenization_spaces=False,
            )

        result = capture_base_holdout_predictions(
            args.prompts,
            expected_prompts_sha256=args.expected_prompts_sha256,
            output=args.output, manifest=args.manifest,
            tokenizer=tokenizer, sampler=sample,
            model=args.model, model_revision=args.revision,
            split=args.split, seed=args.seed,
            max_new_tokens=args.max_new_tokens,
        )
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        print(f"UNKNOWN: Base Holdout capture rejected: {exc}", file=sys.stderr)
        return 3
    # This report is content consistency only, not attested CUDA/model proof.
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
