#!/usr/bin/env python3
"""Revision-pinned CUDA-only Qwen3 raw rollout capture; experimental LAB ONLY.

No Kubernetes calls, no model grading, no optimizer updates and no production
admission. Qwen3 and Transformers are imported only after strict preflight.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_rollout_capture import (
    capture_rollout_groups,
    prepare_capture,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture raw Qwen3 SRE GRPO rollouts")
    parser.add_argument("--execute", action="store_true",
                        help="actually sample a pinned Qwen3 model on CUDA")
    parser.add_argument("--lab-only", action="store_true",
                        help="explicitly acknowledge unverified experimental provenance")
    parser.add_argument("--allow-tiny-lab", action="store_true",
                        help="allow fewer than 8 train rows for a smoke experiment")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--model", required=True, help="Qwen/Qwen3-* model ID")
    parser.add_argument("--revision", required=True,
                        help="full 40-character lowercase Hugging Face commit")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--num-generations", type=int, default=4)
    parser.add_argument("--max-new-tokens", type=int, default=192)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not args.execute or not args.lab_only:
        parser.error("CUDA sampling requires --execute and --lab-only")
    try:
        selected, _ = prepare_capture(
            args.dataset,
            expected_dataset_sha256=args.expected_dataset_sha256,
            model=args.model, model_revision=args.revision,
            group_size=args.num_generations,
            seed=args.seed, max_new_tokens=args.max_new_tokens,
            output=args.output, manifest=args.manifest,
        )
    except (OSError, ValueError) as exc:
        print(f"UNKNOWN: Qwen3 capture preflight rejected: {exc}", file=sys.stderr)
        return 3
    if len(selected) < 8 and not args.allow_tiny_lab:
        parser.error("at least 8 train episodes required without --allow-tiny-lab")
    if len(selected) >= 8 and args.allow_tiny_lab:
        parser.error("--allow-tiny-lab can only be used for fewer than 8 train rows")

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        print(f"UNKNOWN: missing CUDA/transformers dependency: {exc}", file=sys.stderr)
        return 3
    if not torch.cuda.is_available():
        print("UNKNOWN: CUDA GPU required; no model-loading CPU fallback", file=sys.stderr)
        return 3

    # This is *not* an authenticated model provenance or deterministic-kernel
    # guarantee. Both model and tokenizer are requested at the same commit;
    # save the exact versions and independent artifact attestation separately.
    tokenizer = AutoTokenizer.from_pretrained(
        args.model, revision=args.revision, trust_remote_code=False,
    )
    precision = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    model = AutoModelForCausalLM.from_pretrained(
        args.model, revision=args.revision, trust_remote_code=False, dtype=precision,
    )
    model.to("cuda")
    model.eval()

    def sample(prompt: str, seed: int) -> str:
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        inputs = tokenizer(
            prompt, add_special_tokens=False, return_tensors="pt",
        ).to("cuda")
        with torch.inference_mode():
            sequence = model.generate(
                **inputs,
                max_new_tokens=args.max_new_tokens,
                do_sample=True,
                temperature=0.7,
                top_p=0.8,
                top_k=20,
                pad_token_id=tokenizer.eos_token_id,
            )
        # Only decode continuation tokens, not the user or Oracle prompt.
        new_tokens = sequence[0][inputs["input_ids"].shape[-1]:]
        return tokenizer.decode(
            new_tokens, skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )

    try:
        receipt = capture_rollout_groups(
            args.dataset,
            expected_dataset_sha256=args.expected_dataset_sha256,
            output=args.output, manifest=args.manifest,
            tokenizer=tokenizer, sampler=sample,
            model=args.model, model_revision=args.revision,
            group_size=args.num_generations,
            seed=args.seed, max_new_tokens=args.max_new_tokens,
        )
    except (OSError, ValueError) as exc:
        print(f"UNKNOWN: rollout capture rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
