#!/usr/bin/env python3
"""Sample Qwen3 on Oracle-free holdout prompts; no training or release authority.

The inference process takes only a projected prompt JSONL artifact, never
the Oracle-bearing dataset. CUDA and Transformers are imported after
revision, digest and input-shape preflight; a CPU fake-model is only a test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentic_aiops.grpo_adapter import (
    load_pinned_adapter, staged_pinned_adapter,
    verify_loaded_adapter_weights,
)
from agentic_aiops.grpo_adapter_effect import probe_loaded_adapter_effect
from agentic_aiops.grpo_holdout_capture import (
    capture_holdout_predictions,
    validate_holdout_prompts,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Qwen3 read-only holdout prediction capture")
    parser.add_argument("--execute", action="store_true",
                        help="explicitly execute CUDA inference")
    parser.add_argument("--lab-only", action="store_true",
                        help="acknowledge the source and model run are unverified")
    parser.add_argument("--prompts", type=Path, required=True,
                        help="Oracle-free projection; never the original dataset")
    parser.add_argument("--expected-prompts-sha256", required=True)
    parser.add_argument("--split", choices=("test", "validation"), default="test")
    parser.add_argument("--checkpoint-role", choices=("Base","SFT","GRPO"),
                        default="Base")
    parser.add_argument("--adapter-dir", type=Path)
    parser.add_argument("--expected-adapter-config-sha256")
    parser.add_argument("--expected-adapter-weights-sha256")
    parser.add_argument("--model", required=True, help="Qwen/Qwen3-* repository")
    parser.add_argument("--revision", required=True,
                        help="full lowercase 40-character immutable model commit")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-new-tokens", type=int, default=192)
    args = parser.parse_args()

    if not args.execute or not args.lab_only:
        parser.error("CUDA holdout inference requires --execute and --lab-only")
    try:
        validate_holdout_prompts(
            args.prompts, expected_prompts_sha256=args.expected_prompts_sha256,
            model=args.model, model_revision=args.revision,
            seed=args.seed, max_new_tokens=args.max_new_tokens,
            split=args.split, output=args.output, manifest=args.manifest,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: holdout inference preflight rejected: {exc}", file=sys.stderr)
        return 3

    adapter = None
    if args.checkpoint_role == "Base":
        if (args.adapter_dir is not None
                or args.expected_adapter_config_sha256 is not None
                or args.expected_adapter_weights_sha256 is not None):
            parser.error("Base checkpoint-role forbids all adapter arguments")
    else:
        if (args.adapter_dir is None
                or not args.expected_adapter_config_sha256
                or not args.expected_adapter_weights_sha256):
            parser.error(
                "SFT/GRPO --checkpoint-role requires --adapter-dir, "
                "--expected-adapter-config-sha256 and "
                "--expected-adapter-weights-sha256"
            )
        try:
            adapter = load_pinned_adapter(
                args.adapter_dir,
                base_model=args.model, base_revision=args.revision,
                expected_adapter_config_sha256=args.expected_adapter_config_sha256,
                expected_adapter_weights_sha256=args.expected_adapter_weights_sha256,
            )
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"UNKNOWN: pinned adapter preflight rejected: {exc}", file=sys.stderr)
            return 3

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        print(f"UNKNOWN: missing CUDA/Transformers dependency: {exc}", file=sys.stderr)
        return 3
    if not torch.cuda.is_available():
        print("UNKNOWN: CUDA GPU required; no actual model CPU fallback", file=sys.stderr)
        return 3

    tokenizer = AutoTokenizer.from_pretrained(
        args.model, revision=args.revision, trust_remote_code=False,
    )
    dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    model = AutoModelForCausalLM.from_pretrained(
        args.model, revision=args.revision,
        trust_remote_code=False, dtype=dtype,
    )
    model.to("cuda")
    if adapter is not None:
        # PEFT can only access a private copy of the two verified files.
        # Never allow it to reopen mutable original adapter paths.
        try:
            from peft import (
                PeftModel, get_model_status, get_peft_model_state_dict,
            )
        except ImportError as exc:
            print(f"UNKNOWN: missing PEFT for pinned adapter: {exc}", file=sys.stderr)
            return 3
        with staged_pinned_adapter(adapter) as frozen_dir:
            model = PeftModel.from_pretrained(
                model, str(frozen_dir),
                is_trainable=False, local_files_only=True,
                autocast_adapter_dtype=False,
            )
        # PEFT's public checkpoint export drops the runtime adapter name,
        # matching the saved Safetensors state_dict keys. Do NOT infer
        # loading succeeded merely because from_pretrained returned.
        def exact_tensor_bytes(tensor):
            return (tensor.detach().cpu().contiguous()
                    .view(torch.uint8).numpy().tobytes())
        verify_loaded_adapter_weights(
            adapter,
            get_peft_model_state_dict(
                model, adapter_name="default", save_embedding_layers=False,
            ),
            get_model_status(model),
            tensor_bytes=exact_tensor_bytes,
        )
    model.eval()
    if adapter is not None:
        # Identical, fixed-size forward probe with LoRA enabled/disabled.
        # If PEFT silently becomes trainable after disable_adapter(), or
        # logits do not change, fail closed before sampling any Holdout row.
        local_effect = probe_loaded_adapter_effect(
            model, tokenizer, torch=torch, get_model_status=get_model_status,
        )
    else:
        local_effect = None

    def sample(chat_prompt: str, seed: int) -> str:
        # Greedy decode: no user-controlled truncation, temperature or sampling
        # to silently select only the easy or favorable responses.
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        tokens = tokenizer(
            chat_prompt, add_special_tokens=False, return_tensors="pt",
        ).to("cuda")
        with torch.inference_mode():
            generated = model.generate(
                **tokens,
                max_new_tokens=args.max_new_tokens,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        raw_tokens = generated[0][tokens["input_ids"].shape[-1]:]
        return tokenizer.decode(
            raw_tokens, skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )

    try:
        receipt = capture_holdout_predictions(
            args.prompts,
            expected_prompts_sha256=args.expected_prompts_sha256,
            output=args.output, manifest=args.manifest,
            tokenizer=tokenizer, sampler=sample,
            model=args.model, model_revision=args.revision,
            split=args.split, seed=args.seed,
            max_new_tokens=args.max_new_tokens,
            checkpoint_role=args.checkpoint_role,
            adapter_receipt=adapter.receipt if adapter is not None else None,
            local_effect_receipt=local_effect,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"UNKNOWN: holdout capture rejected: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
