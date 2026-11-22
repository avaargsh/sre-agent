#!/usr/bin/env python3
"""Explicit, offline-only SRE GRPO training entrypoint.

Default mode is CPU-only contract inspection. --execute requires a CUDA GPU,
an explicit model and an output directory. Nothing touches live Kubernetes.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
from importlib import metadata
from pathlib import Path

from agentic_aiops.grpo_training import (
    make_trl_reward,
    qwen3_chat_rows,
    training_rows,
)
from agentic_aiops.grpo_rollout_audit import audit_rollout_groups
from agentic_aiops.grpo_train_proof import (
    freeze_train_dataset,
    snapshot_lora_parameters,
    verify_local_lora_update,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="SRE GRPO offline training")
    parser.add_argument(
        "--dataset", type=Path,
        default=Path("benchmarks/grpo/synthetic-episodes.jsonl"),
    )
    parser.add_argument("--execute", action="store_true",
                        help="explicitly start TRL GRPO training on CUDA")
    parser.add_argument("--model", help="explicit Qwen/Qwen3-* model repository")
    parser.add_argument("--model-revision", help="pinned lowercase 40-character model commit SHA")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--allow-tiny-lab", action="store_true",
                        help="skip baseline gate only for <8-row synthetic lab smoke")
    parser.add_argument("--lab-only", action="store_true",
                        help="explicitly acknowledge unverified experimental dataset")
    parser.add_argument("--baseline-rollouts", type=Path,
                        help="complete pinned baseline model rollout groups")
    parser.add_argument("--expected-dataset-sha256",
                        help="dataset digest pinned outside untrusted rollout files")
    parser.add_argument("--expected-rollouts-sha256",
                        help="rollout digest pinned outside untrusted rollout files")
    parser.add_argument("--num-generations", type=int, default=4)
    parser.add_argument("--max-steps", type=int, default=10)
    args = parser.parse_args()

    if not 2 <= args.num_generations <= 64 or not 1 <= args.max_steps <= 100:
        parser.error("num-generations must be 2-64 and max-steps must be 1-100")
    try:
        episodes, frozen_sha = freeze_train_dataset(
            args.dataset,
            expected_dataset_sha256=args.expected_dataset_sha256,
        )
    except (OSError, ValueError) as exc:
        parser.error(f"dataset_sha256/episode validation rejected: {exc}")
    rows = training_rows(episodes)
    if not rows:
        parser.error("dataset must contain train episodes")
    summary = {
        "dataset_sha256": frozen_sha,
        "dataset_schema": "sre.grpo.episode/v1",
        "train_rows": len(rows),
        "validation_rows": sum(e.split == "validation" for e in episodes),
        "test_rows": sum(e.split == "test" for e in episodes),
        "oracle_in_model_prompt": False,
        "live_tool_access": False,
        "mode": "execute" if args.execute else "inspect",
    }
    if not args.execute:
        print(json.dumps(summary, sort_keys=True))
        return

    if not args.model or args.output_dir is None:
        parser.error("--execute requires --model and --output-dir")
    # Until independent issuer identity, immutable data admission and actual
    # GPU/holdout verification exist, the entrypoint has NO promoted mode.
    if not args.lab_only:
        parser.error("--execute requires --lab-only; trusted training admission is not implemented")
    if args.allow_tiny_lab and len(rows) >= 8:
        parser.error("--allow-tiny-lab is restricted to fewer than 8 train episodes")
    if not args.allow_tiny_lab and len(rows) < 8:
        parser.error("at least 8 train episodes required without --allow-tiny-lab")
    if args.output_dir.exists() or args.output_dir.is_symlink():
        parser.error("--output-dir must be a new directory; never overwrite evidence")
    if type(args.model_revision) is not str or not re.fullmatch(
        r"[0-9a-f]{40}", args.model_revision,
    ):
        parser.error("--model-revision must be a pinned lowercase 40-character commit")
    if not re.fullmatch(r"Qwen/Qwen3-[A-Za-z0-9._-]+", args.model):
        parser.error("--model requires an explicit Qwen/Qwen3-* repository")
    if os.environ.get("WORLD_SIZE", "1") != "1":
        parser.error("only single-process LAB training is supported")
    baseline_audit = None
    if not args.allow_tiny_lab:
        if (args.baseline_rollouts is None
                or not args.expected_rollouts_sha256
                or not args.expected_dataset_sha256):
            parser.error(
                "non-tiny --execute requires --baseline-rollouts, "
                "--expected-dataset-sha256 and --expected-rollouts-sha256"
            )
        try:
            baseline_audit = audit_rollout_groups(
                args.dataset,
                args.baseline_rollouts,
                expected_dataset_sha256=args.expected_dataset_sha256,
                expected_rollouts_sha256=args.expected_rollouts_sha256,
                group_size=args.num_generations,
            )
        except (ValueError, OSError) as exc:
            parser.error(f"baseline GRPO reward audit rejected: {exc}")
        if baseline_audit["readiness"] != "GRADIENT_SIGNAL_PRESENT_NOT_TRAINING_PROOF":
            parser.error("baseline GRPO reward audit found insufficient group variance")
    elif args.baseline_rollouts is not None or args.expected_rollouts_sha256:
        parser.error("--allow-tiny-lab does not accept baseline-rollouts options")

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from trl import GRPOConfig, GRPOTrainer
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        parser.error(f"missing train dependency: {exc}; install .[train]")
    if not torch.cuda.is_available():
        parser.error("CUDA required; no CPU fallback for an actual GRPO run")

    # The reward closure contains TRAIN Oracle records only; no holdout keys.
    training_episodes = tuple(e for e in episodes if e.split == "train")
    reward_fn = make_trl_reward(training_episodes)
    tokenizer = AutoTokenizer.from_pretrained(
        args.model, revision=args.model_revision, trust_remote_code=False,
    )
    model_rows = qwen3_chat_rows(tokenizer, training_episodes)
    torch.manual_seed(42)
    bf16 = torch.cuda.is_bf16_supported()
    # A string model=... would let TRL load from a mutable branch at runtime.
    # Pre-load the model at the exact same commit as the tokenizer instead.
    model = AutoModelForCausalLM.from_pretrained(
        args.model, revision=args.model_revision, trust_remote_code=False,
        dtype=torch.bfloat16 if bf16 else torch.float16,
    )
    model.to("cuda")
    args.output_dir.mkdir(parents=True, exist_ok=False)

    training_args = GRPOConfig(
        output_dir=str(args.output_dir),
        num_generations=args.num_generations,
        per_device_train_batch_size=args.num_generations,
        gradient_accumulation_steps=1,
        max_completion_length=192,
        max_prompt_length=1024,
        learning_rate=1e-6,
        max_steps=args.max_steps,
        logging_steps=1,
        report_to="none",
        remove_unused_columns=False,
        bf16=bf16,
        fp16=not bf16,
        seed=42,
    )
    trainer = GRPOTrainer(
        model=model,
        args=training_args,
        train_dataset=Dataset.from_list(model_rows),
        processing_class=tokenizer,
        reward_funcs=reward_fn,
        peft_config=LoraConfig(
            r=8, lora_alpha=16, lora_dropout=0.05,
            bias="none", task_type="CAUSAL_LM",
            target_modules=["q_proj", "v_proj"],
        ),
    )
    def raw_parameter_bytes(parameter):
        # Bit-preserving serialization; BF16 cannot be cast to NumPy directly.
        return (parameter.detach().cpu().contiguous()
                .view(torch.uint8).numpy().tobytes())

    before = snapshot_lora_parameters(
        trainer.model, tensor_bytes=raw_parameter_bytes,
    )
    versions = {}
    for name in ("torch", "trl", "peft", "transformers", "datasets"):
        versions[name] = metadata.version(name)
    manifest = {
        **summary,
        "model": args.model,
        "model_revision": args.model_revision,
        "tokenizer_revision": args.model_revision,
        "python": platform.python_version(),
        "cuda_device_name_unverified": torch.cuda.get_device_name(0),
        "before_lora_snapshot": before,
        "dependency_versions": versions,
        "seed": 42,
        "max_steps": args.max_steps,
        "num_generations": args.num_generations,
        "training_status": "started_not_verified",
        "training_scope": "LAB_ONLY_UNVERIFIED",
        "data_issuer_authenticated": False,
        "training_admission_authorized": False,
        "eligible_for_production": False,
        "baseline_reward_audit": baseline_audit,
        "preflight_model_runtime_verified": False,
        "preflight_reward_hacking_verified_absent": False,
    }
    # Immutable pre-run receipt: no local-optimizer success is claimed yet.
    with (args.output_dir / "sre-grpo-run-manifest.json").open("xb") as stream:
        stream.write(
            (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
        )
    trainer.train()
    after = snapshot_lora_parameters(
        trainer.model, tensor_bytes=raw_parameter_bytes,
    )
    # Trainer returned is NOT enough. Refuse to save as "trained" unless
    # there is an observed LoRA delta and at least one real trainer step.
    local_delta = verify_local_lora_update(
        before, after, global_step=trainer.state.global_step,
        max_steps=args.max_steps,
    )
    trainer.save_model()
    # Separate create-only lab result, not an authenticated GPU attestation.
    with (args.output_dir / "sre-grpo-local-lora-delta.json").open("xb") as stream:
        stream.write(
            (json.dumps({
                "schema_version": "sre.grpo.local-training-receipt/v1",
                "dataset_sha256": frozen_sha,
                "model": args.model,
                "model_revision": args.model_revision,
                "tokenizer_revision": args.model_revision,
                "local_lora_update": local_delta,
                "training_scope": "LAB_ONLY_UNVERIFIED",
                "model_runtime_independently_verified": False,
                "data_issuer_authenticated": False,
                "training_admission_authorized": False,
                "production_eligible": False,
            }, sort_keys=True, indent=2) + "\n").encode("utf-8")
        )


if __name__ == "__main__":
    main()
