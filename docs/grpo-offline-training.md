# SRE GRPO offline training (experimental)

Status: **contract and CPU-only tests; real Qwen3/TR L/PEFT, GPU training and
independent A/B are NOT verified**. This feature is separate from the Go
G1–G2m release/attestation Draft stack and creates no release authorization.

## Boundaries

- `sre.grpo.episode/v1` JSONL contains versioned read-only observations and
  private Oracle truth; it is not a live Kubernetes command log.
- The model receives only `alert` and an allowlisted, frozen observation list.
  The `oracle`, `split` and `fault_family` are never included in prompt text.
- Fault families must not cross train/validation/test. Duplicate JSON keys,
  unknown fields, invalid IDs, unknown tools, duplicate/forged evidence, and
  bad Oracle references fail closed.
- Reward is **independent** of model-supplied tool-call count, latency,
  risk score, tool result, repair action or Judge verdict. Only read-only
  observations, model's diagnostic JSON and isolated Oracle are involved.
- Accepted model output has *exactly* `root_cause_id`, `evidence_ids`,
  `stop_reason` (`verified` or `insufficient_evidence`). Any action,
  tool_calls, unknown field or prose wrapper is rejected.
- A guessed correct root cause without all required evidence gets negative
  reward. Unsupported evidence IDs and wrong guesses get -1.0. Correct
  abstention on an unanswerable episode receives 1.0. Additional **known**
  but unnecessary citations are mildly penalized; this is not a tool
  efficiency metric.
- `scripts/eval_sre_grpo.py` refuses partial, extra and duplicate holdout
  predictions. Train predictions are never scored as test. Its metric
  `exact_success_rate` is an evidence-gated offline correctness proxy,
  **not** production root-cause accuracy.

## Replay without a GPU or model

```bash
pip install -e ".[dev]"
pytest -q tests/test_grpo_training.py tests/test_grpo_eval.py tests/test_grpo_cli.py

# Show dataset SHA256 and split counts only. No Oracle leakage in stdout.
python scripts/train_sre_grpo.py \
  --dataset benchmarks/grpo/synthetic-episodes.jsonl

# Synthetic perfect-abstention fixture (NOT a model output or benchmark).
python scripts/eval_sre_grpo.py \
  --dataset benchmarks/grpo/synthetic-episodes.jsonl \
  --predictions benchmarks/grpo/synthetic-predictions.jsonl --split test
```

The synthetic dataset deliberately has only **one** train episode and one
unanswerable holdout; it tests plumbing, not the benefit of GRPO.

## Opt-in CUDA training entrypoint

```bash
pip install -e ".[train]"
python scripts/train_sre_grpo.py \
  --dataset /path/to/private-versioned-episodes.jsonl \
  --execute --model Qwen/Qwen3-0.6B \
  --output-dir /path/to/new-runs/sre-grpo-smoke \
  --max-steps 10 --num-generations 4
```

The executable path requires a CUDA GPU, explicit model/output-dir, at least
eight train episodes unless `--allow-tiny-lab` is specified, and uses a
single-process LoRA GRPO config. It is **not** a GPU acceptance report. The
training script writes a manifest with data SHA, model, seed and actual
dependency versions; `trainer_returned` is not an independent quality claim.

The declared `.[train]` ranges target the TRL 0.25 interface but are not a
hash-locked, independently verified environment. Pin the entire Python/PyTorch
stack and tokenizer/model revision before reproducible comparisons. Qwen3's
thinking-mode/chat-template behavior must be explicitly fixed and validated
before an actual training run; strict JSON-only reward can otherwise collapse.

## Next acceptance gates

1. Collect real (disposable cluster only) Episodes with raw observation and
   independent fault-injection/Oracle receipts. Store a versioned immutable
   train/validation/test split by *fault family*, plus provenance and data SHA.
2. Verify complete model sampling with actual Qwen3 tokenizer, non-thinking
   JSON output contract and group variance; no fake tool receipts.
3. Run pinned Base vs SFT vs GRPO on exactly the same unseen holdout and log
   repeated seeds, exact weights/tokenizer/template, step count, GPU time,
   wall time, mean reward, evidence-gated RCA, abstention, invalid JSON,
   fabricated citation and independent tool-receipt cost.
4. Conduct reward ablation and adversarial tests: Oracle leakage, duplicate
   evidence, invented tool results, early stop, too-short completion,
   cross-family leakage and malicious observation text. Inspect raw failures.
5. Require independent review and a frozen validation record before using
   any result in a portfolio or release gate; do not infer production repair
   permission from a diagnostic model's reward.

See the [TRL 0.25 GRPO documentation](https://huggingface.co/docs/trl/v0.25.0/grpo_trainer)
for the custom reward and metadata-column interface.
