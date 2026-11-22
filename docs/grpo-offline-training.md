# SRE GRPO offline training (experimental)

Status: **contract and CPU-only tests; real Qwen3/TRL/PEFT, GPU training and
independent A/B are NOT verified**. This feature is separate from the Go
G1–G2m release/attestation Draft stack and creates no release authorization.

## Boundaries

- `sre.grpo.episode/v1` JSONL contains versioned read-only observations and
  private Oracle truth; it is not a live Kubernetes command log.
- The model receives only `alert` and an allowlisted, frozen observation list.
  The `oracle`, `split` and `fault_family` are never included in prompt text.
- Fault families must not cross train/validation/test, and identical\n  normalized alert + observation content cannot cross splits even if family\n  names or evidence IDs are changed. This does not detect semantic near-duplicates.\n  Duplicate JSON keys,
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
stack and tokenizer/model revision before reproducible comparisons. Qwen3 inputs use the explicit \`enable_thinking=False\` chat template. The\npreflight rejects any dataset whose rendered prompt would be truncated or\nwhose Oracle-backed valid JSON answer exceeds the completion budget. Validate\nthe actual tokenizer/model behavior on GPU before claiming a training result.

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



## Import from an existing frozen Evidence Bundle (P0 ingestion)

`scripts/import_sre_episode.py` reads the repository's frozen
`benchmarks/scenarios/checkout-latency.json` scenario format. It uses only
`bundle.incident.summary` and the frozen `bundle.evidence` records for
model input. It **never** reads `bundle.hypotheses`,
`bundle.outcome`, or model predictions as truth labels.

The scenario input is untrusted until its original SHA256 is checked against a
**separate**, owner-authored approval JSON. Approval JSON has this schema:

```json
{
  "schema_version": "sre.grpo.import-approval/v1",
  "case_id": "checkout-latency-001",
  "episode_id": "checkout-synthetic-001",
  "fault_family": "db-pool",
  "split": "train",
  "source_sha256": "<64-lowercase-hex-of-the-exact-scenario-file>",
  "evidence_tools": {
    "e-metrics-1": "prometheus.query",
    "e-k8s-1": "kubernetes.get_pods"
  },
  "oracle": {
    "answerable": true,
    "root_cause_id": "db_pool_saturation",
    "required_evidence_ids": ["e-metrics-1"]
  }
}
```

For controlled offline development, an independent data reviewer confirms the
source, tool attribution, split, required evidence and fault-injection Oracle;
then records the exact **approval-file SHA256 out of band**. A data pipeline
must never compute an approval's trusted expected SHA from that same untrusted
approval file at runtime — doing so provides no authorization check.

```bash
python scripts/import_sre_episode.py \
  --scenario benchmarks/scenarios/checkout-latency.json \
  --approval /trusted/reviewed/approval.json \
  --expected-approval-sha256 "$PINNED_APPROVAL_SHA256" \
  --output /new/episode-001.jsonl

# For a multi-Episode dataset, assemble each reviewed, non-overwriting
# JSONL file, then validate all families/splits with load_episodes().
```

Both original source bytes and approval bytes are SHA-pinned; the output
receipt carries the exact source/approval/episode SHA256 values. Unknown
sources, mismatched read-only tool attribution, orphan evidence references,
duplicate fields, unrecognized schemas and attempts to overwrite output are
rejected before producing an Episode. This importer **does not** run fault
injection or live Kubernetes calls.

**Trust limitation:** SHA256 equality proves bytes were not changed relative
to a separately trusted digest; it does **not** authenticate the reviewer,
establish that any labels are scientifically correct, or prove that a
real Kubernetes incident occurred. `independent_issuer_verified=false` and
`live_fault_injection_verified=false` remain explicit. The existing checkout
scenario is labelled `synthetic-regression`. No actual G2i/G2m Go proof or
production causality should be inferred from this conversion.

CLI regression:

```bash
pytest -q tests/test_grpo_import.py
```

Next: connect disposable kind fault-injection exports and an external Oracle
verifier as independently authenticated evidence inputs. Keep unverified
episodes out of reported real-model accuracy and external release gates.
