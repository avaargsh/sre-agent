# SRE GRPO offline training (experimental)

Status: **contract and CPU-only tests; real Qwen3/TRL/PEFT, GPU training and
independent A/B are NOT verified**. This feature is separate from the Go
G1–G2m release/attestation Draft stack and creates no release authorization.

## Boundaries

- `sre.grpo.episode/v1` JSONL contains versioned read-only observations and
  private Oracle truth; it is not a live Kubernetes command log.
- The model receives only `alert` and an allowlisted, frozen observation list.
  The `oracle`, `split` and `fault_family` are never included in prompt text.
- Fault families must not cross train/validation/test, and identical
  normalized alert + observation content cannot cross splits even if family
  names or evidence IDs are changed. This does not detect semantic near-duplicates.
  Duplicate JSON keys,
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
  --execute --lab-only --model Qwen/Qwen3-0.6B \
  --baseline-rollouts /path/to/complete-baseline-rollouts.jsonl \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-rollouts-sha256 "$PINNED_ROLLOUTS_SHA256" \
  --output-dir /path/to/new-runs/sre-grpo-smoke \
  --max-steps 10 --num-generations 4
```

The executable path requires a CUDA GPU, explicit `--lab-only`, model/output directory, and at least eight train episodes unless `--allow-tiny-lab` is specified. Non-tiny runs additionally require a complete independently SHA-pinned baseline rollout audit with nonconstant group rewards. Without this the script aborts before importing optional training libraries. This is a **conservative readiness gate**, not a claim that baseline rollouts came from an actual model. The trainer uses a single-process LoRA GRPO config. It is **not** a GPU acceptance report. The
training script writes a manifest with data SHA, model, seed and actual
dependency versions; `trainer_returned` is not an independent quality claim.

The declared `.[train]` ranges target the TRL 0.25 interface but are not a
hash-locked, independently verified environment. Pin the entire Python/PyTorch
stack and tokenizer/model revision before reproducible comparisons. Qwen3 inputs use the explicit `enable_thinking=False` chat template. The
preflight rejects any dataset whose rendered prompt would be truncated or
whose Oracle-backed valid JSON answer exceeds the completion budget. Validate
the actual tokenizer/model behavior on GPU before claiming a training result.

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


## G2i NetworkPolicy lab evidence intake (candidate only)

The independent Go G2i NetworkPolicy evaluator, source signing and signer-policy
mechanics are currently in the **separate stacked Draft PR #6–#10**. This
Python GRPO branch **does not merge, endorse, or replace** those Go changes.

The opt-in adapter `grpo_lab_intake.py` understands the G2i data contract:
`episode.json` (15 original admin snapshots across before/during/after),
`evaluation.json`, three independently captured observer logs and three
`sre.dns-observation/v1` files. An owner-authored, independently SHA-pinned
approval must contain:

```json
{
  "schema_version": "sre.grpo.networkpolicy-lab-approval/v1",
  "episode_id": "np-calico-egress-001",
  "output_episode_id": "lab-np-001",
  "fault_family": "network-egress-unknown",
  "split": "test",
  "episode_sha256": "<sha256-of-original-episode.json>",
  "evaluation_sha256": "<sha256-of-original-evaluation.json>",
  "observer_log_sha256": {
    "before": "<sha256-of-before-observer.log>",
    "during": "<sha256-of-during-observer.log>",
    "after": "<sha256-of-after-observer.log>"
  }
}
```

The expected **approval file SHA256** must come from outside the untrusted
artifact directory. The adapter validates all 15 original base64 snapshots
and embedded SHA values, source/evaluation identity, actual before/during/after
probe statuses, original observer/admin log byte equality, probe/observer
diagnostic agreement, and create-only output. It cannot claim cryptographic
origin from these checks. A forged administrator capable of replacing all
files, or a forged self-issued signing key, is **not defeated** merely by
internally consistent SHA256 values.

```bash
python scripts/import_g2i_lab_candidate.py \
  --root /isolated/g2i-raw-proof \
  --approval /independent/reviewed-approval.json \
  --expected-approval-sha256 "$OUT_OF_BAND_APPROVAL_SHA256" \
  --output /new/grpo-lab-candidate.jsonl

pytest -q tests/test_grpo_lab_intake.py
```

**Critical Observer/Oracle distinction:** the G2i admin can prove an isolated
network-policy test fault in a disposable kind cluster. But the restricted
Observer sees only healthy DNS and failed HTTP. It does not have permissions to
read the NetworkPolicy and cannot conclude `network_policy_denial` from its
logs. The generated model prompt includes only **before and during observer
evidence**, not the after-restoration result, admin snapshots or test-admin
verdict. The only defensible label under this observation budget is:

```json
{"root_cause_id":"unknown","evidence_ids":[],"stop_reason":"insufficient_evidence"}
```

Every generated receipt explicitly has
`source_classification=unverified-lab-candidate`,
`lab_claim_authenticated=false`,
`training_admission_authorized=false` and
`production_causality_verified=false`. This is a contract/abstention test
fixture, **not authenticated real training data**. A separate authoritative
source identity, independent Go evaluator verification, signed provenance,
reviewer trust and immutable dataset admission must be implemented and
tested before any actual lab record is promoted or used to claim real
evaluation gains.

The negative CI cases include mutated observer bytes, changed admin bytes,
invalid diagnosis classification, changed episode/evaluation digests,
ambiguous JSON keys, duplicate output, and attempted promotion to a
model-visible positive Oracle.


## GRPO group-variance preflight (P0, no GPU)

`grpo_rollout_audit.py` audits frozen completions as complete **per-episode**
GRPO groups. Each JSONL line must have exactly `episode_id` and
`completions` (an array of precisely `--group-size` raw strings).
Every `train` episode must have exactly one complete group; test/validation
IDs, duplicate groups, missing train groups and invalid completions are rejected.

For each candidate the audit **reuses the independent Oracle reward**
(`score_completion`) rather than trusting a model-reported score. It reports
`constant_reward_groups`, `nonconstant_reward_groups`, all-correct and
all-incorrect group counts, mean reward and the fraction with nonconstant
rewards. An all-correct group with rewards `[1,1,1,1]` is not a useful
GRPO policy gradient signal; neither is `[-1,-1,-1,-1]`. A mixture of
rewards is necessary for this style of group-relative optimization, but
**not sufficient to show learning**.

Example (provide actual externally pinned SHA256 digests, not values
calculated by an untrusted rollout generator):

```bash
python scripts/audit_sre_grpo_rollouts.py \
  --dataset /path/to/episodes.jsonl \
  --rollouts /path/to/baseline-rollouts.jsonl \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-rollouts-sha256 "$PINNED_ROLLOUTS_SHA256" \
  --group-size 4 --min-signal-fraction 0.25 --require-signal
```

The `--require-signal` CLI returns exit code 3 with `UNKNOWN` on missing
or inadequate variance. The output intentionally includes
`model_runtime_verified=false`, `reward_hacking_verified_absent=false`,
`external_provenance_authenticated=false`. Synthetic or hand-written
rollouts can test the scorer, but **cannot prove the model sampled them**.
This command never trains, fetches model weights, reads Kubernetes or
authorizes an actual deployment.

**Training admission remains closed beyond lab mode.**
`train_sre_grpo.py --execute` now requires explicit `--lab-only`; the
separately named `--allow-tiny-lab` bypasses the minimum row count and
baseline-only gate for a knowingly synthetic one-episode smoke experiment.
It cannot produce an accepted training or production result. Real training
admission still requires independent data issuer authentication, an immutable
dataset provenance registry, frozen model/tokenizer/TRL versions, actual
GPU-weight-update evidence and blind holdout A/B. A file hash alone is
not reviewer authorization.


## Qwen3 raw rollout capture and independently replayed receipt (P0)

`scripts/sample_sre_grpo.py` provides the first **opt-in, CUDA-only** Qwen3
sampling entrypoint, built on the same `sre.grpo.episode/v1` train/holdout
dataset. The CPU tests inject a fake sampler to exercise the contract; they do
**not** load model weights or establish that an actual GPU sampled anything.

Capture is deliberately two distinct processes:

1. The **sampler** receives only the non-thinking, rendered user prompt.
   It does not get Oracle/split labels in its prompt or any live tool credentials.
   It samples exactly `N` completions per train episode, uses fixed
   `temperature=0.7`, `top_p=0.8`, `top_k=20`, and records the raw decoded
   output text *even when the model emits invalid JSON or whitespace*. It does
   not cherry-pick successful samples. Test/validation episodes are never
   sampled into the training baseline.
2. An **independent reviewer** pins the exact dataset/rollouts/manifest SHA256
   values out of band and runs the separate reward scorer and metadata
   consistency verifier. The capture manifest by itself is **not** proof that
   the stated model, GPU, tokenizer or environment actually generated the text.

Before running, resolve `Qwen/Qwen3-0.6B` to a specific **40-character
lowercase Hugging Face commit SHA** and pin the dataset hash *outside* the
generated files. A branch name (`main`), eight-character abbreviation or
mutable model alias is rejected. Train data remains experimental, so
`--lab-only` is mandatory. The example below is an invocation template, not
a command that was executed in the project CI.

```bash
pip install -e ".[train]"

python scripts/sample_sre_grpo.py \
  --execute --lab-only \
  --dataset /reviewed/episodes.jsonl \
  --expected-dataset-sha256 "$EXTERNALLY_PINNED_DATASET_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --num-generations 4 --max-new-tokens 192 --seed 42 \
  --output /new/capture-rollouts.jsonl \
  --manifest /new/capture-manifest.json
```

A one-episode **synthetic smoke** can explicitly add `--allow-tiny-lab`;
the flag refuses to bypass normal sample-count requirements on datasets of
eight or more train rows.

The JSONL `capture-rollouts.jsonl` conforms exactly to the existing
`audit_sre_grpo_rollouts.py` format: one group with
`{"episode_id":"...", "completions":["...", "..."]}` for every train episode.
The sibling manifest records model and tokenizer commit, dataset and rollout
SHA256, prompt content SHA256, group size/count, seeds, max output tokens,
fixed sampling parameters and explicit negative authority flags.
Both files are create-only: no appending, replacing, or publishing a partial
group. A crash between the two file writes can leave an **orphan rollout
without a valid manifest**; such orphan output must not be admitted.

The independent binding/score verification then requires **three** externally
recorded digest values:

```bash
python scripts/verify_sre_grpo_capture.py \
  --dataset /reviewed/episodes.jsonl \
  --rollouts /new/capture-rollouts.jsonl \
  --manifest /new/capture-manifest.json \
  --expected-dataset-sha256 "$EXTERNALLY_PINNED_DATASET_SHA256" \
  --expected-rollouts-sha256 "$EXTERNALLY_PINNED_ROLLOUTS_SHA256" \
  --expected-manifest-sha256 "$EXTERNALLY_PINNED_MANIFEST_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --group-size 4 --require-signal
```

The verifier independently rehashes both raw inputs and the manifest,
compares model/tokenizer revisions, group and sample counts, validates
non-promotion flags, and replays `audit_rollout_groups` on **every** train
episode. A zero-advantage group can be detected even if all decoded answers
look structurally different. `--require-signal` returns exit 3 when the
required fraction of groups has no reward variability.

**Evidence boundary:** manifest consistency is a content-binding check,
not independent verification of real Qwen3 execution, Hugging Face commit
origin, exact CUDA kernels, training gradients or model improvement.
The returned `model_runtime_independently_verified=false` and
`training_admission_authorized=false` are intentional. A real model/weights
replay, frozen dependency environment, raw token/latency traces, GPU evidence,
independent reviewer/issuer authority and true Base/SFT/GRPO blind holdout
remain separate unresolved requirements. **Do not merge this Draft PR solely
on CPU passing tests.**

Official references: [Qwen3 quickstart](https://github.com/QwenLM/Qwen3/blob/main/docs/source/getting_started/quickstart.md)
and [TRL GRPO custom reward interface](https://huggingface.co/docs/trl/v0.25.1/grpo_trainer).
