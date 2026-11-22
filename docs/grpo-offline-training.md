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
  --model-revision "$PINNED_QWEN3_COMMIT_SHA40" \
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
 

## Exact-byte Oracle and crash-safe capture publication (P0 hardening)

The capture preflight and offline reward audit now read each input dataset
**once** for its SHA256 check and parse `load_episodes_bytes(raw)` from those
same verified bytes. The previous two-read path admitted a local TOCTOU
risk: when a dataset is mutable between reads, one version might be checked
but another version consumed as trusted Oracle. The regression tests verify
that the pin-to-parse path never reopens the dataset. This protects against
that local consistency bug, **not** against a malicious host or a false
independent source digest.

Raw Rollout and Capture Manifest publication now stages complete bounded
payloads under distinct random `.sre-grpo-*.stage` paths in the same output
directories, fsyncs each unpublished file, and creates the two final paths
with **hard links that fail if a competing writer already created the name**.
The temporary stage paths are removed after publication. If publication of
the second final path fails, the first final path is removed only when it
still points to this invocation's own staged inode. Tests inject an exception
after a partial stage write and race a competing writer for both destination
names. No truncated file is published at its final pathname, and competing
files are not overwritten.

There is **no multi-file atomic transaction** here. SIGKILL/power loss
between the two hard links can leave an orphan `rollouts.jsonl` without
a valid corresponding manifest. An orphan must be rejected by the
independent verifier, rather than silently resumed or declared complete.
The staging/hard-link method requires filesystem support for hard links,
and this implementation does not fsync the parent directory: power-loss
durability and adversarial shared-filesystem race freedom remain
**unverified**. A production artifact registry would instead need immutable
content-addressed uploads, signed publication receipts, and independently
authorized admission.

## P0 remaining acceptance

1. Run the pinned `Qwen3-0.6B` sampler on an actual CUDA device with
   frozen dependencies and trusted weights. Archive model/tokenizer revision,
   GPU information and original raw output bytes.
2. Have a distinct reviewer independently pin dataset, rollout and manifest
   bytes; audit complete train groups without using self-scored rewards.
3. Replay a disposable-kind G2i incident with a separately authenticated
   source/Oracle and approved read-only observer receipts.
4. Only then test actual GRPO parameter/LoRA updates and blind holdout
   comparison against matching Base/SFT baselines.


## Local LoRA optimizer-delta gate (P0, requires actual CUDA for execution)

The real `scripts/train_sre_grpo.py --execute` path now refuses to use a
mutable Qwen3 model alias. Model **and** tokenizer are loaded from the exact
same full lowercase 40-hex commit (`--model-revision`, required), using
`trust_remote_code=False`. Training runs are **lab-only**, single-process,
bounded to 1–100 optimizer steps, and require a **new output directory** so
a prior experiment cannot be overwritten or reused.

`freeze_train_dataset` hashes and parses one immutable in-memory copy of
the JSONL bytes. In inspection mode `--expected-dataset-sha256` is optional,
but if supplied it is checked; in non-tiny executable mode the external
dataset and baseline-rollout SHA256 pins are both mandatory. Tiny synthetic
smokes may also opt into a supplied pinned digest.

Before optimizer training, `snapshot_lora_parameters` enumerates only
trainable LoRA adapter parameters and hashes the raw tensor bits (including
BF16, via `torch.uint8` reinterpretation), parameter names, shapes/dtypes
and element counts. Any unexpected **non-LoRA trainable tensor** is rejected.
After `trainer.train()`, the same snapshot is collected, and
`verify_local_lora_update` requires: a positive, bounded
`trainer.state.global_step`, identical parameter names/layout, and an
actual difference in the before/after tensor fingerprints.

An unchanged adapter after a nominally successful trainer return **fails
closed before `trainer.save_model()`**, rather than recording a successful
train run. The pre-run `sre-grpo-run-manifest.json` is create-only and
retains status `started_not_verified`. When a local delta was observed,
the saved model is accompanied by a distinct create-only
`sre-grpo-local-lora-delta.json` with the exact dataset/model revisions,
before/after digest records and the explicitly negative independent-provenance
flags.

These receipts establish only that local code observed LoRA tensor changes.
They do **not** prove the training run is independent, that real GPU hardware
was used, that the loss improved, that the weights are benign, that the
training dataset was authorized, or that the model improved on blind holdout.
A fake trainer/parameter is used in CPU CI to verify wiring and the
unmodified-weight rejection path. A real pinned CUDA run and independent
weights/optimizer audit remain required.

Only `Qwen/Qwen3-*` repository model IDs are supported by the opt-in
experiment, not arbitrary local paths or mutable branch aliases. The declared
`.[train]` dependencies remain version ranges rather than a frozen lockfile.
Consult the installed pinned TRL and Transformers API before relying on
weight-loading compatibility; passing CPU CI alone does not guarantee a
live CUDA integration is functional.


## P0: three-way paired holdout comparison (Base vs SFT vs GRPO)

The new `scripts/compare_sre_grpo_holdout.py` runs **offline**, imports
no model or GPU library, and recomputes the independent Oracle-based
diagnostic score for **the exact same held-out Episode IDs** across
Base/SFT/GRPO. All four files must be **different paths**, and the dataset
and each of the three raw prediction files require separately supplied,
exact lowercase SHA256 pins. A holdout with more than 2048 cases is refused.
No train/validation contamination, missing cases, duplicate JSON keys,
unrecognized fields or partial prediction sets are accepted.

Each model predictions JSONL file has exactly one record per chosen holdout
Episode, with fields `episode_id` and `completion`, containing the **raw
model text**, not model-owned scores:

```json
{"episode_id":"test-001","completion":"{\"root_cause_id\":\"unknown\",\"evidence_ids\":[],\"stop_reason\":\"insufficient_evidence\"}"}
```

Use independent external pins obtained from a separate reviewer or immutable
artifact store, not a digest copied from the same untrusted model-generated
manifest:

```bash
python scripts/compare_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --expected-dataset-sha256 "$EXTERNALLY_PINNED_DATASET_SHA256" \
  --base /artifacts/base-test.jsonl --base-sha256 "$PINNED_BASE_SHA256" \
  --sft /artifacts/sft-test.jsonl --sft-sha256 "$PINNED_SFT_SHA256" \
  --grpo /artifacts/grpo-test.jsonl --grpo-sha256 "$PINNED_GRPO_SHA256" \
  --split test
```

The JSON response provides the exact set size, each model's
`exact_successes`, `exact_success_rate`, `mean_reward`,
`correct_abstention_rate`, and the paired success transitions
`GRPO_vs_Base`, `GRPO_vs_SFT`, `SFT_vs_Base`: win/loss,
both-correct/both-incorrect ties, discordant case count, percentage-point
success-rate delta, and exact **two-sided sign-test p-value** (descriptive
only). The scorer uses exactly the frozen Oracle and rejects model-supplied
scores/tool counts. It intentionally does not disclose raw answers or Oracle
labels in aggregate stdout.

**Comparison does not establish model identity or causality.** Naming files
Base/SFT/GRPO does not prove those models generated them. SHA256 checks
content against provided digests, not a trusted signer, a live model
execution, an unbiased train/test split or non-duplicated semantic cases.
An accuracy delta or small-sample p-value alone is **not** authorization to
claim that GRPO improved real-world diagnosis. Every report explicitly sets
`model_runtime_verified=false`,
`model_attribution_verified=false`,
`data_issuer_authenticated=false`,
`superiority_claim_authorized=false` and
`production_eligible=false`. Keep reporting the sample size, confidence
limitations, negative cases, and any source-selection caveats.

The older `scripts/eval_sre_grpo.py` remains compatible with prior
synthetic fixtures, but now reads datasets/predictions exactly once and
supports `--expected-dataset-sha256` and
`--expected-predictions-sha256`. Pin both to avoid untrusted file
replacement between hashing and scoring. A missing external pin keeps
that legacy run self-consistent but **not externally authenticated**.

**Remaining gate:** separate signed runner/model/weight revision receipts
for Base, SFT and GRPO; actual CUDA inference and GRPO update evidence;
independent review of experiment design and blind holdout provenance;
repeat-seed statistical comparisons; and real, independently verified G2i
fault-injection scenarios. Until then, these are regression-contract tests,
not performance claims.


## P0: Oracle-free holdout inference, content-chain verification (2026-11-23)

The three-way comparison CLI previously accepted frozen prediction JSONL files,
but it did not provide an isolated way to *produce* them. This patch adds
**separate data-owner and inference-process inputs**, plus an independent
five-artifact content audit. It remains **lab-only**, and no real Qwen3 GPU
inference was executed in the CPU CI.

**Data owner / verifier side:** pin the full Episode dataset and project only
the requested test/validation split into a separate, read-only JSONL of
`episode_id` + `prompt`. The private Oracle stays in the source dataset.
The projection never copies the `oracle`, `split` or `fault_family`
fields into a model input record; the sampler does not receive them.

```bash
python scripts/project_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --split test \
  --output /exports/test-prompts.jsonl \
  --manifest /exports/test-projection.json
```

**Isolated Qwen3 runner:** transfer only `test-prompts.jsonl` and its exact
externally pinned hash to the GPU machine. **Do not mount the original
Oracle dataset into the model runner.** Supply an immutable, full 40-hex
Hugging Face commit for the model and tokenizer. This greedy, non-thinking
sampler generates **one** raw answer for **every** holdout Episode and keeps
invalid JSON/empty/incorrect outputs instead of dropping hard cases.

```bash
python scripts/sample_sre_grpo_holdout.py \
  --execute --lab-only \
  --prompts /readonly/test-prompts.jsonl \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --output /artifacts/base-predictions.jsonl \
  --manifest /artifacts/base-capture.json \
  --split test --seed 42 --max-new-tokens 192
```

The runner supports a full 40-character pinned **Qwen/Qwen3-*** base
checkpoint. It also supports *local* PEFT LoRA adapters as experimental
SFT/GRPO variants when explicitly requested with `--checkpoint-role` and
separate externally pinned adapter SHA256 values, as detailed below. Never
label the same Base checkpoint as SFT/GRPO or infer model identity from
a filename; role is still a **self-declared experimental label**, not an
authenticated weight provenance receipt.

**Independent audit:** an auditor with access to the original pinned dataset
and to all projected and captured files recomputes every prompt using the
Oracle-independent prompt builder, checks the exact Episode order/coverage,
validates all five externally pinned SHA256 digests, rejects fabricated
authority flags, and checks that the capture's model/tokenizer revision,
prompt hash format, output hash, split, decoding config and counts agree.

```bash
python scripts/verify_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --prompts /readonly/test-prompts.jsonl \
  --projection-manifest /exports/test-projection.json \
  --predictions /artifacts/base-predictions.jsonl \
  --capture-manifest /artifacts/base-capture.json \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --expected-projection-manifest-sha256 "$PINNED_PROJECTION_MANIFEST_SHA256" \
  --expected-predictions-sha256 "$PINNED_BASE_SHA256" \
  --expected-capture-manifest-sha256 "$PINNED_BASE_CAPTURE_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" --split test
```

Repeat capture plus independent verification for **each** model checkpoint,
then use `scripts/compare_sre_grpo_holdout.py` with all three exact pinned
prediction JSONL files. The comparison's `model_attribution_verified=false`
remains correct even when content-chain audit passes: raw hashes and
self-reported model IDs do not prove the runtime loaded those weights.
The independent verifier cannot attest host security or control which
files were mounted during the model process; isolation must be enforced
and evidenced by an external operator or trusted sandbox.

**Failure boundaries:** all files are bounded, create-only, and published
using same-directory staged/fsynced writes and no-replace hard links. A
process termination between two final hard-link publications may leave an
orphan JSONL without its companion manifest; such incomplete evidence is
not eligible for a passed chain audit. Directory fsync/power-loss
durability, signed source-provenance, weight attestation, actual GPU
sampling, local LoRA checkpoint inference and blinded multi-seed outcomes
are explicitly **not yet verified**. Passing CPU tests only verifies
the contracts using injected fake tokenizers and samplers.


## P0: SHA-pinned local LoRA adapter for SFT / GRPO Holdout

A Base run defaults to `--checkpoint-role Base` and **refuses** adapter
arguments. SFT/GRPO runs must specify `--checkpoint-role SFT` or `GRPO`
together with an explicit local Adapter directory and **two external SHA256
pins**. The runner does not fetch adapter weights from a mutable Hub ID.
It accepts only the narrow single-file, PEFT-compatible structure:

- `adapter_config.json` (bounded JSON; `peft_type=LORA`,
  `task_type=CAUSAL_LM`, base model ID equal to the pinned Qwen3 model;
  a non-null config `revision` must equal the pinned base commit).
- `adapter_model.safetensors` (bounded, self-describing Safetensors header
  with LoRA A/B pairs and contiguous tensor offsets).
- Optional `README.md` is ignored. Unexpected executable/module files,
  pickle `.bin` weights, symlinks, `auto_mapping`, `modules_to_save`,
  non-LoRA tensor keys and unusual LoRA layer settings are rejected.

The Adapter **configuration bytes and tensor bytes are read only once and
checked against independently provided SHA256 values before loading Torch,
Transformers or PEFT**. A private temporary directory containing *only*
these verified bytes is given to `PeftModel.from_pretrained`, with
`is_trainable=False` and `local_files_only=True`. This prevents changing
the original Adapter file after the hash from silently changing what PEFT
loads. It does **not** authenticate the local host, attest the PEFT runtime
or guarantee the expected weights were applied by a hostile process.

For a GRPO checkpoint saved by the training script, obtain the digests from
the independent reviewer (or immutable artifact registry), then invoke:

```bash
python scripts/sample_sre_grpo_holdout.py \
  --execute --lab-only --checkpoint-role GRPO \
  --prompts /readonly/test-prompts.jsonl \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --adapter-dir /reviewed/grpo-adapter \
  --expected-adapter-config-sha256 "$PINNED_ADAPTER_CONFIG_SHA256" \
  --expected-adapter-weights-sha256 "$PINNED_ADAPTER_WEIGHTS_SHA256" \
  --output /artifacts/grpo-predictions.jsonl \
  --manifest /artifacts/grpo-capture.json
```

Use role `SFT` and a **different pinned adapter and output files** to
produce the SFT lane. Both adapted runs publish a
`sre.grpo.holdout-capture/v2` manifest with the same pinned base commit,
explicit `checkpoint_role`, and an embedded
`sre.grpo.pinned-lora-adapter/v1` receipt containing config and weight
SHA256 hashes. The Base lane retains capture schema v1 for compatibility.

```bash
python scripts/verify_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --prompts /readonly/test-prompts.jsonl \
  --projection-manifest /exports/test-projection.json \
  --predictions /artifacts/grpo-predictions.jsonl \
  --capture-manifest /artifacts/grpo-capture.json \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --expected-projection-manifest-sha256 "$PINNED_PROJECTION_MANIFEST_SHA256" \
  --expected-predictions-sha256 "$PINNED_GRPO_PREDICTIONS_SHA256" \
  --expected-capture-manifest-sha256 "$PINNED_GRPO_CAPTURE_SHA256" \
  --checkpoint-role GRPO \
  --expected-adapter-config-sha256 "$PINNED_ADAPTER_CONFIG_SHA256" \
  --expected-adapter-weights-sha256 "$PINNED_ADAPTER_WEIGHTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40"
```

The verifier binds the v2 capture to the externally pinned Adapter hashes
and requires negative provenance flags. It does not directly receive or
reopen Adapter weight files; the independent Artifact owner must establish
their hash identity. A model-produced manifest cannot promote
`model_runtime_verified`, `model_attribution_verified`,
`superiority_claim_authorized` or `production_eligible` to true.

**CI evidence boundary:** unit tests construct tiny synthetic Safetensors,
and fake Torch/Transformers/PEFT callbacks exercise the real CLI load
wiring. They are *not* a real GPU runtime compatibility test; version ranges
in `.[train]` are not hash-locked, and no real-world diagnosis improvement
or independently authenticated model source is asserted.

Official PEFT references: https://huggingface.co/docs/peft/v0.17.0/en/package_reference/peft_model
and https://huggingface.co/docs/peft/v0.17.0/en/tutorial/peft_model_config .


## P0: loaded LoRA **tensor-bit** admission gate (2026-11-23)

The pinned Adapter loader now adds a **post-PEFT-load check** before any
Holdout generation. The previous path verified that
`PeftModel.from_pretrained()` was called, but a mistaken runtime loader
could still return the Base model with missing, inactive, merged or
incorrectly loaded LoRA tensors. A successful Python function return is
not proof that the intended Adapter was applied.

For SFT/GRPO runs, the CUDA runner now:

1. Calls `PeftModel.from_pretrained(..., is_trainable=False,
   local_files_only=True, autocast_adapter_dtype=False)`. Disabling
   automatic promotion of FP16/BF16 LoRA tensors to FP32 preserves the
   checkpoint tensor dtype for the subsequent byte-exact check.
2. Calls the supported `peft.get_peft_model_state_dict(model,
   adapter_name="default", save_embedding_layers=False)` to read the
   actually loaded PEFT parameters under their saved checkpoint keys.
3. Obtains `peft.get_model_status(model)` and requires exactly one active
   `default` LoRA Adapter, enabled and unmerged, with no trainable
   parameters in inference mode and at least one Adapter layer.
4. Compares the **entire exported parameter set**, each key, tensor shape,
   dtype and exact contiguous raw bytes against the originally pinned,
   independently SHA-checked Safetensors payload. Any omission, extra
   tensor, stale/wrong bytes, unexpected type conversion or disabled
   Adapter aborts before the first prompt is sent to the sampler. No
   predictions or capture manifest are published on these errors.

The gate is implemented in
`agentic_aiops.grpo_adapter.verify_loaded_adapter_weights`.
Its internal local result intentionally remains
`model_runtime_independently_verified=false`,
`model_attribution_verified=false` and
`production_eligible=false`. It is a same-process defensive validation
against silent Adapter no-op, not a cryptographic attestation of GPU
execution. A compromised interpreter, malicious shared filesystem or
changed PEFT source can still fake self-reported state.

**Tests:** `test_grpo_adapter_postload.py` injects missing/extra LoRA
tensors, wrong tensor bytes, wrong dtype/shape, inactive or merged LoRA
and falsely trainable state, and requires fail-closed behavior. The
end-to-end CPU fake loader tests also simulate `from_pretrained`
returning a model while its exported LoRA state is empty: the runner
must refuse sampling and leave no final prediction/manifest file.
These tests do not import actual GPU weights.

This mirrors the published PEFT checkpoint API semantics: saving strips
the adapter name from the state_dict keys, and the
`autocast_adapter_dtype` option defaults to true. The exact current
package release remains **unlocked** in `pyproject.toml`, so a real
version-pinned CUDA/PEFT smoke run is still required:
https://huggingface.co/docs/peft/v0.17.0/package_reference/peft_model
and https://huggingface.co/docs/peft/developer_guides/checkpoint .


## P0: local forward-effect smoke probe, capture v3 (2026-11-23)

**Loaded tensors != applied behavior.** After the pinned LoRA bytes, key
names, dtype and PEFT activation status are verified, SFT/GRPO inference
now performs one **fixed, Oracle-free** short forward probe before the
first Holdout completion. This is a deliberately conservative LAB gate.

The runner feeds the exact same non-thinking probe tokens to the same
evaluation-mode model with PEFT enabled and inside the public PEFT
`model.disable_adapter()` context. It checks both last-token Logits
vectors are finite and have matching bounded vocabulary dimensions, then
measures:

`normalized_logit_delta = max(abs(enabled_logits - disabled_logits))
/ max(1.0, max(abs(disabled_logits)))`

A nonfinite vector or normalized change **not greater than 1e-5** fails
closed without publishing any Holdout predictions. The small threshold
is a LAB heuristic, not an accuracy metric or universally calibrated
numerical tolerance: an adapted model can produce a meaningful but
subthreshold effect on this particular probe, so a failure is **UNKNOWN**,
not proof the Adapter is invalid. The fixed probe is not a substitute for
randomized inference, holdout cases, quality evaluation or independent
model attribution.

**PEFT lifecycle:** the public `disable_adapter()` implementation can
alter `requires_grad` on reenable for some PEFT versions. The runner
re-reads `get_model_status` after the context and refuses a changed,
disabled, merged or unexpectedly trainable Adapter before sampling.
This intentionally fails closed when dependency behavior is unsafe.
See https://github.com/huggingface/peft/issues/3447 for the reported
trainability regression; freeze and independently test a known-good
dependency set on a real CUDA host before using this path operationally.

When an adapted runner passes both the exact loaded-weight check and
the local forward probe, its create-only capture upgrades from v2 to
`sre.grpo.holdout-capture/v3` and includes
`local_effect_probe` with the probe prompt SHA256, finite last-token
delta measurements and negative provenance/production flags. The
independent audit can validate this **self-reported** record's bounded,
internally consistent numbers, negative authority flags and capture
SHA256 binding. It cannot independently prove the GPU executed those
forward passes.

An independent reviewer can refuse legacy v2 captures:

```bash
python scripts/verify_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --prompts /readonly/test-prompts.jsonl \
  --projection-manifest /exports/test-projection.json \
  --predictions /artifacts/grpo-predictions.jsonl \
  --capture-manifest /artifacts/grpo-capture.json \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --expected-projection-manifest-sha256 "$PINNED_PROJECTION_MANIFEST_SHA256" \
  --expected-predictions-sha256 "$PINNED_GRPO_PREDICTIONS_SHA256" \
  --expected-capture-manifest-sha256 "$PINNED_GRPO_CAPTURE_SHA256" \
  --checkpoint-role GRPO \
  --expected-adapter-config-sha256 "$PINNED_ADAPTER_CONFIG_SHA256" \
  --expected-adapter-weights-sha256 "$PINNED_ADAPTER_WEIGHTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --require-local-effect-probe
```

Base capture remains v1; offline synthetic/legacy Adapter capture v2
remains readable, but `--require-local-effect-probe` rejects it.
CPU-only unit tests include both a fake PEFT forward that changes its
Logits and a fake active Adapter with matching weights that produces
identical base/adapter Logits: the second must abort before the sampler.
There is **no real CUDA/PEFT or SFT/GRPO model-quality evidence yet**.


## P0: A-B-A restored LoRA forward consistency (2026-11-23)

**Two forward passes are not a reliable causal test by themselves.**
The earlier LoRA A/B probe compared Adapter enabled logits against
disabled logits for one fixed Oracle-free prompt. Nondeterministic
runtime drift, unexpected PEFT adapter lifecycle changes or a
broken enable/disable transition could mimic an Adapter effect.

The adapted Qwen3 holdout runner now executes three bounded, last-token
forward observations on **identical** prompt tokens in eval/inference mode:

1. **A1:** Adapter enabled; record original Logits.
2. **B:** Adapter disabled via PEFT's context manager; record Base Logits.
3. **A2:** Adapter re-enabled; record Logits again and recheck PEFT status.

The LAB admission heuristic requires both a normalized A1-vs-B effect
**greater than 1e-5**, and a normalized A1-vs-A2 restoration drift
**no greater than 1e-5**. Both use the same denominator
`max(1.0, max(abs(B_logits)))`. All three Logits vectors must be
finite, exactly shape-compatible and from a bounded vocabulary. The
Adapter must remain enabled, unmerged and non-trainable after A2.
Any failure occurs **before sampling any Holdout Episode** and leaves
no prediction/manifest artifact. The thresholds are conservative lab
heuristics, not proven CUDA numerical tolerances: a legitimate but
subthreshold/small LoRA effect or nondeterministic GPU kernel may
cause an UNKNOWN rejection.

**Versioned, non-promoting receipts:** successful local A-B-A runs use
`sre.grpo.local-adapter-effect/v2` inside
`sre.grpo.holdout-capture/v4`. The v2 receipt includes the original
A1-vs-B delta plus the A1-vs-A2 restoration delta, the threshold and
the `forward_reenable_consistent` value. It continues to say
`model_runtime_independently_verified=false`,
`model_attribution_verified=false`, and
`production_eligible=false`. The independent verifier recomputes
the numerical ratios from these **self-reported** metrics; it cannot
independently replay or attest the real GPU forward pass.

An auditor can reject all legacy v2/v3 adapter captures by adding:

```bash
# Along with all five external file SHA256 pins and the two adapter pins:
python scripts/verify_sre_grpo_holdout.py ... \
  --checkpoint-role GRPO \
  --require-reenable-probe
```

Base v1, Adapter v2 and A/B-only Adapter v3 remain parseable for
historical replay without this stronger gate; `--require-local-effect-probe`
still accepts v3 or v4. `--require-reenable-probe` explicitly requires
v4 and an internally consistent A-B-A receipt.

**CPU-only regression evidence:** A-B-A fixtures test realistic-looking
A1/B differences followed by an A2 drift, identical A1/A2 restoration,
nonfinite re-enabled Logits, malformed metrics, false authority claims,
legacy version compatibility and a fake PEFT inference runner with
drifting re-enabled Logits. These do **not** establish actual Qwen3
CUDA/PEFT reproducibility, model provenance or diagnostic advantage.


## P0 CPU-only PEFT config ↔ Safetensors matrix admission

A successful raw SHA256 check and structurally valid Safetensors header do
**not** establish that a LoRA checkpoint is compatible with its PEFT
configuration. Earlier validation only required LoRA A/B keys to be present.
A malformed but correctly hashed file could declare `q_proj` and rank 2 while
containing `k_proj` weights, rank 3 matrices, 3D tensor shapes, incompatible
A/B dtypes, or duplicate PEFT `.default` variants of the same tensor slot.

`grpo_adapter.load_pinned_adapter` now validates all of the following
**before loading any Torch/CUDA dependency**:

- Each tensor target suffix belongs to `target_modules`; every declared
  target module must appear in the single-file Adapter.
- Each A/B tensor is a 2D matrix. `lora_A` has shape
  `[r, in_features]`, and `lora_B` has shape
  `[out_features, r]`. The two rank dimensions must match the
  checked `adapter_config.json:r` value.
- A/B pairs for a given module have the same supported data type, and
  each semantic tensor slot is unique even when the JSON has distinct keys
  such as `lora_A.weight` and `lora_A.default.weight`.
- Corrupt header values (including non-string dtypes) produce controlled
  `ValueError` rejection instead of an uncaught `TypeError`.
  Existing header offset/coverage, tensor-count, size, unsafe PEFT
  configuration and source-byte SHA checks continue to apply.

CPU regression fixtures now use *self-consistent* 2×2 LoRA A/B tensors with
rank 2 and `target_modules=["q_proj"]`. Additional adversarial fixtures
prove that wrong modules, mismatched rank, malformed matrix shape, A/B dtype
mismatch and duplicate semantic slots are rejected despite correctly
recomputed file SHA256 values.

**Scope:** this is a narrow structural admission policy for the supported
Qwen3 q/v projection PEFT configurations. It deliberately rejects unusual
yet potentially valid Adapter formats; those need an explicit format
extension and independent test cases. It does **not** prove weight
provenance, actual PEFT/CUDA compatibility or SRE diagnostic improvement.


## P0: independent CPU-only adapter **physical artifact** audit (2026-11-23)

The existing five-file Holdout audit previously compared the Capture
receipt's `adapter_config_sha256` and `adapter_weights_sha256` to
externally supplied expected digests. It **did not reopen the actual
Adapter files**. If a malicious or mistaken Capture contained a
well-formed but fabricated `target_modules`, `lora_modules`, tensor
count or PEFT rank claim, metadata-only verification could not prove
that claim matched the files which a runner would attempt to load.

The independent verifier now accepts a **physical adapter directory** for
SFT/GRPO. In strict mode, it refuses a missing directory. It reads
`adapter_config.json` and `adapter_model.safetensors` itself (each file
once), recomputes SHA256 against separately supplied reviewer pins,
parses the exact verified bytes and rechecks the safe LoRA configuration,
base Qwen3 model/revision, tensor count, target suffix allowlist, rank,
A/B matrix shape/dtype/pairs, and Safetensors contiguous offsets. It
then compares its **own fully reconstructed Adapter receipt** against
the Capture's untrusted receipt. A digest-consistent yet forged metadata
field, changed physical file, rehashed but incompatible configuration,
unexpected sidecar or symlink **fails closed**.

For a GRPO Holdout v4 Capture, keep all five external dataset/manifest/
prediction digests and add two Adapter digests, physical path and flags:

```bash
python scripts/verify_sre_grpo_holdout.py \
  --dataset /trusted/episodes.jsonl \
  --prompts /readonly/test-prompts.jsonl \
  --projection-manifest /exports/test-projection.json \
  --predictions /artifacts/grpo-predictions.jsonl \
  --capture-manifest /artifacts/grpo-capture.json \
  --expected-dataset-sha256 "$PINNED_DATASET_SHA256" \
  --expected-prompts-sha256 "$PINNED_PROMPTS_SHA256" \
  --expected-projection-manifest-sha256 "$PINNED_PROJECTION_MANIFEST_SHA256" \
  --expected-predictions-sha256 "$PINNED_GRPO_PREDICTIONS_SHA256" \
  --expected-capture-manifest-sha256 "$PINNED_GRPO_CAPTURE_SHA256" \
  --checkpoint-role GRPO \
  --adapter-dir /reviewer-owned/grpo-adapter \
  --expected-adapter-config-sha256 "$PINNED_ADAPTER_CONFIG_SHA256" \
  --expected-adapter-weights-sha256 "$PINNED_ADAPTER_WEIGHTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_QWEN3_COMMIT_SHA40" \
  --require-adapter-files \
  --require-reenable-probe
```

The report adds `adapter_files_content_verified=true` and
`adapter_metadata_matches_files=true` only after this physical
verification. Metadata-only legacy audits return both **false**; when
`--require-adapter-files` is set, absence of physical files is an error.
Base captures reject any Adapter directory or strict Adapter requirement.

The auditor runs on CPU with the Python standard library; it does
**not** import Torch, Transformers, PEFT or access CUDA. Adversarial
tests include mutated config/weight files, rehashed metadata forgeries,
rehashed but impossible LoRA rank, symlink substitutions, omitted
files, Base misuse, and one-read-per-file checks.

**Trust boundary:** SHA256 verifies bytes against an externally
provided digest; it does not establish who issued that digest or that
the same bytes executed on the GPU. Reviewer pins must originate from
outside the potentially untrusted model-producing process, ideally a
controlled immutable artifact store. `model_runtime_verified`,
`model_attribution_verified`, `superiority_claim_authorized` and
`production_eligible` remain **false**. Do not merge the Draft based
only on this CPU-only consistency result.
