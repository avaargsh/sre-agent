# Agentic AIOps

> **Go experimental development baseline (2026-11-23):** PR #1–#10, #12 and #14–#16 are merged into `main`. The Go CLI now supports scoped Alertmanager `plan-alert`, real **read-only** Kubernetes/Prometheus `investigate-alert`, and offline `verify-alert-evidence`, along with scoped source JSON/Unicode integrity checks and isolated fault Oracles. The legacy Python Golden Incident is a separate historical demo, **not proof the Go CLI has a production remediation workflow**. See [Go rewrite plan](docs/go-rewrite-plan.md) and [SRE Golden Incident P0 acceptance plan](docs/sre-p0-golden-path.md).
>
> These are **development features**, not authenticated alert provenance, independent RCA truth, verified production recovery, or permission to modify a real cluster. #11 SFT/GRPO remains Draft and CPU-only validation does not prove GPU training. The latest merged `main` has **not** yet received a fresh fully integrated Actions run; pre-merge checks from older HEADs must not be called final-`main` certification.
>
> Read-only example: `go run ./cmd/sre-agent verify-bundle --scenario --file benchmarks/scenarios/checkout-latency.json`. `STRUCTURALLY_VALID` and `STRUCTURALLY_LINKED` attest only internal consistency, **not source authentication**.

Evidence-first Agentic incident investigation and safe remediation, with a runnable **Golden Incident v0.1** spanning Prometheus, Kubernetes, a Decision Gateway and Temporal durable approval.

## Go read-only investigation baseline

The current Go entrypoints accept original Alertmanager bytes, an operator-pinned cluster/namespace/deployment, and explicit read-only Kubernetes/Prometheus credentials. `plan-alert` produces an untrusted scoped candidate; `investigate-alert` collects a bounded v1 Evidence Bundle; `verify-alert-evidence` independently replays its structural linkage and returns `UNKNOWN` on mismatches. No part of this path approves an execution Permit or makes a production write.

## Golden Incident v0.1

```text
Load / Alert
    ↓
Prometheus + Kubernetes read-only investigation
    ↓
Immutable Evidence Bundle + SHA-256
    ↓
Decision Gateway (/decision)
    ↓
Deterministic Policy
    ↓
Temporal WAIT_APPROVAL
    │
    └── approval_resolved(approval_id)
              ↓
       Kubernetes scale 2 → 4
              ↓
       rollout readiness
              ↓
       Prometheus post-action verification
          ┌───┴────┐
       VERIFIED  rollback
              ↓
       Temporal COMPLETE
              ↓
         Evidence Refs / Replay
```

The key boundary is deliberate: **the model proposes; deterministic policy authorizes; Temporal owns durable lifecycle; the executor performs a bounded write; observability verifies whether the incident actually recovered.**

### Reproduce the demo

Create the disposable Kubernetes environment:

```bash
./scripts/setup-golden-kind.sh
```

Start the supporting Temporal / Decision services using `compose.golden.yml`, then run the incident entrypoint:

```bash
./scripts/run-live-golden-incident.sh
```

The start command returns control after the Run reaches durable approval. Query the frozen Decision for the exact pending approval ID:

```bash
python examples/live_golden_incident.py status \
  --run-id golden-checkout-live-001
```

Then approve that exact ID:

```bash
golden-approval approve \
  --run-id golden-checkout-live-001 \
  --approval-id <pending_approval_id> \
  --reason "scale checkout-api"
```

An approval for another action does not authorize this Run's frozen action.

Then continue the same Run:

```bash
python examples/live_golden_incident.py continue \
  --run-id golden-checkout-live-001
```

See `docs/golden-incident-v0.1.md` for the recording path and `docs/golden-stack.md` for the four-repository topology.

### What the recording should show

```text
[ALERT]         checkout-api latency above SLO
[INVESTIGATE]   Prometheus + Kubernetes read-only evidence
[EVIDENCE]      evidence://sha256/<bundle>
[DECISION]      execute / scale deployment/checkout-api
[GOVERN]        WAIT_APPROVAL (no Kubernetes write)
[APPROVAL]      exact frozen action approval_id approved
[ACTION]        replicas 2 -> 4; rollout ready
[VERIFY]        post-action latency <= SLO
[COMPLETE]      Temporal Run terminal; Evidence Refs attached
[REPLAY]        frozen bundle -> same decision; no live reads
```

This is the acceptance transcript, not a pre-recorded success claim: a real run must produce the corresponding states before the demo is described as end-to-end verified.

## Safety and correctness properties

- Evidence is collected before hypotheses and decisions.
- Investigation tools are read-only; write capability lives behind a separate executor.
- A model decision never bypasses deterministic authorization.
- Approval uses a stable action-bound `approval_id`; an unrelated approval cannot authorize the frozen action, and Temporal owns signal deduplication.
- Deployment `authority_digest` is frozen into evidence, decision, OperationRecord and release evidence; authority drift invalidates resume before a bounded write.
- The AIOps process does not poll while waiting for human approval.
- Successful `kubectl scale` is not treated as recovery: Prometheus must verify the post-action SLO.
- Failed verification can trigger rollback.
- Frozen Evidence Bundles support deterministic replay without querying live Prometheus/Kubernetes.

## Repository role

This repository is the **Evidence Producer + Action Orchestration** layer of the reference stack. It integrates with:

- [`agent-decision-lab`](https://github.com/avaargsh/agent-decision-lab) — synchronous Decision Plane / `/decision` boundary.
- [`cloud-agent-runtime`](https://github.com/avaargsh/cloud-agent-runtime) — Temporal-backed durable Run lifecycle and approval signals.
- [`agent-control-plane`](https://github.com/avaargsh/agent-control-plane) — AgentRelease resolution, evidence validation and release promotion gate.

Together they implement:

```text
Observe → Evidence → Decide → Govern → Durable Run → Act → Verify → Release Gate → Replay
```

M1 live software acceptance is verified on pinned public mainline commits: the fresh kind + Temporal run produces `PROMOTE`, and mutated evidence under the same authority produces `BLOCK` with `INVALID_RELEASE_EVIDENCE`. See [the frozen M1 baseline](docs/baselines/m1-public-mainline.md) for exact revisions, push CI and proof artifacts. This proves the reference software slice; it does not establish production SLOs or real GPU performance.

## Scope after v0.1

The reference slice intentionally stays narrow: Kubernetes workload degradation and bounded scale remediation. Future experiments can cover GPU/NCCL/RDMA incidents, error-budget burn and change regression without changing the control-plane boundaries demonstrated here.


## Experimental CPU-only SRE Episode / Oracle contract

The `agentic_aiops.grpo_training` and `agentic_aiops.grpo_eval` modules
provide a **read-only, pure-Python lab contract** for frozen Episodes,
private Oracle labels, evidence-gated diagnostic reward, and independent
holdout scoring. They add **no** model runtime, GPU training, Kubernetes write
permission, authenticated evidence issuer, or production release authority.

The Episode parser refuses duplicate JSON keys, invalid or non-UTF8 prompt
text, cross-split exact evidence leakage, unsupported tools, excessive JSON
nesting, and oversized files. The public holdout evaluator refuses repeated
Episode IDs (even across splits), missing/extra predictions and invalid
candidate JSON. The model prompt intentionally excludes private Oracle truth.

```bash
pytest -q tests/test_grpo_training.py tests/test_grpo_dataset_unicode.py \
  tests/test_grpo_json_nesting.py tests/test_grpo_core_holdout.py
python - <<'PY'
from agentic_aiops.grpo_training import load_episodes
from agentic_aiops.grpo_eval import load_predictions, evaluate_holdout
episodes = load_episodes("benchmarks/grpo/synthetic-episodes.jsonl")
predictions = load_predictions("benchmarks/grpo/synthetic-predictions.jsonl")
print(evaluate_holdout(episodes, predictions, split="test"))
PY
```

The synthetic fixture contains only one unanswerable holdout example.
A high score on this fixture tests the **scoring contract**, not GRPO training,
true root-cause quality, external evidence provenance, Base/SFT/GRPO superiority
or production suitability. GPU/model training, Adapter evidence and more
sophisticated holdout validation remain experimental in PR #11.

### Frozen scenario → Episode import (CPU-only)

`scripts/import_sre_episode.py` can convert one *already frozen* read-only
scenario into an Episode using a **separately reviewed** Oracle approval and
its exact SHA256 obtained out-of-band. The importer checks that approval
against the original scenario bytes, maps only approved read-only evidence,
and never imports scenario hypotheses/outcome as ground truth.

```bash
python scripts/import_sre_episode.py \
  --scenario benchmarks/scenarios/checkout-latency.json \
  --approval /reviewer-owned/approval.json \
  --expected-approval-sha256 "$REVIEWER_PINNED_APPROVAL_SHA256" \
  --output /new-output/episode.jsonl
```

The target must not exist. Publication stages complete, fsynced bytes in the
same directory and then uses an atomic no-replace hard link; interrupted
writes cannot produce a partially written final Episode path. The importer
returns only an integrity receipt with issuer and live fault-injection
verification flags set to **false**. A SHA256 pinned by the same untrusted
producer is not independent approval or authenticated source provenance.
Combining multiple imported Episodes additionally requires the core
`load_episodes` split-leakage validation. **No automatic training
admission, SRE accuracy or production authorization follows from import.**

### Offline three-way Holdout comparison (CPU-only)

`scripts/compare_sre_grpo_holdout.py` re-evaluates the **same** frozen
test/validation Episode IDs against three separately SHA256-pinned predictions
files labeled Base, SFT and GRPO. Inputs are read at most 4 MiB + 1 byte
each, hashed and decoded from the **same bytes**, and any missing/extra
prediction or cross-split alias fails closed. The report contains matched
wins/losses/ties and a descriptive paired sign-test value; it does **not**
trust a model-supplied reward or claimed accuracy.

```bash
python scripts/compare_sre_grpo_holdout.py \
  --dataset /reviewed/episodes.jsonl \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --base /captures/base.jsonl --base-sha256 "$BASE_SHA256" \
  --sft /captures/sft.jsonl --sft-sha256 "$SFT_SHA256" \
  --grpo /captures/grpo.jsonl --grpo-sha256 "$GRPO_SHA256" \
  --split test
```

All pins must come from an independent review process, not be computed
from an untrusted candidate at admission time. These role labels and pinned
bytes **do not** authenticate the actual model, checkpoint, training step,
data issuer, or captured inference runtime. The report always keeps
`superiority_claim_authorized=false` and `production_eligible=false`.
Evidence-chain attribution and actual GPU training remain unmerged in #11.

### Oracle-free Holdout projection and independent replay (CPU-only)

The data owner can project a **frozen, externally SHA-pinned** validation/test
Episode dataset into a distinct `episode_id, prompt` JSONL file. The private
Oracle, split, fault family and original dataset are not passed to the model
runner. The projection manifest binds the original dataset SHA256, exact
projected bytes, selected split and case count. Output uses staged fsynced
files and no-replace links; it is **not** an atomic two-file transaction, so
an interruption can leave an orphan prompts file with no valid manifest.

```bash
python scripts/project_sre_grpo_holdout.py \
  --dataset /reviewer/episodes.jsonl \
  --expected-dataset-sha256 "$REVIEWER_DATASET_SHA256" \
  --split test --output /new/path/prompts.jsonl \
  --manifest /new/path/projection.json

python scripts/verify_sre_grpo_projection.py \
  --dataset /reviewer/episodes.jsonl \
  --prompts /new/path/prompts.jsonl \
  --manifest /new/path/projection.json \
  --expected-dataset-sha256 "$REVIEWER_DATASET_SHA256" \
  --expected-prompts-sha256 "$REVIEWER_PROMPTS_SHA256" \
  --expected-manifest-sha256 "$REVIEWER_MANIFEST_SHA256"
```

The independent verifier reads the **original pinned Episode bytes**, rebuilds
the exact Oracle-free prompts, checks the projection file byte-for-byte and
validates every manifest field with exact JSON type matching. It refuses
missing, rehashed-but-tampered, oversized or symlinked artifacts. The required
external SHA pins do **not** authenticate the issuing data owner or model.

This is a CPU-only input-projection contract; it does not sample a model,
authenticate checkpoints, establish real SRE diagnostic improvement or grant
production remediation permission. The Draft #11 five-file model capture and
Adapter chain remain separate and **unmerged**.

### Base-only five-file Holdout content-chain audit (CPU-only)

`scripts/verify_sre_grpo_base_holdout.py` independently checks a five-file
sequence: **frozen private Episode dataset → Oracle-free projected prompts →
projection manifest → raw candidate predictions → Base capture manifest**.
It uses the exact three-file replay already in main, plus four-megabyte
bounded prediction reads and a 32 KiB capture-manifest cap. Every artifact
must be a different, regular non-symlink file with an externally approved
SHA256. A changed or re-pinned prediction must still match **every** projected
Episode ID **in the original order**. Capture metadata must use exact
`sre.grpo.holdout-capture/v1` Base-only fields and strict JSON types; Adapter
receipts and any claimed training/production authorization are rejected.

```bash
python scripts/verify_sre_grpo_base_holdout.py \
  --dataset /review/episodes.jsonl \
  --prompts /frozen/prompts.jsonl \
  --projection-manifest /frozen/projection.json \
  --predictions /frozen/base-predictions.jsonl \
  --capture-manifest /frozen/base-capture.json \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --expected-prompts-sha256 "$PROMPTS_SHA256" \
  --expected-projection-manifest-sha256 "$PROJECTION_MANIFEST_SHA256" \
  --expected-predictions-sha256 "$PREDICTIONS_SHA256" \
  --expected-capture-manifest-sha256 "$CAPTURE_MANIFEST_SHA256" \
  --model Qwen/Qwen3-0.6B --revision "$PINNED_40_HEX_COMMIT"
```

This verifies **content consistency only**. In particular, the
`prompt_sha256` for tokenizer-rendered model input is format-checked but
cannot be independently reconstructed from these five files alone. The
reported model name/revision, run identity, source publisher and sampler
are **not authenticated**. The audit always reports
`model_attribution_verified=false`, `data_issuer_authenticated=false`
and `production_eligible=false`. No GPU/model sampling, Adapter/LoRA
verification or write-capable SRE remediation is performed here.

### Base Qwen3 Holdout capture (LAB-only, GPU required)

After publishing an externally pinned Oracle-free projection, run the
isolated **Base-only** inference CLI. It takes only the projected prompts
file: it cannot read the private Episode or Oracle. GPU and Transformers
imports occur **only after** bounded file, SHA, revision, split and
create-only output path checks have passed.

```bash
python scripts/sample_sre_grpo_base_holdout.py \
  --execute --lab-only \
  --prompts /frozen/prompts.jsonl \
  --expected-prompts-sha256 "$REVIEWER_PROMPTS_SHA256" \
  --model Qwen/Qwen3-0.6B \
  --revision "$PINNED_40_HEX_MODEL_REVISION" \
  --output /new/path/base-predictions.jsonl \
  --manifest /new/path/base-capture.json
```

Both `--execute` and `--lab-only` are mandatory. The CLI never silently
falls back to a CPU model. No SFT/GRPO Adapter, arbitrary model repository,
train split, mutable revision alias or writable SRE tool is accepted.
Outputs preserve invalid raw candidate responses and are published via
staged/fsynced create-only hard links. An abrupt kill between links can
leave an orphan predictions file; the five-file verifier must reject it
if the capture manifest is missing or mismatched.

The independent reviewer must run the **Base five-file auditor** with
separately frozen SHA256 pins. Passing checks proves content consistency
only: tokenizer-rendered prompt bytes, actual CUDA/model execution,
checkpoint identity and source issuer **are not independently attested**.
The receipt intentionally keeps `model_runtime_verified=false`,
`model_attribution_verified=false`, `production_eligible=false` and
`superiority_claim_authorized=false`. The CPU tests are not a GPU run.
## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

For cross-repository integration, [four-repo-acceptance](.github/workflows/four-repo-acceptance.yml) verifies pinned public Control Plane, Runtime and Decision commits from this repository's main push CI on disposable kind + Temporal infrastructure.

The dependency revisions are owned by the machine-readable [stack.lock.json](stack.lock.json), not duplicated inside workflow YAML. Validate the lock locally with:

```bash
make stack-lock-check
# or, after installation
agent-stack-lock stack.lock.json
```

A stack change is therefore an explicit reviewable dependency update. CI fails closed if a required repository is renamed, a revision is not a full commit SHA, or the positive/negative release-gate contract is changed accidentally.

## Contributing and license

Contributions are welcome through focused issues and pull requests. See `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.

Licensed under Apache License 2.0. See `LICENSE`.
