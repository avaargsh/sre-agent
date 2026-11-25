# Agentic AIOps

> **Go experimental development baseline (2026-11-24, main@4a336e0):** The Go CLI supports scoped Alertmanager `plan-alert`, **read-only** Kubernetes/Prometheus `investigate-alert`, offline `verify-alert-evidence`, SLI and fault Oracles, RCA human-review policy verification, and laboratory-only signed evidence controls. PRs #104–#106 hardened native JSON field admission across Observer, SLI and Service/EndpointSlice Oracles; case-insensitive aliases are checked against typed schemas while case-sensitive map keys and opaque `json.RawMessage` remain data. These are independently integrated development features, not an end-to-end production-approved Go SRE Agent. The legacy Python Golden Incident is a separate historical demo, **not proof the Go CLI has a production remediation workflow**. See [Go rewrite plan](docs/go-rewrite-plan.md) and [SRE Golden Incident P0 acceptance plan](docs/sre-p0-golden-path.md).
>
> These are **development features**, not authenticated alert provenance, independent RCA truth, verified production recovery, or permission to modify a real cluster. #11 SFT/GRPO remains Draft and CPU-only validation does not prove GPU training. The code baseline `4a336e0` has **not** yet received full-repository Go race/vet/build and live Kind proof; pre-merge or isolated-package checks must not be called final-`main` certification.
>
> Read-only example: `go run ./cmd/sre-agent verify-bundle --scenario --file benchmarks/scenarios/checkout-latency.json`. `STRUCTURALLY_VALID` and `STRUCTURALLY_LINKED` attest only internal consistency, **not source authentication**.

Evidence-first Agentic incident investigation and safe remediation, with a runnable **Golden Incident v0.1** spanning Prometheus, Kubernetes, a Decision Gateway and Temporal durable approval.

## Go read-only investigation baseline

The current Go entrypoints accept original Alertmanager bytes, an operator-pinned cluster/namespace/deployment, and explicit read-only Kubernetes/Prometheus credentials. `plan-alert` produces an untrusted scoped candidate; `investigate-alert` collects a bounded v1 Evidence Bundle; `verify-alert-evidence` independently replays its structural linkage and returns `UNKNOWN` on mismatches. No part of this path approves an execution Permit or makes a production write.

## Offline evaluation quickstart

From the repository root, use Python 3.11 or later:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
agentic-aiops evaluate-scenarios benchmarks/scenarios/checkout-latency.json --metrics-only
```

This prints five metrics for one bundled, frozen scenario. Running the
evaluator needs no cluster, model endpoint, Temporal service, or credentials.
The scenario is a source-tree fixture, not part of the wheel; when running
from another directory, pass its absolute path. The scores describe that
fixture only, not live detection accuracy or permission to remediate.

To render its Python evidence bundle as a local Markdown RCA report:

```bash
agentic-aiops render-rca benchmarks/scenarios/checkout-latency.json --scenario
```

For a standalone Python `EvidenceBundle` JSON file, omit `--scenario`.
The report preserves supplied hypothesis statuses and evidence references;
it does not independently verify claims or authorize actions. The command
reads only local input and writes to stdout. It is not a Go evidence-bundle
converter or validator. Treat report content from untrusted files as data.

For machine-readable output, select the versioned JSON format:

```bash
agentic-aiops render-rca benchmarks/scenarios/checkout-latency.json --scenario --format json
```

The `rca-report/v1` report separates supplied hypothesis status from local
reference checks. Missing or multiply defined evidence IDs are reported
explicitly; empty references are not resolved. A resolved reference is
not proof of causal correctness or source authenticity. Both
`independently_verified` and `execution_authorized` remain false.
The default Markdown format is unchanged.

The JSON report also includes `timeline` and `undated_events`. It combines
supplied observations and change events, sorting explicit-offset timestamps
by UTC instant with up to nine fractional digits. The original timestamps
are retained. Missing or invalid timestamps stay in `undated_events` with
an explicit status; equal instants retain input order (evidence before
changes). This supports investigation but does not establish causal order,
source authenticity or recovery. Leap seconds and timestamps without
explicit offsets are not parsed.

### Offline Go Endpoint observation summary

After collecting a `sre.service-endpoints-capture/v1` archive with the Go
`sre-agent capture-service-endpoints` command, summarize the local file:

```bash
agentic-aiops render-endpoint-capture /secure/path/service-endpoints-capture.json
```

The JSON `endpoint-observation-summary/v1` includes the reported Service
identity, classification, ready endpoint count, timestamps and SHA-256
bindings. It checks the three archived source byte digests against the
supplied report and requires identical before/after Service bytes. Raw
source bodies are not printed. Invalid inputs produce exit 2 without a
partial summary. Use an operator-selected regular file.

This is a display of reported observations, not a Go Oracle replay or
native Kubernetes schema validator. Matching self-reported digests do not
authenticate a source, validate the reported endpoint count or timestamps,
prove a root cause, or authorize execution. The four authority flags remain
false. See [Go Endpoint observation](docs/go-endpoint-oracle.md).

For a structured RCA projection of the same archive, use:

```bash
agentic-aiops render-endpoint-capture /secure/path/service-endpoints-capture.json --format rca-json
```

This reuses `rca-report/v1`, attaches the original observation summary and
capture digest, and places the reported observation on the incident timeline.
Severity is unknown. Only a reported zero-ready observation with count zero
produces three explicitly unverified hypotheses (replica availability,
readiness, and Service selection or EndpointSlice reconciliation). Other
observations, including inconsistent classification/count pairs, produce
no hypotheses. No new source authentication, independent verification,
causality, or execution authority is asserted. The default summary output
is unchanged.

The Endpoint RCA report also includes an `endpoint-investigation-plan/v1`
under `investigation_plan`. Each unverified hypothesis is linked to the
observation and lists distinct pending evidence types and a verification
question. These are descriptive, read-only investigation requirements,
not executable tool calls. The reported target and capture SHA are context,
not trusted scope or permission; `target_verified`, `collection_authorized`
and `execution_authorized` remain false. An independent operator or policy
must validate the target and authorize any actual collection. Reports that
abstain from hypotheses have an empty `checks` list.

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
### Exact Git commit contract verification (Python/Go)

GitHub `test.yml` and `go.yml` run `scripts/verify_exact_tree.py` on the
**checked-out commit SHA**, refusing mismatched HEAD, modified or untracked
workspace files, incorrect Python matrix versions, missing tools and failed
commands. Each job writes `manifest.json` with scope, expected/observed SHA,
step exit codes and SHA256 checksums of verbatim logs, then uploads the proof
as a GitHub Actions artifact even when the verification step fails.

To reproduce locally in a **clean checkout** with dependencies installed:

```bash
SHA="$(git rev-parse HEAD)"
python3 scripts/verify_exact_tree.py --scope python \
  --expected-sha "$SHA" --out-dir /tmp/sre-exact-python
python3 scripts/verify_exact_tree.py --scope go \
  --expected-sha "$SHA" --out-dir /tmp/sre-exact-go
```

Use the Python 3.11 and 3.12 workflow artifacts *separately*, and the Go
race/vet/build/bundle artifact, all pointing to the **same exact SHA**.
A single suite `PASS`, or an old green workflow on another commit, is **not**
an integrated release gate. A missing GitHub Actions run means **unverified**;
the evidence script does not launch GitHub Actions, certify GPU/GRPO results
or grant production authorization. The manifest always records
`production_eligible=false`.

#### Cross-check the three exported CI artifacts

After three **real** Actions jobs finish on the same commit, download their
artifacts to separate directories and cross-check all manifests, step names,
command arguments, exit codes, Git pre/post state and log SHA256 digests:

```bash
SHA="$(git rev-parse HEAD)"
python3 scripts/verify_ci_evidence_bundle.py \
  --expected-sha "$SHA" \
  --python-311 /evidence/python311 \
  --python-312 /evidence/python312 \
  --go /evidence/go \
  --out /evidence/ci-consistency.json
```

An entirely consistent bundle returns `EVIDENCE_CONSISTENT`. Any missing,
aliased, tampered, incomplete, or wrong-SHA source returns `HOLD` (nonzero).
Even a consistent bundle does **not** authenticate its issuer: without
independently checked GitHub run IDs, runner identity, protected branch status
and permissions, no trusted CI or production acceptance is established.
The output always has `github_run_identity_verified=false`,
`source_authenticity_verified=false` and `production_eligible=false`.

### Offline GRPO grouped-rollout reward audit (CPU-only)

`scripts/audit_sre_grpo_rollouts.py` independently re-scores every
**train-split** Episode's complete group of generated completions using
private Oracle labels held in the audit process. It refuses missing,
duplicate, unknown or holdout Episode IDs, malformed JSON, nonuniform
group sizes, symlink/hardlink aliases, nonregular files, unbounded inputs
and invalid Unicode. A nonconstant reward group indicates only possible
advantage signal, not successful GRPO training.

```bash
python scripts/audit_sre_grpo_rollouts.py \
  --dataset /reviewed/train-episodes.jsonl \
  --rollouts /capture/group-rollouts.jsonl \
  --expected-dataset-sha256 "$REVIEWER_DATASET_SHA256" \
  --expected-rollouts-sha256 "$REVIEWER_ROLLOUTS_SHA256" \
  --group-size 4 --min-signal-fraction 0.25 --require-signal
```

The source bytes must be independently pinned before the experiment.
Both files are read once at most 4 MiB + 1 byte, then their digests and
content are evaluated from those same bytes; only LF delimits JSONL
records, preserving valid U+0085/U+2028/U+2029 string characters.
With `--require-signal`, a collapsed or insufficient-signal result exits
nonzero (`UNKNOWN`). The receipt always keeps
`model_runtime_verified=false`, `reward_hacking_verified_absent=false`
and `external_provenance_authenticated=false`. This is a data-side
diagnostic tool only: no GPU training, optimizer attestation, real SRE
quality proof, or production release authorization is provided.
### CPU-only LoRA local parameter delta and frozen Episode evidence

`agentic_aiops.grpo_train_proof` provides a bounded, **read-only** contract
for (1) hashing and parsing the **same** frozen Episode JSONL bytes,
and (2) capturing a local trainable LoRA parameter snapshot before and
after an experimental step. External dataset SHA256 pins must be supplied
for independently reviewed input provenance; generating a digest locally
does not authenticate the data owner.

The tensor serializer supplied by the caller must produce contiguous
**exact raw bytes** with `numel × dtype_bytes` size, not rounded values,
string repr, or a reshaped buffer. Currently accepted dtypes are
`torch.float16`, `torch.bfloat16` and `torch.float32`. Trainable weight
names must use valid `.lora_A[.default].weight` /
`.lora_B[.default].weight` pairs for each LoRA module, with unique saved
slots. Empty or missing pairs, mismatched bytes, invalid shapes, unknown
dtypes or fingerprint metadata are rejected. The input source must be
a regular non-symlink file and is bounded before allocation.

The returned `sre.grpo.local-lora-update/v1` receipt compares names,
layouts and SHA256 fingerprints and intentionally sets
`model_runtime_independently_verified=false`,
`training_admission_authorized=false`, and `production_eligible=false`.
A self-reported parameter delta **does not establish** a real optimizer
step, externally attested GPU run, saved Adapter match, improvement on
blind SRE holdouts or production permission. GPU/PEFT/TRL model execution
and independent weight provenance stay in Draft PR #11.
### CPU-only pinned LoRA Adapter Safetensors admission

`agentic_aiops.grpo_adapter` accepts only a local, single-file PEFT LoRA
Adapter with an externally reviewed lowercase SHA256 pin for both
`adapter_config.json` and `adapter_model.safetensors`, plus a pinned
`Qwen/Qwen3-*` model revision. It rejects arbitrary sidecars/pickle,
symlink inputs, nonregular files, unknown tensor slots, unsupported ranks
and dtype/shape/offset inconsistencies. Adapter files are opened with
no-follow descriptor flags and read with explicit byte limits (64 KiB
config; 256 MiB weights). SHA verification, parsing, staging and
post-load tensor comparison operate on the frozen in-memory bytes.

`staged_pinned_adapter()` independently rechecks even a caller-constructed
`FrozenAdapter` object's raw bytes, schema and claimed digest/layout
before publishing its bytes into a private temporary directory. The
CPU `verify_loaded_adapter_weights()` contract additionally checks
exact tensor names, dtype, shape and raw bytes of the loaded PEFT state.

This **does not authenticate** who approved those pins, the real base
model, the runtime or any GPU inference. No model weights are executed
or trained by this module, and its receipts set all independent model
attribution, training admission and production flags to **false**.
Real CUDA loading and physical model-effect probes remain separate
work for the Draft GRPO PR #11.
## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

For cross-repository integration, [four-repo-acceptance](.github/workflows/four-repo-acceptance.yml) verifies pinned public Control Plane, Runtime and Decision commits from this repository's main push CI on disposable kind + Temporal infrastructure.

The machine-readable [stack.lock.json](stack.lock.json) pins the dependency revisions used by CI. The local check uses Python 3.11 or later and can run before package installation.

```bash
make stack-lock-check
# or select a specific interpreter
make stack-lock-check PYTHON=python3.12
# or, after installation
agent-stack-lock stack.lock.json
```

A stack change is therefore an explicit reviewable dependency update. CI fails closed if a required repository is renamed, a revision is not a full commit SHA, or the positive/negative release-gate contract is changed accidentally.

## Contributing and license

Contributions are welcome through focused issues and pull requests. See `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.

Licensed under Apache License 2.0. See `LICENSE`.
