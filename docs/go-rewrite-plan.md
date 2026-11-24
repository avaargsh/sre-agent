# SRE Agent — Go-native Migration Plan (updated 2026-11-24)

## Repository baseline and migration policy

Pinned development baseline for this update: `avaargsh/sre-agent` `main@5de0398bf3c8b56da653731bef92846771b57304`. The repository now includes Go read-only alert planning/investigation, source-integrity verification, independent SLI and fault Oracles, RCA review and signed-evidence **lab** contracts, alongside the historic Python `agentic-aiops` reference and CPU-only GRPO evidence utilities. These modules are not equivalent to a validated end-to-end Go product. No exact-head integrated Python 3.11/3.12 + Go + kind result has been observed for that pinned `main` commit. The historic M1 evidence is **not** validation of the Go implementation; Python remains as the compatibility oracle. Do not silently update `stack.lock.json` or rewrite frozen historic evidence.

## Product ownership

**sre-agent:** incidents, read-only Kubernetes/Prometheus observation, topology and change-aware investigation, Evidence Packages, hypotheses, RCA and independent post-action verification. A bounded remediation adapter can only be introduced after the authority gate is proven.

**ACP:** identity, Run/approval/permit authority, revocation epochs, policy, audit and evidence links. **Temporal:** durable workflow, retries and recovery. **Kubernetes/Prometheus:** authoritative workload and SLI observations. **LLM:** proposes hypotheses/actions but never grants write permission or self-verifies recovery.

Legacy `agent-control-plane`, `cloud-agent-runtime` and `agent-decision-lab` remain pinned only for reference compatibility; migrating their contracts to ACP requires actual API verification, not a rename.

## Incremental milestones

| Gate | Engineering scope | Required evidence |
| --- | --- | --- |
| **G0: Contract parity (development-integrated)** | Go module, read-only Evidence Bundle verifier CLI, Python-v1 SHA/structural compatibility, Go CI | Frozen Python canonical SHA matches; duplicate IDs/dangling evidence/unsupported claims/digest tampering rejected; `go test -race ./...` and `go vet ./...` pass; no cluster writes |
| **G1: Observation (development-integrated slice)** | scoped client-go list/get/watch; bounded Prometheus queries, evidence timestamps, topology and change events | disposable kind real read-only proof; no write permissions; missing/stale SLI becomes UNKNOWN |
| **G2: Independent Verifier (partial / lab)** | evidence-v2 schema, source hashes, competing hypotheses, deploy/config change timeline and independent Oracle | tampered evidence rejected; no model self-confirmation; pre/post time-window SLI and credible unknown state |
| **G3: Durable authority (not complete in Go)** | ACP API identity/permit+epoch binding; Temporal Go SDK, journal, idempotency and UNKNOWN reconciliation | SIGKILL before/after ACK, revocation, mismatched action/run/evidence, duplicate retries all fail closed |
| **G4: Controlled remediation (not authorized)** | allowlisted executor, Kubernetes UID/resourceVersion/current-replicas CAS, policy-driven rollback and sustained SLI | exact approval and protected Kubernetes write; drift-safe rollback; no false VERIFIED on stale/missing series |
| **G5: Product and evaluation (not certified)** | installable CLI/Helm, audit export, continuous multi-incident replay and SRE benchmarking | exact-HEAD reproducible kind Golden Incident, independent release gate, regression suite |

## Current migration risk and release gates

- **Go functionality vs historical Python demo:** The Go CLI implements multiple read-only analysis and lab-verification commands beyond G0. The Python/Temporal Golden Incident still demonstrates a different reference path; neither its approval flow nor its scale operation is an authorization of new Go remediation.
- **RCA policy admission:** The pinned `sre.rca-policy/v1` verifier must reject JSON key casing aliases and same-logical-field collisions before Go's case-insensitive typed decoder. Checksums bind the bytes provided by a caller; they do not authenticate who issued the policy. See [RCA triage contract](go-rca-triage.md).
- **Offline GRPO:** CPU-only Episode/Oracle, Holdout, Safetensors and local LoRA receipt contracts remain distinct from real training evidence. The isolated [LAB-only Qwen3 raw rollout capture](grpo-lab-rollout-capture.md) requires explicit `--execute --lab-only`, a pinned dataset/revision and CUDA; neither its unverified model capture manifest nor CPU test doubles authenticate model execution or prove TRL/PEFT optimizer steps. Draft [#11](https://github.com/avaargsh/sre-agent/pull/11) must still be decomposed rather than merged wholesale; no diagnostic uplift, issuer authority or production release may be claimed.
- **Required graduation evidence:** run exact-current-main Python 3.11 and 3.12 pytest, Go `test -race` / `vet` / build, and the applicable disposable-kind Golden Incident. Preserve complete logs, Git SHA and post-run clean-tree checks; require independent review of security-critical authority/provenance contracts. No PR-head or old-main green run substitutes for a final-main certification.
- **Offline CI artifact admission:** The read-only three-scope verifier reads each evidence manifest/log through an opened, no-follow, nonblocking file descriptor and applies `fstat`/byte limits to that inode (development hardening [#46](https://github.com/avaargsh/sre-agent/pull/46)). This prevents final-component symlink/FIFO substitution between a pathname precheck and open; it does **not** attest mutable parent directories, trusted CI runner identity, signer policy, or production eligibility. Exact-current-main actions and independent review are still required.
- **Offline CI summary publication:** Each invocation of `scripts/verify_ci_evidence_bundle.py` must use a **fresh, unused `--out` pathname** under an operator-owned directory. The summary is JSON-serialized before filesystem publication, written to a private `0600` no-follow staging file, flushed and `fsync`ed, then atomically hard-linked to the final path (create-only; never replace). On write/fsync/link failure, staging is cleaned up and no incomplete final report is published. Existing files, symlinks and late competing writers remain untouched. This controls a final-component publication hazard, **not** a mutable/untrusted parent directory, independently authenticated CI runner identity, signer authority, or production eligibility.
- **Exact-commit runner proof output:** `scripts/verify_exact_tree.py` now similarly requires a fresh operator-owned `--out-dir`: per-command logs are private `0600` exclusive/no-follow files, and its `manifest.json` uses the same staged, fsynced, create-only publication helper. Existing logs or manifests fail closed rather than overwriting or following an alias. All exact-main Python 3.11/3.12, Go and kind verification remains independently required; output integrity is not CI runner authentication.
- **Authorization:** ACP/EngageGuard owns identity, permit and revocation authority; Temporal owns durable workflow and recovery. The Go SRE investigator must not duplicate those authorities or activate writes without an independently verified integration.

## G0 contract and limitations

`go run ./cmd/sre-agent verify-bundle --file evidence.json` checks serialized Python `EvidenceBundle.to_dict()` structure and hash. `--scenario` reads the `bundle` envelope of `benchmarks/scenarios/checkout-latency.json`. It does **not** validate a scenario's `outcome.recovered`, evidence authenticity, metric freshness, RCA truth or operational recovery.

Python v1 canonical JSON uses sorted keys, UTF-8, no extra whitespace and ignores `metadata.bundle_sha256` when hashing. A SHA-256 value is a checksum, not a signature. Cross-language numeric/Unicode edge cases require additional contract vectors before cryptographic signing or trusted external consumers.

No G0 component accesses a cluster or supplies write credentials. Keep all production write paths disabled until G3/G4 pass independent CI, disposable kind and review.

## Migration map

- `bundle.py` / `models.py` / `provenance.py` → `internal/evidence` and future versioned Evidence API
- `prometheus_tool.py` / `kubernetes_tool.py` → `internal/observe`
- `investigation.py` / `runner.py` → `internal/investigation`
- `evaluation.py` / `scenario.py` → `internal/eval`
- `durable_incident.py` / `operation.py` → `internal/workflow`, `internal/journal`
- `remediation.py` / `policy.py` → ACP-authorized `internal/remediation` only after G3

Keep the legacy Python Golden Incident and its tests as the migration oracle until the same exact-head Go behavior and negative cases are independently verified.
