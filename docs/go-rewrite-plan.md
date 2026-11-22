# SRE Agent — Go-native Migration Plan (2026-11-22)

## Repository baseline and migration policy

At assessment time, `avaargsh/sre-agent` `main` is commit `55860e731753225c7d35f77c566f9dc21de71c1c` and mirrors the Python `agentic-aiops` reference implementation, including pytest, frozen scenarios and the four-repository kind/Temporal acceptance flow. The historic M1 evidence is **not** validation of this Go implementation. Python remains in place until each behavior has passed an equivalent Go migration gate. Do not silently update `stack.lock.json` or rewrite historic evidence.

## Product ownership

**sre-agent:** incidents, read-only Kubernetes/Prometheus observation, topology and change-aware investigation, Evidence Packages, hypotheses, RCA and independent post-action verification. A bounded remediation adapter can only be introduced after the authority gate is proven.

**ACP:** identity, Run/approval/permit authority, revocation epochs, policy, audit and evidence links. **Temporal:** durable workflow, retries and recovery. **Kubernetes/Prometheus:** authoritative workload and SLI observations. **LLM:** proposes hypotheses/actions but never grants write permission or self-verifies recovery.

Legacy `agent-control-plane`, `cloud-agent-runtime` and `agent-decision-lab` remain pinned only for reference compatibility; migrating their contracts to ACP requires actual API verification, not a rename.

## Incremental milestones

| Gate | Engineering scope | Required evidence |
| --- | --- | --- |
| **G0: Contract parity (this PR)** | Go module, read-only Evidence Bundle verifier CLI, Python-v1 SHA/structural compatibility, Go CI | Frozen Python canonical SHA matches; duplicate IDs/dangling evidence/unsupported claims/digest tampering rejected; `go test -race ./...` and `go vet ./...` pass; no cluster writes |
| **G1: Observation** | scoped client-go list/get/watch; bounded Prometheus queries, evidence timestamps, topology and change events | disposable kind real read-only proof; no write permissions; missing/stale SLI becomes UNKNOWN |
| **G2: Independent Verifier** | evidence-v2 schema, source hashes, competing hypotheses, deploy/config change timeline and independent Oracle | tampered evidence rejected; no model self-confirmation; pre/post time-window SLI and credible unknown state |
| **G3: Durable authority** | ACP API identity/permit+epoch binding; Temporal Go SDK, journal, idempotency and UNKNOWN reconciliation | SIGKILL before/after ACK, revocation, mismatched action/run/evidence, duplicate retries all fail closed |
| **G4: Controlled remediation** | allowlisted executor, Kubernetes UID/resourceVersion/current-replicas CAS, policy-driven rollback and sustained SLI | exact approval and protected Kubernetes write; drift-safe rollback; no false VERIFIED on stale/missing series |
| **G5: Product and evaluation** | installable CLI/Helm, audit export, continuous multi-incident replay and SRE benchmarking | exact-HEAD reproducible kind Golden Incident, independent release gate, regression suite |

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
