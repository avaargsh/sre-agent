# SRE Agent delivery roadmap — 2026-11-24

Coordination plan, not a release certificate. Observed base main: `5de0398bf3c8b56da653731bef92846771b57304` (#101). PR #102 adds a bounded Service/EndpointSlice observation candidate with same-type-safe list semantics and remains Draft/HOLD until exact-head Python 3.11/3.12, Go race/vet/build, and live disposable-kind evidence pass. The older [migration plan](go-rewrite-plan.md) and [Golden Incident plan](sre-p0-golden-path.md) remain historical baselines. #50/#51 added LAB raw Rollout capture and publication race hardening, not verified CUDA training. #11 remains Draft; extract small missing slices rather than merging it wholesale.

## Ordered P0 delivery

| Slice | Deliverable | Acceptance |
|---|---|---|
| A — exact-main gate | Python 3.11/3.12, Go race/vet/build, kind/Calico where applicable; cross-check evidence artifacts | Actual run/job IDs, same Git SHA, complete logs, independently checked artifacts. Missing/failure = HOLD. Refresh documented baseline without changing historical proof. |
| B — read-only Go Golden Incident | Alertmanager -> scoped observation -> evidence-linked RCA/UNKNOWN CLI; reuse G0/G1; fill missing authenticated source identity, durable dedup, Events/Pod logs/Service/EndpointSlice | Real disposable kind, namespace-scoped read-only RBAC; deny secrets/writes; bounded observations; replay, stale/conflicting/malformed data, timeout, truncation and prompt injection negatives. |
| C — independent fault benchmark | Selector mismatch, DNS vs NetworkPolicy, CrashLoop/probe regression, healthy negative control | Separate injector/observer/grader credentials; original pre/during/post evidence, private Oracle, exact SHA and per-case artifacts; no hidden labels in observer context. |
| D — G3 authority | Verified ACP/EngageGuard identity, Run/action/evidence-bound permit and revocation; Temporal durable lifecycle and operation reconciliation | Duplicate delivery, expired/revoked permit, drift, SIGKILL, lost ACK and UNKNOWN reconciliation tests. No production writes. |
| E — G4 controlled remediation | One bounded scale action in disposable kind, UID/resourceVersion/current-state CAS | Sustained post-action SLI plus functional checks, rollback only when safe, UNKNOWN otherwise. Requires D first. |

## P1 / P2

- P1: OpenTelemetry metrics/logs/traces/change correlation, competing hypotheses, bounded tool budget and source-linked reports. Continuous replay, overlapping incidents and restart recovery after the single-fault baseline.
- P1 training: reuse #29–#42 and #50–#51. Extract tokenizer-rendered prompt verification, real CUDA LoRA optimizer step and saved Adapter lineage, independently authenticated runtime/data evidence from #11. No GPU or improvement claim from CPU-only checks. Train only on independently reviewed Episodes; fault-family split, identical Base/SFT/GRPO held-out tasks and budgets, repeated seeds, reward-hacking and abstention checks.
- P2: AI infrastructure incidents (GPU OOM, vLLM/SGLang degradation, Kueue admission, DRA claims, NCCL/RDMA), then GitOps proposals and reviewed deployment verification. Keep physical GPU claims separate from synthetic labs.

## Evaluation scorecard

Detection and localization; RCA accuracy by fault family; supported citation fraction; abstention precision/recall; time to first useful finding, time to diagnosis, tool count and token cost; runtime recovery and functional regression pass rate as separate metrics. Safety guardrails: zero unauthorized writes and zero false VERIFIED in negative tests. These are proposed measurements/targets, not achieved scores.

## Research inputs

- [SWEOps-Bench](https://arxiv.org/abs/2611.06099) (2026-11-04): separate diagnosis, runtime symptom clearance and functional recovery.
- [Incident-Arena](https://arxiv.org/abs/2610.00648): realistic applications, faults, load and long-horizon evaluation.
- [SRE-Marathon](https://arxiv.org/abs/2609.33023): overlapping faults and persistent state.
- [PagerDuty benchmark](https://www.pagerduty.com/resources/ai/learn/sre-agent-benchmark-report/): localization, diagnosis, mitigation and grounded evidence.

## Ownership and merge gate

SRE owns evidence, investigation and recovery measurement; ACP/EngageGuard owns authorization; Temporal owns durable workflow. UNKNOWN is not FAILED on timeout or lost ACK. One small PR per slice, regression negatives first, exact-head checks and post-merge exact-main proof. Preserve historical stack lock and evidence. Start with A, then B/C; no G4 before G3. No production release authorization follows from this document.

## Historical integration checkpoint — 2026-11-24 (pre-PR #101)

Historical snapshot only: observed main at that checkpoint was `064ea714615cdc08ed515ab0187ef849f7b96a5a`; its PR #56–#60 inventory and local evidence are retained for audit, not as the current backlog or merge status. The post-#101 baseline and current PR #102 checkpoint are recorded below.

| Workstream | Existing PR | Next acceptance |
|---|---|---|
| A: verification | #56 | Exact-candidate Python matrix and Go checks; non-author review; refresh main proof after merge. |
| B: alert/evidence boundary | #57, #59 | #57 regular-file admission, create-only publishing, bounded credential reads; #59 truncated Alertmanager group rejection. Verify individually, then together on latest main; no authenticated alert or recovery claim. |
| B/C: Pod diagnosis | #60 | Complete native response parsing, independently selected namespace/name/UID, original raw digest, bounded GET/replay. Prove live disposable kind CrashLoopBackOff, current versus historical OOM, healthy negative, UID replacement and malformed state rejection. Keep Evidence v1 schema unchanged; no RCA truth from a container status alone. |
| Model evaluation | #52, #54, #58 | Frozen Oracle-free prompts, real attributed captures, SQL lab limits and isolated execution; separate actual model quality from submitted prediction-byte scoring. |
| Training | #53, #11 | Validate the focused CPU tensor contract; extract rather than merge the divergent training branch wholesale. Actual CUDA/optimizer and independently authenticated model effects remain unverified. |

Contributor-side isolated replay of #60 normalized classifier (Go 1.23.2, Linux): source blob `2bb19cb75faaf2afb419e46e46a8413c14a2642e`, checked-in test blob `d0edbac268891666bf2168cfd260d7f8800acdb4`. Both copied files matched Git blob hashes. `go test -race -v ./internal/poddiagnosis` passed four test functions, including seven negative subtests; `go vet ./internal/poddiagnosis` passed. This is not native adapter or full-repository acceptance. During preparation the native-test branch advanced to `38b7a392d8d14015231d0ad0511529f32cb43292`; avoid overlapping writes, review its final head when implementation is present.

Local `git ls-remote` failed DNS resolution for github.com. The existing `test.yml`, `go.yml`, and `go-endpoint-kind.yml` expose workflow_dispatch; authorized maintainers can dispatch them for the exact candidate ref, verify the checked-out SHA and artifact provenance, and rerun against the merged main. Do not treat a run from another commit or an isolated module as certification. Keep Draft/HOLD until all applicable gates pass.


## Integration checkpoint — after Endpoint Oracle evidence hardening

This checkpoint supersedes the older observed-main SHA above for current work; the earlier checkpoint remains historical context.

- Main before the current candidate: `5de0398bf3c8b56da653731bef92846771b57304` (PR #101 merged).
- Candidate: PR #102 (use the PR's current head SHA), using a Most Recent EndpointSlice LIST without comparing the Service ResourceVersion across resource types, adding ordered per-read timestamps/digests, offline capture replay with the same 30-second window bound, and zero/oversized UTF-8-byte-RV plus HTTP 410 fail-closed cases. Go request tests use race-safe channels, assert exactly one LIST and fail fast on duplicate reads. The Python LAB helper rejects unpaired Unicode surrogates anywhere in source JSON, caps decoded nesting at 64 levels, and opens only bounded regular files with no-follow/nonblocking flags (rejecting final-component symlinks/FIFOs).
- This is a bounded observation interval with stable Service identity, not a cross-resource atomic transaction, controller-convergence proof or source authentication. `source_authenticated=false` remains mandatory.
- Exact-head Go race/vet/build and disposable-kind Endpoint Oracle proof have not been returned by GitHub Actions in this session. Treat the candidate as HOLD until the exact candidate SHA has complete logs and independently checked artifacts; after merge, repeat against the resulting exact main SHA.
- Next P0 after this slice: exact-main Go proof, live kind healthy/fault/recovery proof, then reconcile original evidence artifacts. Only after those pass should work expand to DNS vs NetworkPolicy, Pod diagnosis, and independent fault-family evaluation. Do not advance to G3/G4 authority or remediation claims on this evidence alone.


## Integration checkpoint — native JSON admission consolidation (2026-11-24)

This checkpoint supersedes the prior current-main SHA above; earlier sections remain historical evidence and planning context.

- Exact observed main: `4a336e0b8622834c7d0664dd9e543e73308dcd38` (PR #106).
- PR #104 introduced schema-aware canonical-field admission for Kubernetes Observer, Prometheus SLI and Service Oracle inputs.
- PR #105 removed EndpointOracle's duplicate reflection walker and reused `sourcejson.ValidateCanonicalFields`.
- PR #106 corrected an over-broad global case-fold collision check: the schema-independent syntax pass now rejects exact duplicate JSON keys, while typed struct-field aliases are rejected at the schema-aware boundary. Case-sensitive map keys and opaque `json.RawMessage` values remain data.
- Go 1.23.2 isolated sourcejson harness: unit tests, race tests and `go vet` passed. This is not full-repository validation.
- Exact-main `go test -race ./...`, `go vet ./...`, `go build ./cmd/sre-agent`, and live disposable-Kind Endpoint/SLI proofs have not yet been observed for `4a336e0`. Keep the mainline release posture at HOLD until exact-SHA Actions evidence and artifacts are independently checked.
- Next P0: execute the existing exact-tree Go contract workflow and the two live Kind workflows against the exact merged main SHA; investigate any failures before adding new product scope.
