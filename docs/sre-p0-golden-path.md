# SRE Agent v0.1 — Evidence-first Golden Incident & evaluation gates

> Status: engineering plan, **not** a production-readiness report. Updated baseline: 2026-11-23. Target: `avaargsh/sre-agent`; Go-native read-only investigator and offline Evidence auditor with frozen Python compatibility. PR #1–#10, #12 and #14–#16 are merged into development `main`; GRPO training PR #11 remains Draft. Integrated final-`main` CI and independent security approval remain outstanding. No duplicate ACP/Temporal control plane.

## Product decision

**Positioning:** Kubernetes-first SRE investigation with an explicit `UNKNOWN` verdict when observations are insufficient. The first shipped value is **alert → scoped observation → defensible evidence → root-cause hypothesis/abstention → independent replay**, not an unrestricted LLM shell or autonomous remediation.

| Reference | Verified capability / lesson | What to adopt (not copy) |
| --- | --- | --- |
| [HolmesGPT](https://github.com/HolmesGPT/holmesgpt) | Alert/operator-driven investigations, multi-observability toolsets, context/output budgets, user-facing findings | Single Alertmanager-triggered Golden Incident, compact source-linked report; defer large connector catalog |
| [K8sGPT](https://github.com/k8sgpt-ai/k8sgpt) | Deterministic Kubernetes analyzers and operator workflow | Cheap deterministic K8s baseline before optional LLM hypothesis generation; never adopt broad auto-write privileges |
| [SREGym](https://github.com/SREGym/SREGym) | Live faults with diagnosis/mitigation stage separation, isolated agent and independent grader | Private Oracle, fault-family split, controlled disposable-kind episodes, repeated runs and exact per-case evidence; no official score claim |
| [openarc-labs/agentic-aiops](https://github.com/openarc-labs/agentic-aiops) | Python evidence/approval reference and frozen Golden Incident | Retain compatibility test vectors; do not treat historic cross-repo M1 or staged Draft PRs as a new Go production proof |

## Responsibility boundaries

- **SRE Agent** owns alerts, observations, incident graph/change timeline, hypotheses, evidence ID citations, abstention, independent diagnosis/recovery measurements and evaluation artifacts.
- **ACP/EngageGuard** owns identity, authorization/policy, approvals, permits, revocation epochs, audit and release authority. No Agent/LLM self-granted write access.
- **Temporal/approved executor** owns durable waits, crash recovery, command/ACK reconciliation, bounded authorized actions and compensating workflow. The SRE process must not rebuild this as another control plane.
- **Training/Oracle** are offline/private. The observer sees only read-only pre/during-fault data; never injector commands, hidden root cause, post-recovery truth or grading rubric.

## Ordered implementation; preserve existing PR ownership

### P0-A — G0 evidence digest correctness

Go G0 PR [#1](https://github.com/avaargsh/sre-agent/pull/1) and strict Unicode [#12](https://github.com/avaargsh/sre-agent/pull/12) are merged into development `main`. The `STRUCTURALLY_VALID` verdict is **shape+digest only**, not authenticated provenance, causal truth or recovery. #12 rejects malformed UTF-8 and unpaired UTF-16 surrogate escapes before canonicalization. Independent code/security review and integrated final-`main` tests remain promotion prerequisites.

**Contract negatives:** duplicate keys (including nested), bad Unicode, trailing JSON, oversize bundle, missing/dangling evidence refs, unsupported explicit schema, cross-language Python SHA parity. No claim that a valid hash authenticates the source.

### P0-B — G1 observer and alert entry

Existing G1 [#2](https://github.com/avaargsh/sre-agent/pull/2) now contains scoped Go Deployment/Pod + Prometheus reads; strict raw-source JSON [#14](https://github.com/avaargsh/sre-agent/pull/14), Alertmanager plan [#15](https://github.com/avaargsh/sre-agent/pull/15) and read-only alert Evidence bridge [#16](https://github.com/avaargsh/sre-agent/pull/16) are also in development `main`. They supply deterministic candidate/structural checks, **not** an authenticated webhook receiver, durable deduplication, independent RCA or production executor. Next extend/review with:

1. Retain deterministic Alertmanager groupKey/fingerprint + namespace/deployment routing; implement durable, scoped replay dedup and bounded timeout separately. A repeated deterministic ID is **not** exactly-once delivery or an authenticated incident identity; no caller-supplied tenant privilege escalation.
2. Read-only Kubernetes Events/Pod status/log tail, Service/EndpointSlice, Deployment status/revision; capture source URL/type, Kubernetes UID/resourceVersion, scrape timestamp/query, truncation, observation time and raw response SHA. Exact tool transcript must be separately preservable.
3. Accept only allowlisted GET/LIST endpoints. Deny redirect, overlarge output, secret read, scale/patch/delete. Namespace-scoped tokens, TLS CA, service-identity check. Shared-namespace EndpointSlice LIST is not per-Service label-selector RBAC: document namespace exposure.
4. **Fail closed** if upstream JSON duplicates keys, invalid UTF-8/surrogates, 403, ambiguous identity, pagination, malformed/nonfinite Prometheus value, stale scrape, missing SLI or race/drift; no `SUPPORTED` hypothesis from merely successful reads.
5. Output bundle with evidence IDs/digest, `UNKNOWN` reason when incomplete, no recovery claim, and a plain operator report with citations.

**Proof:** exact HEAD Go race/vet/build+legacy Python CI and disposable-kind original artifact; rehash each source and resulting bundle independently. A green synthetic/unit test is not evidence of physical fault recovery.

### P0-C — G2 real fault Oracle and negative controls

Reuse the already merged [#3](https://github.com/avaargsh/sre-agent/pull/3) SLI Oracle and [#4–#10](https://github.com/avaargsh/sre-agent/pulls?q=is%3Apr+is%3Amerged) Go Evidence/Oracle LAB baselines; their green CI does not independently authenticate upstream evidence or permit production write access. Start with:

- Service/EndpointSlice selector mismatch causing observable outage, with no-Pod-ready and healthy negative controls.
- DNS vs direct-IP contradiction, with injected DNS failure independent from NetworkPolicy denial.
- Pod CrashLoopBackOff/probe failure, including recent Deployment/config change evidence.

For **each** scenario, record immutable original injector/admin source snapshots and separate pre/during/post observer reads, SHA-pinned source artifact, exact CI head, private Oracle verdict and explicit scope. Never let the observer read admin injection or after-recovery snapshots. Controlled kind faults do not prove a production RCA rate.

**Abstention:** contradictory/stale/incomplete evidence, multiple plausible causes, and unsupported negative controls must return `UNKNOWN` and escalation, not a model confidence number dressed as certainty.

### P1 — Offline SFT/GRPO backed by real Episodes

Reuse Draft [#11](https://github.com/avaargsh/sre-agent/pull/11) offline `sre.grpo.episode/v1`, Oracle reward and holdout audit; do not merge/promote synthetic training contracts as a trained model.

Only begin actual Qwen3 training after:
- Independently authenticated actual lab episode intake; fault-family split and normalized cross-split duplicate/near-duplicate audit.
- Reproducible Python 3.12 + pinned/hash-locked Transformers/TRL/PEFT/PyTorch/CUDA stack; explicit GPU/Qwen3 LoRA backward+weight delta proof.
- Frozen Base vs SFT vs GRPO head-to-head replay with identical fault families, prompts, budgets and >=3 seeds when practical; report per-family root-cause accuracy, evidence-support rate, proper abstention, tool-count and latency/cost.
- Reward-hacking checks: no Oracle/admin labels in observer context; no model-supplied tool costs or Judge rewards; no shortening workload/hiding failures/early stop treated as success.
- Independence: Oracle truth, Kev Evidence Judge and risk/probability calibration are separate from observer/policy authority.

**Prohibited claims:** self-reported 17 scenarios = official SREGym score; synthetic good rewards = gradient learning; `.[train]` import = verified CUDA training; trained model = production remediator.

### P2 — AI Infrastructure fault families, after Kubernetes P0 is proven

Add **separate** observable fault-family contracts for GPU OOM/eviction, vLLM/SGLang inference degradation, Kueue admission/quotas, DRA ResourceClaim allocation/release, PCIe/NCCL/RDMA loss or congestion. Preserve the exact evidence-to-Oracle boundary: independently controlled metric/event sources, failure injected or reproduced in a disposable environment, quantitative GPU/time/token cost, and an explicit UNKNOWN outcome for missing counters or operator-only fault labels. Do not imply an MXC500/NVIDIA physical GPU validation from CPU-only kind tests or synthetic logs. No cross-repository dependence on former-employer proprietary gateway code.

### P3 — Policy-governed action, explicitly deferred

After authenticated ACP + Temporal contract tests and independent review only: Proposal → decision/policy → human approval → scoped ActionHash Permit → UID/resourceVersion/current-state CAS → trusted executor → sustained SLI verification → rollback or UNKNOWN reconciliation. SIGKILL/lost ACK, permit expiry, revocation Epoch and external side effect must fail closed. No generic production shell.

## Operator-level Golden Incident acceptance

| Gate | PASS evidence | FAIL/CLOSED evidence |
| --- | --- | --- |
| Alert entry | Deterministic scoped candidate from pinned original bytes; future durable dedup/one `Run` per incident needs explicit journal proof | Missing/ambiguous ownership, replay side effects, unbounded fanout; self-hashed webhook is not authenticated |
| Read-only observation | Real kind ServiceAccount; only required GET/LIST and source hashes; original response artifact | Any secret/scale write, malformed/duplicate JSON, stale SLI, page truncation, unsupported redirect -> UNKNOWN |
| Diagnosis | Hypothesis cites existing evidence IDs; separate independent Oracle; negative control abstains | Unsupported root cause, fabricated refs, model reads injector truth, treats successful GET as recovery |
| Recovery semantics | Distinct pre/during/post SLI and independent verifier for a deliberately injected fault | Partial/single sample or non-finite series marked VERIFIED |
| Reproducibility | Exact SHA/HEAD, dependency lock, test command, CI artifact, private Oracle, failure transcript | Green CI attributed to a different commit or hand-authored summary alone |
| Authorization | Only read-only credentials in v0.1; production writing disabled | Any model-initiated Kubernetes mutation without ACP Permit |

## Branch hygiene — current ownership instead of stale branch counts

At the 2026-11-23 update, development `main` includes #1–#10, #12 and #14–#16. The historical ten-branch snapshot and draft-status list from the original plan are **superseded**. Do not infer live remote branch names or deletion eligibility from a static count. Before any deletion, use fresh GitHub API reads to confirm the exact branch SHA, PR `merged=true`, merged-tree equality and that the name is not the default branch or any active PR head. Only delete with an explicit, separately reviewed user request; this document does not authorize deletions.

The offline GRPO training [#11](https://github.com/avaargsh/sre-agent/pull/11) remains **Draft/unmerged**: CPU-only synthetic evidence, no verified CUDA GRPO gradient run or independent holdout improvement. This document's own PR #13 is a product/acceptance specification and must not be presented as a production gate pass.

## Shipping rule

PR #1–#10, #12 and #14–#16 have been merged into development `main`, not independently certified for production. **No fresh integrated final-`main` GitHub Actions run was emitted after the stacked branch sync/merges**; previously green individual PR HEADs are not a substitute for a single exact integrated-head test. Before production promotion: run full Go/Python/kind/Calico regression on the final main SHA, independently review source/authentication and policy boundaries, and verify signer grants and approval authority. GRPO [#11] stays Draft until actual GPU training, independent holdout and reproducible evidence. Do not silently weaken historic `four-repo-acceptance`; replace it only after an explicitly designed ACP/Temporal authority migration has its own acceptance evidence.

**First user demo target:** one alert, a single CLI command, a printable evidence-linked RCA/UNKNOWN report, and the reproducible independent kind benchmark that can tell whether the diagnosis was actually correct.
