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

### P0-D — Inkling-first model evaluation (2026-11-24 decision; not implemented)

Run this research lane in parallel with P0-A/B/C; do not bypass the Go evidence/authority gates or imply the Golden Incident is certified. Select the model by independently measured SRE task quality and cost, **not by general coding benchmarks**. Inkling-2-Mini is the first candidate, not an approved default.

| Lane | Candidate | Required qualification |
| --- | --- | --- |
| Baseline | Deterministic Go investigator; existing pinned Qwen3 Base | Keep their outputs and budgets frozen; compare separately from the Qwen training lineage |
| Reference | `thinkingmachines/Inkling-2-Mini` original publisher weights | Pin model revision, weight manifest/hash, tokenizer/chat template, tool parser and runtime digest; original weights are not an FP16 quality oracle |
| Local | `unsloth/Inkling-2-Mini-GGUF`, mainline-compatible GGUF with llama.cpp (start with a supported Q4 variant) | Pin exact file, quantizer/revision and llama.cpp commit; smoke-test loading, multi-turn tool calls and memory; smaller quants are separate candidates |
| Apple experimental | MLX-compatible conversion | Optional only after exact engine/model compatibility and tool-call parity are demonstrated; unsupported or unavailable = NOT_RUN, never a silent fallback |
| Serving | vLLM and SGLang on verified hardware | Pin engine image, driver, GPU and kernels; start with speculation OFF, then separate DSpark ON lane where supported; no implied domestic GPU compatibility |

References: [official model card](https://huggingface.co/thinkingmachines/Inkling-2-Mini), [official release](https://thinkingmachines.ai/news/inkling-2-mini/), [Unsloth GGUF](https://huggingface.co/unsloth/Inkling-2-Mini-GGUF), [vLLM recipe](https://recipes.vllm.ai/thinkingmachines/Inkling-2-Mini), [vLLM architecture note](https://vllm.ai/blog/2026-11-20-inkling2-mini), [SGLang support](https://www.sglang.io/blog/inkling-2-small-day0-support). These establish candidate availability and upstream claims, not project-specific results.

#### Reuse the existing evidence and holdout contracts

1. An independent data owner freezes the Episode/Oracle split by fault family, checks exact/near-duplicate leakage, and publishes separately SHA-pinned Oracle-free prompts using the existing projection/replay path. The inference process must not receive the private Oracle or grading rules.
2. Add an isolated LAB-only **evaluation** adapter that consumes frozen projected prompts and emits the existing raw candidate prediction format plus a versioned backend-specific capture receipt. Preserve every projected ID in original order; preserve invalid raw output and explicit failure events. Reject missing/extra/duplicate IDs; no failed-case filtering. Do not widen the Qwen-only CUDA training/capture allowlist or reinterpret its v1 receipts. Model identity, prompt rendering and engine execution need independent evidence beyond content hashes.
3. Separate **static diagnosis** (same frozen observations; existing independent scorer) from **interactive read-only tool-use** (same isolated scenario snapshot, allowlisted tool schemas, deterministic replayable responses, step/timeout/output limits). A new interactive transcript scorer is needed; static prompt success does not establish agent tool-use success. Do not grant shell or cluster mutation rights to a model. Tool proposals are parsed and checked outside the model; rejected proposals remain in the transcript.
4. Independently score frozen captures against private Oracle. Preserve exact model/quantization, template, sampling, seed, prompt and transcript hashes, observation timestamps and raw tool responses, evaluator revision, and all failures. Report actual scope and per-family denominators; synthetic cases test the contract only.

#### Quality and safety measures

- RCA accuracy / root-cause family and per-case causal support (do not substitute semantic similarity).
- Citation validity (references resolve to immutable observed artifacts), claim-level support precision, and coverage of independently labeled essential evidence. An existing evidence ID alone does not establish that it supports a claim.
- Tool JSON/schema validity, allowlist and argument/scope correctness, successful calls, redundant calls, budget exhaustion and rejected unsafe proposals; separate syntax from semantic correctness.
- Appropriate UNKNOWN/abstention under stale, missing, contradictory or out-of-scope evidence; report false confident diagnosis and false abstention separately.
- End-to-end incident resolution of the **diagnosis** task, not physical recovery or authorized remediation; include tool failures, malformed output and timeouts in the fixed denominator.
- Negative gates: zero accepted fabricated/dangling evidence, zero unauthorized executions, zero Oracle exposure; evidence tampering, malformed responses and missing independent verification must HOLD/UNKNOWN. An attempted unsafe proposal is a model-quality failure even if the guard blocks execution.
- Freeze thresholds and sample sizes before blind runs; compare paired per-case results, stratified by fault family, with >=3 seeds/repeats when practical and uncertainty intervals. Do not claim superiority from a single synthetic case or tune on the test split. Model/quant/backend promotion requires independent review and a predeclared quality/cost tradeoff relative to the baselines.

#### Serving and task economics (separate from quality scoring)

Run fixed prompt/output-length microbenchmarks (e.g. 2K/8K/32K prompt, 256 output tokens where supported) and a separate full-task benchmark with identical task/tool/token/time budgets. Use concurrency 1/4/8 where memory permits, explicit cold/warm prefix cache states, speculation OFF then ON on the same backend/model and workload. Record unsupported cells, OOM, timeouts and actual token counts rather than silently changing settings.

| Dimension | Report |
| --- | --- |
| Prefill | input tokens/s, prefill time, cache-hit state; TTFT separately includes queue/transport |
| Decode | output tokens/s per request, inter-token latency, p50/p95; aggregate batch throughput separately |
| Speculation | OFF/ON, draft configuration, acceptance rate/length, quality regression and resource overhead |
| Resources | peak VRAM/RAM, weights, KV and convolution-state allocation where instrumented, GPU seconds, OOM/preemption, batch/context sizes; unknown telemetry stays unknown |
| Task | wall time including tools, completion rate, input/output tokens, tool count, cost per successfully verified diagnosis with failed-task costs included |

Never infer decode speed from prefill throughput, individual speed from batch tokens/s, or cost from active parameter count. On fixed weights, the middle 12 layers run three times (24 physical layers, 48 layer applications); the vLLM implementation maintains distinct KV and convolution state per visit. Weight sharing does not imply state sharing. Cache bytes depend on attention window, cache dtype/layout, batch/context, allocator and draft state; measure rather than multiplying a generic cache formula.

#### Ownership and integration boundary

- **sre-agent** owns task fixtures, scoped observations, quality metrics, raw transcripts and independent diagnostic evidence. It uses a model endpoint/adapter, not an embedded scheduler or inference kernel stack.
- **XPUlink** research owns backend capability probing, pinned engine compatibility, serving telemetry, quantization/kernel and multi-pass cache tests. Publish measured capabilities: model revision, backend build, device class, physical layers, loop passes, effective layer applications, cache/conv state estimates and observed peak bytes, context/concurrency, speculative mode and measurement receipt. Do not expose dynamic loop control for the fixed-loop release.
- **Compute Control Panel** consumes a versioned measured serving profile to estimate capacity/admission/cost; allocated GPU seconds and actual usage remain distinct. Unmeasured capabilities are unknown, not zero; unsupported configurations must not be scheduled as validated. No change to CCP admission authority, no new mandatory cross-repo dependency until an API contract is independently verified.
- **ACP/EngageGuard** remains the only policy/permit authority; the model cannot grant permissions, self-grade or certify recovery. Temporal remains the durable workflow owner.

Prefer a narrow offline evaluation adapter over rewriting the existing Go investigator or training stack around one model. A remote/local OpenAI-compatible adapter is a possible transport, not evidence that its model/parser/runtime identity is genuine. CPU-only contract development and replay can proceed without a GPU; model execution, hardware validation and diagnostic uplift remain NOT_RUN until independently captured.

### P1 — SFT/GRPO only after baseline and gap analysis

Reuse Draft [#11](https://github.com/avaargsh/sre-agent/pull/11) offline `sre.grpo.episode/v1`, Oracle reward and holdout audit; keep existing Qwen3 training lane separate and do not merge/promote synthetic training contracts as a trained model. Training is not a prerequisite for Inkling evaluation.

Only begin training once the independently scored baseline identifies a repeatable gap, and the selected model's trainer/adapter/quantization support is independently qualified. Do not assume Inkling LoRA/GRPO compatibility from Qwen support or upstream serving support. Preserve the existing Qwen-specific safety gates.

- Independently authenticated actual lab episode intake; fault-family split and normalized cross-split duplicate/near-duplicate audit.
- Reproducible pinned/hash-locked training stack and explicit GPU backward/optimizer/weight-delta proof for the selected checkpoint.
- Same-lineage Base vs SFT vs GRPO comparison on frozen holdout, identical prompts/budgets and >=3 seeds when practical. Cross-model or cross-quant comparisons are not training uplift.
- Reward-hacking checks: no Oracle/admin labels in observer context; no model-supplied costs or Judge rewards; no shortening workload, hiding failures or early stop treated as success.
- Independence: Oracle truth, evidence judging and risk calibration are separate from observer/policy authority.

**Prohibited claims:** synthetic rewards = gradient learning; package import = verified GPU training; model benchmark = SRE accuracy; trained model = production remediator.

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
