# SRE Agent delivery roadmap — 2026-11-24

Coordination plan, not a release certificate. Observed main: `064ea714615cdc08ed515ab0187ef849f7b96a5a` (#51). The older [migration plan](go-rewrite-plan.md) and [Golden Incident plan](sre-p0-golden-path.md) remain valid as historical baselines. #50/#51 added LAB raw Rollout capture and publication race hardening, not verified CUDA training. #11 is open Draft and dirty; extract small missing slices, do not merge wholesale.

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
