# SRE Agent v0.1 — Evidence-first Golden Incident & evaluation gates

> Status: engineering plan, **not** a production-readiness report. Snapshot: 2026-11-22. Target: `avaargsh/sre-agent`; Go-native investigator with frozen Python compatibility, optional isolated Python model-training experiments. No duplicate ACP/Temporal control plane.

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

Go G0 PR [#1](https://github.com/avaargsh/sre-agent/pull/1) merged into `main`; its `STRUCTURALLY_VALID` verdict is **shape+digest only**, not authenticated provenance, causal truth or recovery. Complete [#12](https://github.com/avaargsh/sre-agent/pull/12) malformed UTF-8/unpaired-surrogate strict parser review before promoting consumer-facing hashes.

**Contract negatives:** duplicate keys (including nested), bad Unicode, trailing JSON, oversize bundle, missing/dangling evidence refs, unsupported explicit schema, cross-language Python SHA parity. No claim that a valid hash authenticates the source.

### P0-B — G1 observer and alert entry

Existing G1 [#2](https://github.com/avaargsh/sre-agent/pull/2) contains scoped Go Deployment/Pod + Prometheus collection; do not duplicate it. Extend/review with:

1. Stable Alertmanager groupKey/fingerprint + namespace/deployment routing, replay dedup and bounded timeout; no caller-supplied tenant privilege escalation.
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
| Alert entry | Fixed id/dedup; one `Run`/incident for replayed alert; exact source+time | Missing/ambiguous ownership, replay side effects, unbounded fanout |
| Read-only observation | Real kind ServiceAccount; only required GET/LIST and source hashes; original response artifact | Any secret/scale write, malformed/duplicate JSON, stale SLI, page truncation, unsupported redirect -> UNKNOWN |
| Diagnosis | Hypothesis cites existing evidence IDs; separate independent Oracle; negative control abstains | Unsupported root cause, fabricated refs, model reads injector truth, treats successful GET as recovery |
| Recovery semantics | Distinct pre/during/post SLI and independent verifier for a deliberately injected fault | Partial/single sample or non-finite series marked VERIFIED |
| Reproducibility | Exact SHA/HEAD, dependency lock, test command, CI artifact, private Oracle, failure transcript | Green CI attributed to a different commit or hand-authored summary alone |
| Authorization | Only read-only credentials in v0.1; production writing disabled | Any model-initiated Kubernetes mutation without ACP Permit |

## Branch hygiene — verify before deleting any remote ref

Snapshot **2026-11-23**: 17 remote heads in `avaargsh/sre-agent` —
`main`, 10 old heads of merged PR #1–#10, and six live PR heads
#11–#16. PR #16 is stacked on **unmerged** PR #15; do not delete
either one. PR #12, #13 and #11 are still Draft; #14/#15 are Ready but
require a non-author independent review. No branch is eligible merely
because a local CI job was green.

The ten merged heads were independently checked against their respective
GitHub squash merge commits: **for every PR #1–#10, the HEAD Git tree SHA
equals the merged commit Git tree SHA**. Thus their snapshot contents
were preserved in `main`. This checks content, **not** remote ref
deletion. The repository has `delete_branch_on_merge=false`.

The following operator command is deliberately **dry-run by default**.
Use an authenticated GitHub CLI session with repository write access; it
re-checks the PR merged flag, exact head branch name/SHA, and merged-tree
equality immediately before any deletion. It will abort on drift. Run
first without `APPLY_DELETE=1`, inspect all ten printed candidates and
only then opt in to deleting those remote refs.

```bash
set -euo pipefail
repo=avaargsh/sre-agent
gh auth status
for n in $(seq 1 10); do
  pr=$(gh api "repos/$repo/pulls/$n")
  merged=$(jq -r '.merged' <<<"$pr")
  name=$(jq -r '.head.ref' <<<"$pr")
  owner=$(jq -r '.head.repo.full_name // ""' <<<"$pr")
  head=$(jq -r '.head.sha' <<<"$pr")
  merge=$(jq -r '.merge_commit_sha' <<<"$pr")
  [[ "$merged" == "true" && "$owner" == "$repo" ]] || {
    echo "STOP PR #$n is not merged or is a fork"; exit 1;
  }
  [[ "$name" != "main" && "$name" != "feat/sre-grpo-offline-contract-v1" ]] || {
    echo "STOP protected branch $name"; exit 1;
  }
  live=$(gh api "repos/$repo/branches/$name" --jq '.commit.sha')
  [[ "$live" == "$head" ]] || { echo "STOP branch $name moved"; exit 1; }
  old_tree=$(gh api "repos/$repo/git/commits/$head" --jq '.tree.sha')
  merged_tree=$(gh api "repos/$repo/git/commits/$merge" --jq '.tree.sha')
  [[ "$old_tree" == "$merged_tree" ]] || {
    echo "STOP PR #$n has unmatched merged-tree content"; exit 1;
  }
  echo "VERIFIED SAFE merged PR #$n: $name@$head"
  if [[ "${APPLY_DELETE:-0}" == 1 ]]; then
    gh api --method DELETE "repos/$repo/git/refs/heads/$name" >/dev/null
    echo "DELETED $name"
  fi
done
# Only after explicit opt-in deletion, confirm the live branches:
gh api "repos/$repo/branches?per_page=100" --jq '.[].name'
```

To actually delete verified historical refs, run the same command with
`APPLY_DELETE=1` in its environment. Do not move old heads, force push,
or delete open PR heads as a substitute for safe branch cleanup.
**No deletion is claimed until the live branch list confirms it.**

## Shipping rule

Go #1–#10 are merged into development `main` as experimental evidence/Oracle/LAB baselines; do **not** retroactively call them production-certified. Keep still-open PR #11–#16 under exact-head CI, relevant independent reviews and branch rules before merging. GRPO training remains Draft, not real Qwen3/GPU training proof. Do not silently weaken the historic `four-repo-acceptance` workflow because legacy pinned repositories became inaccessible; replace it only after an explicitly designed ACP/Temporal authority migration has its own acceptance evidence.

**First user demo target:** one alert, a single CLI command, a printable evidence-linked RCA/UNKNOWN report, and the reproducible independent kind benchmark that can tell whether the diagnosis was actually correct.
