# G2f — Two real Service fault families, one no-fault control

**Status:** implementation / CI proof in Draft PR #4; not a production release, no Agent write or self-issued recovery authority.

## Why this slice

G2e demonstrated one real kind-only Service targetPort misroute, with independent test-admin HTTP probes and a separate read-only observer. G2f expands this into **two physically different Service failure modes** plus a normal control while keeping candidate claims and injected truth separated.

| Episode | Test-admin action | Frozen read-only diagnosis | Oracle requirement |
| --- | --- | --- | --- |
| `control` | No fault | `UNKNOWN` (no fault diagnosed) | Three HTTP 200s in each phase |
| `misroute` | Set Service `targetPort` from 8080 to 1 | `SERVICE_TARGETPORT_MISROUTED` | Three before 200, three fault 000, three after 200 |
| `selector` | Set Service selector from `app=checkout-api` to `app=checkout-no-match` | `SERVICE_SELECTOR_MISMATCH` | Three before 200, three fault 000, three after 200 |

The test administrator alone applies and reverts faults; the SRE observer uses a separate bearer-token Kubernetes config limited to `get service/checkout-api`. The observer is given **operator-originated healthy baseline** (`targetPort=8080`, `app=checkout-api`) but is **not given the injected scenario label, before/after probes, or oracle episode** before producing its prediction.

`internal/oracle` now distinguishes port and selector mismatch, conservatively abstains `UNKNOWN` for simultaneous mismatches, and requires the selector-fault diagnosis to include the expected baseline. The Oracle verifies Service UID, selector/port changes, recovery and all three independent HTTP probe phases against frozen source-response bytes. The negative cases for tampered source, forged prediction and false recovery remain mandatory.

## Running

Disposable cluster *only* (injected Service edits must never run in production):

```bash
kind create cluster --name golden-oracle
bash demo/go-oracle/run-kind.sh
kind delete cluster --name golden-oracle
```

CI: [`.github/workflows/go-oracle-kind.yml`](../.github/workflows/go-oracle-kind.yml). Original evidence is uploaded under `go-oracle-kind-proof`, including `{control,misroute,selector}/` raw K8s Service snapshots, HTTP probes, predictions and evaluations, plus `suite-summary.json`.

The `demo/go-oracle/score_suite.py` summary records counts, not extrapolated rates: `episodes`, `fault_episodes`, `normal_controls`, `correct_fault_classes`, `correct_normal_rejections`, `false_positive_controls`, `fault_abstentions` and `wrong_fault_classes`. `population_metrics_supported=false` and `production_causality_verified=false` are explicit. One healthy control cannot estimate a useful fleet false-positive rate, and two injection classes cannot support a general RCA accuracy estimate.

## Limits and merge gates

- Rules are **hand-coded baselines**, not LLM-generated RCA or GRPO/SFT quality evidence. This is a narrow *known-baseline configuration-drift detection experiment*.
- Both injected faults involve Kubernetes Service configuration. Neither proves NetworkPolicy, CNI, DNS, EndpointSlice controller, connection tracking, backend crash or GPU model-serving RCA. Service selector mismatch produces connectivity failure, but the collector does not independently inspect actual EndpointSlice membership.
- The administrator's fault truth and the operator's healthy target/selector baseline are not signed or cryptographically tied to ACP identity/approval. Source SHA-256 alone cannot authenticate evidence.
- The resulting `MATCHED_INJECTED_FAULT` verdict means an injected lab fault matched a rule, **not** causal proof for an arbitrary production incident.
- Independent review, additional realistic faults, held-out cases, contradictory evidence, false-positive sampling, historical 4-repo blocker, and ordered G0/G1/G2a/G2b PR merges remain open. Keep this PR Draft.
