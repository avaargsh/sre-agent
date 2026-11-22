# G2e — Disposable real Service misroute fault Oracle

This is a **small reproducible SRE diagnostic evaluation baseline**, not a general SRE Agent model-accuracy claim. It deliberately does not merge or grant any production remediation authority.

## Experiment and independent truth

The test administrator (GitHub Actions in a disposable kind cluster) records three phases:

- **Control / NO_FAULT:** Service `checkout-api` exposes port 8080 and routes to the running checkout application's targetPort 8080; HTTP `/healthz` works across all three phases.
- **Injected / SERVICE_TARGETPORT_MISROUTED:** administrator records a healthy baseline, patches the Service targetPort **to 1** while the application continues to listen on 8080, records HTTP request failures, then restores targetPort to 8080 and verifies successful probes. **Only** the test administrator can patch the Service.
- Each phase stores the **raw Kubernetes Service JSON**, its SHA-256 digest and three actual in-cluster HTTP probe codes. The test-admin record lives under `/tmp/go-oracle-proof/{control,misroute}/episode.json`. The recorded truth is *test-admin asserted*, not independently signed.
- An SRE observer with a **separate bearer-token-only Kubernetes config** has `get` on the named Service. It cannot patch, read Secrets or list Pods. The independent rule baseline reads that observed Service JSON, sees the operator-supplied healthy targetPort = 8080, and emits a frozen `sre.service-diagnosis/v1` prediction with its raw response digest.

The CLI commands are separate:

```bash
go build -o /tmp/sre-agent ./cmd/sre-agent

# Using a genuine GET Service response captured by the read-only SA:
 /tmp/sre-agent diagnose-service \
  --observed-service /tmp/observer-service.json \
  --expected-target-port 8080 \
  --out /tmp/service-prediction.json

# Independent administrator-generated episode. The detector must not see this
# file before it emits its prediction:
 /tmp/sre-agent evaluate-oracle \
  --episode /tmp/test-admin-episode.json \
  --prediction /tmp/service-prediction.json \
  --out /tmp/oracle-result.json
```

`evaluate-oracle` rehashes the **before/during/after** raw K8s snapshots, checks the Service UID, selector, service port and targetPort across phases, enforces **3–12 actual HTTP probe codes per phase**, and verifies the separate frozen observer prediction against its own raw Service response and the test-admin's *during* UID/resourceVersion/targetPort. It rejects summaries or probes that disagree with the raw evidence.

Two narrow verdicts are possible if the evidence is complete: `CORRECT_REJECTION` for the no-fault control, and `MATCHED_INJECTED_FAULT` for the one injected Service-port scenario. Both explicitly set `production_causality_verified=false`.

An incomplete or altered episode/prediction is **UNKNOWN** (CLI exit 3; no evaluation file). Neither a successful evaluation nor its proposed label can authorize write access. The rule-based baseline does not use an LLM and the deliberately chosen Service fault cannot measure performance on unobserved incidents.

## Run the exact test

```bash
# WARNING: the command below deliberately patches a Service. Run ONLY in
# disposable kind. The script contains an EXIT trap to restore targetPort.
kind create cluster --name golden-oracle
bash demo/go-oracle/run-kind.sh
kind delete cluster --name golden-oracle
```

CI runs the same script in [`go-oracle-kind.yml`](../.github/workflows/go-oracle-kind.yml), uploads original independent snapshots, three per-phase HTTP probes, predictions and Oracle scores. It asserts no-fault rejection, fault detection, successful recovery, strict RBAC, and negative tests for a forged prediction, a false recovery, and a tampered source digest.

**Boundaries:** this is a one-fault, one-control rule-based *lab* benchmark. The operator expected port and admin fault label are not cryptographically attested. Network requests themselves are not signed; packet traces, independent external client probes, real production outages and a cross-fault-class confusion matrix are still missing. It does not show that an LLM found the root cause. Further work needs externally authenticated fault injection/run labels, multiple realistic fault classes, adversarial concurrent changes, genuine withheld evaluation data, abstention and false-positive measurement across enough episodes to be meaningful, plus signed evidence tied to ACP.

Historic `four-repo-acceptance` remains blocked on retired pinned repos. Keep G0→G1→G2a→G2b/c/d/e PR stack **Draft**, no production-write authority.
