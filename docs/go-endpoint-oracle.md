# G2g — Evidence-backed EndpointSlice readiness Oracle (disposable kind)

This is a **read-only endpoint-availability observation and independent
admin-injected lab evaluation**, not a generalized causal RCA agent or an
automated production remediation. Keep the stacked PR Draft.

## Why another fault family

G2e–G2f proved only two Service specification regressions (targetPort and
selector). G2g introduces a **different operational mechanism**: test admin
scales the healthy checkout Deployment from two replicas to zero while
leaving Service ports and selector unchanged. Kubernetes EndpointSlice
readiness transitions from >0 to 0, and real service HTTP probes fail.
Admin scales back to two replicas; both EndpointSlice readiness and HTTP
requests must recover. The observer sees only Service GET and EndpointSlice
LIST, not the injected scenario, admin truth or client-probe results.

A zero-ready EndpointSlice is an *observation*: it is insufficient to distinguish
a backend crash, downscale, readiness failure, failed rollout, lack of eligible
Pods, or EndpointSlice-controller fault. Accordingly, the model-independent
baseline uses **NO_READY_ENDPOINTS_OBSERVED**, not BACKEND_DOWN_CONFIRMED.

## Read-only commands

\`sre-agent diagnose-endpoints\` consumes frozen Kubernetes Service and
EndpointSliceList JSON obtained from a separate read-only identity. Its
operator-supplied healthy targetPort and Service selector are explicit,
and should eventually be bound to a separately authorized ACP policy.

\`\`\`bash
go build -o /tmp/sre-agent ./cmd/sre-agent

/tmp/sre-agent diagnose-endpoints \
 --observed-service /tmp/observed-service.json \
 --observed-endpointslices /tmp/observed-endpointslices.json \
 --expected-target-port 8080 --expected-selector app=checkout-api \
 --out /tmp/endpoint-prediction.json

# test-admin supplies this file only *after* the prediction is frozen
/tmp/sre-agent evaluate-endpoints \
 --episode /tmp/admin-endpoint-episode.json \
 --prediction /tmp/endpoint-prediction.json \
 --out /tmp/endpoint-evaluation.json
\`\`\`

\`Diagnose\` validates Service metadata, port/selector, bounded complete
EndpointSliceList, namespace, target Service ownership label, unique slice UID,
explicit boolean EndpointReady conditions and raw JSON. If multiple Service
configuration errors also occur, it abstains UNKNOWN rather than guessing
why endpoint readiness changed. Output preserves exact source bytes and SHA256.

\`Evaluate\` independently replays before/during/after captured Service and
EndpointSlice sources, checks same Service UID/resourceVersion and unchanged
port/selector, checks healthy ready endpoints before+after, checks at least three
real HTTP successes before+after, and the expected during-phase readiness and
HTTP failures in the injected case. It replays the observer's actual response
and forbids unsupported classifications, forged counts/digests and invented
recovery. Exit 3 / UNKNOWN / no output file means fail closed.

## Run disposable kind

\`\`\`bash
kind create cluster --name golden-endpoint
bash demo/go-endpoint/run-kind.sh
kind delete cluster --name golden-endpoint
\`\`\`

CI: [go-endpoint-kind](../.github/workflows/go-endpoint-kind.yml) uploads
\`go-endpoint-kind-proof\`: Service and EndpointSlice raw responses,
separately gathered in-cluster HTTP codes for all 3 phases, observer
prediction, independent test-admin episode, final assessment, and negative
case logs.

The two bounded cases are (1) unchanged healthy control and (2) **real**
Deployment 2 → 0 → 2 fault, with independent HTTP probes 200 → 000 → 200.
The zero-endpoint verdict is \`MATCHED_INJECTED_OUTAGE\` only against the
test-admin labelled incident; \`production_causality_verified=false\` always.

### Security and source limitations

- **Kubernetes RBAC cannot scope EndpointSlice LIST by labelSelector**;
  the ServiceAccount is namespace-scoped and can list *all* EndpointSlices
  inside the disposable \`golden-demo\` namespace. This is broader visibility
  than the named-Service GET. Do not directly copy this role into a shared
  production namespace without a narrower collector/mediator.
- The test administrator alone creates and reverts faults; the observer
  cannot write Deployments, Services, Pods, or Secrets.
- Checksums confirm local data integrity, **not** the provenance of the
  API server, token, administrator, approved baseline, or test-run identity.
  The three Kubernetes snapshots are not one atomic transaction.
- A no-ready-endpoints observation does not explain the **cause**. No
  NetworkPolicy/DNS/CNI fault was injected, no counterfactual model eval,
  no independent source signatures, ACP approval or production recovery
  were proven. There is one normal control plus one endpoint outage.
- Historic 4-repository Python acceptance, separate security review and
  G0→G1→G2a→G2b stacked merges remain blocked/uncompleted. **Do not merge
  or change Draft/release status based on this narrow result.**
