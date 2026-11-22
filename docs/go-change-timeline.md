# G2b — Kubernetes Deployment / ReplicaSet Change Timeline

**Scope:** Read-only, single-namespace / single-Deployment change evidence. This is stacked on G2a PR #3, G1 PR #2 and G0 PR #1. No automatic RCA, remediation, ACP authorization or durable agent execution is implemented here.

## Why

"An incident followed a deployment" is a *temporal correlation*, **not proof that the deployment caused the incident**. This slice creates a reproducible observation of an actual Kubernetes rollout without elevating an Agent-generated hypothesis to an established cause.

## Read contract and evidence

`sre-agent collect-changes` issues **three HTTP GETs** in order:

1. Namespaced Deployment get; require a stable UID, resourceVersion, generation and matching observedGeneration.
2. Namespaced ReplicaSet list; limit 129, reject any continuation token, and select only ReplicaSets whose controller OwnerReference exactly matches the Deployment UID. Reject malformed/duplicate matching UIDs, invalid revision annotation and timestamps. This is not an atomic point-in-time snapshot.
3. Namespaced Deployment get again; if UID, generation or resourceVersion changed between the bracketing reads, fail closed as UNKNOWN. The ReplicaSet list can still change independently, so no stronger consistency guarantee is claimed.

Output is `sre.change-timeline/v1` with sorted owned ReplicaSet revisions, exact raw Kubernetes response bytes encoded as Base64, independently checkable SHA-256 for each of three reads, and explicit `relationship`.

- `TIME_OVERLAP_ONLY` means an owned ReplicaSet was created inside the caller-supplied incident time window; **RCA remains UNVERIFIED**.
- `NO_REVISION_CREATED_IN_WINDOW` means no *retained, controller-owned* ReplicaSet in the observed list was created inside that window. It does **not** rule out configuration, node, networking, autoscaling, eviction, deleted revisions or external dependency changes.
- Any incomplete, denied, drifting, untrusted or inconsistent read returns `UNKNOWN` as exit status 3. No report file is created on failure.

The caller supplies incident start/end timestamps. This CLI does not establish that they are independently authenticated: a future ACP integration must bind trusted incident evidence and the time-window authority. An HTTP response checksum does **not** authenticate Kubernetes or prove causality.

## Manual kind execution

```bash
kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-changes/reader-role.yaml
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
kubectl -n golden-demo create token sre-change-reader --duration=10m > /tmp/sre-change-token
chmod 600 /tmp/sre-change-token
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/sre-change-ca.pem
API="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
START="$(date -u -d '2 minutes ago' +%Y-%m-%dT%H:%M:%SZ)"

# Optional: a disposable test admin can initiate a rollout.
# This NEVER runs under the SRE Agent's read-only identity.
kubectl -n golden-demo rollout restart deploy/checkout-api
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

go run ./cmd/sre-agent collect-changes \
  --kube-api "$API" --namespace golden-demo --deployment checkout-api \
  --kube-token-file /tmp/sre-change-token --ca-file /tmp/sre-change-ca.pem \
  --start "$START" --end "$END" --out /tmp/sre-change-timeline.json
```

`go test -race ./...`, `go vet ./...`, and the `go-change-kind` workflow must pass. CI confirms that the actual scoped ServiceAccount can **get Deployment** and **list ReplicaSets** but cannot patch Deployments or scale them and cannot get Secrets; the workload restart is performed only by the test runner's separate admin account.

## Next G2b/G2c work

- Add authenticated Deployment/ReplicaSet Events, ConfigMap and Helm/Git change references, topology, and reliable absence/retention semantics.
- Contrast competing hypotheses using independent metrics, logs, events, rollout revision history and counterexamples. Never convert timestamp overlap into SUPPORTED causal RCA without independently reproducible proof.
- Introduce versioned evidence packages with origin signatures, appropriate redaction, source identity binding and an independent reviewer.
- Preserve the existing G0→G1→G2a Draft dependency chain. The old Python four-repository acceptance remains blocked on `avaargsh/agent-control-plane` checkout; this change does not remove or weaken it.
