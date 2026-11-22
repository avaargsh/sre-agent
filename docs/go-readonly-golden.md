# G1: Go read-only Golden Observation

This PR is stacked on [G0 PR #1](https://github.com/avaargsh/sre-agent/pull/1) and adds **only** a source-backed observation slice. It does **not** implement root-cause verification, write operations, approval, Temporal recovery or SLI recovery attestation.

## Contract

- Exactly three bounded HTTP GET reads: namespaced Deployment, Deployment-selector Pod list and Prometheus instant-vector query.
- HTTP on loopback only; remote endpoints must use HTTPS. No redirects. Kubernetes bearer token never goes to Prometheus.
- Kubernetes must return namespaced resource UID/resourceVersion and valid selector, and Pod list must have resourceVersion. Response limit: 2 MiB; Pod limit: 100.
- Prometheus must return between 1 and 32 valid numeric, fresh (default 90s) series, all validated; empty/stale/NaN/+Inf/non-vector causes UNKNOWN.
- Go's `aiops.evidence/v1` bundle has two observations, **zero** supported RCA hypotheses, `observation_status=complete` and a SHA-256 consistent with the existing Python-v1 frozen evidence format.
- UNKNOWN causes exit 3 and **no evidence bundle written**; existing files are never overwritten. A complete read does not imply a complete snapshot across both sources, business recovery, causality, or signed evidence.

## Disposable kind recipe

```bash
./scripts/setup-golden-kind.sh
kubectl apply -f demo/k8s/sre-agent-readonly-rbac.yaml
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
kubectl -n golden-demo rollout status deploy/prometheus --timeout=180s

# Create a short-lived token with only Deployment get and Pod list permissions.
kubectl -n golden-demo create token sre-agent-reader --duration=10m > /tmp/sre-reader.token
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/sre-ca.pem
KUBE_API="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"

# Separate terminal: kubectl -n golden-demo port-forward svc/prometheus 19090:9090

go run ./cmd/sre-agent investigate \
  --namespace golden-demo --deployment checkout-api \
  --incident-id inc-go-checkout-001 --summary 'checkout latency' \
  --kube-api "$KUBE_API" --ca-file /tmp/sre-ca.pem \
  --kube-token-file /tmp/sre-reader.token \
  --prometheus http://127.0.0.1:19090 \
  --out /tmp/sre-go-checkout-evidence.json

go run ./cmd/sre-agent verify-bundle --file /tmp/sre-go-checkout-evidence.json
```

The `go-readonly-kind` CI job additionally proves the actual ServiceAccount cannot patch Deployment scale or read Secrets before it runs the Go CLI using that identity.

## Limitations and next gates

- Deployment-to-Pod readings are not an atomic Kubernetes snapshot. No Deployment change timeline, contradicting hypotheses, live logs or multi-incident correlation are claimed.
- Source responses are projected into bounded Evidence attributes. Original API responses are not yet independently signed/stored.
- The standalone command uses a configured instant PromQL, not a sustained post-remediation SLI Oracle.
- G2 requires independent verifier, source-hash provenance, change-aware corroboration and explicit UNKNOWN handling.
- G3/G4 requires ACP-issued permit, Temporal durability, generation/UID CAS safety, SIGKILL/UNKNOWN recovery and separate approval for any compensation.
