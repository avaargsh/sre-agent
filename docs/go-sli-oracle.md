# G2a — Independent SLI Oracle (Read-only)

This is a **narrow, stacked migration slice** on top of G0 and G1. It does not implement Change-Aware RCA, independent production trust isolation, ACP policy, durable execution, remediation, or recovery attestation.

## Contract

`sre-agent verify-sli` evaluates two *freshly queried* Prometheus `query_range` sources: latency and real request traffic. It does **not** accept or trust a model-generated `SUPPORTED`, `VERIFIED`, or `RECOVERED` conclusion.

- `HEALTHY`: every observed latency sample is at or below the configured threshold **and** every observed request rate is at or above the minimum in the complete window.
- `UNHEALTHY`: traffic suffices, but at least one latency sample breaches threshold.
- `UNKNOWN`: no traffic, missing points, a gap, duplicate series, stale/misaligned timestamps, invalid/NaN/Inf/negative values, an HTTP/JSON failure, an invalid query window, or a window predating a supplied trusted barrier. **UNKNOWN must not trigger automatic rollback, approval, or release.**

For each of the two GET requests the JSON result includes a Base64 encoding of the **exact original HTTP response bytes** (`raw_response_base64`) and `response_sha256` for independent readback. The assessment is written exclusively to a new mode-0600 file (or stdout). The response SHA-256 is a checksum, **not** a signature or proof of source identity; protect and independently pin the artifact in a real evidence store. Prometheus labels may contain sensitive metadata: do not publish raw artifacts without review.

## Manual CLI

Build with `go build -o /tmp/sre-agent ./cmd/sre-agent`, port-forward Prometheus and ensure the service receives **genuine traffic**. Run (replace the threshold with an operator-owned SLO):

```bash
/tmp/sre-agent verify-sli \
  --prometheus http://127.0.0.1:19090 \
  --latency-query 'max(checkout_request_latency_seconds)' \
  --traffic-query 'sum(rate(checkout_requests_total[20s]))' \
  --max-latency-seconds 0.35 \
  --min-traffic-rps 0.1 \
  --window 30s --step 5s \
  --out /tmp/sre-sli-evidence.json
```

Optional: `--not-before 2026-11-22T09:00:00Z` rejects any sampling window that begins before an externally supplied action-completion barrier. The CLI **cannot attest that this timestamp is authoritative**; G3/ACP integration must supply and verify that binding.

Exit statuses: `0=HEALTHY`, `4=UNHEALTHY`, `3=UNKNOWN`, `1=I/O error`, `2=invalid CLI arguments`. The assessment remains readable as JSON even on status 3/4, and neither path writes to Kubernetes.

## Reproducible checks

```bash
go test -race ./...
go vet ./...
go build ./cmd/sre-agent
```

`.github/workflows/go-sli-kind.yml` uses disposable kind and the checkout load-generator to demonstrate that fresh nonzero traffic can be distinguished from a deliberately impossible traffic threshold. This is an integration **SLI contract smoke test**, not an injected incident, valid RCA, approved action, rollback or sustained production recovery.

## Remaining work

- **G2b:** Deployment/ReplicaSet/config change timeline and competing evidence hypotheses; source-authenticated evidence, independent reviewer, resource UID/generation cross-checks.
- **G3:** ACP-validated immutable policy and observer identity, authoritative action completion time and authorization epoch; Temporal/UNKNOWN reconciliation.
- **G4:** bounded remediation + resourceVersion/UID CAS, fail-closed recovery, safe compensation policy; independent pre/post SLI and stable production thresholds.
- Legacy `four-repo-acceptance` currently fails checkout of `avaargsh/agent-control-plane`; treat this as an unresolved migration dependency. Do **not** delete that gate to claim the Python-era integration passed.
