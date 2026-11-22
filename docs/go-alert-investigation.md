# G2o — Alertmanager plan → read-only Evidence Bundle (experimental)

**Dependency:** stacked Draft PR #16 on [PR #15](https://github.com/avaargsh/sre-agent/pull/15). This is an **offline CLI demo**. It does not run an Alertmanager listener, authenticate alert provenance, authorize work, guarantee exactly-once, diagnose a root cause, or perform a remediation.

## Two-stage reproduction

The Alertmanager JSON must contain a firing group with a nonempty groupKey, matching common and member target labels, and unique member fingerprints. The alert file is treated as untrusted bytes. Store the exact original payload (no reformatting) in `alert.json`.

**1. Prepare a reviewable immutable plan** with operator-configured scope. `plan-alert` creates a mode-0600 new file and rejects resolved/cross-target/malformed notifications.

```bash
go run ./cmd/sre-agent plan-alert \
  --file alert.json --cluster golden-aiops \
  --namespace golden-demo --deployment checkout-api \
  --out incident-plan.json
```

**2. Independently review operator read access and explicitly select the two endpoints and PromQL.** Use a short-lived namespace-scoped reader token, not cluster-admin credentials. Then run:

```bash
go run ./cmd/sre-agent investigate-alert \
  --alert-file alert.json --plan incident-plan.json \
  --cluster golden-aiops --namespace golden-demo --deployment checkout-api \
  --kube-api "$KUBE_API" --ca-file "$KUBE_CA_PEM" \
  --kube-token-file "$READER_TOKEN_FILE" \
  --prometheus http://127.0.0.1:19090 \
  --query 'max(checkout_request_latency_seconds)' \
  --out incident-evidence.json

go run ./cmd/sre-agent verify-bundle --file incident-evidence.json
```

**3. Independently review all three original artifacts offline** — this performs no Kubernetes/Prometheus requests:

```bash
go run ./cmd/sre-agent verify-alert-evidence \
  --alert-file alert.json --plan incident-plan.json \
  --bundle incident-evidence.json \
  --cluster golden-aiops --namespace golden-demo --deployment checkout-api \
  --expected-query 'max(checkout_request_latency_seconds)'
```

A successful review returns JSON `sre.alert-evidence-review/v1` with `status=STRUCTURALLY_LINKED`, the stable incident ID, exact original alert SHA-256, plan-file SHA-256, canonical bundle SHA-256 and observation count. The fields `source_authenticated`, `authorizes_execution`, `root_cause_verified`, and `recovery_verified` are **always false**. Invalid, stale or mismatched inputs return `UNKNOWN` (exit 3), with no success receipt. The reviewer checks the incident ID/summary/severity and namespace/Deployment in Kubernetes evidence, exactly one Kubernetes plus one Prometheus source, operator-pinned PromQL, a full read-only observation and zero promoted hypotheses. Tests explicitly forge self-hashed but cross-incident, cross-namespace or cross-query bundles, which must still be rejected.

This is not a signed provenance chain. A malicious actor who controls all three files can forge mutually consistent hashes. The `index-evidence` / `sign-evidence` / `verify-evidence` v2 commands elsewhere in the repository can separately bind original files to an externally authorized Ed25519 key and exact workflow attempt, but that authorized signer policy and immutable artifact storage are **not** supplied by this offline command.

`investigate-alert` first recomputes the v1 plan **from the exact original alert file and independently supplied target**. It demands byte-for-byte equality with the canonical output of `plan-alert` (including the newline). It rejects a stale plan if annotations change, forged `source_authenticated`/`authorizes_execution` flags, changed target, extra/duplicate JSON keys, invalid or oversized files, and an existing output path. **No Kubernetes or Prometheus request happens before this preflight.** The existing Go `investigate` command owns all subsequent HTTP reads, TLS, timeouts, sample freshness, evidence generation and exclusive output creation.

The bundle's `incident.incident_id`, `summary` and `severity` are re-derived from the plan; its sources are currently Deployment, matching Pods and a Prometheus instant-vector query. The **separate** `incident-plan.json` carries the exact source alert SHA-256. This implementation does **not** embed a signed alert-identity or source-SHA chain in the Evidence Bundle itself. Preserve both original files and verify them together; a schema-valid SHA-256 is not a proof of source authenticity.

## Test and return codes

| Condition | Expected result |
| --- | --- |
| Matching fresh alert + exact plan + live sources | Exit 0, new mode-0600 v1 Evidence Bundle with **zero promoted RCA hypotheses** |
| Changed raw alert, corrupted plan, cross-target routing, expired/resolved notification, oversized input | Exit 3, `UNKNOWN`, no network reads and no bundle |
| Missing or stale Kubernetes/Prometheus data after valid preflight | Exit 3, `UNKNOWN`, no bundle |
| Output path already exists | Exit 1, old bytes unchanged; no unnecessary snapshot on the early conflict path |
| Incorrect command flags | Exit 2 |

The disposable-kind test in `.github/workflows/go-readonly-kind.yml` uses a **synthetic** Alertmanager notification, a **real** short-lived Kubernetes read-only ServiceAccount, **real** running Prometheus instant-vector samples, and a negative forged-plan case. It proves this narrow source-binding and read-only execution path, not a real Alertmanager firing event or a live injected incident RCA.

## Remaining production gates

- **Authenticity**: authenticated Alertmanager ingress, hardened source identity/cluster mapping and externally pinned policy; a user-supplied scope string and raw SHA cannot attest source.
- **Deduplication**: this CLI's stable incident ID is a correlation key only. A transactional journal or external idempotency authority is required for multiple concurrent hosts, restarted workers and retries.
- **Atomicity**: the three Kubernetes/Prometheus reads are not a single atomic snapshot. Reject incomplete source evidence; don't confuse a successful HTTP GET with root-cause proof or SLI recovery.
- **Boundaries**: keep G1/G2 native-source strict JSON hardening in [PR #14](https://github.com/avaargsh/sre-agent/pull/14) distinct from this stacked PR; both require review. ACP/EngageGuard/Temporal own any future approval, scoped Permit, durable execution and action reconciliation; the SRE Agent does not grant itself writes.
- **Acceptance**: exact-HEAD Go race/vet/build, legacy Python tests, disposable-kind original artifacts, independent reviewer and branch rule inspection. This PR stays Draft until its parent PR #15 and these gates are satisfied.
