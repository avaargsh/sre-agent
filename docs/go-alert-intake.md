# G2n — Alertmanager → deterministic read-only SRE Incident plan

> Experimental Go entrypoint. This is an **offline** plan, **not** a network-facing webhook listener, authenticated Alertmanager subscription, an authorized ACP Run or automatic Kubernetes investigation.

## Why it exists

The legacy Python `incident_from_alertmanager` uses a random UUID when `groupKey` is unavailable. That is convenient for an example but unsafe as a retry/deduplication identity. The Go `plan-alert` command requires a stable Alertmanager group key, binds it to separately supplied operator cluster/namespace/deployment scope, and records the original alert payload's SHA-256 separately from the stable incident ID.

This mirrors the useful "alert → investigation" user workflow popularized by HolmesGPT without exposing any autonomous tool or cluster write capability.

## Usage

Save the original Alertmanager webhook JSON to a mode-0600 file `alert.json`. The payload must be a **firing** alert group with matching `commonLabels.cluster`, `commonLabels.namespace`, `commonLabels.deployment`, and at least one firing alert. Each alert must have a distinct lowercase hexadecimal fingerprint and explicitly matching **cluster, namespace and deployment** labels. A group-wide commonLabels.cluster does not substitute for a missing member cluster label; the snapshot is not an authenticated source.

The **operator**, not the alert itself, supplies the allowed cluster and Kubernetes target. A mismatched common label or alert label fails closed:

```bash
go run ./cmd/sre-agent plan-alert \
  --file alert.json \
  --cluster lab-a \
  --namespace golden-demo \
  --deployment checkout-api \
  --out incident-plan.json
```

The created output has mode **0600**, with these bounded fields:

```json
{
  "schema_version": "sre.alert-plan/v1",
  "status": "READ_ONLY_CANDIDATE",
  "incident_id": "alert-<stable-scoped-hash>",
  "target": {"cluster": "lab-a", "namespace": "golden-demo", "deployment": "checkout-api"},
  "group_key": "...",
  "summary": "...",
  "severity": "sev2",
  "firing_alerts": 1,
  "raw_sha256": "<exact-payload-bytes-hash>",
  "source_authenticated": false,
  "authorizes_execution": false
}
```

A successful command exits **0**; malformed, stale/resolved, duplicate-key, invalid Unicode, cross-target or otherwise unusable payload exits **3** with `UNKNOWN` and creates **no plan**; output-path conflict / I/O error exits **1** and never overwrites an earlier file; invalid arguments exit **2**.

## Manual read-only follow-up

The command only prepares an incident identity and scope. A human may separately invoke the existing scoped `investigate` command using the `incident_id`, `summary`, `severity` and target fields, with existing read-only Kubernetes credentials and a Prometheus query selected by the operator. There is **no implicit bridge**, no untrusted Alertmanager-provided endpoint or tool permission, and no retrying execution solely because a group key matches.

When the standard Alertmanager webhook reports `truncatedAlerts`, its value must be the JSON integer `0`. Positive counts mean omitted alerts, so the group is rejected as `UNKNOWN` rather than treated as a complete scoped group. Invalid types and case aliases are also rejected. Older fixtures without the field remain compatible; absence is not proof of completeness or source authenticity. See [Alertmanager webhook configuration](https://prometheus.io/docs/alerting/latest/configuration/).

A stable incident ID does not mean the same alert bytes. `raw_sha256` changes if the notification changes (such as updated annotations) while the identity stays stable. Callers that want true deduplication must use an external transactional journal/unique key; this CLI by itself cannot ensure exactly-once processing across machines.

## Explicit evidence and trust boundaries

- Reject malformed JSON, duplicate nested or escaped aliases, invalid UTF-8, unpaired UTF-16 surrogate escapes, trailing documents, over-1-MiB input, groups with 0 or >64 alerts, duplicate fingerprints, missing group key, resolved-only notifications, or mismatched target labels.
- Source bytes and the SHA-256 digest are **not authenticated**: a forger may create payload and digest together. A production webhook needs authenticated reverse proxy / signature policy, replay controls and trusted cluster routing upstream.
- Alert status and summary are **not incident causality**; no Oracle, SLI recovery, ACP permit, auto-remediation, OpenAI tool execution or model accuracy claims derive from this plan.
- This command is independent of the still-Draft Go source integrity PR #14; future common source-schema validation can be deduplicated after that security gate merges.

## Acceptance

- `go test -race ./...`, `go vet ./...`, and `go build ./cmd/sre-agent` at exact PR head.
- TDD negative tests: cross-namespace/cluster, nested/escaped duplicate keys, malformed Unicode, resolved-only group, missing fingerprint, oversized input, replayed existing output.
- Legacy Python tests remain green; any kind CI triggered by the changed Go CLI is separate integration evidence, **not** a real authenticated alert ingestion proof.
