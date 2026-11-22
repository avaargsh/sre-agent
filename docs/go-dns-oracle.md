# G2h — Real isolated client DNS failure with direct-IP control

**Draft-only, read-only SRE observation, no production-root-cause or automated remediation claim.** This is stacked on G2g [PR #4](https://github.com/avaargsh/sre-agent/pull/4) and intentionally separated into a smaller PR for independent review.

## Test design and authority boundaries

One disposable kind cluster contains a healthy checkout Service on port 8080, and **two separate one-shot client Pods** executing the exact same Python probe:

- `dns-good`: Kubernetes `dnsPolicy: ClusterFirst`. It must resolve `checkout-api.golden-demo.svc.cluster.local`, and both domain-name HTTP and direct ClusterIP HTTP must return 200.
- `dns-bad`: test-admin-injected `dnsPolicy: None`, `dnsConfig.nameservers: [127.0.0.1]`, `timeout=1` and `attempts=1`. It must fail hostname resolution while a direct request to the **same live Service ClusterIP** succeeds with HTTP 200. A domain failure *plus* direct IP failure is **UNKNOWN**, not DNS-only diagnosis.

The experiment therefore isolates a **client-specific resolver misconfiguration**, not a cluster-wide CoreDNS outage, CNI bug, EndpointSlice-controller failure, or production DNS root cause.

The SRE observer has only GET access to `pods/dns-good`, `pods/dns-bad` and their logs. It cannot create/patch Pods, use `pods/exec`, read Secrets or list arbitrary Pods. The probe Pods themselves have `automountServiceAccountToken: false`, never use Kubernetes credentials, and only emit a frozen JSON log.

`diagnose-dns` accepts the log; it never receives the admin's fault label, Pod spec or separately collected witness. It derives only one of:

- `HEALTHY_NAME_AND_IP` — DNS resolution and both HTTP paths succeed;
- `DNS_FAILURE_WITH_IP_REACHABLE` — hostname lookup fails but direct-IP HTTP succeeds;
- `UNKNOWN` — contradictory, incomplete or insufficient evidence; no specific root-cause assertion.

The independent `evaluate-dns` gate then compares the observer's reports to test-admin-frozen raw Service/POD specs and two admin-captured probe logs. It checks the exact source-byte SHA-256 digests, Service ClusterIP and namespace, Pod identity, Pod completion, both Pod environment targets, expected real DNS policies, in-pod `/etc/resolv.conf`, and observer/admin source byte equality. A successful score is narrowly `MATCHED_ISOLATED_DNS_FAULT`, with `production_causality_verified=false`.

### Reproduce with disposable kind only

```bash
kind create cluster --name golden-dns
bash demo/go-dns/run-kind.sh
kind delete cluster --name golden-dns
```

The script creates only disposable test Pods and does not change any production resource. CI [go-dns-kind.yml](../.github/workflows/go-dns-kind.yml) runs the same experiment and uploads original test-admin Pod specs, original logs, separate read-only log captures, observations, and the evaluator result.

The negative cases deliberately forge the classifier label, the observer's target IP, the admin Pod DNS nameserver (including a matching recomputed SHA), and contradictory DNS/direct-IP evidence. Each must exit 3 / UNKNOWN without producing any evaluation file.

## Limitations and next gates

This single known-configuration fault cannot determine whether a production DNS incident stems from CoreDNS, upstream forwarding, local resolver, CNI egress, NetworkPolicy, application caching or other causes. The deterministic Go diagnostic is **not an LLM/GRPO SRE Agent model evaluation**. The test-admin is a trusted lab operator, not a cryptographically authenticated truth authority. SHA-256 only binds local file bytes; it does **not** attest to the source cluster, observation identity, ACP approval or execution epoch. A malicious source controlling all files and digests remains out of scope.

The inference is narrow and fail-closed; no agent-initiated writes, repairs, cross-namespace privileges or production changes. G0/G1/G2a/G2b stacked merge order, independent security review, historic four-repo acceptance and signed evidence remain open. **Keep PR Draft.**
