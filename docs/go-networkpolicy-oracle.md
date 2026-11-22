# G2i — Real Calico NetworkPolicy egress-denial Oracle

**State:** **Draft** PR #6, rebased by a two-parent reconciliation onto merged `main` (G0–G2h). This is a bounded,
disposable-kind network lab, **not** production RCA, automatic repair, model
accuracy, or authenticated evidence provenance.

## Why a separate network lab

The usual kind default networking can accept Kubernetes NetworkPolicy API
objects **without enforcing them**. The G2i test **disables kind's default
CNI** and provisions version-pinned Calico v3.33.0. The test must verify
the Calico DaemonSet, node readiness and **actual dataplane behavior**,
not just that a NetworkPolicy YAML was accepted. See
[Calico's kind installation instructions](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind)
and the [kind cluster configuration](https://kind.sigs.k8s.io/docs/user/configuration/).

## Threat model, roles, and test matrix

The test admin is the **only writer**, in a disposable cluster.
It installs the CNI, deploys the workload, injects/deletes the policy,
creates three bounded probe Pods, gathers admin proof and evaluates a
separate observer's original logs. The SRE observer ServiceAccount has
**GET only** for the three named probe Pods and their logs. It cannot
create/patch/exec Pods or access Secrets or NetworkPolicies. Each probe
Pod has `automountServiceAccountToken: false`.

| Independent phase | Kubernetes policy | DNS | Service/ready endpoints | Actual FQDN and direct-IP HTTP |
| --- | --- | --- | --- | --- |
| `before` | No NetworkPolicy | Resolves exact Service IP | Stable, Ready > 0 | HTTP 200 three direct-IP probes |
| `during` | `sre-g2i-deny-http` selects client Pod and allows **only** DNS port 53 | Still resolves exact Service IP | Unchanged, Ready > 0 | Both HTTP paths fail; three direct-IP failures |
| `after` | Admin deletes injected NetworkPolicy | Resolves exact Service IP | Still stable, Ready > 0 | HTTP 200, three direct-IP probes |

The change is a **Kubernetes Egress NetworkPolicy**, not a DNS fault,
backend replica downscale, Service selector/port error, or a Calico-specific
GlobalNetworkPolicy. The test restricts the **client**, not the checkout
backend. At each phase a separately created Pod probes the exact same
Service `checkout-api.golden-demo.svc.cluster.local:8080` and ClusterIP;
the browser/runner cannot impersonate this in-cluster dataplane.

### Dataplane startup stabilization (not scored)

The [Calico kind run #45044048997](https://github.com/avaargsh/sre-agent/actions/runs/45044048997) passed both Calico installation digest gates, but the first unmodified, no-policy baseline Pod recorded DNS success with FQDN HTTP failure and direct Service-IP attempts `[0,200,200]`. Treating this cold-start dataplane observation as proof of a sustained policy denial would be incorrect; the experiment failed closed.

A new, separate `np-preflight` Pod (distinct label and UID from the three scored Pods) performs **at most eight explicitly logged snapshots**, each snapshot consisting of one name-resolution/HTTP attempt and three direct-IP HTTP attempts. It only enables the actual experiment after **two consecutive completely clean snapshots**. Every failed and successful preflight snapshot is retained in `preflight-admin.log`, alongside `preflight-pod.json`. Exhausting the limit, a malformed result or a missing Service IP fails closed without creating a successful Oracle result.

**The scored Oracle criteria are unchanged:** the `np-before` and `np-after` Pods must each contain three direct-IP HTTP 200 results and successful name HTTP; the `np-during` Pod must retain DNS success, failed FQDN HTTP, and three failed direct-IP HTTP attempts. The preflight is neither the no-fault control nor a replacement for it. This prevents hiding a failed workload by retrospectively selecting the best attempt. `tests/test_networkpolicy_preflight.py` checks bounded attempts, consecutive stability, all-event logging, and failure behavior.

### Source evidence and independent offline Oracle

The test administrator stores five raw source types per phase: Pod JSON,
actual probe JSON, Service JSON, native EndpointSliceList JSON and native
NetworkPolicyList JSON, **15 raw sources total**. All are independently
bounded, base64-decoded and SHA-256 checked before semantic replay.
The observer reads only three original Pod logs and runs the pre-existing
`sre-agent diagnose-dns` rule. In the denied phase, the result must
remain **UNKNOWN**, because both FQDN and direct-IP HTTP fail despite
healthy DNS. It is explicitly **not** a confirmed production root cause.

The admin then invokes:

```bash
sre-agent evaluate-networkpolicy \
  --episode /tmp/go-networkpolicy-proof/episode.json \
  --before /tmp/go-networkpolicy-proof/before-observation.json \
  --during /tmp/go-networkpolicy-proof/during-observation.json \
  --after /tmp/go-networkpolicy-proof/after-observation.json \
  --out /tmp/go-networkpolicy-proof/evaluation.json
```

The independent `internal/networkpolicyoracle` evaluator checks that
the Service UID, resourceVersion, selector, port and ClusterIP did not
change; EndpointSlices remain scoped to the Service with Ready endpoints;
all three Pods use the expected same label, do not mount a ServiceAccount
token, and have the correct HTTP/DNS environment. It requires the exact
NetworkPolicy selector and **TCP+UDP DNS port 53 only** during the fault,
no competing policy before/after, and validates three actual HTTP outcomes
in each phase. It rejects duplicate JSON keys *even in nested source
objects*, hidden extra ingress/egress rules, forged digests, changed policy
after recomputing SHA, and mismatches between the observer's original
log and test-admin source. Failures yield `UNKNOWN`, CLI exit 3, **no
evaluation artifact**.

A result `MATCHED_LAB_NETWORK_POLICY_DENIAL` is only a verdict
about this **admin-injected, isolated lab scenario**. Its
`production_causality_verified` field always remains `false`.

### Reproduce

Use a fresh disposable cluster with Docker and tools installed:

```bash
kind create cluster --name golden-netpol --config demo/go-networkpolicy/kind-calico.yaml
curl -fsSL https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml -o /tmp/g2i-calico.yaml
bash demo/go-networkpolicy/verify-calico-manifest.sh /tmp/g2i-calico.yaml
bash demo/go-networkpolicy/test-pin.sh /tmp/g2i-calico.yaml
kubectl create -f /tmp/g2i-calico.yaml
kubectl -n kube-system rollout status ds/calico-node --timeout=360s
kubectl wait nodes --all --for condition=Ready --timeout=360s
bash demo/go-networkpolicy/run-kind.sh
kind delete cluster --name golden-netpol
```

CI: `.github/workflows/go-networkpolicy-calico-kind.yml` runs the full
experiment and uploads `go-networkpolicy-kind-proof` even on failure.
The exact Calico v3.33.0 installation YAML is allowlisted with
SHA-256 `2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5`.
`calico-manifest-integrity` runs before the disposable kind job and rejects
tampered or missing files. The installation job separately validates the
downloaded bytes **before** passing them to `kubectl create`.
Both checks are required; a version tag alone is insufficient.

The digest was observed in prior lab CI runs and is a **content allowlist**,
not an independently authenticated Project Calico release signature. It
does not pin the referenced container image digests or prove the producer's
identity. Production-grade Calico provenance and image supply-chain
attestation remain outside this laboratory acceptance.

### Limits and unclosed merge gates

- The three Kubernetes snapshots are not atomic, and in-cluster Pod
  HTTP logs plus SHA-256 do **not** prove their source identities. The
  test-admin can theoretically forge both label and files. An external
  signed source/run manifest bound to ACP would be needed.
- A real admin-injected NetworkPolicy denial only proves enforcement in
  this **Calico kind** environment. It says nothing about production
  CNI dataplanes or whether a particular unobserved incident was caused
  by a network policy. No LLM model diagnosis or GRPO evaluation is tested.
- No policy admission/governance, broad RBAC, prod repair, or model tool
  execution rights are granted. The Agent only gets read-only logs.
- PRs #1–#5 are merged as **experimental** read-only baselines.
  Historical four-repo acceptance, independent external security review,
  evidence source authentication, and production admission/governance remain
  open. Merge PR #6 only after exact-HEAD Go/Python and real Calico deny/restore
  CI succeed. Any such merge is not a production-ready security declaration.
