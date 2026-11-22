# G2j Evidence trust boundary — P0 security hardening

**Scope:** Standalone Draft PR #7 stacked on PR #6 (G2i). No production writes, no autonomous incident repair, no production provenance assertion, and no merge before independent security review.

## Two separate controls

### A. Calico installation YAML: exact content allowlist

`.github/workflows/go-networkpolicy-calico-kind.yml` fetches the upstream Calico tag `v3.33.0` then **requires**:

```bash
bash demo/go-networkpolicy/verify-calico-manifest.sh /tmp/g2i-calico.yaml
bash demo/go-networkpolicy/test-pin.sh /tmp/g2i-calico.yaml
# Only after both succeed may kubectl create the downloaded YAML.
```

Expected SHA-256:

```
2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5
```

This was separately observed in G2i Actions runs [44995100795](https://github.com/avaargsh/sre-agent/actions/runs/44995100795) and [44995351332](https://github.com/avaargsh/sre-agent/actions/runs/44995351332), and is now a **fixed allowlist**, not an informational digest printed after downloading. Changed bytes or a missing manifest must fail **before applying any Kubernetes resource**. Version tags can move; a digest comparison makes drift observable. This does **not** independently authenticate the Calico publisher, verify container image digests, or sign the downloaded YAML. A trusted upstream release signature and pinned image digests are further production gates.

### B. Original evidence: optional Ed25519 signature with external trust anchor

`internal/evidenceauth` implements:

- **Exact-byte index:** explicit relative file allowlist; sorted, unique, no symlinks, no absolute/traversal paths; maximum 64 files, 2 MiB each, 16 MiB total; SHA-256 over source bytes.
- **Signed manifest:** schema `sre.evidence-manifest/v1`, repository, immutable 40-character commit SHA, workflow run ID, episode ID and all file hashes. The signed input is canonical JSON prefixed by the domain separator `sre-agent/evidence-manifest/v1\0`.
- **Ed25519 signature:** PKCS8 PEM private key is obtained **outside the repository** and must be a mode-0600 regular file. The signing command does not generate or approve a key.
- **Independent verification:** `verify-evidence` requires a trusted Ed25519 PKIX public-key PEM **supplied by the verifier**, along with independently established repo, exact HEAD, Run ID and episode. It rejects a forged signature, wrong public key, mismatched identity, duplicate JSON keys (including nested), unknown fields, invalid canonical encoding, missing/changed source files, symlinks and path traversal.
- **Fail-closed contract:** verification failures exit 3, print `UNKNOWN`, and do not publish a signed success verdict.

Example, after a separately authorized signer has provided a *private* PKCS8 PEM key at a secure path:

```bash
sre-agent index-evidence \
  --root /evidence/raw \
  --paths "before-service.json,during-policy.json,after-service.json" \
  --repo avaargsh/sre-agent \
  --head <exact-40-char-commit-sha> \
  --run-id <trusted-run-id> \
  --episode np-calico-egress-001 \
  --out /evidence/manifest.json

sre-agent sign-evidence \
  --manifest /evidence/manifest.json \
  --private-key /secure/approved-ed25519-key.pem \
  --out /evidence/attestation.json

# A separate verifier obtains the public key and expected identity from
# independent policy / CI metadata, NOT from the signed artifact itself.
sre-agent verify-evidence \
  --root /evidence/raw \
  --attestation /evidence/attestation.json \
  --trusted-public-key /policy/approved-ed25519-pub.pem \
  --expected-repo avaargsh/sre-agent \
  --expected-head <exact-40-char-commit-sha> \
  --expected-run-id <trusted-run-id> \
  --expected-episode np-calico-egress-001
```

## What the CI lab *does* and *does not* prove

The `go-networkpolicy-calico-kind` workflow runs the real Calico deny/restore experiment, then the `test-evidence-attestation.sh` demonstration:

1. Build an explicit original-source index covering 3 phase × 7 source types, plus experiment evidence metadata.
2. Generate an **ephemeral self-issued Ed25519 key** outside the artifact directory, sign the manifest, verify it against an explicitly provided public key and exact PR head/run ID.
3. Attempt altered original source, unrelated public key, mismatched exact HEAD and mismatched Run ID. All must fail closed.
4. Delete all private keys before the job ends. The uploaded public PEM is named `LAB-ONLY-UNTRUSTED-public-key.pem` deliberately: possession of a matching public key inside the same artifact proves **no independent signer identity**.

**This CI test proves the signing/verifying machinery, not authenticated evidence provenance.** It must not be treated as ACP-signature verification or a production release gate. A production process needs an out-of-band authorized public key or KMS identity, scoped to tenant/project/run, plus authenticated CI/run metadata, immutable storage and approval records.

## Trust gaps deliberately left open

| Risk | Current control | Required for production |
| --- | --- | --- |
| Downloaded Calico YAML altered | Hardcoded SHA allowlist, tamper-negative test | Independent publisher signature or trusted checksum, image digest verification |
| Original evidence bytes changed | File digests, domain-separated Ed25519 signature | Externally trusted signer identity and sealed, immutable artifact |
| Fake repo/head/run assertion | Exact values compared to caller's expected parameters | Expected values from independently authenticated GitHub/ACP source |
| CI self-issued signing key | Demonstrates mechanism only | Separate approved key, KMS/HSM and audit key lifecycle |
| Disk file changed between validation and read | Bounded `Lstat` and read | Immutable content store or openat2/no-follow file descriptor binding |
| Malicious operator falsifies source, metadata and logs | No current independent truth authority | Separate test-admin approval, verifier isolation, attested workload identity |
| Unauthorized legacy cross-repo references | Historical acceptance remains failing | Explicit governance decision, not a silent rename/substitution |

**Release policy:** keep Draft; never set `production_causality_verified=true`, merge chained PRs or claim production provenance based on lab-generated keys or passing CI alone. Request a reviewer who did not author these security changes and record review evidence before merge.
