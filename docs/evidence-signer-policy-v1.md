# G2l — Independent signer authorization, revocation and scope gate

**State:** Draft PR #9 stacked on G2k PR #8. This is an opt-in, **read-only offline policy check**; it does not deploy a production key authority or prove Kubernetes evidence provenance.

## Threat addressed

G2k checks that an Ed25519 signature, declared key fingerprint, version, immutable commit, workflow run/attempt, episode and original source-file hashes match. **These are integrity and identity consistency checks, not authorization.** An attacker could produce a mathematically valid Ed25519 signature with a newly generated key and a matching key ID. Key possession does not confer release privileges.

G2l introduces a separate `sre.signer-policy/v1` policy. Verification with the new **`verify-evidence-authorized`** CLI requires that **the verifier** supplies:

1. A trusted public Ed25519 PEM **outside** the signed evidence directory.
2. A signer authorization policy file **outside** the signed evidence directory.
3. A lowercase SHA-256 of the exact policy bytes from an **independent trust channel** (`--trusted-policy-sha256`). The verifier checks these bytes before interpretation.
4. The expected repository, immutable commit SHA, workflow Run ID, Run Attempt, Episode, signer SPKI key fingerprint and key version, all from independently trusted metadata.

The entire policy JSON is strictly decoded: a single document, no duplicate keys anywhere (including nested JSON), no unknown fields, bounded at 64 KiB and a maximum of 64 grants. Entries contain exact `key_id`, `key_version`, `repository`, `episode`, `status`, `not_before` and `not_after`. Invalid entries, duplicate signer/version records and missing mandatory fields reject the entire policy. The signer policy has a separate revision identifier.

The verifier requires the actual trusted PEM key's SPKI SHA-256 to match the independent expected fingerprint, then looks for exactly scoped, currently active authorization. An explicit `revoked` grant for the same key fingerprint takes precedence globally across key versions/scopes. Time bounds are checked against the verifier's wall clock, with `not_after` exclusive. **A correct signature with an expired/revoked/out-of-scope key is rejected with `UNKNOWN`, exit code 3.**

## Minimal policy example

The following **illustrative** policy uses a placeholder fingerprint; it is not a valid enrollment and should not be used as a production trust anchor.

```json
{
  "schema_version": "sre.signer-policy/v1",
  "revision": "security-reviewed-rev-001",
  "grants": [{
    "key_id": "<64 lowercase hex SHA256 of trusted Ed25519 PKIX SPKI DER>",
    "key_version": "approved-2026-q4",
    "repository": "avaargsh/sre-agent",
    "episode": "np-calico-egress-001",
    "status": "active",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z"
  }]
}
```

To verify *without granting production authorization*:

```bash
sre-agent verify-evidence-authorized \
  --root /evidence/raw \
  --attestation /evidence/raw/attestation.json \
  --trusted-public-key /trusted/approved-pub.pem \
  --policy-file /trusted/signer-policy.json \
  --trusted-policy-sha256 "<independently-approved-policy-file-SHA256>" \
  --expected-repo avaargsh/sre-agent \
  --expected-head "<exact-40-character-commit-SHA>" \
  --expected-run-id "<authenticated-GitHub-run-id>" \
  --expected-run-attempt "<authenticated-run-attempt>" \
  --expected-episode np-calico-egress-001 \
  --expected-signing-key-id "<independently-approved-SPKI-SHA256>" \
  --expected-signing-key-version approved-2026-q4
```

The existing `verify-evidence` CLI remains a **cryptographic/integrity-only** validator. It is **not** a substitute for `verify-evidence-authorized` in any release process.

### CI proof, limits, and release blockers

`demo/go-networkpolicy/test-evidence-attestation.sh` additionally exercises the authorized command after the real Calico deny/restore lab. It generates a **self-issued, nonproduction** signer key, policy and policy hash outside the evidence root, tests positive authorization, then attempts all of:

- Missing/incorrect pinned policy digest
- Revocation, expiration and not-yet-valid signer
- Wrong repository, episode, key version and key fingerprint **even after rehashing changed policy**
- Trust policy copied into the evidence bundle
- Separate unit tests for strict JSON, policy duplication, time bounds and unrelated revoked keys

The CI-generated hash is calculated from **the same CI-generated policy** to test the parser and comparison only. It is **not an independent policy publisher**. This guard does not claim anyone has authorized the CI signer in a production key registry.

**Not yet implemented:** independently signed, published policy snapshots and monotonic revocation history; enterprise KMS/HSM issuer identity and key lifecycle; authenticated/verifiable time or independent GitHub run metadata; atomic immutable evidence storage; persistent replay journal, tamper-evident receipts; multi-cluster production validation; independent security assessment; historical cross-repository and branch-merge gates. A stale but previously approved policy digest could still be accepted if an external verifier incorrectly reuses it; the trusted policy distribution system must enforce freshness and revocation.

**Gate:** PR #9 stays Draft. Do not merge G0–G2l stack or claim production-grade provenance or `production_causality_verified=true`.
