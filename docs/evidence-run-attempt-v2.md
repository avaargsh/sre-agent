# G2k — Evidence manifest v2: run-attempt replay fencing and signer identity

**Status:** PR #8 is Draft directly against `main` after G2j PR #7 merged at `1e3e136`; v2 verifies an isolated LAB signature contract, not a production-issued signer identity.

## Security failure addressed

A GitHub Actions workflow run has a stable `GITHUB_RUN_ID`, while each rerun changes `GITHUB_RUN_ATTEMPT`. G2j/v1 attestation pinned only Run ID, immutable commit, repository and episode. A valid original signature could therefore be replayed into another attempt of the **same** GitHub workflow run if an external verifier checked no attempt.

G2k bumps both `sre.evidence-manifest/v2` and `sre.evidence-attestation/v2`, with a distinct Ed25519 domain-separation prefix `sre-agent/evidence-manifest/v2\0`. **v1 is not silently interpreted as v2.** Both a signer and a verifier must use the v2 schema.

The v2 manifest additionally signs:

| Field | Required value | Outside verifier's trust source |
| --- | --- | --- |
| `workflow_run_attempt` | Canonical decimal integer >=1, at most uint32 | Exact GitHub Actions `run_attempt` from independently authenticated run metadata |
| `signing_key_id` | Lowercase SHA-256 of Ed25519 public key's canonical X.509 SubjectPublicKeyInfo DER | Key identity enrolled in separate verifier policy / trusted public key fingerprint |
| `signing_key_version` | Explicit, bounded key version identifier | Authorized version as defined by external key lifecycle policy |

The existing exact repository name, immutable commit SHA, workflow Run ID and episode, plus an ordered, explicit allowlist of original source file hashes remain required.

- `Build` refuses missing or malformed attempt, key ID, key version.
- `Sign` refuses a private key whose derived public-key SPKI fingerprint differs from the **signed** manifest's `signing_key_id`.
- `Verify` refuses an external expected key ID not equal to the actual trusted PEM public key, checks the signed manifest identity against the **independent** expected fields, checks the Ed25519 signature, then independently rereads and rehashes original files.
- Incorrect run attempt, signing key ID/version, private key, old v1 schema, modified source, missing source and ambiguous duplicate-key JSON are rejected. No fallback to Run ID alone.

### Example commands

```bash
# The public PEM must be an externally authorized key for real trust.
# In local CI demonstration, a newly generated key is deliberately LAB ONLY.
KEY_ID="$(openssl pkey -pubin -in /policy/approved-ed25519-pub.pem -outform DER | sha256sum | cut -d' ' -f1)"

sre-agent index-evidence \
  --root /evidence/raw \
  --paths "before-service.json,during-policy.json,after-service.json" \
  --repo avaargsh/sre-agent \
  --head <exact-40-character-head-commit> \
  --run-id <authenticated-run-id> \
  --run-attempt <authenticated-run-attempt> \
  --episode np-calico-egress-001 \
  --signing-key-id "$KEY_ID" \
  --signing-key-version <approved-key-version> \
  --out /evidence/manifest.json

sre-agent sign-evidence \
  --manifest /evidence/manifest.json \
  --private-key /secure/approved-private-key.pem \
  --out /evidence/attestation.json

sre-agent verify-evidence \
  --root /evidence/raw \
  --attestation /evidence/attestation.json \
  --trusted-public-key /policy/approved-ed25519-pub.pem \
  --expected-repo avaargsh/sre-agent \
  --expected-head <exact-40-character-head-commit> \
  --expected-run-id <authenticated-run-id> \
  --expected-run-attempt <authenticated-run-attempt> \
  --expected-episode np-calico-egress-001 \
  --expected-signing-key-id "$KEY_ID" \
  --expected-signing-key-version <approved-key-version>
```

The exact-head CI workflow checks out the PR head, derives the run ID and attempt from the GitHub Actions environment, creates a fresh temporary key **outside the evidence directory**, indexes **all 26 original Calico-kind source files including the unscored startup preflight Pod and complete `preflight-admin.log`**, and explicitly tests changed preflight bytes, mismatched attempt, key ID and version. The lab key is intentionally named `LAB-ONLY-UNTRUSTED` when its public counterpart appears in the downloaded evidence. Never automatically trust that bundled key.

## Important non-guarantees and release gates

1. **Run-attempt binding is not global replay prevention.** A signed manifest can still be replayed for its original exact attempt. Permanent replay prevention, revocation and a one-time release/approval transition require a persistent authoritative journal / receipt register.
2. A `signing_key_version` is **a signed claim**, not authorization. Only an independently maintained key registry with issuer, scope, activation and revocation determines what signing key/version is allowed.
3. The lab private key and GitHub Action environment do not attest to actual Kubernetes origin. Lab key validation **does not** establish production evidence provenance.
4. The raw local filesystem can be mutated between path `Lstat` and file reads. A real production gate needs immutable, content-addressed evidence storage with delegated identity / workload attestation and signed approval context.
5. Historical evidence v1 under PR #7 remains inspectable by its original code; **v2 does not accept v1 as production-valid**. Do not alter historical run artifacts or claim they carry v2 attempt identity.
6. G0–G2j (#1–#7) are merged into development `main`, but **independent non-author security review**, external signer key registry/policy and historical four-repository acceptance remain open. Keep PR #8 Draft until fresh exact-head CI and source proof pass. Any later development merge is **not** authorization to release production evidence.
