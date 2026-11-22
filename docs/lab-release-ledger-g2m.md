# G2m — Single-host LAB admission ledger and replay-safe receipt

> **Status: Draft PR #10 targeting merged `main` after G2l PR #9 (`d4b606a`).**
> **Experimental local admission only:** no Kubernetes mutations, no deploy, no published release, no multi-node exactly-once guarantee and no production signer authentication.

## Purpose and security boundary

The G2j/G2k signature checks establish canonical evidence integrity and exact Run/Attempt/key identity. G2l adds external hash-pinned signer policy authorization. Neither prevents a caller from **using the exact same already-verified signed evidence again**, or from promoting distinct evidence for the same target in a separate operation.

G2m introduces a **Go stdlib-only** local append-only admission ledger, with explicit laboratory semantics. The new CLI `sre-agent record-release-lab` never accepts a client-provided `verified=true` flag. Every attempt first re-runs the full `verify-evidence-authorized` signature, policy, source and identity checks, then records an admission on a private local directory.

A receipt has `schema_version=sre.lab-release-receipt/v1`, `status=LAB_ADMISSION_RECORDED`, **`production_release_authorized=false`**, and a monotonically increasing `sequence`. It binds tenant label, project label, release slot ID, signed attestation SHA-256, independently expected signer policy SHA-256, repo, immutable HEAD, Run ID, Run Attempt, episode, signing key fingerprint and key version.

**Local single-use rules:** a tenant/project/release slot can only be admitted once, even with a different signed evidence package; the same attestation hash cannot be re-used for another slot, even across tenant/project labels. These labels are test inputs, not verified tenant IAM identities.

## Durable local mechanics

- The ledger directory must already exist, be a **real private 0700 directory** outside the original evidence root. No symlink roots or group/world readable file contents.
- `os.Mkdir(ledger/.writer, 0700)` acts as a same-host exclusive gate. If a concurrent caller or a previous crashed writer left it in place, all new admission calls fail closed; **no lock stealing or implicit reconciliation**.
- Canonical JSON lines in `ledger.jsonl` are hash-linked with `sre-agent/lab-release-ledger/v1\0` domain separation. Each line contains the previous receipt hash, sequence and its own hash. The entire existing ledger is reread and verified under the lock before each append: unique slots, unique attestation digests, fixed schema/status, exact canonical JSON, valid chain and bounded size/count.
- Initial write creates `.initialized` exclusively; if either marker or journal is missing thereafter, the directory is rejected. Write operations `Sync()` the receipt journal and parent directory **before** returning a success receipt. A lost response can therefore be reconciled by `read-release-lab`; repeating the write is rejected.
- If a crash occurs after a write may have started, the lock is left for explicit investigation. A torn JSON tail is rejected. No automatic truncation, restart, retry with different IDs, or re-creation of an absent journal is performed.

### Local lab sample

```bash
install -d -m 0700 /tmp/sre-lab-ledger

sre-agent record-release-lab --lab-only \
  --ledger-dir /tmp/sre-lab-ledger \
  --tenant demo-tenant --project demo-project --release-id candidate-001 \
  --root /evidence/raw --attestation /evidence/raw/attestation.json \
  --trusted-public-key /trusted/approved-signing-key.pem \
  --policy-file /trusted/approved-signer-policy.json \
  --trusted-policy-sha256 "<out-of-band-approved-policy-SHA256>" \
  --expected-repo avaargsh/sre-agent --expected-head "<exact-40-character-SHA>" \
  --expected-run-id "<trusted-run-id>" --expected-run-attempt "<trusted-run-attempt>" \
  --expected-episode np-calico-egress-001 \
  --expected-signing-key-id "<externally-pinned-SPKI-fingerprint>" \
  --expected-signing-key-version approved-2026-q4

# Read-only inspection: never auto-repairs an interrupted journal.
sre-agent read-release-lab --ledger-dir /tmp/sre-lab-ledger
```

On a successful local admission the program outputs one JSON receipt. For any signature failure, unauthorized signer, corrupt journal, stale/concurrent lock, same attestation reuse or same release slot reuse, it prints `UNKNOWN`, returns exit code 3 and outputs **no new success receipt**. If the receipt write succeeded but stdout failed, the first entry remains durable and subsequent attempts are refused (lost-ACK test).

## Preserved source completeness from the merged upstream

The G2i NetworkPolicy lab already uses a bounded **separate** `np-preflight`
Pod, archiving all startup probe attempts and its Pod identity before any
scored baseline. G2j–G2l sign and authorize a **26-file** source manifest
containing `preflight-admin.log` and `preflight-pod.json`, and reject a
tampered preflight source. The older G2m branch proposed retrying the scored
`np-before` Pod, alongside an extra `check_healthy.py` helper. That legacy
retry was **superseded and intentionally not merged**: the current PR keeps
the independent preflight and exact three-attempt before/during/after Oracle
unchanged, so early failures cannot be silently replaced or promoted.

The LAB ledger receipts are produced only *after* the existing strict
Calico and authorized-signature evidence tests, never before them.

## Required test evidence

Go race tests: exactly one success under 32 concurrent clients; cross-slot replay denial; same slot/new evidence denial; chained record replay; interrupted lock; tampered, truncated or malformed existing journal; invalid labels; symlink/public directory denial. Real Calico CI exercises signature + G2l authorized signer policy, a positive lab admission, duplicate attempt and cross-slot replay rejections, simulated leftover lock, corrupt-journal rejection and a forced `/dev/full` lost-ACK experiment. Evidence output records the original journal and receipt, not any signing private key.

## Non-guarantees / release blockers

1. **This is not a distributed ledger.** `mkdir` and file `fsync` assume an honest local POSIX filesystem. Shared/NFS storage, multi-host scheduling, remote backups and container overlay durability are not validated. No production “exactly once” or atomic commit with a Kubernetes deploy.
2. **Hash chaining alone is not authenticated tamper protection.** An attacker who can replace the entire directory may regenerate matching hashes or remove marker+journal; real deployment needs external monotonic hash anchors, independently witnessed receipts and an immutable store.
3. There is no externally attested trusted signer, monotonic issuer revocation policy, trusted time, authorized tenant/project identity, approver identity, external release receipt authority, or real promotion transition.
4. A crashed/uncertain writer blocks new admission indefinitely. Manual forensic reconciliation is required; blindly removing `.writer`, deleting the marker or truncating the log is not an approved recovery flow.
5. This code does not modify a Kubernetes cluster, create a PR, merge any branch or set `production_causality_verified=true`. A local admission is a *lab record*, not an actual production release.
6. Independent security review, multi-node transactional authority (e.g. PostgreSQL unique constraints and serializable/advisory-lock transaction or equivalent), real authorization/approval receipts and external audit chain remain open. PRs #1–#9 are already merged as experimental development baselines, not production security approvals.

**Decision:** keep G2m PR #10 Draft until exact-HEAD Go/race and true Calico receipt CI have passed and the PR is independently reviewed. A development-main merge does not change its single-host LAB-only semantics.
