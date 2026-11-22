#!/usr/bin/env bash
# LAB ONLY: proves Ed25519 verifier mechanism with an ephemeral CI-generated
# key. A key generated in this same job IS NOT a trusted signer identity.
# Real releases require a separately authorized, independently pinned key,
# run identity, publication policy and audit trail.
set -euo pipefail
ROOT=/tmp/go-networkpolicy-proof
BIN=/tmp/sre-agent-networkpolicy
: "${SRE_SOURCE_HEAD:?exact PR head must come from trusted workflow metadata}"
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_RUN_ID:?}"
: "${GITHUB_RUN_ATTEMPT:?}"
test -f "$ROOT/evaluation.json"
test -x "$BIN"
KEY=/tmp/g2j-selfissued-private.pem
PUBLIC=/tmp/g2j-selfissued-public.pem
COPIED="$(mktemp -d)"
POLICY_DIR="$(mktemp -d)"
cleanup() { rm -f "$KEY" "$PUBLIC"; rm -rf "$COPIED" "$POLICY_DIR"; }
trap cleanup EXIT

# Explicit allowlist: no secrets, credentials, token files or generated
# signer keys may be automatically included in the signed source index.
sources=(evaluation.json calico-node-ds.json kind-ready-nodes.json preflight-pod.json preflight-admin.log)
for phase in before during after; do
  sources+=(
    "$phase-pod.json"
    "$phase-admin.log"
    "$phase-observer.log"
    "$phase-service.json"
    "$phase-endpoint-slices.json"
    "$phase-network-policies.json"
    "$phase-observation.json"
  )
done
paths="$(IFS=,; echo "${sources[*]}")"

# Generate a disposable lab key BEFORE building the signed manifest:
# the manifest must itself pin the exact signer public key fingerprint.
openssl genpkey -algorithm Ed25519 -out "$KEY"
chmod 0600 "$KEY"
openssl pkey -in "$KEY" -pubout -out "$PUBLIC"
KEY_ID="$(openssl pkey -pubin -in "$PUBLIC" -outform DER | sha256sum | cut -d' ' -f1)"
KEY_VERSION=ci-ephemeral-1
"$BIN" index-evidence \
  --root "$ROOT" \
  --paths "$paths" \
  --repo "$GITHUB_REPOSITORY" \
  --head "$SRE_SOURCE_HEAD" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --episode np-calico-egress-001 \
  --signing-key-id "$KEY_ID" \
  --signing-key-version "$KEY_VERSION" \
  --out "$ROOT/source-manifest.json"

# Signed policy proof must include full readiness history, including failures.
python3 - "$ROOT/source-manifest.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1],encoding="utf-8"))
indexed={f["path"] for f in m["files"]}
required={"preflight-admin.log","preflight-pod.json"}
assert required.issubset(indexed),(
  f"FAIL CLOSED: omitted unscored startup evidence: {sorted(required-indexed)}")
print("PASS: signer index contains complete unscored preflight evidence")
PY

# This key is a CI test fixture and is never uploaded. Publishing a public
# key alongside an attestation DOES NOT make it independently trusted.
"$BIN" sign-evidence --manifest "$ROOT/source-manifest.json" \
  --private-key "$KEY" --out "$ROOT/LAB-ONLY-self-issued-attestation.json"
# Public key is intentionally included only for reproducible lab testing:
# a verifier must NOT trust it automatically.
cp "$PUBLIC" "$ROOT/LAB-ONLY-UNTRUSTED-public-key.pem"

verify() {
  local attempt="${4:-$GITHUB_RUN_ATTEMPT}"
  local key_version="${5:-$KEY_VERSION}"
  local key_id="${6:-$KEY_ID}"
  "$BIN" verify-evidence \
    --root "$1" \
    --attestation "$ROOT/LAB-ONLY-self-issued-attestation.json" \
    --trusted-public-key "$2" \
    --expected-repo "$GITHUB_REPOSITORY" \
    --expected-head "$3" \
    --expected-run-id "$GITHUB_RUN_ID" \
    --expected-run-attempt "$attempt" \
    --expected-episode np-calico-egress-001 \
    --expected-signing-key-id "$key_id" \
    --expected-signing-key-version "$key_version"
}
verify "$ROOT" "$PUBLIC" "$SRE_SOURCE_HEAD"

# Never permit a verifier to use a public key shipped inside the same
# evidence bundle as its own trust anchor (a tautological self-signature).

fail_closed() {
  local reason="$1"
  shift
  set +e
  "$@" > "$ROOT/rejected-$reason.txt" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 3 ]] || ! grep -q 'UNKNOWN' "$ROOT/rejected-$reason.txt"; then
    echo "FAIL: invalid evidence $reason did not fail closed (exit $rc)" >&2
    exit 1
  fi
  echo "PASS: invalid signed evidence $reason rejected"
}
# A changed originally signed byte must fail even with the same envelope.
cp -a "$ROOT/." "$COPIED/"
printf '\n# tampered client log\n' >> "$COPIED/during-admin.log"
fail_closed modified-source verify "$COPIED" "$PUBLIC" "$SRE_SOURCE_HEAD"
# Even where the scored three-phase sources remain unchanged, independently
# modifying the original startup log must invalidate its v2 signature.
cp "$ROOT/during-admin.log" "$COPIED/during-admin.log"
printf '\n# forged preflight readiness\n' >> "$COPIED/preflight-admin.log"
fail_closed modified-preflight verify "$COPIED" "$PUBLIC" "$SRE_SOURCE_HEAD"
fail_closed bundled-self-issued-key verify "$ROOT" "$ROOT/LAB-ONLY-UNTRUSTED-public-key.pem" "$SRE_SOURCE_HEAD"

# Verification must reject a different exact commit, not merely branch name.
fail_closed incorrect-exact-head verify "$ROOT" "$PUBLIC" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# Run ID alone is insufficient: rerun attempts must not accept older proof.
WRONG_ATTEMPT="$((GITHUB_RUN_ATTEMPT + 1))"
fail_closed wrong-run-attempt verify "$ROOT" "$PUBLIC" "$SRE_SOURCE_HEAD" "$WRONG_ATTEMPT"
fail_closed wrong-key-version verify "$ROOT" "$PUBLIC" "$SRE_SOURCE_HEAD" "$GITHUB_RUN_ATTEMPT" "ci-ephemeral-2"
fail_closed wrong-key-id verify "$ROOT" "$PUBLIC" "$SRE_SOURCE_HEAD" "$GITHUB_RUN_ATTEMPT" "$KEY_VERSION" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# A self-issued alternate public key cannot verify the original signature.
OTHER=/tmp/g2j-selfissued-other.pem
OTHER_PUB=/tmp/g2j-selfissued-other-public.pem
openssl genpkey -algorithm Ed25519 -out "$OTHER"
chmod 0600 "$OTHER"
openssl pkey -in "$OTHER" -pubout -out "$OTHER_PUB"
fail_closed wrong-key verify "$ROOT" "$OTHER_PUB" "$SRE_SOURCE_HEAD"
rm -f "$OTHER" "$OTHER_PUB"

# Even a valid signature must not accept a wrong operator-supplied Run ID.
set +e
"$BIN" verify-evidence --root "$ROOT" \
  --attestation "$ROOT/LAB-ONLY-self-issued-attestation.json" \
  --trusted-public-key "$PUBLIC" \
  --expected-repo "$GITHUB_REPOSITORY" \
  --expected-head "$SRE_SOURCE_HEAD" \
  --expected-run-id 999999999 \
  --expected-run-attempt "$GITHUB_RUN_ATTEMPT" \
  --expected-episode np-calico-egress-001 \
  --expected-signing-key-id "$KEY_ID" \
  --expected-signing-key-version "$KEY_VERSION" \
  >"$ROOT/rejected-wrong-run.txt" 2>&1
rc=$?
set -e
test "$rc" -eq 3
grep -q UNKNOWN "$ROOT/rejected-wrong-run.txt"
echo "PASS: signed manifest rejects wrong external run identity"

echo "PASS: run-id + run-attempt + key-id/version bound Ed25519 lab mechanics; provenance NOT authenticated"


# G2l: A cryptographically good signature is NOT enough. A different
# out-of-band source must authorize key ID, version, repository, episode and
# current validity. This CI-generated policy/digest is an explicit test
# fixture, never an independently endorsed production authorization.
POLICY="$POLICY_DIR/lab-signer-policy.json"
python3 - "$POLICY" "$KEY_ID" "$KEY_VERSION" "$GITHUB_REPOSITORY" <<'PY'
import json, pathlib, sys
dest, key_id, key_version, repository = sys.argv[1:]
policy = {
    "schema_version": "sre.signer-policy/v1",
    "revision": "ci-lab-rev-1",
    "grants": [{
        "key_id": key_id,
        "key_version": key_version,
        "repository": repository,
        "episode": "np-calico-egress-001",
        "status": "active",
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2030-01-01T00:00:00Z",
    }],
}
pathlib.Path(dest).write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY
POLICY_SHA="$(sha256sum "$POLICY" | awk '{print $1}')"
verify_authorized() {
  local policy_file="$1"
  local expected_policy_sha="$2"
  "$BIN" verify-evidence-authorized \
    --root "$ROOT" \
    --attestation "$ROOT/LAB-ONLY-self-issued-attestation.json" \
    --trusted-public-key "$PUBLIC" \
    --policy-file "$policy_file" \
    --trusted-policy-sha256 "$expected_policy_sha" \
    --expected-repo "$GITHUB_REPOSITORY" \
    --expected-head "$SRE_SOURCE_HEAD" \
    --expected-run-id "$GITHUB_RUN_ID" \
    --expected-run-attempt "$GITHUB_RUN_ATTEMPT" \
    --expected-episode np-calico-egress-001 \
    --expected-signing-key-id "$KEY_ID" \
    --expected-signing-key-version "$KEY_VERSION"
}
verify_authorized "$POLICY" "$POLICY_SHA"
fail_closed invalid-policy-hash verify_authorized "$POLICY" "$(printf '%064d' 0)"
fail_closed missing-policy-hash verify_authorized "$POLICY" ""
# Even if the attacker rehashes their new JSON, a revoked or out-of-scope
# policy cannot authorize the signing key.
python3 - "$POLICY" "$POLICY_DIR" <<'PY'
import json, pathlib, sys
source = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = pathlib.Path(sys.argv[2])
variants = {
    "revoked": ("status", "revoked"),
    "expired": ("not_after", "2025-01-01T00:00:00Z"),
    "future": ("not_before", "2030-01-01T00:00:00Z"),
    "wrong-repo": ("repository", "attacker/sre-agent"),
    "wrong-episode": ("episode", "forged-episode"),
    "wrong-version": ("key_version", "ci-ephemeral-999"),
    "wrong-key-id": ("key_id", "a" * 64),
}
for label,(field,value) in variants.items():
    obj = json.loads(json.dumps(source))
    obj["grants"][0][field] = value
    (out / f"{label}.json").write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY
for variant in revoked expired future wrong-repo wrong-episode wrong-version wrong-key-id; do
  changed="$POLICY_DIR/$variant.json"
  changed_sha="$(sha256sum "$changed" | awk '{print $1}')"
  fail_closed "signer-policy-$variant" verify_authorized "$changed" "$changed_sha"
done
cp "$POLICY" "$ROOT/LAB-ONLY-UNTRUSTED-policy.json"
fail_closed bundled-policy verify_authorized "$ROOT/LAB-ONLY-UNTRUSTED-policy.json" "$POLICY_SHA"
echo "PASS: independent policy gate mechanics only; signer authority, policy publication and revocation remain UNVERIFIED"

# G2m local single-use release admission only. All inputs are validated AGAIN
# by verify-evidence-authorized before recording any receipt. No production
# release/deploy/approval is performed and all policies are CI-self-issued.
record_release_lab() {
  local dir="$1"
  local slot="$2"
  "$BIN" record-release-lab --lab-only \
    --ledger-dir "$dir" --tenant demo-tenant --project demo-project --release-id "$slot" \
    --root "$ROOT" \
    --attestation "$ROOT/LAB-ONLY-self-issued-attestation.json" \
    --trusted-public-key "$PUBLIC" \
    --policy-file "$POLICY" --trusted-policy-sha256 "$POLICY_SHA" \
    --expected-repo "$GITHUB_REPOSITORY" --expected-head "$SRE_SOURCE_HEAD" \
    --expected-run-id "$GITHUB_RUN_ID" --expected-run-attempt "$GITHUB_RUN_ATTEMPT" \
    --expected-episode np-calico-egress-001 \
    --expected-signing-key-id "$KEY_ID" --expected-signing-key-version "$KEY_VERSION"
}

record_release_lab "$LAB_LEDGER" "release-001" >"$ROOT/LAB-ONLY-single-use-receipt.json"
"$BIN" read-release-lab --ledger-dir "$LAB_LEDGER" >"$ROOT/LAB-ONLY-ledger-replayed.json"
cp "$LAB_LEDGER/ledger.jsonl" "$ROOT/LAB-ONLY-ledger-original.jsonl"
python3 - "$ROOT/LAB-ONLY-single-use-receipt.json" "$ROOT/LAB-ONLY-ledger-replayed.json" <<'PY'
import json,sys
receipt=json.load(open(sys.argv[1]))
rows=json.load(open(sys.argv[2]))
assert len(rows)==1 and rows[0]==receipt,(rows,receipt)
assert receipt["status"]=="LAB_ADMISSION_RECORDED"
assert receipt["production_release_authorized"] is False
assert receipt["sequence"]==1
assert receipt["workflow_run_attempt"]==__import__("os").environ["GITHUB_RUN_ATTEMPT"]
print("PASS: one source-bound lab-only receipt recorded and strictly replayed")
PY

fail_closed repeated-same-release record_release_lab "$LAB_LEDGER" "release-001"
fail_closed replay-same-attestation-new-slot record_release_lab "$LAB_LEDGER" "release-002"
after="$(wc -l < "$LAB_LEDGER/ledger.jsonl")"
test "$after" -eq 1

# A crashed writer can leave a lock. A stale gate MUST NOT be stolen; it
# requires independent operator reconciliation. This only simulates that
# residual state in a disposable laboratory directory.
cp -a "$LAB_LEDGER/." "$LAB_CORRUPT/"
mkdir "$LAB_CORRUPT/.writer"
fail_closed crash-lock-sticky record_release_lab "$LAB_CORRUPT" "release-003"
test "$(wc -l < "$LAB_CORRUPT/ledger.jsonl")" -eq 1
rmdir "$LAB_CORRUPT/.writer"

# Signed evidence replay must NOT bypass a truncated / malformed ledger.
printf '{"truncated":true}' >> "$LAB_CORRUPT/ledger.jsonl"
fail_closed corrupted-journal-read "$BIN" read-release-lab --ledger-dir "$LAB_CORRUPT"
fail_closed corrupted-journal-write record_release_lab "$LAB_CORRUPT" "release-003"

# Indeterminate client ACK: force an output error only AFTER durable commit.
# Even if the client never sees the receipt, replay cannot emit another one.
set +e
record_release_lab "$LAB_ACKLOSS" "ack-loss-001" >/dev/full 2>"$ROOT/rejected-lost-ack.txt"
rc=$?
set -e
if [[ "$rc" -ne 3 ]] || ! grep -q 'UNKNOWN' "$ROOT/rejected-lost-ack.txt"; then
  echo "FAIL: lost ACK did not produce explicit UNKNOWN" >&2
  exit 1
fi
test "$(wc -l < "$LAB_ACKLOSS/ledger.jsonl")" -eq 1
fail_closed lost-ack-retry record_release_lab "$LAB_ACKLOSS" "ack-loss-001"
echo "PASS: local LAB receipt is single-use across replay, corrupted journal, stale lock and lost ACK (NOT production release)"
