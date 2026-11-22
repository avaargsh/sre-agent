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
test -f "$ROOT/evaluation.json"
test -x "$BIN"
KEY=/tmp/g2j-selfissued-private.pem
PUBLIC=/tmp/g2j-selfissued-public.pem
COPIED="$(mktemp -d)"
cleanup() { rm -f "$KEY" "$PUBLIC"; rm -rf "$COPIED"; }
trap cleanup EXIT

# Explicit allowlist: no secrets, credentials, token files or generated
# signer keys may be automatically included in the signed source index.
sources=(evaluation.json calico-node-ds.json kind-ready-nodes.json)
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
"$BIN" index-evidence \
  --root "$ROOT" \
  --paths "$paths" \
  --repo "$GITHUB_REPOSITORY" \
  --head "$SRE_SOURCE_HEAD" \
  --run-id "$GITHUB_RUN_ID" \
  --episode np-calico-egress-001 \
  --out "$ROOT/source-manifest.json"

# This preregistered, bounded readiness preflight is part of the original
# incident record. Releasing only the three favorable phase logs would omit
# failed cold-start attempts and permit selective-evidence reporting.
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
openssl genpkey -algorithm Ed25519 -out "$KEY"
chmod 0600 "$KEY"
openssl pkey -in "$KEY" -pubout -out "$PUBLIC"
"$BIN" sign-evidence --manifest "$ROOT/source-manifest.json" \
  --private-key "$KEY" --out "$ROOT/LAB-ONLY-self-issued-attestation.json"
# Public key is intentionally included only for reproducible lab testing:
# a verifier must NOT trust it automatically.
cp "$PUBLIC" "$ROOT/LAB-ONLY-UNTRUSTED-public-key.pem"

verify() {
  "$BIN" verify-evidence \
    --root "$1" \
    --attestation "$ROOT/LAB-ONLY-self-issued-attestation.json" \
    --trusted-public-key "$2" \
    --expected-repo "$GITHUB_REPOSITORY" \
    --expected-head "$3" \
    --expected-run-id "$GITHUB_RUN_ID" \
    --expected-episode np-calico-egress-001
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
fail_closed bundled-self-issued-key verify "$ROOT" "$ROOT/LAB-ONLY-UNTRUSTED-public-key.pem" "$SRE_SOURCE_HEAD"

# Verification must reject a different exact commit, not merely branch name.
fail_closed incorrect-exact-head verify "$ROOT" "$PUBLIC" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
  --expected-episode np-calico-egress-001 \
  >"$ROOT/rejected-wrong-run.txt" 2>&1
rc=$?
set -e
test "$rc" -eq 3
grep -q UNKNOWN "$ROOT/rejected-wrong-run.txt"
echo "PASS: signed manifest rejects wrong external run identity"

echo "PASS: ephemeral test-key Ed25519 mechanics only; provenance NOT authenticated"
