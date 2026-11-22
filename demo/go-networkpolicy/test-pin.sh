#!/usr/bin/env bash
# An external source can change even when its URL contains a version tag.
# RED-before-GREEN test: valid original manifest passes; changed bytes and
# missing files must fail BEFORE kubectl create.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE="${1:?Usage: test-pin.sh VERIFIED_UPSTREAM_MANIFEST}"
test -s "$FILE"
bash "$SCRIPT_DIR/verify-calico-manifest.sh" "$FILE"

copy="$(mktemp)"
trap 'rm -f "$copy"' EXIT
cp "$FILE" "$copy"
printf '\n# attacker-added YAML\n' >> "$copy"
if bash "$SCRIPT_DIR/verify-calico-manifest.sh" "$copy"; then
  echo "FAIL: changed Calico manifest accepted" >&2
  exit 1
fi
if bash "$SCRIPT_DIR/verify-calico-manifest.sh" "$copy.not-found"; then
  echo "FAIL: missing Calico manifest accepted" >&2
  exit 1
fi
echo "PASS: allowlisted Calico manifest accepted, corrupt/missing rejected"
