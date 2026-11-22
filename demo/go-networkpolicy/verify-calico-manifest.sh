#!/usr/bin/env bash
# Pinned Calico YAML integrity: rejects changed upstream bytes before any
# installation. This checksum was observed twice in completed G2i CI runs.
# It is a reproducibility allowlist, NOT an upstream authenticated signature
# or verification of container image digests.
set -euo pipefail
if [[ "$#" -ne 1 || ! -f "$1" || ! -s "$1" ]]; then
  echo "FAIL CLOSED: missing/empty Calico YAML; provide one file path" >&2
  exit 3
fi
readonly CALICO_V3_33_0_SHA256='2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5'
actual="$(sha256sum "$1" | awk '{print $1}')"
if [[ "$actual" != "$CALICO_V3_33_0_SHA256" ]]; then
  echo "FAIL CLOSED: Calico v3.33.0 YAML digest mismatch" >&2
  echo "Expected: $CALICO_V3_33_0_SHA256" >&2
  echo "Actual:   $actual" >&2
  exit 3
fi
echo "PASS: exact Calico v3.33.0 YAML SHA-256 allowlist matched"
