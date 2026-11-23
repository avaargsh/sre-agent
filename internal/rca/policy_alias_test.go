package rca

import (
    "crypto/sha256"
    "encoding/hex"
    "strings"
    "testing"
)

// The digest here is deliberately recomputed from the adversarial bytes:
// valid SHA-256 content integrity must not authorize JSON field aliases.
func TestPinnedPolicyRejectsCaseFoldedFieldAliases(t *testing.T) {
    raw, _ := testSourcePolicy(t)
    cases := map[string]string{
        "alias-only-namespace": strings.Replace(string(raw), `"namespace":`, `"Namespace":`, 1),
        "alias-only-threshold": strings.Replace(string(raw), `"max_latency_seconds":`, `"MAX_LATENCY_SECONDS":`, 1),
        "alias-only-deployment-uid": strings.Replace(string(raw), `"deployment_uid":`, `"Deployment_UID":`, 1),
        "alias-only-query": strings.Replace(string(raw), `"latency_query":`, `"Latency_Query":`, 1),
        "escaped-uppercase-namespace": strings.Replace(string(raw), `"namespace":`, `"\u004eamespace":`, 1),
        "alias-before-canonical": strings.Replace(string(raw), `"namespace":`, `"Namespace":"evil","namespace":`, 1),
        "canonical-before-alias": strings.Replace(string(raw), `"namespace":`, `"namespace":"evil","Namespace":`, 1),
    }
    for name, altered := range cases {
        t.Run(name, func(t *testing.T) {
            if altered == string(raw) {
                t.Fatal("fixture did not change the operator policy")
            }
            digest := sha256.Sum256([]byte(altered))
            if _, err := ParsePinnedPolicy([]byte(altered), hex.EncodeToString(digest[:])); err == nil {
                t.Fatal("accepted noncanonical or case-fold-colliding operator policy keys")
            }
        })
    }
}
