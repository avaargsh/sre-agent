package evidence

import (
 "strings"
 "testing"
)

// Python's legacy JSON decoder rejects non-UTF-8 byte input; Go's decoder
// silently substitutes U+FFFD. That substitution must not produce a
// misleading STRUCTURALLY_VALID evidence digest.
func TestVerifyRejectsInvalidUTF8WithoutCanonicalizingIt(t *testing.T) {
 raw := []byte(strings.Replace(fixture, `"observation":"CPU < 85%"`, `"observation":"bad`+string([]byte{0xff})+`"`, 1))
 if _, err := Verify(raw); err == nil {
  t.Fatal("accepted invalid UTF-8 evidence and silently canonicalized its bytes")
 }
}

func TestVerifyRejectsUnpairedEscapedSurrogates(t *testing.T) {
 cases := map[string]string{
  "high-only": `\ud800`,
  "low-only": `\udc00`,
  "high-then-text": `\ud800A`,
  "high-then-high": `\ud800\ud801`,
  "reversed-pair": `\udc00\ud800`,
 }
 for name, note := range cases {
  t.Run(name, func(t *testing.T) {
   raw := []byte(strings.Replace(fixture,
    `"schema_version":"aiops.evidence/v1"`,
    `"schema_version":"aiops.evidence/v1","note":"`+note+`"`, 1))
   if _, err := Verify(raw); err == nil {
    t.Fatal("accepted unpaired UTF-16 surrogate instead of rejecting ambiguous evidence")
   }
  })
 }
}

func TestVerifyPreservesValidEscapedSurrogatePairAndEscapedBackslash(t *testing.T) {
 for name, note := range map[string]string{
  "valid-pair": `\ud83d\ude80`,
  "literal-backslash": `\\ud800`,
 } {
  t.Run(name, func(t *testing.T) {
   raw := []byte(strings.Replace(fixture,
    `"schema_version":"aiops.evidence/v1"`,
    `"schema_version":"aiops.evidence/v1","note":"`+note+`"`, 1))
   if _, err := Verify(raw); err != nil {
    t.Fatalf("rejected valid legacy JSON escape %s: %v", name, err)
   }
  })
 }
}
