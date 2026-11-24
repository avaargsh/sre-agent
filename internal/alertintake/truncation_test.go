package alertintake

import (
 "errors"
 "strings"
 "testing"
)

func TestTruncatedAlertGroupFailsClosed(t *testing.T) {
 cases := map[string]string{
  "positive": `"truncatedAlerts":1`,
  "negative": `"truncatedAlerts":-1`,
  "fractional": `"truncatedAlerts":0.0`,
  "string": `"truncatedAlerts":"0"`,
  "null": `"truncatedAlerts":null`,
  "bool": `"truncatedAlerts":false`,
  "alias": `"TruncatedAlerts":0`,
  "alias-with-canonical": `"truncatedAlerts":0,"TruncatedAlerts":1`,
  "duplicate": `"truncatedAlerts":0,"truncatedAlerts":1`,
 }
 for name, field := range cases {
  t.Run(name, func(t *testing.T) {
   raw := strings.Replace(firingFixture, "{", "{"+field+",", 1)
   got, err := Parse([]byte(raw), intended)
   if !errors.Is(err, ErrUnknown) || got != (Plan{}) {
    t.Fatalf("incomplete or ambiguous group admitted: %+v %v", got, err)
   }
  })
 }
}

func TestExplicitZeroTruncationPreservesLegacyIncidentIdentity(t *testing.T) {
 original, err := Parse([]byte(firingFixture), intended)
 if err != nil { t.Fatal(err) }
 raw := strings.Replace(firingFixture, "{", `{"truncatedAlerts":0,`, 1)
 zero, err := Parse([]byte(raw), intended)
 if err != nil { t.Fatal(err) }
 if zero.IncidentID != original.IncidentID || zero.RawSHA256 == original.RawSHA256 ||
  zero.SourceAuthenticated || zero.AuthorizesExecution {
  t.Fatalf("unexpected identity or authority change: %+v %+v", original, zero)
 }
}
