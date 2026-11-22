package alertintake

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "strings"
 "testing"
)

const firingFixture = `{
 "receiver":"sre",
 "status":"firing",
 "groupKey":"{}:{alertname=\"CheckoutLatency\"}",
 "commonLabels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api","severity":"sev2","alertname":"CheckoutLatency"},
 "commonAnnotations":{"summary":"checkout p99 latency high"},
 "alerts":[{"status":"firing","fingerprint":"abcdef1234567890","labels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api","alertname":"CheckoutLatency"}}]
}`

var intended = Target{Cluster:"lab-a", Namespace:"golden-demo", Deployment:"checkout-api"}

func TestFiringAlertCreatesStableScopedReadOnlyPlan(t *testing.T) {
 a, err := Parse([]byte(firingFixture), intended)
 if err != nil { t.Fatal(err) }
 b, err := Parse([]byte(strings.Replace(firingFixture, "checkout p99 latency high", "updated annotation", 1)), intended)
 if err != nil { t.Fatal(err) }
 if a.IncidentID == "" || a.IncidentID != b.IncidentID {
  t.Fatalf("same group must have stable scoped identity: %q %q", a.IncidentID, b.IncidentID)
 }
 if a.SchemaVersion != "sre.alert-plan/v1" || a.Status != "READ_ONLY_CANDIDATE" ||
    a.Target != intended || a.FiringAlerts != 1 || a.Summary != "checkout p99 latency high" ||
    a.Severity != "sev2" || a.SourceAuthenticated || a.AuthorizesExecution {
  t.Fatalf("wrong or over-authorized intent: %+v", a)
 }
 digest := sha256.Sum256([]byte(firingFixture))
 if a.RawSHA256 != hex.EncodeToString(digest[:]) || a.RawSHA256 == b.RawSHA256 {
  t.Fatal("raw payload hash not pinned independently from stable incident identity")
 }
 if _, err := Parse([]byte(firingFixture), Target{Cluster:"lab-b",Namespace:"golden-demo",Deployment:"checkout-api"}); err == nil {
  t.Fatal("accepted alert target without trusted cluster match")
 }
}

func TestAlertGroupsRejectAmbiguityAndCrossTargetRouting(t *testing.T) {
 cases := map[string]string{
  "resolved": strings.Replace(firingFixture, `"status":"firing"`, `"status":"resolved"`, 1),
  "empty-group-key": strings.Replace(firingFixture, `"groupKey":"{}:{alertname=\"CheckoutLatency\"}"`, `"groupKey":""`, 1),
  "missing-alert": strings.Replace(firingFixture, `"alerts":[{"status":"firing","fingerprint":"abcdef1234567890","labels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api","alertname":"CheckoutLatency"}}]`, `"alerts":[]`, 1),
  "conflicting-common-namespace": strings.Replace(firingFixture, `"namespace":"golden-demo"`, `"namespace":"secret-prod"`, 1),
  "conflicting-alert-namespace": strings.Replace(firingFixture, `"namespace":"golden-demo","deployment":"checkout-api","alertname":"CheckoutLatency"`, `"namespace":"secret-prod","deployment":"checkout-api","alertname":"CheckoutLatency"`, 1),
  "missing-fingerprint": strings.Replace(firingFixture, `"fingerprint":"abcdef1234567890"`, `"fingerprint":""`, 1),
  "duplicate-top-key": strings.Replace(firingFixture, `"status":"firing",`, `"status":"resolved","status":"firing",`, 1),
  "duplicate-nested-key": strings.Replace(firingFixture, `"severity":"sev2"`, `"severity":"sev0","severity":"sev2"`, 1),
  "escaped-duplicate-key": strings.Replace(firingFixture, `"severity":"sev2"`, `"\u0073everity":"sev0","severity":"sev2"`, 1),
  "trailing-json": firingFixture+`{"another":true}`,
  "unpaired-surrogate": strings.Replace(firingFixture, "checkout p99 latency high", `\ud800`, 1),
 }
 for name, raw := range cases {
  t.Run(name, func(t *testing.T) {
   if _, err := Parse([]byte(raw), intended); err == nil { t.Fatal("accepted ambiguous or cross-target alert group") }
  })
 }
 rawInvalid := strings.Replace(firingFixture,"checkout p99 latency high",string([]byte{0xff}),1)
 if _, err := Parse([]byte(rawInvalid), intended); err == nil { t.Fatal("accepted invalid UTF-8") }
 if _, err := Parse(make([]byte, MaxAlertBytes+1), intended); err == nil { t.Fatal("accepted oversized input") }
}

func TestResolvedAlertIsNotAnInvestigation(t *testing.T) {
 raw := strings.Replace(firingFixture, `"status":"firing",`, `"status":"resolved",`, 1)
 _, err := Parse([]byte(raw), intended)
 if !errors.Is(err, ErrUnknown) { t.Fatalf("resolved alert should be fail-closed: %v", err) }
}
