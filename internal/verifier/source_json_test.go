package verifier

import (
 "context"
 "strings"
 "testing"
)

// A structurally healthy SLI matrix cannot become independent proof if the
// original Prometheus JSON contains contradictory keys or lossy Unicode.
// The verifier previously decoded those bytes with last-key-wins semantics.
func TestSLIOracleFailsClosedOnContradictoryNativeSource(t *testing.T) {
 good := rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"}, -1)
 traffic := rangeResponse([]string{"1","2","3","2","1"}, -1)
 cases := map[string]string{
  "duplicate-status": strings.Replace(good, `"status":"success"`, `"status":"error","status":"success"`, 1),
  "duplicate-result-type": strings.Replace(good, `"resultType":"matrix"`, `"resultType":"vector","resultType":"matrix"`, 1),
  "duplicate-label": strings.Replace(good, `"job":"checkout"`, `"job":"hidden","job":"checkout"`, 1),
  "escaped-status-alias": strings.Replace(good, `"status":"success"`, `"\u0073tatus":"error","status":"success"`, 1),
  "unpaired-surrogate": strings.Replace(good, `"status":"success"`, `"ignored":"\ud800","status":"success"`, 1),
  "invalid-utf8": strings.Replace(good, `"status":"success"`, `"ignored":"`+string([]byte{0xff})+`","status":"success"`, 1),
 }
 for name, latency := range cases {
  t.Run(name, func(t *testing.T) {
   srv, _ := serveRange(t, latency, traffic)
   got := Assess(context.Background(), policy(srv.URL))
   if got.Status != Unknown || len(got.Evidence) != 0 {
    t.Fatalf("unauthenticated contradictory SLI source must be UNKNOWN without accepted evidence: status=%s evidence=%d reason=%q",got.Status,len(got.Evidence),got.Reason)
   }
  })
 }
}
