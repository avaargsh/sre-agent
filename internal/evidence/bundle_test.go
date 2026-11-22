package evidence

import (
 "encoding/json"
 "os"
 "strings"
 "testing"
)

// Independently calculated with Python 3 json.dumps(..., sort_keys=True,
// separators=(",", ":"), ensure_ascii=False) and hashlib.sha256.
const fixture = `{
 "incident":{"incident_id":"inc-1","summary":"CPU < 85% 用户","severity":"sev2","scope":null},
 "evidence":[{"evidence_id":"e-1","source":"prometheus","observation":"CPU < 85%","timestamp":null,"attributes":{},"entity_refs":[]}],
 "hypotheses":[{"hypothesis_id":"h-1","statement":"CPU stable","evidence_ids":["e-1"],"status":"supported"}],
 "entities":[],"edges":[],"changes":[],"metadata":{"schema_version":"aiops.evidence/v1"}
}`

const pythonSHA = "c070bbd1dc8e1bc66969a57781b6e2c5c87d7d7d275f8227c6f9b1ed77e2f3fd"

func TestLegacyPythonDigestParity(t *testing.T) {
 result, err := Verify([]byte(fixture))
 if err != nil { t.Fatal(err) }
 if result.BundleSHA256 != pythonSHA { t.Fatalf("Go=%s Python=%s", result.BundleSHA256, pythonSHA) }
 if result.Status != "STRUCTURALLY_VALID" || result.SupportedHypotheses != 1 || result.EvidenceCount != 1 {
  t.Fatalf("unexpected result: %+v", result)
 }
}
func changed(t *testing.T, alter func(map[string]any)) []byte {
 t.Helper()
 var root map[string]any
 if err := json.Unmarshal([]byte(fixture), &root); err != nil { t.Fatal(err) }
 alter(root)
 raw, err := json.Marshal(root)
 if err != nil { t.Fatal(err) }
 return raw
}
func TestDigestFieldExcludedAndChecked(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["metadata"].(map[string]any)["bundle_sha256"] = pythonSHA })
 if _, err := Verify(raw); err != nil { t.Fatal(err) }
 raw = changed(t, func(root map[string]any) { root["metadata"].(map[string]any)["bundle_sha256"] = strings.Repeat("0", 64) })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted invalid frozen digest") }
}
func TestRejectsUnsupportedClaim(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["hypotheses"].([]any)[0].(map[string]any)["evidence_ids"] = []any{} })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted unsupported claim") }
}
func TestRejectsMissingEvidenceReference(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["hypotheses"].([]any)[0].(map[string]any)["evidence_ids"] = []any{"e-not-found"} })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted dangling evidence reference") }
}
func TestRejectsDuplicateEvidence(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["evidence"] = append(root["evidence"].([]any), root["evidence"].([]any)[0]) })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted duplicate evidence id") }
}
func TestRejectsDuplicateHypothesis(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["hypotheses"] = append(root["hypotheses"].([]any), root["hypotheses"].([]any)[0]) })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted duplicate hypothesis id") }
}
func TestRejectsUnknownSchema(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["metadata"].(map[string]any)["schema_version"] = "aiops.evidence/v2" })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted unknown schema") }
}
func TestRejectsUnexpectedField(t *testing.T) {
 raw := changed(t, func(root map[string]any) { root["unexpected"] = "ignored by Python" })
 if _, err := Verify(raw); err == nil { t.Fatal("accepted unexpected bundle field") }
}
func TestRejectsTrailingJSON(t *testing.T) {
 if _, err := Verify([]byte(fixture+` {"another":"document"}`)); err == nil { t.Fatal("accepted multiple JSON documents") }
}
func TestRejectsOversizedInput(t *testing.T) {
 if _, err := Verify(make([]byte, MaxBundleBytes+1)); err == nil { t.Fatal("accepted oversize bundle") }
}
func TestScenarioWrapper(t *testing.T) {
 raw := []byte(`{"case_id":"case-1","bundle":`+fixture+`,"outcome":{"recovered":true}}`)
 got, err := VerifyScenario(raw)
 if err != nil { t.Fatal(err) }
 if got.BundleSHA256 != pythonSHA { t.Fatalf("wrong scenario bundle SHA: %v", got) }
}
func TestExistingCheckoutBenchmarkParity(t *testing.T) {
 raw, err := os.ReadFile("../../benchmarks/scenarios/checkout-latency.json")
 if err != nil { t.Fatal(err) }
 got, err := VerifyScenario(raw)
 if err != nil { t.Fatal(err) }
 // Frozen Python v1 SHA from the checked-in benchmark.
 const legacyDigest = "0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3"
 if got.BundleSHA256 != legacyDigest { t.Fatalf("Go=%s Python=%s", got.BundleSHA256, legacyDigest) }
 if got.EvidenceCount != 2 || got.SupportedHypotheses != 1 { t.Fatalf("unexpected counts: %+v", got) }
}


func TestRejectsDuplicateJSONObjectKeysAtEveryDepth(t *testing.T) {
 cases:=map[string]string{
  "top-level":strings.Replace(fixture,`"metadata":{`,`"metadata":{},"metadata":{`,1),
  "metadata":strings.Replace(fixture,`"schema_version":"aiops.evidence/v1"`,`"schema_version":"aiops.evidence/v1","schema_version":"aiops.evidence/v1"`,1),
  "evidence":strings.Replace(fixture,`"evidence_id":"e-1"`,`"evidence_id":"e-1","evidence_id":"e-1"`,1),
  "nested-attributes":strings.Replace(fixture,`"attributes":{}`,`"attributes":{"a":1,"a":1}`,1),
 }
 for name,raw:=range cases{
  t.Run(name,func(t *testing.T){
   if _,err:=Verify([]byte(raw));err==nil{
    t.Fatal("duplicate JSON key was silently canonicalized and accepted")
   }
  })
 }
 scenario:=`{"case_id":"one","bundle":`+fixture+`,"bundle":`+fixture+`}`
 if _,err:=VerifyScenario([]byte(scenario));err==nil{
  t.Fatal("duplicate scenario bundle key was silently accepted")
 }
}
