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


func TestLegacyVersionlessMetadataPreservesPythonParity(t *testing.T) {
 // Python EvidenceBundle.metadata is deliberately free-form; an explicit
 // unsupported version must still be rejected (TestRejectsUnknownSchema).
 raw := changed(t, func(root map[string]any) {
  delete(root["metadata"].(map[string]any), "schema_version")
 })
 result, err := Verify(raw)
 if err != nil { t.Fatalf("legacy metadata rejected: %v", err) }
 if result.BundleSHA256 == "" || result.Status != "STRUCTURALLY_VALID" {
  t.Fatalf("legacy bundle unreadable: %+v", result)
 }
}


func TestPythonCanonicalParityForUnicodeSeparators(t *testing.T) {
 // Frozen SHA-256 values independently calculated with Python 3:
 // json.dumps(root, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
 cases := []struct{ name, note, pythonSHA string }{
  {"line-separator", "line"+string(rune(0x2028))+"separator", "113a33ee4460e1e4e648e8dcaf1432de11870c85a15e888c748962650d4f9cf4"},
  {"paragraph-separator", "para"+string(rune(0x2029))+"separator", "8e2d7b33e080d1f359c9ed2af9f97a037e196c4da226f5579d5593ed1ec967e6"},
  {"literal-backslash-u", "literal"+string(rune(92))+"u2028text", "0a5eba897289b6f481782e55ccb9216e6cc2cd93e9743c8dfa71375893582058"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   raw := changed(t, func(root map[string]any) {
    root["metadata"].(map[string]any)["note"] = tc.note
   })
   got, err := Verify(raw)
   if err != nil { t.Fatal(err) }
   if got.BundleSHA256 != tc.pythonSHA {
    t.Fatalf("cross-language evidence canonical digest mismatch: Go %s != Python %s", got.BundleSHA256, tc.pythonSHA)
   }
  })
 }
}
