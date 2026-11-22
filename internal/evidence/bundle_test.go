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


func TestPythonCanonicalParityNormalizesJSONFloatLexemes(t *testing.T) {
 // Python json.loads converts exponent/fraction lexemes to a float, and
 // json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 // writes canonical decimal/scientific notation; Go json.Number must not
 // hash the attacker-controlled noncanonical spelling of the same value.
 cases := []struct{ name, input, pythonSHA string }{
  {"exp-to-decimal", "1e0", "2559cf3cd59057a7f60974149c0c08bc95507e25a06c017d5b2e02d9fa6eaa74"},
  {"extra-fraction-zeros", "1.00", "2559cf3cd59057a7f60974149c0c08bc95507e25a06c017d5b2e02d9fa6eaa74"},
  {"exp-leading-zeroes", "1e+020", "38712b8422e6bef07252d10824e2191c965c2fef2405875d72ed174c66745d9d"},
  {"small-exponent", "1e-7", "c9b2e64cba96e41ee522ec789d8e4d3cbccc25463ca5f7eeaae83bdb81043780"},
  {"negative-zero", "-0.000", "31a024fa740a31c75f3c98574aefd43309f44aa778887cd2cfcea07577c62542"},
  {"decimal-after-exp", "2.500e+03", "b8a82a7f7d825aa021163c2fed5c703546914d51144c381db8d0fd383d8232c9"},
  {"small-fixed-to-exp", "0.00001", "7d1b1386a7e225d0836d1fd59ef3d8e50c13378e00035ed1681cf7e57466ea0e"},
  {"large-integer-unchanged", "9007199254740993", "26ff263007a1a602d4b00f8c9d56732955b0ab9dce9208cd95c6e59f1c01aba1"},
  {"negative-integer-zero", "-0", "1634c59d59d0599d57a9269de509a754fbb42186035fa1355e8de58777092f7f"},
  {"fixed-small-limit", "1e-4", "33466e8e92e171aeb0e72fc57e1bb506077d1563bfc61b1d58e7ed895b5493d8"},
  {"scientific-large-limit", "1e16", "bc112219b3b43446c0cfbd154b6aa041f916265b2db796c82ecef775d92b5c59"},
  {"fixed-large-limit", "1e15", "aa3f14a96345f2ebb16e465cd77593ca1e70846760ad34b5354df760d45b3f4a"},
  {"fixed-million", "1000000.0", "9d7c66ccbd2a4f21db229b17abaad6df90513c6d2da48385693eef0dc6456561"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   raw := strings.Replace(fixture, `"attributes":{}`, `"attributes":{"n":`+tc.input+`}`, 1)
   got, err := Verify([]byte(raw))
   if err != nil { t.Fatal(err) }
   if got.BundleSHA256 != tc.pythonSHA {
    t.Fatalf("legacy Python canonical SHA mismatch for %q: got %s, expected %s", tc.input, got.BundleSHA256, tc.pythonSHA)
   }
  })
 }
}
