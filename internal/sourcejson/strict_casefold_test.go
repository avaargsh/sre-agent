package sourcejson

import "testing"

type nativeCasefoldEnvelope struct {
 Status string `json:"status"`
 Data struct {
  ResultType string `json:"resultType"`
 } `json:"data"`
 Metadata struct {
  ResourceVersion string `json:"resourceVersion"`
  Name string `json:"name"`
 } `json:"metadata"`
 Items []struct {
  Status struct {
   Phase string `json:"phase"`
  } `json:"status"`
 } `json:"items"`
}

// Go encoding/json matches struct fields case-insensitively. Keep native
// struct-field aliases fail-closed, but validate them against the actual
// typed schema rather than treating every JSON object as a struct.
func TestValidateCanonicalFieldsRejectsCaseFoldedNativeFieldAliases(t *testing.T) {
 cases := map[string]string{
  "status": `{"status":"error","Status":"success"}`,
  "prom-result-type": `{"data":{"resultType":"vector","ResultType":"matrix"}}`,
  "kubernetes-resource-version": `{"metadata":{"resourceVersion":"old","ResourceVersion":"new"}}`,
  "nested-pod-status": `{"items":[{"status":{"phase":"Pending","Phase":"Running"}}]}`,
  "unicode-json-fold": `{"metadata":{"name":"one","NAME":"two"}}`,
 }
 for name, raw := range cases {
  t.Run(name, func(t *testing.T) {
   if err := Validate([]byte(raw)); err != nil {
    t.Fatalf("distinct JSON keys should pass syntax validation: %v", err)
   }
   if err := ValidateCanonicalFields([]byte(raw), &nativeCasefoldEnvelope{}); err == nil {
    t.Fatalf("accepted ambiguous typed native fields: %s", raw)
   }
  })
 }
}

func TestDistinctCaseFoldedKeysInSeparateObjectsRemainValid(t *testing.T) {
 for name, raw := range map[string]string{
  "different-object-paths": `{"before":{"status":"error"},"after":{"Status":"success"}}`,
  "one-case-alias": `{"Status":"success"}`,
  "nested-array-elements": `{"items":[{"resourceVersion":"1"},{"ResourceVersion":"2"}]}`,
  "valid-unicode-pair": `{"value":"\ud83d\ude80"}`,
 } {
  t.Run(name, func(t *testing.T) {
   if err := Validate([]byte(raw)); err != nil {
    t.Fatalf("rejected unambiguous source: %v", err)
   }
  })
 }
}

// Kubernetes label maps are case-sensitive data, not struct field names.
// Likewise, json.RawMessage carries opaque source data. A global Unicode
// case-fold collision check must not reject distinct map keys before the
// typed schema validator can distinguish those data boundaries.
func TestValidateAllowsCaseFoldedKeysInsideDataMaps(t *testing.T) {
 raw := []byte(`{
  "metadata":{"resourceVersion":"rv1"},
  "labels":{"app":"checkout","App":"legacy"},
  "raw":{"status":"old","Status":"new"}
 }`)
 if err := Validate(raw); err != nil {
  t.Fatalf("case-sensitive map keys and opaque RawMessage keys must remain data: %v", err)
 }
 if err := ValidateCanonicalFields(raw, &schemaFieldEnvelope{}); err != nil {
  t.Fatalf("typed schema validation must not reinterpret map/RawMessage keys as struct fields: %v", err)
 }
}

func TestValidateStillRejectsExactDuplicateKeysInsideDataMaps(t *testing.T) {
 raw := []byte(`{"labels":{"app":"checkout","app":"legacy"}}`)
 if err := Validate(raw); err == nil {
  t.Fatal("exact duplicate JSON object keys must remain rejected")
 }
}
