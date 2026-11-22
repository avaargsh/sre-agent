package sourcejson

import (
 "strings"
 "testing"
)

// Go encoding/json matches struct field tags case-insensitively. Distinct
// JSON keys "status" and "Status" can therefore overwrite one native source
// field without violating exact-key uniqueness. This must fail closed before
// a typed Kubernetes/Prometheus decoder can emit a misleading observation.
func TestRejectsCaseFoldedDuplicateNativeKeys(t *testing.T) {
 cases:=map[string]string{
  "status":`{"status":"error","Status":"success"}`,
  "prom-result-type":`{"data":{"resultType":"vector","ResultType":"matrix"}}`,
  "kubernetes-resource-version":`{"metadata":{"resourceVersion":"old","ResourceVersion":"new"}}`,
  "nested-pod-status":`{"items":[{"status":{"phase":"Pending","Phase":"Running"}}]}`,
  "unicode-json-fold":`{"metadata":{"name":"one","NAME":"two"}}`,
 }
 for name,raw:=range cases {
  t.Run(name,func(t *testing.T){
   if err:=Validate([]byte(raw));err==nil {
    t.Fatalf("accepted ambiguous case-folded native keys: %s",raw)
   }
  })
 }
}

func TestDistinctCaseFoldedKeysInSeparateObjectsRemainValid(t *testing.T) {
 for name,raw:=range map[string]string{
  "different-object-paths":`{"before":{"status":"error"},"after":{"Status":"success"}}`,
  "one-case-alias":`{"Status":"success"}`,
  "nested-array-elements":`{"items":[{"resourceVersion":"1"},{"ResourceVersion":"2"}]}`,
  "valid-unicode-pair":`{"value":"\ud83d\ude80"}`,
 }{
  t.Run(name,func(t *testing.T){
   if err:=Validate([]byte(raw));err!=nil {t.Fatalf("rejected unambiguous source: %v",err)}
  })
 }
}
