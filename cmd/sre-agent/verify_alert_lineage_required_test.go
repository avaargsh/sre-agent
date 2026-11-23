package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"
)

// This attacker recalculates BOTH the source-derived evidence_id and the outer
// bundle SHA, so an ID mismatch cannot accidentally make the test pass.
func TestOfflineReviewRejectsMissingKubernetesFieldsEvenWithNewEvidenceID(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 changes:=map[string]func(map[string]any){
  "missing-generation":func(a map[string]any){delete(a,"generation")},
  "missing-observed-generation":func(a map[string]any){delete(a,"observed_generation")},
  "missing-pod-list-version":func(a map[string]any){delete(a,"pod_list_resource_version")},
  "non-numeric-generation":func(a map[string]any){a["generation"]="not-a-number"},
  "negative-observed-generation":func(a map[string]any){a["observed_generation"]="-1"},
  "observed-generation-ahead":func(a map[string]any){a["generation"]="1";a["observed_generation"]="2"},
  "blank-pod-list-version":func(a map[string]any){a["pod_list_resource_version"]="" },
 }
 for name,change:=range changes{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,func(bundle map[string]any){
    item:=bundle["evidence"].([]any)[0].(map[string]any)
    attrs:=item["attributes"].(map[string]any)
    change(attrs)
    encoded,err:=json.Marshal(attrs)
    if err!=nil{t.Fatal(err)}
    sum:=sha256.Sum256(append([]byte("kubernetes:"),encoded...))
    item["evidence_id"]="obs-"+hex.EncodeToString(sum[:12])
   })
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
     stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("Kubernetes field omission or bad generation accepted after independent evidence-id rehash: code=%d out=%s err=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}
