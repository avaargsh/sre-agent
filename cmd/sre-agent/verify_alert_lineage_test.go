package main

import (
 "bytes"
 "os"
 "testing"
 "strings"
)

// The outer canonical SHA can be recomputed after a malicious edit. Evidence
// ids and operator-readable observations must still agree with the exact
// source attributes, and read-only snapshots may not invent entity links.
func TestOfflineReviewRejectsRehashedEvidenceLineageMismatch(t *testing.T) {
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 attacks:=map[string]func(map[string]any){
  "forged-kubernetes-evidence-id":func(b map[string]any) {
   b["evidence"].([]any)[0].(map[string]any)["evidence_id"]="obs-000000000000000000000000"
  },
  "forged-prometheus-evidence-id":func(b map[string]any) {
   b["evidence"].([]any)[1].(map[string]any)["evidence_id"]="obs-111111111111111111111111"
  },
  "mismatched-kubernetes-observation":func(b map[string]any) {
   b["evidence"].([]any)[0].(map[string]any)["observation"]="deployment other/forged desired=2 ready=2"
  },
  "mismatched-prometheus-observation":func(b map[string]any) {
   b["evidence"].([]any)[1].(map[string]any)["observation"]="PromQL injected_query: 1 fresh finite series"
  },
  "injected-entity-reference":func(b map[string]any) {
   b["evidence"].([]any)[0].(map[string]any)["entity_refs"]=[]any{"approved:execution"}
  },
  "missing-empty-entity-refs":func(b map[string]any) {
   delete(b["evidence"].([]any)[1].(map[string]any),"entity_refs")
  },
  "null-entity-refs":func(b map[string]any) {
   b["evidence"].([]any)[1].(map[string]any)["entity_refs"]=nil
  },
 }
 for name,edit:=range attacks{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,edit)
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("self-rehashed lineage mismatch accepted: status=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
 // A normal collector's bundle is still structurally linked, without an
 // external signature or any production write/recovery permission.
 if _,err:=os.Stat(bundlePath);err!=nil{t.Fatal(err)}
 var stdout,stderr bytes.Buffer
 if code:=run(reviewArgs(rawPath,planPath,bundlePath),&stdout,&stderr);code!=0{
  t.Fatalf("valid read-only snapshot rejected: status=%d err=%s",code,stderr.String())
 }
}
