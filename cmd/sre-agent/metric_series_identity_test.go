package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
 "time"
)

func TestOfflineVerifierRejectsDuplicateInstantVectorLabelsets(t *testing.T){
 observed:=time.Unix(1795350600,0).UTC()
 cases:=[]struct{name,series string;wantErr bool}{
  {"duplicate-swapped-key-order",`[{"metric":{"namespace":"n","pod":"a"},"timestamp":1795350600,"value":"0.2"},{"metric":{"pod":"a","namespace":"n"},"timestamp":1795350600,"value":"0.3"}]`,true},
  {"duplicate-empty-labels",`[{"metric":{},"timestamp":1795350600,"value":"0.2"},{"metric":{},"timestamp":1795350600,"value":"0.3"}]`,true},
  {"missing-metric",`[{"timestamp":1795350600,"value":"0.2"}]`,true},
  {"empty-label-name",`[{"metric":{"":"bad"},"timestamp":1795350600,"value":"0.2"}]`,true},
  {"valid-distinct",`[{"metric":{"pod":"a"},"timestamp":1795350600,"value":"0.2"},{"metric":{"pod":"b"},"timestamp":1795350600,"value":"0.3"}]`,false},
  {"valid-unlabelled",`[{"metric":{},"timestamp":1795350600,"value":"0.2"}]`,false},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   count:="1"
   if tc.name=="duplicate-swapped-key-order"||tc.name=="duplicate-empty-labels"||tc.name=="valid-distinct"{count="2"}
   attrs:=map[string]any{"samples_json":tc.series,"series_count":count,"max_age_seconds":"90"}
   err:=validateEmbeddedSamples(attrs,observed)
   if (err!=nil)!=tc.wantErr{
    t.Fatalf("offline instant-vector verdict inconsistent: err=%v wantErr=%v",err,tc.wantErr)
   }
  })
 }
}

 // This attacker rehashes BOTH source-derived evidence_id and the canonical
 // bundle digest, so the failure must come from duplicate series verification.
func TestOfflineReviewRejectsRehashedDuplicateInstantVector(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 forged:=rehashStructurallyValidBundle(t,bundlePath,func(bundle map[string]any){
  item:=bundle["evidence"].([]any)[1].(map[string]any)
  attrs:=item["attributes"].(map[string]any)
  var samples []map[string]any
  if err:=json.Unmarshal([]byte(attrs["samples_json"].(string)),&samples);err!=nil{t.Fatal(err)}
  if len(samples)!=1{t.Fatalf("expected single source series, got %d",len(samples))}
  clone:=make(map[string]any,len(samples[0]))
  for key,value:=range samples[0]{clone[key]=value}
  clone["value"]="0.25"
  samples=append(samples,clone)
  updated,err:=json.Marshal(samples)
  if err!=nil{t.Fatal(err)}
  attrs["samples_json"]=string(updated)
  attrs["series_count"]="2"
  item["observation"] = fmt.Sprintf("PromQL %s: 2 fresh finite series", attrs["promql"])
  encoded,err:=json.Marshal(attrs)
  if err!=nil{t.Fatal(err)}
  digest:=sha256.Sum256(append([]byte("prometheus:"),encoded...))
  item["evidence_id"]="obs-"+hex.EncodeToString(digest[:12])
 })
 var stdout,stderr bytes.Buffer
 if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
  stdout.Len()!=0||!strings.Contains(stderr.String(),"duplicate instant-vector"){
  t.Fatalf("self-rehashed duplicate instant-vector accepted or rejected for wrong reason: exit=%d out=%s err=%s",code,stdout.String(),stderr.String())
 }
}
