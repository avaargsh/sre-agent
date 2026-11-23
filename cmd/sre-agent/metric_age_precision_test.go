package main

import (
 "testing"
 "time"
)

// Test values are fixed CPU-only source snapshots, not live Prometheus evidence.
func TestOfflineSampleFreshnessUsesExactSubsecondBudget(t *testing.T){
 observed:=time.Unix(1795350600,0).UTC()
 base:=map[string]any{"series_count":"1","max_age_seconds":"0.25"}
 for _,tc:=range []struct{name,json string;wantErr bool}{
  {"300ms stale",`[{"metric":{},"timestamp":1795350599.7,"value":"0.2"}]`,true},
  {"200ms fresh",`[{"metric":{},"timestamp":1795350599.8,"value":"0.2"}]`,false},
  {"now",`[{"metric":{},"timestamp":1795350600,"value":"0.2"}]`,false},
 }{
  t.Run(tc.name,func(t *testing.T){
   attrs:=map[string]any{"series_count":base["series_count"],"max_age_seconds":base["max_age_seconds"],"samples_json":tc.json}
   err:=validateEmbeddedSamples(attrs,observed)
   if (err!=nil)!=tc.wantErr{t.Fatalf("err=%v wantErr=%v",err,tc.wantErr)}
  })
 }
}

func TestOfflineSampleFreshnessKeepsLegacyRoundedIntegerEvidence(t *testing.T){
 observed:=time.Unix(1795350600,0).UTC()
 attrs:=map[string]any{
  "series_count":"1","max_age_seconds":"1",
  "samples_json":`[{"metric":{},"timestamp":1795350598.7,"value":"0.2"}]`,
 }
 // Older collector rounded duration to whole seconds and verifier allowed
 // up to 500ms representation error. Preserve read compatibility only.
 if err:=validateEmbeddedSamples(attrs,observed);err!=nil{t.Fatalf("legacy integer age budget rejected: %v",err)}
}

func TestOfflineSampleFreshnessRejectsMalformedPrecision(t *testing.T){
 observed:=time.Unix(1795350600,0).UTC()
 for _,age:=range []string{"0","-1","0.0000000001","0.2500","1e-3","NaN","601"} {
  t.Run(age,func(t *testing.T){
   attrs:=map[string]any{"series_count":"1","max_age_seconds":age,
    "samples_json":`[{"metric":{},"timestamp":1795350600,"value":"0.2"}]`}
   if err:=validateEmbeddedSamples(attrs,observed);err==nil{
    t.Fatalf("noncanonical or unsupported metric age %q accepted",age)
   }
  })
 }
}
