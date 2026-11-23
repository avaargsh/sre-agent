package main

import (
 "testing"
 "time"
)

func TestOfflineVerifierRejectsRehashedDuplicateInstantVectorLabelsets(t *testing.T){
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
