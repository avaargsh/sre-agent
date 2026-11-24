package main

import (
 "testing"

 "github.com/avaargsh/sre-agent/internal/endpointoracle"
)

func TestEvaluateEndpointRejectsAmbiguousRawEnvelope(t *testing.T) {
 for _,tc:=range []struct{name string;episode,prediction []byte}{
  {"duplicate episode key",[]byte(`{"schema_version":"sre.endpoint-oracle/v1","schema_version":"bad"}`),[]byte(`{}`)},
  {"case-fold episode key",[]byte(`{"schema_version":"sre.endpoint-oracle/v1","SchemaVersion":"bad"}`),[]byte(`{}`)},
  {"trailing prediction value",[]byte(`{}`),[]byte(`{} {}`)},
  {"nested duplicate prediction key",[]byte(`{}`),[]byte(`{"service":{"resourceVersion":"1","ResourceVersion":"2"}}`)},
  {"invalid UTF-8",[]byte{0xff},[]byte(`{}`)},
 } {
  t.Run(tc.name,func(t *testing.T){
   if _,err:=endpointoracle.EvaluateRaw(tc.episode,tc.prediction);err==nil{
    t.Fatal("ambiguous raw evidence accepted")
   }
  })
 }
}
