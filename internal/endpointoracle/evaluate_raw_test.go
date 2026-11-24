package endpointoracle

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"
)

func TestEvaluateRawBindsExactInputBytes(t *testing.T) {
 e,p:=episode(t,false)
 episodeRaw,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 predictionRaw,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 got,err:=EvaluateRaw(episodeRaw,predictionRaw);if err!=nil{t.Fatal(err)}
 eh:=sha256.Sum256(episodeRaw);ph:=sha256.Sum256(predictionRaw)
 if got.EpisodeSHA256!=hex.EncodeToString(eh[:]){t.Fatalf("episode digest not bound to exact bytes: %s",got.EpisodeSHA256)}
 if got.PredictionSHA256!=hex.EncodeToString(ph[:]){t.Fatalf("prediction digest not bound to exact bytes: %s",got.PredictionSHA256)}
 reformatted:=append([]byte(" \n"),episodeRaw...)
 second,err:=EvaluateRaw(reformatted,predictionRaw);if err!=nil{t.Fatal(err)}
 if second.EpisodeSHA256==got.EpisodeSHA256{t.Fatal("digest must bind original bytes, not normalized typed object")}
}

func TestEvaluateRawRejectsAmbiguousEnvelopes(t *testing.T) {
 validPrediction:=[]byte(`{}`)
 for _,tc:=range []struct{name string;episode,prediction []byte}{
  {"duplicate episode key",[]byte(`{"schema_version":"sre.endpoint-oracle/v1","schema_version":"bad"}`),validPrediction},
  {"case-fold episode key",[]byte(`{"schema_version":"sre.endpoint-oracle/v1","SchemaVersion":"bad"}`),validPrediction},
  {"trailing episode value",[]byte(`{} {}`),validPrediction},
  {"duplicate prediction key",[]byte(`{}`),[]byte(`{"classification":"READY","classification":"UNKNOWN"}`)},
  {"invalid UTF-8 episode",[]byte{0xff},validPrediction},
 }{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=EvaluateRaw(tc.episode,tc.prediction);err==nil{t.Fatal("ambiguous raw evidence accepted")}
  })
 }
}

func TestEvaluateRawRejectsUnconsumedFields(t *testing.T) {
 e,p:=episode(t,false)
 episodeRaw,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 predictionRaw,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 cases:=[]struct{name string;episode,prediction []byte}{
  {"unknown episode field",[]byte(strings.TrimSuffix(string(episodeRaw),"}")+`,"operator_approval":true}`),predictionRaw},
  {"unknown nested phase field",[]byte(strings.Replace(string(episodeRaw),`"probes":[200,200,200]}`,`"probes":[200,200,200],"sampled_at":"2026-11-24T00:00:00Z"}`,1)),predictionRaw},
  {"unknown prediction field",episodeRaw,[]byte(strings.TrimSuffix(string(predictionRaw),"}")+`,"evidence_attestation":"signed"}`)},
  {"noncanonical field alias",[]byte(strings.TrimSuffix(string(episodeRaw),"}")+`,"SchemaVersion":"sre.endpoint-oracle/v1"}`),predictionRaw},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=EvaluateRaw(tc.episode,tc.prediction);err==nil{t.Fatal("unconsumed envelope field accepted")}
  })
 }
}
func TestEvaluateRawEnforcesEnvelopeByteBudgets(t *testing.T) {
 if _,err:=EvaluateRaw(make([]byte,(12<<20)+1),[]byte(`{}`));err==nil{t.Fatal("oversized episode accepted")}
 if _,err:=EvaluateRaw([]byte(`{}`),make([]byte,(6<<20)+1));err==nil{t.Fatal("oversized prediction accepted")}
}
