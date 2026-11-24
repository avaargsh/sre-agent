package observe

import (
 "context"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
)

func TestPrometheusCompletenessAdmission(t *testing.T) {
 for _,tc:=range []struct{name,fields string;valid bool}{
  {"absent","",true},
  {"explicit-complete",`"isPartial":false,"partialResponse":false,"warnings":[],`,true},
  {"extension",`"backend":"test",`,true},
  {"is-partial",`"isPartial":true,`,false},
  {"partial-response",`"partialResponse":true,`,false},
  {"mixed-flags",`"isPartial":false,"partialResponse":true,`,false},
  {"null-is-partial",`"isPartial":null,`,false},
  {"null-partial-response",`"partialResponse":null,`,false},
  {"string-flag",`"isPartial":"false",`,false},
  {"numeric-flag",`"partialResponse":0,`,false},
  {"alias-is-partial",`"IsPartial":false,`,false},
  {"alias-partial-response",`"PartialResponse":false,`,false},
  {"warnings",`"warnings":["private upstream warning"],`,false},
  {"null-warnings",`"warnings":null,`,false},
  {"alias-warnings",`"Warnings":[],`,false},
  {"duplicate-flag",`"isPartial":true,"isPartial":false,`,false},
  {"contradictory-alias",`"partialResponse":true,"PartialResponse":false,`,false},
 }{t.Run(tc.name,func(t *testing.T){
  var metrics atomic.Int32
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   if r.Method!=http.MethodGet {t.Errorf("unexpected method %s",r.Method);w.WriteHeader(405);return}
   switch r.URL.Path {
   case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
    _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`)
   case "/api/v1/namespaces/golden-demo/pods":
    _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
   case "/api/v1/query":
    metrics.Add(1)
    _,_=fmt.Fprint(w,`{"status":"success",`+tc.fields+`"data":{"resultType":"vector","result":`+validSample+`}}`)
   default:w.WriteHeader(404)
   }
  }));defer srv.Close()
  raw,err:=Collect(context.Background(),fixture(srv.URL))
  if metrics.Load()!=1{t.Fatalf("unexpected metric reads: %d",metrics.Load())}
  if tc.valid {
   if err!=nil||len(raw)==0{t.Fatalf("complete response rejected: bytes=%d err=%v",len(raw),err)}
  } else if !errors.Is(err,ErrUnknown)||raw!=nil||strings.Contains(err.Error(),"private upstream warning"){t.Fatalf("invalid response admitted or warning leaked: bytes=%d err=%v",len(raw),err)}
 })}
}
