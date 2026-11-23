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

func TestCollectRefusesPrometheusWarningsOnSuccess(t *testing.T) {
 cases:=[]struct{name,warnings string;wantUnknown bool}{
  {"single warning",`"warnings":["partial response: one source failed"],`,true},
  {"multiple warnings",`"warnings":["partial response","series dropped"],`,true},
  {"empty warnings",`"warnings":[],`,false},
  {"no warnings field","",false},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   var prometheusReads atomic.Int32
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    if r.Method!=http.MethodGet {t.Errorf("write method requested: %s",r.Method)}
    switch r.URL.Path{
    case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
     _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
    case "/api/v1/namespaces/golden-demo/pods":
     _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
    case "/api/v1/query":
     prometheusReads.Add(1)
     _,_=fmt.Fprintf(w,`{"status":"success",%s"data":{"resultType":"vector","result":%s}}`,tc.warnings,validSample)
    default:
     w.WriteHeader(http.StatusNotFound)
    }
   }))
   defer server.Close()
   raw,err:=Collect(context.Background(),fixture(server.URL))
   if prometheusReads.Load()!=1 {t.Fatalf("unexpected metric query calls: %d",prometheusReads.Load())}
   if tc.wantUnknown {
    if !errors.Is(err,ErrUnknown)||raw!=nil {
     t.Fatalf("warning-bearing success must return UNKNOWN without a bundle: raw=%q err=%v",raw,err)
    }
    if err!=nil&&strings.Contains(err.Error(),"partial response: one source failed"){
     t.Fatal("remote warnings should not be leaked into evidence error messages")
    }
   }else if err!=nil||len(raw)==0 {
    t.Fatalf("clean successful response rejected: rawlen=%d err=%v",len(raw),err)
   }
  })
 }
}
