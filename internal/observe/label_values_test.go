package observe

import (
 "context"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
)

func TestCollectSelectorLabelValueTypes(t *testing.T) {
 for _,tc:=range []struct{name,value string;valid bool}{
  {"empty",`""`,true},
  {"normal",`"prod"`,true},
  {"null",`null`,false},
  {"number",`0`,false},
  {"boolean",`false`,false},
  {"object",`{}`,false},
 } {t.Run(tc.name,func(t *testing.T){
  var extra atomic.Int32
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   switch r.URL.Path {
   case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
    _,_=fmt.Fprintf(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"tier":%s}}},"status":{"readyReplicas":1,"observedGeneration":1}}`,tc.value)
   case "/api/v1/namespaces/golden-demo/pods":
    extra.Add(1)
    if tc.valid && r.URL.Query().Get("labelSelector")!="tier="+tc.value[1:len(tc.value)-1] {t.Errorf("unexpected selector %q",r.URL.RawQuery)}
    _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
   case "/api/v1/query":
    extra.Add(1)
    _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
   default:w.WriteHeader(404)
   }
  }));defer srv.Close()
  raw,err:=Collect(context.Background(),fixture(srv.URL))
  if tc.valid {
   if err!=nil||len(raw)==0||extra.Load()!=2 {t.Fatalf("valid label rejected: bytes=%d err=%v reads=%d",len(raw),err,extra.Load())}
  } else if !errors.Is(err,ErrUnknown)||raw!=nil||extra.Load()!=0 {t.Fatalf("invalid label admitted: bytes=%d err=%v reads=%d",len(raw),err,extra.Load())}
 })}
}

func TestCollectMetricLabelValueTypes(t *testing.T) {
 for _,tc:=range []struct{name,labels string;valid bool}{
  {"aggregate",`{}`,true},
  {"empty",`{"pod":""}`,true},
  {"normal",`{"pod":"checkout-0"}`,true},
  {"null",`{"pod":null}`,false},
  {"number",`{"pod":0}`,false},
  {"boolean",`{"pod":false}`,false},
  {"object",`{"pod":{}}`,false},
  {"null-labelset",`null`,false},
 } {t.Run(tc.name,func(t *testing.T){
  srv,_:=serve(t,`[{"metric":`+tc.labels+`,"value":[1795350600,"0.18"]}]`,false)
  raw,err:=Collect(context.Background(),fixture(srv.URL))
  if tc.valid {
   if err!=nil||len(raw)==0 {t.Fatalf("valid metric labels rejected: bytes=%d err=%v",len(raw),err)}
  } else if !errors.Is(err,ErrUnknown)||raw!=nil {t.Fatalf("invalid metric labels admitted: bytes=%d err=%v",len(raw),err)}
 })}
}
