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

func TestCollectRequiresExplicitPodListItemsArray(t *testing.T) {
 for _,tc:=range []struct{name,podList string;invalid bool}{
  {"omitted-items",`{"metadata":{"resourceVersion":"rv2"}}`,true},
  {"null-items",`{"metadata":{"resourceVersion":"rv2"},"items":null}`,true},
  {"empty-array",`{"metadata":{"resourceVersion":"rv2"},"items":[]}`,false},
  {"valid-pod-array",`{"metadata":{"resourceVersion":"rv2"},"items":[{"metadata":{"uid":"p1","name":"checkout-api-0","namespace":"golden-demo"},"status":{"phase":"Running"}}]}`,false},
 }{
  t.Run(tc.name,func(t *testing.T){
   var prometheusReads atomic.Int32
   srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    if r.Method!=http.MethodGet{t.Errorf("unexpected write method: %s",r.Method);w.WriteHeader(405);return}
    switch r.URL.Path{
    case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
     _,_=fmt.Fprint(w,`{"metadata":{"uid":"deployment-1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"rv1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`)
    case "/api/v1/namespaces/golden-demo/pods":
     _,_=fmt.Fprint(w,tc.podList)
    case "/api/v1/query":
     prometheusReads.Add(1)
     _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
    default:
     w.WriteHeader(404)
    }
   }))
   defer srv.Close()
   raw,err:=Collect(context.Background(),fixture(srv.URL))
   if tc.invalid{
    if !errors.Is(err,ErrUnknown)||raw!=nil||prometheusReads.Load()!=0{
     t.Fatalf("missing items cannot be published as complete: raw=%q err=%v prometheusReads=%d",raw,err,prometheusReads.Load())
    }
   }else{
    if err!=nil||len(raw)==0||prometheusReads.Load()!=1{
     t.Fatalf("real PodList items array rejected: rawlen=%d err=%v prometheusReads=%d",len(raw),err,prometheusReads.Load())
    }
   }
  })
 }
}
