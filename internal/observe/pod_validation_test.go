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

func TestValidatePodProjectionRejectsContradictions(t *testing.T) {
 cases:=[]struct{name string;pods []map[string]string;bad bool}{
  {"valid",[]map[string]string{{"uid":"p1","name":"checkout-1","phase":"Running"},{"uid":"p2","name":"checkout-2","phase":"Pending"}},false},
  {"empty accepted",[]map[string]string{},false},
  {"duplicate UID",[]map[string]string{{"uid":"p1","name":"checkout-1","phase":"Running"},{"uid":"p1","name":"checkout-2","phase":"Running"}},true},
  {"duplicate name",[]map[string]string{{"uid":"p1","name":"checkout-1","phase":"Running"},{"uid":"p2","name":"checkout-1","phase":"Pending"}},true},
  {"invalid phase",[]map[string]string{{"uid":"p1","name":"checkout-1","phase":"Rebooting"}},true},
  {"missing phase",[]map[string]string{{"uid":"p1","name":"checkout-1"}},true},
  {"missing UID",[]map[string]string{{"name":"checkout-1","phase":"Running"}},true},
  {"missing name",[]map[string]string{{"uid":"p1","phase":"Running"}},true},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   err:=validatePodProjection(tc.pods)
   if (err!=nil)!=tc.bad{t.Fatalf("got err=%v want failure=%v",err,tc.bad)}
  })
 }
}

func TestCollectRejectsImpossiblePodSnapshotBeforePrometheus(t *testing.T){
 cases:=map[string]string{
  "duplicate-uid":`[{"metadata":{"uid":"pod-1","name":"checkout-1","namespace":"golden-demo"},"status":{"phase":"Running"}},{"metadata":{"uid":"pod-1","name":"checkout-2","namespace":"golden-demo"},"status":{"phase":"Pending"}}]`,
  "duplicate-name":`[{"metadata":{"uid":"pod-1","name":"checkout-1","namespace":"golden-demo"},"status":{"phase":"Running"}},{"metadata":{"uid":"pod-2","name":"checkout-1","namespace":"golden-demo"},"status":{"phase":"Pending"}}]`,
  "invalid-phase":`[{"metadata":{"uid":"pod-1","name":"checkout-1","namespace":"golden-demo"},"status":{"phase":"Rebooting"}}]`,
  "missing-phase":`[{"metadata":{"uid":"pod-1","name":"checkout-1","namespace":"golden-demo"},"status":{}}]`,
 }
 for name,items:=range cases{
  t.Run(name,func(t *testing.T){
   var prometheusRead atomic.Bool
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    switch r.URL.Path{
    case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
     _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
    case "/api/v1/namespaces/golden-demo/pods":
     _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":`+items+`}`)
    case "/api/v1/query":
     prometheusRead.Store(true)
     _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
    default:
     w.WriteHeader(http.StatusNotFound)
    }
   }))
   defer server.Close()
   raw,err:=Collect(context.Background(),fixture(server.URL))
   if !errors.Is(err,ErrUnknown)||raw!=nil||prometheusRead.Load(){
    t.Fatalf("invalid Pod list must stop without Evidence Bundle or Prometheus GET: raw=%q err=%v prometheusRead=%v",raw,err,prometheusRead.Load())
   }
  })
 }
}
