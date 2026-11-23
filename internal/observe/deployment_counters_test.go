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

func TestDeploymentCounterContract(t *testing.T) {
 for _,tc:=range []struct{name string;generation,observed int64;desired,ready int;invalid bool}{
  {"valid",3,3,2,2,false},
  {"rolling update allows temporary excess ready",4,3,2,3,false},
  {"no ready replicas",4,0,0,0,false},
  {"negative generation",-1,0,1,1,true},
  {"negative observed generation",2,-1,1,1,true},
  {"observed generation ahead",2,3,1,1,true},
  {"negative desired replicas",2,2,-1,0,true},
  {"negative ready replicas",2,2,1,-1,true},
 }{
  t.Run(tc.name,func(t *testing.T){
   err:=validateDeploymentCounters(tc.generation,tc.observed,tc.desired,tc.ready)
   if (err!=nil)!=tc.invalid{t.Fatalf("unexpected counter verdict: err=%v invalid=%v",err,tc.invalid)}
  })
 }
}

func TestCollectRejectsImpossibleDeploymentCountersBeforeOtherReads(t *testing.T){
 for _,tc:=range []struct{name string;generation,observed int64;desired,ready int}{
  {"negative-generation",-1,0,2,2},
  {"negative-observed-generation",3,-1,2,2},
  {"observed-ahead-of-generation",3,4,2,2},
  {"negative-desired-replicas",3,3,-1,2},
  {"negative-ready-replicas",3,3,2,-1},
 }{
  t.Run(tc.name,func(t *testing.T){
   var extraRead atomic.Bool
   srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    switch r.URL.Path{
    case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
     _,_=fmt.Fprintf(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":%d},"spec":{"replicas":%d,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":%d,"observedGeneration":%d}}`,tc.generation,tc.desired,tc.ready,tc.observed)
    default:
     extraRead.Store(true)
     w.WriteHeader(http.StatusInternalServerError)
    }
   }))
   defer srv.Close()
   raw,err:=Collect(context.Background(),fixture(srv.URL))
   if !errors.Is(err,ErrUnknown)||raw!=nil||extraRead.Load(){
    t.Fatalf("invalid deployment counters must fail before Pod and metric reads: raw=%q err=%v extraRead=%v",raw,err,extraRead.Load())
   }
  })
 }
}
