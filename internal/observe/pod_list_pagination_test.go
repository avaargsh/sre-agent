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

func TestCollectPodListPaginationMetadata(t *testing.T) {
 for _,tc:=range []struct{name,extra string;valid bool}{
  {"absent","",true},
  {"zero",`,"remainingItemCount":0`,true},
  {"zero-empty-continuation",`,"remainingItemCount":0,"continue":""`,true},
  {"positive",`,"remainingItemCount":1`,false},
  {"negative",`,"remainingItemCount":-1`,false},
  {"null-count",`,"remainingItemCount":null`,false},
  {"string-count",`,"remainingItemCount":"0"`,false},
  {"fractional-count",`,"remainingItemCount":0.0`,false},
  {"overflow-count",`,"remainingItemCount":9223372036854775808`,false},
  {"count-alias",`,"RemainingItemCount":0`,false},
  {"duplicate-count",`,"remainingItemCount":1,"remainingItemCount":0`,false},
  {"continuation",`,"remainingItemCount":0,"continue":"next"`,false},
  {"null-continuation",`,"continue":null`,false},
  {"continuation-alias",`,"Continue":""`,false},
 } {t.Run(tc.name,func(t *testing.T){
  var metrics atomic.Int32
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   if r.Method!=http.MethodGet {t.Errorf("unexpected method %s",r.Method);w.WriteHeader(405);return}
   switch r.URL.Path {
   case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
    _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`)
   case "/api/v1/namespaces/golden-demo/pods":
    _,_=fmt.Fprintf(w,`{"metadata":{"resourceVersion":"2"%s},"items":[]}`,tc.extra)
   case "/api/v1/query":
    metrics.Add(1)
    _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
   default:w.WriteHeader(404)
   }
  }));defer srv.Close()
  raw,err:=Collect(context.Background(),fixture(srv.URL))
  if tc.valid {
   if err!=nil||len(raw)==0||metrics.Load()!=1 {t.Fatalf("complete list rejected: bytes=%d err=%v metric reads=%d",len(raw),err,metrics.Load())}
  } else if !errors.Is(err,ErrUnknown)||raw!=nil||metrics.Load()!=0 {t.Fatalf("incomplete list admitted: bytes=%d err=%v metric reads=%d",len(raw),err,metrics.Load())}
 })}
}
