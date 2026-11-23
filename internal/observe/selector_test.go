package observe

import (
 "context"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestSelectorLabelOKQualifiedAndInjection(t *testing.T) {
 for _,tc:=range []struct{name,key,value string;want bool}{
  {"qualified key","app.kubernetes.io/name","checkout-api",true},
  {"empty value","tier","",true},
  {"unqualified key","app","checkout-api",true},
  {"equals injection","app=team","checkout-api",false},
  {"comma injection","app","checkout,prod",false},
  {"multiple slashes","team.io/app/role","checkout-api",false},
  {"uppercase DNS prefix","UPPER.io/name","checkout-api",false},
  {"query injection","app?role","checkout-api",false},
  {"oversized value","app","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",false},
 } {
  t.Run(tc.name,func(t *testing.T) {
   if got:=selectorLabelOK(tc.key,tc.value);got!=tc.want {
    t.Fatalf("selectorLabelOK(%q,%q) = %v, want %v",tc.key,tc.value,got,tc.want)
   }
  })
 }
}

func TestCollectAcceptsQualifiedAndEmptyValueLabelSelectors(t *testing.T) {
 for _,tc:=range []struct{name,key,value,want string}{
  {"qualified key","app.kubernetes.io/name","checkout-api","app.kubernetes.io/name=checkout-api"},
  {"empty value","tier","","tier="},
 } {
  t.Run(tc.name,func(t *testing.T) {
   sawPods:=false
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    switch r.URL.Path {
    case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
     _,_=fmt.Fprintf(w,`{"metadata":{"uid":"deployment-1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{%q:%q}}},"status":{"readyReplicas":1,"observedGeneration":1}}`,tc.key,tc.value)
    case "/api/v1/namespaces/golden-demo/pods":
     sawPods=true
     if got:=r.URL.Query().Get("labelSelector");got!=tc.want {
      t.Errorf("wrong Kubernetes selector: %q, want %q",got,tc.want)
     }
     _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[{"metadata":{"uid":"pod-1","name":"checkout-api-0","namespace":"golden-demo"},"status":{"phase":"Running"}}]}`)
    case "/api/v1/query":
     _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
    default:
     w.WriteHeader(http.StatusNotFound)
    }
   }))
   defer server.Close()
   raw,err:=Collect(context.Background(),fixture(server.URL))
   if err!=nil || len(raw)==0 || !sawPods {
    t.Fatalf("legitimate Kubernetes selector failed: err=%v bytes=%d pod_read=%v",err,len(raw),sawPods)
   }
  })
 }
}

func TestCollectRejectsSelectorControlCharactersBeforePodList(t *testing.T) {
 for _,tc:=range []struct{key,value string}{
  {"app=team","checkout-api"},
  {"app.kubernetes.io/name/extra","checkout-api"},
  {"app","checkout,prod"},
 } {
  t.Run(tc.key+"-"+tc.value,func(t *testing.T) {
   readPods:=false
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    if r.URL.Path!="/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api"{
     readPods=true
     w.WriteHeader(http.StatusInternalServerError)
     return
    }
    _,_=fmt.Fprintf(w,`{"metadata":{"uid":"deployment-1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{%q:%q}}},"status":{"readyReplicas":1,"observedGeneration":1}}`,tc.key,tc.value)
   }))
   defer server.Close()
   raw,err:=Collect(context.Background(),fixture(server.URL))
   if !errors.Is(err,ErrUnknown)||raw!=nil||readPods {
    t.Fatalf("unsafe selector must stop before other source reads: raw=%q err=%v readPods=%v",raw,err,readPods)
   }
  })
 }
}
