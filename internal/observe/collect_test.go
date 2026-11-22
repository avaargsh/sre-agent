package observe

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync"
 "testing"
 "time"
 "github.com/avaargsh/sre-agent/internal/evidence"
)
const validSample=`[{"metric":{},"value":[1795350600,"0.18"]}]`

func serve(t *testing.T,sample string,denyKube bool)(*httptest.Server,*[]string){
 t.Helper()
 methods:=&[]string{}
 var mu sync.Mutex
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  mu.Lock();*methods=append(*methods,r.Method+" "+r.URL.RequestURI());mu.Unlock()
  switch r.URL.Path{
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   if denyKube{w.WriteHeader(403);return}
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"deployment-uid-1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"44","generation":3},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":3}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   if r.URL.Query().Get("labelSelector")!="app=checkout-api"{t.Errorf("unexpected selector: %s",r.URL.RawQuery)}
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"45"},"items":[{"metadata":{"uid":"pod-uid-1","name":"checkout-api-0","namespace":"golden-demo"},"status":{"phase":"Running"}}]}`)
  case "/api/v1/query":
   if r.URL.Query().Get("query")!="max(checkout_request_latency_seconds)"{t.Errorf("unexpected query: %s",r.URL.RawQuery)}
   _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+sample+`}}`)
  default:t.Errorf("unexpected endpoint: %s",r.URL.String());w.WriteHeader(404)
  }
 }))
 t.Cleanup(srv.Close)
 return srv,methods
}
func fixture(u string)Config{return Config{KubernetesURL:u,PrometheusURL:u,Namespace:"golden-demo",Deployment:"checkout-api",IncidentID:"inc-checkout",Summary:"latency",Severity:"sev2",Now:func()time.Time{return time.Unix(1795350600,0)},MaxMetricAge:90*time.Second}}
func TestCollectV1LegacyEvidenceAndGetOnly(t *testing.T){
 srv,methods:=serve(t,validSample,false)
 raw,err:=Collect(context.Background(),fixture(srv.URL))
 if err!=nil{t.Fatal(err)}
 verified,err:=evidence.Verify(raw)
 if err!=nil{t.Fatal(err)}
 if verified.EvidenceCount!=2||verified.SupportedHypotheses!=0{t.Fatalf("unexpected evidence summary: %+v",verified)}
 var doc map[string]any
 if err:=json.Unmarshal(raw,&doc);err!=nil{t.Fatal(err)}
 if doc["metadata"].(map[string]any)["bundle_sha256"]!=verified.BundleSHA256{t.Fatal("hash missing")}
 if len(*methods)!=3{t.Fatalf("wrong calls: %v",*methods)}
 for _,request:=range *methods{if !strings.HasPrefix(request,"GET "){t.Fatalf("write attempted: %s",request)}}
}
func TestUnknownForMissingStaleNaNInfAndPartialInvalidMetrics(t *testing.T){
 for name,sample:=range map[string]string{
  "missing":`[]`,
  "stale":`[{"metric":{},"value":[1,"0.18"]}]`,
  "nan":`[{"metric":{},"value":[1795350600,"NaN"]}]`,
  "inf":`[{"metric":{},"value":[1795350600,"+Inf"]}]`,
  "partial":`[{"metric":{"pod":"a"},"value":[1795350600,"0.18"]},{"metric":{"pod":"b"},"value":[1,"0.18"]}]`,
 }{
  t.Run(name,func(t *testing.T){
   srv,_:=serve(t,sample,false)
   raw,err:=Collect(context.Background(),fixture(srv.URL))
   if !errors.Is(err,ErrUnknown)||raw!=nil{t.Fatalf("must fail closed: raw=%q err=%v",raw,err)}
  })
 }
}
func TestKubernetes403Unknown(t *testing.T){
 srv,_:=serve(t,validSample,true)
 raw,err:=Collect(context.Background(),fixture(srv.URL))
 if !errors.Is(err,ErrUnknown)||raw!=nil{t.Fatalf("expected UNKNOWN, got %q %v",raw,err)}
}
func TestUnknownOnUnsafeEndpointAndSelector(t *testing.T){
 for _,c:=range []Config{
  fixture("http://example.com"),
  func()Config{c:=fixture("http://127.0.0.1:1");c.Namespace="../prod";return c}(),
  func()Config{c:=fixture("http://127.0.0.1:1");c.PrometheusURL="https://user:secret@example.com";return c}(),
 }{
  if _,err:=Collect(context.Background(),c);!errors.Is(err,ErrUnknown){t.Fatalf("accepted unsafe config: %v",err)}
 }
}
func TestNeverFollowRedirect(t *testing.T){
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,"http://example.com",302)}))
 defer srv.Close()
 if _,err:=Collect(context.Background(),fixture(srv.URL));!errors.Is(err,ErrUnknown){t.Fatal("followed untrusted redirect")}
}
func TestKubernetesTokenIsNotSentToPrometheus(t *testing.T){
 var kubeHeaders []string
 var promHeader string
 kube:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  kubeHeaders=append(kubeHeaders,r.Header.Get("Authorization"))
  if strings.Contains(r.URL.Path,"/deployments/"){
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}}}`)
  }else{
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
  }
 }))
 defer kube.Close()
 prom:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  promHeader=r.Header.Get("Authorization")
  _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
 }))
 defer prom.Close()
 c:=fixture(kube.URL);c.PrometheusURL=prom.URL;c.KubernetesBearerToken="readonly-test"
 if _,err:=Collect(context.Background(),c);err!=nil{t.Fatal(err)}
 if len(kubeHeaders)!=2||kubeHeaders[0]!="Bearer readonly-test"||kubeHeaders[1]!="Bearer readonly-test"||promHeader!=""{t.Fatal("Kubernetes credential leaked to Prometheus")}
}


func TestRejectsPaginatedKubernetesPodList(t *testing.T) {
 // A LIST with metadata.continue is a partial source. Reporting a complete
 // observation from the first page would conceal Pods and violate the G1
 // provenance/total-count boundary.
 seenPrometheus := false
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  switch r.URL.Path {
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   _,_=fmt.Fprint(w,`{"kind":"PodList","metadata":{"resourceVersion":"2","continue":"next-page-token"},"items":[]}`)
  case "/api/v1/query":
   seenPrometheus=true
   _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
  default:
   w.WriteHeader(http.StatusNotFound)
  }
 }))
 defer srv.Close()
 raw,err:=Collect(context.Background(),fixture(srv.URL))
 if !errors.Is(err,ErrUnknown)||raw!=nil{
  t.Fatalf("accepted partial Kubernetes list as complete: raw=%q err=%v",raw,err)
 }
 if seenPrometheus {t.Fatal("continued metric collection after incomplete pod source")}
}
