package change

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)
var testNow=time.Date(2026,11,22,12,0,0,0,time.UTC)
func config(endpoint string)Config{return Config{APIURL:endpoint,Namespace:"golden-demo",Deployment:"checkout-api",Token:"readonly-token",WindowStart:testNow.Add(-10*time.Minute),WindowEnd:testNow,Now:func()time.Time{return testNow}}}
func deploymentJSON(rv string)string{
 return fmt.Sprintf(`{"metadata":{"uid":"dep-uid","name":"checkout-api","namespace":"golden-demo","resourceVersion":"%s","generation":2},"status":{"observedGeneration":2}}`,rv)
}
func rsJSON(created string)string{
 return fmt.Sprintf(`{"metadata":{"resourceVersion":"86"},"items":[{"metadata":{"uid":"rs-1","name":"checkout-api-old","namespace":"golden-demo","resourceVersion":"81","creationTimestamp":"2026-11-22T11:00:00Z","annotations":{"deployment.kubernetes.io/revision":"1"},"ownerReferences":[{"uid":"dep-uid","kind":"Deployment","controller":true}]},"spec":{"replicas":0}},{"metadata":{"uid":"rs-2","name":"checkout-api-new","namespace":"golden-demo","resourceVersion":"85","creationTimestamp":"%s","annotations":{"deployment.kubernetes.io/revision":"2"},"ownerReferences":[{"uid":"dep-uid","kind":"Deployment","controller":true}]},"spec":{"replicas":2}},{"metadata":{"uid":"foreign","name":"other","namespace":"golden-demo","resourceVersion":"55","creationTimestamp":"2026-11-22T11:57:00Z","annotations":{"deployment.kubernetes.io/revision":"3"},"ownerReferences":[{"uid":"another-deployment","kind":"Deployment","controller":true}]},"spec":{"replicas":2}}]}`,created)
}
func serve(t *testing.T, drift, forbidden bool, rsOverride string)(*httptest.Server,*[]string){
 t.Helper()
 calls:=&[]string{}
 depReads:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  *calls=append(*calls,r.Method+" "+r.URL.RequestURI())
  if r.Method!="GET"||r.Header.Get("Authorization")!="Bearer readonly-token"{w.WriteHeader(403);return}
  if forbidden{w.WriteHeader(403);return}
  switch r.URL.Path{
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   depReads++
   rv:="85"
   if drift&&depReads==2{rv="86"}
   _,_=fmt.Fprint(w,deploymentJSON(rv))
  case "/apis/apps/v1/namespaces/golden-demo/replicasets":
   if r.URL.Query().Get("limit")!="129"{t.Errorf("expected bounded list, got %s",r.URL.RawQuery)}
   data:=rsJSON("2026-11-22T11:57:00Z")
   if rsOverride!=""{data=rsOverride}
   _,_=fmt.Fprint(w,data)
  default:t.Errorf("unexpected path: %s",r.URL.Path);w.WriteHeader(404)
  }
 }))
 t.Cleanup(srv.Close)
 return srv,calls
}
func TestCollectTimelineObservedButRCAUnverified(t *testing.T){
 srv,calls:=serve(t,false,false,"")
 got,err:=Collect(context.Background(),config(srv.URL))
 if err!=nil{t.Fatal(err)}
 if got.Status!="OBSERVED"||got.Relationship!="TIME_OVERLAP_ONLY"{t.Fatalf("unexpected timeline %+v",got)}
 if len(got.Revisions)!=2||got.Revisions[0].Revision!="1"||got.Revisions[1].Revision!="2"{t.Fatalf("foreign or misordered ReplicaSet: %+v",got.Revisions)}
 if !strings.Contains(got.Explanation,"UNVERIFIED"){t.Fatal("mistaken causal RCA claim")}
 if len(got.Sources)!=3||len(*calls)!=3{t.Fatalf("wrong source count: %d %v",len(got.Sources),*calls)}
 for _,req:=range *calls{if !strings.HasPrefix(req,"GET "){t.Fatalf("write request: %s",req)}}
 for _,source:=range got.Sources{
  raw,err:=base64.StdEncoding.DecodeString(source.RawResponseBase64)
  if err!=nil{t.Fatal(err)}
  sha:=sha256.Sum256(raw)
  if fmt.Sprintf("%x",sha[:])!=source.ResponseSHA256{t.Fatal("source hash mismatch")}
 }
}
func TestNoChangesInWindowNotSameAsNoRootCause(t *testing.T){
 srv,_:=serve(t,false,false,rsJSON("2026-11-22T11:45:00Z"))
 got,err:=Collect(context.Background(),config(srv.URL))
 if err!=nil{t.Fatal(err)}
 if got.Relationship!="NO_REVISION_CREATED_IN_WINDOW"||!strings.Contains(got.Explanation,"UNVERIFIED"){t.Fatalf("bad causal inference: %+v",got)}
}
func TestDeploymentDriftMustFailClosed(t *testing.T){
 srv,_:=serve(t,true,false,"")
 got,err:=Collect(context.Background(),config(srv.URL))
 if err==nil||got.Status=="OBSERVED"{t.Fatalf("accepted inconsistent deployment snapshot: %+v %v",got,err)}
}
func TestKubernetesForbiddenMustFailClosed(t *testing.T){
 srv,_:=serve(t,false,true,"")
 _,err:=Collect(context.Background(),config(srv.URL))
 if err==nil||!strings.Contains(err.Error(),"403"){t.Fatalf("accepted 403: %v",err)}
}
func TestRejectForeignOnlyAndUnpagedList(t *testing.T){
 for name,data:=range map[string]string{
  "empty":`{"metadata":{"resourceVersion":"86"},"items":[]}`,
  "page":`{"metadata":{"resourceVersion":"86","continue":"cursor"},"items":[]}`,
  "missing-rv":`{"metadata":{},"items":[]}`,
 }{
  t.Run(name,func(t *testing.T){
   srv,_:=serve(t,false,false,data)
   if _,err:=Collect(context.Background(),config(srv.URL));err==nil{t.Fatal("accepted invalid snapshot")}
  })
 }
}
func TestRejectUntrustedScopeWindowTransport(t *testing.T){
 for _,mutate:=range []func(*Config){
  func(c *Config){c.Namespace="../kube-system"},
  func(c *Config){c.APIURL="http://example.com"},
  func(c *Config){c.WindowStart=c.WindowEnd.Add(time.Minute)},
  func(c *Config){c.WindowEnd=c.WindowEnd.Add(time.Minute)},
  func(c *Config){c.WindowStart=c.WindowEnd.Add(-25*time.Hour)},
 }{
  c:=config("http://127.0.0.1:1")
  mutate(&c)
  if _,err:=Collect(context.Background(),c);err==nil{t.Fatalf("unsafe configuration accepted: %+v",c)}
 }
}
