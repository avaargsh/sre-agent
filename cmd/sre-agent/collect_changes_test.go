package main

import (
 "bytes"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestCollectChangesCLIReadOnlyAndImmutable(t *testing.T){
 calls:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls++
  if r.Method!="GET"{t.Errorf("write attempted: %s",r.Method);w.WriteHeader(405);return}
  switch r.URL.Path{
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"dep","name":"checkout-api","namespace":"golden-demo","resourceVersion":"2","generation":1},"status":{"observedGeneration":1}}`)
  case "/apis/apps/v1/namespaces/golden-demo/replicasets":
   created:=time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
   _,_=fmt.Fprintf(w,`{"metadata":{"resourceVersion":"12"},"items":[{"metadata":{"uid":"rs","name":"checkout-api-abc","namespace":"golden-demo","resourceVersion":"11","creationTimestamp":"%s","annotations":{"deployment.kubernetes.io/revision":"1"},"ownerReferences":[{"uid":"dep","kind":"Deployment","controller":true}]},"spec":{"replicas":2}}]}`,created)
  default:t.Errorf("unexpected path %s",r.URL.Path);w.WriteHeader(404)
  }
 }))
 defer srv.Close()
 path:=filepath.Join(t.TempDir(),"changes.json")
 start:=time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339)
 end:=time.Now().UTC().Format(time.RFC3339)
 args:=[]string{"collect-changes","--kube-api",srv.URL,"--namespace","golden-demo","--deployment","checkout-api","--start",start,"--end",end,"--out",path}
 var stdout,stderr bytes.Buffer
 if code:=run(args,&stdout,&stderr);code!=0{t.Fatalf("status %d: %s",code,stderr.String())}
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if !bytes.Contains(raw,[]byte(`"relationship": "TIME_OVERLAP_ONLY"`))||!bytes.Contains(raw,[]byte("UNVERIFIED")){t.Fatalf("incorrect causal report: %s",raw)}
 if calls!=3{t.Fatalf("expected 3 GETs, got %d",calls)}
 if code:=run(args,&stdout,&stderr);code!=1{t.Fatal("overwrote frozen change evidence file")}
}
func TestCollectChangesCLI403LeavesNoFile(t *testing.T){
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(403)}))
 defer srv.Close()
 path:=filepath.Join(t.TempDir(),"changes.json")
 var stdout,stderr bytes.Buffer
 code:=run([]string{"collect-changes","--kube-api",srv.URL,"--namespace","golden-demo","--deployment","checkout-api",
 "--start",time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339),"--end",time.Now().UTC().Format(time.RFC3339),"--out",path},&stdout,&stderr)
 if code!=3||!strings.Contains(stderr.String(),"UNKNOWN"){t.Fatalf("wrong rejection: code=%d stderr=%s",code,stderr.String())}
 if _,err:=os.Stat(path);!os.IsNotExist(err){t.Fatal("UNKNOWN emitted evidence artifact")}
}
