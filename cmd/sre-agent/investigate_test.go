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
 "sync/atomic"
 "time"
 "github.com/avaargsh/sre-agent/internal/evidence"
)
func TestInvestigateCLIProducesVerifiableBundleUsingOnlyGET(t *testing.T){
 var methods []string
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  methods=append(methods,r.Method)
  switch r.URL.Path {
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
  case "/api/v1/query":
   _,_=fmt.Fprintf(w,`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d,"0.2"]}]}}`,time.Now().Unix())
  default:w.WriteHeader(404)
  }
 }))
 defer srv.Close()
 path:=filepath.Join(t.TempDir(),"evidence.json")
 args:=[]string{"investigate","--kube-api",srv.URL,"--prometheus",srv.URL,"--namespace","golden-demo","--deployment","checkout-api","--incident-id","inc-001","--summary","latency","--out",path}
 var stdout,stderr bytes.Buffer
 if exit:=run(args,&stdout,&stderr);exit!=0{t.Fatalf("exit=%d stderr=%s",exit,stderr.String())}
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if _,err:=evidence.Verify(raw);err!=nil{t.Fatalf("unverifiable evidence file: %v",err)}
 if len(methods)!=3{t.Fatalf("unexpected requests: %v",methods)}
 for _,method:=range methods{if method!="GET"{t.Fatalf("mutating request: %s",method)}}
 if exit:=run(args,&stdout,&stderr);exit!=1{t.Fatal("overwrote immutable evidence artifact")}
}
func TestInvestigateUnknownDoesNotWriteArtifact(t *testing.T){
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(403)}))
 defer srv.Close()
 path:=filepath.Join(t.TempDir(),"evidence.json")
 var stdout,stderr bytes.Buffer
 exit:=run([]string{"investigate","--kube-api",srv.URL,"--prometheus",srv.URL,"--namespace","golden-demo","--deployment","checkout-api","--incident-id","inc-001","--summary","latency","--out",path},&stdout,&stderr)
 if exit!=3||!strings.Contains(stderr.String(),"UNKNOWN:"){t.Fatalf("exit=%d stderr=%s",exit,stderr.String())}
 if _,err:=os.Stat(path);!os.IsNotExist(err){t.Fatal("created evidence file for UNKNOWN collection")}
}


func TestInvestigateExistingOutputSkipsObservation(t *testing.T) {
 dir := t.TempDir()
 for _, alias := range []bool{false, true} {
  name := "regular"
  if alias { name = "symlink" }
  t.Run(name, func(t *testing.T) {
   target := filepath.Join(dir, name+".json")
   original := []byte("preserved evidence")
   source := target
   if alias { source = filepath.Join(dir, "protected.json") }
   if err := os.WriteFile(source, original, 0600); err != nil { t.Fatal(err) }
   if alias { if err := os.Symlink(source, target); err != nil { t.Fatal(err) } }
   var hits atomic.Int32
   srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    hits.Add(1)
    w.WriteHeader(http.StatusForbidden)
   }))
   defer srv.Close()
   var stdout, stderr bytes.Buffer
   exit := run([]string{"investigate", "--kube-api", srv.URL, "--prometheus", srv.URL,
    "--namespace", "golden-demo", "--deployment", "checkout-api",
    "--incident-id", "inc-001", "--summary", "latency", "--out", target}, &stdout, &stderr)
   if exit != 1 || stdout.Len() != 0 { t.Fatalf("existing output: exit=%d stderr=%s", exit, stderr.String()) }
   if hits.Load() != 0 { t.Fatalf("existing output triggered %d reads", hits.Load()) }
   got, err := os.ReadFile(source)
   if err != nil || !bytes.Equal(got, original) { t.Fatalf("existing evidence changed: %q %v", got, err) }
   if alias { if got, err := os.Readlink(target); err != nil || got != source { t.Fatal("existing alias changed") } }
  })
 }
}
