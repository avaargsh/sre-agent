package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "testing"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

// Exercise the actual command dispatcher, including the stdin boundary used
// by replay and verification. This test is intentionally not parallel.
func TestPodEventsCommandDispatch(t *testing.T) {
 var hits atomic.Int32
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hits.Add(1)
  if r.Method!=http.MethodGet {t.Errorf("unexpected method: %s",r.Method);w.WriteHeader(405);return}
  switch r.URL.Path {
  case "/api/v1/namespaces/demo/pods/checkout-1":
   _,_=fmt.Fprint(w,cliPod)
  case "/api/v1/namespaces/demo/events":
   if r.URL.Query().Get("fieldSelector")!="involvedObject.uid=pod-uid-1" {t.Error("wrong event selector");w.WriteHeader(400);return}
   _,_=fmt.Fprint(w,cliEvents)
  default:w.WriteHeader(404)
  }
 }));defer server.Close()
 target:=poddiagnosis.Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 pod,err:=poddiagnosis.AssessNative(target,[]byte(cliPod));if err!=nil{t.Fatal(err)}
 events,err:=poddiagnosis.AssessEvents(target,[]byte(cliEvents));if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name,raw,kind string;report any}{
  {"pod",cliPod,"pod",pod},{"events",cliEvents,"events",events},
 }{
  claim,err:=json.Marshal(tc.report);if err!=nil{t.Fatal(err)}
  pin:=fmt.Sprintf("%x",sha256.Sum256([]byte(tc.raw)))
  reportPath:=filepath.Join(t.TempDir(),"report.json")
  if err:=os.WriteFile(reportPath,claim,0600);err!=nil{t.Fatal(err)}
  for _,step:=range []struct{command,input,want string;args []string;code int;reads int32}{
   {"capture-"+tc.kind,"",tc.raw,[]string{"--kube-api",server.URL},0,1},
   {"replay-"+tc.kind,tc.raw,string(claim)+"\n",[]string{"--sha256",pin},0,0},
   {"verify-"+tc.kind+"-report",tc.raw,"STRUCTURALLY_LINKED\n",[]string{"--sha256",pin,"--report",reportPath},0,0},
   {"replay-"+tc.kind,tc.raw+" ","",[]string{"--sha256",pin},3,0},
  }{
   name:=step.command;if step.code!=0{name+="-tampered"}
   t.Run(name,func(t *testing.T){
    inputPath:=filepath.Join(t.TempDir(),"stdin")
    if err:=os.WriteFile(inputPath,[]byte(step.input),0600);err!=nil{t.Fatal(err)}
    input,err:=os.Open(inputPath);if err!=nil{t.Fatal(err)}
    previous:=os.Stdin;os.Stdin=input
    defer func(){os.Stdin=previous;_ = input.Close()}()
    var out,stderr bytes.Buffer
    before:=hits.Load()
    args:=append([]string{step.command},cliTargetArgs()...);args=append(args,step.args...)
    if code:=run(args,&out,&stderr);code!=step.code || out.String()!=step.want || hits.Load()-before!=step.reads {t.Fatalf("dispatch %s: exit=%d stdout=%q stderr=%s reads=%d",step.command,code,out.String(),stderr.String(),hits.Load()-before)}
   })
  }
 }
 var out,stderr bytes.Buffer
 if code:=run(nil,&out,&stderr);code!=2{t.Fatalf("missing command returned %d",code)}
 for _,cmd:=range []string{"capture-pod","replay-pod","verify-pod-report","capture-events","replay-events","verify-events-report"}{
  if !strings.Contains(stderr.String(),cmd){t.Errorf("usage missing %s",cmd)}
 }
}
