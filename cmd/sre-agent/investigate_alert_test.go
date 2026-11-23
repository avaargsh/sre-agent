package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/alertintake"
 "github.com/avaargsh/sre-agent/internal/evidence"
)

func alertBridgeInputs(t *testing.T)(string,string,string){
 t.Helper()
 dir:=t.TempDir()
 alertFile:=filepath.Join(dir,"alert.json")
 planFile:=filepath.Join(dir,"plan.json")
 output:=filepath.Join(dir,"bundle.json")
 if err:=os.WriteFile(alertFile,[]byte(testAlert),0600);err!=nil {t.Fatal(err)}
 var stdout,stderr bytes.Buffer
 if status:=run([]string{"plan-alert","--file",alertFile,"--cluster","lab-a","--namespace","golden-demo","--deployment","checkout-api","--out",planFile},&stdout,&stderr);status!=0{
  t.Fatalf("cannot prepare plan: status=%d stderr=%s",status,stderr.String())
 }
 return alertFile,planFile,output
}

func bridgeArgs(alertFile,planFile,out,url string) []string {
 return []string{"investigate-alert","--alert-file",alertFile,"--plan",planFile,
  "--cluster","lab-a","--namespace","golden-demo","--deployment","checkout-api",
  "--kube-api",url,"--prometheus",url,"--query","max(checkout_request_latency_seconds)",
  "--out",out}
}

func TestAlertPlanToReadOnlyEvidenceRealHTTPAndReplay(t *testing.T){
 alertFile,planFile,out:=alertBridgeInputs(t)
 var mu sync.Mutex
 calls:=[]string{}
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  mu.Lock()
  calls=append(calls,r.Method+" "+r.URL.RequestURI())
  mu.Unlock()
  switch r.URL.Path {
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
  case "/api/v1/query":
   _,_=fmt.Fprintf(w,`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d,"0.2"]}]}}`,time.Now().Unix())
  default:
   w.WriteHeader(http.StatusNotFound)
  }
 }))
 defer srv.Close()
 var stdout,stderr bytes.Buffer
 args:=bridgeArgs(alertFile,planFile,out,srv.URL)
 if status:=run(args,&stdout,&stderr);status!=0 {t.Fatalf("bridge status=%d stderr=%s",status,stderr.String())}
 raw,err:=os.ReadFile(out)
 if err!=nil {t.Fatal(err)}
 result,err:=evidence.Verify(raw)
 if err!=nil || result.EvidenceCount!=2||result.SupportedHypotheses!=0 {
  t.Fatalf("evidence must be structurally valid read-only observation: result=%+v err=%v",result,err)
 }
 var bundle map[string]any
 if err:=json.Unmarshal(raw,&bundle);err!=nil {t.Fatal(err)}
 plan,err:=alertintake.Parse([]byte(testAlert),alertintake.Target{Cluster:"lab-a",Namespace:"golden-demo",Deployment:"checkout-api"})
 if err!=nil {t.Fatal(err)}
 incident:=bundle["incident"].(map[string]any)
 if incident["incident_id"]!=plan.IncidentID || incident["summary"]!=plan.Summary || incident["severity"]!=plan.Severity {
  t.Fatalf("evidence lost alert/plan identity: %v",incident)
 }
 info,err:=os.Stat(out)
 if err!=nil || info.Mode().Perm()!=0600 {t.Fatalf("invalid evidence file permissions: %v %v",info,err)}
 mu.Lock()
 before:=len(calls)
 for _,request:=range calls {if !strings.HasPrefix(request,"GET "){mu.Unlock();t.Fatalf("mutation attempted: %s",request)}}
 mu.Unlock()
 if before!=3 {t.Fatalf("should do exactly 3 read-only source requests, got %d",before)}
 stdout.Reset();stderr.Reset()
 if status:=run(args,&stdout,&stderr);status!=1 {t.Fatalf("replay overwrote artifact: %d %s",status,stderr.String())}
 after,err:=os.ReadFile(out)
 if err!=nil||!bytes.Equal(raw,after){t.Fatal("replay changed frozen evidence")}
 mu.Lock()
 later:=len(calls)
 mu.Unlock()
 if later!=before {t.Fatal("replayed output must not repeat external source reads")}
}

func TestAlertBridgeFailsClosedBeforeAnyNetworkRead(t *testing.T){
 alertFile,planFile,out:=alertBridgeInputs(t)
 var mu sync.Mutex
 hits:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  mu.Lock();hits++;mu.Unlock()
  w.WriteHeader(http.StatusForbidden)
 }))
 defer srv.Close()
 origPlan,err:=os.ReadFile(planFile)
 if err!=nil {t.Fatal(err)}
 origAlert,err:=os.ReadFile(alertFile)
 if err!=nil {t.Fatal(err)}
 cases:=[]struct{
  name string
  mutate func() error
  args func([]string) []string
 }{
  {"tampered-plan",func()error{return os.WriteFile(planFile,bytes.Replace(origPlan,[]byte(`"source_authenticated": false`),[]byte(`"source_authenticated": true`),1),0600)},nil},
  {"stale-plan-for-updated-alert",func()error{return os.WriteFile(alertFile,bytes.Replace(origAlert,[]byte("checkout latency above SLO"),[]byte("new text in alert"),1),0600)},nil},
  {"wrong-operator-namespace",func()error{return nil},func(args []string)[]string{
   for i:=range args {if args[i]=="--namespace" {args[i+1]="other-namespace"; break}}
   return args
  }},
  {"resolved-alert",func()error{return os.WriteFile(alertFile,bytes.Replace(origAlert,[]byte(`"status":"firing"`),[]byte(`"status":"resolved"`),1),0600)},nil},
  {"oversize-plan",func()error{return os.WriteFile(planFile,bytes.Repeat([]byte{'a'},alertintake.MaxPlanBytes+1),0600)},nil},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   if err:=os.WriteFile(alertFile,origAlert,0600);err!=nil {t.Fatal(err)}
   if err:=os.WriteFile(planFile,origPlan,0600);err!=nil {t.Fatal(err)}
   if err:=tc.mutate();err!=nil {t.Fatal(err)}
   args:=bridgeArgs(alertFile,planFile,out,srv.URL)
   if tc.args!=nil {args=tc.args(args)}
   var stdout,stderr bytes.Buffer
   if status:=run(args,&stdout,&stderr);status!=3 || stdout.Len()!=0 || !strings.Contains(stderr.String(),"UNKNOWN:") {
    t.Fatalf("must fail UNKNOWN without evidence; status=%d stdout=%s stderr=%s",status,stdout.String(),stderr.String())
   }
   if _,err:=os.Stat(out);!os.IsNotExist(err){t.Fatal("invalid alert or plan produced evidence")}
  })
 }
 mu.Lock()
 defer mu.Unlock()
 if hits!=0 {t.Fatalf("invalid plans initiated %d network requests",hits)}
}
