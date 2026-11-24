package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

const verifyCLIPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`

func TestVerifyPodReportCLI(t *testing.T) {
 raw:=[]byte(verifyCLIPod)
 pin:=fmt.Sprintf("%x",sha256.Sum256(raw))
 target:=poddiagnosis.Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 report,err:=poddiagnosis.AssessNative(target,raw);if err!=nil{t.Fatal(err)}
 claim,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name,body,digest,uid,receipt string; want int;missing bool}{
  {"valid",verifyCLIPod,pin,target.UID,string(claim),0,false},
  {"wrong pin",verifyCLIPod,strings.Repeat("0",64),target.UID,string(claim),3,false},
  {"wrong UID",verifyCLIPod,pin,"replacement",string(claim),3,false},
  {"tampered raw",verifyCLIPod+" ",pin,target.UID,string(claim),3,false},
  {"forged receipt",verifyCLIPod,pin,target.UID,strings.Replace(string(claim),`"source_authenticated":false`,`"source_authenticated":true`,1),3,false},
  {"missing receipt",verifyCLIPod,pin,target.UID,"",3,true},
  {"oversized receipt",verifyCLIPod,pin,target.UID,strings.Repeat(" ",poddiagnosis.MaxNativeReportBytes+1),3,false},
  {"bad pin syntax",verifyCLIPod,"bad",target.UID,string(claim),2,false},
 }{t.Run(tc.name,func(t *testing.T){
  path:=filepath.Join(t.TempDir(),"report.json")
  if !tc.missing {if err:=os.WriteFile(path,[]byte(tc.receipt),0600);err!=nil{t.Fatal(err)}}
  var out,stderr bytes.Buffer
  args:=[]string{"--namespace","demo","--pod","checkout-1","--uid",tc.uid,"--sha256",tc.digest,"--report",path}
  exit:=verifyPodReport(args,strings.NewReader(tc.body),&out,&stderr)
  if exit!=tc.want{t.Fatalf("exit=%d want=%d stderr=%s",exit,tc.want,stderr.String())}
  if tc.want==0 {if out.String()!="STRUCTURALLY_LINKED\n"{t.Fatalf("unexpected receipt: %q",out.String())}} else if out.Len()!=0 {t.Fatal("rejected claim emitted output")}
 })}
}
