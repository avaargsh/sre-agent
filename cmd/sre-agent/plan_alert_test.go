package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/avaargsh/sre-agent/internal/alertintake"
)

const testAlert = `{"status":"firing","groupKey":"g1","commonLabels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api","severity":"sev2","alertname":"CheckoutHighLatency"},"commonAnnotations":{"summary":"checkout latency above SLO"},"alerts":[{"status":"firing","fingerprint":"0123456789abcdef","labels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api"}}]}`

func TestPlanAlertCLIEmitsCreateOnlyReadOnlyIntent(t *testing.T) {
 dir:=t.TempDir()
 input:=filepath.Join(dir,"alert.json")
 output:=filepath.Join(dir,"plan.json")
 if err:=os.WriteFile(input,[]byte(testAlert),0600);err!=nil{t.Fatal(err)}
 args:=[]string{"plan-alert","--file",input,"--cluster","lab-a","--namespace","golden-demo","--deployment","checkout-api","--out",output}
 var stdout,stderr bytes.Buffer
 if exit:=run(args,&stdout,&stderr);exit!=0{t.Fatalf("exit=%d stderr=%s",exit,stderr.String())}
 info,err:=os.Stat(output)
 if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600{t.Fatalf("unexpected mode %v",info.Mode())}
 raw,err:=os.ReadFile(output)
 if err!=nil{t.Fatal(err)}
 var got alertintake.Plan
 if err:=json.Unmarshal(raw,&got);err!=nil{t.Fatal(err)}
 hash:=sha256.Sum256([]byte(testAlert))
 if got.SchemaVersion!="sre.alert-plan/v1"||got.IncidentID==""||got.Status!="READ_ONLY_CANDIDATE"||
 got.RawSHA256!=hex.EncodeToString(hash[:])||got.SourceAuthenticated||got.AuthorizesExecution {
  t.Fatalf("untrusted alert granted authority or produced wrong plan: %+v",got)
 }
 stdout.Reset();stderr.Reset()
 if exit:=run(args,&stdout,&stderr);exit!=1 {t.Fatalf("replayed same input overwrote artifact: exit=%d",exit)}
 final,err:=os.ReadFile(output)
 if err!=nil||!bytes.Equal(raw,final){t.Fatal("replay mutated frozen plan")}
}

func TestPlanAlertCLIUnknownCreatesNoReport(t *testing.T) {
 dir:=t.TempDir()
 input:=filepath.Join(dir,"alert.json")
 output:=filepath.Join(dir,"plan.json")
 payload:=strings.Replace(testAlert,`"namespace":"golden-demo"`,`"namespace":"unauthorized"`,1)
 if err:=os.WriteFile(input,[]byte(payload),0600);err!=nil{t.Fatal(err)}
 var stdout,stderr bytes.Buffer
 exit:=run([]string{"plan-alert","--file",input,"--cluster","lab-a","--namespace","golden-demo","--deployment","checkout-api","--out",output},&stdout,&stderr)
 if exit!=3||stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:") {
  t.Fatalf("expected fail-closed unknown: exit=%d stderr=%s",exit,stderr.String())
 }
 if _,err:=os.Stat(output);!os.IsNotExist(err){t.Fatal("UNKNOWN alert created plan file")}
}
