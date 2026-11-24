package poddiagnosis

import (
 "encoding/json"
 "testing"
)

func TestPodPhaseAdmission(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 for _,tc:=range []struct{name,phase string;valid bool}{
  {"pending","Pending",true}, {"running","Running",true},
  {"succeeded","Succeeded",true}, {"failed","Failed",true},
  {"unknown","Unknown",true}, {"empty","",false},
  {"lowercase","running",false}, {"whitespace"," Running ",false},
  {"display-status","CrashLoopBackOff",false}, {"arbitrary","Healthy",false},
 } {
  t.Run(tc.name+"/normalized",func(t *testing.T){
   snapshot:=Snapshot{Target:target,ResourceVersion:"42",Phase:tc.phase,Containers:[]string{"app"},Statuses:[]ContainerStatus{{Name:"app",State:"waiting",Reason:"CrashLoopBackOff",RestartCount:5,LastTerminationReason:"OOMKilled"}}}
   got:=Assess(target,snapshot)
   if tc.valid {
    if got.Status!="SIGNALS_PRESENT"||len(got.Findings)!=2||got.RootCauseVerified||got.RecoveryVerified {t.Fatalf("valid phase rejected: %+v",got)}
   } else if got.Status!="UNKNOWN"||got.Reason!=invalidSnapshotReason||len(got.Findings)!=0 {t.Fatalf("invalid phase admitted: %+v",got)}
  })
  t.Run(tc.name+"/native",func(t *testing.T){
   phase,err:=json.Marshal(tc.phase);if err!=nil{t.Fatal(err)}
   raw:=[]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":`+string(phase)+`,"containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}}]}}`)
   got,err:=AssessNative(target,raw)
   if tc.valid {
    if err!=nil||got.RawSHA256==""||len(got.Assessment.Findings)!=2||got.SourceAuthenticated||got.Assessment.RootCauseVerified||got.Assessment.RecoveryVerified {t.Fatalf("valid phase rejected: %+v %v",got,err)}
   } else if err==nil||got.RawSHA256!=""||len(got.Assessment.Findings)!=0 {t.Fatalf("invalid native phase admitted: %+v %v",got,err)}
  })
 }
}
