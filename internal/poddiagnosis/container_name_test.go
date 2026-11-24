package poddiagnosis

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestContainerNameAdmission(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 for _,tc:=range []struct{name,value string;valid bool}{
  {"single-letter","a",true}, {"single-digit","0",true},
  {"hyphenated","checkout-api-2",true}, {"max-length",strings.Repeat("a",63),true},
  {"empty","",false}, {"whitespace"," ",false},
  {"uppercase","App",false}, {"leading-hyphen","-app",false},
  {"trailing-hyphen","app-",false}, {"dot","app.sidecar",false},
  {"underscore","app_sidecar",false}, {"path","app/sidecar",false},
  {"padded"," app ",false}, {"overlength",strings.Repeat("a",64),false},
  {"unicode","应用",false},
 } {
  t.Run(tc.name+"/normalized",func(t *testing.T){
   snapshot:=Snapshot{Target:target,ResourceVersion:"42",Phase:"Running",Containers:[]string{tc.value},Statuses:[]ContainerStatus{{Name:tc.value,State:"waiting",Reason:"CrashLoopBackOff",RestartCount:5}}}
   got:=Assess(target,snapshot)
   if tc.valid {
    if got.Status!="SIGNALS_PRESENT"||len(got.Findings)!=1||got.Findings[0].Container!=tc.value||got.RootCauseVerified||got.RecoveryVerified {t.Fatalf("valid container rejected: %+v",got)}
   } else if got.Status!="UNKNOWN"||got.Reason!=invalidSnapshotReason||len(got.Findings)!=0 {t.Fatalf("invalid container admitted: %+v",got)}
  })
  t.Run(tc.name+"/native",func(t *testing.T){
   name,err:=json.Marshal(tc.value);if err!=nil{t.Fatal(err)}
   raw:=[]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":`+string(name)+`}]},"status":{"phase":"Running","containerStatuses":[{"name":`+string(name)+`,"ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`)
   got,err:=AssessNative(target,raw)
   if tc.valid {
    if err!=nil||got.RawSHA256==""||len(got.Assessment.Findings)!=1||got.Assessment.Findings[0].Container!=tc.value||got.SourceAuthenticated||got.Assessment.RootCauseVerified||got.Assessment.RecoveryVerified {t.Fatalf("valid container rejected: %+v %v",got,err)}
   } else if err==nil||got.RawSHA256!=""||len(got.Assessment.Findings)!=0 {t.Fatalf("invalid container admitted: %+v %v",got,err)}
  })
 }
}
