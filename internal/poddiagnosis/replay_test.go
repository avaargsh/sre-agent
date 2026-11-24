package poddiagnosis

import (
 "crypto/sha256"
 "fmt"
 "strings"
 "testing"
)

const replayPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}}]}}`

func TestVerifyNativeReportRejectsTampering(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 raw:=[]byte(replayPod)
 pin:=fmt.Sprintf("%x",sha256.Sum256(raw))
 for name,mutate:=range map[string]func(*Target,*[]byte,*string,*NativeReport){
  "wrong expected UID":func(t *Target,_ *[]byte,_ *string,_ *NativeReport){t.UID="replacement"},
  "missing pin":func(_ *Target,_ *[]byte,p *string,_ *NativeReport){*p=""},
  "uppercase pin":func(_ *Target,_ *[]byte,p *string,_ *NativeReport){*p=strings.ToUpper(*p)},
  "same meaning different bytes":func(_ *Target,b *[]byte,_ *string,_ *NativeReport){*b=append(*b,'\n')},
  "rehashed replacement":func(t *Target,b *[]byte,_ *string,r *NativeReport){*b=[]byte(strings.Replace(string(*b),`"resourceVersion":"42"`,`"resourceVersion":"43"`,1));*r,_=AssessNative(*t,*b)},
  "wrong report target":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Target.UID="replacement"},
  "wrong resource version":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.ResourceVersion="43"},
  "wrong schema":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.SchemaVersion="sre.pod-diagnosis/v2"},
  "wrong report digest":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.RawSHA256=strings.Repeat("0",64)},
  "forged source authentication":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.SourceAuthenticated=true},
  "forged RCA":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.RootCauseVerified=true},
  "forged recovery":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.RecoveryVerified=true},
  "forged status":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.Status="VERIFIED"},
  "forged reason":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.Reason="verified"},
  "omitted signal":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.Findings=r.Assessment.Findings[:1]},
  "historical signal promoted":func(_ *Target,_ *[]byte,_ *string,r *NativeReport){r.Assessment.Findings[1].TemporalScope="current"},
 } {t.Run(name,func(t *testing.T){
  expected,body,digest:=target,[]byte(replayPod),pin
  report,err:=AssessNative(expected,body);if err!=nil{t.Fatal(err)}
  mutate(&expected,&body,&digest,&report)
  if err:=VerifyNativeReport(expected,body,digest,report);err==nil{t.Fatal("tampered replay admitted")}
 })}
}

func TestVerifyNativeReportAcceptsExactSignalsAndUnknown(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 healthy:=strings.Replace(replayPod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"running":{}`,1)
 healthy=strings.Replace(healthy,`"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}`,`"lastState":{}`,1)
 for _,body:=range []string{replayPod,healthy}{
  raw:=[]byte(body);pin:=fmt.Sprintf("%x",sha256.Sum256(raw))
  report,err:=AssessNative(target,raw);if err!=nil{t.Fatal(err)}
  if err:=VerifyNativeReport(target,raw,pin,report);err!=nil{t.Fatal(err)}
  if report.SourceAuthenticated||report.Assessment.RootCauseVerified||report.Assessment.RecoveryVerified{t.Fatal("replay promoted authority")}
  if body==healthy&&report.Assessment.Status!="UNKNOWN"{t.Fatal("no-signal report promoted")}
 }
}
