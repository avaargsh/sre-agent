package poddiagnosis

import (
 "strings"
 "testing"
)

const boundsPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}}]}}`

func TestNativePodRejectsInvalidTerminationAndRestartFields(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 cases:=map[string]string{
  "missing historical exit code":strings.Replace(boundsPod,`,"exitCode":137`,"",1),
  "null exit code":strings.Replace(boundsPod,`"exitCode":137`,`"exitCode":null`,1),
  "fractional exit code":strings.Replace(boundsPod,`"exitCode":137`,`"exitCode":137.0`,1),
  "out of range exit code":strings.Replace(boundsPod,`"exitCode":137`,`"exitCode":2147483648`,1),
  "aliased exit code":strings.Replace(boundsPod,`"exitCode":137`,`"ExitCode":137`,1),
  "missing current exit code":strings.Replace(boundsPod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"terminated":{"reason":"OOMKilled"}`,1),
  "out of range restart count":strings.Replace(boundsPod,`"restartCount":5`,`"restartCount":2147483648`,1),
 }
 for name,raw:=range cases {t.Run(name,func(t *testing.T){report,err:=AssessNative(target,[]byte(raw));if err==nil||report.RawSHA256!=""||len(report.Assessment.Findings)!=0 {t.Fatalf("invalid source admitted: %+v %v",report,err)}})}
}

func TestNativePodValidTerminationAndMaxRestartCount(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 raw:=strings.Replace(boundsPod,`"restartCount":5`,`"restartCount":2147483647`,1)
 raw=strings.Replace(raw,`"waiting":{"reason":"CrashLoopBackOff"}`,`"terminated":{"reason":"OOMKilled","exitCode":137}`,1)
 report,err:=AssessNative(target,[]byte(raw))
 if err!=nil||len(report.Assessment.Findings)!=2||report.Assessment.Findings[0].TemporalScope!="current"||report.Assessment.Findings[1].TemporalScope!="historical"||report.SourceAuthenticated||report.Assessment.RootCauseVerified||report.Assessment.RecoveryVerified {t.Fatalf("wrong receipt: %+v %v",report,err)}
}
