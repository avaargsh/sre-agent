package poddiagnosis

import (
 "crypto/sha256"
 "fmt"
 "strings"
 "testing"
)

const nativePod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app","image":"example/app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}}]}}`

func TestNativePodBindsBytesAndIdentity(t *testing.T) {
 target,_:=fixture()
 report,err:=AssessNative(target,[]byte(nativePod))
 if err!=nil {t.Fatal(err)}
 if report.RawSHA256!=fmt.Sprintf("%x",sha256.Sum256([]byte(nativePod))) || report.Target!=target || report.ResourceVersion!="42" || report.Assessment.Status!="SIGNALS_PRESENT" || len(report.Assessment.Findings)!=2 || report.SourceAuthenticated || report.Assessment.RootCauseVerified || report.Assessment.RecoveryVerified {t.Fatalf("wrong report: %+v",report)}
 if report.Assessment.Findings[0].TemporalScope!="current" || report.Assessment.Findings[1].TemporalScope!="historical" {t.Fatalf("wrong temporal scope: %+v",report)}
}

func TestNativePodRejectsAmbiguousIncompleteAndWrongScope(t *testing.T) {
 target,_:=fixture()
 cases:=map[string]string{
  "uid":strings.Replace(nativePod,"pod-uid-1","replaced",1),
  "kind":strings.Replace(nativePod,`"kind":"Pod"`,`"kind":"Service"`,1),
  "missing-ready":strings.Replace(nativePod,`"ready":false,`,"",1),
  "null-ready":strings.Replace(nativePod,`"ready":false`,`"ready":null`,1),
  "missing-restarts":strings.Replace(nativePod,`"restartCount":5,`,"",1),
  "null-restarts":strings.Replace(nativePod,`"restartCount":5`,`"restartCount":null`,1),
  "duplicate":strings.Replace(nativePod,`"ready":false`,`"ready":false,"ready":true`,1),
  "alias":strings.Replace(nativePod,`"ready":false`,`"Ready":false`,1),
  "alias-last-state":strings.Replace(nativePod,`"lastState"`,`"LastState"`,1),
  "alias-reason":strings.Replace(nativePod,`"reason":"CrashLoopBackOff"`,`"Reason":"CrashLoopBackOff"`,1),
  "ambiguous-union":strings.Replace(nativePod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"waiting":{"reason":"CrashLoopBackOff"},"running":{}`,1),
  "null-union":strings.Replace(nativePod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"waiting":null`,1),
  "unknown-union":strings.Replace(nativePod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"unexpected":{}`,1),
  "missing-status":strings.Replace(nativePod,`"containerStatuses"`,`"other"`,1),
  "trailing":nativePod+"{}",
  "oversize":strings.Repeat(" ",MaxNativePodBytes+1),
 }
 for name,raw:=range cases {t.Run(name,func(t *testing.T){report,err:=AssessNative(target,[]byte(raw));if err==nil || report.RawSHA256!="" || len(report.Assessment.Findings)!=0 {t.Fatalf("invalid source admitted: %+v %v",report,err)}})}
}

func TestNativePodNoFailureIsUnknown(t *testing.T) {
 target,_:=fixture()
 raw:=strings.Replace(nativePod,`"waiting":{"reason":"CrashLoopBackOff"}`,`"running":{"startedAt":"2026-11-24T00:00:00Z"}`,1)
 raw=strings.Replace(raw,`"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}`,`"lastState":{}`,1)
 report,err:=AssessNative(target,[]byte(raw))
 if err!=nil || report.Assessment.Status!="UNKNOWN" || report.RawSHA256=="" || report.Assessment.RecoveryVerified {t.Fatalf("unexpected report: %+v %v",report,err)}
}
