package poddiagnosis

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestVerifyEventReportJSON(t *testing.T) {
 raw:=[]byte(eventsFixture)
 target:=eventTarget()
 report,err:=AssessEvents(target,raw)
 if err!=nil {t.Fatal(err)}
 claim,err:=json.Marshal(report)
 if err!=nil {t.Fatal(err)}
 if err:=VerifyEventReportJSON(target,raw,report.RawSHA256,claim);err!=nil {t.Fatal(err)}
 var pretty strings.Builder
 pretty.WriteString(" \n");pretty.Write(claim);pretty.WriteString("\n")
 if err:=VerifyEventReportJSON(target,raw,report.RawSHA256,[]byte(pretty.String()));err!=nil {t.Fatal(err)}
 for name,bad:=range map[string]string{
  "reason":strings.Replace(string(claim),"BackOff","Failed",1),
  "authority":strings.Replace(string(claim),`"source_authenticated":false`,`"source_authenticated":true`,1),
  "missing-authority":strings.Replace(string(claim),`,"source_authenticated":false`,"",1),
  "alias":strings.Replace(string(claim),`"events"`,`"Events"`,1),
  "duplicate":strings.Replace(string(claim),`"reason":"BackOff"`,`"reason":"BackOff","reason":"BackOff"`,1),
  "extra":strings.TrimSuffix(string(claim),"}")+`,"root_cause_verified":true}`,
  "drop-event":strings.Replace(string(claim),`[{"uid":"event-1","type":"Warning","reason":"BackOff"}]`,`[]`,1),
  "wrong-schema":strings.Replace(string(claim),"sre.pod-events/v1","sre.pod-diagnosis/v1",1),
  "trailing":string(claim)+"{}",
 } {t.Run(name,func(t *testing.T){if bad==string(claim){t.Fatal("mutation ineffective")};if VerifyEventReportJSON(target,raw,report.RawSHA256,[]byte(bad))==nil {t.Fatal("mutated report admitted")}})}
 if VerifyEventReportJSON(target,append(append([]byte(nil),raw...),' '),report.RawSHA256,claim)==nil {t.Fatal("changed source bytes admitted")}
 other:=target;other.UID="replacement"
 if VerifyEventReportJSON(other,raw,report.RawSHA256,claim)==nil {t.Fatal("cross-Pod replay admitted")}
 if VerifyEventReportJSON(target,raw,strings.Repeat("0",64),claim)==nil {t.Fatal("wrong independent pin admitted")}
}
