package verifier

import (
 "context"
 "strings"
 "testing"
)

func TestSLIPrometheusCompletenessAdmission(t *testing.T) {
 for _,tc:=range []struct{name,fields string;valid bool}{
  {"absent","",true},
  {"explicit-complete",`"isPartial":false,"partialResponse":false,"warnings":[],`,true},
  {"extension",`"backend":"test",`,true},
  {"is-partial",`"isPartial":true,`,false},
  {"partial-response",`"partialResponse":true,`,false},
  {"mixed-flags",`"isPartial":false,"partialResponse":true,`,false},
  {"null-is-partial",`"isPartial":null,`,false},
  {"null-partial-response",`"partialResponse":null,`,false},
  {"string-flag",`"isPartial":"false",`,false},
  {"numeric-flag",`"partialResponse":0,`,false},
  {"alias-is-partial",`"IsPartial":false,`,false},
  {"alias-partial-response",`"PartialResponse":false,`,false},
  {"warnings",`"warnings":["private upstream warning"],`,false},
  {"null-warnings",`"warnings":null,`,false},
  {"alias-warnings",`"Warnings":[],`,false},
  {"duplicate-flag",`"isPartial":true,"isPartial":false,`,false},
  {"contradictory-alias",`"partialResponse":true,"PartialResponse":false,`,false},
 }{for index,stage:=range []string{"latency","traffic","age"}{t.Run(tc.name+"/"+stage,func(t *testing.T){
  good:=rangeResponse([]string{"0.1","0.1","0.1","0.1","0.1"},-1)
  traffic:=rangeResponse([]string{"2","2","2","2","2"},-1)
  age:=rangeResponse([]string{"2","2","2","2","2"},-1)
  responses:=[]string{good,traffic,age}
  responses[index]=strings.Replace(responses[index],`"status":"success"`,tc.fields+`"status":"success"`,1)
  srv,calls:=serveRange(t,responses[0],responses[1],responses[2])
  got:=Assess(context.Background(),policy(srv.URL))
  if tc.valid {
   if got.Status!=Healthy||len(got.Evidence)!=3||len(*calls)!=3{t.Fatalf("complete response rejected: status=%s evidence=%d reads=%d reason=%s",got.Status,len(got.Evidence),len(*calls),got.Reason)}
  } else if got.Status!=Unknown||len(got.Evidence)!=index||len(*calls)!=index+1||strings.Contains(got.Reason,"private upstream warning"){t.Fatalf("invalid response admitted or warning leaked: status=%s evidence=%d reads=%d reason=%s",got.Status,len(got.Evidence),len(*calls),got.Reason)}
 })}}
}
