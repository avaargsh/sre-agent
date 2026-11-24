package poddiagnosis

import (
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
)

func TestVerifyNativeReportJSONStrictWire(t *testing.T) {
 target:=Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 raw:=[]byte(replayPod)
 pin:=fmt.Sprintf("%x",sha256.Sum256(raw))
 report,err:=AssessNative(target,raw);if err!=nil{t.Fatal(err)}
 canonical,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 wire:=string(canonical)
 cases:=map[string]string{
  "duplicate authority":strings.Replace(wire,`"source_authenticated":false`,`"source_authenticated":true,"source_authenticated":false`,1),
  "missing authority":strings.Replace(wire,`,"source_authenticated":false`,"",1),
  "null authority":strings.Replace(wire,`"source_authenticated":false`,`"source_authenticated":null`,1),
  "authority alias":strings.Replace(wire,`"source_authenticated"`,`"SOURCE_AUTHENTICATED"`,1),
  "forged authority":strings.Replace(wire,`"source_authenticated":false`,`"source_authenticated":true`,1),
  "unknown root":strings.TrimSuffix(wire,"}")+`,"approved":true}`,
  "unknown nested":strings.Replace(wire,`"root_cause_verified":false`,`"root_cause_verified":false,"approved":true`,1),
  "missing recovery":strings.Replace(wire,`,"recovery_verified":false`,"",1),
  "target alias":strings.Replace(wire,`"UID"`,`"uid"`,1),
  "finding alias":strings.Replace(wire,`"temporal_scope"`,`"Temporal_Scope"`,1),
  "wrong scope":strings.Replace(wire,`"temporal_scope":"historical"`,`"temporal_scope":"current"`,1),
  "trailing document":wire+`{}`,
  "oversized":wire+strings.Repeat(" ",MaxNativeReportBytes),
  "null object":"null",
 }
 for name,claim:=range cases{t.Run(name,func(t *testing.T){
  if claim==wire{t.Fatal("mutation did not change receipt")}
  if err:=VerifyNativeReportJSON(target,raw,pin,[]byte(claim));err==nil{t.Fatal("invalid receipt admitted")}
 })}
 var reordered map[string]any
 if err:=json.Unmarshal(canonical,&reordered);err!=nil{t.Fatal(err)}
 pretty,err:=json.MarshalIndent(reordered,"","  ");if err!=nil{t.Fatal(err)}
 for _,claim:=range [][]byte{canonical,append(pretty,'\n')}{
  if err:=VerifyNativeReportJSON(target,raw,pin,claim);err!=nil{t.Fatalf("valid receipt rejected: %v",err)}
 }
 if err:=VerifyNativeReportJSON(target,raw,strings.Repeat("0",64),canonical);err==nil{t.Fatal("wrong pin admitted")}
}
