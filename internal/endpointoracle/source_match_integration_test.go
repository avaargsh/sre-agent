package endpointoracle

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

func TestEvaluateRequiresFullEndpointSourceAgreement(t *testing.T) {
 for _,tc:=range []struct{
  name string
  change func([]byte) []byte
  wantError bool
 }{
  {"different addresses",func(raw []byte)[]byte{return []byte(strings.ReplaceAll(string(raw),"10.0.0.1","10.0.0.2"))},true},
  {"different slice identity",func(raw []byte)[]byte{return []byte(strings.ReplaceAll(string(raw),"eps-1","eps-other"))},true},
  {"formatting only",func(raw []byte)[]byte{var b bytes.Buffer;if err:=json.Indent(&b,raw,"","  ");err!=nil{panic(err)};return b.Bytes()},false},
 }{
  t.Run(tc.name,func(t *testing.T){
   e,p:=episode(t,false)
   original,err:=checkedRaw(e.During.EndpointSlices);if err!=nil{t.Fatal(err)}
   changed:=tc.change(original)
   if bytes.Equal(original,changed){t.Fatal("test did not change source")}
   service,err:=checkedRaw(e.During.Service);if err!=nil{t.Fatal(err)}
   q,err:=Diagnose(service,changed,e.ExpectedTargetPort,e.ExpectedSelector);if err!=nil{t.Fatal(err)}
   if q.ReadyEndpoints!=p.ReadyEndpoints||q.ListResourceVersion!=p.ListResourceVersion{t.Fatal("test must preserve aggregate and version")}
   e.During.EndpointSlices=snap(changed)
   _,err=Evaluate(e,p)
   if (err!=nil)!=tc.wantError{t.Fatalf("source agreement admission mismatch: %v",err)}
  })
 }
}
