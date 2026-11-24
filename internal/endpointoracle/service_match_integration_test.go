package endpointoracle

import (
 "strings"
 "testing"
)

func TestEvaluateRequiresFullServiceSourceAgreement(t *testing.T) {
 t.Run("admin phases drift outside modeled fields",func(t *testing.T){
  e,p:=episode(t,false)
  raw,err:=checkedRaw(e.During.Service);if err!=nil{t.Fatal(err)}
  changed:=string(replaceJSONOnce(t,string(raw),`"resourceVersion":"19"`,`"resourceVersion":"19","annotations":{"audit":"changed"}`))
  if changed==string(raw){t.Fatal("fixture change not applied")}
  e.During.Service=snap([]byte(changed))
  if _,err:=Evaluate(e,p);err==nil{t.Fatal("accepted same-RV Service source drift")}
 })
 t.Run("observer differs from independent admin",func(t *testing.T){
  e,p:=episode(t,false)
  raw,err:=checkedRaw(e.During.Service);if err!=nil{t.Fatal(err)}
  changed:=string(replaceJSONOnce(t,string(raw),`"resourceVersion":"19"`,`"resourceVersion":"19","annotations":{"audit":"observer-only"}`))
  if changed==string(raw){t.Fatal("fixture change not applied")}
  list,err:=checkedRaw(e.During.EndpointSlices);if err!=nil{t.Fatal(err)}
  p,err=Diagnose([]byte(changed),list,e.ExpectedTargetPort,e.ExpectedSelector);if err!=nil{t.Fatal(err)}
  if _,err:=Evaluate(e,p);err==nil{t.Fatal("accepted observer/admin Service divergence")}
 })
 t.Run("formatting only",func(t *testing.T){
  e,p:=episode(t,false)
  raw,err:=checkedRaw(e.During.Service);if err!=nil{t.Fatal(err)}
  changed:=strings.ReplaceAll(string(raw),`,"spec"`,",\n \"spec\"")
  e.During.Service=snap([]byte(changed))
  if _,err:=Evaluate(e,p);err!=nil{t.Fatalf("formatting-only JSON rejected: %v",err)}
 })
}
