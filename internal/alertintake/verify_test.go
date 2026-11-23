package alertintake

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
 "testing"
)

func canonicalTestPlan(t *testing.T,raw []byte,target Target) ([]byte,Plan) {
 t.Helper()
 p,err:=Parse(raw,target)
 if err!=nil {t.Fatal(err)}
 b,err:=json.MarshalIndent(p,"","  ")
 if err!=nil {t.Fatal(err)}
 return append(b,'\n'),p
}

func TestVerifyPlanBindsExactRawAlertAndOperatorScope(t *testing.T){
 raw:=[]byte(firingFixture)
 frozen,expected:=canonicalTestPlan(t,raw,intended)
 got,err:=VerifyPlan(raw,frozen,intended)
 if err!=nil || got!=expected {t.Fatalf("valid exact alert plan rejected: got=%+v err=%v",got,err)}
 for name,tc:=range map[string]struct{raw,plan []byte;scope Target}{
  "updated-annotation-old-plan":{[]byte(strings.Replace(firingFixture,"checkout p99 latency high","different summary",1)),frozen,intended},
  "other-cluster":{raw,frozen,Target{Cluster:"lab-b",Namespace:intended.Namespace,Deployment:intended.Deployment}},
  "missing-canonical-newline":{raw,bytes.TrimSuffix(frozen,[]byte("\n")),intended},
  "trailing-object":{raw,append(bytes.Clone(frozen),[]byte("{}")...),intended},
  "duplicate-plan-field":{raw,[]byte(strings.Replace(string(frozen),`"status": "READ_ONLY_CANDIDATE"`,`"status": "READ_ONLY_CANDIDATE", "status": "READ_ONLY_CANDIDATE"`,1)),intended},
  "fabricated-authentication":{raw,[]byte(strings.Replace(string(frozen),`"source_authenticated": false`,`"source_authenticated": true`,1)),intended},
  "fabricated-execution":{raw,[]byte(strings.Replace(string(frozen),`"authorizes_execution": false`,`"authorizes_execution": true`,1)),intended},
  "oversized-plan":{raw,make([]byte,MaxPlanBytes+1),intended},
 }{
  t.Run(name,func(t *testing.T){
   if _,err:=VerifyPlan(tc.raw,tc.plan,tc.scope);!errors.Is(err,ErrUnknown){
    t.Fatalf("must reject unpinned, ambiguous or cross-target plan: %v",err)
   }
  })
 }
}
