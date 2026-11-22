package oracle

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"
)

func source(t *testing.T, targetPort int)(Snapshot,string){
 t.Helper()
 obj:=map[string]any{
  "metadata":map[string]any{"name":"checkout-api","namespace":"golden-demo","uid":"svc-uid","resourceVersion":"87"},
  "spec":map[string]any{"selector":map[string]string{"app":"checkout-api"},"ports":[]any{map[string]any{"port":8080,"targetPort":targetPort}}},
 }
 b,err:=json.Marshal(obj);if err!=nil{t.Fatal(err)}
 h:=sha256.Sum256(b)
 return Snapshot{ResponseSHA256:hex.EncodeToString(h[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(b)},string(b)
}
func setup(t *testing.T,scenario string)(Episode,Prediction){
 t.Helper()
 before,_:=source(t,8080)
 during,raw:=source(t,8080)
 expected:="NO_FAULT"
 codes:=[]int{200,200,200}
 if scenario=="SERVICE_TARGETPORT_MISROUTED"{
  during,raw=source(t,1)
  expected=scenario
  codes=[]int{0,0,0}
 }
 after,_:=source(t,8080)
 episode:=Episode{
  SchemaVersion:"sre.fault-oracle/v1",EpisodeID:"e-0001",
  Scenario:scenario,Namespace:"golden-demo",Service:"checkout-api",ServiceUID:"svc-uid",ExpectedTargetPort:8080,
  Before:before,During:during,After:after,
  Probes:ProbePhases{Before:[]int{200,200,200},During:codes,After:[]int{200,200,200}},
 }
 p,err:=Diagnose([]byte(raw),8080)
 if err!=nil{t.Fatal(err)}
 if p.Classification!=expected&&!(scenario=="NO_FAULT"&&p.Classification=="UNKNOWN"){
  t.Fatalf("diagnosis unexpectedly classified %+v",p)
 }
 return episode,p
}
func TestRealFaultOracleAndNoFaultControl(t *testing.T){
 for _,tc:=range []struct{scenario,verdict string}{
  {"SERVICE_TARGETPORT_MISROUTED","MATCHED_INJECTED_FAULT"},
  {"NO_FAULT","CORRECT_REJECTION"},
 }{
  t.Run(tc.scenario,func(t *testing.T){
   episode,p:=setup(t,tc.scenario)
   result,err:=Evaluate(episode,p)
   if err!=nil{t.Fatal(err)}
   if result.Verdict!=tc.verdict||result.ProductionCausalityVerified{
    t.Fatalf("incorrect oracle result: %+v",result)
   }
  })
 }
}
func TestOracleFailsClosedIfControlOrRecoveryIsMissing(t *testing.T){
 for label,change:=range map[string]func(*Episode){
  "baseline-failed":func(e *Episode){e.Probes.Before[0]=0},
  "recovery-failed":func(e *Episode){e.Probes.After[0]=0},
  "injection-did-not-break":func(e *Episode){e.Probes.During[1]=200},
  "wrong-oracle-class":func(e *Episode){e.Scenario="NO_FAULT"},
  "wrong-expected-target":func(e *Episode){e.ExpectedTargetPort=999},
  "broken-during-source":func(e *Episode){e.During.RawResponseBase64=base64.StdEncoding.EncodeToString([]byte("{}"))},
  "missing-observation":func(e *Episode){e.During.ResponseSHA256=""},
 }{
  t.Run(label,func(t *testing.T){
   e,p:=setup(t,"SERVICE_TARGETPORT_MISROUTED")
   change(&e)
   if _,err:=Evaluate(e,p);err==nil{t.Fatal("accepted invalid Oracle")}
  })
 }
}
func TestPredictionMustComeFromFrozenObservedBytes(t *testing.T){
 for _,alter:=range []func(*Prediction){
  func(p *Prediction){p.Classification="UNKNOWN"},
  func(p *Prediction){p.ServiceUID="an-invented-UID"},
  func(p *Prediction){p.CurrentTargetPort=8080},
  func(p *Prediction){p.ExpectedTargetPort=999},
  func(p *Prediction){p.Observed.ResponseSHA256="012345"},
 }{
  e,p:=setup(t,"SERVICE_TARGETPORT_MISROUTED")
  alter(&p)
  if _,err:=Evaluate(e,p);err==nil{t.Fatalf("accepted forged prediction %+v",p)}
 }
}
func TestDetectorDistinguishesCorrectPortAndMisroute(t *testing.T){
 for port,expected:=range map[int]string{8080:"UNKNOWN",1:"SERVICE_TARGETPORT_MISROUTED"}{
  _,raw:=source(t,port)
  p,err:=Diagnose([]byte(raw),8080)
  if err!=nil{t.Fatal(err)}
  if p.Classification!=expected{t.Fatalf("port %d: %+v",port,p)}
  if p.ServiceUID!="svc-uid"||p.CurrentTargetPort!=port{t.Fatal("missing observed identity")}
 }
}
func TestMissingAndAmbiguousServicePortMustNotBeDiagnosed(t *testing.T){
 for _,raw:=range []string{
  `{"metadata":{"uid":"svc-uid","name":"checkout-api","namespace":"golden-demo"},"spec":{"ports":[]}}`,
  `{"metadata":{"uid":"svc-uid","name":"checkout-api","namespace":"golden-demo"},"spec":{"ports":[{"port":8080,"targetPort":"web"}]}}`,
  `{"metadata":{"uid":"svc-uid","name":"checkout-api","namespace":"golden-demo"},"spec":{"ports":[{"port":8080,"targetPort":1},{"port":9090,"targetPort":9090}]}}`,
 }{
  if _,err:=Diagnose([]byte(raw),8080);err==nil{t.Fatalf("diagnosed ambiguous port: %s",raw)}
 }
}
