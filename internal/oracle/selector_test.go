package oracle

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"
)

func selectorRaw(t *testing.T,selector string)(Snapshot,[]byte){
 t.Helper()
 obj:=map[string]any{
  "metadata":map[string]any{"name":"checkout-api","namespace":"golden-demo","uid":"svc-uid","resourceVersion":"87"},
  "spec":map[string]any{"selector":map[string]string{"app":selector},"ports":[]any{map[string]any{"port":8080,"targetPort":8080}}},
 }
 b,err:=json.Marshal(obj);if err!=nil{t.Fatal(err)}
 h:=sha256.Sum256(b)
 return Snapshot{ResponseSHA256:hex.EncodeToString(h[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(b)},b
}
func TestSelectorFaultHasIndependentControlAndRecoveredEvidence(t *testing.T){
 e,_:=setup(t,"NO_FAULT")
 e.Scenario="SERVICE_SELECTOR_MISMATCH"
 e.Probes.During=[]int{0,0,0}
 bad,raw:=selectorRaw(t,"checkout-missing")
 e.During=bad
 pred,err:=DiagnoseWithSelector(raw,8080,map[string]string{"app":"checkout-api"})
 if err!=nil{t.Fatal(err)}
 if pred.Classification!="SERVICE_SELECTOR_MISMATCH"{t.Fatalf("missed selector mismatch: %+v",pred)}
 scored,err:=Evaluate(e,pred)
 if err!=nil{t.Fatal(err)}
 if scored.Verdict!="MATCHED_INJECTED_FAULT"||scored.ProductionCausalityVerified{
  t.Fatalf("incorrect selector fault evaluation: %+v",scored)
 }
}
func TestSelectorHealthyMustRemainUnknown(t *testing.T){
 e,_:=setup(t,"NO_FAULT")
 _,raw:=selectorRaw(t,"checkout-api")
 pred,err:=DiagnoseWithSelector(raw,8080,map[string]string{"app":"checkout-api"})
 if err!=nil{t.Fatal(err)}
 result,err:=Evaluate(e,pred)
 if err!=nil{t.Fatal(err)}
 if pred.Classification!="UNKNOWN"||result.Verdict!="CORRECT_REJECTION"{t.Fatalf("control falsely flagged: %+v %+v",pred,result)}
}
func TestSelectorFaultRejectsForgedBaselineOrPortDrift(t *testing.T){
 for name,change:=range map[string]func(*Episode,*Prediction){
  "wrong-baseline":func(_ *Episode,p *Prediction){p.ExpectedSelector=map[string]string{"app":"checkout-missing"}},
  "false-recovery":func(e *Episode,_ *Prediction){e.After=e.During},
  "healthy-probes-in-fault":func(e *Episode,_ *Prediction){e.Probes.During=[]int{200,200,200}},
  "port-and-selector-change":func(e *Episode,_ *Prediction){
    snap,_:=source(t,1)
    e.During=snap
  },
  "selector-only-not-port":func(e *Episode,p *Prediction){p.CurrentTargetPort=1},
 }{
  t.Run(name,func(t *testing.T){
   e,_:=setup(t,"NO_FAULT")
   e.Scenario="SERVICE_SELECTOR_MISMATCH"
   e.Probes.During=[]int{0,0,0}
   bad,raw:=selectorRaw(t,"checkout-missing")
   e.During=bad
   pred,err:=DiagnoseWithSelector(raw,8080,map[string]string{"app":"checkout-api"})
   if err!=nil{t.Fatal(err)}
   change(&e,&pred)
   if _,err:=Evaluate(e,pred);err==nil{t.Fatal("accepted forged selector oracle/prediction")}
  })
 }
}
func TestSelectorDiagnosisCannotUseUnpinnedOrAmbiguousExpectation(t *testing.T){
 _,raw:=selectorRaw(t,"checkout-missing")
 for _,selector:=range []map[string]string{
  nil,{},{"app":""},{"":"checkout-api"},{"app":"checkout-api","other":"unexpected"},
 }{
  if _,err:=DiagnoseWithSelector(raw,8080,selector);err==nil{
   // Extra nonempty selector can be valid but different from the source.
   if len(selector)==2{continue}
   t.Fatalf("accepted unbound expected selector: %+v",selector)
  }
 }
}
