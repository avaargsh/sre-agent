package endpointoracle

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"

 "github.com/avaargsh/sre-agent/internal/oracle"
)
func fixture(t *testing.T, ready int)(oracle.Snapshot,oracle.Snapshot,[]byte,[]byte){
 t.Helper()
 service:=map[string]any{
  "metadata":map[string]any{"namespace":"golden-demo","name":"checkout-api","uid":"svc-1","resourceVersion":"19"},
  "spec":map[string]any{"selector":map[string]string{"app":"checkout-api"},"ports":[]any{map[string]any{"port":8080,"targetPort":8080}}},
 }
 list:=map[string]any{"kind":"EndpointSliceList","metadata":map[string]any{"resourceVersion":"25"},"items":[]any{}}
 if ready>0 {
  endpoints:=[]any{}
  for i:=0;i<ready;i++{endpoints=append(endpoints,map[string]any{"addresses":[]string{"10.0.0.1"},"conditions":map[string]any{"ready":true}})}
  list["items"]=[]any{map[string]any{
   "metadata":map[string]any{"uid":"eps-1","name":"checkout-slice","namespace":"golden-demo","labels":map[string]string{"kubernetes.io/service-name":"checkout-api"}},
   "addressType":"IPv4","endpoints":endpoints,
  }}
 }
 encode:=func(v any)(oracle.Snapshot,[]byte){
  raw,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
  digest:=sha256.Sum256(raw)
  return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(digest[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)},raw
 }
 ss,sraw:=encode(service)
 es,eraw:=encode(list)
 return ss,es,sraw,eraw
}
func episode(t *testing.T,fault bool)(Episode,Prediction){
 t.Helper()
 service,healthy,servRaw,rawHealthy:=fixture(t,2)
 _,empty,_,rawEmpty:=fixture(t,0)
 _=rawHealthy
 middle:=healthy
 duringRaw:=rawHealthy
 scenario:="NO_FAULT"
 probes:=[]int{200,200,200}
 if fault{middle=empty;duringRaw=rawEmpty;scenario="NO_READY_ENDPOINTS";probes=[]int{0,0,0}}
 e:=Episode{
  SchemaVersion:"sre.endpoint-oracle/v1",ID:"endpoint-001",Scenario:scenario,
  Namespace:"golden-demo",Service:"checkout-api",ServiceUID:"svc-1",ExpectedTargetPort:8080,
  ExpectedSelector:map[string]string{"app":"checkout-api"},
  Before:Phase{Service:service,EndpointSlices:healthy,Probes:[]int{200,200,200}},
  During:Phase{Service:service,EndpointSlices:middle,Probes:probes},
  After:Phase{Service:service,EndpointSlices:healthy,Probes:[]int{200,200,200}},
 }
 p,err:=Diagnose(servRaw,duringRaw,8080,map[string]string{"app":"checkout-api"})
 if err!=nil{t.Fatal(err)}
 return e,p
}
func TestNoReadyEndpointsAndHealthyControl(t *testing.T){
 cases:=[]struct{fault bool;wantClass,wantVerdict string}{
  {true,"NO_READY_ENDPOINTS_OBSERVED","MATCHED_INJECTED_OUTAGE"},
  {false,"READY_ENDPOINTS_OBSERVED","CORRECT_CONTROL"},
 }
 for _,tc:=range cases{
  e,p:=episode(t,tc.fault)
  got,err:=Evaluate(e,p)
  if err!=nil{t.Fatal(err)}
  if p.Classification!=tc.wantClass||got.Verdict!=tc.wantVerdict||got.ProductionCausalityVerified{
   t.Fatalf("incorrect endpoint Oracle: %+v %+v",p,got)
  }
 }
}
func TestEndpointOracleRejectsTamperedOrAmbiguousEvidence(t *testing.T){
 cases:=map[string]func(*Episode,*Prediction){
  "fake-during-probes":func(e *Episode,_ *Prediction){e.During.Probes=[]int{200,200,200}},
  "false-recovery":func(e *Episode,_ *Prediction){e.After=e.During},
  "change-service":func(e *Episode,_ *Prediction){e.During.Service.ResponseSHA256="nope"},
  "change-slice":func(e *Episode,_ *Prediction){e.During.EndpointSlices.ResponseSHA256="bad"},
  "forge-ready-count":func(_ *Episode,p *Prediction){p.ReadyEndpoints=2},
  "forge-prediction":func(_ *Episode,p *Prediction){p.Classification="BACKEND_CRASH_CONFIRMED"},
  "forge-expected-selector":func(_ *Episode,p *Prediction){p.ExpectedSelector=map[string]string{"app":"bad"}},
  "forge-source":func(_ *Episode,p *Prediction){p.EndpointSlices.RawResponseBase64=base64.StdEncoding.EncodeToString([]byte("{}"))},
  "fake-truth":func(e *Episode,_ *Prediction){e.Scenario="NO_FAULT"},
 }
 for name,mutate:=range cases{
  t.Run(name,func(t *testing.T){
   e,p:=episode(t,true);mutate(&e,&p)
   if _,err:=Evaluate(e,p);err==nil{t.Fatal("accepted forged endpoint Oracle")}
  })
 }
}
func TestRejectMalformedOrUnboundEndpointSliceLists(t *testing.T){
 _,_,service,_:=fixture(t,2)
 payloads:=[]string{
  `{"items":[],"metadata":{"resourceVersion":"","continue":""}}`,
  `{"items":[],"metadata":{"resourceVersion":"10","continue":"next"}}`,
  `{"items":[{"metadata":{"uid":"s1","namespace":"other","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[]}],"metadata":{"resourceVersion":"10"}}`,
  `{"items":[{"metadata":{"uid":"s1","namespace":"golden-demo","labels":{"kubernetes.io/service-name":"else"}},"addressType":"IPv4","endpoints":[]}],"metadata":{"resourceVersion":"10"}}`,
  `{"items":[{"metadata":{"uid":"s1","namespace":"golden-demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.1"],"conditions":{}}]}],"metadata":{"resourceVersion":"10"}}`,
 }
 for _,payload:=range payloads{
  if _,err:=Diagnose(service,[]byte(payload),8080,map[string]string{"app":"checkout-api"});err==nil{
   t.Fatalf("accepted malformed EndpointSlice: %s",payload)
  }
 }
}
func TestAmbiguousServiceConfigurationAbstainsWithoutCausalClaim(t *testing.T){
 _,_,_,raw:=fixture(t,0)
 svc:=map[string]any{
  "metadata":map[string]any{"namespace":"golden-demo","name":"checkout-api","uid":"svc-1","resourceVersion":"19"},
  "spec":map[string]any{"selector":map[string]string{"app":"wrong"},"ports":[]any{map[string]any{"port":8080,"targetPort":1}}},
 }
 service,_:=json.Marshal(svc)
 p,err:=Diagnose(service,raw,8080,map[string]string{"app":"checkout-api"})
 if err!=nil{t.Fatal(err)}
 if p.Classification!="UNKNOWN"{t.Fatalf("ambiguous multi-fault must abstain: %+v",p)}
}


func TestEndpointObservationRejectsDuplicateNestedReadinessKey(t *testing.T){
 _,_,service,endpoint:=fixture(t,2)
 broken:=string(replaceJSONOnce(t,string(endpoint),`"ready":true`,`"ready":false,"ready":true`))
 if broken==string(endpoint){t.Fatal("test setup failed")}
 if prediction,err:=Diagnose(service,[]byte(broken),8080,map[string]string{"app":"checkout-api"});err==nil{
  t.Fatalf("accepted EndpointSlice duplicate readiness field: %+v",prediction)
 }
}
