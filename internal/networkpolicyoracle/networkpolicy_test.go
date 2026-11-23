package networkpolicyoracle

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"
 "strings"
 "github.com/avaargsh/sre-agent/internal/dnsoracle"
 "github.com/avaargsh/sre-agent/internal/oracle"
)
func frozen(t *testing.T,v any)oracle.Snapshot{
 t.Helper()
 raw,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw)
 return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(sum[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)}
}
func setup(t *testing.T)(Episode,[3]dnsoracle.Observation){
 t.Helper()
 service:=map[string]any{"kind":"Service","metadata":map[string]any{"uid":"svc-1","namespace":"golden-demo","name":"checkout-api","resourceVersion":"100"},"spec":map[string]any{"clusterIP":"10.96.0.55","selector":map[string]string{"app":"checkout-api"},"ports":[]any{map[string]any{"port":8080,"targetPort":8080}}}}
 endpoint:=map[string]any{"kind":"EndpointSliceList","metadata":map[string]any{"resourceVersion":"101"},"items":[]any{map[string]any{
  "metadata":map[string]any{"uid":"slice-1","namespace":"golden-demo","name":"checkout-api-a","labels":map[string]string{"kubernetes.io/service-name":"checkout-api"}},
  "addressType":"IPv4","endpoints":[]any{map[string]any{"addresses":[]string{"10.244.0.2"},"conditions":map[string]bool{"ready":true}}},
 }}}
 policy:=map[string]any{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":map[string]any{"name":"sre-g2i-deny-http","namespace":"golden-demo","uid":"policy-1"},
  "spec":map[string]any{"podSelector":map[string]any{"matchLabels":map[string]string{"app":"sre-np-probe"}},"policyTypes":[]string{"Egress"},
   "egress":[]any{map[string]any{"ports":[]any{map[string]any{"protocol":"UDP","port":53},map[string]any{"protocol":"TCP","port":53}}}},
  }}
 policyList:=func(enabled bool)any{
  items:=[]any{}
  if enabled{items=append(items,policy)}
  return map[string]any{"kind":"NetworkPolicyList","metadata":map[string]any{"resourceVersion":"88"},"items":items}
 }
 obs:=[3]dnsoracle.Observation{}
 phase:=[3]Phase{}
 labels:=[]string{"before","during","after"}
 for i,label:=range labels{
  probe:=dnsoracle.Probe{SchemaVersion:"sre.dns-probe/v1",
   Host:"checkout-api.golden-demo.svc.cluster.local",ServiceIP:"10.96.0.55",
   Resolver:"nameserver 10.96.0.10\n",DNSOK:true,DNSAddresses:[]string{"10.96.0.55"},
   DNSError:"",NameHTTPStatus:200,DirectHTTPStatus:200,
   DirectHTTPAttempts:[]int{200,200,200},DirectHTTPErrors:[]string{"","",""}}
  if i==1{probe.NameHTTPStatus=0;probe.DirectHTTPStatus=0;probe.DirectHTTPAttempts=[]int{0,0,0};probe.DirectHTTPErrors=[]string{"timeout","timeout","timeout"}}
  payload,err:=json.Marshal(probe);if err!=nil{t.Fatal(err)}
  o,err:=dnsoracle.Diagnose(payload);if err!=nil{t.Fatal(err)}
  obs[i]=o
  pod:=map[string]any{"kind":"Pod",
   "metadata":map[string]any{"namespace":"golden-demo","name":"np-"+label,"uid":"pod-"+label,"labels":map[string]string{"app":"sre-np-probe"}},
   "status":map[string]any{"phase":"Succeeded"},
   "spec":map[string]any{"automountServiceAccountToken":false,"dnsPolicy":"ClusterFirst",
    "containers":[]any{map[string]any{"name":"probe","env":[]any{
     map[string]any{"name":"SERVICE_HOST","value":"checkout-api.golden-demo.svc.cluster.local"},
     map[string]any{"name":"SERVICE_IP","value":"10.96.0.55"},
     map[string]any{"name":"PROBE_PHASE","value":label}},
    }},
   }}
  phase[i]=Phase{Pod:frozen(t,pod),Probe:frozen(t,probe),Service:frozen(t,service),
   EndpointSlices:frozen(t,endpoint),PolicyList:frozen(t,policyList(i==1))}
 }
 return Episode{SchemaVersion:"sre.networkpolicy-oracle/v1",EpisodeID:"np-001",
  Before:phase[0],During:phase[1],After:phase[2]},obs
}
func TestLabNetworkPolicyDenialAndPositiveRecovery(t *testing.T){
 e,o:=setup(t)
 r,err:=Evaluate(e,o)
 if err!=nil{t.Fatal(err)}
 if r.Status!="MATCHED_LAB_NETWORK_POLICY_DENIAL"||r.ProductionCausalityVerified{
  t.Fatalf("wrong kind policy result: %+v",r)
 }
 if r.DuringDiagnostic!="UNKNOWN"{
  t.Fatalf("DNS-only diagnostic over-attributed a policy fault: %+v",r)
 }
}
func TestRejectForgedControlAndConfoundedEvidence(t *testing.T){
 for label,mutate:=range map[string]func(*Episode,*[3]dnsoracle.Observation){
  "before-not-connected":func(e *Episode,_ *[3]dnsoracle.Observation){e.Before.Probe=e.During.Probe},
  "after-not-recovered":func(e *Episode,_ *[3]dnsoracle.Observation){e.After.Probe=e.During.Probe},
  "no-policy":func(e *Episode,_ *[3]dnsoracle.Observation){e.During.PolicyList=e.Before.PolicyList},
  "policy-before":func(e *Episode,_ *[3]dnsoracle.Observation){e.Before.PolicyList=e.During.PolicyList},
  "policy-after":func(e *Episode,_ *[3]dnsoracle.Observation){e.After.PolicyList=e.During.PolicyList},
  "no-ready-endpoints":func(e *Episode,_ *[3]dnsoracle.Observation){e.During.EndpointSlices.ResponseSHA256="nohash"},
  "forged-admin-bytes":func(e *Episode,_ *[3]dnsoracle.Observation){e.During.Probe.ResponseSHA256="0"},
  "forged-observer":func(_ *Episode,o *[3]dnsoracle.Observation){o[1].Classification="NETWORK_POLICY_CONFIRMED"},
  "duplicate-pod-phase":func(e *Episode,_ *[3]dnsoracle.Observation){e.During.Pod=e.Before.Pod},
  "service-drift":func(e *Episode,_ *[3]dnsoracle.Observation){e.During.Service.ResponseSHA256="bad"},
 }{
  t.Run(label,func(t *testing.T){e,o:=setup(t);mutate(&e,&o);if _,err:=Evaluate(e,o);err==nil{t.Fatal("accepted tampered network policy evidence")}})
 }
}
func TestUncertainDualTransportFailureCannotClaimGeneralRootCause(t *testing.T){
 e,o:=setup(t)
 r,err:=Evaluate(e,o)
 if err!=nil{t.Fatal(err)}
 if r.Status=="PRODUCTION_ROOT_CAUSE_CONFIRMED"||r.ProductionCausalityVerified||r.DuringDiagnostic!="UNKNOWN"{
  t.Fatalf("must restrict interpretation to lab policy injection: %+v",r)
 }
}

func rehashRaw(t *testing.T,payload []byte)oracle.Snapshot{
 t.Helper()
 sum:=sha256.Sum256(payload)
 return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(sum[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(payload)}
}
func TestPolicySourceNestedDuplicateJSONKeysFailClosed(t *testing.T){
 e,o:=setup(t)
 wire,err:=base64.StdEncoding.DecodeString(e.During.PolicyList.RawResponseBase64)
 if err!=nil{t.Fatal(err)}
 // Same semantic value duplicated: ordinary Go JSON unmarshalling silently
 // accepts it, while different auditors/policy systems may reject it.
 modified:=strings.Replace(string(wire),`"resourceVersion":"88"`,`"resourceVersion":"88","resourceVersion":"88"`,1)
 if modified==string(wire){t.Fatal("test fixture source JSON changed")}
 e.During.PolicyList=rehashRaw(t,[]byte(modified))
 if _,err:=Evaluate(e,o);err==nil{t.Fatal("duplicate nested JSON keys accepted after digest recomputation")}
}
func TestPolicySourceRejectsExtraPermissiveRulesEvenWithRecomputedSHA(t *testing.T){
 e,o:=setup(t)
 wire,err:=base64.StdEncoding.DecodeString(e.During.PolicyList.RawResponseBase64)
 if err!=nil{t.Fatal(err)}
 var doc map[string]any
 if err:=json.Unmarshal(wire,&doc);err!=nil{t.Fatal(err)}
 items:=doc["items"].([]any)
 spec:=items[0].(map[string]any)["spec"].(map[string]any)
 spec["ingress"]=[]any{map[string]any{}}
 changed,err:=json.Marshal(doc);if err!=nil{t.Fatal(err)}
 e.During.PolicyList=rehashRaw(t,changed)
 if _,err:=Evaluate(e,o);err==nil{t.Fatal("permissive, unreviewed ingress block accepted after valid digest")}
}
