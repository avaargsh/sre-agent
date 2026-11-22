package rca

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "fmt"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

func source(payload string) (string,string) {
 b:=[]byte(payload)
 hash:=sha256.Sum256(b)
 return hex.EncodeToString(hash[:]),base64.StdEncoding.EncodeToString(b)
}
func fixtures()(change.Report,verifier.Assessment,string,string,string){
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 depSHA,depRaw:=source(`{"kind":"Deployment","uid":"dep-1"}`)
 rsSHA,rsRaw:=source(`{"kind":"ReplicaSetList","items":[{"uid":"rs-2","revision":"2"}]}`)
 promSHA,promRaw:=source(`{"status":"success","data":{"resultType":"matrix"}}`)
 changes:=change.Report{
  SchemaVersion:"sre.change-timeline/v1",Status:"OBSERVED",Relationship:"TIME_OVERLAP_ONLY",
  Namespace:"golden-demo",Deployment:"checkout-api",DeploymentUID:"dep-1",Generation:2,ResourceVersion:"44",
  WindowStart:now.Add(-20*time.Minute),WindowEnd:now,
  Sources:[]change.Source{
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:depSHA,RawResponseBase64:depRaw},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/replicasets",ResponseSHA256:rsSHA,RawResponseBase64:rsRaw},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:depSHA,RawResponseBase64:depRaw},
  },
 }
 sli:=verifier.Assessment{
  Status:verifier.Unhealthy,Start:now.Add(-time.Minute),End:now,StepSeconds:5,
  Evidence:[]verifier.SourceEvidence{
   {Query:"max(latency_seconds)",ResponseSHA256:promSHA,RawResponseBase64:promRaw,Series:1,Samples:13},
  },
 }
 return changes,sli,"k8s:"+rsSHA,"prom:"+promSHA,"k8s:"+depSHA
}
func TestCompetingHypothesesNeverBecomeCausalProof(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 got,err:=Review(changes,sli,[]Candidate{
  {ID:"h-rollout",Kind:DeploymentCausal,Statement:"rollout caused latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{revision,metric}},
  {ID:"h-database",Kind:OtherCausal,Statement:"connection pool caused latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{metric}},
 })
 if err!=nil{t.Fatal(err)}
 if got.Status!="HUMAN_REVIEW_REQUIRED"||len(got.Candidates)!=2{t.Fatalf("invalid report: %+v",got)}
 if got.Candidates[0].Verdict!=CorrelatedNotProven{t.Fatalf("causal claim was promoted or lost: %+v",got.Candidates[0])}
 if got.Candidates[1].Verdict!=Unverified{t.Fatalf("missing independent evidence must be unverified: %+v",got.Candidates[1])}
 for _,v:=range got.Candidates {
  if v.Verdict=="SUPPORTED"||v.Verdict=="CONFIRMED"||v.Verdict=="RECOVERED"{t.Fatalf("untrusted status escaped: %+v",v)}
 }
}
func TestContradictingEvidencePreventsPromotion(t *testing.T){
 changes,sli,revision,metric,other:=fixtures()
 got,err:=Review(changes,sli,[]Candidate{{ID:"h-rollout",Kind:DeploymentCausal,Statement:"rollout caused latency",SupportingRefs:[]string{revision,metric},ContradictingRefs:[]string{other}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Contested{t.Fatalf("contradicting evidence ignored: %+v",got)}
}
func TestTamperedSourcePayloadOrDigestRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 claims:=[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"rollout cause",SupportingRefs:[]string{revision,metric}}}
 changes.Sources[1].RawResponseBase64=base64.StdEncoding.EncodeToString([]byte(`{"forged":true}`))
 if _,err:=Review(changes,sli,claims);err==nil{t.Fatal("accepted changed Kubernetes raw bytes")}
 changes,sli,revision,metric,_=fixtures()
 sli.Evidence[0].ResponseSHA256=fmt.Sprintf("%064x",0)
 claims[0].SupportingRefs=[]string{revision,metric}
 if _,err:=Review(changes,sli,claims);err==nil{t.Fatal("accepted changed Prometheus source hash")}
}
func TestUnknownDuplicateOrOverlappingCitationsRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 for name,candidate:=range map[string]Candidate{
  "unknown":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,"k8s:not-found"}},
  "repeated":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,revision}},
  "overlap":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric},ContradictingRefs:[]string{revision}},
 }{
  t.Run(name,func(t *testing.T){if _,err:=Review(changes,sli,[]Candidate{candidate});err==nil{t.Fatal("invalid references accepted")}})
 }
}
func TestClaimedSupportWithoutTwoSourceTypesIsUnverified(t *testing.T){
 changes,sli,revision,_,other:=fixtures()
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",ClaimedStatus:"CONFIRMED",SupportingRefs:[]string{revision,other}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("two Kubernetes reads treated as independent corroboration: %+v",got)}
}
func TestNoRevisionOverlapNeverClaimsNoCause(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 changes.Relationship="NO_REVISION_CREATED_IN_WINDOW"
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("absence of retained revision misread as causal refutation: %+v",got)}
}
func TestDisconnectedWindowsRemainUnverified(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 sli.Start=changes.WindowEnd.Add(time.Minute)
 sli.End=sli.Start.Add(time.Minute)
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("disjoint windows incorrectly correlated: %+v",got)}
}
func TestInvalidClaimsAndUnverifiedSourcesAreRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures()
 good:=Candidate{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}
 inputs:=[][]Candidate{
  {},{good,good},
  {{ID:"h",Kind:"model-admin",Statement:"cause",SupportingRefs:[]string{revision}}},
  {{ID:"h",Kind:DeploymentCausal,Statement:"",SupportingRefs:[]string{revision}}},
  {{ID:"h",Kind:DeploymentCausal,Statement:"cause"}},
 }
 for _,claims:=range inputs{if _,err:=Review(changes,sli,claims);err==nil{t.Fatalf("accepted invalid claims: %+v",claims)}}
 changes,sli,revision,metric,_=fixtures()
 changes.Status="UNKNOWN"
 if _,err:=Review(changes,sli,[]Candidate{good});err==nil{t.Fatal("UNKNOWN change report became proven")}
}
