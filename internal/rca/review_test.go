package rca

import (
 "encoding/base64"
 "fmt"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

func fixtures(t *testing.T)(change.Report,verifier.Assessment,string,string,string){
 ch,sli,claims:=replayFixture(t)
 return ch,sli,claims[0].SupportingRefs[0],claims[0].SupportingRefs[1],"k8s:"+ch.Sources[0].ResponseSHA256
}
func TestCompetingHypothesesNeverBecomeCausalProof(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
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
 changes,sli,revision,metric,other:=fixtures(t)
 got,err:=Review(changes,sli,[]Candidate{{ID:"h-rollout",Kind:DeploymentCausal,Statement:"rollout caused latency",SupportingRefs:[]string{revision,metric},ContradictingRefs:[]string{other}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Contested{t.Fatalf("contradicting evidence ignored: %+v",got)}
}
func TestTamperedSourcePayloadOrDigestRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
 claims:=[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"rollout cause",SupportingRefs:[]string{revision,metric}}}
 changes.Sources[1].RawResponseBase64=base64.StdEncoding.EncodeToString([]byte(`{"forged":true}`))
 if _,err:=Review(changes,sli,claims);err==nil{t.Fatal("accepted changed Kubernetes raw bytes")}
 changes,sli,revision,metric,_=fixtures(t)
 sli.Evidence[0].ResponseSHA256=fmt.Sprintf("%064x",0)
 claims[0].SupportingRefs=[]string{revision,metric}
 if _,err:=Review(changes,sli,claims);err==nil{t.Fatal("accepted changed Prometheus source hash")}
}
func TestUnknownDuplicateOrOverlappingCitationsRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
 for name,candidate:=range map[string]Candidate{
  "unknown":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,"k8s:not-found"}},
  "repeated":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,revision}},
  "overlap":{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric},ContradictingRefs:[]string{revision}},
 }{
  t.Run(name,func(t *testing.T){if _,err:=Review(changes,sli,[]Candidate{candidate});err==nil{t.Fatal("invalid references accepted")}})
 }
}
func TestClaimedSupportWithoutTwoSourceTypesIsUnverified(t *testing.T){
 changes,sli,revision,_,other:=fixtures(t)
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",ClaimedStatus:"CONFIRMED",SupportingRefs:[]string{revision,other}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("two Kubernetes reads treated as independent corroboration: %+v",got)}
}
func TestNoRevisionOverlapNeverClaimsNoCause(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
 changes.WindowStart=changes.WindowEnd.Add(-4*time.Minute)
 changes.WindowEnd=changes.WindowStart.Add(2*time.Minute)
 changes.Relationship="NO_REVISION_CREATED_IN_WINDOW"
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("absence of retained revision misread as causal refutation: %+v",got)}
}
func TestDisconnectedWindowsRemainUnverified(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
 changes.WindowEnd=changes.WindowStart.Add(35*time.Second)
 got,err:=Review(changes,sli,[]Candidate{{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}})
 if err!=nil{t.Fatal(err)}
 if got.Candidates[0].Verdict!=Unverified{t.Fatalf("disjoint windows incorrectly correlated: %+v",got)}
}
func TestInvalidClaimsAndUnverifiedSourcesAreRejected(t *testing.T){
 changes,sli,revision,metric,_:=fixtures(t)
 good:=Candidate{ID:"h",Kind:DeploymentCausal,Statement:"cause",SupportingRefs:[]string{revision,metric}}
 inputs:=[][]Candidate{
  {},{good,good},
  {{ID:"h",Kind:"model-admin",Statement:"cause",SupportingRefs:[]string{revision}}},
  {{ID:"h",Kind:DeploymentCausal,Statement:"",SupportingRefs:[]string{revision}}},
  {{ID:"h",Kind:DeploymentCausal,Statement:"cause"}},
 }
 for _,claims:=range inputs{if _,err:=Review(changes,sli,claims);err==nil{t.Fatalf("accepted invalid claims: %+v",claims)}}
 changes,sli,revision,metric,_=fixtures(t)
 changes.Status="UNKNOWN"
 if _,err:=Review(changes,sli,[]Candidate{good});err==nil{t.Fatal("UNKNOWN change report became proven")}
}
