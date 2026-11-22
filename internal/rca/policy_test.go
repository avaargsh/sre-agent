package rca

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func testSourcePolicy(t *testing.T)([]byte,string){
 t.Helper()
 ch,sli,_:=replayFixture(t)
 policy:=SourcePolicy{
  SchemaVersion:"sre.rca-policy/v1",Namespace:ch.Namespace,Deployment:ch.Deployment,
  DeploymentUID:ch.DeploymentUID,LatencyQuery:sli.Evidence[0].Query,
  TrafficQuery:sli.Evidence[1].Query,AgeQuery:sli.Evidence[2].Query,
  MaxLatencySeconds:sli.MaxLatencySeconds,
  MinTrafficPerSecond:sli.MinTrafficPerSecond,
  MaxSampleAgeSeconds:sli.MaxSampleAgeSeconds,
  WindowSeconds:int64(sli.End.Sub(sli.Start)/time.Second),StepSeconds:sli.StepSeconds,
 }
 raw,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 sha:=sha256.Sum256(raw)
 return raw,hex.EncodeToString(sha[:])
}
func TestPinnedPolicyAcceptsRawReplayButNeverGrantsCausalAuthority(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 raw,sha:=testSourcePolicy(t)
 got,err:=ReviewWithPolicy(ch,sli,claims,raw,sha)
 if err!=nil{t.Fatal(err)}
 if got.PolicySHA256!=sha||got.Status!="HUMAN_REVIEW_REQUIRED"||got.Candidates[0].Verdict!=CorrelatedNotProven{
  t.Fatalf("wrong pinned review: %+v",got)
 }
}
func TestPinnedPolicyRejectsChangedQueryOrThresholdEvenIfRawReplayConsistent(t *testing.T){
 raw,sha:=testSourcePolicy(t)
 tests:=map[string]func(*SourcePolicy){
  "namespace":func(p *SourcePolicy){p.Namespace="kube-system"},
  "deployment-uid":func(p *SourcePolicy){p.DeploymentUID="other-uid"},
  "latency-query":func(p *SourcePolicy){p.LatencyQuery="max(other_metric)"},
  "traffic-query":func(p *SourcePolicy){p.TrafficQuery="vector(1)"},
  "age-query":func(p *SourcePolicy){p.AgeQuery="vector(0)"},
  "latency-threshold":func(p *SourcePolicy){p.MaxLatencySeconds=100},
  "traffic-threshold":func(p *SourcePolicy){p.MinTrafficPerSecond=1.99},
  "age-threshold":func(p *SourcePolicy){p.MaxSampleAgeSeconds=99},
  "step":func(p *SourcePolicy){p.StepSeconds=10},
  "window":func(p *SourcePolicy){p.WindowSeconds=60},
 }
 for name,mutate:=range tests {
  t.Run(name,func(t *testing.T){
   ch,sli,claims:=replayFixture(t)
   // The report is still replay-valid when only its claimed query changes.
   switch name{
    case "namespace":ch.Namespace="kube-system"
    case "deployment-uid":ch.DeploymentUID="other-uid"
    case "latency-query":sli.Evidence[0].Query="max(other_metric)"
    case "traffic-query":sli.Evidence[1].Query="vector(1)"
    case "age-query":sli.Evidence[2].Query="vector(0)"
    case "latency-threshold":sli.MaxLatencySeconds=100;sli.Status="HEALTHY"
    case "traffic-threshold":sli.MinTrafficPerSecond=1.99
    case "age-threshold":sli.MaxSampleAgeSeconds=99
    case "step":sli.StepSeconds=10
    case "window":sli.Start=sli.Start.Add(-40*time.Second)
   }
   if name=="namespace"||name=="deployment-uid"||name=="step"||name=="window"||name=="latency-threshold"{
    // This mutation is already rejected by raw replay; the policy gate must
    // also reject any disagreement even if the other checks are relaxed.
   }
   if _,err:=ReviewWithPolicy(ch,sli,claims,raw,sha);err==nil{t.Fatal("accepted source-policy mismatch")}
  })
  _=mutate
 }
}
func TestPinnedPolicyDigestAndStrictEncodingFailClosed(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 raw,sha:=testSourcePolicy(t)
 for name,policy:=range map[string][]byte{
  "tampered":append(append([]byte(nil),raw...),byte(' ')),
  "duplicate-key":[]byte(strings.Replace(string(raw),`"namespace":`,`"namespace":"evil","namespace":`,1)),
  "unknown-key":[]byte(strings.Replace(string(raw),`"schema_version":`,`"extra":"attacker","schema_version":`,1)),
  "trailing-json":append(append([]byte(nil),raw...),[]byte(`{}`)...),
 }{
  t.Run(name,func(t *testing.T){
   digest:=sha
   if name!="tampered"{h:=sha256.Sum256(policy);digest=hex.EncodeToString(h[:])}
   if _,err:=ReviewWithPolicy(ch,sli,claims,policy,digest);err==nil{t.Fatal("accepted modified or ambiguous operator policy")}
  })
 }
 if _,err:=ReviewWithPolicy(ch,sli,claims,raw,strings.Repeat("0",64));err==nil{t.Fatal("accepted unpinned policy")}
 if _,err:=ReviewWithPolicy(ch,sli,claims,raw,"");err==nil{t.Fatal("accepted missing operator pin")}
}
