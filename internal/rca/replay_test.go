package rca

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

func rawEvidence(t *testing.T, v any)(string,string){
 t.Helper()
 raw,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(raw)
 return hex.EncodeToString(sum[:]),base64.StdEncoding.EncodeToString(raw)
}
func replayFixture(t *testing.T)(change.Report,verifier.Assessment,[]Candidate){
 t.Helper()
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 dep:=map[string]any{"metadata":map[string]any{"uid":"dep-1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"44","generation":2},"status":map[string]any{"observedGeneration":2}}
 rs:=map[string]any{"metadata":map[string]any{"resourceVersion":"45"},"items":[]any{
  map[string]any{"metadata":map[string]any{"uid":"rs-1","name":"checkout-old","namespace":"golden-demo","resourceVersion":"40","creationTimestamp":"2026-11-22T11:50:00Z","annotations":map[string]string{"deployment.kubernetes.io/revision":"1"},"ownerReferences":[]any{map[string]any{"kind":"Deployment","uid":"dep-1","controller":true}}},"spec":map[string]any{"replicas":0}},
  map[string]any{"metadata":map[string]any{"uid":"rs-2","name":"checkout-new","namespace":"golden-demo","resourceVersion":"43","creationTimestamp":"2026-11-22T11:59:30Z","annotations":map[string]string{"deployment.kubernetes.io/revision":"2"},"ownerReferences":[]any{map[string]any{"kind":"Deployment","uid":"dep-1","controller":true}}},"spec":map[string]any{"replicas":2}},
 }}
 d,db:=rawEvidence(t,dep)
 r,rb:=rawEvidence(t,rs)
 ch:=change.Report{SchemaVersion:"sre.change-timeline/v1",Status:"OBSERVED",Relationship:"TIME_OVERLAP_ONLY",Namespace:"golden-demo",Deployment:"checkout-api",DeploymentUID:"dep-1",Generation:2,ResourceVersion:"44",
 WindowStart:now.Add(-time.Minute),WindowEnd:now,CollectedAt:now,
 Revisions:[]change.Revision{
  {UID:"rs-1",Name:"checkout-old",Revision:"1",CreatedAt:now.Add(-10*time.Minute),ResourceVersion:"40",Replicas:0},
  {UID:"rs-2",Name:"checkout-new",Revision:"2",CreatedAt:now.Add(-30*time.Second),ResourceVersion:"43",Replicas:2},
 },
 Sources:[]change.Source{
 {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:d,RawResponseBase64:db},
 {Endpoint:"/apis/apps/v1/namespaces/golden-demo/replicasets",ResponseSHA256:r,RawResponseBase64:rb},
 {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:d,RawResponseBase64:db},
 }}
 start:=now.Add(-20*time.Second)
 makeMatrix:=func(values []string)(string,string){
  points:=make([][]any,0,len(values))
  for i,v:=range values{points=append(points,[]any{start.Add(time.Duration(i)*5*time.Second).Unix(),v})}
  return rawEvidence(t,map[string]any{"status":"success","data":map[string]any{"resultType":"matrix","result":[]any{map[string]any{"metric":map[string]string{"job":"checkout"},"values":points}}}})
 }
 latency,lraw:=makeMatrix([]string{"0.20","0.20","0.42","0.18","0.20"})
 traffic,traw:=makeMatrix([]string{"2","2","2","2","2"})
 age,araw:=makeMatrix([]string{"2","2","2","2","2"})
 sli:=verifier.Assessment{
  Status:verifier.Unhealthy,Start:start,End:now,StepSeconds:5,
  MaxLatencySeconds:0.35,MinTrafficPerSecond:0.1,MaxSampleAgeSeconds:10,
  Evidence:[]verifier.SourceEvidence{
   {Query:"max(latency)",ResponseSHA256:latency,RawResponseBase64:lraw,Series:1,Samples:5},
   {Query:"sum(rate(requests[20s]))",ResponseSHA256:traffic,RawResponseBase64:traw,Series:1,Samples:5},
   {Query:"max(time()-timestamp(latency))",ResponseSHA256:age,RawResponseBase64:araw,Series:1,Samples:5},
  },
 }
 claims:=[]Candidate{{ID:"h-rollout",Kind:DeploymentCausal,Statement:"rollout caused latency",ClaimedStatus:"SUPPORTED",
 SupportingRefs:[]string{"k8s:"+r,"prom:"+latency}}}
 return ch,sli,claims
}
func TestReplayAcceptsRawAndStillRefusesCausalConfirmation(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 got,err:=Review(ch,sli,claims)
 if err!=nil{t.Fatal(err)}
 if got.Status!="HUMAN_REVIEW_REQUIRED"||got.Candidates[0].Verdict!=CorrelatedNotProven{t.Fatalf("invalid replay result %+v",got)}
}
func TestReplayRejectsForgedSummariesWithAuthenticRawBytes(t *testing.T){
 variants:=map[string]func(*change.Report,*verifier.Assessment){
  "fake-relationship":func(c *change.Report,_ *verifier.Assessment){c.Relationship="NO_REVISION_CREATED_IN_WINDOW"},
  "fake-deployment-uid":func(c *change.Report,_ *verifier.Assessment){c.DeploymentUID="forged-dep"},
  "fake-resource-version":func(c *change.Report,_ *verifier.Assessment){c.ResourceVersion="999"},
  "fake-revision":func(c *change.Report,_ *verifier.Assessment){c.Revisions[1].Revision="999"},
  "missing-revision":func(c *change.Report,_ *verifier.Assessment){c.Revisions=c.Revisions[:1]},
  "fake-sli-status":func(_ *change.Report,s *verifier.Assessment){s.Status=verifier.Healthy},
  "fake-latency-threshold":func(_ *change.Report,s *verifier.Assessment){s.MaxLatencySeconds=0.5},
  "fake-sample-count":func(_ *change.Report,s *verifier.Assessment){s.Evidence[0].Samples=9},
  "fake-sli-series":func(_ *change.Report,s *verifier.Assessment){s.Evidence[1].Series=9},
  "swap-metric-query":func(_ *change.Report,s *verifier.Assessment){s.Evidence[0].Query=s.Evidence[1].Query},
  "gap-window":func(_ *change.Report,s *verifier.Assessment){s.End=s.End.Add(5*time.Second)},
 }
 for name,mutate:=range variants{
  t.Run(name,func(t *testing.T){
   ch,sli,claims:=replayFixture(t);mutate(&ch,&sli)
   if result,err:=Review(ch,sli,claims);err==nil{t.Fatalf("accepted forged summary: %+v",result)}
  })
 }
}
func TestReplayRejectsRawTamperingEvenWithRecomputedDigest(t *testing.T){
 for name,mutate:=range map[string]func(*change.Report,*verifier.Assessment){
  "remove-controller":func(ch *change.Report,_ *verifier.Assessment){
   var root map[string]any
   b,_:=base64.StdEncoding.DecodeString(ch.Sources[1].RawResponseBase64)
   _=json.Unmarshal(b,&root)
   items:=root["items"].([]any)
   rs:=items[1].(map[string]any)
   owners:=rs["metadata"].(map[string]any)["ownerReferences"].([]any)
   owners[0].(map[string]any)["controller"]=false
   sum,raw:=rawEvidence(t,root)
   ch.Sources[1].ResponseSHA256=sum;ch.Sources[1].RawResponseBase64=raw
  },
  "misalign-prometheus-point":func(_ *change.Report,sli *verifier.Assessment){
   var root map[string]any
   b,_:=base64.StdEncoding.DecodeString(sli.Evidence[0].RawResponseBase64)
   _=json.Unmarshal(b,&root)
   series:=root["data"].(map[string]any)["result"].([]any)
   points:=series[0].(map[string]any)["values"].([]any)
   points[2].([]any)[0]=float64(1795350600)
   sum,raw:=rawEvidence(t,root)
   sli.Evidence[0].ResponseSHA256=sum;sli.Evidence[0].RawResponseBase64=raw
  },
  "non-finite-age":func(_ *change.Report,sli *verifier.Assessment){
   var root map[string]any
   b,_:=base64.StdEncoding.DecodeString(sli.Evidence[2].RawResponseBase64)
   _=json.Unmarshal(b,&root)
   series:=root["data"].(map[string]any)["result"].([]any)
   points:=series[0].(map[string]any)["values"].([]any)
   points[3].([]any)[1]="NaN"
   sum,raw:=rawEvidence(t,root)
   sli.Evidence[2].ResponseSHA256=sum;sli.Evidence[2].RawResponseBase64=raw
  },
 }{
  t.Run(name,func(t *testing.T){
   ch,sli,claims:=replayFixture(t);mutate(&ch,&sli)
   if got,err:=Review(ch,sli,claims);err==nil{t.Fatalf("accepted recomputed but inconsistent raw: %+v",got)}
  })
 }
}
func TestReplayUnknownIfUnderlyingScrapeStale(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 sli.Evidence[2].Samples=5
 var root map[string]any
 b,_:=base64.StdEncoding.DecodeString(sli.Evidence[2].RawResponseBase64)
 _=json.Unmarshal(b,&root)
 points:=root["data"].(map[string]any)["result"].([]any)[0].(map[string]any)["values"].([]any)
 for _,point:=range points{point.([]any)[1]="15"}
 sum,raw:=rawEvidence(t,root)
 sli.Evidence[2].ResponseSHA256=sum;sli.Evidence[2].RawResponseBase64=raw
 if got,err:=Review(ch,sli,claims);err==nil{t.Fatalf("accepted stale scrape with original SLI verdict: %+v",got)}
}
func TestReplayRejectsPartialMatricesAndDuplicateSeries(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 for _,kind:=range []string{"missing","duplicate"}{
  t.Run(kind,func(t *testing.T){
   broken:=sli
   broken.Evidence=append([]verifier.SourceEvidence(nil),sli.Evidence...)
   var root map[string]any
   b,_:=base64.StdEncoding.DecodeString(broken.Evidence[0].RawResponseBase64)
   _=json.Unmarshal(b,&root)
   rs:=root["data"].(map[string]any)["result"].([]any)
   if kind=="missing"{rs[0].(map[string]any)["values"]=rs[0].(map[string]any)["values"].([]any)[:4]}else{root["data"].(map[string]any)["result"]=append(rs,rs[0])}
   sum,raw:=rawEvidence(t,root)
   broken.Evidence[0].ResponseSHA256=sum;broken.Evidence[0].RawResponseBase64=raw
   if got,err:=Review(ch,broken,claims);err==nil{t.Fatalf("accepted %s matrix: %+v",kind,got)}
  })
 }
}
func TestReplayNoExternalCommandsOrAuthority(t *testing.T){
 ch,sli,claims:=replayFixture(t)
 claims[0].ClaimedStatus="RECOVERED"
 got,err:=Review(ch,sli,claims)
 if err!=nil{t.Fatal(err)}
 if got.Status!="HUMAN_REVIEW_REQUIRED"||strings.Contains(string(got.Candidates[0].Verdict),"RECOVERED"){t.Fatalf("model self-certification accepted: %+v",got)}
}
