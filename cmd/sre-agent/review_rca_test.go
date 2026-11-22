package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/rca"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

func writeReviewFixture(t *testing.T, dir string)(string,string,string,string) {
 t.Helper()
 now:=time.Date(2026,11,22,12,0,0,0,time.UTC)
 source:=func(value any)(string,string){
  b,err:=json.Marshal(value);if err!=nil{t.Fatal(err)}
  digest:=sha256.Sum256(b)
  return hex.EncodeToString(digest[:]),base64.StdEncoding.EncodeToString(b)
 }
 dep:=map[string]any{"metadata":map[string]any{"uid":"deployment-uid","name":"checkout-api","namespace":"golden-demo","resourceVersion":"71","generation":2},
  "status":map[string]any{"observedGeneration":2}}
 rs:=map[string]any{"metadata":map[string]any{"resourceVersion":"72"},"items":[]any{
  map[string]any{"metadata":map[string]any{"uid":"replica-set-uid","name":"checkout-api-new","namespace":"golden-demo","resourceVersion":"70","creationTimestamp":"2026-11-22T11:59:30Z","annotations":map[string]string{"deployment.kubernetes.io/revision":"2"},"ownerReferences":[]any{map[string]any{"kind":"Deployment","uid":"deployment-uid","controller":true}}},"spec":map[string]any{"replicas":2}},
 }}
 dh,db:=source(dep)
 rh,rb:=source(rs)
 changes:=change.Report{
  SchemaVersion:"sre.change-timeline/v1",Status:"OBSERVED",Relationship:"TIME_OVERLAP_ONLY",
  Namespace:"golden-demo",Deployment:"checkout-api",DeploymentUID:"deployment-uid",ResourceVersion:"71",Generation:2,
  CollectedAt:now,WindowStart:now.Add(-time.Minute),WindowEnd:now,
  Revisions:[]change.Revision{{UID:"replica-set-uid",Name:"checkout-api-new",Revision:"2",CreatedAt:now.Add(-30*time.Second),ResourceVersion:"70",Replicas:2}},
  Sources:[]change.Source{
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:dh,RawResponseBase64:db},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/replicasets",ResponseSHA256:rh,RawResponseBase64:rb},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:dh,RawResponseBase64:db},
  },
 }
 win:=now.Add(-20*time.Second)
 matrix:=func(values []string)(string,string) {
  points:=make([][]any,0,len(values))
  for i,v:=range values{points=append(points,[]any{win.Add(time.Duration(i)*5*time.Second).Unix(),v})}
  return source(map[string]any{"status":"success","data":map[string]any{"resultType":"matrix","result":[]any{map[string]any{"metric":map[string]string{"job":"checkout"},"values":points}}}})
 }
 lh,lb:=matrix([]string{"0.18","0.42","0.18","0.18","0.18"})
 th,tb:=matrix([]string{"2","2","2","2","2"})
 ah,ab:=matrix([]string{"1","1","1","1","1"})
 sli:=verifier.Assessment{Status:verifier.Unhealthy,Start:win,End:now,StepSeconds:5,
  MaxLatencySeconds:.35,MinTrafficPerSecond:.1,MaxSampleAgeSeconds:10,
  Evidence:[]verifier.SourceEvidence{
   {Query:"max(latency)",ResponseSHA256:lh,RawResponseBase64:lb,Series:1,Samples:5},
   {Query:"sum(rate(requests[20s]))",ResponseSHA256:th,RawResponseBase64:tb,Series:1,Samples:5},
   {Query:"max(time()-timestamp(latency))",ResponseSHA256:ah,RawResponseBase64:ab,Series:1,Samples:5},
  }}
 claims:=[]rca.Candidate{
  {ID:"h-deployment",Kind:rca.DeploymentCausal,Statement:"deployment caused p99 latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{"k8s:"+rh,"prom:"+lh}},
  {ID:"h-database",Kind:rca.OtherCausal,Statement:"database saturation caused latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{"prom:"+lh}},
 }
 save:=func(name string,v any)string{
  b,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
  path:=filepath.Join(dir,name)
  if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
  return path
 }
 return save("changes.json",changes),save("sli.json",sli),save("candidates.json",claims),rh
}
func writePinnedReviewPolicy(t *testing.T,dir,changesPath,sliPath string)(string,string){
 t.Helper()
 var c change.Report
 var s verifier.Assessment
 chRaw,err:=os.ReadFile(changesPath);if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(chRaw,&c);err!=nil{t.Fatal(err)}
 sliRaw,err:=os.ReadFile(sliPath);if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(sliRaw,&s);err!=nil{t.Fatal(err)}
 policy:=rca.SourcePolicy{
  SchemaVersion:"sre.rca-policy/v1",Namespace:c.Namespace,Deployment:c.Deployment,
  DeploymentUID:c.DeploymentUID,LatencyQuery:s.Evidence[0].Query,
  TrafficQuery:s.Evidence[1].Query,AgeQuery:s.Evidence[2].Query,
  MaxLatencySeconds:s.MaxLatencySeconds,MinTrafficPerSecond:s.MinTrafficPerSecond,
  MaxSampleAgeSeconds:s.MaxSampleAgeSeconds,
  WindowSeconds:int64(s.End.Sub(s.Start)/time.Second),StepSeconds:s.StepSeconds,
 }
 raw,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 pin:=sha256.Sum256(raw)
 path:=filepath.Join(dir,"operator-policy.json")
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 return path,hex.EncodeToString(pin[:])
}

func TestReviewRCACLIProducesHumanReviewOnly(t *testing.T){
 dir:=t.TempDir()
 changes,sli,candidates,_:=writeReviewFixture(t,dir)
 policy,pin:=writePinnedReviewPolicy(t,dir,changes,sli)
 out:filepath.Join(dir,"review.json")
 args:=[]string{"review-rca","--changes",changes,"--sli",sli,"--candidates",candidates,"--policy",policy,"--policy-sha256",pin,"--out",out}
 var stdout,stderr bytes.Buffer
 if code:=run(args,&stdout,&stderr);code!=0{t.Fatalf("review exit=%d stderr=%s",code,stderr.String())}
 b,err:=os.ReadFile(out);if err!=nil{t.Fatal(err)}
 var r rca.Report
 if err:=json.Unmarshal(b,&r);err!=nil{t.Fatal(err)}
 if r.Status!="HUMAN_REVIEW_REQUIRED"||len(r.Candidates)!=2||r.Candidates[0].Verdict!=rca.CorrelatedNotProven||r.Candidates[1].Verdict!=rca.Unverified {
  t.Fatalf("unsafe RCA report: %s",b)
 }
 if code:=run(args,&stdout,&stderr);code!=1{t.Fatal("overwrote existing review report")}
}
func TestReviewRCACLIRejectsTamperedSourceAndLeavesNoFile(t *testing.T){
 dir:=t.TempDir()
 changes,sli,candidates,_:=writeReviewFixture(t,dir)
 policy,pin:=writePinnedReviewPolicy(t,dir,changes,sli)
 var c change.Report
 raw,err:=os.ReadFile(changes);if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(raw,&c);err!=nil{t.Fatal(err)}
 c.Sources[1].RawResponseBase64=base64.StdEncoding.EncodeToString([]byte(`{"forged":true}`))
 b,err:=json.Marshal(c);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(changes,b,0600);err!=nil{t.Fatal(err)}
 out:=filepath.Join(dir,"forged-review.json")
 var stdout,stderr bytes.Buffer
 code:=run([]string{"review-rca","--changes",changes,"--sli",sli,"--candidates",candidates,"--policy",policy,"--policy-sha256",pin,"--out",out},&stdout,&stderr)
 if code!=3||!strings.Contains(stderr.String(),"UNKNOWN"){t.Fatalf("accepted tampered input: code=%d stderr=%s",code,stderr.String())}
 if _,err:=os.Stat(out);!os.IsNotExist(err){t.Fatal("wrote a report from tampered evidence")}
}
