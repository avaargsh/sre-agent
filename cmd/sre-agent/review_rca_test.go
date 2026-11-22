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
 digest:=func(raw string)(string,string) {
  hash:=sha256.Sum256([]byte(raw))
  return hex.EncodeToString(hash[:]),base64.StdEncoding.EncodeToString([]byte(raw))
 }
 depHash,depBytes:=digest(`{"metadata":{"uid":"deployment-uid"}}`)
 rsHash,rsBytes:=digest(`{"items":[{"metadata":{"uid":"replica-set-uid"}}]}`)
 metricHash,metricBytes:=digest(`{"status":"success","data":{"resultType":"matrix"}}`)
 changes:=change.Report{
  SchemaVersion:"sre.change-timeline/v1",Status:"OBSERVED",Relationship:"TIME_OVERLAP_ONLY",
  Namespace:"golden-demo",Deployment:"checkout-api",DeploymentUID:"deployment-uid",ResourceVersion:"71",Generation:2,
  WindowStart:now.Add(-time.Minute),WindowEnd:now,
  Sources:[]change.Source{
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:depHash,RawResponseBase64:depBytes},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/replicasets",ResponseSHA256:rsHash,RawResponseBase64:rsBytes},
   {Endpoint:"/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api",ResponseSHA256:depHash,RawResponseBase64:depBytes},
  },
 }
 sli:=verifier.Assessment{Status:verifier.Unhealthy,Start:now.Add(-30*time.Second),End:now,
  Evidence:[]verifier.SourceEvidence{{Query:"max(latency)",ResponseSHA256:metricHash,RawResponseBase64:metricBytes,Series:1,Samples:7}},
 }
 candidates:=[]rca.Candidate{
  {ID:"h-deployment",Kind:rca.DeploymentCausal,Statement:"deployment caused p99 latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{"k8s:"+rsHash,"prom:"+metricHash}},
  {ID:"h-database",Kind:rca.OtherCausal,Statement:"database saturation caused latency",ClaimedStatus:"SUPPORTED",SupportingRefs:[]string{"prom:"+metricHash}},
 }
 save:=func(name string,v any)string{
  b,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
  path:=filepath.Join(dir,name)
  if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
  return path
 }
 return save("changes.json",changes),save("sli.json",sli),save("candidates.json",candidates),rsHash
}
func TestReviewRCACLIProducesHumanReviewOnly(t *testing.T){
 dir:=t.TempDir()
 changes,sli,candidates,_:=writeReviewFixture(t,dir)
 out:=filepath.Join(dir,"review.json")
 args:=[]string{"review-rca","--changes",changes,"--sli",sli,"--candidates",candidates,"--out",out}
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
 var c change.Report
 raw,err:=os.ReadFile(changes);if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(raw,&c);err!=nil{t.Fatal(err)}
 c.Sources[1].RawResponseBase64=base64.StdEncoding.EncodeToString([]byte(`{"forged":true}`))
 b,err:=json.Marshal(c);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(changes,b,0600);err!=nil{t.Fatal(err)}
 out:=filepath.Join(dir,"forged-review.json")
 var stdout,stderr bytes.Buffer
 code:=run([]string{"review-rca","--changes",changes,"--sli",sli,"--candidates",candidates,"--out",out},&stdout,&stderr)
 if code!=3||!strings.Contains(stderr.String(),"UNKNOWN"){t.Fatalf("accepted tampered input: code=%d stderr=%s",code,stderr.String())}
 if _,err:=os.Stat(out);!os.IsNotExist(err){t.Fatal("wrote a report from tampered evidence")}
}
