package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/evidence"
)

func linkedAlertEvidenceFixture(t *testing.T) (string,string,string) {
 t.Helper()
 rawPath,planPath,out:=alertBridgeInputs(t)
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  switch r.URL.Path {
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":2,"observedGeneration":1}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
  case "/api/v1/query":
   _,_=fmt.Fprintf(w,`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d,"0.2"]}]}}`,time.Now().Unix())
  default:
   w.WriteHeader(http.StatusNotFound)
  }
 }))
 defer srv.Close()
 var stdout,stderr bytes.Buffer
 if code:=run(bridgeArgs(rawPath,planPath,out,srv.URL),&stdout,&stderr);code!=0 {
  t.Fatalf("cannot make true observed evidence bundle: status=%d err=%s",code,stderr.String())
 }
 return rawPath,planPath,out
}

func reviewArgs(rawPath,planPath,bundlePath string)[]string{
 return []string{"verify-alert-evidence","--alert-file",rawPath,"--plan",planPath,"--bundle",bundlePath,
  "--cluster","lab-a","--namespace","golden-demo","--deployment","checkout-api",
  "--expected-query","max(checkout_request_latency_seconds)"}
}

func TestOfflineAlertEvidenceReviewLinksExactSources(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 var stdout,stderr bytes.Buffer
 if code:=run(reviewArgs(rawPath,planPath,bundlePath),&stdout,&stderr);code!=0 {
  t.Fatalf("legitimate alert evidence rejected: exit=%d err=%s",code,stderr.String())
 }
 var receipt AlertEvidenceReview
 if err:=json.Unmarshal(stdout.Bytes(),&receipt);err!=nil{t.Fatal(err)}
 if receipt.SchemaVersion!="sre.alert-evidence-review/v1"||receipt.Status!="STRUCTURALLY_LINKED"||
  receipt.IncidentID==""||receipt.RawAlertSHA256==""||receipt.CanonicalBundleSHA256==""||
  receipt.SourceAuthenticated||receipt.AuthorizesExecution||receipt.RootCauseVerified||
  receipt.RecoveryVerified||receipt.EvidenceCount!=2{
  t.Fatalf("false authentication or incorrect offline linkage: %+v",receipt)
 }
 if !strings.HasPrefix(receipt.IncidentID,"alert-"){t.Fatalf("incident identity lost: %+v",receipt)}
}

func rehashStructurallyValidBundle(t *testing.T,bundlePath string,edit func(map[string]any))string{
 t.Helper()
 raw,err:=os.ReadFile(bundlePath)
 if err!=nil{t.Fatal(err)}
 var bundle map[string]any
 if err:=json.Unmarshal(raw,&bundle);err!=nil{t.Fatal(err)}
 edit(bundle)
 metadata:=bundle["metadata"].(map[string]any)
 delete(metadata,"bundle_sha256")
 interim,err:=json.Marshal(bundle)
 if err!=nil{t.Fatal(err)}
 result,err:=evidence.Verify(interim)
 if err!=nil{t.Fatalf("expected malicious control to remain structurally valid: %v",err)}
 metadata["bundle_sha256"]=result.BundleSHA256
 forged,err:=json.Marshal(bundle)
 if err!=nil{t.Fatal(err)}
 if _,err:=evidence.Verify(forged);err!=nil{t.Fatalf("invalid test attack fixture: %v",err)}
 path:=filepath.Join(t.TempDir(),"forged.json")
 if err:=os.WriteFile(path,forged,0600);err!=nil{t.Fatal(err)}
 return path
}

func TestOfflineReviewRejectsStructurallyValidButUnlinkedEvidence(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 cases:=map[string]func(map[string]any){
  "foreign-incident-id":func(b map[string]any){b["incident"].(map[string]any)["incident_id"]="alert-different"},
  "changed-summary":func(b map[string]any){b["incident"].(map[string]any)["summary"]="unrelated incident"},
  "wrong-kubernetes-target":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["attributes"].(map[string]any)["namespace"]="other"
  },
  "wrong-prometheus-query":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["promql"]="unapproved-query"
  },
  "changed-source-type":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["source"]="untrusted-collector"
  },
  "fake-recovery-claim":func(b map[string]any){
   b["metadata"].(map[string]any)["observation_status"]="recovered"
  },
 }
 for name,edit:=range cases{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,edit)
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:") {
    t.Fatalf("independent replay accepted source-mismatched self-hashed bundle: status=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}

func TestOfflineReviewRejectsChangedOriginalPlanOrUnapprovedQuery(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 cases:=map[string]func([]string)[]string{
  "wrong-target":func(args []string)[]string{
   for i:=range args {if args[i]=="--cluster"{args[i+1]="lab-b";break}}
   return args
  },
  "wrong-operator-query":func(args []string)[]string{
   for i:=range args {if args[i]=="--expected-query"{args[i+1]="different-query";break}}
   return args
  },
 }
 for name,change:=range cases{
  t.Run(name,func(t *testing.T){
   args:=change(reviewArgs(rawPath,planPath,bundlePath))
   var stdout,stderr bytes.Buffer
   if code:=run(args,&stdout,&stderr);code!=3||stdout.Len()!=0{
    t.Fatalf("replayed plan was accepted under wrong external scope: exit=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
 raw,err:=os.ReadFile(rawPath);if err!=nil{t.Fatal(err)}
 modified:=filepath.Join(t.TempDir(),"altered-alert.json")
 if err:=os.WriteFile(modified,bytes.Replace(raw,[]byte("checkout latency above SLO"),[]byte("changed alert summary"),1),0600);err!=nil{t.Fatal(err)}
 var stdout,stderr bytes.Buffer
 if code:=run(reviewArgs(modified,planPath,bundlePath),&stdout,&stderr);code!=3||stdout.Len()!=0 {
  t.Fatalf("stale alert source accepted: exit=%d stdout=%s",code,stdout.String())
 }
}


func TestOfflineReviewRejectsCaseAliasEvenWhenBundleDigestValid(t *testing.T){
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 // The structural verifier walks exact JSON keys and accepts the distinct
 // "source" / "Source" strings. An encoding/json struct decoder may silently
 // map both to the source field. Keep the last alias AFTER the canonical key.
 initial:=rehashStructurallyValidBundle(t,bundlePath,func(b map[string]any){
  e:=b["evidence"].([]any)[0].(map[string]any)
  e["source"]="forged-source"
  e["Source"]="kubernetes"
 })
 raw,err:=os.ReadFile(initial)
 if err!=nil{t.Fatal(err)}
 // Move the uppercase alias behind the original lower-case key in the wire,
 // without changing the canonical SHA256 (which is based on sorted map keys).
 first:=[]byte(`"Source":"kubernetes",`)
 last:=[]byte(`"source":"forged-source"`)
 if !bytes.Contains(raw,first)||!bytes.Contains(raw,last){t.Fatal("fixture source keys missing")}
 raw=bytes.Replace(raw,first,nil,1)
 raw=bytes.Replace(raw,last,[]byte(`"source":"forged-source","Source":"kubernetes"`),1)
 if _,err:=evidence.Verify(raw);err!=nil{
  t.Fatalf("must construct a structural SHA-valid alias attack: %v",err)
 }
 forged:=filepath.Join(t.TempDir(),"wire-alias.json")
 if err:=os.WriteFile(forged,raw,0600);err!=nil{t.Fatal(err)}
 var stdout,stderr bytes.Buffer
 if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
  stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
  t.Fatalf("accepted alias-overridden source with valid original digest: code=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
 }
}


func TestOfflineReviewRejectsValidCanonicalKeysWithAmbiguousAliases(t *testing.T) {
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 attacks:=map[string]func(map[string]any){
  "alias-evidence-source":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["Source"]="untrusted-collector"
  },
  "alias-incident-identity":func(b map[string]any){
   b["incident"].(map[string]any)["Incident_ID"]="another-incident"
  },
  "alias-prometheus-query":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["Promql"]="unapproved_query"
  },
  "alias-observation-status":func(b map[string]any){
   b["metadata"].(map[string]any)["Observation_Status"]="recovered"
  },
 }
 for name,change:=range attacks{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,change)
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("ambiguous exact/case-fold source fields passed structural review: exit=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}


func TestOfflineReviewRejectsRehashedAuthorityClaimsAndInconsistentObservationClock(t *testing.T) {
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 attacks:=map[string]func(map[string]any){
  "metadata-fabricated-source-auth":func(b map[string]any){
   b["metadata"].(map[string]any)["source_authenticated"]=true
  },
  "metadata-fabricated-execution-permit":func(b map[string]any){
   b["metadata"].(map[string]any)["authorizes_execution"]=true
  },
  "metadata-fabricated-rca":func(b map[string]any){
   b["metadata"].(map[string]any)["root_cause_verified"]=true
  },
  "metadata-fabricated-recovery":func(b map[string]any){
   b["metadata"].(map[string]any)["recovery_verified"]=true
  },
  "metadata-fabricated-approval":func(b map[string]any){
   b["metadata"].(map[string]any)["release_status"]="APPROVED"
  },
  "incident-fabricated-permit":func(b map[string]any){
   b["incident"].(map[string]any)["authorizes_execution"]=true
  },
  "stale-global-observation-clock":func(b map[string]any){
   b["metadata"].(map[string]any)["observed_at"]="2001-01-01T00:00:00Z"
  },
  "different-evidence-timestamp":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["timestamp"]="2001-01-01T00:00:00Z"
  },
  "different-source-attribute-timestamp":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["observed_at"]="2001-01-01T00:00:00Z"
  },
 }
 for name,change:=range attacks{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,change)
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("accepted SHA-valid authority claim or inconsistent observation clock: exit=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}


func TestOfflineReviewRejectsRehashedContradictorySourceContents(t *testing.T) {
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 changeSamples:=func(b map[string]any,edit func([]any)) {
  attrs:=b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)
  var samples []any
  if err:=json.Unmarshal([]byte(attrs["samples_json"].(string)),&samples);err!=nil{t.Fatal(err)}
  edit(samples)
  updated,err:=json.Marshal(samples)
  if err!=nil{t.Fatal(err)}
  attrs["samples_json"]=string(updated)
 }
 attacks:=map[string]func(map[string]any){
  "prom-sample-json-invalid":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["samples_json"]="not JSON"
  },
  "prom-series-count-contradicts-samples":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["series_count"]="99"
  },
  "prom-sample-nonfinite":func(b map[string]any){
   changeSamples(b,func(s []any){s[0].(map[string]any)["value"]="NaN"})
  },
  "prom-sample-too-old":func(b map[string]any){
   changeSamples(b,func(s []any){s[0].(map[string]any)["timestamp"]=float64(1)})
  },
  "prom-sample-future":func(b map[string]any){
   changeSamples(b,func(s []any){s[0].(map[string]any)["timestamp"]=float64(time.Now().Add(time.Hour).Unix())})
  },
  "prom-zero-max-age":func(b map[string]any){
   b["evidence"].([]any)[1].(map[string]any)["attributes"].(map[string]any)["max_age_seconds"]="0"
  },
  "kubernetes-pods-not-array":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["attributes"].(map[string]any)["pods_json"]="{}"
  },
  "kubernetes-pod-missing-uid":func(b map[string]any){
   b["evidence"].([]any)[0].(map[string]any)["attributes"].(map[string]any)["pods_json"]=`[{"name":"one","phase":"Running"}]`
  },
 }
 for name,change:=range attacks{
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,change)
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("accepted self-hashed contradictory source contents: exit=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}


func TestOfflineReviewRejectsImpossibleEmbeddedPodSnapshots(t *testing.T) {
 rawPath,planPath,bundlePath:=linkedAlertEvidenceFixture(t)
 attacks:=map[string]string{
  "duplicate-pod-name":`[{"uid":"pod-1","name":"checkout-api-1","phase":"Running"},{"uid":"pod-2","name":"checkout-api-1","phase":"Pending"}]`,
  "unknown-pod-phase":`[{"uid":"pod-1","name":"checkout-api-1","phase":"Rebooting"}]`,
 }
 for name,podsJSON:=range attacks {
  t.Run(name,func(t *testing.T){
   forged:=rehashStructurallyValidBundle(t,bundlePath,func(b map[string]any){
    attrs:=b["evidence"].([]any)[0].(map[string]any)["attributes"].(map[string]any)
    attrs["pods_json"]=podsJSON
   })
   var stdout,stderr bytes.Buffer
   if code:=run(reviewArgs(rawPath,planPath,forged),&stdout,&stderr);code!=3||
    stdout.Len()!=0||!strings.Contains(stderr.String(),"UNKNOWN:"){
    t.Fatalf("accepted impossible Kubernetes pod snapshot: exit=%d stdout=%s stderr=%s",code,stdout.String(),stderr.String())
   }
  })
 }
}
