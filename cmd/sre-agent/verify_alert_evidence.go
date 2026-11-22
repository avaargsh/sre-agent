package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "strings"
 "unicode/utf8"

 "github.com/avaargsh/sre-agent/internal/alertintake"
 "github.com/avaargsh/sre-agent/internal/evidence"
)

// AlertEvidenceReview proves only structural linkage among three untrusted
// local files. It is NOT an authenticated attestation, incident RCA verdict,
// permit, approval, recovery outcome, or authorization to run a tool.
type AlertEvidenceReview struct {
 SchemaVersion string `json:"schema_version"`
 Status string `json:"status"`
 IncidentID string `json:"incident_id"`
 RawAlertSHA256 string `json:"raw_alert_sha256"`
 CanonicalBundleSHA256 string `json:"canonical_bundle_sha256"`
 PlanFileSHA256 string `json:"plan_file_sha256"`
 EvidenceCount int `json:"evidence_count"`
 SourceAuthenticated bool `json:"source_authenticated"`
 AuthorizesExecution bool `json:"authorizes_execution"`
 RootCauseVerified bool `json:"root_cause_verified"`
 RecoveryVerified bool `json:"recovery_verified"`
}

func alertEvidenceUnknown(stderr io.Writer,reason string)int{
 fmt.Fprintln(stderr,"UNKNOWN:",reason)
 return 3
}
func sha256hex(raw []byte)string{
 digest:=sha256.Sum256(raw)
 return hex.EncodeToString(digest[:])
}

// reviewLinkedEvidence verifies a sealed-v1 plan against the original raw
// alert and expected independently supplied operator scope, then independently
// verifies the Evidence Bundle's canonical hash and cross-field linkage.
// A malicious producer can replace all three self-hashed files: no source
// authentication or signed external trust anchor is implied.
func reviewLinkedEvidence(rawAlert,frozenPlan,bundle []byte,target alertintake.Target,expectedQuery string)(AlertEvidenceReview,error){
 plan,err:=alertintake.VerifyPlan(rawAlert,frozenPlan,target)
 if err!=nil{return AlertEvidenceReview{},err}
 if len(bundle)==0||len(bundle)>evidence.MaxBundleBytes||!utf8.Valid(bundle){
  return AlertEvidenceReview{},fmt.Errorf("invalid or oversized evidence bytes")
 }
 checked,err:=evidence.Verify(bundle)
 if err!=nil{return AlertEvidenceReview{},err}
 if checked.EvidenceCount!=2||checked.SupportedHypotheses!=0 {
  return AlertEvidenceReview{},fmt.Errorf("not an unpromoted two-source read-only observation")
 }
 var doc struct{
  Incident struct{
   ID string `json:"incident_id"`
   Summary string `json:"summary"`
   Severity string `json:"severity"`
   Scope string `json:"scope"`
  } `json:"incident"`
  Evidence []struct{
   Source string `json:"source"`
   Attributes map[string]string `json:"attributes"`
  } `json:"evidence"`
  Hypotheses []json.RawMessage `json:"hypotheses"`
  Entities []json.RawMessage `json:"entities"`
  Edges []json.RawMessage `json:"edges"`
  Changes []json.RawMessage `json:"changes"`
  Metadata struct{
   SchemaVersion string `json:"schema_version"`
   ObservationStatus string `json:"observation_status"`
   ToolCount int `json:"tool_count"`
   EvidenceCount int `json:"evidence_count"`
  } `json:"metadata"`
 }
 if err:=json.Unmarshal(bundle,&doc);err!=nil {
  return AlertEvidenceReview{},fmt.Errorf("unparseable observation bundle: %w",err)
 }
 expectedScope:="namespace="+target.Namespace+",deployment="+target.Deployment
 if doc.Incident.ID!=plan.IncidentID||doc.Incident.Summary!=plan.Summary||
   doc.Incident.Severity!=plan.Severity||doc.Incident.Scope!=expectedScope {
  return AlertEvidenceReview{},fmt.Errorf("bundle incident identity or operator scope differs from reviewed plan")
 }
 if doc.Metadata.SchemaVersion!="aiops.evidence/v1"||
   doc.Metadata.ObservationStatus!="complete"||
   doc.Metadata.ToolCount!=2||doc.Metadata.EvidenceCount!=2||
   len(doc.Evidence)!=2||len(doc.Hypotheses)!=0||len(doc.Entities)!=0||
   len(doc.Edges)!=0||len(doc.Changes)!=0 {
  return AlertEvidenceReview{},fmt.Errorf("bundle does not match the v1 read-only observation contract")
 }
 sources:=map[string]bool{}
 for _,item:=range doc.Evidence{
  if sources[item.Source]{return AlertEvidenceReview{},fmt.Errorf("duplicate observation source")}
  sources[item.Source]=true
  switch item.Source{
  case "kubernetes":
   if item.Attributes["namespace"]!=target.Namespace||
     item.Attributes["deployment"]!=target.Deployment ||
     item.Attributes["uid"]==""||
     item.Attributes["resource_version"]=="" {
    return AlertEvidenceReview{},fmt.Errorf("Kubernetes observation target mismatch")
   }
  case "prometheus":
   if expectedQuery==""||len(expectedQuery)>512||
     item.Attributes["promql"]!=expectedQuery||
     item.Attributes["result_type"]!="vector" {
    return AlertEvidenceReview{},fmt.Errorf("unapproved Prometheus observation query")
   }
  default:
   return AlertEvidenceReview{},fmt.Errorf("unknown observation source")
  }
 }
 if !sources["kubernetes"]||!sources["prometheus"]{
  return AlertEvidenceReview{},fmt.Errorf("missing required independent source types")
 }
 return AlertEvidenceReview{
  SchemaVersion:"sre.alert-evidence-review/v1",Status:"STRUCTURALLY_LINKED",
  IncidentID:plan.IncidentID,RawAlertSHA256:plan.RawSHA256,
  CanonicalBundleSHA256:checked.BundleSHA256,PlanFileSHA256:sha256hex(frozenPlan),
  EvidenceCount:checked.EvidenceCount,
  SourceAuthenticated:false,AuthorizesExecution:false,
  RootCauseVerified:false,RecoveryVerified:false,
 },nil
}

// verifyAlertEvidence requires all three original files. It intentionally has
// no HTTP client, write output path, model call or execution/approval API.
func verifyAlertEvidence(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("verify-alert-evidence",flag.ContinueOnError)
 flags.SetOutput(stderr)
 alertPath:=flags.String("alert-file","","original Alertmanager JSON")
 planPath:=flags.String("plan","","exact canonical read-only plan")
 bundlePath:=flags.String("bundle","","original Evidence Bundle v1")
 cluster:=flags.String("cluster","","operator-owned cluster identity")
 namespace:=flags.String("namespace","","operator-owned namespace")
 deployment:=flags.String("deployment","","operator-owned deployment")
 query:=flags.String("expected-query","","operator-approved PromQL used in observation")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0||*alertPath==""||*alertPath=="-"||
  *planPath==""||*planPath=="-"||*bundlePath==""||*bundlePath=="-"||
  *cluster==""||*namespace==""||*deployment==""||
  *query==""||strings.TrimSpace(*query)==""||len(*query)>512 {
  fmt.Fprintln(stderr,"usage: sre-agent verify-alert-evidence --alert-file FILE --plan PLAN --bundle BUNDLE --cluster ID --namespace NS --deployment NAME --expected-query PROMQL")
  return 2
 }
 rawAlert,err:=boundedAlertFile(*alertPath,alertintake.MaxAlertBytes)
 if err!=nil{return alertEvidenceUnknown(stderr,"original alert unreadable or oversized")}
 frozen,err:=boundedAlertFile(*planPath,alertintake.MaxPlanBytes)
 if err!=nil{return alertEvidenceUnknown(stderr,"canonical plan unreadable or oversized")}
 rawBundle,err:=boundedAlertFile(*bundlePath,evidence.MaxBundleBytes)
 if err!=nil{return alertEvidenceUnknown(stderr,"Evidence Bundle unreadable or oversized")}
 review,err:=reviewLinkedEvidence(rawAlert,frozen,rawBundle,alertintake.Target{
  Cluster:*cluster,Namespace:*namespace,Deployment:*deployment,
 },*query)
 if err!=nil{return alertEvidenceUnknown(stderr,err.Error())}
 if err:=json.NewEncoder(stdout).Encode(review);err!=nil{
  fmt.Fprintln(stderr,"cannot print offline review receipt")
  return 1
 }
 return 0
}
