package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "strings"
 "time"
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

// Exact-name extraction deliberately refuses to treat "Status" as "status".
// Invalid types yield empty values and are rejected by the contract checks;
// the v1 Evidence verifier independently checks outer schema/digest validity.
func exactObject(v any)map[string]any{
 m,_:=v.(map[string]any)
 return m
}
func exactArray(v any)[]any{
 items,_:=v.([]any)
 return items
}
func exactText(m map[string]any,key string)string{
 v,_:=m[key].(string)
 return v
}
func exactInt(m map[string]any,key string)float64{
 v,_:=m[key].(float64)
 return v
}

// rejectCasefoldAliases ensures no other consumer of these same original
// bytes can silently resolve a different value through Go struct field
// matching. The v1 evidence schema permits additional metadata/attributes,
// so only routing and release-sensitive canonical names are reserved here.
func rejectCasefoldAliases(obj map[string]any, location string, canonical ...string)error{
 for actual:=range obj{
  for _,key:=range canonical{
   if actual!=key && strings.EqualFold(actual,key){
    return fmt.Errorf("%s contains ambiguous alias %q for %q",location,actual,key)
   }
  }
 }
 return nil
}

// A v1 read-only observation has an exact producer-owned shape. Unknown
// fields can carry fabricated approval or recovery claims despite valid
// self-hashes; that ambiguity is prohibited rather than ignored.
func requireOnlyFields(obj map[string]any,location string,keys ...string)error{
 if obj==nil{return fmt.Errorf("%s must be an object",location)}
 allowed:=make(map[string]bool,len(keys))
 for _,key:=range keys{allowed[key]=true}
 for actual:=range obj{
  if !allowed[actual]{return fmt.Errorf("%s includes unsupported field %q",location,actual)}
 }
 return nil
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
 // Use a generic map after the structural verifier rather than decoding
 // into Go structs: encoding/json matches struct tags case-insensitively,
 // and a late "Source" alias can override the canonical "source" key.
 var doc map[string]any
 if err:=json.Unmarshal(bundle,&doc);err!=nil {
  return AlertEvidenceReview{},fmt.Errorf("unparseable observation bundle: %w",err)
 }
 if err:=rejectCasefoldAliases(doc,"bundle",
  "incident","evidence","hypotheses","entities","edges","changes","metadata");err!=nil{
  return AlertEvidenceReview{},err
 }
 incident:=exactObject(doc["incident"])
 meta:=exactObject(doc["metadata"])
 items:=exactArray(doc["evidence"])
 if err:=rejectCasefoldAliases(incident,"incident",
  "incident_id","summary","severity","scope");err!=nil{return AlertEvidenceReview{},err}
 if err:=rejectCasefoldAliases(meta,"metadata",
  "schema_version","observation_status","bundle_sha256","tool_count","evidence_count","observed_at");err!=nil{
  return AlertEvidenceReview{},err
 }
 if err:=requireOnlyFields(incident,"read-only incident",
  "incident_id","summary","severity","scope");err!=nil{return AlertEvidenceReview{},err}
 if err:=requireOnlyFields(meta,"read-only metadata",
  "schema_version","observation_status","observed_at","tool_count","evidence_count","bundle_sha256");err!=nil{
  return AlertEvidenceReview{},err
 }
 observedAt:=exactText(meta,"observed_at")
 if observedAt==""{
  return AlertEvidenceReview{},fmt.Errorf("read-only observation timestamp missing")
 }
 observationClock,err:=time.Parse(time.RFC3339Nano,observedAt)
 if err!=nil{
  return AlertEvidenceReview{},fmt.Errorf("invalid read-only observation timestamp")
 }
 expectedScope:="namespace="+target.Namespace+",deployment="+target.Deployment
 if exactText(incident,"incident_id")!=plan.IncidentID||
  exactText(incident,"summary")!=plan.Summary||
  exactText(incident,"severity")!=plan.Severity||
  exactText(incident,"scope")!=expectedScope {
  return AlertEvidenceReview{},fmt.Errorf("bundle incident identity or operator scope differs from reviewed plan")
 }
 if exactText(meta,"schema_version")!="aiops.evidence/v1"||
  exactText(meta,"observation_status")!="complete"||
  exactText(meta,"bundle_sha256")!=checked.BundleSHA256||
  exactInt(meta,"tool_count")!=2||exactInt(meta,"evidence_count")!=2||
  len(items)!=2||len(exactArray(doc["hypotheses"]))!=0||
  len(exactArray(doc["entities"]))!=0||
  len(exactArray(doc["edges"]))!=0||len(exactArray(doc["changes"]))!=0{
  return AlertEvidenceReview{},fmt.Errorf("bundle does not match the v1 read-only observation contract")
 }
 sources:=map[string]bool{}
 for _,rawItem:=range items{
  item:=exactObject(rawItem)
  if err:=rejectCasefoldAliases(item,"evidence item","source","attributes","timestamp");err!=nil{
   return AlertEvidenceReview{},err
  }
  if err:=requireOnlyFields(item,"read-only evidence item",
   "evidence_id","source","observation","timestamp","attributes","entity_refs");err!=nil{
   return AlertEvidenceReview{},err
  }
  if exactText(item,"timestamp")!=observedAt {
   return AlertEvidenceReview{},fmt.Errorf("source evidence timestamp disagrees with observation")
  }
  source:=exactText(item,"source")
  if sources[source]{return AlertEvidenceReview{},fmt.Errorf("duplicate observation source")}
  sources[source]=true
  attrs:=exactObject(item["attributes"])
  if err:=rejectCasefoldAliases(attrs,"source attributes",
   "namespace","deployment","uid","resource_version","promql","result_type");err!=nil{
   return AlertEvidenceReview{},err
  }
  if exactText(attrs,"observed_at")!=observedAt {
   return AlertEvidenceReview{},fmt.Errorf("source attribute timestamp disagrees with observation")
  }
  switch source{
  case "kubernetes":
   if err:=requireOnlyFields(attrs,"Kubernetes observation attributes",
    "namespace","deployment","uid","resource_version","generation",
    "observed_generation","desired_replicas","ready_replicas","pods_json",
    "pod_list_resource_version","observed_at");err!=nil{
    return AlertEvidenceReview{},err
   }
   if err:=validateEmbeddedPods(attrs);err!=nil{
    return AlertEvidenceReview{},err
   }
   if exactText(attrs,"namespace")!=target.Namespace||
     exactText(attrs,"deployment")!=target.Deployment||
     exactText(attrs,"uid")==""||
     exactText(attrs,"resource_version")==""{
    return AlertEvidenceReview{},fmt.Errorf("Kubernetes observation target mismatch")
   }
  case "prometheus":
   if err:=requireOnlyFields(attrs,"Prometheus observation attributes",
    "promql","samples_json","result_type","series_count","observed_at","max_age_seconds");err!=nil{
    return AlertEvidenceReview{},err
   }
   if err:=validateEmbeddedSamples(attrs,observationClock);err!=nil{
    return AlertEvidenceReview{},err
   }
   if expectedQuery==""||len(expectedQuery)>512||
     exactText(attrs,"promql")!=expectedQuery||
     exactText(attrs,"result_type")!="vector"{
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
