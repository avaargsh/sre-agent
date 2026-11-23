// Package alertintake turns an untrusted Alertmanager webhook snapshot into
// a deterministic, scoped proposal for read-only investigation. No action or
// source authentication is implied by the plan, even when its bytes hash.
package alertintake

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "regexp"
 "strconv"
 "strings"
 "unicode/utf8"

 "github.com/avaargsh/sre-agent/internal/evidence"
)

const MaxAlertBytes = 1 << 20
const maxGroupAlerts = 64

var ErrUnknown = errors.New("alert intake UNKNOWN")
var scopePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

type Target struct {
 Cluster string `json:"cluster"`
 Namespace string `json:"namespace"`
 Deployment string `json:"deployment"`
}

// Plan is an untrusted input-to-read-only-work mapping. No field is an
// approval, proof of origin, or command execution capability.
type Plan struct {
 SchemaVersion string `json:"schema_version"`
 Status string `json:"status"`
 IncidentID string `json:"incident_id"`
 Target Target `json:"target"`
 GroupKey string `json:"group_key"`
 Summary string `json:"summary"`
 Severity string `json:"severity"`
 FiringAlerts int `json:"firing_alerts"`
 RawSHA256 string `json:"raw_sha256"`
 SourceAuthenticated bool `json:"source_authenticated"`
 AuthorizesExecution bool `json:"authorizes_execution"`
}

type alert struct {
 Status string `json:"status"`
 Fingerprint string `json:"fingerprint"`
 Labels map[string]string `json:"labels"`
}
type envelope struct {
 Status string `json:"status"`
 GroupKey string `json:"groupKey"`
 CommonLabels map[string]string `json:"commonLabels"`
 CommonAnnotations map[string]string `json:"commonAnnotations"`
 Alerts []alert `json:"alerts"`
}

func unknown(msg string) error { return fmt.Errorf("%w: %s",ErrUnknown,msg) }
func scopeOK(v string) bool { return len(v)>0 && len(v)<=63 && scopePattern.MatchString(v) }
func labelMatches(labels map[string]string,t Target) bool {
 return labels["cluster"]==t.Cluster && labels["namespace"]==t.Namespace && labels["deployment"]==t.Deployment
}

// checkEscapedSurrogates prevents lossy \uD800 -> U+FFFD transformations by
// encoding/json. A valid UTF-16 surrogate pair is allowed; escaped backslashes
// are not mistaken for a JSON Unicode escape. The JSON decoder owns syntax.
func checkEscapedSurrogates(raw []byte) error {
 inString:=false
 for i:=0;i<len(raw);i++ {
  if !inString { if raw[i]=='"' {inString=true};continue }
  if raw[i]=='"' {inString=false;continue}
  if raw[i]!='\\' {continue}
  if i+1>=len(raw) {return unknown("truncated escape")}
  if raw[i+1]!='u' {i++;continue}
  if i+6>len(raw) {return unknown("truncated Unicode escape")}
  code,err:=strconv.ParseUint(string(raw[i+2:i+6]),16,16)
  if err!=nil {return unknown("invalid Unicode escape")}
  switch {
  case code>=0xd800 && code<=0xdbff:
   if i+12>len(raw)||raw[i+6]!='\\'||raw[i+7]!='u' {
    return unknown("unpaired Unicode surrogate")
   }
   low,err:=strconv.ParseUint(string(raw[i+8:i+12]),16,16)
   if err!=nil||low<0xdc00||low>0xdfff {return unknown("unpaired Unicode surrogate")}
   i+=11
  case code>=0xdc00 && code<=0xdfff:
   return unknown("unpaired Unicode surrogate")
  default:
   i+=5
  }
 }
 return nil
}

// Parse only accepts firing groups explicitly matching a separately configured
// operator target. The stable incident ID is scoped to that target plus group
// key; it does not change with alert annotations or repeated deliveries.
func Parse(raw []byte,t Target)(Plan,error) {
 if !scopeOK(t.Cluster)||!scopeOK(t.Namespace)||!scopeOK(t.Deployment) {
  return Plan{},unknown("invalid operator target scope")
 }
 if len(raw)==0||len(raw)>MaxAlertBytes||!utf8.Valid(raw) {
  return Plan{},unknown("invalid payload size or encoding")
 }
 if err:=checkEscapedSurrogates(raw);err!=nil {return Plan{},err}
 // The v1 evidence helper walks all nested objects and rejects duplicate keys
 // (including escaped aliases) and trailing documents before typed decoding.
 if err:=evidence.ValidateUniqueJSONObject(raw);err!=nil {return Plan{},unknown("ambiguous Alertmanager JSON")}
 if err:=checkCanonicalFields(raw);err!=nil{return Plan{},err}
 var input envelope
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 if err:=decoder.Decode(&input);err!=nil {return Plan{},unknown("malformed Alertmanager payload")}
 if input.Status!="firing" || strings.TrimSpace(input.GroupKey)==""||len(input.GroupKey)>512||
  len(input.Alerts)==0||len(input.Alerts)>maxGroupAlerts {
  return Plan{},unknown("missing or nonfiring bounded alert group")
 }
 if !labelMatches(input.CommonLabels,t) {
  return Plan{},unknown("group labels disagree with operator scope")
 }
 summary:=strings.TrimSpace(input.CommonAnnotations["summary"])
 if summary==""{summary=strings.TrimSpace(input.CommonAnnotations["description"])}
 if summary==""{summary=strings.TrimSpace(input.CommonLabels["alertname"])}
 if summary==""||len(summary)>512 {return Plan{},unknown("missing or oversized alert summary")}
 severity:=strings.TrimSpace(input.CommonLabels["severity"])
 if severity=="" {severity="unknown"}
 if len(severity)>64||strings.ContainsAny(severity,"\r\n\t") {return Plan{},unknown("invalid alert severity")}
 fingerprints:=make(map[string]bool,len(input.Alerts))
 firing:=0
 for _,item:=range input.Alerts {
  if (item.Status!="firing" && item.Status!="resolved") ||
   !fingerprintPattern.MatchString(item.Fingerprint) ||
   fingerprints[item.Fingerprint] ||
   !labelMatches(item.Labels,t) {
   return Plan{},unknown("ambiguous, cross-target or duplicate alert")
  }
  fingerprints[item.Fingerprint]=true
  if item.Status=="firing" {firing++}
 }
 if firing==0 {return Plan{},unknown("no firing alert in group")}
 // Include exact separators so two different scoped tuples cannot concatenate
 // to the same preimage. This identity is a deduplication key, not a signature.
 material:=strings.Join([]string{"sre.alert-plan/v1",t.Cluster,t.Namespace,t.Deployment,input.GroupKey},"\x00")
 identity:=sha256.Sum256([]byte(material))
 digest:=sha256.Sum256(raw)
 return Plan{SchemaVersion:"sre.alert-plan/v1",Status:"READ_ONLY_CANDIDATE",
  IncidentID:"alert-"+hex.EncodeToString(identity[:20]),Target:t,
  GroupKey:input.GroupKey,Summary:summary,Severity:severity,FiringAlerts:firing,
  RawSHA256:hex.EncodeToString(digest[:]),
  SourceAuthenticated:false,AuthorizesExecution:false},nil
}
