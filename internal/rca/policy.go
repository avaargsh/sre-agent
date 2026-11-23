package rca

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "math"
 "strings"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

const maxPolicyBytes=8192

// SourcePolicy is an operator-owned, externally pinned read-only review
// contract. Its SHA-256 pin MUST arrive from a separate trusted channel;
// recomputing the pin from a candidate's policy file proves nothing.
type SourcePolicy struct {
 SchemaVersion string `json:"schema_version"`
 Namespace string `json:"namespace"`
 Deployment string `json:"deployment"`
 DeploymentUID string `json:"deployment_uid"`
 LatencyQuery string `json:"latency_query"`
 TrafficQuery string `json:"traffic_query"`
 AgeQuery string `json:"age_query"`
 MaxLatencySeconds float64 `json:"max_latency_seconds"`
 MinTrafficPerSecond float64 `json:"min_traffic_rps"`
 MaxSampleAgeSeconds float64 `json:"max_sample_age_seconds"`
 WindowSeconds int64 `json:"window_seconds"`
 StepSeconds int64 `json:"step_seconds"`
}
func finitePositive(v float64)bool{return v>0&&!math.IsNaN(v)&&!math.IsInf(v,0)}
func ParsePinnedPolicy(raw []byte,expectedSHA string)(SourcePolicy,error){
 var result SourcePolicy
 if len(raw)==0||len(raw)>maxPolicyBytes{return result,errors.New("operator policy exceeds bounds or is empty")}
 if len(expectedSHA)!=64||strings.ToLower(expectedSHA)!=expectedSHA{return result,errors.New("operator policy pin missing or invalid")}
 if _,err:=hex.DecodeString(expectedSHA);err!=nil{return result,errors.New("invalid operator policy hash")}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=expectedSHA{return result,errors.New("operator policy bytes differ from external pin")}
 // The contract is intentionally one flat object: disallow duplicate keys to
 // avoid 'last value wins' disagreement between Go, JSON tooling and signers.
 tokens:=json.NewDecoder(bytes.NewReader(raw))
 first,err:=tokens.Token()
 if err!=nil||first!=json.Delim('{'){return result,errors.New("operator policy must be an object")}
 // Go's struct decoder accepts case-insensitive aliases of JSON tags.
 // An exact-byte pin does not make an ambiguous field name canonical.
 // This allowlist is the security-facing v1 schema, not an advisory hint.
 canonical:=map[string]struct{}{
  "schema_version":{}, "namespace":{}, "deployment":{}, "deployment_uid":{},
  "latency_query":{}, "traffic_query":{}, "age_query":{},
  "max_latency_seconds":{}, "min_traffic_rps":{},
  "max_sample_age_seconds":{}, "window_seconds":{}, "step_seconds":{},
 }
 seen:=map[string]bool{}
 for tokens.More(){
  token,err:=tokens.Token()
  if err!=nil{return result,errors.New("invalid policy object")}
  key,ok:=token.(string)
  if !ok||seen[key]{return result,errors.New("duplicate or nonstring operator policy key")}
  if _,allowed:=canonical[key];!allowed {
   return result,errors.New("unknown or noncanonical operator policy field")
  }
  seen[key]=true
  var value any
  if err:=tokens.Decode(&value);err!=nil{return result,errors.New("invalid operator policy value")}
  switch value.(type){
  case map[string]any,[]any:
   return result,errors.New("operator policy must be a flat scalar object")
  }
 }
 end,err:=tokens.Token()
 if err!=nil||end!=json.Delim('}'){return result,errors.New("unterminated operator policy")}
 var trailing any
 if !errors.Is(tokens.Decode(&trailing),io.EOF){return result,errors.New("trailing operator policy JSON")}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&result);err!=nil{return SourcePolicy{},fmt.Errorf("invalid policy contract: %w",err)}
 if result.SchemaVersion!="sre.rca-policy/v1"||
  strings.TrimSpace(result.Namespace)==""||strings.TrimSpace(result.Deployment)==""||strings.TrimSpace(result.DeploymentUID)==""||
  len(result.Namespace)>63||len(result.Deployment)>63||len(result.DeploymentUID)>256||
  len(result.LatencyQuery)==0||len(result.LatencyQuery)>512||
  len(result.TrafficQuery)==0||len(result.TrafficQuery)>512||
  len(result.AgeQuery)==0||len(result.AgeQuery)>512||
  !finitePositive(result.MaxLatencySeconds)||!finitePositive(result.MinTrafficPerSecond)||!finitePositive(result.MaxSampleAgeSeconds)||
  result.WindowSeconds<2||result.WindowSeconds>600||result.StepSeconds<1||
  result.WindowSeconds%result.StepSeconds!=0||result.WindowSeconds/result.StepSeconds<2 {
  return SourcePolicy{},errors.New("operator policy has missing or unsafe fields")
 }
 return result,nil
}

// ReviewWithPolicy checks *all* target, query, threshold and sampling fields
// against a separately pinned operator policy before raw evidence replay.
// It still cannot authenticate the Prometheus server, the provenance of
// evidence files, the operator, or the approval source.
func ReviewWithPolicy(ch change.Report,sli verifier.Assessment,claims []Candidate,policyRaw []byte,policySHA string)(Report,error){
 p,err:=ParsePinnedPolicy(policyRaw,policySHA)
 if err!=nil{return Report{},err}
 if ch.Namespace!=p.Namespace||ch.Deployment!=p.Deployment||ch.DeploymentUID!=p.DeploymentUID{
  return Report{},errors.New("Kubernetes target identity differs from pinned policy")
 }
 if len(sli.Evidence)!=3||
  sli.Evidence[0].Query!=p.LatencyQuery||
  sli.Evidence[1].Query!=p.TrafficQuery||
  sli.Evidence[2].Query!=p.AgeQuery{
  return Report{},errors.New("Prometheus queries differ from pinned policy")
 }
 if sli.MaxLatencySeconds!=p.MaxLatencySeconds||
  sli.MinTrafficPerSecond!=p.MinTrafficPerSecond||
  sli.MaxSampleAgeSeconds!=p.MaxSampleAgeSeconds||
  sli.StepSeconds!=p.StepSeconds||
  sli.End.Sub(sli.Start)!=time.Duration(p.WindowSeconds)*time.Second{
  return Report{},errors.New("SLI threshold or evaluation window differs from pinned policy")
 }
 report,err:=Review(ch,sli,claims)
 if err!=nil{return Report{},err}
 report.PolicySHA256=policySHA
 return report,nil
}
