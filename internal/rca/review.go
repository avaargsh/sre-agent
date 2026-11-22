// Package rca links competing hypotheses to source bytes without accepting
// an LLM-provided claim of causality, authorization, or incident recovery.
package rca

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

type Kind string
const (
 DeploymentCausal Kind = "DEPLOYMENT_CAUSAL"
 OtherCausal Kind = "OTHER_CAUSAL"
)
type Verdict string
const (
 CorrelatedNotProven Verdict = "CORRELATED_NOT_PROVEN"
 Contested Verdict = "CONTESTED"
 Unverified Verdict = "UNVERIFIED"
)
type Candidate struct {
 ID string `json:"id"`
 Kind Kind `json:"kind"`
 Statement string `json:"statement"`
 ClaimedStatus string `json:"claimed_status,omitempty"`
 SupportingRefs []string `json:"supporting_refs"`
 ContradictingRefs []string `json:"contradicting_refs"`
}
type Decision struct {
 ID string `json:"id"`
 Kind Kind `json:"kind"`
 Statement string `json:"statement"`
 Verdict Verdict `json:"verdict"`
 Reason string `json:"reason"`
 SupportingRefs []string `json:"supporting_refs"`
 ContradictingRefs []string `json:"contradicting_refs"`
}
type Report struct {
 SchemaVersion string `json:"schema_version"`
 Status string `json:"status"`
 PolicySHA256 string `json:"policy_sha256,omitempty"`
 Explanation string `json:"explanation"`
 Candidates []Decision `json:"candidates"`
}
type boundSource struct {
 origin string
}
const maxSourceBytes=2<<20
const maxCandidates=16
const maxRefs=32

// sourceRef checks the exact bytes and an unambiguous content digest.
// The source connection / its identity is NOT authenticated by this checksum.
func sourceRef(origin, hash, encoded string)(string,error){
 if len(hash)!=64||strings.ToLower(hash)!=hash{return "",errors.New("invalid source SHA-256 syntax")}
 if _,err:=hex.DecodeString(hash);err!=nil{return "",errors.New("invalid source SHA-256 hex")}
 if len(encoded)>base64.StdEncoding.EncodedLen(maxSourceBytes){return "",errors.New("source exceeds size budget")}
 raw,err:=base64.StdEncoding.Strict().DecodeString(encoded)
 if err!=nil||len(raw)==0||len(raw)>maxSourceBytes{return "",errors.New("invalid or oversized source bytes")}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=hash{return "",errors.New("source content digest mismatch")}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 var obj map[string]any
 if err:=decoder.Decode(&obj);err!=nil||obj==nil{return "",errors.New("source is not JSON object")}
 var extra any
 if !errors.Is(decoder.Decode(&extra),io.EOF){return "",errors.New("source contains trailing JSON")}
 return origin+":"+hash,nil
}
func sources(ch change.Report,sli verifier.Assessment)(map[string]boundSource,error){
 if ch.SchemaVersion!="sre.change-timeline/v1"||ch.Status!="OBSERVED"||
  (ch.Relationship!="TIME_OVERLAP_ONLY"&&ch.Relationship!="NO_REVISION_CREATED_IN_WINDOW")||
  ch.Namespace==""||ch.Deployment==""||ch.DeploymentUID==""||ch.Generation<=0||
  ch.ResourceVersion==""||ch.WindowStart.IsZero()||ch.WindowEnd.IsZero()||
  !ch.WindowStart.Before(ch.WindowEnd)||len(ch.Sources)!=3 {
   return nil,errors.New("change report is incomplete or not an observation")
 }
 if sli.Status!=verifier.Healthy&&sli.Status!=verifier.Unhealthy&&sli.Status!=verifier.Unknown {
  return nil,errors.New("invalid SLI status")
 }
 if sli.Start.IsZero()||sli.End.IsZero()||!sli.Start.Before(sli.End)||
  len(sli.Evidence)==0||len(sli.Evidence)>maxRefs{
  return nil,errors.New("SLI report has missing window or raw evidence")
 }
 index:=map[string]boundSource{}
 for i,src:=range ch.Sources{
  id,err:=sourceRef("k8s",src.ResponseSHA256,src.RawResponseBase64)
  if err!=nil{return nil,fmt.Errorf("change source %d: %w",i,err)}
  if src.Endpoint==""||!strings.HasPrefix(src.Endpoint,"/apis/apps/v1/namespaces/"+ch.Namespace+"/"){
   return nil,fmt.Errorf("change source %d: invalid endpoint context",i)
  }
  index[id]=boundSource{origin:"k8s"}
 }
 for i,src:=range sli.Evidence{
  id,err:=sourceRef("prom",src.ResponseSHA256,src.RawResponseBase64)
  if err!=nil{return nil,fmt.Errorf("SLI source %d: %w",i,err)}
  if strings.TrimSpace(src.Query)==""{return nil,fmt.Errorf("SLI source %d lacks a query",i)}
  index[id]=boundSource{origin:"prom"}
 }
 return index,nil
}
func windowsOverlap(aStart,aEnd,bStart,bEnd time.Time)bool{
 return aStart.Before(bEnd)&&bStart.Before(aEnd)
}
// Review is a deterministic, fail-closed citation/linkage gate.
// It replays the raw source bytes to recompute summaries but does not query
// live sources or authenticate their identities or the caller-owned policy.
// It cannot return CONFIRMED/SUPPORTED.
func Review(ch change.Report,sli verifier.Assessment,claims []Candidate)(Report,error){
 index,err:=sources(ch,sli)
 if err!=nil{return Report{},err}
 // Bound and hash-check input bytes before decoding them into replay models.
 if err:=Replay(ch,sli);err!=nil{return Report{},err}
 if len(claims)==0||len(claims)>maxCandidates{return Report{},errors.New("invalid candidate count")}
 report:=Report{
  SchemaVersion:"sre.rca-triage/v1",Status:"HUMAN_REVIEW_REQUIRED",
  Explanation:"Content digests check source byte integrity only; timeline and SLI evidence cannot independently establish root cause, source authenticity, or authorization.",
  Candidates:make([]Decision,0,len(claims)),
 }
 seenIDs:=map[string]bool{}
 for _,candidate:=range claims{
  if strings.TrimSpace(candidate.ID)==""||len(candidate.ID)>128||seenIDs[candidate.ID]||
   strings.TrimSpace(candidate.Statement)==""||len(candidate.Statement)>512||
   (candidate.Kind!=DeploymentCausal&&candidate.Kind!=OtherCausal)||
   len(candidate.ClaimedStatus)>64||
   len(candidate.SupportingRefs)+len(candidate.ContradictingRefs)==0||
   len(candidate.SupportingRefs)+len(candidate.ContradictingRefs)>maxRefs{
    return Report{},errors.New("invalid or duplicated candidate")
  }
  seenIDs[candidate.ID]=true
  seenRefs:=map[string]bool{}
  hasK8s,hasProm:=false,false
  for _,ref:=range candidate.SupportingRefs{
   source,ok:=index[ref]
   if !ok||seenRefs[ref]{return Report{},fmt.Errorf("candidate %s has unknown or duplicate support reference",candidate.ID)}
   seenRefs[ref]=true
   if source.origin=="k8s"{hasK8s=true}
   if source.origin=="prom"{hasProm=true}
  }
  for _,ref:=range candidate.ContradictingRefs{
   if _,ok:=index[ref];!ok||seenRefs[ref]{return Report{},fmt.Errorf("candidate %s has unknown or overlapping contrary reference",candidate.ID)}
   seenRefs[ref]=true
  }
  verdict:=Unverified
  reason:="Independent causal Oracle is unavailable; the hypothesis remains unverified"
  if len(candidate.ContradictingRefs)>0{
   verdict=Contested
   reason="Candidate has cited opposing evidence; adjudication requires independent review"
  }else if candidate.Kind==DeploymentCausal&&hasK8s&&hasProm&&
   ch.Relationship=="TIME_OVERLAP_ONLY"&&sli.Status==verifier.Unhealthy&&
   windowsOverlap(ch.WindowStart,ch.WindowEnd,sli.Start,sli.End){
   verdict=CorrelatedNotProven
   reason="Deployment revision and SLI degradation overlap, but temporal correlation is not causal evidence"
  }
  report.Candidates=append(report.Candidates,Decision{
   ID:candidate.ID,Kind:candidate.Kind,Statement:candidate.Statement,
   Verdict:verdict,Reason:reason,
   SupportingRefs:append([]string{},candidate.SupportingRefs...),
   ContradictingRefs:append([]string{},candidate.ContradictingRefs...),
  })
 }
 return report,nil
}
