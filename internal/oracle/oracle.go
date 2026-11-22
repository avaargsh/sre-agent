// Package oracle scores a narrow, disposable-kind Service targetPort fault.
// A test-admin injection record is independent of the read-only rule baseline.
// Neither record is an authenticated production truth source.
package oracle

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "regexp"
 "strings"
 "reflect"
)

type Snapshot struct {
 ResponseSHA256 string `json:"response_sha256"`
 RawResponseBase64 string `json:"raw_response_base64"`
}
type ProbePhases struct {
 Before []int `json:"before"`
 During []int `json:"during"`
 After []int `json:"after"`
}
type Episode struct {
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Scenario string `json:"scenario"`
 Namespace string `json:"namespace"`
 Service string `json:"service"`
 ServiceUID string `json:"service_uid"`
 ExpectedTargetPort int `json:"expected_target_port"`
 Before Snapshot `json:"before"`
 During Snapshot `json:"during"`
 After Snapshot `json:"after"`
 Probes ProbePhases `json:"probes"`
}
type Prediction struct {
 SchemaVersion string `json:"schema_version"`
 Classification string `json:"classification"`
 Namespace string `json:"namespace"`
 Service string `json:"service"`
 ServiceUID string `json:"service_uid"`
 ResourceVersion string `json:"resource_version"`
 ExpectedTargetPort int `json:"expected_target_port"`
 CurrentTargetPort int `json:"current_target_port"`
 ExpectedSelector map[string]string `json:"expected_selector,omitempty"`
 CurrentSelector map[string]string `json:"current_selector,omitempty"`
 Observed Snapshot `json:"observed"`
}
type Result struct {
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Scenario string `json:"scenario"`
 Prediction string `json:"prediction"`
 Verdict string `json:"verdict"`
 ExpectedTargetPort int `json:"expected_target_port"`
 ObservedTargetPort int `json:"observed_target_port"`
 ProductionCausalityVerified bool `json:"production_causality_verified"`
 Explanation string `json:"explanation"`
}
const maxSnapshot=2<<20
var idPattern=regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
type service struct {
 Metadata struct {
  UID string `json:"uid"`
  Name string `json:"name"`
  Namespace string `json:"namespace"`
  ResourceVersion string `json:"resourceVersion"`
 } `json:"metadata"`
 Spec struct {
  Selector map[string]string `json:"selector"`
  Ports []struct {
   Port int `json:"port"`
   TargetPort json.RawMessage `json:"targetPort"`
  } `json:"ports"`
 } `json:"spec"`
}
type parsed struct{
 UID, Name, Namespace, ResourceVersion string
 ServicePort, TargetPort int
 SelectorJSON string
}
func parse(raw []byte)(parsed,error){
 var v service
 if len(raw)==0||len(raw)>maxSnapshot{return parsed{},errors.New("Service JSON too large or empty")}
 d:=json.NewDecoder(bytes.NewReader(raw))
 if err:=d.Decode(&v);err!=nil{return parsed{},errors.New("invalid Service JSON")}
 var trailing any
 if !errors.Is(d.Decode(&trailing),io.EOF){return parsed{},errors.New("trailing Service JSON")}
 m:=v.Metadata
 if m.UID==""||m.Name==""||m.Namespace==""||m.ResourceVersion==""||len(v.Spec.Ports)!=1||len(v.Spec.Selector)==0{
  return parsed{},errors.New("missing identity, selector or unambiguous Service port")
 }
 var target int
 if len(v.Spec.Ports[0].TargetPort)==0||v.Spec.Ports[0].TargetPort[0]=='"'||
  json.Unmarshal(v.Spec.Ports[0].TargetPort,&target)!=nil||target<1||target>65535||
  v.Spec.Ports[0].Port<1||v.Spec.Ports[0].Port>65535{
  return parsed{},errors.New("unsupported named or invalid numeric targetPort")
 }
 sel,err:=json.Marshal(v.Spec.Selector)
 if err!=nil{return parsed{},err}
 return parsed{UID:m.UID,Name:m.Name,Namespace:m.Namespace,ResourceVersion:m.ResourceVersion,
  ServicePort:v.Spec.Ports[0].Port,TargetPort:target,SelectorJSON:string(sel)},nil
}
func decode(s Snapshot)(parsed,error){
 if len(s.ResponseSHA256)!=64||strings.ToLower(s.ResponseSHA256)!=s.ResponseSHA256{
  return parsed{},errors.New("invalid snapshot digest")
 }
 if _,err:=hex.DecodeString(s.ResponseSHA256);err!=nil{return parsed{},err}
 if len(s.RawResponseBase64)>base64.StdEncoding.EncodedLen(maxSnapshot){
  return parsed{},errors.New("snapshot exceeds bounded Base64 size")
 }
 raw,err:=base64.StdEncoding.Strict().DecodeString(s.RawResponseBase64)
 if err!=nil{return parsed{},errors.New("invalid snapshot encoding")}
 hash:=sha256.Sum256(raw)
 if hex.EncodeToString(hash[:])!=s.ResponseSHA256{return parsed{},errors.New("snapshot bytes and SHA differ")}
 return parse(raw)
}
// Diagnose only reads a frozen Service GET response and an operator-provided
// expected targetPort. It does NOT read test-admin Oracle labels or probes.
func Diagnose(raw []byte,expectedTargetPort int)(Prediction,error){
 return diagnoseService(raw,expectedTargetPort,nil)
}
// DiagnoseWithSelector independently compares the read-only Service GET to
// both operator-pinned targetPort and expected label selector. Simultaneous
// faults conservatively abstain rather than invent a single root cause.
func DiagnoseWithSelector(raw []byte,expectedTargetPort int,expectedSelector map[string]string)(Prediction,error){
 if len(expectedSelector)==0{return Prediction{},errors.New("missing operator expected selector")}
 for k,v:=range expectedSelector{
  if k==""||v==""{return Prediction{},errors.New("invalid operator expected selector")}
 }
 return diagnoseService(raw,expectedTargetPort,expectedSelector)
}
func diagnoseService(raw []byte,expectedTargetPort int,expectedSelector map[string]string)(Prediction,error){
 if expectedTargetPort<1||expectedTargetPort>65535{return Prediction{},errors.New("invalid operator expected targetPort")}
 v,err:=parse(raw)
 if err!=nil{return Prediction{},err}
 var actual map[string]string
 if err:=json.Unmarshal([]byte(v.SelectorJSON),&actual);err!=nil{return Prediction{},err}
 digest:=sha256.Sum256(raw)
 portMismatch:=v.TargetPort!=expectedTargetPort
 selectorMismatch:=len(expectedSelector)>0&&!reflect.DeepEqual(actual,expectedSelector)
 label:="UNKNOWN"
 if portMismatch&&!selectorMismatch{label="SERVICE_TARGETPORT_MISROUTED"}
 if selectorMismatch&&!portMismatch{label="SERVICE_SELECTOR_MISMATCH"}
 return Prediction{SchemaVersion:"sre.service-diagnosis/v1",Classification:label,
 Namespace:v.Namespace,Service:v.Name,ServiceUID:v.UID,ResourceVersion:v.ResourceVersion,
 ExpectedTargetPort:expectedTargetPort,CurrentTargetPort:v.TargetPort,
 ExpectedSelector:expectedSelector,CurrentSelector:actual,
 Observed:Snapshot{ResponseSHA256:hex.EncodeToString(digest[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)}},nil
}
func validateProbes(probes []int,wantSuccess bool)error{
 if len(probes)<3||len(probes)>12{return errors.New("at least 3 and at most 12 independently captured probes required")}
 for _,code:=range probes{
  if code<0||code>599{return errors.New("invalid HTTP code")}
  success:=code>=200&&code<300
  if success!=wantSuccess{return fmt.Errorf("probe inconsistent with independent scenario (HTTP %d)",code)}
 }
 return nil
}
// Evaluate validates frozen admin-controlled before/during/after snapshots and
// actual probe observations, then scores the separate read-only rule baseline.
// It does not independently sign or authenticate the admin-provided Episode.
func Evaluate(e Episode,p Prediction)(Result,error){
 if e.SchemaVersion!="sre.fault-oracle/v1"||!idPattern.MatchString(e.EpisodeID)||
  e.Namespace==""||e.Service==""||e.ServiceUID==""||
  e.ExpectedTargetPort<1||e.ExpectedTargetPort>65535||
  (e.Scenario!="NO_FAULT"&&e.Scenario!="SERVICE_TARGETPORT_MISROUTED"&&e.Scenario!="SERVICE_SELECTOR_MISMATCH"){
  return Result{},errors.New("invalid Oracle identity or scenario")
 }
 before,err:=decode(e.Before);if err!=nil{return Result{},err}
 during,err:=decode(e.During);if err!=nil{return Result{},err}
 after,err:=decode(e.After);if err!=nil{return Result{},err}
 for _,v:=range []parsed{before,during,after}{
  if v.Name!=e.Service||v.Namespace!=e.Namespace||v.UID!=e.ServiceUID||
   v.ServicePort!=before.ServicePort{
   return Result{},errors.New("Service identity, selector or exposed port drifted between phases")
  }
 }
 if before.TargetPort!=e.ExpectedTargetPort||after.TargetPort!=e.ExpectedTargetPort||
  after.SelectorJSON!=before.SelectorJSON{
  return Result{},errors.New("baseline not clean or service was not restored")
 }
 if err:=validateProbes(e.Probes.Before,true);err!=nil{return Result{},err}
 if err:=validateProbes(e.Probes.After,true);err!=nil{return Result{},err}
 portFault:=e.Scenario=="SERVICE_TARGETPORT_MISROUTED"
 selectorFault:=e.Scenario=="SERVICE_SELECTOR_MISMATCH"
 fault:=portFault||selectorFault
 if portFault&&(during.TargetPort==e.ExpectedTargetPort||during.SelectorJSON!=before.SelectorJSON){
  return Result{},errors.New("port fault must change only targetPort")
 }
 if selectorFault&&(during.TargetPort!=e.ExpectedTargetPort||during.SelectorJSON==before.SelectorJSON){
  return Result{},errors.New("selector fault must change only Service selector")
 }
 if !fault&&(during.TargetPort!=e.ExpectedTargetPort||during.SelectorJSON!=before.SelectorJSON){
  return Result{},errors.New("control episode contains unauthorized fault")
 }
 if err:=validateProbes(e.Probes.During,!fault);err!=nil{return Result{},err}
 observed,err:=decode(p.Observed);if err!=nil{return Result{},err}
 if p.SchemaVersion!="sre.service-diagnosis/v1"||
  p.ExpectedTargetPort!=e.ExpectedTargetPort||
  p.ServiceUID!=e.ServiceUID||p.Namespace!=e.Namespace||p.Service!=e.Service||
  p.CurrentTargetPort!=observed.TargetPort||p.ResourceVersion!=observed.ResourceVersion||
  observed.UID!=during.UID||observed.ResourceVersion!=during.ResourceVersion||
  observed.TargetPort!=during.TargetPort||observed.SelectorJSON!=during.SelectorJSON{
  return Result{},errors.New("read-only prediction is not correlated to frozen during-phase Service identity")
 }
 raw,err:=base64.StdEncoding.Strict().DecodeString(p.Observed.RawResponseBase64)
 if err!=nil{return Result{},err}
 var expected Prediction
 if len(p.ExpectedSelector)>0{
  var beforeSelector map[string]string
  if err:=json.Unmarshal([]byte(before.SelectorJSON),&beforeSelector);err!=nil{return Result{},err}
  if !reflect.DeepEqual(p.ExpectedSelector,beforeSelector){
   return Result{},errors.New("expected selector was not operator-baselined")
  }
  expected,err=DiagnoseWithSelector(raw,p.ExpectedTargetPort,p.ExpectedSelector)
 }else{
  if selectorFault{return Result{},errors.New("selector diagnosis requires independent expected-selector baseline")}
  expected,err=Diagnose(raw,p.ExpectedTargetPort)
 }
 if err!=nil{return Result{},err}
 if p.Classification!=expected.Classification||!reflect.DeepEqual(p.CurrentSelector,expected.CurrentSelector){
  return Result{},errors.New("prediction classification/selector disagrees with the observed source")
 }
 verdict:="CORRECT_REJECTION"
 if fault{verdict="MATCHED_INJECTED_FAULT"}
 return Result{SchemaVersion:"sre.fault-evaluation/v1",EpisodeID:e.EpisodeID,
 Scenario:e.Scenario,Prediction:p.Classification,Verdict:verdict,
 ExpectedTargetPort:e.ExpectedTargetPort,ObservedTargetPort:observed.TargetPort,
 ProductionCausalityVerified:false,
 Explanation:"Disposable-kind Service fault Oracle with operator-baselined port/selector rule. No general causal RCA, LLM accuracy or signed source identity is established."},nil
}
