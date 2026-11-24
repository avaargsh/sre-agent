// Package endpointoracle tests a read-only, observable lack of ready Service
// endpoints against a separate disposable-kind test-admin incident record.
// A zero-ready EndpointSlice is not proof of the underlying root cause.
package endpointoracle

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "reflect"
 "strings"

 "github.com/avaargsh/sre-agent/internal/evidence"
 "github.com/avaargsh/sre-agent/internal/oracle"
)

const maxRaw=2<<20
type Phase struct{
 Service oracle.Snapshot `json:"service"`
 EndpointSlices oracle.Snapshot `json:"endpoint_slices"`
 Probes []int `json:"probes"`
}
type Episode struct{
 SchemaVersion string `json:"schema_version"`
 ID string `json:"episode_id"`
 Scenario string `json:"scenario"`
 Namespace string `json:"namespace"`
 Service string `json:"service"`
 ServiceUID string `json:"service_uid"`
 ExpectedTargetPort int `json:"expected_target_port"`
 ExpectedSelector map[string]string `json:"expected_selector"`
 Before Phase `json:"before"`
 During Phase `json:"during"`
 After Phase `json:"after"`
}
type Prediction struct{
 SchemaVersion string `json:"schema_version"`
 Classification string `json:"classification"`
 Service oracle.Prediction `json:"service"`
 EndpointSlices oracle.Snapshot `json:"endpoint_slices"`
 ListResourceVersion string `json:"list_resource_version"`
 ReadyEndpoints int `json:"ready_endpoints"`
 ExpectedSelector map[string]string `json:"expected_selector"`
}
type Result struct{
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Scenario string `json:"scenario"`
 Prediction string `json:"prediction"`
 Verdict string `json:"verdict"`
 ProductionCausalityVerified bool `json:"production_causality_verified"`
 Explanation string `json:"explanation"`
}

type sliceList struct {
 Kind string `json:"kind"`
 Metadata struct {
  ResourceVersion string `json:"resourceVersion"`
  Continue string `json:"continue"`
 } `json:"metadata"`
 Items []struct {
  Metadata struct {
   UID string `json:"uid"`
   Name string `json:"name"`
   Namespace string `json:"namespace"`
   Labels map[string]string `json:"labels"`
  } `json:"metadata"`
  AddressType string `json:"addressType"`
  Endpoints []struct {
   Addresses []string `json:"addresses"`
   Conditions struct {Ready *bool `json:"ready"`} `json:"conditions"`
  } `json:"endpoints"`
 } `json:"items"`
}
type observation struct{ready int;version string}

func checkedRaw(s oracle.Snapshot)([]byte,error){
 if len(s.ResponseSHA256)!=64||strings.ToLower(s.ResponseSHA256)!=s.ResponseSHA256{
  return nil,errors.New("invalid source digest")
 }
 if _,err:=hex.DecodeString(s.ResponseSHA256);err!=nil{return nil,err}
 if len(s.RawResponseBase64)>base64.StdEncoding.EncodedLen(maxRaw){return nil,errors.New("source over byte budget")}
 raw,err:=base64.StdEncoding.Strict().DecodeString(s.RawResponseBase64)
 if err!=nil||len(raw)==0||len(raw)>maxRaw{return nil,errors.New("invalid source encoding/length")}
 h:=sha256.Sum256(raw)
 if hex.EncodeToString(h[:])!=s.ResponseSHA256{return nil,errors.New("source digest mismatch")}
 return raw,nil
}
func snap(raw []byte)oracle.Snapshot{
 h:=sha256.Sum256(raw)
 return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(h[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)}
}
func inspect(raw []byte,namespace,service string)(observation,error){
 if len(raw)==0||len(raw)>maxRaw{return observation{},errors.New("EndpointSlice response size invalid")}
 if err:=evidence.ValidateUniqueJSONObject(raw);err!=nil{return observation{},errors.New("ambiguous EndpointSlice JSON keys")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 var list sliceList
 if err:=dec.Decode(&list);err!=nil{return observation{},errors.New("invalid EndpointSlice JSON")}
 var extra any
 if !errors.Is(dec.Decode(&extra),io.EOF){return observation{},errors.New("trailing EndpointSlice JSON")}
 if list.Kind!="EndpointSliceList"||list.Metadata.ResourceVersion==""||list.Metadata.Continue!=""||list.Items==nil||len(list.Items)>128{
  return observation{},errors.New("EndpointSlice list is incomplete or wrong kind")
 }
 ready:=0
 seenUIDs:=map[string]bool{}
 seenNames:=map[string]bool{}
 for _,item:=range list.Items{
  meta:=item.Metadata
  if meta.Name==""||len(meta.Name)>253||meta.UID==""||seenUIDs[meta.UID]||seenNames[meta.Name]||
   meta.Namespace!=namespace||meta.Labels==nil||
   meta.Labels["kubernetes.io/service-name"]!=service||
   (item.AddressType!="IPv4"&&item.AddressType!="IPv6"&&item.AddressType!="FQDN"){
   return observation{},errors.New("invalid or off-scope EndpointSlice membership")
  }
  seenUIDs[meta.UID]=true
  seenNames[meta.Name]=true
  if len(item.Endpoints)>256{return observation{},errors.New("EndpointSlice too many endpoints")}
  for _,endpoint:=range item.Endpoints{
   if endpoint.Conditions.Ready==nil||len(endpoint.Addresses)==0||len(endpoint.Addresses)>16{
    return observation{},errors.New("ambiguous endpoint readiness or address")
   }
   if *endpoint.Conditions.Ready{ready++}
  }
 }
 return observation{ready:ready,version:list.Metadata.ResourceVersion},nil
}
// Diagnose receives only the observer's Kubernetes Service and EndpointSlice
// GET/LIST responses and the operator's independently supplied good baseline.
// It never receives test-admin episode labels or client HTTP probe results.
func Diagnose(serviceRaw,endpointRaw []byte,targetPort int,selector map[string]string)(Prediction,error){
 service,err:=oracle.DiagnoseWithSelector(serviceRaw,targetPort,selector)
 if err!=nil{return Prediction{},err}
 obs,err:=inspect(endpointRaw,service.Namespace,service.Service)
 if err!=nil{return Prediction{},err}
 classification:="UNKNOWN"
 if service.Classification=="UNKNOWN"&&service.CurrentTargetPort==targetPort&&reflect.DeepEqual(service.CurrentSelector,selector){
  if obs.ready>0{classification="READY_ENDPOINTS_OBSERVED"
  }else{classification="NO_READY_ENDPOINTS_OBSERVED"}
 }
 return Prediction{SchemaVersion:"sre.endpoint-observation/v1",
  Classification:classification,Service:service,EndpointSlices:snap(endpointRaw),
  ListResourceVersion:obs.version,ReadyEndpoints:obs.ready,ExpectedSelector:selector},nil
}
func phase(e Episode,p Phase)(oracle.Prediction,observation,error){
 serviceRaw,err:=checkedRaw(p.Service);if err!=nil{return oracle.Prediction{},observation{},err}
 endpointRaw,err:=checkedRaw(p.EndpointSlices);if err!=nil{return oracle.Prediction{},observation{},err}
 got,err:=oracle.DiagnoseWithSelector(serviceRaw,e.ExpectedTargetPort,e.ExpectedSelector)
 if err!=nil{return oracle.Prediction{},observation{},err}
 obs,err:=inspect(endpointRaw,e.Namespace,e.Service)
 if err!=nil{return oracle.Prediction{},observation{},err}
 if got.Namespace!=e.Namespace||got.Service!=e.Service||got.ServiceUID!=e.ServiceUID||
  got.Classification!="UNKNOWN"||!reflect.DeepEqual(got.CurrentSelector,e.ExpectedSelector)||
  got.CurrentTargetPort!=e.ExpectedTargetPort{
  return oracle.Prediction{},observation{},errors.New("Service drift confounds EndpointSlice-only episode")
 }
 return got,obs,nil
}
func probes(codes []int,success bool)error{
 if len(codes)<3||len(codes)>12{return errors.New("missing real HTTP probes")}
 for _,code:=range codes{
  if code<0||code>599{return errors.New("probe status invalid")}
  good:=code>=200&&code<300
  if good!=success{return fmt.Errorf("HTTP %d disagrees with recorded phase",code)}
 }
 return nil
}
// Evaluate compares the read-only prediction to independent admin-labelled
// before/during/after raw evidence. It cannot authenticate the admin or prove
// which backend defect caused empty EndpointSlices in production.
func Evaluate(e Episode,p Prediction)(Result,error){
 if e.SchemaVersion!="sre.endpoint-oracle/v1"||e.ID==""||len(e.ID)>128||
  (e.Scenario!="NO_FAULT"&&e.Scenario!="NO_READY_ENDPOINTS")||
  e.Namespace==""||e.Service==""||e.ServiceUID==""||
  e.ExpectedTargetPort<=0||len(e.ExpectedSelector)==0{
  return Result{},errors.New("invalid independent endpoint episode")
 }
 before,bs,err:=phase(e,e.Before);if err!=nil{return Result{},fmt.Errorf("before: %w",err)}
 during,ds,err:=phase(e,e.During);if err!=nil{return Result{},fmt.Errorf("during: %w",err)}
 after,as,err:=phase(e,e.After);if err!=nil{return Result{},fmt.Errorf("after: %w",err)}
 if before.ResourceVersion!=during.ResourceVersion||before.ResourceVersion!=after.ResourceVersion{
  return Result{},errors.New("Service was modified; EndpointSlice-only attribution unsafe")
 }
 if bs.ready==0||as.ready==0{return Result{},errors.New("baseline or recovery has no ready endpoints")}
 if err:=probes(e.Before.Probes,true);err!=nil{return Result{},err}
 if err:=probes(e.After.Probes,true);err!=nil{return Result{},err}
 fault:=e.Scenario=="NO_READY_ENDPOINTS"
 if fault!=(ds.ready==0){return Result{},errors.New("injected truth inconsistent with EndpointSlice readiness")}
 if err:=probes(e.During.Probes,!fault);err!=nil{return Result{},err}
 if p.SchemaVersion!="sre.endpoint-observation/v1"||
  p.Service.ServiceUID!=e.ServiceUID||p.Service.Service!=e.Service||p.Service.Namespace!=e.Namespace||
  p.Service.ResourceVersion!=during.ResourceVersion||
  p.ReadyEndpoints!=ds.ready||p.ListResourceVersion!=ds.version||
  !reflect.DeepEqual(p.ExpectedSelector,e.ExpectedSelector){
  return Result{},errors.New("observer prediction does not match test-admin during-phase source state")
 }
 sraw,err:=checkedRaw(p.Service.Observed);if err!=nil{return Result{},err}
 eraw,err:=checkedRaw(p.EndpointSlices);if err!=nil{return Result{},err}
 replay,err:=Diagnose(sraw,eraw,e.ExpectedTargetPort,e.ExpectedSelector)
 if err!=nil{return Result{},err}
 if !reflect.DeepEqual(replay,p){return Result{},errors.New("model prediction differs from source-only replay")}
 verdict:="CORRECT_CONTROL"
 if fault{verdict="MATCHED_INJECTED_OUTAGE"}
 return Result{SchemaVersion:"sre.endpoint-evaluation/v1",EpisodeID:e.ID,Scenario:e.Scenario,
  Prediction:p.Classification,Verdict:verdict,ProductionCausalityVerified:false,
  Explanation:"Observed EndpointSlice readiness and actual HTTP probes in disposable kind. Empty endpoints are not proof of backend root cause; operator truth and source identity are not signed."},nil
}
