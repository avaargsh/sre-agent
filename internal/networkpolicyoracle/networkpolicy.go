// Package networkpolicyoracle checks a narrow, admin-injected Kubernetes
// NetworkPolicy deny/restore experiment. Policy labels and SHA digests in this
// evaluator are test evidence only, NOT proof of authenticated production RCA.
package networkpolicyoracle

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "reflect"
 "strings"

 "github.com/avaargsh/sre-agent/internal/dnsoracle"
 "github.com/avaargsh/sre-agent/internal/oracle"
)
const maxBytes=2<<20
type Phase struct{
 Pod oracle.Snapshot `json:"pod"`
 Probe oracle.Snapshot `json:"probe"`
 Service oracle.Snapshot `json:"service"`
 EndpointSlices oracle.Snapshot `json:"endpoint_slices"`
 PolicyList oracle.Snapshot `json:"network_policy_list"`
}
type Episode struct{
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Before Phase `json:"before"`
 During Phase `json:"during"`
 After Phase `json:"after"`
}
type Result struct{
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Status string `json:"status"`
 BeforeDiagnostic string `json:"before_diagnostic"`
 DuringDiagnostic string `json:"during_diagnostic"`
 AfterDiagnostic string `json:"after_diagnostic"`
 ProductionCausalityVerified bool `json:"production_causality_verified"`
 Explanation string `json:"explanation"`
}
func rawSource(s oracle.Snapshot)([]byte,error){
 if len(s.ResponseSHA256)!=64||s.ResponseSHA256!=strings.ToLower(s.ResponseSHA256){return nil,errors.New("invalid SHA-256 spelling")}
 if _,err:=hex.DecodeString(s.ResponseSHA256);err!=nil{return nil,err}
 if len(s.RawResponseBase64)>base64.StdEncoding.EncodedLen(maxBytes){return nil,errors.New("source exceeds budget")}
 raw,err:=base64.StdEncoding.Strict().DecodeString(s.RawResponseBase64)
 if err!=nil||len(raw)==0||len(raw)>maxBytes{return nil,errors.New("invalid source length/base64")}
 sum:=sha256.Sum256(raw)
 if hex.EncodeToString(sum[:])!=s.ResponseSHA256{return nil,errors.New("source digest disagrees with raw bytes")}
 return raw,nil
}
func decode(s oracle.Snapshot,output any)error{
 raw,err:=rawSource(s);if err!=nil{return err}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 if err:=dec.Decode(output);err!=nil{return err}
 var extra any
 if !errors.Is(dec.Decode(&extra),io.EOF){return errors.New("trailing source JSON")}
 return nil
}
type meta struct{
 UID string `json:"uid"`
 Name string `json:"name"`
 Namespace string `json:"namespace"`
 ResourceVersion string `json:"resourceVersion"`
 Labels map[string]string `json:"labels"`
}
type service struct{
 Kind string `json:"kind"`
 Metadata meta `json:"metadata"`
 Spec struct{
  ClusterIP string `json:"clusterIP"`
  Selector map[string]string `json:"selector"`
  Ports []struct{Port int `json:"port"`;TargetPort int `json:"targetPort"`} `json:"ports"`
 } `json:"spec"`
}
type endpointSliceList struct{
 Kind string `json:"kind"`
 Metadata struct{ResourceVersion string `json:"resourceVersion"`;Continue string `json:"continue"`} `json:"metadata"`
 Items []struct{
  Metadata meta `json:"metadata"`
  Endpoints []struct{
   Addresses []string `json:"addresses"`
   Conditions struct{Ready *bool `json:"ready"`} `json:"conditions"`
  } `json:"endpoints"`
 } `json:"items"`
}
type networkPolicyList struct{
 Kind string `json:"kind"`
 Metadata struct{ResourceVersion string `json:"resourceVersion"`;Continue string `json:"continue"`} `json:"metadata"`
 Items []struct{
  Metadata meta `json:"metadata"`
  Spec struct{
   PodSelector struct{MatchLabels map[string]string `json:"matchLabels"`} `json:"podSelector"`
   PolicyTypes []string `json:"policyTypes"`
   Egress []struct{Ports []struct{Protocol string `json:"protocol"`;Port int `json:"port"`} `json:"ports"`} `json:"egress"`
  } `json:"spec"`
 } `json:"items"`
}
type pod struct{
 Metadata meta `json:"metadata"`
 Status struct{Phase string `json:"phase"`} `json:"status"`
 Spec struct{
  AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
  DNSPolicy string `json:"dnsPolicy"`
  Containers []struct{Name string `json:"name"`;Env []struct{Name string `json:"name"`;Value string `json:"value"`} `json:"env"`} `json:"containers"`
 } `json:"spec"`
}
type evidence struct{service service;ready int;policyPresent bool;probe dnsoracle.Probe;observation dnsoracle.Observation;podUID string}
func inspect(e Phase,phase string,obs dnsoracle.Observation)(evidence,error){
 var result evidence
 if err:=decode(e.Service,&result.service);err!=nil{return result,fmt.Errorf("Service source: %w",err)}
 svc:=result.service
 if svc.Kind!="Service"||svc.Metadata.Name!="checkout-api"||
 svc.Metadata.Namespace!="golden-demo"||svc.Metadata.UID==""||svc.Metadata.ResourceVersion==""||
 net.ParseIP(svc.Spec.ClusterIP)==nil||len(svc.Spec.Ports)!=1||
 svc.Spec.Ports[0].Port!=8080||svc.Spec.Ports[0].TargetPort!=8080||
 !reflect.DeepEqual(svc.Spec.Selector,map[string]string{"app":"checkout-api"}){
  return result,errors.New("Service identity, selector or targetPort differs from healthy baseline")
 }
 var eps endpointSliceList
 if err:=decode(e.EndpointSlices,&eps);err!=nil{return result,fmt.Errorf("EndpointSlice source: %w",err)}
 if eps.Kind!="EndpointSliceList"||eps.Metadata.ResourceVersion==""||eps.Metadata.Continue!=""||
 len(eps.Items)>128{return result,errors.New("incomplete or unbounded EndpointSlice list")}
 seen:=map[string]bool{}
 for _,item:=range eps.Items{
  m:=item.Metadata
  if m.Namespace!="golden-demo"||m.UID==""||seen[m.UID]||
   m.Labels["kubernetes.io/service-name"]!="checkout-api"{
   return result,errors.New("EndpointSlice identity or association invalid")
  }
  seen[m.UID]=true
  if len(item.Endpoints)>256{return result,errors.New("EndpointSlice item too large")}
  for _,ep:=range item.Endpoints{
   if ep.Conditions.Ready==nil||len(ep.Addresses)==0{return result,errors.New("ambiguous EndpointSlice ready state")}
   if *ep.Conditions.Ready{result.ready++}
  }
 }
 if result.ready==0{return result,errors.New("no Ready Endpoint; network policy attribution is confounded")}
 var policies networkPolicyList
 if err:=decode(e.PolicyList,&policies);err!=nil{return result,fmt.Errorf("NetworkPolicy source: %w",err)}
 if policies.Kind!="NetworkPolicyList"||policies.Metadata.ResourceVersion==""||policies.Metadata.Continue!=""||len(policies.Items)>1{
  return result,errors.New("NetworkPolicy collection incomplete or competing policies")
 }
 if len(policies.Items)==1{
  p:=policies.Items[0]
  if p.Metadata.Namespace!="golden-demo"||p.Metadata.Name!="sre-g2i-deny-http"||p.Metadata.UID==""||
   !reflect.DeepEqual(p.Spec.PodSelector.MatchLabels,map[string]string{"app":"sre-np-probe"})||
   len(p.Spec.PolicyTypes)!=1||p.Spec.PolicyTypes[0]!="Egress"||len(p.Spec.Egress)!=1||
   len(p.Spec.Egress[0].Ports)!=2{
   return result,errors.New("unexpected/unsafe NetworkPolicy scope or ingress/egress rule")
  }
  ports:=map[string]bool{}
  for _,port:=range p.Spec.Egress[0].Ports{ports[fmt.Sprintf("%s/%d",port.Protocol,port.Port)]=true}
  if len(ports)!=2||!ports["UDP/53"]||!ports["TCP/53"]{
   return result,errors.New("policy does not restrict egress to DNS-only port 53")
  }
  result.policyPresent=true
 }
 var client pod
 if err:=decode(e.Pod,&client);err!=nil{return result,fmt.Errorf("probe Pod source: %w",err)}
 if client.Metadata.Namespace!="golden-demo"||client.Metadata.Name!="np-"+phase||
  client.Metadata.UID==""||client.Metadata.Labels["app"]!="sre-np-probe"||
  client.Status.Phase!="Succeeded"||client.Spec.AutomountServiceAccountToken==nil||
  *client.Spec.AutomountServiceAccountToken||client.Spec.DNSPolicy!="ClusterFirst"||
  len(client.Spec.Containers)!=1||client.Spec.Containers[0].Name!="probe"{
  return result,errors.New("Pod identity, isolation, completion, or DNS baseline invalid")
 }
 result.podUID=client.Metadata.UID
 env:=map[string]string{}
 for _,v:=range client.Spec.Containers[0].Env{
  if _,ok:=env[v.Name];ok{return result,errors.New("duplicated Pod env")}
  env[v.Name]=v.Value
 }
 if env["SERVICE_IP"]!=svc.Spec.ClusterIP||env["SERVICE_HOST"]!="checkout-api.golden-demo.svc.cluster.local"||
  env["PROBE_PHASE"]!=phase{return result,errors.New("client environment not tied to Service/phase")}
 raw,err:=rawSource(e.Probe);if err!=nil{return result,err}
 if err:=json.Unmarshal(raw,&result.probe);err!=nil{return result,err}
 replay,err:=dnsoracle.Diagnose(raw);if err!=nil{return result,err}
 if !reflect.DeepEqual(replay,obs){return result,errors.New("observer classification or raw bytes differ from source replay")}
 result.observation=replay
 p:=result.probe
 if p.ServiceIP!=svc.Spec.ClusterIP||p.Host!=env["SERVICE_HOST"]||!p.DNSOK||p.DNSError!=""||
  !strings.Contains(p.Resolver,"nameserver ")||len(p.DNSAddresses)==0||
  p.NameHTTPStatus<0||p.DirectHTTPStatus<0{
  return result,errors.New("DNS failed or probe target differed; cannot attribute transport outage to policy")
 }
 hasIP:=false
 for _,ip:=range p.DNSAddresses{if ip==svc.Spec.ClusterIP{hasIP=true}}
 if !hasIP{return result,errors.New("DNS did not resolve to current Service IP")}
 if len(p.DirectHTTPAttempts)<3||len(p.DirectHTTPAttempts)>8{
  return result,errors.New("insufficient bounded direct-IP dataplane probe attempts")
 }
 for _,code:=range p.DirectHTTPAttempts{
  want:=200
  if phase=="during"{want=0}
  if code!=want{return result,errors.New("unstable or contradictory direct-IP dataplane observation")}
 }
 if phase=="during"{
  if p.NameHTTPStatus!=0||p.DirectHTTPStatus!=0||obs.Classification!="UNKNOWN"||
   !result.policyPresent{return result,errors.New("not an independently isolated policy-denied transport phase")}
 }else{
  if p.NameHTTPStatus!=200||p.DirectHTTPStatus!=200||
   obs.Classification!="HEALTHY_NAME_AND_IP"||result.policyPresent{
   return result,errors.New("baseline or restoration not shown with healthy DNS + two HTTP paths")
  }
 }
 return result,nil
}
// Evaluate compares original test-admin policy/Service/EndpointSlice/Pod/log
// witnesses to separately captured read-only log diagnoses. It is intentionally
// an isolated kind lab check, not a source-signed causal production RCA.
func Evaluate(e Episode,obs [3]dnsoracle.Observation)(Result,error){
 if e.SchemaVersion!="sre.networkpolicy-oracle/v1"||len(e.EpisodeID)==0||len(e.EpisodeID)>128{
  return Result{},errors.New("invalid test-admin episode identity")
 }
 phases:=[]Phase{e.Before,e.During,e.After}
 names:=[]string{"before","during","after"}
 evidenceList:=make([]evidence,0,3)
 for i,phase:=range phases{
  item,err:=inspect(phase,names[i],obs[i])
  if err!=nil{return Result{},fmt.Errorf("%s phase: %w",names[i],err)}
  evidenceList=append(evidenceList,item)
 }
 baseline:=evidenceList[0]
 for i,item:=range evidenceList{
  if item.service.Metadata.UID!=baseline.service.Metadata.UID||
   item.service.Metadata.ResourceVersion!=baseline.service.Metadata.ResourceVersion||
   item.service.Spec.ClusterIP!=baseline.service.Spec.ClusterIP||
   item.podUID==""{
   return Result{},fmt.Errorf("Service changed or phase %d lacks separate probe Pod",i)
  }
 }
 if evidenceList[0].podUID==evidenceList[1].podUID||
  evidenceList[1].podUID==evidenceList[2].podUID||
  evidenceList[0].podUID==evidenceList[2].podUID{
  return Result{},errors.New("probe phases must be distinct individual Pods")
 }
 return Result{SchemaVersion:"sre.networkpolicy-evaluation/v1",EpisodeID:e.EpisodeID,
  Status:"MATCHED_LAB_NETWORK_POLICY_DENIAL",
  BeforeDiagnostic:obs[0].Classification,
  DuringDiagnostic:obs[1].Classification,
  AfterDiagnostic:obs[2].Classification,
  ProductionCausalityVerified:false,
  Explanation:"CNI-enforced lab policy observed by a test administrator. DNS and Ready Endpoints stayed healthy while client TCP failed. This is not authenticated source provenance or root cause of a production incident."},nil
}
