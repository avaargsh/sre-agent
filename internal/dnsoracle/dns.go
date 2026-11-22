// Package dnsoracle isolates name resolution from direct ClusterIP reachability
// in a disposable Kubernetes DNS experiment. Neither probes nor test-admin
// snapshots are independently authenticated or proof of production causality.
package dnsoracle

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

 "github.com/avaargsh/sre-agent/internal/oracle"
)

const maxSource=2<<20
const maxProbe=16<<10

type Probe struct {
 SchemaVersion string `json:"schema_version"`
 Host string `json:"host"`
 ServiceIP string `json:"service_ip"`
 Resolver string `json:"resolver"`
 DNSOK bool `json:"dns_ok"`
 DNSAddresses []string `json:"dns_addresses"`
 DNSError string `json:"dns_error"`
 NameHTTPStatus int `json:"name_http_status"`
 DirectHTTPStatus int `json:"direct_http_status"`
 DirectHTTPAttempts []int `json:"direct_http_attempts,omitempty"`
 DirectHTTPErrors []string `json:"direct_http_errors,omitempty"`
}
type Observation struct {
 SchemaVersion string `json:"schema_version"`
 Classification string `json:"classification"`
 Host string `json:"host"`
 ServiceIP string `json:"service_ip"`
 Observed oracle.Snapshot `json:"observed"`
}
type Episode struct {
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 Service oracle.Snapshot `json:"service"`
 HealthyPod oracle.Snapshot `json:"healthy_pod"`
 BrokenPod oracle.Snapshot `json:"broken_pod"`
 HealthyProbe oracle.Snapshot `json:"healthy_probe"`
 BrokenProbe oracle.Snapshot `json:"broken_probe"`
}
type Result struct{
 SchemaVersion string `json:"schema_version"`
 EpisodeID string `json:"episode_id"`
 GoodClassification string `json:"good_classification"`
 BadClassification string `json:"bad_classification"`
 Verdict string `json:"verdict"`
 ProductionCausalityVerified bool `json:"production_causality_verified"`
 Explanation string `json:"explanation"`
}
func snapshot(raw []byte)oracle.Snapshot{
 h:=sha256.Sum256(raw)
 return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(h[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)}
}
func decodeSnapshot(s oracle.Snapshot,limit int)([]byte,error){
 if len(s.ResponseSHA256)!=64||s.ResponseSHA256!=strings.ToLower(s.ResponseSHA256){return nil,errors.New("invalid source digest")}
 if _,err:=hex.DecodeString(s.ResponseSHA256);err!=nil{return nil,err}
 if len(s.RawResponseBase64)>base64.StdEncoding.EncodedLen(limit){return nil,errors.New("oversized source")}
 b,err:=base64.StdEncoding.Strict().DecodeString(s.RawResponseBase64)
 if err!=nil||len(b)==0||len(b)>limit{return nil,errors.New("invalid or empty source bytes")}
 h:=sha256.Sum256(b)
 if hex.EncodeToString(h[:])!=s.ResponseSHA256{return nil,errors.New("source hash mismatch")}
 return b,nil
}
// parseProbe explicitly rejects duplicate JSON keys, unknown fields, trailing
// objects and nonfinite/malformed values before deriving any diagnostic label.
func parseProbe(raw []byte)(Probe,error){
 var p Probe
 if len(raw)==0||len(raw)>maxProbe{return p,errors.New("DNS log exceeds byte budget")}
 scanner:=json.NewDecoder(bytes.NewReader(raw))
 first,err:=scanner.Token()
 if err!=nil||first!=json.Delim('{'){return p,errors.New("DNS probe must be a JSON object")}
 keys:=map[string]bool{}
 for scanner.More(){
  k,err:=scanner.Token()
  if err!=nil{return p,errors.New("invalid JSON key")}
  key,ok:=k.(string)
  if !ok||keys[key]{return p,errors.New("duplicate DNS probe JSON key")}
  keys[key]=true
  var value json.RawMessage
  if err:=scanner.Decode(&value);err!=nil{return p,errors.New("invalid DNS probe value")}
 }
 last,err:=scanner.Token()
 if err!=nil||last!=json.Delim('}'){return p,errors.New("incomplete DNS probe object")}
 var trailing any
 if !errors.Is(scanner.Decode(&trailing),io.EOF){return p,errors.New("trailing DNS probe JSON")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(&p);err!=nil{return Probe{},errors.New("invalid DNS probe schema")}
 if p.SchemaVersion!="sre.dns-probe/v1"||
  p.Host!="checkout-api.golden-demo.svc.cluster.local"||
  net.ParseIP(p.ServiceIP)==nil||p.ServiceIP==""||
  p.Resolver==""||len(p.Resolver)>4096||
  len(p.DNSAddresses)>32||len(p.DNSError)>512||
  p.NameHTTPStatus<0||p.NameHTTPStatus>599||
  p.DirectHTTPStatus<0||p.DirectHTTPStatus>599{
  return Probe{},errors.New("incomplete or out-of-scope DNS probe")
 }
 if len(p.DirectHTTPAttempts)>8||len(p.DirectHTTPErrors)>8{
  return Probe{},errors.New("oversized bounded direct-IP retry history")
 }
 if len(p.DirectHTTPAttempts)>0{
  if p.DirectHTTPAttempts[len(p.DirectHTTPAttempts)-1]!=p.DirectHTTPStatus{
   return Probe{},errors.New("direct-IP final status differs from actual retry history")
  }
  if len(p.DirectHTTPErrors)>0&&len(p.DirectHTTPErrors)!=len(p.DirectHTTPAttempts){
   return Probe{},errors.New("incomplete direct-IP per-attempt error history")
  }
  for _,code:=range p.DirectHTTPAttempts{
   if code<0||code>599{return Probe{},errors.New("invalid intermediate HTTP status")}
  }
 }
 for _,addr:=range p.DNSAddresses{
  if net.ParseIP(addr)==nil{return Probe{},errors.New("non-IP DNS result")}
 }
 return p,nil
}
// Diagnose sees only one observer-readable probe log, never the operator's
// injected Pod spec or held-out scenario label. Contradictions must abstain.
func Diagnose(raw []byte)(Observation,error){
 p,err:=parseProbe(raw)
 if err!=nil{return Observation{},err}
 classification:="UNKNOWN"
 resolvedService:=false
 for _,addr:=range p.DNSAddresses{if addr==p.ServiceIP{resolvedService=true}}
 if p.DNSOK&&resolvedService&&p.DNSError==""&&
  p.NameHTTPStatus==200&&p.DirectHTTPStatus==200{
  classification="HEALTHY_NAME_AND_IP"
 }
 if !p.DNSOK&&len(p.DNSAddresses)==0&&p.DNSError!=""&&
  p.NameHTTPStatus==0&&p.DirectHTTPStatus==200{
  classification="DNS_FAILURE_WITH_IP_REACHABLE"
 }
 return Observation{SchemaVersion:"sre.dns-observation/v1",
  Classification:classification,Host:p.Host,ServiceIP:p.ServiceIP,Observed:snapshot(raw)},nil
}
type podInfo struct{
 Metadata struct{Name string `json:"name"`;Namespace string `json:"namespace"`;UID string `json:"uid"`} `json:"metadata"`
 Status struct{Phase string `json:"phase"`} `json:"status"`
 Spec struct{
  DNSPolicy string `json:"dnsPolicy"`
  DNSConfig struct{Nameservers []string `json:"nameservers"`} `json:"dnsConfig"`
  Containers []struct{
   Name string `json:"name"`
   Env []struct{Name string `json:"name"`;Value string `json:"value"`} `json:"env"`
  } `json:"containers"`
 } `json:"spec"`
}
type serviceInfo struct{
 Metadata struct{Name string `json:"name"`;Namespace string `json:"namespace"`;UID string `json:"uid"`} `json:"metadata"`
 Spec struct{
  ClusterIP string `json:"clusterIP"`
  Ports []struct{Port int `json:"port"`} `json:"ports"`
 } `json:"spec"`
}
func validPod(raw []byte,name,host,ip string,broken bool)error{
 var p podInfo
 if err:=json.Unmarshal(raw,&p);err!=nil{return err}
 if p.Metadata.Name!=name||p.Metadata.Namespace!="golden-demo"||p.Metadata.UID==""||
  p.Status.Phase!="Succeeded"||len(p.Spec.Containers)!=1||p.Spec.Containers[0].Name!="probe"{
  return errors.New("Pod identity, single-probe container or completion differs")
 }
 expectedPolicy:="ClusterFirst"
 if broken{expectedPolicy="None"}
 if p.Spec.DNSPolicy!=expectedPolicy{return errors.New("unexpected test-admin DNS policy")}
 if broken{
  if len(p.Spec.DNSConfig.Nameservers)!=1||p.Spec.DNSConfig.Nameservers[0]!="127.0.0.1"{
   return errors.New("DNS fault not injected into isolated client")
  }
 }
 env:=map[string]string{}
 for _,v:=range p.Spec.Containers[0].Env{
  if _,ok:=env[v.Name];ok{return errors.New("duplicate Pod environment key")}
  env[v.Name]=v.Value
 }
 if env["SERVICE_IP"]!=ip||env["SERVICE_HOST"]!=host{return errors.New("probe Pod target disagrees with actual Service")}
 return nil
}
// Evaluate replays both frozen test-admin pod specs and their original logs,
// then compares two separately generated read-only observations. A fabricated
// pair of administrator and observer artifacts remains outside this trust model.
func Evaluate(e Episode,healthy,broken Observation)(Result,error){
 if e.SchemaVersion!="sre.dns-oracle/v1"||len(e.EpisodeID)==0||len(e.EpisodeID)>128{
  return Result{},errors.New("invalid operator episode contract")
 }
 svcBytes,err:=decodeSnapshot(e.Service,maxSource)
 if err!=nil{return Result{},err}
 var svc serviceInfo
 if err:=json.Unmarshal(svcBytes,&svc);err!=nil{return Result{},err}
 if svc.Metadata.Name!="checkout-api"||svc.Metadata.Namespace!="golden-demo"||
  svc.Metadata.UID==""||net.ParseIP(svc.Spec.ClusterIP)==nil||
  len(svc.Spec.Ports)!=1||svc.Spec.Ports[0].Port!=8080{
  return Result{},errors.New("operator Service evidence out of scope")
 }
 hraw,err:=decodeSnapshot(e.HealthyPod,maxSource);if err!=nil{return Result{},err}
 braw,err:=decodeSnapshot(e.BrokenPod,maxSource);if err!=nil{return Result{},err}
 host:="checkout-api.golden-demo.svc.cluster.local"
 if err:=validPod(hraw,"dns-good",host,svc.Spec.ClusterIP,false);err!=nil{return Result{},fmt.Errorf("healthy Pod invalid: %w",err)}
 if err:=validPod(braw,"dns-bad",host,svc.Spec.ClusterIP,true);err!=nil{return Result{},fmt.Errorf("fault Pod invalid: %w",err)}
 hlog,err:=decodeSnapshot(e.HealthyProbe,maxProbe);if err!=nil{return Result{},err}
 blog,err:=decodeSnapshot(e.BrokenProbe,maxProbe);if err!=nil{return Result{},err}
 h,err:=Diagnose(hlog);if err!=nil{return Result{},err}
 b,err:=Diagnose(blog);if err!=nil{return Result{},err}
 if h.ServiceIP!=svc.Spec.ClusterIP||b.ServiceIP!=svc.Spec.ClusterIP||
  h.Host!=host||b.Host!=host{return Result{},errors.New("raw probe does not target independent Service source")}
 hobs,err:=decodeSnapshot(healthy.Observed,maxProbe);if err!=nil{return Result{},err}
 bobs,err:=decodeSnapshot(broken.Observed,maxProbe);if err!=nil{return Result{},err}
 rh,err:=Diagnose(hobs);if err!=nil{return Result{},err}
 rb,err:=Diagnose(bobs);if err!=nil{return Result{},err}
 if !reflect.DeepEqual(h,rh)||!reflect.DeepEqual(b,rb)||
  !reflect.DeepEqual(h,healthy)||!reflect.DeepEqual(b,broken){
  return Result{},errors.New("observer and admin source bytes or classifications disagree")
 }
 goodProbe,_:=parseProbe(hlog)
 badProbe,_:=parseProbe(blog)
 if !strings.Contains(goodProbe.Resolver,"nameserver ")||
  strings.Contains(goodProbe.Resolver,"nameserver 127.0.0.1")||
  !strings.Contains(badProbe.Resolver,"nameserver 127.0.0.1"){
  return Result{},errors.New("in-pod /etc/resolv.conf contradicts admin DNS injection")
 }
 if h.Classification!="HEALTHY_NAME_AND_IP"||b.Classification!="DNS_FAILURE_WITH_IP_REACHABLE"{
  return Result{},errors.New("not enough independent evidence to classify an isolated DNS fault")
 }
 return Result{SchemaVersion:"sre.dns-evaluation/v1",EpisodeID:e.EpisodeID,
  GoodClassification:h.Classification,BadClassification:b.Classification,
  Verdict:"MATCHED_ISOLATED_DNS_FAULT",ProductionCausalityVerified:false,
  Explanation:"One isolated client DNS policy misconfiguration and one healthy control. Observed name-resolution failure with direct Service IP still reachable; not signed, not an LLM result or production root cause."},nil
}
