// Package observe collects a bounded, read-only Kubernetes/Prometheus snapshot.
// It does not authorize remediation or verify operational recovery.
package observe

import (
  "bytes"
  "context"
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "math"
  "net"
  "net/http"
  "net/url"
  "regexp"
  "sort"
  "strconv"
  "strings"
  "time"
  "github.com/avaargsh/sre-agent/internal/evidence"
  "github.com/avaargsh/sre-agent/internal/metricseries"
)

var ErrUnknown = errors.New("observation UNKNOWN")
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var labelName = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
// Kubernetes label keys allow an optional DNS-subdomain prefix followed by '/'.
// Validate the selector grammar before building a query, rather than rejecting
// legitimate qualified keys or accepting selector control characters.
func selectorLabelOK(key, value string) bool {
 if len(key)==0 || len(key)>317 || len(value)>63 {return false}
 if strings.Count(key,"/")>1 {return false}
 name:=key
 if prefix,suffix,ok:=strings.Cut(key,"/");ok {
  if len(prefix)==0 || len(prefix)>253 {return false}
  for _,component:=range strings.Split(prefix,".") {
   if len(component)==0 || len(component)>63 || !dnsLabel.MatchString(component) {return false}
  }
  name=suffix
 }
 if len(name)==0 || len(name)>63 || !labelName.MatchString(name) {return false}
 return value=="" || labelName.MatchString(value)
}

const maxResponseBytes = 2 << 20
const maxPods = 100
const maxSeries = 32

type Config struct {
 KubernetesURL, PrometheusURL string
 Namespace, Deployment string
 IncidentID, Summary, Severity string
 LatencyQuery string
 KubernetesBearerToken string
 MaxMetricAge time.Duration
 Now func() time.Time
 Client *http.Client
}

type metadata struct {
 UID string `json:"uid"`
 Name string `json:"name"`
 Namespace string `json:"namespace"`
 ResourceVersion string `json:"resourceVersion"`
 Generation int64 `json:"generation"`
}
type deployment struct {
 Metadata metadata `json:"metadata"`
 Spec struct {
  Replicas *int `json:"replicas"`
  Selector struct{
  MatchLabels map[string]string `json:"matchLabels"`
  MatchExpressions []json.RawMessage `json:"matchExpressions"`
 } `json:"selector"`
 } `json:"spec"`
 Status struct{ReadyReplicas int `json:"readyReplicas"`; ObservedGeneration int64 `json:"observedGeneration"`} `json:"status"`
}
type podList struct {
 Metadata struct{
  ResourceVersion string `json:"resourceVersion"`
  Continue string `json:"continue"`
 } `json:"metadata"`
 Items []struct{
  Metadata metadata `json:"metadata"`
  Status struct{Phase string `json:"phase"`} `json:"status"`
 } `json:"items"`
}
type promResult struct {
 Status string `json:"status"`
 Warnings []string `json:"warnings"`
 Data struct {
  ResultType string `json:"resultType"`
  Result []struct{
    Metric map[string]string `json:"metric"`
    Value []json.RawMessage `json:"value"`
  } `json:"result"`
 } `json:"data"`
}

func unknownf(format string, args ...any) error {return fmt.Errorf("%w: %s",ErrUnknown,fmt.Sprintf(format,args...))}
func endpoint(s string)(*url.URL,error) {
 u,err:=url.Parse(s)
 if err!=nil||u==nil||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||(u.Path!=""&&u.Path!="/") {return nil,unknownf("invalid source endpoint")}
 if u.Scheme!="https"&&u.Scheme!="http" {return nil,unknownf("source must use HTTP(S)")}
 if u.Scheme=="http"{
   host:=u.Hostname()
   ip:=net.ParseIP(host)
   if host!="localhost"&&(ip==nil||!ip.IsLoopback()){return nil,unknownf("plaintext HTTP is restricted to localhost")}
 }
 return u,nil
}
func nameOK(s string)bool{return len(s)>0&&len(s)<=63&&dnsLabel.MatchString(s)}
func validate(c Config)(*url.URL,*url.URL,error){
 if !nameOK(c.Namespace)||!nameOK(c.Deployment){return nil,nil,unknownf("invalid namespace/deployment selector")}
 if strings.TrimSpace(c.IncidentID)==""||strings.TrimSpace(c.Summary)==""||strings.TrimSpace(c.Severity)==""{return nil,nil,unknownf("incident identity, summary and severity are required")}
 if c.MaxMetricAge<0||c.MaxMetricAge>10*time.Minute{return nil,nil,unknownf("unsupported metric freshness budget")}
 k,err:=endpoint(c.KubernetesURL);if err!=nil{return nil,nil,err}
 p,err:=endpoint(c.PrometheusURL);if err!=nil{return nil,nil,err}
 return k,p,nil
}
// Caller-supplied HTTP clients may keep their custom transport/TLS settings,
// but may not disable the collector's bounded, read-only source deadline.
const maxSourceReadTimeout = 30 * time.Second

func client(c Config)*http.Client{
 var copied http.Client
 if c.Client!=nil{copied=*c.Client}else{copied=http.Client{Timeout:10*time.Second}}
 if copied.Timeout<=0{copied.Timeout=10*time.Second}
 if copied.Timeout>maxSourceReadTimeout{copied.Timeout=maxSourceReadTimeout}
 // Never follow HTTP redirects; the source authority must stay fixed.
 copied.CheckRedirect=func(req *http.Request,via []*http.Request)error{return http.ErrUseLastResponse}
 return &copied
}
func getRawJSON(ctx context.Context,hc *http.Client,endpoint *url.URL,path,token string)([]byte,error){
 u:=*endpoint
 parsed,err:=url.Parse(path)
 if err!=nil||!strings.HasPrefix(parsed.Path,"/"){return nil,unknownf("invalid read path")}
 u.Path=parsed.Path
 u.RawQuery=parsed.RawQuery
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,u.String(),nil)
 if err!=nil{return nil,unknownf("invalid read request")}
 req.Header.Set("Accept","application/json")
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 res,err:=hc.Do(req)
 if err!=nil{return nil,unknownf("read request failed: %T",err)}
 defer res.Body.Close()
 if res.StatusCode!=http.StatusOK{return nil,unknownf("source response status %d",res.StatusCode)}
 payload,err:=io.ReadAll(io.LimitReader(res.Body,maxResponseBytes+1))
 if err!=nil||len(payload)>maxResponseBytes{return nil,unknownf("source response failed or exceeded limit")}
 if err:=validateSourceJSON(payload);err!=nil{return nil,unknownf("invalid native source JSON")}
 return payload,nil
}
func getJSON(ctx context.Context,hc *http.Client,endpoint *url.URL,path,token string,out any)error{
 payload,err:=getRawJSON(ctx,hc,endpoint,path,token)
 if err!=nil{return err}
 decoder:=json.NewDecoder(bytes.NewReader(payload))
 if err:=decoder.Decode(out);err!=nil{return unknownf("malformed source JSON")}
 var extra any
 if !errors.Is(decoder.Decode(&extra),io.EOF){return unknownf("trailing source JSON")}
 return nil
}
func evidenceItem(id,source,observation,when string,attrs map[string]string)map[string]any{
 return map[string]any{"evidence_id":id,"source":source,"observation":observation,"timestamp":when,"attributes":attrs,"entity_refs":[]string{}}
}
func stableID(source string,data any)string{
 b,_:=json.Marshal(data)
 hash:=sha256.Sum256(append([]byte(source+":"),b...))
 return "obs-"+hex.EncodeToString(hash[:12])
}
func readKubernetes(ctx context.Context,hc *http.Client,u *url.URL,c Config,when string)(map[string]any,error){
 var d deployment
 path:="/apis/apps/v1/namespaces/"+c.Namespace+"/deployments/"+c.Deployment
 if err:=getJSON(ctx,hc,u,path,c.KubernetesBearerToken,&d);err!=nil{return nil,err}
 if d.Metadata.Name!=c.Deployment||d.Metadata.Namespace!=c.Namespace||d.Metadata.UID==""||d.Metadata.ResourceVersion==""||d.Spec.Replicas==nil||len(d.Spec.Selector.MatchLabels)==0||len(d.Spec.Selector.MatchExpressions)>0{return nil,unknownf("deployment identity or selector missing")}
 if err:=validateDeploymentCounters(d.Metadata.Generation,d.Status.ObservedGeneration,*d.Spec.Replicas,d.Status.ReadyReplicas);err!=nil{return nil,unknownf("invalid Deployment counters: %v",err)}
 selectors:=make([]string,0,len(d.Spec.Selector.MatchLabels))
 for key,val:=range d.Spec.Selector.MatchLabels{
  if !selectorLabelOK(key,val){return nil,unknownf("unsafe deployment label selector")}
  selectors=append(selectors,key+"="+val)
 }
 sort.Strings(selectors)
 listPath:="/api/v1/namespaces/"+c.Namespace+"/pods?labelSelector="+url.QueryEscape(strings.Join(selectors,","))
 var pods podList
 if err:=getJSON(ctx,hc,u,listPath,c.KubernetesBearerToken,&pods);err!=nil{return nil,err}
 if pods.Metadata.ResourceVersion==""||pods.Metadata.Continue!=""||pods.Items==nil||len(pods.Items)>maxPods{return nil,unknownf("incomplete pod-list items, missing resourceVersion, pagination, or too many pods")}
 projected:=make([]map[string]string,0,len(pods.Items))
 for _,pod:=range pods.Items{
  if pod.Metadata.UID==""||pod.Metadata.Namespace!=c.Namespace||pod.Metadata.Name==""{return nil,unknownf("invalid pod identity")}
  projected=append(projected,map[string]string{"uid":pod.Metadata.UID,"name":pod.Metadata.Name,"phase":pod.Status.Phase})
 }
 if err:=validatePodProjection(projected);err!=nil{return nil,unknownf("invalid Pod snapshot: %v",err)}
 b,_:=json.Marshal(projected)
 attrs:=map[string]string{
 "namespace":c.Namespace,"deployment":c.Deployment,"uid":d.Metadata.UID,"resource_version":d.Metadata.ResourceVersion,
 "generation":strconv.FormatInt(d.Metadata.Generation,10),"observed_generation":strconv.FormatInt(d.Status.ObservedGeneration,10),
 "desired_replicas":strconv.Itoa(*d.Spec.Replicas),"ready_replicas":strconv.Itoa(d.Status.ReadyReplicas),
 "pods_json":string(b),"pod_list_resource_version":pods.Metadata.ResourceVersion,"observed_at":when,
 }
 return evidenceItem(stableID("kubernetes",attrs),"kubernetes",fmt.Sprintf("deployment %s/%s desired=%d ready=%d",c.Namespace,c.Deployment,*d.Spec.Replicas,d.Status.ReadyReplicas),when,attrs),nil
}
func readPrometheus(ctx context.Context,hc *http.Client,u *url.URL,c Config,now time.Time,when string)(map[string]any,error){
 query:=c.LatencyQuery
 if query==""{query="max(checkout_request_latency_seconds)"}
 if len(query)>512{return nil,unknownf("query exceeds length limit")}
 var p promResult
 path:="/api/v1/query?query="+url.QueryEscape(query)
 if err:=getJSON(ctx,hc,u,path,"",&p);err!=nil{return nil,err}
 if p.Status!="success"||p.Data.ResultType!="vector"||len(p.Data.Result)==0||len(p.Data.Result)>maxSeries{return nil,unknownf("missing or invalid Prometheus instant-vector result")}
 if len(p.Warnings)>0{return nil,unknownf("Prometheus query returned warnings; cannot assert complete observation")}
 maxAge:=c.MaxMetricAge
 if maxAge==0{maxAge=90*time.Second}
 samples:=make([]map[string]any,0,len(p.Data.Result))
 labelsets:=make([]map[string]string,0,len(p.Data.Result))
 for i,series:=range p.Data.Result{
  if len(series.Value)!=2{return nil,unknownf("series %d missing sample",i)}
  var timestamp float64
  var value string
  if err:=json.Unmarshal(series.Value[0],&timestamp);err!=nil||!metricseries.ValidTimestamp(timestamp){return nil,unknownf("series %d invalid or non-replayable timestamp",i)}
  if err:=json.Unmarshal(series.Value[1],&value);err!=nil{return nil,unknownf("series %d invalid value encoding",i)}
  number,err:=strconv.ParseFloat(value,64)
  if err!=nil||math.IsNaN(number)||math.IsInf(number,0){return nil,unknownf("series %d non-finite value",i)}
  sampleAt:=time.Unix(0,int64(timestamp*float64(time.Second)))
  if now.Sub(sampleAt)>maxAge||sampleAt.Sub(now)>5*time.Second{return nil,unknownf("series %d stale or future-dated",i)}
  labelsets=append(labelsets,series.Metric)
  samples=append(samples,map[string]any{"metric":series.Metric,"timestamp":timestamp,"value":value})
 }
 if err:=metricseries.Unique(labelsets);err!=nil{return nil,unknownf("invalid Prometheus instant-vector labelset: %v",err)}
 b,_:=json.Marshal(samples)
 attrs:=map[string]string{"promql":query,"samples_json":string(b),"result_type":"vector","series_count":strconv.Itoa(len(samples)),
  "observed_at":when,"max_age_seconds":strconv.FormatFloat(maxAge.Seconds(),'f',-1,64)}
 return evidenceItem(stableID("prometheus",attrs),"prometheus",fmt.Sprintf("PromQL %s: %d fresh finite series",query,len(samples)),when,attrs),nil
}
// Collect gathers observation facts, never marks a hypothesis SUPPORTED or the
// incident RECOVERED. On any incomplete read it returns UNKNOWN and no bundle.
func Collect(ctx context.Context,c Config)([]byte,error){
 k,p,err:=validate(c);if err!=nil{return nil,err}
 now:=time.Now().UTC()
 if c.Now!=nil{now=c.Now().UTC()}
 when:=now.Format(time.RFC3339Nano)
 hc:=client(c)
 kubernetesEvidence,err:=readKubernetes(ctx,hc,k,c,when);if err!=nil{return nil,err}
 prometheusEvidence,err:=readPrometheus(ctx,hc,p,c,now,when);if err!=nil{return nil,err}
 payload:=map[string]any{
  "incident":map[string]any{"incident_id":c.IncidentID,"summary":c.Summary,"severity":c.Severity,"scope":"namespace="+c.Namespace+",deployment="+c.Deployment},
  "evidence":[]any{kubernetesEvidence,prometheusEvidence},
  "hypotheses":[]any{},"entities":[]any{},"edges":[]any{},"changes":[]any{},
  "metadata":map[string]any{"schema_version":"aiops.evidence/v1","observation_status":"complete","observed_at":when,"tool_count":2,"evidence_count":2},
 }
 serialized,err:=json.Marshal(payload)
 if err!=nil{return nil,unknownf("failed to encode bundle")}
 result,err:=evidence.Verify(serialized)
 if err!=nil{return nil,unknownf("evidence validation: %v",err)}
 payload["metadata"].(map[string]any)["bundle_sha256"]=result.BundleSHA256
 serialized,err=json.MarshalIndent(payload,"","  ")
 if err!=nil{return nil,unknownf("failed to encode frozen bundle")}
 if _,err=evidence.Verify(serialized);err!=nil{return nil,unknownf("final bundle validation: %v",err)}
 return serialized,nil
}
