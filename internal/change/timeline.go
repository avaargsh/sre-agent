// Package change collects a bounded, read-only Kubernetes rollout timeline.
// A temporal relationship never proves a causal RCA claim.
package change

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "regexp"
 "sort"
 "strconv"
 "strings"
 "time"
 "github.com/avaargsh/sre-agent/internal/evidence"
)

var ErrUnknown=errors.New("change evidence UNKNOWN")
var label=regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
const maxPayload=2<<20
const maxReplicaSets=128

type Config struct{
 APIURL,Namespace,Deployment,Token string
 WindowStart,WindowEnd time.Time
 Now func()time.Time
 Client *http.Client
}
type Source struct {
 Endpoint string `json:"endpoint"`
 ResponseSHA256 string `json:"response_sha256"`
 RawResponseBase64 string `json:"raw_response_base64"`
}
type Revision struct{
 UID string `json:"uid"`
 Name string `json:"name"`
 Revision string `json:"revision"`
 CreatedAt time.Time `json:"created_at"`
 ResourceVersion string `json:"resource_version"`
 Replicas int `json:"replicas"`
}
type Report struct{
 SchemaVersion string `json:"schema_version"`
 Status string `json:"status"`
 Relationship string `json:"relationship"`
 Explanation string `json:"explanation"`
 Namespace string `json:"namespace"`
 Deployment string `json:"deployment"`
 DeploymentUID string `json:"deployment_uid"`
 Generation int64 `json:"generation"`
 ResourceVersion string `json:"resource_version"`
 CollectedAt time.Time `json:"collected_at"`
 WindowStart time.Time `json:"window_start"`
 WindowEnd time.Time `json:"window_end"`
 Revisions []Revision `json:"revisions"`
 Sources []Source `json:"sources"`
}
type meta struct{
 Name string `json:"name"`
 Namespace string `json:"namespace"`
 UID string `json:"uid"`
 ResourceVersion string `json:"resourceVersion"`
 Generation int64 `json:"generation"`
 CreationTimestamp string `json:"creationTimestamp"`
 Annotations map[string]string `json:"annotations"`
 OwnerReferences []struct{UID string `json:"uid"`;Kind string `json:"kind"`;Controller *bool `json:"controller"`} `json:"ownerReferences"`
}
type deployment struct{
 Metadata meta `json:"metadata"`
 Status struct{ObservedGeneration int64 `json:"observedGeneration"`} `json:"status"`
}
type replicaSetList struct{
 Metadata struct{ResourceVersion string `json:"resourceVersion"`;Continue string `json:"continue"`} `json:"metadata"`
 Items []struct{Metadata meta `json:"metadata"`;Spec struct{Replicas *int `json:"replicas"`} `json:"spec"`} `json:"items"`
}
func unknown(format string, args ...any)error{return fmt.Errorf("%w: %s",ErrUnknown,fmt.Sprintf(format,args...))}
func safeEndpoint(c Config)(*url.URL,time.Time,error){
 if c.Now==nil{c.Now=time.Now}
 now:=c.Now().UTC()
 if len(c.Namespace)>63||len(c.Deployment)>63||!label.MatchString(c.Namespace)||!label.MatchString(c.Deployment){return nil,now,unknown("invalid resource scope")}
 if c.WindowStart.IsZero()||c.WindowEnd.IsZero()||!c.WindowStart.Before(c.WindowEnd)||c.WindowEnd.After(now.Add(5*time.Second))||c.WindowEnd.Sub(c.WindowStart)>24*time.Hour{return nil,now,unknown("invalid or overly broad change window")}
 u,err:=url.Parse(c.APIURL)
 if err!=nil||u==nil||u.Host==""||u.User!=nil||u.Fragment!=""||u.RawQuery!=""||(u.Path!=""&&u.Path!="/"){return nil,now,unknown("invalid Kubernetes endpoint")}
 if u.Scheme!="https"&&u.Scheme!="http"{return nil,now,unknown("invalid Kubernetes transport")}
 if u.Scheme=="http"{
  ip:=net.ParseIP(u.Hostname())
  if u.Hostname()!="localhost"&&(ip==nil||!ip.IsLoopback()){return nil,now,unknown("non-local HTTP is denied")}
 }
 return u,now,nil
}
func get(ctx context.Context,hc *http.Client,u *url.URL,path,token string,out any)(Source,error){
 endpoint:=*u
 parsed,err:=url.Parse(path)
 if err!=nil||!strings.HasPrefix(parsed.Path,"/"){return Source{},unknown("invalid API path")}
 endpoint.Path=parsed.Path
 endpoint.RawQuery=parsed.RawQuery
 request,err:=http.NewRequestWithContext(ctx,http.MethodGet,endpoint.String(),nil)
 if err!=nil{return Source{},unknown("cannot build request")}
 request.Header.Set("Accept","application/json")
 if token!=""{request.Header.Set("Authorization","Bearer "+token)}
 response,err:=hc.Do(request)
 if err!=nil{return Source{},unknown("Kubernetes transport error: %T",err)}
 defer response.Body.Close()
 if response.StatusCode!=200{return Source{},unknown("Kubernetes HTTP status %d",response.StatusCode)}
 raw,err:=io.ReadAll(io.LimitReader(response.Body,maxPayload+1))
 if err!=nil||len(raw)>maxPayload{return Source{},unknown("Kubernetes response too large or unreadable")}
 if err:=evidence.ValidateUniqueJSONObject(raw);err!=nil{return Source{},unknown("Kubernetes source contains ambiguous JSON keys")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 if err:=dec.Decode(out);err!=nil{return Source{},unknown("Kubernetes returned invalid JSON")}
 var extra any
 if !errors.Is(dec.Decode(&extra),io.EOF){return Source{},unknown("Kubernetes returned trailing JSON")}
 digest:=sha256.Sum256(raw)
 return Source{Endpoint:parsed.Path,ResponseSHA256:hex.EncodeToString(digest[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw)},nil
}
func hasOwner(m meta,depUID string)bool{
 for _,o:=range m.OwnerReferences{
  if o.UID==depUID&&o.Kind=="Deployment"&&o.Controller!=nil&&*o.Controller{return true}
 }
 return false
}
func stableDeployment(d deployment,c Config)bool{
 m:=d.Metadata
 return m.Name==c.Deployment&&m.Namespace==c.Namespace&&m.UID!=""&&m.ResourceVersion!=""&&m.Generation>0&&d.Status.ObservedGeneration==m.Generation
}
// Collect obtains Deployment / ReplicaSets / Deployment in that order.
// It rejects changed resourceVersion or UID between bracketing reads rather
// than falsely describing a stable rollout. It NEVER emits SUPPORTED RCA.
func Collect(ctx context.Context,c Config)(Report,error){
 u,now,err:=safeEndpoint(c);if err!=nil{return Report{},err}
 var hc http.Client
 if c.Client!=nil{hc=*c.Client}else{hc.Timeout=10*time.Second}
 hc.CheckRedirect=func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}
 deploymentPath:="/apis/apps/v1/namespaces/"+c.Namespace+"/deployments/"+c.Deployment
 replicaPath:="/apis/apps/v1/namespaces/"+c.Namespace+"/replicasets?limit=129"
 var before,after deployment
 first,err:=get(ctx,&hc,u,deploymentPath,c.Token,&before)
 if err!=nil{return Report{},err}
 if !stableDeployment(before,c){return Report{},unknown("Deployment identity or observedGeneration not stable")}
 var list replicaSetList
 middle,err:=get(ctx,&hc,u,replicaPath,c.Token,&list)
 if err!=nil{return Report{},err}
 if list.Metadata.ResourceVersion==""||list.Metadata.Continue!=""||len(list.Items)>maxReplicaSets{return Report{},unknown("ReplicaSet list is incomplete")}
 last,err:=get(ctx,&hc,u,deploymentPath,c.Token,&after)
 if err!=nil{return Report{},err}
 if !stableDeployment(after,c)||before.Metadata.UID!=after.Metadata.UID||before.Metadata.Generation!=after.Metadata.Generation||before.Metadata.ResourceVersion!=after.Metadata.ResourceVersion{
  return Report{},unknown("Deployment drift during observation")
 }
 revisions:=make([]Revision,0)
 seen:=map[string]bool{}
 for _,rs:=range list.Items{
  m:=rs.Metadata
  if !hasOwner(m,before.Metadata.UID){continue}
  if m.UID==""||m.Name==""||m.Namespace!=c.Namespace||m.ResourceVersion==""||seen[m.UID]||rs.Spec.Replicas==nil||*rs.Spec.Replicas<0{
   return Report{},unknown("matching ReplicaSet has malformed or duplicated identity")
  }
  seen[m.UID]=true
  created,err:=time.Parse(time.RFC3339Nano,m.CreationTimestamp)
  if err!=nil||created.After(now.Add(5*time.Second)){return Report{},unknown("ReplicaSet has invalid creation time")}
  revision:=m.Annotations["deployment.kubernetes.io/revision"]
  if revision==""{return Report{},unknown("ReplicaSet revision annotation missing")}
  if n,err:=strconv.ParseUint(revision,10,64);err!=nil||n==0{return Report{},unknown("ReplicaSet has malformed revision")}
  revisions=append(revisions,Revision{UID:m.UID,Name:m.Name,Revision:revision,CreatedAt:created.UTC(),ResourceVersion:m.ResourceVersion,Replicas:*rs.Spec.Replicas})
 }
 if len(revisions)==0{return Report{},unknown("no controller-owned ReplicaSet available")}
 sort.Slice(revisions,func(i,j int)bool{
  if revisions[i].CreatedAt.Equal(revisions[j].CreatedAt){return revisions[i].UID<revisions[j].UID}
  return revisions[i].CreatedAt.Before(revisions[j].CreatedAt)
 })
 relationship:="NO_REVISION_CREATED_IN_WINDOW"
 for _,rs:=range revisions{
  if !rs.CreatedAt.Before(c.WindowStart)&&!rs.CreatedAt.After(c.WindowEnd){relationship="TIME_OVERLAP_ONLY";break}
 }
 return Report{
  SchemaVersion:"sre.change-timeline/v1",Status:"OBSERVED",Relationship:relationship,
  Explanation:"ReplicaSet creation timestamps are observations, not evidence that this change caused or resolved an incident; RCA remains UNVERIFIED.",
  Namespace:c.Namespace,Deployment:c.Deployment,DeploymentUID:before.Metadata.UID,Generation:before.Metadata.Generation,
  ResourceVersion:before.Metadata.ResourceVersion,CollectedAt:now,
  WindowStart:c.WindowStart.UTC(),WindowEnd:c.WindowEnd.UTC(),Revisions:revisions,Sources:[]Source{first,middle,last},
 },nil
}
