package observe

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "mime"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "time"
 "unicode/utf8"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

const (
 maxPodLogBytes = 64 << 10
 maxPodLogTailLines = 200
)

type PodLogsConfig struct {
 PodConfig
 Container string
 TailLines int
}

type PodLogsReport struct {
 SchemaVersion string `json:"schema_version"`
 Target poddiagnosis.Target `json:"target"`
 Container string `json:"container"`
 TailLines int `json:"tail_lines"`
 MaxBytes int `json:"max_bytes"`
 Timestamps bool `json:"timestamps"`
 BeforeResourceVersion string `json:"before_resource_version"`
 AfterResourceVersion string `json:"after_resource_version"`
 BeforePodSHA256 string `json:"before_pod_sha256"`
 AfterPodSHA256 string `json:"after_pod_sha256"`
 LogsSHA256 string `json:"logs_sha256"`
 ObservedAt string `json:"observed_at"`
 SourceAuthenticated bool `json:"source_authenticated"`
}

// PodLogsObservation preserves the exact bounded log response. Raw logs can
// contain credentials, tokens, customer data or other secrets; treat Raw as
// sensitive and never publish it to public artifacts or model prompts by default.
type PodLogsObservation struct {
 Raw []byte
 Report PodLogsReport
}

func podContainsContainer(raw []byte, expected string) bool {
 var pod struct {
  Spec struct {
   Containers []struct {
    Name string `json:"name"`
   } `json:"containers"`
  } `json:"spec"`
 }
 if json.Unmarshal(raw,&pod)!=nil{return false}
 matches:=0
 for _,container:=range pod.Spec.Containers {
  if container.Name==expected {matches++}
 }
 return matches==1
}

// getRawText is the bounded counterpart to getRawJSON for Kubernetes log
// responses. It preserves the original bytes but rejects truncation, non-text
// content, invalid UTF-8, redirects and incomplete reads.
func getRawText(ctx context.Context,hc *http.Client,source *url.URL,path,token string,maxBytes int)([]byte,error){
 if maxBytes<=0||maxBytes>maxPodLogBytes{return nil,unknownf("invalid Pod log byte budget")}
 if ctx.Err()!=nil{return nil,unknownf("Pod log read canceled or collection deadline exceeded")}
 u:=*source
 parsed,err:=url.Parse(path)
 if err!=nil||!strings.HasPrefix(parsed.Path,"/"){return nil,unknownf("invalid Pod log path")}
 u.Path=parsed.Path
 u.RawQuery=parsed.RawQuery
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,u.String(),nil)
 if err!=nil{return nil,unknownf("invalid Pod log request")}
 req.Header.Set("Accept","text/plain")
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 res,err:=hc.Do(req)
 if err!=nil{return nil,unknownf("Pod log request failed: %T",err)}
 if ctx.Err()!=nil{
  if res!=nil&&res.Body!=nil{_ = res.Body.Close()}
  return nil,unknownf("Pod log read canceled or collection deadline exceeded")
 }
 defer res.Body.Close()
 if res.StatusCode!=http.StatusOK{return nil,unknownf("Pod log response status %d",res.StatusCode)}
 mediaType,params,err:=mime.ParseMediaType(res.Header.Get("Content-Type"))
 charset:=strings.ToLower(params["charset"])
 if err!=nil||mediaType!="text/plain"||(charset!=""&&charset!="utf-8"&&charset!="utf8"){return nil,unknownf("Pod log response is not UTF-8 text/plain")}
 if res.ContentLength>int64(maxBytes){return nil,unknownf("Pod log response exceeds byte budget")}
 raw,err:=io.ReadAll(io.LimitReader(res.Body,int64(maxBytes)+1))
 if err!=nil||len(raw)==0||len(raw)>=maxBytes{return nil,unknownf("Pod log response is empty, truncated or exceeds byte budget")}
 if ctx.Err()!=nil{return nil,unknownf("Pod log read canceled or collection deadline exceeded")}
 if !utf8.Valid(raw){return nil,unknownf("Pod log response is not valid UTF-8")}
 return raw,nil
}

// CollectPodLogs captures a bounded current-container tail between two
// independently validated reads of the selected Pod UID. Kubernetes' log
// endpoint is name-scoped, so the pre/post UID fence rejects replacement
// during collection. It does not authenticate the API server or prove log
// freshness, completeness beyond the requested tail, causality or recovery.
func CollectPodLogs(ctx context.Context,c PodLogsConfig)(PodLogsObservation,error){
 target:=c.Target
 if !nameOK(target.Namespace)||!podNameOK(target.Name)||!eventSelectorUID.MatchString(target.UID)||
  !nameOK(c.Container)||c.TailLines<1||c.TailLines>maxPodLogTailLines{
  return PodLogsObservation{},unknownf("invalid Pod log target, container or tail budget")
 }
 source,err:=endpoint(c.KubernetesURL)
 if err!=nil{return PodLogsObservation{},err}
 bounded,cancel:=context.WithTimeout(ctx,maxCollectionDuration)
 defer cancel()
 if bounded.Err()!=nil{return PodLogsObservation{},unknownf("Pod log collection canceled or deadline exceeded")}
 before,err:=CollectPod(bounded,c.PodConfig)
 if err!=nil{return PodLogsObservation{},err}
 if bounded.Err()!=nil||!podContainsContainer(before.Raw,c.Container){
  return PodLogsObservation{},unknownf("selected container is absent from the pre-read Pod snapshot")
 }
 query:=url.Values{}
 query.Set("container",c.Container)
 query.Set("tailLines",strconv.Itoa(c.TailLines))
 query.Set("timestamps","true")
 query.Set("limitBytes",strconv.Itoa(maxPodLogBytes))
 path:="/api/v1/namespaces/"+target.Namespace+"/pods/"+target.Name+"/log?"+query.Encode()
 raw,err:=getRawText(bounded,client(Config{Client:c.Client}),source,path,c.BearerToken,maxPodLogBytes)
 if err!=nil{return PodLogsObservation{},err}
 if bounded.Err()!=nil{return PodLogsObservation{},unknownf("Pod log collection canceled or deadline exceeded")}
 after,err:=CollectPod(bounded,c.PodConfig)
 if err!=nil{return PodLogsObservation{},err}
 if bounded.Err()!=nil||!podContainsContainer(after.Raw,c.Container){
  return PodLogsObservation{},unknownf("selected container is absent from the post-read Pod snapshot")
 }
 digest:=sha256.Sum256(raw)
 report:=PodLogsReport{
  SchemaVersion:"sre.pod-logs/v1",Target:target,Container:c.Container,
  TailLines:c.TailLines,MaxBytes:maxPodLogBytes,Timestamps:true,
  BeforeResourceVersion:before.Report.ResourceVersion,
  AfterResourceVersion:after.Report.ResourceVersion,
  BeforePodSHA256:before.Report.RawSHA256,
  AfterPodSHA256:after.Report.RawSHA256,
  LogsSHA256:hex.EncodeToString(digest[:]),
  ObservedAt:time.Now().UTC().Format(time.RFC3339Nano),
  SourceAuthenticated:false,
 }
 if report.BeforeResourceVersion==""||report.AfterResourceVersion==""||
  report.BeforePodSHA256==""||report.AfterPodSHA256==""||report.LogsSHA256==""{
  return PodLogsObservation{},unknownf("incomplete Pod log identity receipt")
 }
 return PodLogsObservation{Raw:raw,Report:report},nil
}
