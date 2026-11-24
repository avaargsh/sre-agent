// Package verifier measures an independent read-only Prometheus SLI window.
// HEALTHY is not proof of root cause, authorization, or incident recovery.
package verifier

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
 "math"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "time"
 "github.com/avaargsh/sre-agent/internal/sourcejson"
)

type Status string
const (
 Healthy Status = "HEALTHY"
 Unhealthy Status = "UNHEALTHY"
 Unknown Status = "UNKNOWN"
)
type Policy struct {
 PrometheusURL string
 LatencyQuery string
 TrafficQuery string
 AgeQuery string
 MaxLatencySeconds float64
 MinTrafficPerSecond float64
 MaxSampleAgeSeconds float64
 Window time.Duration
 Step time.Duration
 NotBefore time.Time
 Now func() time.Time
 Client *http.Client
}
type SourceEvidence struct {
 Query string `json:"query"`
 ResponseSHA256 string `json:"response_sha256"`
 RawResponseBase64 string `json:"raw_response_base64"`
 Series int `json:"series"`
 Samples int `json:"samples"`
}
type Assessment struct {
 Status Status `json:"status"`
 Reason string `json:"reason"`
 Start time.Time `json:"start"`
 End time.Time `json:"end"`
 StepSeconds int64 `json:"step_seconds"`
 MaxLatencySeconds float64 `json:"max_latency_seconds"`
 MinTrafficPerSecond float64 `json:"min_traffic_per_second"`
 MaxSampleAgeSeconds float64 `json:"max_sample_age_seconds"`
 Evidence []SourceEvidence `json:"evidence"`
}
const maxResponseSize = 2 << 20
func finite(x float64)bool{return !math.IsNaN(x)&&!math.IsInf(x,0)}
func checkPolicy(p Policy)(*url.URL,time.Time,time.Time,error){
 if p.Now==nil {p.Now=time.Now}
 if p.Window<=0||p.Step<time.Second||p.Step%time.Second!=0||p.Window%p.Step!=0||p.Window<2*p.Step||p.Window>10*time.Minute||p.Window/p.Step>120{return nil,time.Time{},time.Time{},errors.New("unsupported or undersampled SLI window")}
 if !finite(p.MaxLatencySeconds)||p.MaxLatencySeconds<=0||!finite(p.MinTrafficPerSecond)||p.MinTrafficPerSecond<=0||!finite(p.MaxSampleAgeSeconds)||p.MaxSampleAgeSeconds<=0{return nil,time.Time{},time.Time{},errors.New("positive finite latency and traffic thresholds are required")}
 if len(p.LatencyQuery)==0||len(p.LatencyQuery)>512||len(p.TrafficQuery)==0||len(p.TrafficQuery)>512||len(p.AgeQuery)==0||len(p.AgeQuery)>512{return nil,time.Time{},time.Time{},errors.New("invalid SLI query")}
 u,err:=url.Parse(p.PrometheusURL)
 if err!=nil||u==nil||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||(u.Path!=""&&u.Path!="/"){return nil,time.Time{},time.Time{},errors.New("invalid Prometheus URL")}
 if u.Scheme!="http"&&u.Scheme!="https"{return nil,time.Time{},time.Time{},errors.New("invalid Prometheus scheme")}
 if u.Scheme=="http"{
  ip:=net.ParseIP(u.Hostname())
  if u.Hostname()!="localhost"&&(ip==nil||!ip.IsLoopback()){return nil,time.Time{},time.Time{},errors.New("plaintext Prometheus must be loopback")}
 }
 now:=p.Now().UTC()
 end:=now.Truncate(p.Step)
 start:=end.Add(-p.Window)
 if end.After(now)||(!p.NotBefore.IsZero()&&start.Before(p.NotBefore.UTC())){return nil,time.Time{},time.Time{},errors.New("SLI window predates trusted barrier")}
 return u,start,end,nil
}
type response struct {
 Status string `json:"status"`
 Warnings []string `json:"warnings"`
 IsPartial bool `json:"isPartial"`
 PartialResponse bool `json:"partialResponse"`
 Data struct {
  ResultType string `json:"resultType"`
  Result []struct{
   Metric map[string]*string `json:"metric"`
   Values [][]json.RawMessage `json:"values"`
  } `json:"result"`
 } `json:"data"`
}
func query(ctx context.Context,p Policy,u *url.URL,start,end time.Time,threshold float64,mode string)(SourceEvidence,bool,error){
 api:=*u
 api.Path="/api/v1/query_range"
 q:=url.Values{}
 name:=p.LatencyQuery
 if mode=="traffic"{name=p.TrafficQuery}
 if mode=="age"{name=p.AgeQuery}
 q.Set("query",name)
 q.Set("start",strconv.FormatInt(start.Unix(),10))
 q.Set("end",strconv.FormatInt(end.Unix(),10))
 q.Set("step",strconv.FormatInt(int64(p.Step.Seconds()),10))
 api.RawQuery=q.Encode()
 req,err:=http.NewRequestWithContext(ctx,http.MethodGet,api.String(),nil)
 if err!=nil{return SourceEvidence{},false,err}
 req.Header.Set("Accept","application/json")
 var hc http.Client
 if p.Client!=nil{hc=*p.Client}else{hc.Timeout=10*time.Second}
 hc.CheckRedirect=func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}
 resp,err:=hc.Do(req)
 if err!=nil{return SourceEvidence{},false,fmt.Errorf("Prometheus transport failed: %T",err)}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return SourceEvidence{},false,fmt.Errorf("Prometheus HTTP %d",resp.StatusCode)}
 raw,err:=io.ReadAll(io.LimitReader(resp.Body,maxResponseSize+1))
 if err!=nil||len(raw)>maxResponseSize{return SourceEvidence{},false,errors.New("Prometheus response exceeds limit or failed")}
 if err:=sourcejson.Validate(raw);err!=nil{return SourceEvidence{},false,errors.New("invalid native Prometheus SLI JSON")}
 var parsed response
 dec:=json.NewDecoder(bytes.NewReader(raw))
 if err:=dec.Decode(&parsed);err!=nil{return SourceEvidence{},false,errors.New("invalid Prometheus response JSON")}
 var extra any
 if !errors.Is(dec.Decode(&extra),io.EOF){return SourceEvidence{},false,errors.New("trailing Prometheus JSON")}
 if len(parsed.Warnings)>0||parsed.IsPartial||parsed.PartialResponse{return SourceEvidence{},false,errors.New("Prometheus returned warned or partial SLI evidence")}
 if parsed.Status!="success"||parsed.Data.ResultType!="matrix"||len(parsed.Data.Result)==0||len(parsed.Data.Result)>16{return SourceEvidence{},false,errors.New("missing or invalid Prometheus matrix")}
 expected:=int(p.Window/p.Step)+1
 keys:=map[string]bool{}
 allHealthy:=true
 samples:=0
 for _,series:=range parsed.Data.Result{
  // Missing or null metric objects and null label values are not valid
  // labelsets. Keep explicit empty strings and unlabelled aggregates valid.
  if series.Metric==nil{return SourceEvidence{},false,errors.New("missing Prometheus metric label set")}
  for name,value:=range series.Metric{
   if name==""||value==nil{return SourceEvidence{},false,errors.New("invalid Prometheus metric label")}
  }
  labels,err:=json.Marshal(series.Metric)
  if err!=nil{return SourceEvidence{},false,err}
  if keys[string(labels)]{return SourceEvidence{},false,errors.New("duplicate Prometheus metric label set")}
  keys[string(labels)]=true
  if len(series.Values)!=expected{return SourceEvidence{},false,errors.New("incomplete Prometheus SLI window")}
  for i,point:=range series.Values{
   if len(point)!=2{return SourceEvidence{},false,errors.New("invalid Prometheus point")}
   var timestamp float64
   var value string
   if err:=json.Unmarshal(point[0],&timestamp);err!=nil||!finite(timestamp){return SourceEvidence{},false,errors.New("invalid sample timestamp")}
   if math.Abs(timestamp-float64(start.Add(time.Duration(i)*p.Step).Unix()))>0.001{return SourceEvidence{},false,errors.New("misaligned or missing Prometheus sample")}
   if err:=json.Unmarshal(point[1],&value);err!=nil{return SourceEvidence{},false,errors.New("invalid sample encoding")}
   number,err:=strconv.ParseFloat(value,64)
   if err!=nil||!finite(number)||number<0{return SourceEvidence{},false,errors.New("non-finite or negative SLI sample")}
   if ((mode=="latency"||mode=="age")&&number>threshold)||(mode=="traffic"&&number<threshold){allHealthy=false}
   samples++
  }
 }
 digest:=sha256.Sum256(raw)
 return SourceEvidence{Query:name,ResponseSHA256:hex.EncodeToString(digest[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(raw),Series:len(parsed.Data.Result),Samples:samples},allHealthy,nil
}
// Assess never reads an Agent-generated success statement. HEALTHY means only
// that the inspected bounded SLI window meets operator-selected constraints.
// UNKNOWN cannot authorize automation or compensation.
func Assess(ctx context.Context,p Policy) Assessment{
 report:=Assessment{Status:Unknown,Reason:"insufficient independently verified SLI",MaxLatencySeconds:p.MaxLatencySeconds,MinTrafficPerSecond:p.MinTrafficPerSecond,MaxSampleAgeSeconds:p.MaxSampleAgeSeconds,Evidence:[]SourceEvidence{}}
 u,start,end,err:=checkPolicy(p)
 if err!=nil{report.Reason=err.Error();return report}
 report.Start,report.End,report.StepSeconds=start,end,int64(p.Step.Seconds())
 latency,okLatency,err:=query(ctx,p,u,start,end,p.MaxLatencySeconds,"latency")
 if err!=nil{report.Reason=err.Error();return report}
 report.Evidence=append(report.Evidence,latency)
 traffic,okTraffic,err:=query(ctx,p,u,start,end,p.MinTrafficPerSecond,"traffic")
 if err!=nil{report.Reason=err.Error();return report}
 report.Evidence=append(report.Evidence,traffic)
 age,okAge,err:=query(ctx,p,u,start,end,p.MaxSampleAgeSeconds,"age")
 if err!=nil{report.Reason=err.Error();return report}
 report.Evidence=append(report.Evidence,age)
 if !okAge{report.Reason="one or more Prometheus scrape samples exceed freshness budget";return report}
 if !okTraffic{report.Reason="insufficient observed request traffic";return report}
 if !okLatency{report.Status=Unhealthy;report.Reason="one or more observed latency samples breach SLI threshold";return report}
 report.Status=Healthy;report.Reason="all observed samples satisfy latency and minimum traffic SLI conditions"
 return report
}
