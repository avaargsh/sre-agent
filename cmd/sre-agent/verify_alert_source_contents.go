package main

import (
 "encoding/json"
 "fmt"
 "math"
 "strconv"
 "strings"
 "time"
 "unicode/utf8"

 "github.com/avaargsh/sre-agent/internal/evidence"
)

// The v1 collector embeds bounded pod/sample JSON as strings. A valid outer
// bundle digest alone does not establish that these inner snapshots agree with
// the claimed series count, source identities or collection clock.
// This remains a consistency check, NOT an independent source attestation.
const maxEmbeddedSourceJSON = 2 << 20

func parseEmbeddedReadOnlyList(raw,location string)([]any,error){
 if len(raw)==0||len(raw)>maxEmbeddedSourceJSON||!utf8.ValidString(raw){
  return nil,fmt.Errorf("%s missing, oversized or non-UTF8",location)
 }
 // Reuse the legacy verifier's recursive duplicate-key rejection, including
 // nested JSON concealed in the observer's string-valued attributes.
 wrapped:=[]byte(`{"items":`+raw+`}`)
 if err:=evidence.ValidateUniqueJSONObject(wrapped);err!=nil{
  return nil,fmt.Errorf("%s contains ambiguous JSON: %w",location,err)
 }
 var obj map[string]any
 if err:=json.Unmarshal(wrapped,&obj);err!=nil{return nil,fmt.Errorf("%s invalid JSON",location)}
 items,ok:=obj["items"].([]any)
 if !ok{return nil,fmt.Errorf("%s must be an array",location)}
 return items,nil
}

func validateEmbeddedPods(attrs map[string]any)error{
 pods,err:=parseEmbeddedReadOnlyList(exactText(attrs,"pods_json"),"Kubernetes pods_json")
 if err!=nil{return err}
 if len(pods)>100{return fmt.Errorf("too many embedded pods")}
 seenUIDs:=make(map[string]bool,len(pods))
 seenNames:=make(map[string]bool,len(pods))
 for _,item:=range pods{
  pod:=exactObject(item)
  if err:=requireOnlyFields(pod,"embedded pod","uid","name","phase");err!=nil{return err}
  uid,name:=exactText(pod,"uid"),exactText(pod,"name")
  if uid==""||name==""{return fmt.Errorf("embedded pod missing identity")}
  phase,ok:=pod["phase"].(string)
  if !ok{return fmt.Errorf("embedded pod phase is not a string")}
  switch phase{
  case "Pending","Running","Succeeded","Failed","Unknown":
  default:
   return fmt.Errorf("embedded pod has invalid phase")
  }
  if seenUIDs[uid]{return fmt.Errorf("duplicated embedded pod UID")}
  if seenNames[name]{return fmt.Errorf("duplicated embedded pod name")}
  seenUIDs[uid]=true
  seenNames[name]=true
 }
 return nil
}

func validateEmbeddedSamples(attrs map[string]any,observedAt time.Time)error{
 samples,err:=parseEmbeddedReadOnlyList(exactText(attrs,"samples_json"),"Prometheus samples_json")
 if err!=nil{return err}
 if len(samples)==0||len(samples)>32{return fmt.Errorf("invalid embedded Prometheus series count")}
 series,err:=strconv.Atoi(exactText(attrs,"series_count"))
 if err!=nil||series!=len(samples){return fmt.Errorf("Prometheus series_count disagrees with samples_json")}
 ageText:=exactText(attrs,"max_age_seconds")
 budget,err:=strconv.ParseFloat(ageText,64)
 // investigate-alert accepts at most 10m. The current observer stores
 // subsecond seconds exactly; pre-fix whole-second receipts remain readable.
 if err!=nil||math.IsNaN(budget)||math.IsInf(budget,0)||budget<=0||budget>600||
  strconv.FormatFloat(budget,'f',-1,64)!=ageText||
  time.Duration(budget*float64(time.Second))<time.Nanosecond{
  return fmt.Errorf("invalid or unverifiable Prometheus sample age budget")
 }
 // Preserve the old whole-second rounded receipt representation with up to
 // 500ms of historical rounding slack. New fractional receipts are exact.
 maxAllowedAge:=time.Duration(budget*float64(time.Second))
 if !strings.Contains(ageText,"."){maxAllowedAge+=500*time.Millisecond}
 for _,item:=range samples{
  sample:=exactObject(item)
  if err:=requireOnlyFields(sample,"embedded Prometheus series","metric","timestamp","value");err!=nil{return err}
  labels:=exactObject(sample["metric"])
  if labels==nil{return fmt.Errorf("embedded Prometheus metric missing")}
  for key,label:=range labels{
   if key==""{return fmt.Errorf("embedded metric label key missing")}
   if _,ok:=label.(string);!ok{return fmt.Errorf("embedded metric label is not a string")}
  }
  timestamp,ok:=sample["timestamp"].(float64)
  if !ok||math.IsNaN(timestamp)||math.IsInf(timestamp,0)||timestamp<=0||timestamp>9e9{
   return fmt.Errorf("invalid embedded Prometheus timestamp")
  }
  value,ok:=sample["value"].(string)
  if !ok{return fmt.Errorf("embedded Prometheus value must be string")}
  number,err:=strconv.ParseFloat(value,64)
  if err!=nil||math.IsNaN(number)||math.IsInf(number,0){
   return fmt.Errorf("non-finite embedded Prometheus value")
  }
  at:=time.Unix(0,int64(timestamp*float64(time.Second))).UTC()
  // The snapshot is checked against its own collection clock; neither
  // this freshness check nor its content digest authenticates the source.
  if observedAt.Sub(at)>maxAllowedAge||
   at.Sub(observedAt)>5*time.Second{
   return fmt.Errorf("embedded Prometheus sample stale or future-dated against bundle clock")
  }
 }
 return nil
}
