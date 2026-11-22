package rca

import (
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "math"
 "reflect"
 "sort"
 "strconv"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

// Replay independently reconstructs Kubernetes revision relationships and
// Prometheus SLI decisions from the stored *raw* source bytes. It protects
// against forged report summaries, not an attacker controlling source bytes
// and digests together. It does not authenticate upstream HTTP identities.
func Replay(ch change.Report, sli verifier.Assessment) error {
 if err:=replayChanges(ch);err!=nil{return fmt.Errorf("Kubernetes replay UNKNOWN: %w",err)}
 if err:=replaySLI(sli);err!=nil{return fmt.Errorf("Prometheus replay UNKNOWN: %w",err)}
 return nil
}

type replayOwner struct {
 UID string `json:"uid"`
 Kind string `json:"kind"`
 Controller *bool `json:"controller"`
}
type replayMeta struct {
 UID string `json:"uid"`
 Name string `json:"name"`
 Namespace string `json:"namespace"`
 ResourceVersion string `json:"resourceVersion"`
 Generation int64 `json:"generation"`
 CreationTimestamp string `json:"creationTimestamp"`
 Annotations map[string]string `json:"annotations"`
 OwnerReferences []replayOwner `json:"ownerReferences"`
}
type replayDeployment struct {
 Metadata replayMeta `json:"metadata"`
 Status struct{ObservedGeneration int64 `json:"observedGeneration"`} `json:"status"`
}
type replayReplicaSetList struct {
 Metadata struct{
  ResourceVersion string `json:"resourceVersion"`
  Continue string `json:"continue"`
 } `json:"metadata"`
 Items []struct{
  Metadata replayMeta `json:"metadata"`
  Spec struct{Replicas *int `json:"replicas"`} `json:"spec"`
 } `json:"items"`
}
func unmarshalRaw(encoded string,out any) error {
 raw,err:=base64.StdEncoding.Strict().DecodeString(encoded)
 if err!=nil||len(raw)==0{return errors.New("invalid source encoding")}
 if err:=json.Unmarshal(raw,out);err!=nil{return errors.New("invalid source JSON")}
 return nil
}
func replayChanges(ch change.Report)error{
 if ch.SchemaVersion!="sre.change-timeline/v1"||ch.Status!="OBSERVED"||len(ch.Sources)!=3||
  ch.WindowStart.IsZero()||ch.WindowEnd.IsZero()||ch.CollectedAt.IsZero()||
  !ch.WindowStart.Before(ch.WindowEnd)||ch.WindowEnd.Sub(ch.WindowStart)>24*time.Hour||
  ch.WindowEnd.After(ch.CollectedAt.Add(5*time.Second)){
  return errors.New("incomplete or invalid change observation window")
 }
 expectedDep:="/apis/apps/v1/namespaces/"+ch.Namespace+"/deployments/"+ch.Deployment
 expectedRS:="/apis/apps/v1/namespaces/"+ch.Namespace+"/replicasets"
 if ch.Sources[0].Endpoint!=expectedDep||ch.Sources[1].Endpoint!=expectedRS||ch.Sources[2].Endpoint!=expectedDep{
  return errors.New("unexpected Kubernetes endpoint or source order")
 }
 var before,after replayDeployment
 var sets replayReplicaSetList
 if err:=unmarshalRaw(ch.Sources[0].RawResponseBase64,&before);err!=nil{return err}
 if err:=unmarshalRaw(ch.Sources[1].RawResponseBase64,&sets);err!=nil{return err}
 if err:=unmarshalRaw(ch.Sources[2].RawResponseBase64,&after);err!=nil{return err}
 dep:=before.Metadata
 if dep.UID==""||dep.Name!=ch.Deployment||dep.Namespace!=ch.Namespace||
  dep.ResourceVersion==""||dep.Generation<=0||before.Status.ObservedGeneration!=dep.Generation{
  return errors.New("invalid initial Deployment identity or observedGeneration")
 }
 if after.Metadata.UID!=dep.UID||after.Metadata.ResourceVersion!=dep.ResourceVersion||
  after.Metadata.Generation!=dep.Generation||after.Metadata.Name!=dep.Name||
  after.Metadata.Namespace!=dep.Namespace||after.Status.ObservedGeneration!=dep.Generation{
  return errors.New("Deployment changed during collection")
 }
 if ch.DeploymentUID!=dep.UID||ch.Generation!=dep.Generation||ch.ResourceVersion!=dep.ResourceVersion{
  return errors.New("Deployment summary does not match raw source")
 }
 if sets.Metadata.ResourceVersion==""||sets.Metadata.Continue!=""||len(sets.Items)>128{
  return errors.New("incomplete or paginated ReplicaSet list")
 }
 revisions:=make([]change.Revision,0)
 seenUID:=map[string]bool{}
 for _,item:=range sets.Items {
  m:=item.Metadata
  owned:=false
  for _,o:=range m.OwnerReferences {
   if o.UID==dep.UID&&o.Kind=="Deployment"&&o.Controller!=nil&&*o.Controller{owned=true;break}
  }
  if !owned{continue}
  if m.UID==""||m.Name==""||m.Namespace!=ch.Namespace||m.ResourceVersion==""||
   seenUID[m.UID]||item.Spec.Replicas==nil||*item.Spec.Replicas<0{
   return errors.New("invalid or duplicate owned ReplicaSet")
  }
  seenUID[m.UID]=true
  created,err:=time.Parse(time.RFC3339Nano,m.CreationTimestamp)
  if err!=nil||created.After(ch.CollectedAt.Add(5*time.Second)){
   return errors.New("invalid ReplicaSet creation time")
  }
  revision:=m.Annotations["deployment.kubernetes.io/revision"]
  num,err:=strconv.ParseUint(revision,10,64)
  if err!=nil||num==0{return errors.New("invalid ReplicaSet revision annotation")}
  revisions=append(revisions,change.Revision{
   UID:m.UID,Name:m.Name,Revision:revision,CreatedAt:created.UTC(),
   ResourceVersion:m.ResourceVersion,Replicas:*item.Spec.Replicas,
  })
 }
 if len(revisions)==0{return errors.New("no owned ReplicaSet")}
 sort.Slice(revisions,func(i,j int)bool{
  if revisions[i].CreatedAt.Equal(revisions[j].CreatedAt){return revisions[i].UID<revisions[j].UID}
  return revisions[i].CreatedAt.Before(revisions[j].CreatedAt)
 })
 if !reflect.DeepEqual(revisions,ch.Revisions){
  return errors.New("ReplicaSet revisions differ from raw list")
 }
 overlap:=false
 for _,rs:=range revisions{
  if !rs.CreatedAt.Before(ch.WindowStart)&&!rs.CreatedAt.After(ch.WindowEnd){overlap=true;break}
 }
 relation:="NO_REVISION_CREATED_IN_WINDOW"
 if overlap{relation="TIME_OVERLAP_ONLY"}
 if relation!=ch.Relationship{return errors.New("change relationship was not derived from raw source")}
 return nil
}

type replayMatrix struct{
 Status string `json:"status"`
 Data struct {
  ResultType string `json:"resultType"`
  Result []struct{
   Metric map[string]string `json:"metric"`
   Values [][]json.RawMessage `json:"values"`
  } `json:"result"`
 } `json:"data"`
}
func finiteNumber(x float64)bool{return !math.IsNaN(x)&&!math.IsInf(x,0)}
func replaySLI(s verifier.Assessment)error{
 if s.Start.IsZero()||s.End.IsZero()||!s.Start.Before(s.End)||
  s.StepSeconds<1||s.StepSeconds>600||len(s.Evidence)!=3||
  !finiteNumber(s.MaxLatencySeconds)||s.MaxLatencySeconds<=0||
  !finiteNumber(s.MinTrafficPerSecond)||s.MinTrafficPerSecond<=0||
  !finiteNumber(s.MaxSampleAgeSeconds)||s.MaxSampleAgeSeconds<=0 {
  return errors.New("invalid SLI policy or missing source matrices")
 }
 step:=time.Duration(s.StepSeconds)*time.Second
 duration:=s.End.Sub(s.Start)
 if duration>10*time.Minute||duration%step!=0||duration/step<2||duration/step>120{
  return errors.New("invalid SLI sample window")
 }
 count:=int(duration/step)+1
 thresholds:=[3]float64{s.MaxLatencySeconds,s.MinTrafficPerSecond,s.MaxSampleAgeSeconds}
 verdicts:=[3]bool{true,true,true}
 queries:=map[string]bool{}
 for idx,src:=range s.Evidence{
  if src.Query==""||len(src.Query)>512||queries[src.Query]{
   return errors.New("duplicate or absent SLI source query")
  }
  queries[src.Query]=true
  var m replayMatrix
  if err:=unmarshalRaw(src.RawResponseBase64,&m);err!=nil{return err}
  if m.Status!="success"||m.Data.ResultType!="matrix"||len(m.Data.Result)==0||len(m.Data.Result)>16{
   return fmt.Errorf("SLI source %d is not a complete matrix",idx)
  }
  if len(m.Data.Result)!=src.Series{
   return fmt.Errorf("SLI source %d forged series count",idx)
  }
  seenMetric:=map[string]bool{}
  actualSamples:=0
  for _,series:=range m.Data.Result {
   key,err:=json.Marshal(series.Metric)
   if err!=nil{return err}
   if seenMetric[string(key)]{return errors.New("duplicate metric label set")}
   seenMetric[string(key)]=true
   if len(series.Values)!=count{return fmt.Errorf("SLI source %d contains missing samples",idx)}
   for pointIdx,point:=range series.Values{
    if len(point)!=2{return errors.New("SLI source has malformed sample")}
    var ts float64
    var value string
    if err:=json.Unmarshal(point[0],&ts);err!=nil||!finiteNumber(ts)||
     math.Abs(ts-float64(s.Start.Add(time.Duration(pointIdx)*step).UnixNano())/1e9)>0.001{
     return errors.New("SLI timestamp missing or misaligned")
    }
    if err:=json.Unmarshal(point[1],&value);err!=nil{return errors.New("SLI sample value is not a string")}
    number,err:=strconv.ParseFloat(value,64)
    if err!=nil||!finiteNumber(number)||number<0{
     return errors.New("SLI metric is non-finite or negative")
    }
    if (idx==0||idx==2)&&number>thresholds[idx]{verdicts[idx]=false}
    if idx==1&&number<thresholds[idx]{verdicts[idx]=false}
    actualSamples++
   }
  }
  if src.Samples!=actualSamples{return fmt.Errorf("SLI source %d forged sample count",idx)}
 }
 status:=verifier.Healthy
 if !verdicts[2]||!verdicts[1]{status=verifier.Unknown
 }else if !verdicts[0]{status=verifier.Unhealthy}
 if status!=s.Status{return fmt.Errorf("SLI status %q conflicts with raw matrix-derived %q",s.Status,status)}
 return nil
}
