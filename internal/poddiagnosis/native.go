package poddiagnosis

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "strings"

 "github.com/avaargsh/sre-agent/internal/sourcejson"
)

const MaxNativePodBytes = 2 << 20
var errInvalidPod = errors.New("invalid, incomplete or mismatched native Pod snapshot")

type NativeReport struct {
 SchemaVersion string `json:"schema_version"`
 Target Target `json:"target"`
 ResourceVersion string `json:"resource_version"`
 RawSHA256 string `json:"raw_sha256"`
 Assessment Report `json:"assessment"`
 SourceAuthenticated bool `json:"source_authenticated"`
}

type nativeObject map[string]json.RawMessage

func object(raw []byte, reserved ...string) (nativeObject,error) {
 var m nativeObject
 if json.Unmarshal(raw,&m)!=nil || m==nil {return nil,errInvalidPod}
 for key:=range m {for _,canonical:=range reserved {if key!=canonical && strings.EqualFold(key,canonical) {return nil,errInvalidPod}}}
 return m,nil
}

func field[T any](m nativeObject,key string) (T,error) {
 var value T
 raw,ok:=m[key]
 if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) || json.Unmarshal(raw,&value)!=nil {return value,errInvalidPod}
 return value,nil
}

func state(raw []byte, allowEmpty bool) (string,string,error) {
 m,err:=object(raw,"waiting","running","terminated")
 if err!=nil {return "","",err}
 if allowEmpty && len(m)==0 {return "","",nil}
 if len(m)!=1 {return "","",errInvalidPod}
 for kind,payload:=range m {
  if kind!="waiting" && kind!="running" && kind!="terminated" {return "","",errInvalidPod}
  details,err:=object(payload,"reason","exitCode")
  if err!=nil {return "","",err}
  if kind=="terminated" {
   if _,err:=field[int32](details,"exitCode");err!=nil {return "","",err}
  }
  reason:=""
  if _,ok:=details["reason"];ok {reason,err=field[string](details,"reason");if err!=nil {return "","",err}}
  return kind,reason,nil
 }
 return "","",errInvalidPod
}

// AssessNative replays exact original Pod bytes. The digest binds content,
// not API issuer, collection time, freshness, or authorization.
func AssessNative(expected Target,raw []byte) (NativeReport,error) {
 if len(raw)==0 || len(raw)>MaxNativePodBytes || sourcejson.Validate(raw)!=nil {return NativeReport{},errInvalidPod}
 root,err:=object(raw,"apiVersion","kind","metadata","spec","status")
 if err!=nil {return NativeReport{},err}
 version,e1:=field[string](root,"apiVersion");kind,e2:=field[string](root,"kind")
 if e1!=nil || e2!=nil || version!="v1" || kind!="Pod" {return NativeReport{},errInvalidPod}
 meta,e1:=object(root["metadata"],"namespace","name","uid","resourceVersion")
 spec,e2:=object(root["spec"],"containers")
 status,e3:=object(root["status"],"phase","containerStatuses")
 if e1!=nil || e2!=nil || e3!=nil {return NativeReport{},errInvalidPod}
 ns,e1:=field[string](meta,"namespace");name,e2:=field[string](meta,"name");uid,e3:=field[string](meta,"uid");rv,e4:=field[string](meta,"resourceVersion")
 phase,e5:=field[string](status,"phase")
 if e1!=nil || e2!=nil || e3!=nil || e4!=nil || e5!=nil {return NativeReport{},errInvalidPod}
 snapshot:=Snapshot{Target:Target{Namespace:ns,Name:name,UID:uid},ResourceVersion:rv,Phase:phase}
 if snapshot.Target!=expected || strings.TrimSpace(phase)=="" {return NativeReport{},errInvalidPod}
 containers,e1:=field[[]json.RawMessage](spec,"containers");statuses,e2:=field[[]json.RawMessage](status,"containerStatuses")
 if e1!=nil || e2!=nil || len(containers)==0 || len(containers)>128 || len(containers)!=len(statuses) {return NativeReport{},errInvalidPod}
 for _,entry:=range containers {
  m,err:=object(entry,"name");if err!=nil {return NativeReport{},err}
  name,err:=field[string](m,"name");if err!=nil {return NativeReport{},err}
  snapshot.Containers=append(snapshot.Containers,name)
 }
 for _,entry:=range statuses {
  m,err:=object(entry,"name","ready","restartCount","state","lastState");if err!=nil {return NativeReport{},err}
  name,e1:=field[string](m,"name");ready,e2:=field[bool](m,"ready");restarts,e3:=field[int32](m,"restartCount")
  kind,reason,e4:=state(m["state"],false)
  if e1!=nil || e2!=nil || e3!=nil || e4!=nil {return NativeReport{},errInvalidPod}
  previous:=""
  if last,ok:=m["lastState"];ok {
   previousKind,previousReason,err:=state(last,true)
   if err!=nil {return NativeReport{},err}
   if previousKind=="terminated" {previous=previousReason}
  }
  snapshot.Statuses=append(snapshot.Statuses,ContainerStatus{Name:name,State:kind,Reason:reason,LastTerminationReason:previous,RestartCount:int(restarts),Ready:ready})
 }
 assessment:=Assess(expected,snapshot)
 if assessment.Reason==invalidSnapshotReason {return NativeReport{},errInvalidPod}
 digest:=sha256.Sum256(raw)
 return NativeReport{SchemaVersion:"sre.pod-diagnosis/v1",Target:expected,ResourceVersion:rv,RawSHA256:hex.EncodeToString(digest[:]),Assessment:assessment},nil
}
