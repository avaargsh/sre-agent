package poddiagnosis

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "regexp"
 "strings"

 "github.com/avaargsh/sre-agent/internal/sourcejson"
)

const MaxEvents = 128
var eventReason = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

type EventFact struct {
 UID string `json:"uid"`
 Type string `json:"type"`
 Reason string `json:"reason"`
}
type EventReport struct {
 SchemaVersion string `json:"schema_version"`
 Target Target `json:"target"`
 ResourceVersion string `json:"resource_version"`
 RawSHA256 string `json:"raw_sha256"`
 Events []EventFact `json:"events"`
 SourceAuthenticated bool `json:"source_authenticated"`
}

// AssessEvents projects scoped core/v1 EventList facts, not causal or fresh
// observations. Empty lists are valid and do not prove health. Messages are
// deliberately excluded from the projection; raw bytes may be sensitive.
func AssessEvents(expected Target, raw []byte) (EventReport,error) {
 if strings.TrimSpace(expected.Namespace)=="" || strings.TrimSpace(expected.Name)=="" || strings.TrimSpace(expected.UID)=="" || len(raw)==0 || len(raw)>MaxNativePodBytes || sourcejson.Validate(raw)!=nil {return EventReport{},errInvalidPod}
 root,err:=object(raw,"apiVersion","kind","metadata","items")
 if err!=nil {return EventReport{},err}
 version,e1:=field[string](root,"apiVersion");kind,e2:=field[string](root,"kind")
 if e1!=nil || e2!=nil || version!="v1" || kind!="EventList" {return EventReport{},errInvalidPod}
 meta,err:=object(root["metadata"],"resourceVersion","continue")
 if err!=nil {return EventReport{},err}
 rv,err:=field[string](meta,"resourceVersion")
 if err!=nil || strings.TrimSpace(rv)=="" {return EventReport{},errInvalidPod}
 if _,ok:=meta["continue"];ok {next,err:=field[string](meta,"continue");if err!=nil || next!="" {return EventReport{},errInvalidPod}}
 items,err:=field[[]json.RawMessage](root,"items")
 if err!=nil || items==nil || len(items)>MaxEvents {return EventReport{},errInvalidPod}
 facts:=make([]EventFact,0,len(items))
 seen:=make(map[string]bool,len(items))
 for _,item:=range items {
  m,err:=object(item,"metadata","involvedObject","type","reason");if err!=nil {return EventReport{},err}
  em,e1:=object(m["metadata"],"uid","namespace");ref,e2:=object(m["involvedObject"],"apiVersion","kind","namespace","name","uid")
  if e1!=nil || e2!=nil {return EventReport{},errInvalidPod}
  uid,e1:=field[string](em,"uid");ns,e2:=field[string](em,"namespace")
  refVersion,e3:=field[string](ref,"apiVersion");refKind,e4:=field[string](ref,"kind");refNS,e5:=field[string](ref,"namespace");refName,e6:=field[string](ref,"name");refUID,e7:=field[string](ref,"uid")
  typ,e8:=field[string](m,"type");reason,e9:=field[string](m,"reason")
  if e1!=nil || e2!=nil || e3!=nil || e4!=nil || e5!=nil || e6!=nil || e7!=nil || e8!=nil || e9!=nil || strings.TrimSpace(uid)=="" || len(uid)>128 || seen[uid] || ns!=expected.Namespace || refVersion!="v1" || refKind!="Pod" || (Target{Namespace:refNS,Name:refName,UID:refUID})!=expected || (typ!="Normal" && typ!="Warning") || !eventReason.MatchString(reason) {return EventReport{},errInvalidPod}
  seen[uid]=true
  facts=append(facts,EventFact{UID:uid,Type:typ,Reason:reason})
 }
 digest:=sha256.Sum256(raw)
 return EventReport{SchemaVersion:"sre.pod-events/v1",Target:expected,ResourceVersion:rv,RawSHA256:hex.EncodeToString(digest[:]),Events:facts},nil
}
