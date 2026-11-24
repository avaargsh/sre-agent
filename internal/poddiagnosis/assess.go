// Package poddiagnosis interprets normalized, untrusted container status snapshots.
// It never authenticates a source, establishes causality, or verifies recovery.
package poddiagnosis

import "strings"

type Target struct { Namespace, Name, UID string }
type ContainerStatus struct {
 Name, State, Reason, LastTerminationReason string
 RestartCount int
 Ready bool
}
type Snapshot struct {
 Target
 ResourceVersion, Phase string
 Containers []string
 Statuses []ContainerStatus
}
type Finding struct {
 Container string `json:"container"`
 Code string `json:"code"`
 TemporalScope string `json:"temporal_scope"`
}
type Report struct {
 Status string `json:"status"`
 Reason string `json:"reason"`
 Findings []Finding `json:"findings"`
 RootCauseVerified bool `json:"root_cause_verified"`
 RecoveryVerified bool `json:"recovery_verified"`
}

// Assess requires a separately selected Pod identity and complete regular
// container coverage. The caller owns JSON validation, source provenance,
// freshness, and normalization of native Kubernetes state fields.
const invalidSnapshotReason = "incomplete or mismatched pod snapshot"

func Assess(expected Target, s Snapshot) Report {
 r:=Report{Status:"UNKNOWN", Reason:invalidSnapshotReason, Findings:[]Finding{}}
 if strings.TrimSpace(expected.Namespace)=="" || strings.TrimSpace(expected.Name)=="" || strings.TrimSpace(expected.UID)=="" || s.Target!=expected || strings.TrimSpace(s.ResourceVersion)=="" || len(s.Containers)==0 || len(s.Containers)>128 || len(s.Containers)!=len(s.Statuses) { return r }
 names:=make(map[string]bool,len(s.Containers))
 for _,name:=range s.Containers {
  if strings.TrimSpace(name)=="" || names[name] {return r}
  names[name]=true
 }
 for _,c:=range s.Statuses {
  if !names[c.Name] || c.RestartCount<0 || (c.State!="waiting" && c.State!="running" && c.State!="terminated") || (c.State!="running" && c.Ready) {return r}
  delete(names,c.Name)
 }
 // Only after all input checks succeed may any diagnostic signal be exposed.
 for _,c:=range s.Statuses {
  if c.State=="waiting" {
   switch c.Reason {
   case "CrashLoopBackOff","ImagePullBackOff","ErrImagePull","CreateContainerConfigError","CreateContainerError":
    r.Findings=append(r.Findings,Finding{c.Name,c.Reason,"current"})
   }
  }
  if c.State=="terminated" && c.Reason=="OOMKilled" {r.Findings=append(r.Findings,Finding{c.Name,"OOMKilled","current"})}
  if c.LastTerminationReason=="OOMKilled" {r.Findings=append(r.Findings,Finding{c.Name,"OOMKilled","historical"})}
 }
 if len(r.Findings)>0 {r.Status="SIGNALS_PRESENT";r.Reason="container status signals require independent investigation"} else {r.Reason="no recognized failure signal; health and recovery remain unverified"}
 return r
}
