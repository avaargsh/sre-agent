package observe

import (
 "context"
 "net/url"
 "regexp"
 "strconv"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

var eventSelectorUID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type PodEventObservation struct {
 Raw []byte
 Report poddiagnosis.EventReport
}

// CollectPodEvents lists bounded core/v1 events for one independently pinned
// Pod UID. Kubernetes RBAC list permission is namespace-wide, not UID-scoped;
// the selector and per-item validation constrain this client's returned facts.
func CollectPodEvents(ctx context.Context,c PodConfig)(PodEventObservation,error){
 t:=c.Target
 if !nameOK(t.Namespace)||!podNameOK(t.Name)||!eventSelectorUID.MatchString(t.UID){return PodEventObservation{},unknownf("invalid expected Pod event identity")}
 u,err:=endpoint(c.KubernetesURL);if err!=nil{return PodEventObservation{},err}
 query:=url.Values{"fieldSelector":{"involvedObject.uid="+t.UID},"limit":{strconv.Itoa(poddiagnosis.MaxEvents)}}
 raw,err:=getRawJSON(ctx,client(Config{Client:c.Client}),u,"/api/v1/namespaces/"+t.Namespace+"/events?"+query.Encode(),c.BearerToken)
 if err!=nil{return PodEventObservation{},err}
 report,err:=poddiagnosis.AssessEvents(t,raw)
 if err!=nil{return PodEventObservation{},unknownf("invalid or incomplete Pod event response")}
 return PodEventObservation{Raw:raw,Report:report},nil
}
