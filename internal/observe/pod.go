package observe

import (
 "context"
 "net/http"
 "strings"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

type PodConfig struct {
 KubernetesURL string
 Target poddiagnosis.Target
 BearerToken string
 Client *http.Client
}

// PodObservation contains the exact response body and its replayable report.
// Treat Raw as sensitive; it can include Pod configuration and environment
// values. Neither the report nor the digest is source attestation.
type PodObservation struct {
 Raw []byte
 Report poddiagnosis.NativeReport
}

func podNameOK(name string) bool {
 if len(name)==0 || len(name)>253 {return false}
 for _,part:=range strings.Split(name,".") {if !nameOK(part) {return false}}
 return true
}

// CollectPod performs one scoped read, using an independently provided UID.
// It does not discover targets, prove Deployment ownership or grant authority.
func CollectPod(ctx context.Context,c PodConfig)(PodObservation,error){
 t:=c.Target
 if !nameOK(t.Namespace)||!podNameOK(t.Name)||strings.TrimSpace(t.UID)==""||len(t.UID)>128{
  return PodObservation{},unknownf("invalid expected Pod identity")
 }
 u,err:=endpoint(c.KubernetesURL)
 if err!=nil{return PodObservation{},err}
 raw,err:=getRawJSON(ctx,client(Config{Client:c.Client}),u,"/api/v1/namespaces/"+t.Namespace+"/pods/"+t.Name,c.BearerToken)
 if err!=nil{return PodObservation{},err}
 report,err:=poddiagnosis.AssessNative(t,raw)
 if err!=nil{return PodObservation{},unknownf("invalid or mismatched Pod response")}
 return PodObservation{Raw:raw,Report:report},nil
}
