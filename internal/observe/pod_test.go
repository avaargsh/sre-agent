package observe

import (
 "bytes"
 "context"
 "crypto/sha256"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

const podResponse = " \n"+`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`+"\n"

func podTarget() poddiagnosis.Target {return poddiagnosis.Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}}

func TestCollectPodPreservesExactResponseAndReadOnlyScope(t *testing.T) {
 var hits atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hits.Add(1)
  if r.Method!="GET" || r.URL.RequestURI()!="/api/v1/namespaces/demo/pods/checkout-1" || r.Header.Get("Authorization")!="Bearer readonly-test" {t.Errorf("unexpected request: %s %s",r.Method,r.URL.RequestURI())}
  _,_=fmt.Fprint(w,podResponse)
 }))
 defer srv.Close()
 got,err:=CollectPod(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:podTarget(),BearerToken:"readonly-test"})
 if err!=nil {t.Fatal(err)}
 if hits.Load()!=1 || !bytes.Equal(got.Raw,[]byte(podResponse)) || got.Report.RawSHA256!=fmt.Sprintf("%x",sha256.Sum256(got.Raw)) || got.Report.Assessment.Status!="SIGNALS_PRESENT" || got.Report.SourceAuthenticated {t.Fatalf("wrong observation: %+v",got)}
 replay,err:=poddiagnosis.AssessNative(podTarget(),got.Raw)
 if err!=nil || replay.RawSHA256!=got.Report.RawSHA256 {t.Fatalf("offline replay mismatch: %+v %v",replay,err)}
}

func TestCollectPodRejectsIncompleteResponses(t *testing.T) {
 for name,tc:=range map[string]struct{status int;body string}{
  "forbidden":{403,""},
  "not-found":{404,""},
  "recreated":{200,strings.Replace(podResponse,"pod-uid-1","pod-uid-2",1)},
  "trailing":{200,podResponse+"{}"},
  "oversized":{200,strings.Repeat(" ",poddiagnosis.MaxNativePodBytes+1)},
 } {t.Run(name,func(t *testing.T){
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(tc.status);_,_=fmt.Fprint(w,tc.body)}))
  defer srv.Close()
  got,err:=CollectPod(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:podTarget()})
  if !errors.Is(err,ErrUnknown)||got.Raw!=nil||got.Report.RawSHA256!="" {t.Fatalf("invalid response admitted: %v %v",got.Report,err)}
 })}
}

func TestCollectPodRejectsInvalidTargetBeforeHTTP(t *testing.T) {
 var hits atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){hits.Add(1);w.WriteHeader(403)}))
 defer srv.Close()
 for _,target:=range []poddiagnosis.Target{{Namespace:"demo",Name:"../secrets",UID:"uid"},{Namespace:"demo",Name:"pod"},{Namespace:"a/b",Name:"pod",UID:"uid"}} {
  got,err:=CollectPod(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:target})
  if !errors.Is(err,ErrUnknown)||got.Raw!=nil {t.Fatalf("invalid target admitted: %+v %v",got,err)}
 }
 if hits.Load()!=0 {t.Fatal("invalid target initiated HTTP")}
}

func TestCollectPodNeverFollowsRedirect(t *testing.T) {
 var hits atomic.Int32
 other:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){hits.Add(1)}));defer other.Close()
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,other.URL,http.StatusFound)}));defer srv.Close()
 got,err:=CollectPod(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:podTarget(),BearerToken:"readonly-test",Client:&http.Client{}})
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil||hits.Load()!=0 {t.Fatalf("redirect accepted: %+v %v",got,err)}
}

func TestCollectPodHonorsCanceledContext(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){<-r.Context().Done()}));defer srv.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Millisecond);defer cancel()
 got,err:=CollectPod(ctx,PodConfig{KubernetesURL:srv.URL,Target:podTarget()})
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil {t.Fatalf("canceled request admitted: %+v %v",got,err)}
}
