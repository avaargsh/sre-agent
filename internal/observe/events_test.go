package observe

import (
 "context"
 "errors"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
)

func TestCollectPodEventsScopedGET(t *testing.T) {
 var hits atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hits.Add(1)
  if r.Method!="GET" || r.URL.Path!="/api/v1/namespaces/demo/events" || r.URL.Query().Get("fieldSelector")!="involvedObject.uid=pod-uid-1" || r.URL.Query().Get("limit")!="128" || r.Header.Get("Authorization")!="Bearer reader" {t.Errorf("wrong request: %s %s",r.Method,r.URL.RequestURI())}
  _,_=w.Write([]byte(`{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43"},"items":[]}`))
 }));defer srv.Close()
 got,err:=CollectPodEvents(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:podTarget(),BearerToken:"reader"})
 if err!=nil || got.Report.RawSHA256=="" || got.Raw==nil || hits.Load()!=1 {t.Fatalf("wrong result: %+v %v",got,err)}
 target:=podTarget();target.UID="pod-uid-1,involvedObject.name=other"
 got,err=CollectPodEvents(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:target})
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil||hits.Load()!=1 {t.Fatalf("unsafe UID admitted: %+v %v",got,err)}
}
