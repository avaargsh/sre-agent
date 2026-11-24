package observe

import (
 "context"
 "errors"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
)

func TestCollectPodEventsRejectsRemainingItems(t *testing.T) {
 var hits atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  hits.Add(1)
  _,_=w.Write([]byte(`{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43","remainingItemCount":5},"items":[]}`))
 }));defer srv.Close()
 got,err:=CollectPodEvents(context.Background(),PodConfig{KubernetesURL:srv.URL,Target:podTarget()})
 if !errors.Is(err,ErrUnknown) || got.Raw!=nil || got.Report.RawSHA256!="" || hits.Load()!=1 {t.Fatalf("partial list admitted: %+v %v hits=%d",got,err,hits.Load())}
}
