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
)

const podLogsFixture = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`

const podLogTail = "2026-11-24T10:00:00Z startup failed\n2026-11-24T10:00:01Z connection refused\n"

func podLogsConfig(endpoint string) PodLogsConfig {
 return PodLogsConfig{
  PodConfig: PodConfig{KubernetesURL:endpoint,Target:podTarget(),BearerToken:"readonly-test"},
  Container:"app",TailLines:80,
 }
}

func podJSONWithResourceVersion(rv string) string {
 return strings.Replace(podLogsFixture, `"resourceVersion":"42"`, `"resourceVersion":"`+rv+`"`, 1)
}

func TestCollectPodLogsUsesBoundedTailAndUIDFence(t *testing.T) {
 var podReads,logReads atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if r.Method!=http.MethodGet || r.Header.Get("Authorization")!="Bearer readonly-test" {
   t.Errorf("unexpected request method/auth: %s %q",r.Method,r.Header.Get("Authorization"))
  }
  switch r.URL.Path {
  case "/api/v1/namespaces/demo/pods/checkout-1":
   n:=podReads.Add(1)
   if n==1 {_,_=fmt.Fprint(w,podJSONWithResourceVersion("42"))} else {_,_=fmt.Fprint(w,podJSONWithResourceVersion("43"))}
  case "/api/v1/namespaces/demo/pods/checkout-1/log":
   logReads.Add(1)
   q:=r.URL.Query()
   if q.Get("container")!="app" || q.Get("tailLines")!="80" || q.Get("timestamps")!="true" || q.Get("limitBytes")!=fmt.Sprint(maxPodLogBytes) {
    t.Errorf("unexpected bounded log query: %v",q)
   }
   w.Header().Set("Content-Type","text/plain; charset=utf-8")
   _,_=w.Write([]byte(podLogTail))
  default:t.Errorf("unexpected path %s",r.URL.Path);http.NotFound(w,r)
  }
 }))
 defer srv.Close()
 got,err:=CollectPodLogs(context.Background(),podLogsConfig(srv.URL))
 if err!=nil {t.Fatal(err)}
 if podReads.Load()!=2 || logReads.Load()!=1 {t.Fatalf("unexpected read counts: pod=%d logs=%d",podReads.Load(),logReads.Load())}
 if !bytes.Equal(got.Raw,[]byte(podLogTail)) {t.Fatalf("raw log tail changed: %q",got.Raw)}
 if !bytes.Equal(got.BeforePodRaw,[]byte(podJSONWithResourceVersion("42"))) ||
  !bytes.Equal(got.AfterPodRaw,[]byte(podJSONWithResourceVersion("43"))) {
  t.Fatal("pre/post Pod source bytes were not preserved for independent replay")
 }
 if got.Report.Target!=podTarget() || got.Report.Container!="app" || got.Report.TailLines!=80 || got.Report.MaxBytes!=maxPodLogBytes || !got.Report.Timestamps {
  t.Fatalf("wrong report scope: %+v",got.Report)
 }
 if got.Report.BeforeResourceVersion!="42" || got.Report.AfterResourceVersion!="43" {
  t.Fatalf("pre/post resource versions not retained: %+v",got.Report)
 }
 if got.Report.LogsSHA256!=fmt.Sprintf("%x",sha256.Sum256(got.Raw)) || got.Report.SourceAuthenticated {
  t.Fatalf("wrong digest or authority flags: %+v",got.Report)
 }
}

func TestCollectPodLogsRejectsPodUIDReplacementDuringRead(t *testing.T) {
 var podReads atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  switch r.URL.Path {
  case "/api/v1/namespaces/demo/pods/checkout-1":
   if podReads.Add(1)==1 {_,_=fmt.Fprint(w,podLogsFixture)} else {
    _,_=fmt.Fprint(w,strings.Replace(podLogsFixture,"pod-uid-1","pod-uid-2",1))
   }
  case "/api/v1/namespaces/demo/pods/checkout-1/log":
   w.Header().Set("Content-Type","text/plain");_,_=fmt.Fprint(w,podLogTail)
  default:http.NotFound(w,r)
  }
 }))
 defer srv.Close()
 got,err:=CollectPodLogs(context.Background(),podLogsConfig(srv.URL))
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil||got.Report.LogsSHA256!="" {t.Fatalf("replaced Pod log evidence admitted: %+v %v",got,err)}
 if podReads.Load()!=2 {t.Fatalf("post-read UID fence not executed: %d",podReads.Load())}
}

func TestCollectPodLogsRejectsMissingContainerBeforeLogRead(t *testing.T) {
 var logReads atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if strings.HasSuffix(r.URL.Path,"/log") {logReads.Add(1);return}
  body:=strings.Replace(podLogsFixture,`"name":"app"`, `"name":"worker"`, 2)
  _,_=fmt.Fprint(w,body)
 }))
 defer srv.Close()
 got,err:=CollectPodLogs(context.Background(),podLogsConfig(srv.URL))
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil||logReads.Load()!=0 {t.Fatalf("missing container was queried: %+v %v",got,err)}
}

func TestCollectPodLogsRejectsInvalidResponses(t *testing.T) {
 tests:=[]struct{name string;status int;contentType string;body []byte}{
  {"forbidden",http.StatusForbidden,"text/plain",[]byte("denied")},
  {"empty",http.StatusOK,"text/plain",nil},
  {"wrong-content-type",http.StatusOK,"application/json",[]byte("{}")},
  {"wrong-charset",http.StatusOK,"text/plain; charset=iso-8859-1",[]byte("log")},
  {"invalid-utf8",http.StatusOK,"text/plain",[]byte{0xff,0xfe}},
  {"invalid-timestamp",http.StatusOK,"text/plain",[]byte("not-rfc3339 log\n")},
  {"too-many-lines",http.StatusOK,"text/plain",[]byte(strings.Repeat("2026-11-24T10:00:00Z log\n",81))},
  {"at-byte-limit",http.StatusOK,"text/plain",bytes.Repeat([]byte("x"),maxPodLogBytes)},
  {"over-byte-limit",http.StatusOK,"text/plain",bytes.Repeat([]byte("x"),maxPodLogBytes+1)},
 }
 for _,tc:=range tests {t.Run(tc.name,func(t *testing.T) {
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
   if strings.HasSuffix(r.URL.Path,"/log") {w.Header().Set("Content-Type",tc.contentType);w.WriteHeader(tc.status);_,_=w.Write(tc.body);return}
   _,_=fmt.Fprint(w,podLogsFixture)
  }))
  defer srv.Close()
  got,err:=CollectPodLogs(context.Background(),podLogsConfig(srv.URL))
  if !errors.Is(err,ErrUnknown)||got.Raw!=nil||got.Report.LogsSHA256!="" {t.Fatalf("invalid logs admitted: %+v %v",got,err)}
 })}
}

func TestCollectPodLogsRejectsInvalidScopeBeforeHTTP(t *testing.T) {
 var hits atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){hits.Add(1);w.WriteHeader(http.StatusForbidden)}))
 defer srv.Close()
 cases:=[]PodLogsConfig{podLogsConfig(srv.URL),podLogsConfig(srv.URL),podLogsConfig(srv.URL),podLogsConfig(srv.URL)}
 cases[0].Container="../secrets"
 cases[1].TailLines=0
 cases[2].TailLines=maxPodLogTailLines+1
 cases[3].Target.UID="pod-uid-1,involvedObject.name=other"
 for _,cfg:=range cases {
  got,err:=CollectPodLogs(context.Background(),cfg)
  if !errors.Is(err,ErrUnknown)||got.Raw!=nil {t.Fatalf("invalid scope admitted: %+v %v",got,err)}
 }
 if hits.Load()!=0 {t.Fatalf("invalid scope initiated HTTP: %d",hits.Load())}
}

func TestCollectPodLogsNeverFollowsRedirect(t *testing.T) {
 var otherHits atomic.Int32
 other:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){otherHits.Add(1)}))
 defer other.Close()
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if strings.HasSuffix(r.URL.Path,"/log") {http.Redirect(w,r,other.URL,http.StatusFound);return}
  _,_=fmt.Fprint(w,podLogsFixture)
 }))
 defer srv.Close()
 got,err:=CollectPodLogs(context.Background(),podLogsConfig(srv.URL))
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil||otherHits.Load()!=0 {t.Fatalf("redirect followed: %+v %v",got,err)}
}

func TestCollectPodLogsHonorsEarlierCallerDeadline(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if strings.HasSuffix(r.URL.Path,"/log") {<-r.Context().Done();return}
  _,_=fmt.Fprint(w,podLogsFixture)
 }))
 defer srv.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Millisecond);defer cancel()
 got,err:=CollectPodLogs(ctx,podLogsConfig(srv.URL))
 if !errors.Is(err,ErrUnknown)||got.Raw!=nil {t.Fatalf("expired caller context admitted: %+v %v",got,err)}
}
