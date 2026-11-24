package observe

import (
 "context"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

type observeRoundTripFunc func(*http.Request)(*http.Response,error)
func(f observeRoundTripFunc)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}

func TestCollectSharesOneDeadlineAcrossSourceReads(t *testing.T){
 var calls atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls.Add(1)
  time.Sleep(45*time.Millisecond)
  switch r.URL.Path {
  case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
   _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`)
  case "/api/v1/namespaces/golden-demo/pods":
   _,_=fmt.Fprint(w,`{"metadata":{"resourceVersion":"2"},"items":[]}`)
  case "/api/v1/query":
   _,_=fmt.Fprint(w,`{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
  default:w.WriteHeader(http.StatusNotFound)
  }
 }));defer srv.Close()
 raw,err:=collectWithBudget(context.Background(),fixture(srv.URL),90*time.Millisecond)
 if !errors.Is(err,ErrUnknown)||raw!=nil{t.Fatalf("budget exhaustion must fail closed: bytes=%d err=%v",len(raw),err)}
 if calls.Load()<2||calls.Load()>3{t.Fatalf("unexpected source reads before shared budget expired: %d",calls.Load())}
}

func TestCollectHonorsEarlierCallerDeadline(t *testing.T){
 var calls atomic.Int32
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls.Add(1);time.Sleep(100*time.Millisecond)
  _,_=fmt.Fprint(w,`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`)
 }));defer srv.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Millisecond);defer cancel()
 raw,err:=collectWithBudget(ctx,fixture(srv.URL),time.Second)
 if !errors.Is(err,ErrUnknown)||raw!=nil{t.Fatalf("caller deadline must fail closed: bytes=%d err=%v",len(raw),err)}
 if calls.Load()!=1{t.Fatalf("expected only first read, got %d",calls.Load())}
}

func TestCollectRejectsResponseReturnedAfterCancellation(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 var calls atomic.Int32
 caller:=&http.Client{Transport:observeRoundTripFunc(func(r *http.Request)(*http.Response,error){
  calls.Add(1)
  cancel()
  body:=`{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`
  return &http.Response{StatusCode:http.StatusOK,Body:io.NopCloser(strings.NewReader(body)),Header:make(http.Header)},nil
 })}
 c:=fixture("http://127.0.0.1:1");c.Client=caller
 raw,err:=collectWithBudget(ctx,c,time.Second)
 if !errors.Is(err,ErrUnknown)||raw!=nil{t.Fatalf("late source response must fail closed: bytes=%d err=%v",len(raw),err)}
 if calls.Load()!=1{t.Fatalf("canceled collection continued to another source: %d",calls.Load())}
}
