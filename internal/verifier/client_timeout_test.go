package verifier

import (
 "context"
 "io"
 "net/http"
 "strings"
 "testing"
 "time"
)

type timeoutTransport func(*http.Request) (*http.Response,error)
func (f timeoutTransport) RoundTrip(r *http.Request)(*http.Response,error){return f(r)}

// Inspect the real request context at the transport boundary rather than
// sleeping for the default or maximum client timeout.
func TestSLIClientBoundsCustomTimeout(t *testing.T){
 for _,tc:=range []struct{name string;given,want time.Duration}{
  {"zero",0,10*time.Second},
  {"negative",-time.Second,10*time.Second},
  {"short",2*time.Second,2*time.Second},
  {"bounded",15*time.Second,15*time.Second},
  {"excessive",time.Minute,30*time.Second},
 }{t.Run(tc.name,func(t *testing.T){
  calls:=0
  caller:=&http.Client{Timeout:tc.given}
  caller.Transport=timeoutTransport(func(r *http.Request)(*http.Response,error){
   calls++
   deadline,ok:=r.Context().Deadline()
   if !ok {t.Error("missing request deadline")} else if left:=time.Until(deadline);left<=0||left>tc.want||left<tc.want-time.Second {t.Errorf("request deadline remaining=%s want approximately %s",left,tc.want)}
   value:="0.1";if r.URL.Query().Get("query")=="sum(rate(checkout_requests_total[30s]))"{value="2"}
   body:=rangeResponse([]string{value,value,value,value,value},-1)
   return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader(body)),Header:make(http.Header)},nil
  })
  p:=policy("http://127.0.0.1:1");p.Client=caller
  got:=Assess(context.Background(),p)
  if got.Status!=Healthy||calls!=3||len(got.Evidence)!=3{t.Fatalf("unexpected assessment: %s reads=%d evidence=%d reason=%s",got.Status,calls,len(got.Evidence),got.Reason)}
  if caller.Timeout!=tc.given||caller.CheckRedirect!=nil{t.Fatal("caller client mutated")}
 })}
}

func TestSLIClientStopsAfterTransportDeadline(t *testing.T){
 calls:=0
 p:=policy("http://127.0.0.1:1")
 p.Client=&http.Client{Timeout:20*time.Millisecond,Transport:timeoutTransport(func(r *http.Request)(*http.Response,error){
  calls++
  select{case <-r.Context().Done():return nil,r.Context().Err();case <-time.After(time.Second):t.Error("transport deadline did not cancel request");return nil,context.DeadlineExceeded}
 })}
 got:=Assess(context.Background(),p)
 if got.Status!=Unknown||len(got.Evidence)!=0||calls!=1{t.Fatalf("timeout did not fail closed: %s evidence=%d reads=%d",got.Status,len(got.Evidence),calls)}
}
