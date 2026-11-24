package verifier

import (
 "context"
 "io"
 "net/http"
 "strings"
 "testing"
 "time"
)

func budgetResponse(r *http.Request) *http.Response {
 value:="0.1";if r.URL.Query().Get("query")=="sum(rate(checkout_requests_total[30s]))"{value="2"}
 return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader(rangeResponse([]string{value,value,value,value,value},-1))),Header:make(http.Header)}
}

func TestAssessmentSharesOneDeadline(t *testing.T){
 for _,tc:=range []struct{name string;parent time.Duration}{
  {"default-budget",0},{"shorter-parent",4*time.Second},{"longer-parent",time.Minute},
 }{t.Run(tc.name,func(t *testing.T){
  ctx:=context.Background()
  if tc.parent>0 {var cancel context.CancelFunc;ctx,cancel=context.WithTimeout(ctx,tc.parent);defer cancel()}
  start:=time.Now()
  var deadlines []time.Time
  p:=policy("http://127.0.0.1:1")
  p.Client=&http.Client{Timeout:time.Minute,Transport:timeoutTransport(func(r *http.Request)(*http.Response,error){
   deadline,ok:=r.Context().Deadline();if !ok{t.Error("missing request deadline")}
   deadlines=append(deadlines,deadline)
   return budgetResponse(r),nil
  })}
  got:=Assess(ctx,p)
  if got.Status!=Healthy||len(got.Evidence)!=3||len(deadlines)!=3{t.Fatalf("unexpected assessment: %s evidence=%d reads=%d",got.Status,len(got.Evidence),len(deadlines))}
  want:=start.Add(30*time.Second)
  if tc.parent>0&&tc.parent<30*time.Second{want,_=ctx.Deadline()}
  if diff:=deadlines[0].Sub(want);diff< -time.Second||diff>time.Second{t.Errorf("first deadline offset %s",diff)}
  for _,deadline:=range deadlines[1:]{if !deadline.Equal(deadlines[0]){t.Errorf("assessment renewed deadline: %v != %v",deadline,deadlines[0])}}
 })}
}

func TestAssessmentCancellationRejectsLateEvidence(t *testing.T){
 for _,at:=range []int{0,1,2,3}{t.Run(string(rune('0'+at)),func(t *testing.T){
  ctx,cancel:=context.WithCancel(context.Background());defer cancel()
  if at==0{cancel()}
  calls:=0
  p:=policy("http://127.0.0.1:1")
  p.Client=&http.Client{Timeout:time.Minute,Transport:timeoutTransport(func(r *http.Request)(*http.Response,error){
   calls++
   if calls==at{cancel()}
   // A finite but non-cooperative transport may still return valid bytes.
   return budgetResponse(r),nil
  })}
  got:=Assess(ctx,p)
  accepted:=at-1;if accepted<0{accepted=0}
  if got.Status!=Unknown||len(got.Evidence)!=accepted||calls!=at{t.Fatalf("cancelled assessment admitted evidence: status=%s evidence=%d reads=%d",got.Status,len(got.Evidence),calls)}
 })}
}
