package observe

import (
 "context"
 "encoding/json"
 "errors"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/evidence"
)

func TestCollectPreservesSubsecondFreshnessBudget(t *testing.T) {
 srv,_:=serve(t,validSample,false)
 c:=fixture(srv.URL)
 c.MaxMetricAge=250*time.Millisecond
 raw,err:=Collect(context.Background(),c)
 if err!=nil{t.Fatalf("collect failed: %v",err)}
 if _,err:=evidence.Verify(raw);err!=nil{t.Fatalf("unverifiable bundle: %v",err)}
 var doc map[string]any
 if err:=json.Unmarshal(raw,&doc);err!=nil{t.Fatal(err)}
 items:=doc["evidence"].([]any)
 attrs:=items[1].(map[string]any)["attributes"].(map[string]any)
 if got:=attrs["max_age_seconds"];got!="0.25"{
  t.Fatalf("lossy max_age_seconds: got %q want 0.25",got)
 }
}

func TestCollectRejectsFreshnessBudgetBeyondReviewerLimit(t *testing.T){
 c:=fixture("http://127.0.0.1:1")
 c.MaxMetricAge=10*time.Minute+time.Nanosecond
 raw,err:=Collect(context.Background(),c)
 if !errors.Is(err,ErrUnknown)||raw!=nil{
  t.Fatalf("collector must reject unsupported age budget before source reads: raw=%q err=%v",raw,err)
 }
}
