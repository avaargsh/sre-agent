package observe

import (
 "context"
 "errors"
 "fmt"
 "testing"
 "time"
)

// The collector must enforce the same sample-time domain as independent
// offline replay before it declares the snapshot complete.
func TestCollectRejectsOutOfRangePrometheusSampleTime(t *testing.T) {
 for _,tc:=range []struct{name string;seconds int64;bad bool}{
  {"pre-epoch", -1, true},
  {"unix-epoch-zero", 0, true},
  {"ordinary-current-sample", 1795350600, false},
  {"maximum-replayable-timestamp", 9000000000, false},
  {"past-replayable-timestamp", 9000000001, true},
 }{
  t.Run(tc.name,func(t *testing.T){
   sample:=fmt.Sprintf(`[{"metric":{},"value":[%d,"0.18"]}]`,tc.seconds)
   srv,_:=serve(t,sample,false)
   c:=fixture(srv.URL)
   c.Now=func()time.Time{return time.Unix(tc.seconds,0)}
   raw,err:=Collect(context.Background(),c)
   if tc.bad {
    if !errors.Is(err,ErrUnknown)||raw!=nil{
     t.Fatalf("out-of-domain timestamp accepted as complete evidence: ts=%d raw=%q err=%v",tc.seconds,raw,err)
    }
   }else if err!=nil||len(raw)==0{
    t.Fatalf("valid in-domain timestamp rejected: ts=%d rawlen=%d err=%v",tc.seconds,len(raw),err)
   }
  })
 }
}
