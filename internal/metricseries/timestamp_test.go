package metricseries

import (
 "math"
 "testing"
)

func TestValidTimestampReplayBounds(t *testing.T){
 for _,tc:=range []struct{name string;value float64;valid bool}{
  {"negative",-1,false},
  {"zero",0,false},
  {"normal",1795350600,true},
  {"upper replayable bound",9000000000,true},
  {"above replayable bound",9000000001,false},
  {"NaN",math.NaN(),false},
  {"positive infinity",math.Inf(1),false},
  {"negative infinity",math.Inf(-1),false},
 }{
  t.Run(tc.name,func(t *testing.T){
   if got:=ValidTimestamp(tc.value);got!=tc.valid{
    t.Fatalf("ValidTimestamp(%v)=%v want %v",tc.value,got,tc.valid)
   }
  })
 }
}
