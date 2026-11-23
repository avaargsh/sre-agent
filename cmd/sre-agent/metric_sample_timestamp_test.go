package main

import (
 "fmt"
 "testing"
 "time"
)

// Both sides of the frozen Evidence Bundle contract must reject timestamps
// that cannot be independently replayed, regardless of the collection clock.
func TestOfflineSampleTimestampDomainMatchesCollector(t *testing.T) {
 for _,tc:=range []struct{name string;unixSeconds int64;invalid bool}{
  {"pre epoch",-1,true},
  {"epoch",0,true},
  {"normal",1795350600,false},
  {"last replayable second",9000000000,false},
  {"after replayable domain",9000000001,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   attrs:=map[string]any{
    "samples_json":fmt.Sprintf(`[{"metric":{},"timestamp":%d,"value":"0.2"}]`,tc.unixSeconds),
    "series_count":"1",
    "max_age_seconds":"90",
   }
   observed:=time.Unix(tc.unixSeconds,0).UTC()
   err:=validateEmbeddedSamples(attrs,observed)
   if (err!=nil)!=tc.invalid{
    t.Fatalf("offline timestamp %d: err=%v invalid=%v",tc.unixSeconds,err,tc.invalid)
   }
  })
 }
}
