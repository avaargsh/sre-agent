package verifier

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
 "time"
)

func TestSLIDecimalSampleAdmission(t *testing.T) {
 now := time.Unix(1795350600, 0).UTC()
 for _,tc := range []struct{name, sample string; valid bool}{
  {"decimal", "0.2", true},
  {"scientific", "2e-1", true},
  {"hex", "0x1p-2", false},
  {"upper-hex", "0X1P-2", false},
  {"separator", "0_0.2", false},
  {"exponent-separator", "2e-0_1", false},
 } {
  for index,stage := range []string{"latency", "traffic", "age"} {
   t.Run(tc.name+"/"+stage,func(t *testing.T){
    var calls atomic.Int32
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
     calls.Add(1)
     v := "0.2"
     if r.URL.Query().Get("query")==stage {v=tc.sample}
     rows:=make([][]any,0,3)
     for i:=0;i<3;i++ {rows=append(rows,[]any{now.Unix()-10+int64(i)*5,v})}
     _=json.NewEncoder(w).Encode(map[string]any{"status":"success","data":map[string]any{"resultType":"matrix","result":[]any{map[string]any{"metric":map[string]string{},"values":rows}}}})
    }))
    defer srv.Close()
    got:=Assess(context.Background(),Policy{PrometheusURL:srv.URL,LatencyQuery:"latency",TrafficQuery:"traffic",AgeQuery:"age",MaxLatencySeconds:1,MinTrafficPerSecond:.1,MaxSampleAgeSeconds:1,Window:10*time.Second,Step:5*time.Second,Now:func()time.Time{return now}})
    if tc.valid {
     if got.Status!=Healthy||len(got.Evidence)!=3||calls.Load()!=3 {t.Fatalf("valid sample refused: %s (%s)",got.Status,got.Reason)}
    } else if got.Status!=Unknown||len(got.Evidence)!=index||calls.Load()!=int32(index+1) {t.Fatalf("invalid sample admitted: status=%s evidence=%d reads=%d",got.Status,len(got.Evidence),calls.Load())}
   })
  }
 }
}
