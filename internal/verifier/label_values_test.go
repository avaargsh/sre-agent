package verifier

import (
 "context"
 "fmt"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
 "time"
)

func TestSLIMatrixLabelTypes(t *testing.T) {
 for _,tc:=range []struct{name,metric string;valid bool}{
  {"aggregate",`"metric":{},`,true},
  {"empty-value",`"metric":{"job":""},`,true},
  {"ordinary",`"metric":{"job":"checkout"},`,true},
  {"missing","",false},
  {"null-object",`"metric":null,`,false},
  {"null-value",`"metric":{"job":null},`,false},
  {"empty-name",`"metric":{"":"checkout"},`,false},
  {"number",`"metric":{"job":0},`,false},
  {"boolean",`"metric":{"job":false},`,false},
  {"array",`"metric":[],`,false},
 } {for index,stage:=range []string{"latency","traffic","age"}{t.Run(tc.name+"/"+stage,func(t *testing.T){
  var calls atomic.Int32
  srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   calls.Add(1)
   query:=r.URL.Query().Get("query")
   metric:=`"metric":{"job":"checkout"},`
   if query==stage{metric=tc.metric}
   value:="0.1";if query=="traffic"{value="2"}
   _,_=fmt.Fprintf(w,`{"status":"success","data":{"resultType":"matrix","result":[{%s"values":[[1795350598,%q],[1795350599,%q],[1795350600,%q]]}]}}`,metric,value,value,value)
  }));defer srv.Close()
  p:=Policy{PrometheusURL:srv.URL,LatencyQuery:"latency",TrafficQuery:"traffic",AgeQuery:"age",MaxLatencySeconds:.35,MinTrafficPerSecond:1,MaxSampleAgeSeconds:10,Window:2*time.Second,Step:time.Second,Now:func()time.Time{return time.Unix(1795350600,0)}}
  got:=Assess(context.Background(),p)
  if tc.valid {
   if got.Status!=Healthy||len(got.Evidence)!=3||calls.Load()!=3 {t.Fatalf("valid metric rejected: status=%s evidence=%d reads=%d reason=%s",got.Status,len(got.Evidence),calls.Load(),got.Reason)}
  } else if got.Status!=Unknown||len(got.Evidence)!=index||calls.Load()!=int32(index+1){t.Fatalf("invalid metric admitted: status=%s evidence=%d reads=%d",got.Status,len(got.Evidence),calls.Load())}
 })}}
}
