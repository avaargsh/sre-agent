package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
)
func TestVerifySLICommandHealthyEvidenceAndNoOverwrite(t *testing.T){
 calls:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls++
  if r.Method!="GET"||r.URL.Path!="/api/v1/query_range"{t.Errorf("not readonly: %v",r);w.WriteHeader(403);return}
  start,err:=strconv.ParseInt(r.URL.Query().Get("start"),10,64);if err!=nil{t.Fatal(err)}
  value:="0.18"
  if r.URL.Query().Get("query")=="sum(rate(requests[10s]))"{value="10"}
  if r.URL.Query().Get("query")!="max(latency)"&&r.URL.Query().Get("query")!="sum(rate(requests[10s]))"{t.Errorf("unexpected query: %s",r.URL.RawQuery)}
  _,_=fmt.Fprintf(w,`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[%d,"%s"],[%d,"%s"],[%d,"%s"]]}]}}`,start,value,start+5,value,start+10,value)
 }))
 defer srv.Close()
 path:=filepath.Join(t.TempDir(),"assessment.json")
 args:=[]string{"verify-sli","--prometheus",srv.URL,"--latency-query","max(latency)","--traffic-query","sum(rate(requests[10s]))","--max-latency-seconds","0.35","--min-traffic-rps","0.1","--window","10s","--step","5s","--out",path}
 var stdout,stderr bytes.Buffer
 if exit:=run(args,&stdout,&stderr);exit!=0{t.Fatalf("exit=%d stderr=%s",exit,stderr.String())}
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 var report map[string]any
 if err:=json.Unmarshal(raw,&report);err!=nil{t.Fatal(err)}
 if report["status"]!="HEALTHY"{t.Fatalf("wrong result: %s",raw)}
 if calls!=2{t.Fatalf("expected two independent source reads, got %d",calls)}
 if len(report["evidence"].([]any))!=2{t.Fatalf("missing independently collected raw evidence: %s",raw)}
 if exit:=run(args,&stdout,&stderr);exit!=1{t.Fatal("overwrote existing assessment")}
}
func TestVerifySLICommandUnknownExit3(t *testing.T){
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(503)}))
 defer srv.Close()
 var stdout,stderr bytes.Buffer
 status:=run([]string{"verify-sli","--prometheus",srv.URL,"--latency-query","max(latency)","--traffic-query","sum(rate(requests[10s]))","--max-latency-seconds","0.35","--min-traffic-rps","0.1","--window","10s","--step","5s"},&stdout,&stderr)
 if status!=3||!strings.Contains(stdout.String(),`"status": "UNKNOWN"`){t.Fatalf("expected UNKNOWN exit 3: exit=%d stdout=%s stderr=%s",status,stdout.String(),stderr.String())}
}
