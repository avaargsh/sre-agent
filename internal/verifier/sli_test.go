package verifier

import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

var fixtureNow = time.Unix(1795350600, 0).UTC()
func policy(url string) Policy {
 return Policy{PrometheusURL:url,LatencyQuery:"max(checkout_request_latency_seconds)",TrafficQuery:"sum(rate(checkout_requests_total[30s]))",MaxLatencySeconds:.35,MinTrafficPerSecond:.1,Window:20*time.Second,Step:5*time.Second,Now:func()time.Time{return fixtureNow}}
}
func rangeResponse(values []string, omit int) string {
 rows:=make([][]any,0)
 for i,v:=range values{
  if i==omit{continue}
  rows=append(rows,[]any{float64(fixtureNow.Unix()-20+int64(i)*5),v})
 }
 response,_:=json.Marshal(map[string]any{"status":"success","data":map[string]any{"resultType":"matrix","result":[]any{map[string]any{"metric":map[string]any{"job":"checkout"},"values":rows}}}})
 return string(response)
}
func serveRange(t *testing.T, latency,traffic string)(*httptest.Server,*[]string){
 t.Helper()
 calls:=&[]string{}
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  *calls=append(*calls,r.Method+" "+r.URL.Path)
  if r.URL.Path!="/api/v1/query_range"{w.WriteHeader(404);return}
  if r.URL.Query().Get("start")!="1795350580"||r.URL.Query().Get("end")!="1795350600"||r.URL.Query().Get("step")!="5"{t.Errorf("unexpected bounded range: %s",r.URL.RawQuery)}
  switch r.URL.Query().Get("query"){
  case "max(checkout_request_latency_seconds)":_,_=fmt.Fprint(w,latency)
  case "sum(rate(checkout_requests_total[30s]))":_,_=fmt.Fprint(w,traffic)
  default:t.Errorf("unexpected query: %s",r.URL.RawQuery);w.WriteHeader(400)
  }
 }))
 t.Cleanup(srv.Close)
 return srv,calls
}
func TestHealthyRequiresSustainedLatencyAndTraffic(t *testing.T){
 latency:=rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"},-1)
 traffic:=rangeResponse([]string{"1","2","3","2","1"},-1)
 srv,calls:=serveRange(t,latency,traffic)
 got:=Assess(context.Background(),policy(srv.URL))
 if got.Status!=Healthy{t.Fatalf("status=%s reason=%s",got.Status,got.Reason)}
 if len(got.Evidence)!=2||got.Evidence[0].ResponseSHA256==""||got.Evidence[0].RawResponse==nil{t.Fatalf("source proof missing: %+v",got)}
 if len(*calls)!=2||(*calls)[0]!="GET /api/v1/query_range"||(*calls)[1]!="GET /api/v1/query_range"{t.Fatalf("not exactly two readonly requests: %v",*calls)}
}
func TestUnhealthyWhenOneLatencySampleBreaches(t *testing.T){
 latency:=rangeResponse([]string{"0.12","0.15","0.6","0.16","0.18"},-1)
 traffic:=rangeResponse([]string{"1","2","3","2","1"},-1)
 srv,_:=serveRange(t,latency,traffic)
 got:=Assess(context.Background(),policy(srv.URL))
 if got.Status!=Unhealthy{t.Fatalf("breach must fail: %+v",got)}
}
func TestUnknownOnMissingTrafficOrMissingSamples(t *testing.T){
 good:=rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"},-1)
 noTraffic:=rangeResponse([]string{"0","0","0","0","0"},-1)
 gap:=rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"},2)
 for name,pair:=range map[string][2]string{
  "idle":{good,noTraffic},
  "gap":{gap,good},
  "bad-json":{`{broken`,good},
  "stale":{strings.Replace(good,"1795350580","1795350500",1),good},
  "nan":{strings.Replace(good,"\"0.20\"","\"NaN\"",1),good},
 }{
  t.Run(name,func(t *testing.T){
   srv,_:=serveRange(t,pair[0],pair[1])
   got:=Assess(context.Background(),policy(srv.URL))
   if got.Status!=Unknown{t.Fatalf("expected UNKNOWN; got=%+v",got)}
  })
 }
}
func TestRejectsInvalidPolicyAndRedirect(t *testing.T){
 for _,tc:=range []func(Policy)Policy{
  func(p Policy)Policy{p.Window=0;return p},
  func(p Policy)Policy{p.Step=0;return p},
  func(p Policy)Policy{p.MaxLatencySeconds=-1;return p},
  func(p Policy)Policy{p.TrafficQuery="";return p},
  func(p Policy)Policy{p.PrometheusURL="http://example.com";return p},
 }{
  got:=Assess(context.Background(),tc(policy("http://127.0.0.1:1")))
  if got.Status!=Unknown{t.Fatalf("invalid policy accepted: %+v",got)}
 }
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,"http://example.com",302)}))
 defer srv.Close()
 if got:=Assess(context.Background(),policy(srv.URL));got.Status!=Unknown{t.Fatalf("redirect accepted: %+v",got)}
}
func TestTrustedWindowBarrierPreventsPreActionSamples(t *testing.T){
 latency:=rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"},-1)
 traffic:=rangeResponse([]string{"1","2","3","2","1"},-1)
 srv,_:=serveRange(t,latency,traffic)
 p:=policy(srv.URL)
 p.NotBefore=fixtureNow.Add(-10*time.Second)
 got:=Assess(context.Background(),p)
 if got.Status!=Unknown||len(got.Evidence)!=0{t.Fatalf("pre-action window was accepted: %+v",got)}
}
func TestDuplicateSeriesRejectedEvenWhenMetricsHealthy(t *testing.T){
 one:=rangeResponse([]string{"0.12","0.15","0.20","0.16","0.18"},-1)
 var root map[string]any
 if err:=json.Unmarshal([]byte(one),&root);err!=nil{t.Fatal(err)}
 d:=root["data"].(map[string]any)
 series:=d["result"].([]any)
 d["result"]=append(series,series[0])
 duplicated,err:=json.Marshal(root)
 if err!=nil{t.Fatal(err)}
 srv,_:=serveRange(t,string(duplicated),one)
 got:=Assess(context.Background(),policy(srv.URL))
 if got.Status!=Unknown{t.Fatalf("duplicate metric accepted: %+v",got)}
}
