package dnsoracle

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"

 "github.com/avaargsh/sre-agent/internal/oracle"
)

func frozen(t *testing.T, v any) oracle.Snapshot {
 t.Helper()
 b, err := json.Marshal(v)
 if err != nil { t.Fatal(err) }
 h := sha256.Sum256(b)
 return oracle.Snapshot{ResponseSHA256:hex.EncodeToString(h[:]),RawResponseBase64:base64.StdEncoding.EncodeToString(b)}
}
func fixture(t *testing.T) (Episode, Observation, Observation) {
 t.Helper()
 service := map[string]any{
  "metadata":map[string]any{"name":"checkout-api","namespace":"golden-demo","uid":"svc-1"},
  "spec":map[string]any{"clusterIP":"10.96.0.88","ports":[]any{map[string]any{"port":8080}}},
 }
 pod := func(name,dnsPolicy string,ns []string) map[string]any {
  return map[string]any{
   "metadata":map[string]any{"name":name,"namespace":"golden-demo","uid":name+"-uid"},
   "status":map[string]any{"phase":"Succeeded"},
   "spec":map[string]any{
    "dnsPolicy":dnsPolicy,"dnsConfig":map[string]any{"nameservers":ns},
    "containers":[]any{map[string]any{
      "name":"probe","env":[]any{
       map[string]any{"name":"SERVICE_IP","value":"10.96.0.88"},
       map[string]any{"name":"SERVICE_HOST","value":"checkout-api.golden-demo.svc.cluster.local"},
      },
    }},
   },
  }
 }
 good := Probe{SchemaVersion:"sre.dns-probe/v1",
  Host:"checkout-api.golden-demo.svc.cluster.local",ServiceIP:"10.96.0.88",
  Resolver:"nameserver 10.96.0.10\nsearch golden-demo.svc.cluster.local\n",
  DNSOK:true,DNSAddresses:[]string{"10.96.0.88"},DNSError:"",
  NameHTTPStatus:200,DirectHTTPStatus:200,
 }
 bad := Probe{SchemaVersion:"sre.dns-probe/v1",
  Host:good.Host,ServiceIP:good.ServiceIP,
  Resolver:"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
  DNSOK:false,DNSAddresses:[]string{},DNSError:"name resolution failed",
  NameHTTPStatus:0,DirectHTTPStatus:200,
 }
 e := Episode{SchemaVersion:"sre.dns-oracle/v1",EpisodeID:"dns-001",
  Service:frozen(t,service),
  HealthyPod:frozen(t,pod("dns-good","ClusterFirst",nil)),
  BrokenPod:frozen(t,pod("dns-bad","None",[]string{"127.0.0.1"})),
  HealthyProbe:frozen(t,good),BrokenProbe:frozen(t,bad),
 }
 bGood,_:=json.Marshal(good)
 bBad,_:=json.Marshal(bad)
 g,err:=Diagnose(bGood);if err!=nil{t.Fatal(err)}
 b,err:=Diagnose(bBad);if err!=nil{t.Fatal(err)}
 return e,g,b
}
func TestDNSOnlyFaultAndHealthyControlHaveIndependentTruth(t *testing.T){
 e,g,b:=fixture(t)
 if g.Classification!="HEALTHY_NAME_AND_IP"||b.Classification!="DNS_FAILURE_WITH_IP_REACHABLE"{
  t.Fatalf("wrong initial probe classification %+v %+v",g,b)
 }
 result,err:=Evaluate(e,g,b)
 if err!=nil{t.Fatal(err)}
 if result.Verdict!="MATCHED_ISOLATED_DNS_FAULT"||result.ProductionCausalityVerified{
  t.Fatalf("unsafe result %+v",result)
 }
}
func TestDNSContradictionMustAbstainInsteadOfGuessing(t *testing.T){
 _,g,_:=fixture(t)
 raw,err:=base64.StdEncoding.DecodeString(g.Observed.RawResponseBase64)
 if err!=nil{t.Fatal(err)}
 var p Probe
 if err:=json.Unmarshal(raw,&p);err!=nil{t.Fatal(err)}
 for name,edit:=range map[string]func(*Probe){
  "both-fail":func(p *Probe){p.DNSOK=false;p.DNSAddresses=nil;p.DNSError="failure";p.NameHTTPStatus=0;p.DirectHTTPStatus=0},
  "dns-ok-ip-fail":func(p *Probe){p.DirectHTTPStatus=0},
  "dns-fail-name-http-ok":func(p *Probe){p.DNSOK=false;p.DNSAddresses=nil;p.DNSError="failure"},
  "dns-success-no-addresses":func(p *Probe){p.DNSAddresses=nil},
 }{
  t.Run(name,func(t *testing.T){
   q:=p;edit(&q)
   b,err:=json.Marshal(q);if err!=nil{t.Fatal(err)}
   v,err:=Diagnose(b);if err!=nil{t.Fatal(err)}
   if v.Classification!="UNKNOWN"{t.Fatalf("must abstain on contradictory evidence %+v",v)}
  })
 }
}
func TestDNSOracleRejectsForgedObserverAndAdminSources(t *testing.T){
 cases:=map[string]func(*Episode,*Observation,*Observation){
  "false-class":func(_ *Episode,_ *Observation,b *Observation){b.Classification="DNS_ROOT_CAUSE_CONFIRMED"},
  "swapped-sources":func(_ *Episode,g *Observation,b *Observation){g.Observed,b.Observed=b.Observed,g.Observed},
  "wrong-admin-digest":func(e *Episode,_ *Observation,_ *Observation){e.BrokenPod.ResponseSHA256="0"},
  "wrong-service":func(e *Episode,_ *Observation,_ *Observation){e.Service.ResponseSHA256="00"},
  "wrong-observer-sha":func(_ *Episode,_ *Observation,b *Observation){b.Observed.ResponseSHA256="0"},
  "mismatched-ip":func(e *Episode,_ *Observation,b *Observation){b.ServiceIP="10.0.0.1"},
  "missing-broken-observation":func(e *Episode,_ *Observation,_ *Observation){e.BrokenProbe.RawResponseBase64=""},
 }
 for name,edit:=range cases{
  t.Run(name,func(t *testing.T){
   e,g,b:=fixture(t)
   edit(&e,&g,&b)
   if _,err:=Evaluate(e,g,b);err==nil{t.Fatal("accepted forged DNS Oracle")}
  })
 }
}
func TestDNSEpisodeRejectsUntrustedOrOutOfScopePod(t *testing.T){
 e,g,b:=fixture(t)
 for name,mutate:=range map[string]func(map[string]any){
  "wrong-namespace":func(m map[string]any){m["metadata"].(map[string]any)["namespace"]="kube-system"},
  "changed-dnspolicy":func(m map[string]any){m["spec"].(map[string]any)["dnsPolicy"]="ClusterFirst"},
  "wrong-nameserver":func(m map[string]any){m["spec"].(map[string]any)["dnsConfig"]=map[string]any{"nameservers":[]string{"1.1.1.1"}}},
  "pod-never-completed":func(m map[string]any){m["status"].(map[string]any)["phase"]="Pending"},
 }{
  t.Run(name,func(t *testing.T){
   copy:=e
   raw,_:=base64.StdEncoding.DecodeString(e.BrokenPod.RawResponseBase64)
   var m map[string]any
   if err:=json.Unmarshal(raw,&m);err!=nil{t.Fatal(err)}
   mutate(m);copy.BrokenPod=frozen(t,m)
   if _,err:=Evaluate(copy,g,b);err==nil{t.Fatal("accepted forged operator-injected truth")}
  })
 }
}
func TestDNSProbeRejectsMalformedOrAmbiguousJSON(t *testing.T){
 for _,s:=range []string{
  "",
  "[]",
  `{"schema_version":"sre.dns-probe/v1","schema_version":"sre.dns-probe/v1"}`,
  `{"schema_version":"sre.dns-probe/v1","host":"bad"}{}`,
  `{"schema_version":"sre.dns-probe/v1","host":"bad","unknown_operator_permission":true}`,
 }{
  if _,err:=Diagnose([]byte(s));err==nil{t.Fatalf("accepted malformed probe %s",s)}
 }
}

func TestDirectIPRetryHistoryIsAuditableAndConsistent(t *testing.T){
 e,_,b:=fixture(t)
 raw,err:=base64.StdEncoding.DecodeString(e.BrokenProbe.RawResponseBase64)
 if err!=nil{t.Fatal(err)}
 var probe Probe
 if err:=json.Unmarshal(raw,&probe);err!=nil{t.Fatal(err)}
 probe.DirectHTTPAttempts=[]int{0,0,200}
 probe.DirectHTTPErrors=[]string{"connection refused","timeout",""}
 replay,_:=json.Marshal(probe)
 good,err:=Diagnose(replay)
 if err!=nil||good.Classification!="DNS_FAILURE_WITH_IP_REACHABLE"{
  t.Fatalf("bounded convergence trace should allow final successful direct IP %+v %v",good,err)
 }
 for name,edit:=range map[string]func(*Probe){
  "inconsistent-final-status":func(p *Probe){p.DirectHTTPAttempts=[]int{0,0}},
  "overlong-attempt-history":func(p *Probe){p.DirectHTTPAttempts=make([]int,20)},
  "invalid-intermediate-status":func(p *Probe){p.DirectHTTPAttempts=[]int{999,200}},
  "inconsistent-errors-length":func(p *Probe){p.DirectHTTPErrors=[]string{"only one"}},
 }{
  t.Run(name,func(t *testing.T){
   test:=probe
   edit(&test)
   data,_:=json.Marshal(test)
   if _,err:=Diagnose(data);err==nil{t.Fatal("accepted malformed convergence history")}
  })
 }
 _=b
}

func TestDNSSuccessToWrongAddressCannotProveHealthyService(t *testing.T){
 e,_,bad:=fixture(t)
 raw,err:=base64.StdEncoding.DecodeString(e.HealthyProbe.RawResponseBase64)
 if err!=nil{t.Fatal(err)}
 var p Probe
 if err:=json.Unmarshal(raw,&p);err!=nil{t.Fatal(err)}
 p.DNSAddresses=[]string{"203.0.113.7"}
 bytes,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 obs,err:=Diagnose(bytes)
 if err!=nil{t.Fatal(err)}
 if obs.Classification!="UNKNOWN"{
  t.Fatalf("DNS name resolved outside pinned Service IP, must abstain: %+v",obs)
 }
 e.HealthyProbe=frozen(t,p)
 if _,err:=Evaluate(e,obs,bad);err==nil{t.Fatal("accepted wrong resolved address as a genuine healthy control")}
}
