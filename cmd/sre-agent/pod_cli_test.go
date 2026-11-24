package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

const cliPod = " \n"+`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-1","uid":"pod-uid-1","resourceVersion":"42"},"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","ready":false,"restartCount":5,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`+"\n"

func cliTargetArgs() []string {return []string{"--namespace","demo","--pod","checkout-1","--uid","pod-uid-1"}}

func TestPodCaptureReplayExactBytes(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET" || r.URL.RequestURI()!="/api/v1/namespaces/demo/pods/checkout-1" {t.Errorf("unexpected request: %s %s",r.Method,r.URL.RequestURI())}
  _,_=fmt.Fprint(w,cliPod)
 }));defer srv.Close()
 var raw,stderr,report bytes.Buffer
 if exit:=capturePod(append(cliTargetArgs(),"--kube-api",srv.URL),&raw,&stderr);exit!=0||raw.String()!=cliPod {t.Fatalf("capture: %d %s",exit,stderr.String())}
 pin:=fmt.Sprintf("%x",sha256.Sum256([]byte(cliPod)))
 if exit:=replayPod(append(cliTargetArgs(),"--sha256",pin),bytes.NewReader(raw.Bytes()),&report,&stderr);exit!=0 {t.Fatalf("replay: %d %s",exit,stderr.String())}
 var got poddiagnosis.NativeReport
 if err:=json.Unmarshal(report.Bytes(),&got);err!=nil||got.RawSHA256!=pin||got.Assessment.Status!="SIGNALS_PRESENT"||got.SourceAuthenticated||got.Assessment.RootCauseVerified||got.Assessment.RecoveryVerified {t.Fatalf("report: %+v %v",got,err)}
}

func TestPodReplayRejectsWrongPinAndUID(t *testing.T) {
 for _,raw:=range []string{cliPod+" ",strings.Replace(cliPod,"pod-uid-1","pod-uid-2",1)} {
  pin:=fmt.Sprintf("%x",sha256.Sum256([]byte(cliPod)))
  if strings.Contains(raw,"pod-uid-2") {pin=fmt.Sprintf("%x",sha256.Sum256([]byte(raw)))}
  var out,stderr bytes.Buffer
  if exit:=replayPod(append(cliTargetArgs(),"--sha256",pin),strings.NewReader(raw),&out,&stderr);exit!=3||out.Len()!=0 {t.Fatalf("invalid replay admitted: %d %s",exit,stderr.String())}
 }
}

func TestPodCaptureFailureEmitsNoRawBytes(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusForbidden);_,_=fmt.Fprint(w,"private error body")}));defer srv.Close()
 var out,stderr bytes.Buffer
 if exit:=capturePod(append(cliTargetArgs(),"--kube-api",srv.URL),&out,&stderr);exit!=3||out.Len()!=0||strings.Contains(stderr.String(),"private error body") {t.Fatalf("failure leaked bytes: %d %s",exit,stderr.String())}
}
