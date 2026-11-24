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

const cliEvents = `{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43"},"items":[{"metadata":{"uid":"event-1","namespace":"demo"},"involvedObject":{"apiVersion":"v1","kind":"Pod","namespace":"demo","name":"checkout-1","uid":"pod-uid-1"},"type":"Warning","reason":"BackOff","message":"private diagnostic text"}]}`+"\n"

func TestEventsCaptureReplay(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET" || r.URL.Path!="/api/v1/namespaces/demo/events" || r.URL.Query().Get("fieldSelector")!="involvedObject.uid=pod-uid-1" {t.Errorf("wrong request: %s %s",r.Method,r.URL.RequestURI())}
  _,_=fmt.Fprint(w,cliEvents)
 }));defer srv.Close()
 var raw,stderr,out bytes.Buffer
 if code:=captureEvents(append(cliTargetArgs(),"--kube-api",srv.URL),&raw,&stderr);code!=0||raw.String()!=cliEvents {t.Fatalf("capture %d %s",code,stderr.String())}
 pin:=fmt.Sprintf("%x",sha256.Sum256(raw.Bytes()))
 if code:=replayEvents(append(cliTargetArgs(),"--sha256",pin),&raw,&out,&stderr);code!=0 {t.Fatalf("replay %d %s",code,stderr.String())}
 var report poddiagnosis.EventReport
 if err:=json.Unmarshal(out.Bytes(),&report);err!=nil||report.RawSHA256!=pin||len(report.Events)!=1||report.Events[0].Reason!="BackOff"||report.SourceAuthenticated||strings.Contains(out.String(),"private diagnostic text") {t.Fatalf("wrong report: %s %v",out.String(),err)}
}

func TestEventsReplayRejectsTamperAndForeignUID(t *testing.T) {
 for _,raw:=range []string{cliEvents+" ",strings.Replace(cliEvents,"pod-uid-1","pod-uid-2",1)} {
  pin:=fmt.Sprintf("%x",sha256.Sum256([]byte(cliEvents)))
  if strings.Contains(raw,"pod-uid-2") {pin=fmt.Sprintf("%x",sha256.Sum256([]byte(raw)))}
  var out,stderr bytes.Buffer
  if code:=replayEvents(append(cliTargetArgs(),"--sha256",pin),strings.NewReader(raw),&out,&stderr);code!=3||out.Len()!=0 {t.Fatalf("invalid replay %d %s",code,stderr.String())}
 }
}

func TestEventsCaptureDeniedNoRawOutput(t *testing.T) {
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(403);_,_=fmt.Fprint(w,"private error")}));defer srv.Close()
 var out,stderr bytes.Buffer
 if code:=captureEvents(append(cliTargetArgs(),"--kube-api",srv.URL),&out,&stderr);code!=3||out.Len()!=0||strings.Contains(stderr.String(),"private error") {t.Fatalf("invalid capture %d %s",code,stderr.String())}
}
