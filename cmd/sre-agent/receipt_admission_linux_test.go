//go:build linux && sre_file_hardening

package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

func TestReceiptAdmissionAfterFileHardening(t *testing.T) {
 target:=poddiagnosis.Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"}
 pod,err:=poddiagnosis.AssessNative(target,[]byte(cliPod));if err!=nil {t.Fatal(err)}
 events,err:=poddiagnosis.AssessEvents(target,[]byte(cliEvents));if err!=nil {t.Fatal(err)}
 for _,tc:=range []struct{name,raw string;report any;verify func([]string,io.Reader,io.Writer,io.Writer)int}{
  {"pod",cliPod,pod,verifyPodReport},{"events",cliEvents,events,verifyEventsReport},
 } {t.Run(tc.name,func(t *testing.T){
  claim,err:=json.Marshal(tc.report);if err!=nil {t.Fatal(err)}
  dir:=t.TempDir();regular:=filepath.Join(dir,"report.json")
  if err:=os.WriteFile(regular,claim,0600);err!=nil {t.Fatal(err)}
  link:=filepath.Join(dir,"alias");if err:=os.Symlink(regular,link);err!=nil {t.Fatal(err)}
  fifo:=filepath.Join(dir,"fifo");if err:=syscall.Mkfifo(fifo,0600);err!=nil {t.Fatal(err)}
  pin:=fmt.Sprintf("%x",sha256.Sum256([]byte(tc.raw)))
  for _,input:=range []struct{name,path string;want int}{{"regular",regular,0},{"symlink",link,3},{"fifo",fifo,3},{"directory",dir,3}} {
   t.Run(input.name,func(t *testing.T){
    type result struct{exit int;stdout string}
    done:=make(chan result,1)
    go func(){var out,stderr bytes.Buffer;args:=[]string{"--namespace",target.Namespace,"--pod",target.Name,"--uid",target.UID,"--sha256",pin,"--report",input.path};code:=tc.verify(args,strings.NewReader(tc.raw),&out,&stderr);done<-result{code,out.String()}}()
    select {case r:=<-done:
     expected:="";if input.want==0 {expected="STRUCTURALLY_LINKED\n"}
     if r.exit!=input.want || r.stdout!=expected {t.Fatalf("exit=%d stdout=%q; expected %d %q",r.exit,r.stdout,input.want,expected)}
    case <-time.After(time.Second):
     if input.name=="fifo" {fd,e:=syscall.Open(fifo,syscall.O_RDWR|syscall.O_NONBLOCK,0);if e==nil {_=syscall.Close(fd)}}
     t.Fatal("report admission blocked")
    }
   })
  }
 })}
}
