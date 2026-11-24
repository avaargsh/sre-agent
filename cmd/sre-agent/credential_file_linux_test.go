//go:build linux

package main

import (
 "bytes"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "syscall"
 "testing"
 "time"
)

func TestInvestigateCredentialFileAdmission(t *testing.T) {
 for _, tc := range []struct { name, flag string; size int; fifo, alias bool }{
  {name:"oversized token",flag:"--kube-token-file",size:64*1024+1},
  {name:"oversized CA",flag:"--ca-file",size:1024*1024+1},
  {name:"token FIFO",flag:"--kube-token-file",fifo:true},
  {name:"CA FIFO alias",flag:"--ca-file",fifo:true,alias:true},
  {name:"projected token alias",flag:"--kube-token-file",size:16,alias:true},
 } {
  t.Run(tc.name,func(t *testing.T){
   dir:=t.TempDir()
   file:=filepath.Join(dir,"source")
   if tc.fifo { if err:=syscall.Mkfifo(file,0600);err!=nil{t.Fatal(err)} } else {
    if err:=os.WriteFile(file,bytes.Repeat([]byte("a"),tc.size),0600);err!=nil{t.Fatal(err)}
   }
   input:=file
   if tc.alias { input=filepath.Join(dir,"projected");if err:=os.Symlink(file,input);err!=nil{t.Fatal(err)} }
   var hits atomic.Int32
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){hits.Add(1);w.WriteHeader(http.StatusForbidden)}))
   defer server.Close()
   target:=filepath.Join(dir,"evidence.json")
   args:=[]string{"--kube-api",server.URL,"--prometheus",server.URL,"--namespace","golden-demo","--deployment","checkout-api","--incident-id","inc-001","--summary","latency","--out",target,tc.flag,input}
   var stdout,stderr bytes.Buffer
   done:=make(chan int,1)
   go func(){done<-investigate(args,&stdout,&stderr)}()
   select {
   case exit:=<-done:
    if tc.name=="projected token alias" {
     if exit!=3||hits.Load()!=1 {t.Fatalf("valid projected token rejected: exit=%d hits=%d stderr=%s",exit,hits.Load(),stderr.String())}
    } else if exit!=2||hits.Load()!=0||!strings.Contains(stderr.String(),"cannot read") {
     t.Fatalf("invalid credential admitted: exit=%d hits=%d stderr=%s",exit,hits.Load(),stderr.String())
    }
    if stdout.Len()!=0 {t.Fatal("unexpected stdout")}
    if _,err:=os.Lstat(target);!os.IsNotExist(err){t.Fatal("unexpected evidence file")}
   case <-time.After(2*time.Second):
    if tc.fifo {fd,err:=syscall.Open(file,syscall.O_RDWR|syscall.O_NONBLOCK,0);if err==nil{_ = syscall.Close(fd)}}
    t.Fatal("credential admission blocked")
   }
  })
 }
}
