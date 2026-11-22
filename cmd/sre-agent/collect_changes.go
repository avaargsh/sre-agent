package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net/http"
 "os"
 "strings"
 "time"

 "github.com/avaargsh/sre-agent/internal/change"
)

// collectChanges never writes to Kubernetes and never asserts a causal RCA.
func collectChanges(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("collect-changes",flag.ContinueOnError)
 flags.SetOutput(stderr)
 kube:=flags.String("kube-api","","Kubernetes API URL")
 ns:=flags.String("namespace","","namespace")
 deployment:=flags.String("deployment","","Deployment")
 start:=flags.String("start","","incident window start RFC3339")
 end:=flags.String("end","","incident window end RFC3339")
 tokenFile:=flags.String("kube-token-file","","read-only Kubernetes token file")
 caFile:=flags.String("ca-file","","Kubernetes CA PEM")
 timeout:=flags.Duration("timeout",15*time.Second,"bounded read deadline")
 out:=flags.String("out","-","new report path or - for stdout")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0||*kube==""||*ns==""||*deployment==""||*start==""||*end==""||*out==""||*timeout<=0||*timeout>60*time.Second{
  fmt.Fprintln(stderr,"invalid collect-changes flags");return 2
 }
 windowStart,err:=time.Parse(time.RFC3339,*start)
 if err!=nil{fmt.Fprintln(stderr,"invalid --start");return 2}
 windowEnd,err:=time.Parse(time.RFC3339,*end)
 if err!=nil{fmt.Fprintln(stderr,"invalid --end");return 2}
 token:=""
 if *tokenFile!=""{
  b,err:=os.ReadFile(*tokenFile)
  if err!=nil{fmt.Fprintln(stderr,"cannot read Kubernetes bearer token");return 2}
  token=strings.TrimSpace(string(b))
  if token==""{fmt.Fprintln(stderr,"Kubernetes bearer token missing");return 2}
 }
 var hc *http.Client
 if *caFile!=""{
  pem,err:=os.ReadFile(*caFile)
  if err!=nil{fmt.Fprintln(stderr,"cannot read Kubernetes CA");return 2}
  roots,err:=x509.SystemCertPool()
  if err!=nil{fmt.Fprintln(stderr,"cannot read trust store");return 2}
  if !roots.AppendCertsFromPEM(pem){fmt.Fprintln(stderr,"invalid Kubernetes CA PEM");return 2}
  hc=&http.Client{Timeout:*timeout,Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12}}}
 }
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 result,err:=change.Collect(ctx,change.Config{APIURL:*kube,Namespace:*ns,Deployment:*deployment,
  Token:token,WindowStart:windowStart,WindowEnd:windowEnd,Client:hc})
 if err!=nil{
  if errors.Is(err,change.ErrUnknown){fmt.Fprintln(stderr,"UNKNOWN:",err);return 3}
  fmt.Fprintln(stderr,"change collection failed");return 1
 }
 data,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{fmt.Fprintln(stderr,"could not encode change evidence");return 1}
 data=append(data,'\n')
 if *out=="-"{
  if _,err:=stdout.Write(data);err!=nil{fmt.Fprintln(stderr,"failed to write stdout");return 1}
  return 0
 }
 file,err:=os.OpenFile(*out,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{fmt.Fprintln(stderr,"cannot open new evidence file:",err);return 1}
 n,writeErr:=file.Write(data)
 if writeErr==nil&&n!=len(data){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{_ = os.Remove(*out);fmt.Fprintln(stderr,"could not persist change evidence");return 1}
 fmt.Fprintln(stdout,*out)
 return 0
}
