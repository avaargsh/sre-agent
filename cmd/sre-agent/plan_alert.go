package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"

 "github.com/avaargsh/sre-agent/internal/alertintake"
)

// planAlert converts a bounded Alertmanager JSON file to a scoped read-only
// proposal. It never invokes Kubernetes, Prometheus, ACP or an action executor.
func planAlert(args []string,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("plan-alert",flag.ContinueOnError)
 flags.SetOutput(stderr)
 path:=flags.String("file","","Alertmanager webhook JSON file, or - for stdin")
 cluster:=flags.String("cluster","","operator-owned cluster scope")
 namespace:=flags.String("namespace","","operator-owned Kubernetes namespace")
 deployment:=flags.String("deployment","","operator-owned Deployment name")
 out:=flags.String("out","","new plan artifact path or - for stdout")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0 || *path=="" || *cluster=="" || *namespace=="" || *deployment=="" || *out=="" {
  fmt.Fprintln(stderr,"usage: sre-agent plan-alert --file FILE|- --cluster ID --namespace NS --deployment NAME --out NEW_FILE|-")
  return 2
 }
 var source io.Reader=os.Stdin
 if *path!="-" {
  f,err:=os.Open(*path)
  if err!=nil{fmt.Fprintln(stderr,"cannot open alert file");return 1}
  defer f.Close()
  source=f
 }
 raw,err:=io.ReadAll(io.LimitReader(source,alertintake.MaxAlertBytes+1))
 if err!=nil{fmt.Fprintln(stderr,"cannot read alert file");return 1}
 plan,err:=alertintake.Parse(raw,alertintake.Target{
  Cluster:*cluster,Namespace:*namespace,Deployment:*deployment,
 })
 if err!=nil{
  if errors.Is(err,alertintake.ErrUnknown){fmt.Fprintln(stderr,"UNKNOWN:",err);return 3}
  fmt.Fprintln(stderr,"invalid alert plan:",err)
  return 1
 }
 data,err:=json.MarshalIndent(plan,"","  ")
 if err!=nil{fmt.Fprintln(stderr,"cannot serialize alert plan");return 1}
 data=append(data,'\n')
 if *out=="-" {
  if _,err:=stdout.Write(data);err!=nil{fmt.Fprintln(stderr,"cannot write alert plan");return 1}
  return 0
 }
 f,err:=os.OpenFile(*out,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{fmt.Fprintln(stderr,"cannot create new alert plan:",err);return 1}
 n,writeErr:=f.Write(data)
 if writeErr==nil&&n!=len(data){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil||closeErr!=nil{
  _=os.Remove(*out)
  fmt.Fprintln(stderr,"cannot finish alert plan")
  return 1
 }
 fmt.Fprintln(stdout,*out)
 return 0
}
