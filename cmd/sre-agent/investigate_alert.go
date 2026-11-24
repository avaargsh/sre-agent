package main

import (
 "flag"
 "fmt"
 "io"
 "os"
 "strings"
 "time"

 "github.com/avaargsh/sre-agent/internal/alertintake"
)

// investigateAlert only accepts an exact replay of the operator-reviewed
// plan built from original Alertmanager bytes. It never derives credentials,
// source endpoints, scope, query or permission from the untrusted alert.
//
// Once preflight succeeds it delegates all K8s/Prometheus access and the
// no-overwrite Evidence Bundle output to the existing investigate command.
func investigateAlert(args []string,stdout,stderr io.Writer)int {
 flags:=flag.NewFlagSet("investigate-alert",flag.ContinueOnError)
 flags.SetOutput(stderr)
 rawPath:=flags.String("alert-file","","original Alertmanager JSON file")
 planPath:=flags.String("plan","","exact output of plan-alert")
 cluster:=flags.String("cluster","","operator-owned cluster identity")
 namespace:=flags.String("namespace","","operator-owned namespace")
 deployment:=flags.String("deployment","","operator-owned deployment")
 kube:=flags.String("kube-api","","operator-provided Kubernetes API endpoint")
 prom:=flags.String("prometheus","","operator-provided Prometheus URL")
 query:=flags.String("query","","operator-approved instant-vector PromQL")
 output:=flags.String("out","","new Evidence Bundle path or - for stdout")
 tokenPath:=flags.String("kube-token-file","","read-only Kubernetes ServiceAccount bearer token file")
 caPath:=flags.String("ca-file","","optional CA PEM")
 timeout:=flags.Duration("timeout",15*time.Second,"bounded overall observation deadline")
 maxAge:=flags.Duration("max-metric-age",90*time.Second,"Prometheus sample freshness limit")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0||*rawPath==""||*rawPath=="-"||*planPath==""||*planPath=="-"||
  *cluster==""||*namespace==""||*deployment==""||*kube==""||*prom==""||
  *query==""||strings.TrimSpace(*query)==""||*output==""||
  *timeout<=0||*timeout>60*time.Second||*maxAge<=0||*maxAge>10*time.Minute{
  fmt.Fprintln(stderr,"usage: sre-agent investigate-alert --alert-file FILE --plan PLAN --cluster ID --namespace NS --deployment NAME --kube-api URL --prometheus URL --query PROMQL --out NEW_FILE|- [--ca-file CA --kube-token-file TOKEN]")
  return 2
 }
 // Avoid an unnecessary second snapshot if this exact output already exists.
 // This is only a fast-path; investigate still requires atomic O_EXCL and does
 // not promise durable exactly-once operation or cross-host deduplication.
 if *output!="-" {
  if _,err:=os.Lstat(*output);err==nil{
   fmt.Fprintln(stderr,"cannot overwrite an existing evidence artifact")
   return 1
  }else if !os.IsNotExist(err){
   fmt.Fprintln(stderr,"cannot inspect evidence output")
   return 1
  }
 }
 original,err:=boundedAlertFile(*rawPath,alertintake.MaxAlertBytes)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: alert bytes unavailable or over limit");return 3}
 frozen,err:=boundedAlertFile(*planPath,alertintake.MaxPlanBytes)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: plan bytes unavailable or over limit");return 3}
 plan,err:=alertintake.VerifyPlan(original,frozen,alertintake.Target{Cluster:*cluster,Namespace:*namespace,Deployment:*deployment})
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid or stale alert plan:",err);return 3}
 // The verified notification proposes no authority. Operator-provided read
 // endpoints, exact target, query and credentials are handed to the existing
 // scoped, read-only collector. No model call or arbitrary command is issued.
 forwarded:=[]string{
  "--kube-api",*kube,"--prometheus",*prom,
  "--namespace",*namespace,"--deployment",*deployment,
  "--incident-id",plan.IncidentID,"--summary",plan.Summary,
  "--severity",plan.Severity,"--query",*query,"--out",*output,
  "--timeout",timeout.String(),"--max-metric-age",maxAge.String(),
 }
 if *tokenPath!="" {forwarded=append(forwarded,"--kube-token-file",*tokenPath)}
 if *caPath!="" {forwarded=append(forwarded,"--ca-file",*caPath)}
 return investigate(forwarded,stdout,stderr)
}
