package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "flag"
 "fmt"
 "io"
 "net/http"
 "os"
 "strings"
 "time"
 "github.com/avaargsh/sre-agent/internal/observe"
)
func investigate(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("investigate",flag.ContinueOnError)
 flags.SetOutput(stderr)
 kube:=flags.String("kube-api","","Kubernetes API URL (HTTPS remote or loopback proxy)")
 prom:=flags.String("prometheus","","Prometheus URL (HTTPS remote or loopback port-forward)")
 namespace:=flags.String("namespace","","Kubernetes namespace")
 deployment:=flags.String("deployment","","Deployment name")
 incident:=flags.String("incident-id","","stable incident ID")
 summary:=flags.String("summary","","incident summary")
 severity:=flags.String("severity","sev2","incident severity")
 query:=flags.String("query","max(checkout_request_latency_seconds)","bounded instant-vector PromQL")
 outfile:=flags.String("out","","output bundle path (or - for stdout)")
 maxAge:=flags.Duration("max-metric-age",90*time.Second,"freshness budget")
 timeout:=flags.Duration("timeout",15*time.Second,"overall read budget")
 tokenPath:=flags.String("kube-token-file","","read-only Kubernetes bearer token file")
 caPath:=flags.String("ca-file","","optional CA PEM for HTTPS sources")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())>0||*kube==""||*prom==""||*namespace==""||*deployment==""||*incident==""||*summary==""||*outfile==""||*timeout<=0||*timeout>60*time.Second||*maxAge<=0||*maxAge>10*time.Minute{
   fmt.Fprintln(stderr,"invalid investigate arguments; require --kube-api --prometheus --namespace --deployment --incident-id --summary --out and bounded timeouts")
   return 2
 }
 token:=""
 if *tokenPath!=""{
  b,err:=os.ReadFile(*tokenPath)
  if err!=nil{fmt.Fprintln(stderr,"cannot read Kubernetes token file");return 2}
  token=strings.TrimSpace(string(b))
  if token==""{fmt.Fprintln(stderr,"Kubernetes token file is empty");return 2}
 }
 var hc *http.Client
 if *caPath!=""{
  pem,err:=os.ReadFile(*caPath)
  if err!=nil{fmt.Fprintln(stderr,"cannot read CA file");return 2}
  roots,err:=x509.SystemCertPool()
  if err!=nil{fmt.Fprintln(stderr,"cannot read trust store");return 2}
  if !roots.AppendCertsFromPEM(pem){fmt.Fprintln(stderr,"CA file contains no valid certificates");return 2}
  hc=&http.Client{Timeout:*timeout,Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12}}}
 }
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 raw,err:=observe.Collect(ctx,observe.Config{KubernetesURL:*kube,PrometheusURL:*prom,Namespace:*namespace,
  Deployment:*deployment,IncidentID:*incident,Summary:*summary,Severity:*severity,LatencyQuery:*query,
  KubernetesBearerToken:token,MaxMetricAge:*maxAge,Client:hc})
 if err!=nil{
  if errors.Is(err,observe.ErrUnknown){fmt.Fprintln(stderr,"UNKNOWN:",err);return 3}
  fmt.Fprintln(stderr,err);return 1
 }
 raw=append(raw,'\n')
 if *outfile=="-"{if _,err:=stdout.Write(raw);err!=nil{fmt.Fprintln(stderr,err);return 1};return 0}
 file,err:=os.OpenFile(*outfile,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{fmt.Fprintln(stderr,"cannot create new evidence file:",err);return 1}
 n,writeErr:=file.Write(raw)
 if writeErr==nil&&n!=len(raw){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{_ = os.Remove(*outfile);fmt.Fprintln(stderr,"cannot finish evidence file");return 1}
 fmt.Fprintln(stdout,*outfile)
 return 0
}
