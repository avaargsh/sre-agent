package main

import (
 "bytes"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "strings"

 "github.com/avaargsh/sre-agent/internal/endpointoracle"
)
func diagnoseEndpoints(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("diagnose-endpoints",flag.ContinueOnError)
 f.SetOutput(stderr)
 servicePath:=f.String("observed-service","","read-only Service GET response")
 slicesPath:=f.String("observed-endpointslices","","read-only EndpointSlice LIST response for one Service")
 port:=f.Int("expected-target-port",0,"operator-owned healthy target port")
 selector:=f.String("expected-selector","","operator-owned healthy selector key=value")
 out:=f.String("out","-","new prediction output file")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())>0||*servicePath==""||*slicesPath==""||*port<=0||*selector==""||*out==""{
  fmt.Fprintln(stderr,"usage: diagnose-endpoints --observed-service FILE --observed-endpointslices FILE --expected-target-port PORT --expected-selector key=value [--out NEW_FILE|-]")
  return 2
 }
 parts:=strings.SplitN(*selector,"=",2)
 if len(parts)!=2||parts[0]==""||parts[1]==""{fmt.Fprintln(stderr,"UNKNOWN: invalid operator selector");return 3}
 service,err:=readSmallFile(*servicePath,2<<20);if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid Service source");return 3}
 slices,err:=readSmallFile(*slicesPath,2<<20);if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid EndpointSlice source");return 3}
 prediction,err:=endpointoracle.Diagnose(service,slices,*port,map[string]string{parts[0]:parts[1]})
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: endpoint source replay failed:",err);return 3}
 if err:=writeNewJSON(*out,prediction,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write prediction:",err);return 1}
 return 0
}
func evaluateEndpoints(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("evaluate-endpoints",flag.ContinueOnError)
 f.SetOutput(stderr)
 episodePath:=f.String("episode","","test-admin frozen independent episode")
 predictionPath:=f.String("prediction","","observer read-only prediction")
 out:=f.String("out","-","new Oracle score output")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())>0||*episodePath==""||*predictionPath==""||*out==""{
  fmt.Fprintln(stderr,"usage: evaluate-endpoints --episode FILE --prediction FILE [--out NEW_FILE|-]")
  return 2
 }
 b,err:=readSmallFile(*episodePath,12<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing Episode");return 3}
 c,err:=readSmallFile(*predictionPath,6<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing Prediction");return 3}
 var e endpointoracle.Episode
 var p endpointoracle.Prediction
 if err:=json.NewDecoder(bytes.NewReader(b)).Decode(&e);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed Episode");return 3}
 if err:=json.NewDecoder(bytes.NewReader(c)).Decode(&p);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed Prediction");return 3}
 result,err:=endpointoracle.Evaluate(e,p)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: EndpointSlice Oracle evidence invalid:",err);return 3}
 if err:=writeNewJSON(*out,result,stdout);err!=nil{fmt.Fprintln(stderr,"could not save evaluation:",err);return 1}
 return 0
}
