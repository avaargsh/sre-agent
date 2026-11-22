package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "bytes"
 "strings"

 "github.com/avaargsh/sre-agent/internal/oracle"
)

func readSmallFile(path string,max int)([]byte,error){
 f,err:=os.Open(path);if err!=nil{return nil,err}
 defer f.Close()
 raw,err:=io.ReadAll(io.LimitReader(f,int64(max)+1))
 if err!=nil||len(raw)==0||len(raw)>max{return nil,fmt.Errorf("missing, oversized or unreadable file")}
 return raw,nil
}
func writeNewJSON(path string,value any,stdout io.Writer)error{
 data,err:=json.MarshalIndent(value,"","  ")
 if err!=nil{return err}
 data=append(data,'\n')
 if path=="-"{
  _,err=stdout.Write(data)
  return err
 }
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 n,writeErr:=f.Write(data)
 if writeErr==nil&&n<len(data){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil||closeErr!=nil{
  _=os.Remove(path)
  return fmt.Errorf("could not persist Oracle artifact")
 }
 _,err=fmt.Fprintln(stdout,path)
 return err
}
func diagnoseService(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("diagnose-service",flag.ContinueOnError)
 flags.SetOutput(stderr)
 src:=flags.String("observed-service","","frozen read-only Kubernetes Service response")
 expected:=flags.Int("expected-target-port",0,"operator-supplied healthy Service targetPort")
 expectedSelector:=flags.String("expected-selector","","operator-pinned healthy Service selector, e.g. app=checkout-api")
 output:=flags.String("out","-","new prediction JSON file or stdout")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())>0||*src==""||*expected<1||*output==""{
  fmt.Fprintln(stderr,"usage: diagnose-service --observed-service FILE --expected-target-port PORT --out NEW_FILE")
  return 2
 }
 raw,err:=readSmallFile(*src,2<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: read-only Service source unavailable");return 3}
 var prediction oracle.Prediction
 if *expectedSelector!=""{
  parts:=strings.SplitN(*expectedSelector,"=",2)
  if len(parts)!=2||parts[0]==""||parts[1]==""{fmt.Fprintln(stderr,"UNKNOWN: invalid expected selector");return 3}
  prediction,err=oracle.DiagnoseWithSelector(raw,*expected,map[string]string{parts[0]:parts[1]})
 }else{
  prediction,err=oracle.Diagnose(raw,*expected)
 }
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: unable to diagnose Service:",err);return 3}
 if err:=writeNewJSON(*output,prediction,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write new prediction:",err);return 1}
 return 0
}
func evaluateOracle(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("evaluate-oracle",flag.ContinueOnError)
 flags.SetOutput(stderr)
 episodePath:=flags.String("episode","","independent test-admin fault record JSON")
 predictionPath:=flags.String("prediction","","read-only prediction JSON, separately produced")
 output:=flags.String("out","-","new evaluation JSON file or stdout")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())>0||*episodePath==""||*predictionPath==""||*output==""{
  fmt.Fprintln(stderr,"usage: evaluate-oracle --episode FILE --prediction FILE --out NEW_FILE")
  return 2
 }
 a,err:=readSmallFile(*episodePath,10<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing Oracle episode");return 3}
 b,err:=readSmallFile(*predictionPath,4<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing independent read-only prediction");return 3}
 var episode oracle.Episode
 var prediction oracle.Prediction
 if err:=json.NewDecoder(bytes.NewReader(a)).Decode(&episode);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed Oracle episode");return 3}
 if err:=json.NewDecoder(bytes.NewReader(b)).Decode(&prediction);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed read-only prediction");return 3}
 result,err:=oracle.Evaluate(episode,prediction)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid Oracle evidence:",err);return 3}
 if err:=writeNewJSON(*output,result,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write Oracle result:",err);return 1}
 return 0
}
