package main

import (
 "bytes"
 "encoding/json"
 "flag"
 "fmt"
 "io"

 "github.com/avaargsh/sre-agent/internal/networkpolicyoracle"
 "github.com/avaargsh/sre-agent/internal/dnsoracle"
)

func evaluateNetworkPolicy(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("evaluate-networkpolicy",flag.ContinueOnError)
 flags.SetOutput(stderr)
 ep:=flags.String("episode","","test-admin frozen NetworkPolicy phase evidence JSON")
 bef:=flags.String("before","","read-only baseline Pod log diagnosis JSON")
 dur:=flags.String("during","","read-only policy-isolated Pod log diagnosis JSON")
 aft:=flags.String("after","","read-only restored Pod log diagnosis JSON")
 out:=flags.String("out","-","new offline Oracle result")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0||*ep==""||*bef==""||*dur==""||*aft==""||*out==""{
  fmt.Fprintln(stderr,"usage: evaluate-networkpolicy --episode FILE --before FILE --during FILE --after FILE --out NEW_FILE")
  return 2
 }
 raw,err:=readSmallFile(*ep,16<<20)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing independent policy episode");return 3}
 var e networkpolicyoracle.Episode
 if err:=json.NewDecoder(bytes.NewReader(raw)).Decode(&e);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid policy episode");return 3}
 var observations [3]dnsoracle.Observation
 for i,path:=range []string{*bef,*dur,*aft}{
  raw,readErr:=readSmallFile(path,4<<20)
  if readErr!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing restricted observer log");return 3}
  if err:=json.NewDecoder(bytes.NewReader(raw)).Decode(&observations[i]);err!=nil{
   fmt.Fprintln(stderr,"UNKNOWN: malformed restricted observer diagnosis");return 3
  }
 }
 result,err:=networkpolicyoracle.Evaluate(e,observations)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: NetworkPolicy evidence rejected:",err);return 3}
 if err:=writeNewJSON(*out,result,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write evidence:",err);return 1}
 return 0
}
