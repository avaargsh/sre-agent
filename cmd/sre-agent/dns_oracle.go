package main

import (
 "bytes"
 "encoding/json"
 "flag"
 "fmt"
 "io"

 "github.com/avaargsh/sre-agent/internal/dnsoracle"
)
func diagnoseDNS(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("diagnose-dns",flag.ContinueOnError)
 f.SetOutput(stderr)
 src:=f.String("probe","","frozen read-only Pod log JSON (no operator truth)")
 out:=f.String("out","-","new observation file (or stdout)")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*src==""||*out==""{
  fmt.Fprintln(stderr,"usage: diagnose-dns --probe READ_ONLY_POD_LOG --out NEW_FILE")
  return 2
 }
 raw,err:=readSmallFile(*src,16<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: cannot read DNS observation");return 3}
 result,err:=dnsoracle.Diagnose(raw)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid DNS observation:",err);return 3}
 if err:=writeNewJSON(*out,result,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write DNS observation:",err);return 1}
 return 0
}
func evaluateDNS(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("evaluate-dns",flag.ContinueOnError)
 f.SetOutput(stderr)
 ep:=f.String("episode","","test-admin independent frozen Pod/Service/probe evidence")
 good:=f.String("healthy","","read-only healthy-control observation")
 bad:=f.String("broken","","read-only misconfigured-client observation")
 out:=f.String("out","-","new independent evaluation file")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*ep==""||*good==""||*bad==""||*out==""{
  fmt.Fprintln(stderr,"usage: evaluate-dns --episode FILE --healthy FILE --broken FILE --out NEW_FILE")
  return 2
 }
 raw,err:=readSmallFile(*ep,12<<20);if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing independent episode");return 3}
 graw,err:=readSmallFile(*good,5<<20);if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing healthy observation");return 3}
 braw,err:=readSmallFile(*bad,5<<20);if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: missing broken observation");return 3}
 var episode dnsoracle.Episode
 var healthy,broken dnsoracle.Observation
 if err:=json.NewDecoder(bytes.NewReader(raw)).Decode(&episode);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed independent episode");return 3}
 if err:=json.NewDecoder(bytes.NewReader(graw)).Decode(&healthy);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed healthy observation");return 3}
 if err:=json.NewDecoder(bytes.NewReader(braw)).Decode(&broken);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: malformed broken observation");return 3}
 result,err:=dnsoracle.Evaluate(episode,healthy,broken)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: DNS Oracle evidence rejected:",err);return 3}
 if err:=writeNewJSON(*out,result,stdout);err!=nil{fmt.Fprintln(stderr,"cannot write DNS Oracle result:",err);return 1}
 return 0
}
