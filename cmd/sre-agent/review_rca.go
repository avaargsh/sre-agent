package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"

 "github.com/avaargsh/sre-agent/internal/change"
 "github.com/avaargsh/sre-agent/internal/rca"
 "github.com/avaargsh/sre-agent/internal/verifier"
)

// reviewRCA is a read-only claim-citation checker; exit 0 means a review
// report exists, NOT that an RCA has been confirmed or a service recovered.
func reviewRCA(args []string,stdout,stderr io.Writer)int{
 flags:=flag.NewFlagSet("review-rca",flag.ContinueOnError)
 flags.SetOutput(stderr)
 changes:=flags.String("changes","","frozen Kubernetes change evidence JSON")
 sli:=flags.String("sli","","independently queried SLI assessment JSON")
 candidates:=flags.String("candidates","","agent-proposed candidate hypotheses JSON")
 output:=flags.String("out","-","new review report path or stdout")
 if err:=flags.Parse(args);err!=nil{return 2}
 if len(flags.Args())!=0||*changes==""||*sli==""||*candidates==""||*output==""{
  fmt.Fprintln(stderr,"usage: sre-agent review-rca --changes FILE --sli FILE --candidates FILE [--out NEW_FILE|-]")
  return 2
 }
 read:=func(path string,target any)error{
  file,err:=os.Open(path)
  if err!=nil{return err}
  defer file.Close()
  // Raw Kubernetes evidence inside base64 can be several MiB; cap each input.
  b,err:=io.ReadAll(io.LimitReader(file,16<<20+1))
  if err!=nil||len(b)>(16<<20){return fmt.Errorf("invalid or oversized input")}
  return json.Unmarshal(b,target)
 }
 var c change.Report
 var s verifier.Assessment
 var claims []rca.Candidate
 if err:=read(*changes,&c);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid change report");return 3}
 if err:=read(*sli,&s);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid SLI report");return 3}
 if err:=read(*candidates,&claims);err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid hypotheses");return 3}
 report,err:=rca.Review(c,s,claims)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: claim citation checks failed:",err);return 3}
 serialized,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{fmt.Fprintln(stderr,"could not encode RCA review");return 1}
 serialized=append(serialized,'\n')
 if *output=="-"{
  if _,err:=stdout.Write(serialized);err!=nil{fmt.Fprintln(stderr,"cannot write RCA review");return 1}
  return 0
 }
 file,err:=os.OpenFile(*output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{fmt.Fprintln(stderr,"cannot create review report:",err);return 1}
 n,writeErr:=file.Write(serialized)
 if writeErr==nil&&n!=len(serialized){writeErr=io.ErrShortWrite}
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil||closeErr!=nil{_ = os.Remove(*output);fmt.Fprintln(stderr,"cannot finish RCA review");return 1}
 fmt.Fprintln(stdout,*output)
 return 0
}
