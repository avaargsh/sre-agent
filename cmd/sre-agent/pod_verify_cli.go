package main

import (
 "crypto/sha256"
 "encoding/hex"
 "flag"
 "fmt"
 "io"
 "strings"

 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

// verifyPodReport consumes the exact snapshot on stdin and an operator-owned
// report file. Its successful result is structural linkage only. Safe named
// file admission relies on the shared boundedAlertFile hardening in PR #57.
func verifyPodReport(args []string,stdin io.Reader,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("verify-pod-report",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 pin:=flags.String("sha256","","independently trusted snapshot SHA-256")
 path:=flags.String("report","","operator-controlled report file")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) || *path=="" || *path=="-" {return 2}
 decoded,err:=hex.DecodeString(*pin)
 if err!=nil || len(decoded)!=sha256.Size || strings.ToLower(*pin)!=*pin {return 2}
 claim,err:=boundedAlertFile(*path,poddiagnosis.MaxNativeReportBytes)
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: invalid Pod receipt input");return 3}
 raw,err:=io.ReadAll(io.LimitReader(stdin,poddiagnosis.MaxNativePodBytes+1))
 if err!=nil || len(raw)>poddiagnosis.MaxNativePodBytes || poddiagnosis.VerifyNativeReportJSON(target,raw,*pin,claim)!=nil {fmt.Fprintln(stderr,"UNKNOWN: Pod receipt verification failed");return 3}
 const result="STRUCTURALLY_LINKED\n"
 if n,err:=io.WriteString(stdout,result);err!=nil || n!=len(result) {fmt.Fprintln(stderr,"cannot write verification result");return 1}
 return 0
}
