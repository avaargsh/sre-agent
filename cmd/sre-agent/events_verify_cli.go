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

// verifyEventsReport checks a separate operator-owned report against raw
// stdin and independent pins. Named-file hardening depends on PR #57.
func verifyEventsReport(args []string,stdin io.Reader,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("verify-events-report",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 pin:=flags.String("sha256","","independently trusted EventList SHA-256")
 path:=flags.String("report","","operator-controlled report file")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) || *path=="" || *path=="-" {return 2}
 decoded,err:=hex.DecodeString(*pin)
 if err!=nil || len(decoded)!=sha256.Size || strings.ToLower(*pin)!=*pin {return 2}
 claim,err:=boundedAlertFile(*path,poddiagnosis.MaxEventReportBytes)
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: invalid EventList receipt input");return 3}
 raw,err:=io.ReadAll(io.LimitReader(stdin,poddiagnosis.MaxNativePodBytes+1))
 if err!=nil || len(raw)>poddiagnosis.MaxNativePodBytes || poddiagnosis.VerifyEventReportJSON(target,raw,*pin,claim)!=nil {fmt.Fprintln(stderr,"UNKNOWN: EventList receipt verification failed");return 3}
 const result="STRUCTURALLY_LINKED\n"
 if n,err:=io.WriteString(stdout,result);err!=nil || n!=len(result) {fmt.Fprintln(stderr,"cannot write verification result");return 1}
 return 0
}
