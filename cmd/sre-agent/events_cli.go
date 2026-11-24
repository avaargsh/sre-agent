package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "strings"
 "time"

 "github.com/avaargsh/sre-agent/internal/observe"
 "github.com/avaargsh/sre-agent/internal/poddiagnosis"
)

// captureEvents uses an operator-approved proxy with namespace event list
// permission. Its UID selector is not an authorization boundary.
func captureEvents(args []string,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("capture-events",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 endpoint:=flags.String("kube-api","","operator-controlled Kubernetes endpoint")
 timeout:=flags.Duration("timeout",15*time.Second,"bounded request deadline")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) || *endpoint=="" || *timeout<=0 || *timeout>30*time.Second {return 2}
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 observation,err:=observe.CollectPodEvents(ctx,observe.PodConfig{KubernetesURL:*endpoint,Target:target})
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: EventList capture rejected");return 3}
 n,err:=stdout.Write(observation.Raw)
 if err!=nil || n!=len(observation.Raw) {fmt.Fprintln(stderr,"cannot write EventList snapshot");return 1}
 return 0
}

// replayEvents requires independent identity and exact-byte digest pins.
func replayEvents(args []string,stdin io.Reader,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("replay-events",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 pin:=flags.String("sha256","","expected lowercase SHA-256 from trusted record")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) {return 2}
 decoded,err:=hex.DecodeString(*pin)
 if err!=nil || len(decoded)!=sha256.Size || strings.ToLower(*pin)!=*pin {return 2}
 raw,err:=io.ReadAll(io.LimitReader(stdin,poddiagnosis.MaxNativePodBytes+1))
 if err!=nil || len(raw)>poddiagnosis.MaxNativePodBytes {fmt.Fprintln(stderr,"UNKNOWN: invalid EventList input");return 3}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=*pin {fmt.Fprintln(stderr,"UNKNOWN: EventList digest mismatch");return 3}
 report,err:=poddiagnosis.AssessEvents(target,raw)
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: EventList validation failed");return 3}
 if err:=json.NewEncoder(stdout).Encode(report);err!=nil {fmt.Fprintln(stderr,"cannot write EventList report");return 1}
 return 0
}
