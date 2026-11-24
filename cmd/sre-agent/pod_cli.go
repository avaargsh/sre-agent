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

func podFlags(flags *flag.FlagSet, target *poddiagnosis.Target) {
 flags.StringVar(&target.Namespace,"namespace","","operator-selected namespace")
 flags.StringVar(&target.Name,"pod","","operator-selected Pod name")
 flags.StringVar(&target.UID,"uid","","independently obtained Pod UID")
}

func podTargetPresent(t poddiagnosis.Target) bool {
 return strings.TrimSpace(t.Namespace)!="" && strings.TrimSpace(t.Name)!="" && strings.TrimSpace(t.UID)!=""
}

// capturePod writes only the validated original response to explicit stdout.
// Use an operator-controlled API proxy; this CLI does not accept credentials.
func capturePod(args []string,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("capture-pod",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 endpoint:=flags.String("kube-api","","operator-controlled Kubernetes endpoint")
 timeout:=flags.Duration("timeout",15*time.Second,"bounded request deadline")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) || *endpoint=="" || *timeout<=0 || *timeout>30*time.Second {return 2}
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 observation,err:=observe.CollectPod(ctx,observe.PodConfig{KubernetesURL:*endpoint,Target:target})
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: Pod capture rejected");return 3}
 n,err:=stdout.Write(observation.Raw)
 if err!=nil || n!=len(observation.Raw) {fmt.Fprintln(stderr,"cannot write Pod snapshot");return 1}
 return 0
}

// replayPod trusts neither the supplied bytes nor their self-reported UID.
// The expected digest and target must come from a separate trusted record.
func replayPod(args []string,stdin io.Reader,stdout,stderr io.Writer) int {
 flags:=flag.NewFlagSet("replay-pod",flag.ContinueOnError)
 flags.SetOutput(stderr)
 var target poddiagnosis.Target
 podFlags(flags,&target)
 pin:=flags.String("sha256","","expected lowercase SHA-256 from trusted record")
 if flags.Parse(args)!=nil || len(flags.Args())!=0 || !podTargetPresent(target) {return 2}
 decoded,err:=hex.DecodeString(*pin)
 if err!=nil || len(decoded)!=sha256.Size || strings.ToLower(*pin)!=*pin {return 2}
 raw,err:=io.ReadAll(io.LimitReader(stdin,poddiagnosis.MaxNativePodBytes+1))
 if err!=nil || len(raw)>poddiagnosis.MaxNativePodBytes {fmt.Fprintln(stderr,"UNKNOWN: invalid snapshot input");return 3}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=*pin {fmt.Fprintln(stderr,"UNKNOWN: snapshot digest mismatch");return 3}
 report,err:=poddiagnosis.AssessNative(target,raw)
 if err!=nil {fmt.Fprintln(stderr,"UNKNOWN: snapshot validation failed");return 3}
 if err:=json.NewEncoder(stdout).Encode(report);err!=nil {fmt.Fprintln(stderr,"cannot write report");return 1}
 return 0
}
