package main

import (
 "context"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "time"

 "github.com/avaargsh/sre-agent/internal/verifier"
)

// verifySLI only evaluates source SLI; HEALTHY is not incident recovery.
func verifySLI(args []string, stdout, stderr io.Writer) int {
 flags := flag.NewFlagSet("verify-sli", flag.ContinueOnError)
 flags.SetOutput(stderr)
 prom := flags.String("prometheus", "", "Prometheus URL (HTTPS or loopback HTTP)")
 latency := flags.String("latency-query", "", "operator-selected latency query")
 traffic := flags.String("traffic-query", "", "operator-selected traffic rate query")
 age := flags.String("age-query", "", "operator-selected max scrape age query")
 maxAge := flags.Float64("max-sample-age-seconds", 0, "maximum observed scrape age in seconds")
 threshold := flags.Float64("max-latency-seconds", 0, "maximum allowed latency")
 minTraffic := flags.Float64("min-traffic-rps", 0, "minimum required request rate")
 window := flags.Duration("window", 30*time.Second, "evaluation window")
 step := flags.Duration("step", 5*time.Second, "query sample step")
 timeout := flags.Duration("timeout", 15*time.Second, "maximum request time")
 barrier := flags.String("not-before", "", "optional trusted SLI window lower bound, RFC3339")
 outfile := flags.String("out", "-", "result evidence JSON file (default stdout)")
 if err := flags.Parse(args); err != nil {return 2}
 if len(flags.Args()) != 0 || *prom == "" || *latency == "" || *traffic == "" || *age == "" || *timeout <= 0 || *timeout > 60*time.Second || *outfile == "" {
  fmt.Fprintln(stderr, "invalid verify-sli arguments")
  return 2
 }
 var notBefore time.Time
 if *barrier != "" {
  parsed, err := time.Parse(time.RFC3339, *barrier)
  if err != nil {fmt.Fprintln(stderr, "invalid --not-before timestamp"); return 2}
  notBefore = parsed
 }
 ctx, cancel := context.WithTimeout(context.Background(), *timeout)
 defer cancel()
 result := verifier.Assess(ctx, verifier.Policy{
  PrometheusURL: *prom, LatencyQuery: *latency, TrafficQuery: *traffic, AgeQuery: *age, MaxSampleAgeSeconds: *maxAge,
  MaxLatencySeconds: *threshold, MinTrafficPerSecond: *minTraffic,
  Window: *window, Step: *step, NotBefore: notBefore,
 })
 serialized, err := json.MarshalIndent(result, "", "  ")
 if err != nil {fmt.Fprintln(stderr, "cannot serialize SLI assessment");return 1}
 serialized = append(serialized, '\n')
 if *outfile == "-" {
  if _, err := stdout.Write(serialized); err != nil {fmt.Fprintln(stderr, err);return 1}
 } else {
  file, err := os.OpenFile(*outfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
  if err != nil {fmt.Fprintln(stderr, "cannot create immutable SLI assessment:",err);return 1}
  n, writeErr := file.Write(serialized)
  if writeErr == nil && n != len(serialized) {writeErr=io.ErrShortWrite}
  if writeErr == nil {writeErr = file.Sync()}
  closeErr := file.Close()
  if writeErr != nil || closeErr != nil {_ = os.Remove(*outfile);fmt.Fprintln(stderr, "cannot persist SLI assessment");return 1}
 }
 switch result.Status {
 case verifier.Healthy: return 0
 case verifier.Unhealthy: return 4
 default: return 3
 }
}
