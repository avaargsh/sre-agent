// sre-agent is a Go-native entrypoint. The initial command checks frozen
// evidence only; it never contacts or mutates a cluster.
package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"

 "github.com/avaargsh/sre-agent/internal/evidence"
)

func run(args []string, stdout, stderr io.Writer) int {
 if len(args) == 0 {
  fmt.Fprintln(stderr, "usage: sre-agent verify-bundle|investigate|verify-sli|collect-changes [options]")
  return 2
 }
 if args[0] == "investigate" { return investigate(args[1:], stdout, stderr) }
 if args[0] == "verify-sli" { return verifySLI(args[1:], stdout, stderr) }
 if args[0] == "collect-changes" { return collectChanges(args[1:], stdout, stderr) }
 if args[0] != "verify-bundle" { fmt.Fprintln(stderr, "usage: sre-agent verify-bundle|investigate|verify-sli|collect-changes [options]"); return 2 }
 flags := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
 flags.SetOutput(stderr)
 path := flags.String("file", "", "bundle JSON file (use - for stdin)")
 scenario := flags.Bool("scenario", false, "read bundle from benchmark scenario JSON")
 if err := flags.Parse(args[1:]); err != nil { return 2 }
 if *path == "" || len(flags.Args()) != 0 {
  fmt.Fprintln(stderr, "--file is required and no positional arguments are allowed")
  return 2
 }
 var reader io.Reader = os.Stdin
 if *path != "-" {
  file, err := os.Open(*path)
  if err != nil { fmt.Fprintln(stderr, err); return 1 }
  defer file.Close()
  reader = file
 }
 raw, err := io.ReadAll(io.LimitReader(reader, evidence.MaxBundleBytes+1))
 if err != nil { fmt.Fprintln(stderr, err); return 1 }
 var result evidence.Result
 if *scenario { result, err = evidence.VerifyScenario(raw) } else { result, err = evidence.Verify(raw) }
 if err != nil { fmt.Fprintln(stderr, "INVALID:", err); return 1 }
 if err := json.NewEncoder(stdout).Encode(result); err != nil { fmt.Fprintln(stderr, err); return 1 }
 return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
