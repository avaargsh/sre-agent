package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyBundleCLIExistingBenchmark(t *testing.T) {
 var stdout, stderr bytes.Buffer
 status := run([]string{"verify-bundle", "--file", "../../benchmarks/scenarios/checkout-latency.json", "--scenario"}, &stdout, &stderr)
 if status != 0 { t.Fatalf("exit=%d stderr=%s", status, stderr.String()) }
 if !strings.Contains(stdout.String(), `"status":"STRUCTURALLY_VALID"`) { t.Fatalf("wrong output: %s", stdout.String()) }
}
func TestVerifyBundleCLIRejectsCorruptInput(t *testing.T) {
 file := filepath.Join(t.TempDir(), "bad.json")
 if err := os.WriteFile(file, []byte(`{"incident":{}}`), 0600); err != nil { t.Fatal(err) }
 var stdout, stderr bytes.Buffer
 status := run([]string{"verify-bundle", "--file", file}, &stdout, &stderr)
 if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "INVALID:") {
  t.Fatalf("exit=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
 }
}
func TestVerifyBundleCLIMissingCommand(t *testing.T) {
 var stdout, stderr bytes.Buffer
 if exit := run(nil, &stdout, &stderr); exit != 2 { t.Fatalf("exit=%d", exit) }
}
