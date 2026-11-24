package main

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"
)

func TestPublishAlertPlanCompletePrivateAndCreateOnly(t *testing.T) {
 dir := t.TempDir()
 target := filepath.Join(dir, "plan.json")
 data := []byte("complete plan\n")
 if err := publishAlertPlan(target, data); err != nil { t.Fatal(err) }
 raw, err := os.ReadFile(target)
 if err != nil || !bytes.Equal(raw, data) { t.Fatalf("wrong bytes: %q %v", raw, err) }
 info, err := os.Stat(target)
 if err != nil || info.Mode().Perm() != 0600 { t.Fatalf("wrong permissions: %v %v", info, err) }
 if err := publishAlertPlan(target, []byte("replacement")); err == nil { t.Fatal("overwrite admitted") }
 raw, err = os.ReadFile(target)
 if err != nil || !bytes.Equal(raw, data) { t.Fatalf("competing output changed: %q %v", raw, err) }
 entries, err := os.ReadDir(dir)
 if err != nil || len(entries) != 1 { t.Fatalf("staging leak: %v %v", entries, err) }
}

func TestPublishAlertPlanPreservesExistingSymlink(t *testing.T) {
 dir := t.TempDir()
 source := filepath.Join(dir, "protected")
 target := filepath.Join(dir, "plan.json")
 if err := os.WriteFile(source, []byte("protected"), 0600); err != nil { t.Fatal(err) }
 if err := os.Symlink(source, target); err != nil { t.Fatal(err) }
 if err := publishAlertPlan(target, []byte("replacement")); err == nil { t.Fatal("symlink overwritten") }
 raw, err := os.ReadFile(source)
 if err != nil || string(raw) != "protected" { t.Fatal("protected source modified") }
 link, err := os.Readlink(target)
 if err != nil || link != source { t.Fatal("existing symlink changed") }
 entries, err := os.ReadDir(dir)
 if err != nil || len(entries) != 2 { t.Fatalf("staging leak: %v %v", entries, err) }
}
