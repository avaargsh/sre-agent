//go:build linux

package main

import (
 "os"
 "path/filepath"
 "syscall"
 "testing"
 "time"
)

func TestBoundedAlertFileRegularAndLimits(t *testing.T) {
 path := filepath.Join(t.TempDir(), "alert.json")
 if err := os.WriteFile(path, []byte("1234"), 0600); err != nil { t.Fatal(err) }
 got, err := boundedAlertFile(path, 4)
 if err != nil || string(got) != "1234" { t.Fatalf("exact limit: %q %v", got, err) }
 if _, err := boundedAlertFile(path, 3); err == nil { t.Fatal("oversized input accepted") }
 if err := os.WriteFile(path, nil, 0600); err != nil { t.Fatal(err) }
 if _, err := boundedAlertFile(path, 4); err == nil { t.Fatal("empty input accepted") }
}

func TestBoundedAlertFileRejectsSymlink(t *testing.T) {
 dir := t.TempDir()
 target := filepath.Join(dir, "target")
 if err := os.WriteFile(target, []byte("data"), 0600); err != nil { t.Fatal(err) }
 link := filepath.Join(dir, "link")
 if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
 if _, err := boundedAlertFile(link, 4); err == nil { t.Fatal("symlink accepted") }
}

func TestBoundedAlertFileRejectsFIFOWithoutWriter(t *testing.T) {
 path := filepath.Join(t.TempDir(), "fifo")
 if err := syscall.Mkfifo(path, 0600); err != nil { t.Fatal(err) }
 done := make(chan error, 1)
 go func() { _, err := boundedAlertFile(path, 4); done <- err }()
 select {
 case err := <-done:
  if err == nil { t.Fatal("FIFO accepted") }
 case <-time.After(time.Second):
  fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
  if err == nil { _ = syscall.Close(fd) }
  t.Fatal("FIFO blocked input admission")
 }
}
