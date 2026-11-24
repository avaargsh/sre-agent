//go:build unix

package main

import (
 "fmt"
 "io"
 "os"
 "syscall"
)

// boundedAlertFile checks the opened inode before reading. O_NONBLOCK
// prevents a FIFO from stalling preflight; O_NOFOLLOW rejects a final symlink.
func boundedAlertFile(path string, max int) ([]byte, error) {
 return boundedRegularFile(path, max, syscall.O_NOFOLLOW)
}

// Credential paths must be operator-controlled. Follow projected-volume
// symlinks (Kubernetes rotates them), but admit only a bounded regular inode.
func boundedCredentialFile(path string, max int) ([]byte, error) {
 return boundedRegularFile(path, max, 0)
}

func boundedRegularFile(path string, max int, flags int) ([]byte, error) {
 if max <= 0 { return nil, fmt.Errorf("invalid input limit") }
 file, err := os.OpenFile(path, os.O_RDONLY|flags|syscall.O_NONBLOCK, 0)
 if err != nil { return nil, err }
 defer file.Close()
 info, err := file.Stat()
 if err != nil || !info.Mode().IsRegular() || info.Size() > int64(max) { return nil, fmt.Errorf("not a regular bounded input file") }
 raw, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
 if err != nil || len(raw) == 0 || len(raw) > max { return nil, fmt.Errorf("missing, unreadable or oversized file") }
 return raw, nil
}
