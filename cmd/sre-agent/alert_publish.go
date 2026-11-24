package main

import (
 "io"
 "os"
 "path/filepath"
)

// publishAlertPlan exposes only complete, synced plan bytes at target.
// The parent must be operator-owned and not writable by untrusted parties.
// A hard link publishes create-only; competing paths are never removed.
func publishAlertPlan(target string, data []byte) error {
 stage, err := os.CreateTemp(filepath.Dir(target), ".sre-alert-plan-*")
 if err != nil { return err }
 defer os.Remove(stage.Name())
 n, err := stage.Write(data)
 if err == nil && n != len(data) { err = io.ErrShortWrite }
 if err == nil { err = stage.Sync() }
 closeErr := stage.Close()
 if err != nil { return err }
 if closeErr != nil { return closeErr }
 return os.Link(stage.Name(), target)
}
