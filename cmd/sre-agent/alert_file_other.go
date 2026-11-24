//go:build !unix

package main

import "fmt"

// Fail closed where the secure Unix open flags are unavailable.
func boundedAlertFile(path string, max int) ([]byte, error) {
 return nil, fmt.Errorf("secure alert file admission is unavailable on this platform")
}
