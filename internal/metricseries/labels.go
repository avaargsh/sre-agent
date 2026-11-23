// Package metricseries enforces the labelset identity of a Prometheus
// instant vector. It neither attests Prometheus source identity nor proves
// any incident hypothesis.
package metricseries

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// Key canonicalizes one labelset, rejecting an absent metric object or a
// missing label name. A valid unlabelled aggregate is represented by {}.
func Key(labels map[string]string) (string, error) {
	if labels == nil {
		return "", errors.New("missing instant-vector metric labelset")
	}
	for name := range labels {
		if name == "" {
			return "", errors.New("empty instant-vector metric label name")
		}
	}
	encoded, err := json.Marshal(labels)
	if err != nil {
		return "", fmt.Errorf("canonicalize instant-vector labels: %w", err)
	}
	return string(encoded), nil
}

// Unique rejects repeated series identities. A Prometheus instant vector
// contains at most one sample for each labelset, irrespective of JSON key order.
func Unique(labelsets []map[string]string) error {
	seen := make(map[string]bool, len(labelsets))
	for i, labels := range labelsets {
		id, err := Key(labels)
		if err != nil {
			return fmt.Errorf("instant-vector series %d: %w", i, err)
		}
		if seen[id] {
			return fmt.Errorf("duplicate instant-vector labelset at series %d", i)
		}
		seen[id] = true
	}
	return nil
}

// ValidTimestamp matches the independent replay validator's supported
// Prometheus Unix-second range. The bound also prevents overflow when the
// collector converts seconds to int64 nanoseconds before freshness checks.
func ValidTimestamp(value float64) bool {
 return !math.IsNaN(value) && !math.IsInf(value,0) && value>0 && value<=9e9
}
