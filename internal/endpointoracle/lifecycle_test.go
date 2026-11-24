package endpointoracle

import "testing"

func TestServiceReadinessPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		accepted  bool
	}{
		{"default", `{"spec":{}}`, true},
		{"false", `{"spec":{"publishNotReadyAddresses":false}}`, true},
		{"true", `{"spec":{"publishNotReadyAddresses":true}}`, false},
		{"null", `{"spec":{"publishNotReadyAddresses":null}}`, false},
		{"string", `{"spec":{"publishNotReadyAddresses":"false"}}`, false},
		{"missing spec", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateServiceReadinessPolicy([]byte(tc.raw)); (got == nil) != tc.accepted {
				t.Fatalf("admission mismatch: %v", got)
			}
		})
	}
}

func TestEndpointLifecycleAdmission(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name                 string
		ready                bool
		serving, terminating *bool
		accepted             bool
	}{
		{"legacy ready", true, nil, nil, true},
		{"legacy not ready", false, nil, nil, true},
		{"steady serving", true, &yes, &no, true},
		{"steady unavailable", false, &no, &no, true},
		{"ready but not serving", true, &no, &no, false},
		{"not ready but serving", false, &yes, &no, false},
		{"terminating serving", false, &yes, &yes, false},
		{"terminating not serving", false, &no, &yes, false},
		{"ready terminating", true, &yes, &yes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateEndpointLifecycle(tc.ready, tc.serving, tc.terminating); (got == nil) != tc.accepted {
				t.Fatalf("admission mismatch: %v", got)
			}
		})
	}
}
