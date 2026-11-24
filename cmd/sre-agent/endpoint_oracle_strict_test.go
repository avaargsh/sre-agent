package main

import "testing"

func TestDecodeStrictEndpointEnvelope(t *testing.T) {
	type envelope struct {
		Scenario string `json:"scenario"`
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"valid", []byte(`{"scenario":"NO_FAULT"}`), true},
		{"duplicate", []byte(`{"scenario":"NO_FAULT","scenario":"NO_READY_ENDPOINTS"}`), false},
		{"casefold conflict", []byte(`{"scenario":"NO_FAULT","Scenario":"NO_READY_ENDPOINTS"}`), false},
		{"nested duplicate", []byte(`{"scenario":"NO_FAULT","nested":{"ready":true,"ready":false}}`), false},
		{"trailing value", []byte(`{"scenario":"NO_FAULT"} {"scenario":"NO_READY_ENDPOINTS"}`), false},
		{"invalid utf8", []byte{0xff}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got envelope
			err := decodeStrictEndpointEnvelope(tc.raw, &got)
			if (err == nil) != tc.ok {
				t.Fatalf("admission mismatch: %v", err)
			}
			if tc.ok && got.Scenario != "NO_FAULT" {
				t.Fatalf("unexpected decode: %+v", got)
			}
		})
	}
}
