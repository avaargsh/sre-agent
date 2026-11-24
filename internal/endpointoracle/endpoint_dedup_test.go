package endpointoracle

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestEndpointAddressGroupDeduplication(t *testing.T) {
	type record struct {
		family    string
		addresses []string
		ready     bool
	}
	for _, tc := range []struct {
		name    string
		records []record
		want    int
		invalid bool
	}{
		{"distinct", []record{{"IPv4", []string{"10.0.0.1"}, true}, {"IPv4", []string{"10.0.0.2"}, true}}, 2, false},
		{"cross slice duplicate", []record{{"IPv4", []string{"10.0.0.1"}, true}, {"IPv4", []string{"10.0.0.1"}, true}}, 1, false},
		{"IPv6 equivalent", []record{{"IPv6", []string{"2001:db8::1"}, true}, {"IPv6", []string{"2001:0db8:0:0:0:0:0:1"}, true}}, 1, false},
		{"FQDN equivalent", []record{{"FQDN", []string{"Backend.example.org."}, true}, {"FQDN", []string{"backend.example.org"}, true}}, 1, false},
		{"dual stack", []record{{"IPv4", []string{"10.0.0.1"}, true}, {"IPv6", []string{"2001:db8::1"}, true}}, 2, false},
		{"reordered group", []record{{"IPv4", []string{"10.0.0.1", "10.0.0.2"}, true}, {"IPv4", []string{"10.0.0.2", "10.0.0.1"}, true}}, 1, false},
		{"partial overlap", []record{{"IPv4", []string{"10.0.0.1", "10.0.0.2"}, true}, {"IPv4", []string{"10.0.0.2"}, true}}, 0, true},
		{"conflicting readiness", []record{{"IPv4", []string{"10.0.0.1"}, true}, {"IPv4", []string{"10.0.0.1"}, false}}, 0, true},
		{"duplicate within group", []record{{"IPv4", []string{"10.0.0.1", "10.0.0.1"}, true}}, 0, true},
		{"duplicate not ready", []record{{"IPv4", []string{"10.0.0.1"}, false}, {"IPv4", []string{"10.0.0.1"}, false}}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []any{}
			for i, r := range tc.records {
				id := fmt.Sprintf("slice-%d", i)
				items = append(items, map[string]any{
					"metadata":    map[string]any{"uid": id, "name": id, "namespace": "demo", "labels": map[string]string{"kubernetes.io/service-name": "checkout-api"}},
					"addressType": r.family,
					"endpoints":   []any{map[string]any{"addresses": r.addresses, "conditions": map[string]bool{"ready": r.ready}}},
				})
			}
			raw, err := json.Marshal(map[string]any{"kind": "EndpointSliceList", "metadata": map[string]string{"resourceVersion": "25"}, "items": items})
			if err != nil {
				t.Fatal(err)
			}
			got, err := inspect(raw, "demo", "checkout-api", "service-uid-1")
			if tc.invalid {
				if err == nil {
					t.Fatalf("ambiguous endpoint admitted: %+v", got)
				}
				return
			}
			if err != nil || got.ready != tc.want {
				t.Fatalf("ready groups = %d, want %d, err=%v", got.ready, tc.want, err)
			}
		})
	}
}
