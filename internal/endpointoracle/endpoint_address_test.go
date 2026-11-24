package endpointoracle

import (
	"encoding/json"
	"testing"
)

func TestEndpointAddressMatchesDeclaredFamily(t *testing.T) {
	for _, tc := range []struct {
		name, family, address string
		valid                 bool
	}{
		{"IPv4", "IPv4", "10.0.0.1", true},
		{"IPv6", "IPv6", "2001:db8::1", true},
		{"FQDN", "FQDN", "backend.example.org", true},
		{"absolute FQDN", "FQDN", "backend.example.org.", true},
		{"empty", "IPv4", "", false},
		{"whitespace", "IPv4", " 10.0.0.1", false},
		{"invalid IP", "IPv4", "10.0.0.999", false},
		{"IPv6 in IPv4", "IPv4", "2001:db8::1", false},
		{"IPv4 in IPv6", "IPv6", "10.0.0.1", false},
		{"mapped IPv4", "IPv6", "::ffff:10.0.0.1", false},
		{"zoned IPv6", "IPv6", "fe80::1%eth0", false},
		{"invalid FQDN", "FQDN", "backend..example.org", false},
		{"URL", "FQDN", "https://backend.example.org", false},
		{"IP as FQDN", "FQDN", "10.0.0.1", false},
		{"invalid label", "FQDN", "-backend.example.org", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := json.Marshal(tc.address)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":[{"metadata":{"uid":"slice-1","name":"slice","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"` + tc.family + `","endpoints":[{"addresses":[` + string(address) + `],"conditions":{"ready":true}}]}]}`)
			got, err := inspect(raw, "demo", "checkout-api", "service-uid-1")
			if tc.valid {
				if err != nil || got.ready != 1 {
					t.Fatalf("valid address rejected: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("invalid address counted: %+v", got)
			}
		})
	}
}
