package endpointoracle

import "testing"

func TestEndpointSliceRequiresExplicitEndpointsArray(t *testing.T) {
	const prefix = `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":[{"metadata":{"uid":"slice-1","name":"checkout-1","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4"`
	for _, tc := range []struct {
		name string
		field string
		wantError bool
	}{
		{"missing", "", true},
		{"null", `,"endpoints":null`, true},
		{"explicit empty", `,"endpoints":[]`, false},
		{"ready endpoint", `,"endpoints":[{"addresses":["10.0.0.1"],"conditions":{"ready":true}}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspect([]byte(prefix+tc.field+`}]}`), "demo", "checkout-api", "service-uid-1")
			if tc.wantError {
				if err == nil {
					t.Fatalf("incomplete source accepted as observation: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantReady := 0
			if tc.name == "ready endpoint" {
				wantReady = 1
			}
			if got.ready != wantReady || got.version != "25" {
				t.Fatalf("unexpected observation: %+v", got)
			}
		})
	}
}
