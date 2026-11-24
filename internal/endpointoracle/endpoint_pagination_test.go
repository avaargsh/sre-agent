package endpointoracle

import "testing"

func TestEndpointSliceListPaginationMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, metadata string
		valid          bool
	}{
		{"omitted optional fields", `"resourceVersion":"25"`, true},
		{"complete list", `"resourceVersion":"25","continue":"","remainingItemCount":0`, true},
		{"opaque version", `"resourceVersion":"opaque-version"`, true},
		{"continued", `"resourceVersion":"25","continue":"next"`, false},
		{"null continuation", `"resourceVersion":"25","continue":null`, false},
		{"remaining items", `"resourceVersion":"25","remainingItemCount":1`, false},
		{"negative remaining", `"resourceVersion":"25","remainingItemCount":-1`, false},
		{"null remaining", `"resourceVersion":"25","remainingItemCount":null`, false},
		{"string remaining", `"resourceVersion":"25","remainingItemCount":"0"`, false},
		{"fractional remaining", `"resourceVersion":"25","remainingItemCount":0.0`, false},
		{"boolean remaining", `"resourceVersion":"25","remainingItemCount":false`, false},
		{"object remaining", `"resourceVersion":"25","remainingItemCount":{}`, false},
		{"empty version", `"resourceVersion":""`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"kind":"EndpointSliceList","metadata":{` + tc.metadata + `},"items":[]}`)
			got, err := inspect(raw, "demo", "checkout-api", "service-uid-1")
			if tc.valid {
				if err != nil || got.ready != 0 || got.version == "" {
					t.Fatalf("complete empty list rejected: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("incomplete or malformed metadata admitted: %+v", got)
			}
		})
	}
}
