package endpointoracle

import "testing"

func TestSameEndpointSource(t *testing.T) {
	for _, tc := range []struct {
		name, observer, admin string
		want                  bool
	}{
		{"same", `{"items":[],"metadata":{"resourceVersion":"25"}}`, `{"items":[],"metadata":{"resourceVersion":"25"}}`, true},
		{"format and key order", `{"items":[],"metadata":{"resourceVersion":"25"}}`, "{\n  \"metadata\": {\"resourceVersion\": \"25\"}, \"items\": []\n}", true},
		{"different addresses", `{"items":[{"addresses":["10.0.0.1"],"ready":true}]}`, `{"items":[{"addresses":["10.0.0.2"],"ready":true}]}`, false},
		{"different metadata", `{"items":[{"uid":"old"}]}`, `{"items":[{"uid":"new"}]}`, false},
		{"number precision", `{"generation":9007199254740992}`, `{"generation":9007199254740993}`, false},
		{"type drift", `{"value":true}`, `{"value":1}`, false},
		{"array order", `{"items":[1,2]}`, `{"items":[2,1]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameEndpointSource([]byte(tc.observer), []byte(tc.admin)); got != tc.want {
				t.Fatalf("source equality = %v, want %v", got, tc.want)
			}
		})
	}
}
