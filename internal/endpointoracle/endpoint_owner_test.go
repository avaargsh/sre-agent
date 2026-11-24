package endpointoracle

import "testing"

func TestEndpointSliceServiceOwnerIdentity(t *testing.T) {
	const matching = `{"apiVersion":"v1","kind":"Service","name":"checkout-api","uid":"service-uid-1"}`
	const stale = `{"apiVersion":"v1","kind":"Service","name":"checkout-api","uid":"service-uid-old"}`
	const wrongName = `{"apiVersion":"v1","kind":"Service","name":"other","uid":"service-uid-1"}`
	const wrongVersion = `{"apiVersion":"apps/v1","kind":"Service","name":"checkout-api","uid":"service-uid-1"}`
	for _, tc := range []struct {
		name, manager, owners string
		wantError             bool
	}{
		{"matching", `,"endpointslice.kubernetes.io/managed-by":"endpointslice-controller.k8s.io"`, `,"ownerReferences":[` + matching + `]`, false},
		{"stale UID", "", `,"ownerReferences":[` + stale + `]`, true},
		{"wrong name", "", `,"ownerReferences":[` + wrongName + `]`, true},
		{"wrong API version", "", `,"ownerReferences":[` + wrongVersion + `]`, true},
		{"duplicate Service owner", "", `,"ownerReferences":[` + matching + `,` + matching + `]`, true},
		{"managed missing owner", `,"endpointslice.kubernetes.io/managed-by":"endpointslice-controller.k8s.io"`, "", true},
		{"managed null owners", `,"endpointslice.kubernetes.io/managed-by":"endpointslice-controller.k8s.io"`, `,"ownerReferences":null`, true},
		{"legacy label only", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":[{"metadata":{"uid":"slice-1","name":"slice","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"` + tc.manager + `}` + tc.owners + `},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.1"],"conditions":{"ready":true}}]}]}`
			got, err := inspect([]byte(raw), "demo", "checkout-api", "service-uid-1")
			if tc.wantError {
				if err == nil {
					t.Fatalf("unsafe owner admitted: %+v", got)
				}
				return
			}
			if err != nil || got.ready != 1 {
				t.Fatalf("valid source rejected: %+v %v", got, err)
			}
		})
	}
}
