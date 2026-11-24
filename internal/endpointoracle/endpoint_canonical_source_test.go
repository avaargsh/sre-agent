package endpointoracle

import (
	"strings"
	"testing"
)

func TestDiagnoseRejectsNonCanonicalNativeServiceFieldNames(t *testing.T) {
	_, _, service, endpointSlices := fixture(t, 1)
	cases := map[string]string{
		"metadata": strings.Replace(string(service), `"metadata":`, `"Metadata":`, 1),
		"resource-version": strings.Replace(string(service), `"resourceVersion":`, `"ResourceVersion":`, 1),
		"spec": strings.Replace(string(service), `"spec":`, `"Spec":`, 1),
		"target-port": strings.Replace(string(service), `"targetPort":`, `"TargetPort":`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == string(service) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := Diagnose([]byte(raw), endpointSlices, 8080, map[string]string{"app": "checkout-api"}); err == nil {
				t.Fatal("accepted a non-canonical native Service field name")
			}
		})
	}
}

func TestDiagnoseRejectsNonCanonicalEndpointSliceFieldNames(t *testing.T) {
	_, _, service, endpointSlices := fixture(t, 1)
	cases := map[string]string{
		"kind": strings.Replace(string(endpointSlices), `"kind":`, `"Kind":`, 1),
		"metadata": strings.Replace(string(endpointSlices), `"metadata":`, `"Metadata":`, 1),
		"resource-version": strings.Replace(string(endpointSlices), `"resourceVersion":`, `"ResourceVersion":`, 1),
		"ready": strings.Replace(string(endpointSlices), `"ready":`, `"Ready":`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == string(endpointSlices) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := Diagnose(service, []byte(raw), 8080, map[string]string{"app": "checkout-api"}); err == nil {
				t.Fatal("accepted a non-canonical native EndpointSlice field name")
			}
		})
	}
}
