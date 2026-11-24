package endpointoracle

import (
	"strings"
	"testing"
)

func TestDiagnoseRejectsUnsupportedLifecycleEvidence(t *testing.T) {
	_, _, service, endpoints := fixture(t, 1)
	selector := map[string]string{"app": "checkout-api"}
	for _, tc := range []struct {
		name string
		service, endpoints string
	}{
		{"publish override", strings.Replace(string(service), `"spec":{`, `"spec":{"publishNotReadyAddresses":true,`, 1), string(endpoints)},
		{"terminating", string(service), strings.Replace(string(endpoints), `"ready":true`, `"ready":true,"serving":true,"terminating":true`, 1)},
		{"serving conflict", string(service), strings.Replace(string(endpoints), `"ready":true`, `"ready":true,"serving":false`, 1)},
		{"invalid serving", string(service), strings.Replace(string(endpoints), `"ready":true`, `"ready":true,"serving":"true"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Diagnose([]byte(tc.service), []byte(tc.endpoints), 8080, selector); err == nil {
				t.Fatal("unsupported lifecycle evidence admitted")
			}
		})
	}
}

func TestEpisodeRejectsUnsupportedLifecycleInRecoveryPhase(t *testing.T) {
	e, p := episode(t, true)
	_, _, service, endpoints := fixture(t, 1)
	e.After.Service = snap([]byte(strings.Replace(string(service), `"spec":{`, `"spec":{"publishNotReadyAddresses":true,`, 1)))
	e.After.EndpointSlices = snap(endpoints)
	if _, err := Evaluate(e, p); err == nil {
		t.Fatal("unsupported recovery policy admitted")
	}
	e, p = episode(t, true)
	e.After.EndpointSlices = snap([]byte(strings.Replace(string(endpoints), `"ready":true`, `"ready":true,"terminating":true`, 1)))
	if _, err := Evaluate(e, p); err == nil {
		t.Fatal("terminating recovery endpoint admitted")
	}
}
