package endpointoracle

import (
	"testing"
)

func TestDiagnoseRejectsUnsupportedLifecycleEvidence(t *testing.T) {
	_, _, service, endpoints := fixture(t, 1)
	selector := map[string]string{"app": "checkout-api"}
	for _, tc := range []struct {
		name string
		service, endpoints string
	}{
		{"publish override", string(replaceJSONOnce(t, string(service), `"spec":{`, `"spec":{"publishNotReadyAddresses":true,`)), string(endpoints)},
		{"terminating", string(service), string(replaceJSONOnce(t, string(endpoints), `"ready":true`, `"ready":true,"serving":true,"terminating":true`))},
		{"serving conflict", string(service), string(replaceJSONOnce(t, string(endpoints), `"ready":true`, `"ready":true,"serving":false`))},
		{"invalid serving", string(service), string(replaceJSONOnce(t, string(endpoints), `"ready":true`, `"ready":true,"serving":"true"`))},
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
	e.After.Service = snap([]byte(string(replaceJSONOnce(t, string(service), `"spec":{`, `"spec":{"publishNotReadyAddresses":true,`))))
	e.After.EndpointSlices = snap(endpoints)
	if _, err := Evaluate(e, p); err == nil {
		t.Fatal("unsupported recovery policy admitted")
	}
	e, p = episode(t, true)
	e.After.EndpointSlices = snap([]byte(string(replaceJSONOnce(t, string(endpoints), `"ready":true`, `"ready":true,"terminating":true`))))
	if _, err := Evaluate(e, p); err == nil {
		t.Fatal("terminating recovery endpoint admitted")
	}
}
