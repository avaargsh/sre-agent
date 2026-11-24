package observe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const serviceEndpointsService = `{"metadata":{"namespace":"demo","name":"checkout-api","uid":"service-uid-1","resourceVersion":"19"},"spec":{"selector":{"app":"checkout-api"},"ports":[{"port":8080,"targetPort":8080}]}}`
const serviceEndpointsSlices = `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25","continue":""},"items":[{"metadata":{"uid":"slice-uid-1","name":"checkout-api-abc","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.10"],"conditions":{"ready":true}}]}]}`

func serviceEndpointsConfig(endpoint string) ServiceEndpointsConfig {
	return ServiceEndpointsConfig{
		KubernetesURL: endpoint,
		Target: ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"},
		ExpectedTargetPort: 8080,
		ExpectedSelector: map[string]string{"app": "checkout-api"},
		BearerToken: "readonly-test",
	}
}

func serviceEndpointsServer(t *testing.T, before, slices, after string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer readonly-test" {
			t.Errorf("unexpected request method/auth: %s %q", r.Method, r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			if calls.Load() == 1 {
				_, _ = fmt.Fprint(w, before)
			} else {
				_, _ = fmt.Fprint(w, after)
			}
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			if r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=checkout-api" || r.URL.Query().Get("limit") != "129" {
				t.Errorf("unbounded or off-scope EndpointSlice query: %s", r.URL.RequestURI())
			}
			_, _ = fmt.Fprint(w, slices)
		default:
			t.Errorf("unexpected Kubernetes path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	return srv, &calls
}

func TestCollectServiceEndpointsPreservesExactReadOnlyEvidence(t *testing.T) {
	srv, calls := serviceEndpointsServer(t, serviceEndpointsService, serviceEndpointsSlices, serviceEndpointsService)
	defer srv.Close()
	got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected Service/EndpointSlice/Service reads, got %d", calls.Load())
	}
	if !bytes.Equal(got.ServiceBeforeRaw, []byte(serviceEndpointsService)) ||
		!bytes.Equal(got.EndpointSlicesRaw, []byte(serviceEndpointsSlices)) ||
		!bytes.Equal(got.ServiceAfterRaw, []byte(serviceEndpointsService)) {
		t.Fatal("collector did not preserve exact source bytes")
	}
	r := got.Report
	if r.SchemaVersion != "sre.service-endpoints/v2" || r.Target != (ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"}) ||
		r.ServiceResourceVersion != "19" || r.EndpointSliceListResourceVersion != "25" ||
		r.ReadyEndpoints != 1 || r.Classification != "READY_ENDPOINTS_OBSERVED" ||
		r.ExpectedTargetPort != 8080 || r.ExpectedSelector["app"] != "checkout-api" || r.SourceAuthenticated {
		t.Fatalf("wrong report: %+v", r)
	}
	if r.ServiceBeforeSHA256 != fmt.Sprintf("%x", sha256.Sum256(got.ServiceBeforeRaw)) ||
		r.EndpointSlicesSHA256 != fmt.Sprintf("%x", sha256.Sum256(got.EndpointSlicesRaw)) ||
		r.ServiceAfterSHA256 != fmt.Sprintf("%x", sha256.Sum256(got.ServiceAfterRaw)) {
		t.Fatalf("raw evidence digest mismatch: %+v", r)
	}
	if _, err := time.Parse(time.RFC3339Nano, r.ObservedAt); err != nil {
		t.Fatalf("invalid observation time: %q", r.ObservedAt)
	}
}

func TestReplayServiceEndpointsRecomputesSourceOnlyPrediction(t *testing.T) {
	prediction, err := ReplayServiceEndpoints(
		ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"},
		8080, map[string]string{"app": "checkout-api"},
		[]byte(serviceEndpointsService), []byte(serviceEndpointsSlices), []byte(serviceEndpointsService),
	)
	if err != nil {
		t.Fatal(err)
	}
	if prediction.Classification != "READY_ENDPOINTS_OBSERVED" ||
		prediction.ReadyEndpoints != 1 || prediction.Service.ServiceUID != "service-uid-1" {
		t.Fatalf("wrong offline replay: %+v", prediction)
	}
	if _, err := ReplayServiceEndpoints(
		ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"},
		8080, map[string]string{"app": "checkout-api"},
		[]byte(serviceEndpointsService), []byte(serviceEndpointsSlices),
		[]byte(strings.Replace(serviceEndpointsService, `"name":"checkout-api"`, `"name":"checkout-api","annotations":{"drift":"true"}`, 1)),
	); !errors.Is(err, ErrUnknown) {
		t.Fatalf("same-RV byte drift must fail replay: %v", err)
	}
}

func TestReplayServiceEndpointsRejectsInvalidOrOversizedSourceJSON(t *testing.T) {
	valid := []byte(serviceEndpointsService)
	validSlices := []byte(serviceEndpointsSlices)
	target := ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"}
	selector := map[string]string{"app": "checkout-api"}
	cases := map[string][][]byte{
		"invalid-service-utf8": {[]byte{0xff}, validSlices, valid},
		"invalid-slices-utf8": {valid, []byte{0xff}, valid},
		"duplicate-service-key": {[]byte(`{"metadata":{},"Metadata":{}}`), validSlices, valid},
		"oversized-slices": {valid, make([]byte, maxResponseBytes+1), valid},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplayServiceEndpoints(target, 8080, selector, raw[0], raw[1], raw[2]); !errors.Is(err, ErrUnknown) {
				t.Fatalf("invalid source JSON admitted: %v", err)
			}
		})
	}
}

func TestCollectServiceEndpointsReportsNoReadyEndpointsWithoutRootCauseClaim(t *testing.T) {
	empty := `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"26","continue":""},"items":[]}`
	srv, _ := serviceEndpointsServer(t, serviceEndpointsService, empty, serviceEndpointsService)
	defer srv.Close()
	got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got.Report.Classification != "NO_READY_ENDPOINTS_OBSERVED" || got.Report.ReadyEndpoints != 0 || got.Report.SourceAuthenticated {
		t.Fatalf("zero endpoints must remain an observation, not a causal claim: %+v", got.Report)
	}
}

func TestCollectServiceEndpointsAbstainsOnServiceConfigurationMismatch(t *testing.T) {
	mismatched := strings.Replace(serviceEndpointsService, `"targetPort":8080`, `"targetPort":9090`, 1)
	srv, _ := serviceEndpointsServer(t, mismatched, serviceEndpointsSlices, mismatched)
	defer srv.Close()
	got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got.Report.Classification != "UNKNOWN" || got.Report.ReadyEndpoints != 1 {
		t.Fatalf("Service config mismatch must abstain while preserving raw endpoint observation: %+v", got.Report)
	}
}

func TestCollectServiceEndpointsRejectsServiceIdentityOrVersionDrift(t *testing.T) {
	cases := map[string]string{
		"uid-replaced": strings.Replace(serviceEndpointsService, "service-uid-1", "service-uid-2", 1),
		"resource-version-changed": strings.Replace(serviceEndpointsService, `"resourceVersion":"19"`, `"resourceVersion":"20"`, 1),
	}
	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			srv, calls := serviceEndpointsServer(t, serviceEndpointsService, serviceEndpointsSlices, after)
			defer srv.Close()
			got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
			if !errors.Is(err, ErrUnknown) || got.ServiceBeforeRaw != nil || got.EndpointSlicesRaw != nil || got.ServiceAfterRaw != nil {
				t.Fatalf("Service drift must fail closed without partial evidence: %+v %v", got, err)
			}
			if calls.Load() != 3 {
				t.Fatalf("expected both Service fences and one EndpointSlice read, got %d", calls.Load())
			}
		})
	}
}

func TestReplayServiceEndpointsRejectsZeroServiceResourceVersion(t *testing.T) {
    zeroVersion := strings.Replace(
        serviceEndpointsService, `"resourceVersion":"19"`,
        `"resourceVersion":"0"`, 1,
    )
    if zeroVersion == serviceEndpointsService {
        t.Fatal("zero-RV fixture mutation did not apply")
    }
    target := ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"}
    if _, err := ReplayServiceEndpoints(
        target, 8080, map[string]string{"app": "checkout-api"},
        []byte(zeroVersion), []byte(serviceEndpointsSlices), []byte(zeroVersion),
    ); !errors.Is(err, ErrUnknown) {
        t.Fatalf("zero Service resourceVersion must not replay as a snapshot: %v", err)
    }
}


func TestCollectServiceEndpointsRejectsWrongInitialUIDBeforeListing(t *testing.T) {
	srv, calls := serviceEndpointsServer(t, strings.Replace(serviceEndpointsService, "service-uid-1", "other-service", 1), serviceEndpointsSlices, serviceEndpointsService)
	defer srv.Close()
	got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
	if !errors.Is(err, ErrUnknown) || got.EndpointSlicesRaw != nil || calls.Load() != 1 {
		t.Fatalf("wrong Service UID must stop before list: %+v %v calls=%d", got, err, calls.Load())
	}
}

func TestCollectServiceEndpointsRejectsIncompleteOrForeignEndpointSlices(t *testing.T) {
	cases := map[string]string{
		"missing-items": `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"}}`,
		"null-items": `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":null}`,
		"continued-list": `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25","continue":"next"},"items":[]}`,
		"foreign-namespace": strings.Replace(serviceEndpointsSlices, `"namespace":"demo"`, `"namespace":"other"`, 1),
		"foreign-service": strings.Replace(serviceEndpointsSlices, `"kubernetes.io/service-name":"checkout-api"`, `"kubernetes.io/service-name":"other-service"`, 1),
		"unknown-readiness": strings.Replace(serviceEndpointsSlices, `"ready":true`, `"ready":null`, 1),
		"duplicate-readiness": strings.Replace(serviceEndpointsSlices, `"ready":true`, `"ready":false,"ready":true`, 1),
		"duplicate-name": `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25","continue":""},"items":[{"metadata":{"uid":"slice-uid-1","name":"same","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[]},{"metadata":{"uid":"slice-uid-2","name":"same","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[]}]}`,
	}
	for name, slices := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _ := serviceEndpointsServer(t, serviceEndpointsService, slices, serviceEndpointsService)
			defer srv.Close()
			got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
			if !errors.Is(err, ErrUnknown) || got.ServiceBeforeRaw != nil {
				t.Fatalf("invalid EndpointSlice source admitted: %+v %v", got, err)
			}
		})
	}
}

func TestCollectServiceEndpointsRejectsInvalidConfigBeforeHTTP(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	cases := []ServiceEndpointsConfig{
		serviceEndpointsConfig(srv.URL),
		serviceEndpointsConfig(srv.URL),
		serviceEndpointsConfig(srv.URL),
		serviceEndpointsConfig(srv.URL),
		serviceEndpointsConfig(srv.URL),
	}
	cases[0].Target.Namespace = "../prod"
	cases[1].Target.Name = "../service"
	cases[2].Target.UID = ""
	cases[3].ExpectedTargetPort = 0
	cases[4].ExpectedSelector = map[string]string{"bad key": "value"}
	for _, cfg := range cases {
		got, err := CollectServiceEndpoints(context.Background(), cfg)
		if !errors.Is(err, ErrUnknown) || got.ServiceBeforeRaw != nil {
			t.Fatalf("invalid config admitted: %+v %v", got, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid config initiated HTTP: %d", hits.Load())
	}
}

func TestCollectServiceEndpointsRejectsForbiddenAndRedirectResponses(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"forbidden": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden); _, _ = fmt.Fprint(w, "private error") },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://example.com", http.StatusFound) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			got, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(srv.URL))
			if !errors.Is(err, ErrUnknown) || got.ServiceBeforeRaw != nil {
				t.Fatalf("unsafe response admitted: %+v %v", got, err)
			}
		})
	}
}

func TestCollectServiceEndpointsHonorsCallerDeadlineAcrossReads(t *testing.T) {
	var calls atomic.Int32
	caller := &http.Client{Transport: observeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(serviceEndpointsService)), Header: make(http.Header)}, nil
	})}
	cfg := serviceEndpointsConfig("http://127.0.0.1:1")
	cfg.Client = caller
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	got, err := CollectServiceEndpoints(ctx, cfg)
	if !errors.Is(err, ErrUnknown) || got.ServiceBeforeRaw != nil || calls.Load() != 1 {
		t.Fatalf("caller deadline must stop subsequent reads: %+v %v calls=%d", got, err, calls.Load())
	}
}
