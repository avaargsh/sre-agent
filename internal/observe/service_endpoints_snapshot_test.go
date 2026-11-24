package observe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectServiceEndpointsPinsListAtOrAfterServiceResourceVersion(t *testing.T) {
	listQueryCh := make(chan url.Values, 1)
	var serviceReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			serviceReads.Add(1)
			_, _ = fmt.Fprint(w, serviceEndpointsService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			listQueryCh <- r.URL.Query()
			_, _ = fmt.Fprint(w, serviceEndpointsSlices)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if serviceReads.Load() != 2 {
		t.Fatalf("expected two Service fences, got %d", serviceReads.Load())
	}
	listQuery := <-listQueryCh
	if listQuery.Get("resourceVersion") != "19" ||
		listQuery.Get("resourceVersionMatch") != "NotOlderThan" ||
		listQuery.Get("labelSelector") != "kubernetes.io/service-name=checkout-api" ||
		listQuery.Get("limit") != "129" {
		t.Fatalf("EndpointSlice LIST is not bounded to the Service version: %s", listQuery.Encode())
	}

	report := observation.Report
	if len(report.ReadTimeline) != 3 {
		t.Fatalf("expected three ordered source reads, got %+v", report.ReadTimeline)
	}
	if report.ReadTimeline[0].Name != "service_get_before" ||
		report.ReadTimeline[1].Name != "endpoint_slice_list" ||
		report.ReadTimeline[2].Name != "service_get_after" {
		t.Fatalf("unexpected source read order: %+v", report.ReadTimeline)
	}
	if report.ReadTimeline[0].ResponseResourceVersion != "19" ||
		report.ReadTimeline[1].RequestResourceVersion != "19" ||
		report.ReadTimeline[1].RequestResourceVersionMatch != "NotOlderThan" ||
		report.ReadTimeline[1].RequestLabelSelector != "kubernetes.io/service-name=checkout-api" ||
		report.ReadTimeline[1].RequestLimit != 129 ||
		report.ReadTimeline[1].ResponseResourceVersion != "25" ||
		report.ReadTimeline[2].ResponseResourceVersion != "19" {
		t.Fatalf("read timeline lost cross-resource version association: %+v", report.ReadTimeline)
	}
	if report.CollectionStartedAt == "" || report.ObservedAt == "" {
		t.Fatalf("collection window is incomplete: %+v", report)
	}

	parse := func(value string) time.Time {
		t.Helper()
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			t.Fatalf("invalid capture timestamp %q: %v", value, err)
		}
		if parsed.UTC().Format(time.RFC3339Nano) != value {
			t.Fatalf("timestamp is not canonical UTC RFC3339Nano: %q", value)
		}
		return parsed
	}
	collectionStart := parse(report.CollectionStartedAt)
	collectionEnd := parse(report.ObservedAt)
	previousEnd := collectionStart
	for _, read := range report.ReadTimeline {
		started := parse(read.StartedAt)
		completed := parse(read.CompletedAt)
		if started.Before(previousEnd) || completed.Before(started) {
			t.Fatalf("source read intervals overlap or run backwards: %+v", report.ReadTimeline)
		}
		if read.ResponseSHA256 == "" || read.ResponseResourceVersion == "" {
			t.Fatalf("source read lacks response binding: %+v", read)
		}
		previousEnd = completed
	}
	if collectionEnd.Before(previousEnd) {
		t.Fatalf("collection completed before its final read: %+v", report)
	}
}

func TestReplayServiceEndpointsObservationValidatesReadAndRawEvidenceBinding(t *testing.T) {
	server, _ := serviceEndpointsServer(t, serviceEndpointsService, serviceEndpointsSlices, serviceEndpointsService)
	defer server.Close()
	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"}
	selector := map[string]string{"app": "checkout-api"}
	prediction, err := ReplayServiceEndpointsObservation(target, 8080, selector, observation)
	if err != nil {
		t.Fatalf("valid capture did not replay: %v", err)
	}
	if prediction.Classification != "READY_ENDPOINTS_OBSERVED" || prediction.ReadyEndpoints != 1 {
		t.Fatalf("unexpected replay: %+v", prediction)
	}

	cases := map[string]func(*ServiceEndpointsObservation){
		"request-version-not-bound": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].RequestResourceVersion = "18"
		},
		"request-match-weakened": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].RequestResourceVersionMatch = "Exact"
		},
		"request-label-selector-forged": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].RequestLabelSelector = "kubernetes.io/service-name=other"
		},
		"request-limit-weakened": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].RequestLimit = 128
		},
		"response-digest-forged": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].ResponseSHA256 = strings.Repeat("0", 64)
		},
		"collection-window-inverted": func(capture *ServiceEndpointsObservation) {
			capture.Report.ObservedAt = capture.Report.CollectionStartedAt
		},
		"service-after-version-forged": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[2].ResponseResourceVersion = "20"
		},
		"raw-endpoint-source-tampered": func(capture *ServiceEndpointsObservation) {
			capture.EndpointSlicesRaw = append([]byte(nil), capture.EndpointSlicesRaw...)
			changed := strings.Replace(string(capture.EndpointSlicesRaw), `"ready":true`, `"ready":false`, 1)
			if changed == string(capture.EndpointSlicesRaw) {
				t.Fatal("raw source mutation did not apply")
			}
			capture.EndpointSlicesRaw = []byte(changed)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			candidate.ServiceBeforeRaw = append([]byte(nil), observation.ServiceBeforeRaw...)
			candidate.EndpointSlicesRaw = append([]byte(nil), observation.EndpointSlicesRaw...)
			candidate.ServiceAfterRaw = append([]byte(nil), observation.ServiceAfterRaw...)
			candidate.Report.ReadTimeline = append([]ServiceEndpointsRead(nil), observation.Report.ReadTimeline...)
			mutate(&candidate)
			if _, err := ReplayServiceEndpointsObservation(target, 8080, selector, candidate); err == nil {
				t.Fatal("accepted capture with inconsistent source/read metadata")
			}
		})
	}
}

func TestCollectServiceEndpointsFailsClosedWhenPinnedListVersionExpires(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			_, _ = fmt.Fprint(w, serviceEndpointsService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			if r.URL.Query().Get("resourceVersion") != "19" ||
				r.URL.Query().Get("resourceVersionMatch") != "NotOlderThan" ||
				r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=checkout-api" ||
				r.URL.Query().Get("limit") != "129" {
				t.Errorf("missing cross-resource version fence: %s", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusGone)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if !errors.Is(err, ErrUnknown) ||
		observation.ServiceBeforeRaw != nil ||
		observation.EndpointSlicesRaw != nil ||
		observation.ServiceAfterRaw != nil ||
		calls.Load() != 2 {
		t.Fatalf("expired pinned snapshot must fail closed without fallback or partial evidence: %+v err=%v calls=%d", observation, err, calls.Load())
	}
}

func TestCollectServiceEndpointsRejectsZeroServiceResourceVersionBeforeList(t *testing.T) {
	zeroVersion := strings.Replace(serviceEndpointsService, `"resourceVersion":"19"`, `"resourceVersion":"0"`, 1)
	if zeroVersion == serviceEndpointsService {
		t.Fatal("zero-RV fixture mutation did not apply")
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, zeroVersion)
	}))
	defer server.Close()

	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if !errors.Is(err, ErrUnknown) ||
		observation.ServiceBeforeRaw != nil ||
		observation.EndpointSlicesRaw != nil ||
		calls.Load() != 1 {
		t.Fatalf("zero RV must not weaken the cross-resource snapshot fence: %+v err=%v calls=%d", observation, err, calls.Load())
	}
}

func TestCollectServiceEndpointsRejectsOversizedServiceResourceVersionBeforeList(t *testing.T) {
	oversizedVersion := strings.Repeat("x", 257)
	oversizedService := strings.Replace(
		serviceEndpointsService,
		`"resourceVersion":"19"`,
		`"resourceVersion":"`+oversizedVersion+`"`,
		1,
	)
	if oversizedService == serviceEndpointsService {
		t.Fatal("oversized resourceVersion fixture mutation did not apply")
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, oversizedService)
	}))
	defer server.Close()

	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if !errors.Is(err, ErrUnknown) ||
		observation.ServiceBeforeRaw != nil ||
		observation.EndpointSlicesRaw != nil ||
		calls.Load() != 1 {
		t.Fatalf("oversized resourceVersion must not be used in a LIST request: %+v err=%v calls=%d", observation, err, calls.Load())
	}
}

func TestReplayServiceEndpointsObservationRejectsLegacyReportSchema(t *testing.T) {
	server, _ := serviceEndpointsServer(t, serviceEndpointsService, serviceEndpointsSlices, serviceEndpointsService)
	defer server.Close()
	observation, err := CollectServiceEndpoints(context.Background(), serviceEndpointsConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	observation.Report.SchemaVersion = "sre.service-endpoints/v1"
	if _, err := ReplayServiceEndpointsObservation(
		ServiceTarget{Namespace: "demo", Name: "checkout-api", UID: "service-uid-1"},
		8080, map[string]string{"app": "checkout-api"}, observation,
	); !errors.Is(err, ErrUnknown) {
		t.Fatalf("legacy report without the required version-fenced timeline must fail closed: %v", err)
	}
}
