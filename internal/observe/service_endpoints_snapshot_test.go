package observe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCollectServiceEndpointsPinsListAtOrAfterServiceResourceVersion(t *testing.T) {
	var listQuery url.Values
	var serviceReads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			serviceReads++
			_, _ = fmt.Fprint(w, serviceEndpointsService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			listQuery = r.URL.Query()
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
	if serviceReads != 2 {
		t.Fatalf("expected two Service fences, got %d", serviceReads)
	}
	if listQuery.Get("resourceVersion") != "19" ||
		listQuery.Get("resourceVersionMatch") != "NotOlderThan" ||
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
		report.ReadTimeline[1].ResponseResourceVersion != "25" ||
		report.ReadTimeline[2].ResponseResourceVersion != "19" {
		t.Fatalf("read timeline lost cross-resource version association: %+v", report.ReadTimeline)
	}
	if report.CollectionStartedAt == "" || report.CollectionCompletedAt == "" ||
		report.ObservedAt != report.CollectionCompletedAt {
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
	collectionEnd := parse(report.CollectionCompletedAt)
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
		"response-digest-forged": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[1].ResponseSHA256 = strings.Repeat("0", 64)
		},
		"collection-window-inverted": func(capture *ServiceEndpointsObservation) {
			capture.Report.CollectionCompletedAt = capture.Report.CollectionStartedAt
			capture.Report.ObservedAt = capture.Report.CollectionCompletedAt
		},
		"service-after-version-forged": func(capture *ServiceEndpointsObservation) {
			capture.Report.ReadTimeline[2].ResponseResourceVersion = "20"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			candidate.Report.ReadTimeline = append([]ServiceEndpointsRead(nil), observation.Report.ReadTimeline...)
			mutate(&candidate)
			if _, err := ReplayServiceEndpointsObservation(target, 8080, selector, candidate); err == nil {
				t.Fatal("accepted capture with inconsistent source/read metadata")
			}
		})
	}
}

func TestCollectServiceEndpointsFailsClosedWhenPinnedListVersionExpires(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			_, _ = fmt.Fprint(w, serviceEndpointsService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			if r.URL.Query().Get("resourceVersion") != "19" ||
				r.URL.Query().Get("resourceVersionMatch") != "NotOlderThan" {
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
		calls != 2 {
		t.Fatalf("expired pinned snapshot must fail closed without fallback or partial evidence: %+v err=%v calls=%d", observation, err, calls)
	}
}
