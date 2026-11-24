package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/avaargsh/sre-agent/internal/observe"
)

const cliServiceEndpointService = `{"metadata":{"namespace":"demo","name":"checkout-api","uid":"service-uid-1","resourceVersion":"19"},"spec":{"selector":{"app":"checkout-api"},"ports":[{"port":8080,"targetPort":8080}]}}`
const cliServiceEndpointSlices = `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25","continue":""},"items":[{"metadata":{"uid":"slice-uid-1","name":"checkout-api-abc","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.10"],"conditions":{"ready":true}}]}]}`

type cliServiceEndpointsCapture struct {
	SchemaVersion     string `json:"schema_version"`
	Report            observe.ServiceEndpointsReport `json:"report"`
	ServiceBeforeRaw  []byte `json:"service_before_raw"`
	EndpointSlicesRaw []byte `json:"endpoint_slices_raw"`
	ServiceAfterRaw []byte `json:"service_after_raw"`
}

func cliServiceEndpointArgs(endpoint string) []string {
	return []string{
		"--namespace", "demo", "--service", "checkout-api", "--uid", "service-uid-1",
		"--kube-api", endpoint, "--expected-target-port", "8080",
		"--expected-selector", "app=checkout-api",
	}
}

func TestCaptureServiceEndpointsEmitsReplayableExactBytes(t *testing.T) {
	var serviceReads, sliceReads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet { t.Errorf("non-read request: %s", r.Method) }
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			serviceReads++
			_, _ = fmt.Fprint(w, cliServiceEndpointService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			sliceReads++
			if r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=checkout-api" { t.Errorf("wrong selector: %s", r.URL.RawQuery) }
			_, _ = fmt.Fprint(w, cliServiceEndpointSlices)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"capture-service-endpoints"}, cliServiceEndpointArgs(srv.URL)...), &stdout, &stderr); code != 0 {
		t.Fatalf("capture exit=%d stderr=%s", code, stderr.String())
	}
	var got cliServiceEndpointsCapture
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil { t.Fatal(err) }
	if got.SchemaVersion != "sre.service-endpoints-capture/v1" ||
		string(got.ServiceBeforeRaw) != cliServiceEndpointService ||
		string(got.EndpointSlicesRaw) != cliServiceEndpointSlices ||
		string(got.ServiceAfterRaw) != cliServiceEndpointService {
		t.Fatalf("capture did not preserve exact bytes: %+v", got)
	}
	if got.Report.Classification != "READY_ENDPOINTS_OBSERVED" || got.Report.SourceAuthenticated ||
		len(got.Report.ReadTimeline) != 3 ||
		got.Report.ReadTimeline[1].RequestResourceVersion != "" ||
		got.Report.ReadTimeline[1].RequestResourceVersionMatch != "" ||
		got.Report.ReadTimeline[1].RequestConsistency != "MOST_RECENT" ||
		got.Report.ReadTimeline[1].RequestLabelSelector != "kubernetes.io/service-name=checkout-api" ||
		got.Report.ReadTimeline[1].RequestLimit != 129 ||
		serviceReads != 2 || sliceReads != 1 {
		t.Fatalf("wrong capture report or read count: %+v service=%d slices=%d", got.Report, serviceReads, sliceReads)
	}
	// encoding/json encodes []byte as base64; confirm the serialized envelope
	// retains the exact bytes rather than a lossy decoded projection.
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &encoded); err != nil { t.Fatal(err) }
	var serviceBase64 string
	if err := json.Unmarshal(encoded["service_before_raw"], &serviceBase64); err != nil { t.Fatal(err) }
	raw, err := base64.StdEncoding.Strict().DecodeString(serviceBase64)
	if err != nil || string(raw) != cliServiceEndpointService { t.Fatalf("invalid base64 evidence: %v", err) }
}

func TestCaptureServiceEndpointsRejectsDeniedSourceWithoutOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "private response body")
	}))
	defer srv.Close()
	var stdout, stderr bytes.Buffer
	if code := captureServiceEndpoints(cliServiceEndpointArgs(srv.URL), &stdout, &stderr); code != 3 ||
		stdout.Len() != 0 || strings.Contains(stderr.String(), "private response body") {
		t.Fatalf("denied capture leaked source bytes: exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestCaptureServiceEndpointsRejectsMalformedSelectorBeforeHTTP(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	args := cliServiceEndpointArgs(srv.URL)
	for i := range args {
		if args[i] == "app=checkout-api" { args[i] = "app" }
	}
	var stdout, stderr bytes.Buffer
	if code := captureServiceEndpoints(args, &stdout, &stderr); code != 2 || hits != 0 || stdout.Len() != 0 {
		t.Fatalf("malformed selector initiated source read: exit=%d hits=%d", code, hits)
	}
}
