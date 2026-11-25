//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeServiceEndpointReplayCLI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			fmt.Fprint(w, cliServiceEndpointService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			fmt.Fprint(w, cliServiceEndpointSlices)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	if code := captureServiceEndpoints(cliServiceEndpointArgs(srv.URL), &stdout, &stderr); code != 0 {
		t.Fatalf("capture exit=%d stderr=%s", code, stderr.String())
	}
	raw := append([]byte(nil), stdout.Bytes()...)
	srv.Close()
	path := filepath.Join(t.TempDir(), "capture.json")
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(raw)
	args := []string{"replay-service-endpoints", "--capture", path, "--namespace", "demo", "--service", "checkout-api", "--uid", "service-uid-1", "--expected-target-port", "8080", "--expected-selector", "app=checkout-api"}
	replay := func(args []string) int {
		stdout.Reset()
		stderr.Reset()
		return run(args, &stdout, &stderr)
	}
	if code := replay(args); code != 0 {
		t.Fatalf("replay exit=%d stderr=%s", code, stderr.String())
	}
	var receipt map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if receipt["status"] != "REPLAYED" ||
		receipt["schema_version"] != "sre.service-endpoints-replay/v1" ||
		receipt["archive_sha256"] != hex.EncodeToString(sum[:]) ||
		receipt["classification"] != "READY_ENDPOINTS_OBSERVED" ||
		receipt["ready_endpoints"] != float64(1) ||
		receipt["source_authenticated"] != false ||
		receipt["causality_verified"] != false ||
		receipt["execution_authorized"] != false ||
		strings.Contains(stdout.String(), "10.0.0.10") {
		t.Fatalf("unexpected replay receipt: %s", stdout.String())
	}

	wrongUID := append([]string(nil), args...)
	wrongUID[8] = "different-service-uid"
	if code := replay(wrongUID); code != 3 || stdout.Len() != 0 {
		t.Fatalf("mismatched target accepted: exit=%d", code)
	}
	for _, field := range []string{"ready_endpoints", "source_authenticated"} {
		for _, missing := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/missing=%t", field, missing), func(t *testing.T) {
				var envelope map[string]any
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatal(err)
				}
				report := envelope["report"].(map[string]any)
				if missing {
					delete(report, field)
				} else {
					report[field] = nil
				}
				data, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				write(data)
				if code := replay(args); code != 3 || stdout.Len() != 0 {
					t.Fatalf("invalid report accepted: exit=%d", code)
				}
			})
		}
	}
	write(raw)
	var altered map[string]any
	if err := json.Unmarshal(raw, &altered); err != nil {
		t.Fatal(err)
	}
	altered["service_after_raw"] = []byte("{}")
	data, err := json.Marshal(altered)
	if err != nil {
		t.Fatal(err)
	}
	write(data)
	if code := replay(args); code != 3 || stdout.Len() != 0 {
		t.Fatalf("modified source accepted: exit=%d", code)
	}
}
