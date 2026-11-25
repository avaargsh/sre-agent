//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type endpointReplayShortWriter struct{}

func (endpointReplayShortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

type endpointReplayErrorWriter struct{}

func (endpointReplayErrorWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

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
	args := []string{"replay-service-endpoints", "--capture", path, "--namespace", "demo", "--service", "checkout-api", "--uid", "service-uid-1", "--expected-target-port", "8080", "--expected-selector", "app=checkout-api", "--sha256", fmt.Sprintf("%x", sha256.Sum256(raw))}
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

	// A complete successful receipt is required even if the writer violates
	// the io.Writer contract by returning a short count and nil error.
	for _, tc := range []struct {
		name   string
		writer io.Writer
	}{
		{"short write", endpointReplayShortWriter{}},
		{"write error", endpointReplayErrorWriter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr.Reset()
			if code := run(args, tc.writer, &stderr); code != 1 ||
				!strings.Contains(stderr.String(), "cannot write replay receipt") {
				t.Fatalf("failed receipt reported success: exit=%d stderr=%s", code, stderr.String())
			}
		})
	}
	wrongUID := append([]string(nil), args...)
	wrongUID[8] = "different-service-uid"
	if code := replay(wrongUID); code != 3 || stdout.Len() != 0 {
		t.Fatalf("mismatched target accepted: exit=%d", code)
	}
	// A parseable archive with changed bytes is not the independently pinned input.
	write(append(append([]byte(nil), raw...), ' '))
	if code := replay(args); code != 3 || stdout.Len() != 0 {
		t.Fatalf("digest mismatch accepted: exit=%d", code)
	}
	write(raw)
	if code := replay(args[:len(args)-2]); code != 2 || stdout.Len() != 0 {
		t.Fatalf("missing pin accepted: exit=%d", code)
	}
	wrongDigest := append([]string(nil), args...)
	wrongDigest[len(wrongDigest)-1] = strings.Repeat("0", 64)
	if code := replay(wrongDigest); code != 3 || stdout.Len() != 0 {
		t.Fatalf("wrong pin accepted: exit=%d", code)
	}
	uppercaseDigest := append([]string(nil), args...)
	uppercaseDigest[len(uppercaseDigest)-1] = strings.ToUpper(args[len(args)-1])
	if code := replay(uppercaseDigest); code != 2 || stdout.Len() != 0 {
		t.Fatalf("noncanonical pin accepted: exit=%d", code)
	}
	// Re-pin adversarial cases so the native semantic validation, not the
	// outer digest mismatch, must reject them.
	repin := func(data []byte) []string {
		out := append([]string(nil), args...)
		out[len(out)-1] = fmt.Sprintf("%x", sha256.Sum256(data))
		return out
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
				if code := replay(repin(data)); code != 3 || stdout.Len() != 0 {
					t.Fatalf("invalid report accepted: exit=%d", code)
				}
			})
		}
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"ready_endpoints", 99},
		{"source_authenticated", true},
	} {
		t.Run("repinned forged "+tc.field, func(t *testing.T) {
			var envelope map[string]any
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			envelope["report"].(map[string]any)[tc.field] = tc.value
			data, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			write(data)
			if code := replay(repin(data)); code != 3 || stdout.Len() != 0 {
				t.Fatalf("forged report accepted: exit=%d", code)
			}
		})
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
	if code := replay(repin(data)); code != 3 || stdout.Len() != 0 {
		t.Fatalf("modified source accepted: exit=%d", code)
	}
}

