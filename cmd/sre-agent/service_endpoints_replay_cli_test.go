package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func pinnedEndpointReplayArgs(raw []byte) []string {
	return []string{
		"--namespace", "demo", "--service", "checkout-api", "--uid", "service-uid-1",
		"--expected-target-port", "8080", "--expected-selector", "app=checkout-api",
		"--sha256", fmt.Sprintf("%x", sha256.Sum256(raw)),
	}
}

func TestPinnedServiceEndpointsArchiveReplay(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/api/v1/namespaces/demo/services/checkout-api":
			_, _ = fmt.Fprint(w, cliServiceEndpointService)
		case "/apis/discovery.k8s.io/v1/namespaces/demo/endpointslices":
			_, _ = fmt.Fprint(w, cliServiceEndpointSlices)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var capture, stderr bytes.Buffer
	if code := captureServiceEndpoints(cliServiceEndpointArgs(server.URL), &capture, &stderr); code != 0 {
		t.Fatalf("capture exit=%d stderr=%s", code, stderr.String())
	}
	raw := capture.Bytes()
	if hits.Load() != 3 {
		t.Fatal("unexpected collection read count")
	}
	path := filepath.Join(t.TempDir(), "archive.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous; _ = input.Close() }()
	var out bytes.Buffer
	stderr.Reset()
	if code := run(append([]string{"replay-service-endpoints"}, pinnedEndpointReplayArgs(raw)...), &out, &stderr); code != 0 {
		t.Fatalf("replay exit=%d stderr=%s", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] != "sre.service-endpoints-replay/v1" ||
		got["archive_sha256"] != fmt.Sprintf("%x", sha256.Sum256(raw)) ||
		got["classification"] != "READY_ENDPOINTS_OBSERVED" ||
		got["ready_endpoints"] != float64(1) || got["source_authenticated"] != false {
		t.Fatalf("unexpected receipt: %s", out.String())
	}
	if len(got) != 5 || hits.Load() != 3 || strings.Contains(out.String(), "10.0.0.10") {
		t.Fatal("replay made network calls or emitted source bytes")
	}

	var claim cliServiceEndpointsCapture
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	claim.Report.ReadyEndpoints++
	forged, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	claim.Report.ReadyEndpoints--
	claim.Report.SourceAuthenticated = true
	authClaim, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	wrongUID := pinnedEndpointReplayArgs(raw)
	wrongUID[5] = "service-uid-other"
	for _, tc := range []struct {
		name string
		raw []byte
		args []string
		code int
	}{
		{"digest mismatch", append(append([]byte{}, raw...), ' '), pinnedEndpointReplayArgs(raw), 3},
		{"forged count with matching digest", forged, pinnedEndpointReplayArgs(forged), 3},
		{"authentication claim with matching digest", authClaim, pinnedEndpointReplayArgs(authClaim), 3},
		{"wrong selected uid", raw, wrongUID, 3},
		{"invalid json with matching digest", []byte("private-invalid-json"), pinnedEndpointReplayArgs([]byte("private-invalid-json")), 3},
		{"missing expected pin", raw, pinnedEndpointReplayArgs(raw)[:10], 2},
		{"oversized archive", bytes.Repeat([]byte{' '}, (10<<20)+1), pinnedEndpointReplayArgs(raw), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			stderr.Reset()
			if code := replayServiceEndpointsArchive(tc.args, bytes.NewReader(tc.raw), &out, &stderr); code != tc.code || out.Len() != 0 || strings.Contains(stderr.String(), "private-invalid-json") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if hits.Load() != 3 {
				t.Fatal("offline replay issued source reads")
			}
		})
	}
}
