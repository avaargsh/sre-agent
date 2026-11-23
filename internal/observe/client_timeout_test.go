package observe

import (
	"net/http"
	"testing"
	"time"
)

// A caller-supplied http.Client must not silently disable the read budget.
func TestReadOnlyHTTPClientEnforcesBoundedTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		given, want time.Duration
	}{
		{"zero-custom-client", 0, 10 * time.Second},
		{"negative-custom-client", -time.Second, 10 * time.Second},
		{"shorter-custom-client", 2 * time.Second, 2 * time.Second},
		{"bounded-custom-client", 15 * time.Second, 15 * time.Second},
		{"excessive-custom-client", time.Minute, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := &http.Client{Timeout: tc.given}
			actual := client(Config{Client: caller})
			if actual.Timeout != tc.want {
				t.Fatalf("timeout=%s want=%s", actual.Timeout, tc.want)
			}
			if caller.Timeout != tc.given {
				t.Fatalf("caller's client mutated: timeout=%s", caller.Timeout)
			}
		})
	}
	defaultClient := client(Config{})
	if defaultClient.Timeout != 10*time.Second {
		t.Fatalf("unexpected default timeout: %s", defaultClient.Timeout)
	}
}

func TestReadOnlyHTTPClientRetainsTransportAndNeverFollowsRedirects(t *testing.T) {
	transport := &http.Transport{}
	caller := &http.Client{Timeout: time.Second, Transport: transport}
	actual := client(Config{Client: caller})
	if actual.Transport != transport { t.Fatal("custom transport lost") }
	req, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if err != nil { t.Fatal(err) }
	if err := actual.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect was not refused: %v", err)
	}
}
