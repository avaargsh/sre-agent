package workloadtopology

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectOwnership(t *testing.T) {
	paths := []string{"/apis/apps/v1/namespaces/demo/deployments/checkout", "/apis/apps/v1/namespaces/demo/replicasets/checkout-rs", "/api/v1/namespaces/demo/pods/checkout-pod"}
	for _, tc := range []struct {
		name      string
		failAt    int
		body      string
		status    int
		wantReads int
	}{
		{"stable", -1, "", 0, 6},
		{"deployment-drift", 5, strings.Replace(dep, `"10"`, `"13"`, 1), 200, 6},
		{"replicaset-drift", 4, strings.Replace(rs, `"11"`, `"14"`, 1), 200, 5},
		{"pod-drift", 3, strings.Replace(pod, `"12"`, `"15"`, 1), 200, 4},
		{"wrong-owner", 2, strings.Replace(pod, `"rs-1"`, `"other"`, 1), 200, 3},
		{"wrong-replicaset-name", 1, strings.Replace(rs, `"name":"checkout-rs"`, `"name":"other"`, 1), 200, 3},
		{"forbidden", 1, "", 403, 2},
		{"not-found", 0, "", 404, 1},
		{"oversize", 0, strings.Repeat("x", MaxSnapshotBytes+1), 200, 1},
		{"redirect", 0, "", 302, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			var outside atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside.Add(1) }))
			defer other.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				i := calls
				calls++
				mu.Unlock()
				order := []int{0, 1, 2, 2, 1, 0}
				if i >= len(order) || r.Method != http.MethodGet || r.URL.RequestURI() != paths[order[i]] || r.Header.Get("Authorization") != "Bearer lab-token" {
					t.Errorf("unexpected request %d: %s %s", i, r.Method, r.URL.RequestURI())
					w.WriteHeader(400)
					return
				}
				if i == tc.failAt {
					if tc.status == 302 {
						http.Redirect(w, r, other.URL, 302)
						return
					}
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprint(w, tc.body)
					return
				}
				_, _ = fmt.Fprint(w, []string{dep, rs, pod}[order[i]])
			}))
			defer srv.Close()
			got, err := Collect(context.Background(), CollectConfig{APIURL: srv.URL, Target: target(), ReplicaSetName: "checkout-rs", BearerToken: "lab-token"})
			mu.Lock()
			n := calls
			mu.Unlock()
			if n != tc.wantReads || outside.Load() != 0 {
				t.Fatalf("reads=%d outside=%d", n, outside.Load())
			}
			if tc.name != "stable" {
				if !errors.Is(err, ErrUnknown) || got.Report.Status != "" || len(got.Snapshots) != 0 || len(got.Confirmations) != 0 {
					t.Fatalf("invalid capture admitted: %+v %v", got.Report, err)
				}
				return
			}
			if err != nil || got.Report.Status != "LINKED" || len(got.Snapshots) != 3 || len(got.Confirmations) != 3 || got.Report.SourceAuthenticated || got.Report.RootCauseVerified || got.Report.RecoveryVerified {
				t.Fatalf("wrong observation: %+v %v", got.Report, err)
			}
			for i, raw := range []string{dep, rs, pod} {
				if string(got.Snapshots[i].Raw) != raw || got.Snapshots[i].SHA256 != pin(raw).SHA256 || string(got.Confirmations[i].Raw) != raw || got.Confirmations[i].SHA256 != pin(raw).SHA256 {
					t.Fatal("raw mismatch")
				}
			}
			replay, err := Verify(target(), got.Snapshots[0], got.Snapshots[1], got.Snapshots[2])
			if err != nil || replay.Status != "LINKED" {
				t.Fatalf("replay failed: %v", err)
			}
		})
	}
}

func TestCollectRejectsInvalidTargetBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	for _, name := range []string{"../secrets", "a/b", "a?x=y", "a%2fb", "", "a..b", "-a"} {
		got, err := Collect(context.Background(), CollectConfig{APIURL: srv.URL, Target: target(), ReplicaSetName: name})
		if !errors.Is(err, ErrUnknown) || len(got.Snapshots) != 0 || len(got.Confirmations) != 0 {
			t.Fatalf("unsafe name admitted: %q %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := Collect(ctx, CollectConfig{APIURL: srv.URL, Target: target(), ReplicaSetName: "checkout-rs"}); !errors.Is(err, ErrUnknown) || len(got.Snapshots) != 0 || len(got.Confirmations) != 0 {
		t.Fatalf("canceled capture admitted: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid config initiated %d reads", calls.Load())
	}
}

func TestCollectCanceledDuringRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }))
	defer srv.Close()
	got, err := Collect(ctx, CollectConfig{APIURL: srv.URL, Target: target(), ReplicaSetName: "checkout-rs"})
	if !errors.Is(err, ErrUnknown) || len(got.Snapshots) != 0 || len(got.Confirmations) != 0 || calls.Load() > 1 {
		t.Fatalf("canceled read admitted: %v, reads=%d", err, calls.Load())
	}
}
