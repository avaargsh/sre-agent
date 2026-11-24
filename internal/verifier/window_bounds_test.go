package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSLIWindowTimestampBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"normal", time.Unix(1795350600, 0), true},
		{"first-positive-window", time.Unix(15, 0), true},
		{"upper-bound", time.Unix(9000000000, 0), true},
		{"epoch-start", time.Unix(10, 0), false},
		{"negative-start", time.Unix(5, 0), false},
		{"negative-window", time.Unix(-10, 0), false},
		{"zero-clock", time.Time{}, false},
		{"above-supported-range", time.Unix(9000000005, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				rows := make([][]any, 0, 3)
				end := tc.now.UTC().Truncate(5 * time.Second)
				for i := 0; i < 3; i++ {
					rows = append(rows, []any{end.Unix() - 10 + int64(i)*5, "0.2"})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{}, "values": rows}}}})
			}))
			defer srv.Close()
			got := Assess(context.Background(), Policy{PrometheusURL: srv.URL, LatencyQuery: "latency", TrafficQuery: "traffic", AgeQuery: "age", MaxLatencySeconds: 1, MinTrafficPerSecond: .1, MaxSampleAgeSeconds: 1, Window: 10 * time.Second, Step: 5 * time.Second, Now: func() time.Time { return tc.now }})
			if tc.valid {
				if got.Status != Healthy || len(got.Evidence) != 3 || calls.Load() != 3 {
					t.Fatalf("valid window rejected: %s (%s)", got.Status, got.Reason)
				}
			} else if got.Status != Unknown || len(got.Evidence) != 0 || calls.Load() != 0 {
				t.Fatalf("invalid window admitted: status=%s evidence=%d reads=%d", got.Status, len(got.Evidence), calls.Load())
			}
		})
	}
}

func TestSLISampleCannotExceedTimestampLimitWithinAlignmentTolerance(t *testing.T) {
	now := time.Unix(9000000000, 0)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		rows := [][]any{{8999999990, "0.2"}, {8999999995, "0.2"}, {9000000000.0005, "0.2"}}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{}, "values": rows}}}})
	}))
	defer srv.Close()
	got := Assess(context.Background(), Policy{PrometheusURL: srv.URL, LatencyQuery: "latency", TrafficQuery: "traffic", AgeQuery: "age", MaxLatencySeconds: 1, MinTrafficPerSecond: .1, MaxSampleAgeSeconds: 1, Window: 10 * time.Second, Step: 5 * time.Second, Now: func() time.Time { return now }})
	if got.Status != Unknown || len(got.Evidence) != 0 || calls.Load() != 1 {
		t.Fatalf("out-of-range sample admitted: status=%s evidence=%d reads=%d", got.Status, len(got.Evidence), calls.Load())
	}
}
