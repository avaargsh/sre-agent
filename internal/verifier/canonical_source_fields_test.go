package verifier

import (
	"context"
	"strings"
	"testing"
)

func TestSLIOracleRejectsSingleCaseInsensitivePrometheusFieldAliases(t *testing.T) {
	good := rangeResponse([]string{"0.12", "0.15", "0.20", "0.16", "0.18"}, -1)
	traffic := rangeResponse([]string{"1", "2", "3", "2", "1"}, -1)
	cases := map[string]string{
		"status":     strings.Replace(good, `"status":`, `"Status":`, 1),
		"data":       strings.Replace(good, `"data":`, `"Data":`, 1),
		"resultType": strings.Replace(good, `"resultType":`, `"ResultType":`, 1),
		"result":     strings.Replace(good, `"result":`, `"Result":`, 1),
		"metric":     strings.Replace(good, `"metric":`, `"Metric":`, 1),
		"values":     strings.Replace(good, `"values":`, `"Values":`, 1),
	}
	for name, latency := range cases {
		t.Run(name, func(t *testing.T) {
			if latency == good {
				t.Fatal("test fixture alias mutation did not apply")
			}
			srv, _ := serveRange(t, latency, traffic)
			got := Assess(context.Background(), policy(srv.URL))
			if got.Status != Unknown || len(got.Evidence) != 0 {
				t.Fatalf("noncanonical Prometheus fields must be UNKNOWN without evidence: status=%s evidence=%d reason=%q", got.Status, len(got.Evidence), got.Reason)
			}
		})
	}
}
