package observe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const canonicalFieldPrometheus = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1795350600,"0.18"]}]}}`

func TestCollectRejectsSingleCaseInsensitivePrometheusFieldAliases(t *testing.T) {
	cases := map[string]string{
		"status": strings.Replace(canonicalFieldPrometheus, `"status":`, `"Status":`, 1),
		"data": strings.Replace(canonicalFieldPrometheus, `"data":`, `"Data":`, 1),
		"resultType": strings.Replace(canonicalFieldPrometheus, `"resultType":`, `"ResultType":`, 1),
		"result": strings.Replace(canonicalFieldPrometheus, `"result":`, `"Result":`, 1),
		"metric": strings.Replace(canonicalFieldPrometheus, `"metric":`, `"Metric":`, 1),
		"value": strings.Replace(canonicalFieldPrometheus, `"value":`, `"Value":`, 1),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if payload == canonicalFieldPrometheus {
				t.Fatal("fixture alias mutation did not apply")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
					_, _ = fmt.Fprint(w, canonicalFieldDeployment)
				case "/api/v1/namespaces/golden-demo/pods":
					_, _ = fmt.Fprint(w, canonicalFieldPodList)
				case "/api/v1/query":
					_, _ = fmt.Fprint(w, payload)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			raw, err := Collect(context.Background(), fixture(srv.URL))
			if !errors.Is(err, ErrUnknown) || raw != nil {
				t.Fatalf("noncanonical Prometheus source must fail closed: raw=%q err=%v", raw, err)
			}
		})
	}
}
