package observe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const canonicalFieldDeployment = `{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"1","generation":1},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"checkout-api"}}},"status":{"readyReplicas":1,"observedGeneration":1}}`
const canonicalFieldPodList = `{"metadata":{"resourceVersion":"2"},"items":[{"metadata":{"uid":"p1","name":"checkout-api-0","namespace":"golden-demo"},"status":{"phase":"Running"}}]}`

func TestCollectRejectsSingleCaseInsensitiveKubernetesFieldAliases(t *testing.T) {
	cases := []struct {
		name, deployment, podList string
		wantPodRead, wantMetricRead bool
	}{
		{
			name: "deployment root metadata alias",
			deployment: strings.Replace(canonicalFieldDeployment, `"metadata":`, `"Metadata":`, 1),
			podList: canonicalFieldPodList,
		},
		{
			name: "deployment nested resourceVersion alias",
			deployment: strings.Replace(canonicalFieldDeployment, `"resourceVersion":`, `"ResourceVersion":`, 1),
			podList: canonicalFieldPodList,
		},
		{
			name: "PodList items alias",
			deployment: canonicalFieldDeployment,
			podList: strings.Replace(canonicalFieldPodList, `"items":`, `"Items":`, 1),
			wantPodRead: true,
		},
		{
			name: "Pod status phase alias",
			deployment: canonicalFieldDeployment,
			podList: strings.Replace(canonicalFieldPodList, `"phase":`, `"Phase":`, 1),
			wantPodRead: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var podReads, metricReads atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/apis/apps/v1/namespaces/golden-demo/deployments/checkout-api":
					_, _ = fmt.Fprint(w, tc.deployment)
				case "/api/v1/namespaces/golden-demo/pods":
					podReads.Add(1)
					_, _ = fmt.Fprint(w, tc.podList)
				case "/api/v1/query":
					metricReads.Add(1)
					_, _ = fmt.Fprint(w, validSample)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			raw, err := Collect(context.Background(), fixture(srv.URL))
			if !errors.Is(err, ErrUnknown) || raw != nil {
				t.Fatalf("noncanonical Kubernetes source must fail closed: raw=%q err=%v", raw, err)
			}
			if got := podReads.Load() > 0; got != tc.wantPodRead {
				t.Fatalf("Pod read occurred=%v, want %v", got, tc.wantPodRead)
			}
			if got := metricReads.Load() > 0; got != tc.wantMetricRead {
				t.Fatalf("Prometheus read occurred=%v, want %v", got, tc.wantMetricRead)
			}
		})
	}
}
