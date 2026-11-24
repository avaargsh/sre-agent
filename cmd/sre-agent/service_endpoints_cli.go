package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/avaargsh/sre-agent/internal/observe"
)

type serviceEndpointsCapture struct {
	SchemaVersion    string                         `json:"schema_version"`
	Report           observe.ServiceEndpointsReport `json:"report"`
	ServiceBeforeRaw []byte                         `json:"service_before_raw"`
	EndpointSlicesRaw []byte                        `json:"endpoint_slices_raw"`
	ServiceAfterRaw  []byte                         `json:"service_after_raw"`
}

func parseExpectedSelector(raw string) (map[string]string, error) {
	selector := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("expected selector must be comma-separated key=value pairs")
		}
		if _, exists := selector[key]; exists {
			return nil, fmt.Errorf("duplicate expected selector key")
		}
		selector[key] = value
		if len(selector) > 32 {
			return nil, fmt.Errorf("too many expected selector labels")
		}
	}
	if len(selector) == 0 {
		return nil, fmt.Errorf("missing expected selector")
	}
	return selector, nil
}

// captureServiceEndpoints uses an operator-approved API proxy. It accepts no
// Kubernetes credentials and emits the exact bounded source bodies as base64
// JSON byte fields; stdout is sensitive evidence and must be protected.
func captureServiceEndpoints(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("capture-service-endpoints", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var target observe.ServiceTarget
	flags.StringVar(&target.Namespace, "namespace", "", "operator-selected namespace")
	flags.StringVar(&target.Name, "service", "", "operator-selected Service name")
	flags.StringVar(&target.UID, "uid", "", "independently obtained Service UID")
	endpoint := flags.String("kube-api", "", "operator-controlled Kubernetes endpoint")
	targetPort := flags.Int("expected-target-port", 0, "operator-owned healthy numeric targetPort")
	selectorText := flags.String("expected-selector", "", "operator-owned selector key=value[,key=value]")
	timeout := flags.Duration("timeout", 15*time.Second, "bounded collection deadline")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 ||
		strings.TrimSpace(target.Namespace) == "" || strings.TrimSpace(target.Name) == "" ||
		strings.TrimSpace(target.UID) == "" || *endpoint == "" ||
		*targetPort < 1 || *targetPort > 65535 || *timeout <= 0 || *timeout > 30*time.Second {
		return 2
	}
	selector, err := parseExpectedSelector(*selectorText)
	if err != nil {
		fmt.Fprintln(stderr, "invalid expected Service selector")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	observation, err := observe.CollectServiceEndpoints(ctx, observe.ServiceEndpointsConfig{
		KubernetesURL: *endpoint,
		Target: target,
		ExpectedTargetPort: *targetPort,
		ExpectedSelector: selector,
	})
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: Service endpoint capture rejected")
		return 3
	}
	capture := serviceEndpointsCapture{
		SchemaVersion: "sre.service-endpoints-capture/v1",
		Report: observation.Report,
		ServiceBeforeRaw: observation.ServiceBeforeRaw,
		EndpointSlicesRaw: observation.EndpointSlicesRaw,
		ServiceAfterRaw: observation.ServiceAfterRaw,
	}
	if err := json.NewEncoder(stdout).Encode(capture); err != nil {
		fmt.Fprintln(stderr, "cannot write Service endpoint capture")
		return 1
	}
	return 0
}
