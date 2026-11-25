package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/avaargsh/sre-agent/internal/endpointarchive"
	"github.com/avaargsh/sre-agent/internal/observe"
)

// replayServiceEndpoints recomputes a source-only observation offline against
// an independently supplied baseline. A successful replay is not proof of
// source authenticity, incident causality, or permission to execute changes.
func replayServiceEndpoints(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("replay-service-endpoints", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("capture", "", "bounded native endpoint capture file")
	var target observe.ServiceTarget
	flags.StringVar(&target.Namespace, "namespace", "", "independently selected namespace")
	flags.StringVar(&target.Name, "service", "", "independently selected Service name")
	flags.StringVar(&target.UID, "uid", "", "independently selected Service UID")
	port := flags.Int("expected-target-port", 0, "independent healthy numeric targetPort")
	selectorText := flags.String("expected-selector", "", "independent selector key=value[,key=value]")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 ||
		strings.TrimSpace(*path) == "" || strings.TrimSpace(target.Namespace) == "" ||
		strings.TrimSpace(target.Name) == "" || strings.TrimSpace(target.UID) == "" ||
		*port < 1 || *port > 65535 {
		fmt.Fprintln(stderr, "invalid replay arguments")
		return 2
	}
	selector, err := parseExpectedSelector(*selectorText)
	if err != nil {
		fmt.Fprintln(stderr, "invalid expected Service selector")
		return 2
	}
	raw, err := boundedAlertFile(*path, endpointarchive.MaxArchiveBytes)
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: capture file rejected")
		return 3
	}
	capture, err := endpointarchive.Decode[observe.ServiceEndpointsReport](raw)
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: capture archive rejected")
		return 3
	}
	prediction, err := observe.ReplayServiceEndpointsObservation(target, *port, selector, observe.ServiceEndpointsObservation{
		Report:            capture.Report,
		ServiceBeforeRaw:  capture.ServiceBeforeRaw,
		EndpointSlicesRaw: capture.EndpointSlicesRaw,
		ServiceAfterRaw:   capture.ServiceAfterRaw,
	})
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: capture replay rejected")
		return 3
	}
	receipt := map[string]any{
		"schema_version":       "sre.service-endpoints-replay/v1",
		"status":               "REPLAYED",
		"archive_sha256":       capture.ArchiveSHA256,
		"classification":       prediction.Classification,
		"ready_endpoints":      prediction.ReadyEndpoints,
		"source_authenticated": false,
		"causality_verified":   false,
		"execution_authorized": false,
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "cannot write replay receipt")
		return 1
	}
	return 0
}
