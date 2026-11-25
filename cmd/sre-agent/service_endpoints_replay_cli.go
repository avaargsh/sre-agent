package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/avaargsh/sre-agent/internal/endpointarchive"
	"github.com/avaargsh/sre-agent/internal/observe"
)

// replayServiceEndpointsArchive checks an independently pinned archive against
// an independently selected Service and baseline. It performs no live reads,
// grants no authority and never emits raw source evidence.
func replayServiceEndpointsArchive(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("replay-service-endpoints", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var target observe.ServiceTarget
	flags.StringVar(&target.Namespace, "namespace", "", "operator-selected namespace")
	flags.StringVar(&target.Name, "service", "", "operator-selected Service name")
	flags.StringVar(&target.UID, "uid", "", "independently obtained Service UID")
	targetPort := flags.Int("expected-target-port", 0, "operator-owned healthy numeric targetPort")
	selectorText := flags.String("expected-selector", "", "operator-owned selector key=value[,key=value]")
	pin := flags.String("sha256", "", "independently trusted lowercase archive SHA-256")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 ||
		strings.TrimSpace(target.Namespace) == "" || strings.TrimSpace(target.Name) == "" ||
		strings.TrimSpace(target.UID) == "" || *targetPort < 1 || *targetPort > 65535 {
		return 2
	}
	pinBytes, err := hex.DecodeString(*pin)
	if err != nil || len(pinBytes) != sha256.Size || strings.ToLower(*pin) != *pin {
		return 2
	}
	selector, err := parseExpectedSelector(*selectorText)
	if err != nil {
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, endpointarchive.MaxArchiveBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > endpointarchive.MaxArchiveBytes {
		fmt.Fprintln(stderr, "UNKNOWN: invalid endpoint archive input")
		return 3
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != *pin {
		fmt.Fprintln(stderr, "UNKNOWN: endpoint archive digest mismatch")
		return 3
	}
	archive, err := endpointarchive.Decode[observe.ServiceEndpointsReport](raw)
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: invalid endpoint archive")
		return 3
	}
	prediction, err := observe.ReplayServiceEndpointsObservation(target, *targetPort, selector, observe.ServiceEndpointsObservation{
		Report: archive.Report,
		ServiceBeforeRaw: archive.ServiceBeforeRaw,
		EndpointSlicesRaw: archive.EndpointSlicesRaw,
		ServiceAfterRaw: archive.ServiceAfterRaw,
	})
	if err != nil {
		fmt.Fprintln(stderr, "UNKNOWN: endpoint archive replay failed")
		return 3
	}
	receipt := struct {
		SchemaVersion string `json:"schema_version"`
		ArchiveSHA256 string `json:"archive_sha256"`
		Classification string `json:"classification"`
		ReadyEndpoints int `json:"ready_endpoints"`
		SourceAuthenticated bool `json:"source_authenticated"`
	}{
		SchemaVersion: "sre.service-endpoints-replay/v1",
		ArchiveSHA256: archive.ArchiveSHA256,
		Classification: prediction.Classification,
		ReadyEndpoints: prediction.ReadyEndpoints,
		SourceAuthenticated: false,
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		fmt.Fprintln(stderr, "cannot write endpoint archive replay receipt")
		return 1
	}
	return 0
}
