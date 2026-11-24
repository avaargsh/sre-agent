package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/avaargsh/sre-agent/internal/workloadtopology"
)

func topologyFlags(flags *flag.FlagSet, t *workloadtopology.Target, rs *string) {
	flags.StringVar(&t.Namespace, "namespace", "", "operator-selected namespace")
	flags.StringVar(&t.DeploymentName, "deployment", "", "operator-selected Deployment name")
	flags.StringVar(&t.DeploymentUID, "deployment-uid", "", "independently obtained Deployment UID")
	flags.StringVar(rs, "replicaset", "", "operator-selected ReplicaSet name")
	flags.StringVar(&t.PodName, "pod", "", "operator-selected Pod name")
	flags.StringVar(&t.PodUID, "pod-uid", "", "independently obtained Pod UID")
}
func topologyTargetPresent(t workloadtopology.Target, rs string) bool {
	for _, value := range []string{t.Namespace, t.DeploymentName, t.DeploymentUID, rs, t.PodName, t.PodUID} {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

// captureTopology uses an operator-controlled API proxy, without credentials.
// Its output contains sensitive raw snapshots. Capture hashes are not trust pins.
func captureTopology(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("capture-topology", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var target workloadtopology.Target
	var rs string
	topologyFlags(flags, &target, &rs)
	endpoint := flags.String("kube-api", "", "operator-controlled Kubernetes endpoint")
	timeout := flags.Duration("timeout", 15*time.Second, "bounded collection deadline")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || !topologyTargetPresent(target, rs) || *endpoint == "" || *timeout <= 0 || *timeout > 30*time.Second {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	obs, err := workloadtopology.Collect(ctx, workloadtopology.CollectConfig{APIURL: *endpoint, Target: target, ReplicaSetName: rs})
	if err != nil || len(obs.Snapshots) != 3 {
		fmt.Fprintln(stderr, "UNKNOWN: topology capture rejected")
		return 3
	}
	pins := [3]string{obs.Snapshots[0].SHA256, obs.Snapshots[1].SHA256, obs.Snapshots[2].SHA256}
	raw, err := workloadtopology.MarshalObservationJSON(target, rs, pins, obs)
	if err != nil || ctx.Err() != nil {
		fmt.Fprintln(stderr, "UNKNOWN: topology encoding rejected")
		return 3
	}
	if n, err := stdout.Write(raw); err != nil || n != len(raw) {
		fmt.Fprintln(stderr, "cannot write topology observation")
		return 1
	}
	return 0
}

// verifyTopology requires independent pins; no API endpoint or credentials.
func verifyTopology(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-topology", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var target workloadtopology.Target
	var rs string
	topologyFlags(flags, &target, &rs)
	var pins [3]string
	flags.StringVar(&pins[0], "deployment-sha256", "", "independently trusted Deployment digest")
	flags.StringVar(&pins[1], "replicaset-sha256", "", "independently trusted ReplicaSet digest")
	flags.StringVar(&pins[2], "pod-sha256", "", "independently trusted Pod digest")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || !topologyTargetPresent(target, rs) {
		return 2
	}
	for _, pin := range pins {
		if len(pin) != 2*sha256.Size || strings.ToLower(pin) != pin {
			return 2
		}
		if _, err := hex.DecodeString(pin); err != nil {
			return 2
		}
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, workloadtopology.MaxObservationJSONBytes+1))
	if err != nil || len(raw) > workloadtopology.MaxObservationJSONBytes || workloadtopology.VerifyObservationJSON(target, rs, pins, raw) != nil {
		fmt.Fprintln(stderr, "UNKNOWN: topology verification failed")
		return 3
	}
	const result = "STRUCTURALLY_LINKED\n"
	if n, err := io.WriteString(stdout, result); err != nil || n != len(result) {
		fmt.Fprintln(stderr, "cannot write verification result")
		return 1
	}
	return 0
}
