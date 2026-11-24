package workloadtopology

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrUnknown = errors.New("workload ownership observation UNKNOWN")
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

const collectionTimeout = 30 * time.Second

type CollectConfig struct {
	APIURL                      string
	Target                      Target
	ReplicaSetName, BearerToken string
	Client                      *http.Client
}

// Observation retains both exact read rounds in Deployment, ReplicaSet, Pod
// order (the second round was requested in reverse). These may contain
// sensitive Pod configuration. Capture hashes are not independent trust pins.
type Observation struct {
	Report        Report
	Snapshots     []Snapshot
	Confirmations []Snapshot
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) > 63 || !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func sourceURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrUnknown
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrUnknown
		}
	} else if u.Scheme != "https" {
		return nil, ErrUnknown
	}
	return u, nil
}

func readSnapshot(ctx context.Context, hc *http.Client, u *url.URL, path, token string) (Snapshot, error) {
	if ctx.Err() != nil {
		return Snapshot{}, ErrUnknown
	}
	endpoint := *u
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Snapshot{}, ErrUnknown
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := hc.Do(req)
	if err != nil {
		return Snapshot{}, ErrUnknown
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Snapshot{}, ErrUnknown
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxSnapshotBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxSnapshotBytes || ctx.Err() != nil {
		return Snapshot{}, ErrUnknown
	}
	sum := sha256.Sum256(raw)
	return Snapshot{Raw: raw, SHA256: hex.EncodeToString(sum[:])}, nil
}

// Collect performs six scoped GETs (D,R,P,P,R,D) under one deadline.
// Exact byte equality across each pair is conservative: even harmless status
// or serialization changes cause UNKNOWN. This is not an atomic API snapshot.
func Collect(ctx context.Context, c CollectConfig) (Observation, error) {
	t := c.Target
	if len(t.Namespace) > 63 || !dnsLabel.MatchString(t.Namespace) || !validName(t.DeploymentName) || !validName(t.PodName) || !validName(c.ReplicaSetName) || !identity(t.DeploymentUID, 128) || !identity(t.PodUID, 128) || t.DeploymentUID == t.PodUID {
		return Observation{}, ErrUnknown
	}
	u, err := sourceURL(c.APIURL)
	if err != nil {
		return Observation{}, ErrUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()
	hc := http.Client{}
	if c.Client != nil {
		hc = *c.Client
	}
	if hc.Timeout <= 0 {
		hc.Timeout = 10 * time.Second
	}
	if hc.Timeout > collectionTimeout {
		hc.Timeout = collectionTimeout
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := "/apis/apps/v1/namespaces/" + t.Namespace
	paths := []string{base + "/deployments/" + t.DeploymentName, base + "/replicasets/" + c.ReplicaSetName, "/api/v1/namespaces/" + t.Namespace + "/pods/" + t.PodName}
	snaps := make([]Snapshot, 3)
	for i, path := range paths {
		snaps[i], err = readSnapshot(ctx, &hc, u, path, c.BearerToken)
		if err != nil {
			return Observation{}, ErrUnknown
		}
	}
	report, err := Verify(t, snaps[0], snaps[1], snaps[2])
	if err != nil || report.Sources[1].Name != c.ReplicaSetName {
		return Observation{}, ErrUnknown
	}
	confirmed := make([]Snapshot, 3)
	for i := len(paths) - 1; i >= 0; i-- {
		again, err := readSnapshot(ctx, &hc, u, paths[i], c.BearerToken)
		if err != nil || !bytes.Equal(again.Raw, snaps[i].Raw) {
			return Observation{}, ErrUnknown
		}
		confirmed[i] = again
	}
	if ctx.Err() != nil {
		return Observation{}, ErrUnknown
	}
	return Observation{Report: report, Snapshots: snaps, Confirmations: confirmed}, nil
}
