// Package workloadtopology verifies an offline, pinned native ownership chain.
// It does not collect resources, establish snapshot freshness or authenticate an issuer.
package workloadtopology

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/avaargsh/sre-agent/internal/sourcejson"
)

const MaxSnapshotBytes = 2 << 20
const maxOwners = 128

var errInvalid = errors.New("invalid, incomplete or mismatched workload ownership evidence")

// Snapshot pairs exact source bytes with a separately supplied SHA-256 pin.
// A pin derived from untrusted input is not an independent trust anchor.
type Snapshot struct {
	Raw    []byte
	SHA256 string
}
type Target struct{ Namespace, DeploymentName, DeploymentUID, PodName, PodUID string }
type Source struct {
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	SHA256          string `json:"sha256"`
}
type Report struct {
	Status              string   `json:"status"`
	Sources             []Source `json:"sources"`
	SourceAuthenticated bool     `json:"source_authenticated"`
	RootCauseVerified   bool     `json:"root_cause_verified"`
	RecoveryVerified    bool     `json:"recovery_verified"`
}

type object map[string]json.RawMessage

func parseObject(raw []byte, reserved ...string) (object, error) {
	var m object
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, errInvalid
	}
	for k := range m {
		for _, canonical := range reserved {
			if k != canonical && strings.EqualFold(k, canonical) {
				return nil, errInvalid
			}
		}
	}
	return m, nil
}
func field[T any](m object, k string) (T, error) {
	var v T
	raw, ok := m[k]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &v) != nil {
		return v, errInvalid
	}
	return v, nil
}
func bounded(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}
func identity(s string, max int) bool { return bounded(s, max) && !strings.ContainsAny(s, " /\\") }

type owner struct{ version, kind, name, uid string }

func controller(meta object) (owner, error) {
	refs, err := field[[]json.RawMessage](meta, "ownerReferences")
	if err != nil || len(refs) == 0 || len(refs) > maxOwners {
		return owner{}, errInvalid
	}
	seen := map[string]bool{}
	var found owner
	for _, raw := range refs {
		m, err := parseObject(raw, "apiVersion", "kind", "name", "uid", "controller")
		if err != nil {
			return owner{}, err
		}
		version, e1 := field[string](m, "apiVersion")
		kind, e2 := field[string](m, "kind")
		name, e3 := field[string](m, "name")
		uid, e4 := field[string](m, "uid")
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !bounded(version, 128) || !identity(kind, 128) || !identity(name, 253) || !identity(uid, 128) || seen[uid] {
			return owner{}, errInvalid
		}
		seen[uid] = true
		if _, ok := m["controller"]; !ok {
			continue
		}
		ctrl, err := field[bool](m, "controller")
		if err != nil {
			return owner{}, err
		}
		if ctrl {
			if found.uid != "" {
				return owner{}, errInvalid
			}
			found = owner{version, kind, name, uid}
		}
	}
	if found.uid == "" {
		return owner{}, errInvalid
	}
	return found, nil
}
func inspect(s Snapshot, version, kind string) (Source, object, error) {
	if len(s.Raw) == 0 || len(s.Raw) > MaxSnapshotBytes || len(s.SHA256) != 64 {
		return Source{}, nil, errInvalid
	}
	sum := sha256.Sum256(s.Raw)
	if hex.EncodeToString(sum[:]) != s.SHA256 || sourcejson.Validate(s.Raw) != nil {
		return Source{}, nil, errInvalid
	}
	root, err := parseObject(s.Raw, "apiVersion", "kind", "metadata")
	if err != nil {
		return Source{}, nil, err
	}
	v, e1 := field[string](root, "apiVersion")
	k, e2 := field[string](root, "kind")
	if e1 != nil || e2 != nil || v != version || k != kind {
		return Source{}, nil, errInvalid
	}
	meta, err := parseObject(root["metadata"], "namespace", "name", "uid", "resourceVersion", "ownerReferences")
	if err != nil {
		return Source{}, nil, err
	}
	ns, e1 := field[string](meta, "namespace")
	name, e2 := field[string](meta, "name")
	uid, e3 := field[string](meta, "uid")
	rv, e4 := field[string](meta, "resourceVersion")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !identity(ns, 63) || !identity(name, 253) || !identity(uid, 128) || !bounded(rv, 256) {
		return Source{}, nil, errInvalid
	}
	return Source{Kind: kind, Namespace: ns, Name: name, UID: uid, ResourceVersion: rv, SHA256: s.SHA256}, meta, nil
}

// Verify checks only the content of the three pinned snapshots and the
// caller-selected endpoint identities. LINKED is not an assertion that the
// resources were observed atomically, currently exist, or caused an incident.
func Verify(expected Target, deployment, replicaSet, pod Snapshot) (Report, error) {
	if !identity(expected.Namespace, 63) || !identity(expected.DeploymentName, 253) || !identity(expected.DeploymentUID, 128) || !identity(expected.PodName, 253) || !identity(expected.PodUID, 128) {
		return Report{}, errInvalid
	}
	d, _, err := inspect(deployment, "apps/v1", "Deployment")
	if err != nil {
		return Report{}, err
	}
	r, rm, err := inspect(replicaSet, "apps/v1", "ReplicaSet")
	if err != nil {
		return Report{}, err
	}
	p, pm, err := inspect(pod, "v1", "Pod")
	if err != nil {
		return Report{}, err
	}
	if d.Namespace != expected.Namespace || r.Namespace != expected.Namespace || p.Namespace != expected.Namespace || d.Name != expected.DeploymentName || d.UID != expected.DeploymentUID || p.Name != expected.PodName || p.UID != expected.PodUID || d.UID == r.UID || r.UID == p.UID || d.UID == p.UID {
		return Report{}, errInvalid
	}
	ro, err := controller(rm)
	if err != nil || ro != (owner{"apps/v1", "Deployment", d.Name, d.UID}) {
		return Report{}, errInvalid
	}
	po, err := controller(pm)
	if err != nil || po != (owner{"apps/v1", "ReplicaSet", r.Name, r.UID}) {
		return Report{}, errInvalid
	}
	return Report{Status: "LINKED", Sources: []Source{d, r, p}}, nil
}
