package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const topologyDeployment = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"namespace":"demo","name":"checkout","uid":"dep-1","resourceVersion":"10"}}`
const topologyReplicaSet = `{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"namespace":"demo","name":"checkout-rs","uid":"rs-1","resourceVersion":"11","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-1","controller":true}]}}`
const topologyPod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-pod","uid":"pod-1","resourceVersion":"12","ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-rs","uid":"rs-1","controller":true}]}}`

func topologyArgs() []string {
	return []string{"--namespace", "demo", "--deployment", "checkout", "--deployment-uid", "dep-1", "--replicaset", "checkout-rs", "--pod", "checkout-pod", "--pod-uid", "pod-1"}
}
func topologyVerifyArgs() []string {
	return append(topologyArgs(), "--deployment-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(topologyDeployment))), "--replicaset-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(topologyReplicaSet))), "--pod-sha256", fmt.Sprintf("%x", sha256.Sum256([]byte(topologyPod))))
}
func topologyServer(t *testing.T, drift bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	paths := []string{"/apis/apps/v1/namespaces/demo/deployments/checkout", "/apis/apps/v1/namespaces/demo/replicasets/checkout-rs", "/api/v1/namespaces/demo/pods/checkout-pod"}
	bodies := []string{topologyDeployment, topologyReplicaSet, topologyPod}
	order := []int{0, 1, 2, 2, 1, 0}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(hits.Add(1)) - 1
		if i >= len(order) || r.Method != http.MethodGet || r.URL.RequestURI() != paths[order[i]] || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(400)
			return
		}
		body := bodies[order[i]]
		if drift && i == 3 {
			body = strings.Replace(body, `"12"`, `"13"`, 1)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

type topologyShortWriter struct{}

func (topologyShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestTopologyCLICaptureAndVerify(t *testing.T) {
	srv, hits := topologyServer(t, false)
	var out, errOut bytes.Buffer
	if rc := captureTopology(append(topologyArgs(), "--kube-api", srv.URL), &out, &errOut); rc != 0 || hits.Load() != 6 || errOut.Len() != 0 {
		t.Fatalf("capture rc=%d reads=%d stderr=%s", rc, hits.Load(), errOut.String())
	}
	raw := append([]byte(nil), out.Bytes()...)
	out.Reset()
	if rc := verifyTopology(topologyVerifyArgs(), bytes.NewReader(raw), &out, &errOut); rc != 0 || out.String() != "STRUCTURALLY_LINKED\n" || errOut.Len() != 0 {
		t.Fatalf("verify rc=%d stdout=%q stderr=%q", rc, out.String(), errOut.String())
	}
	for _, tc := range []struct {
		name string
		args []string
		raw  []byte
		code int
	}{
		{"missing-pins", topologyArgs(), raw, 2},
		{"wrong-pin", append(topologyVerifyArgs(), "--pod-sha256", strings.Repeat("0", 64)), raw, 3},
		{"uppercase-pin", append(topologyVerifyArgs(), "--pod-sha256", strings.Repeat("A", 64)), raw, 2},
		{"forged-report", topologyVerifyArgs(), bytes.Replace(raw, []byte(`"root_cause_verified":false`), []byte(`"root_cause_verified":true`), 1), 3},
		{"trailing", topologyVerifyArgs(), append(append([]byte(nil), raw...), []byte("{}")...), 3},
		{"empty", topologyVerifyArgs(), nil, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			errOut.Reset()
			if rc := verifyTopology(tc.args, bytes.NewReader(tc.raw), &out, &errOut); rc != tc.code || out.Len() != 0 {
				t.Fatalf("rc=%d want=%d stdout=%q", rc, tc.code, out.String())
			}
		})
	}
	if rc := verifyTopology(topologyVerifyArgs(), bytes.NewReader(raw), topologyShortWriter{}, io.Discard); rc != 1 {
		t.Fatalf("short verify write rc=%d", rc)
	}
	if hits.Load() != 6 {
		t.Fatal("offline verification initiated HTTP")
	}
}

func TestTopologyCLIRejectsDriftAndBadArguments(t *testing.T) {
	srv, hits := topologyServer(t, true)
	var out, errOut bytes.Buffer
	for _, args := range [][]string{topologyArgs(), append(topologyArgs(), "--kube-api", srv.URL, "--timeout", "0s"), append(topologyArgs(), "--kube-api", srv.URL, "--timeout", "31s"), append(topologyArgs(), "--kube-api", srv.URL, "extra")} {
		if rc := captureTopology(args, &out, &errOut); rc != 2 || out.Len() != 0 || hits.Load() != 0 {
			t.Fatalf("bad args rc=%d reads=%d", rc, hits.Load())
		}
	}
	if rc := captureTopology(append(topologyArgs(), "--kube-api", srv.URL), &out, &errOut); rc != 3 || out.Len() != 0 || hits.Load() != 4 {
		t.Fatalf("drift rc=%d reads=%d", rc, hits.Load())
	}
}
func TestTopologyCLICaptureShortWrite(t *testing.T) {
	srv, hits := topologyServer(t, false)
	if rc := captureTopology(append(topologyArgs(), "--kube-api", srv.URL), topologyShortWriter{}, io.Discard); rc != 1 || hits.Load() != 6 {
		t.Fatalf("short capture rc=%d reads=%d", rc, hits.Load())
	}
}
