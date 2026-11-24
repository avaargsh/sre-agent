package workloadtopology

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const dep = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"namespace":"demo","name":"checkout","uid":"dep-1","resourceVersion":"10"}}`
const rs = `{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"namespace":"demo","name":"checkout-rs","uid":"rs-1","resourceVersion":"11","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":"checkout","uid":"dep-1","controller":true}]}}`
const pod = `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"demo","name":"checkout-pod","uid":"pod-1","resourceVersion":"12","ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-rs","uid":"rs-1","controller":true}]}}`

func pin(raw string) Snapshot {
	return Snapshot{Raw: []byte(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))}
}
func target() Target {
	return Target{Namespace: "demo", DeploymentName: "checkout", DeploymentUID: "dep-1", PodName: "checkout-pod", PodUID: "pod-1"}
}
func TestOwnershipChain(t *testing.T) {
	extra := `,{"apiVersion":"v1","kind":"ConfigMap","name":"other","uid":"cm-1"}`
	cases := []struct {
		name, d, r, p string
		valid         bool
	}{
		{"valid", dep, rs, pod, true},
		{"non-controller-reference", dep, rs, strings.Replace(pod, `true}]`, `true}`+extra+`]`, 1), true},
		{"foreign-namespace", dep, rs, strings.Replace(pod, `"demo"`, `"other"`, 1), false},
		{"replaced-deployment", strings.Replace(dep, `"dep-1"`, `"dep-new"`, 1), rs, pod, false},
		{"replaced-pod", dep, rs, strings.Replace(pod, `"pod-1"`, `"pod-new"`, 1), false},
		{"replaced-replicaset", dep, strings.Replace(rs, `"rs-1"`, `"rs-new"`, 1), pod, false},
		{"wrong-owner-kind", dep, rs, strings.Replace(pod, `"ReplicaSet"`, `"StatefulSet"`, 1), false},
		{"wrong-owner-version", dep, strings.Replace(rs, `"apiVersion":"apps/v1","kind":"Deployment"`, `"apiVersion":"apps/v2","kind":"Deployment"`, 1), pod, false},
		{"wrong-owner-name", dep, strings.Replace(rs, `"name":"checkout","uid":"dep-1"`, `"name":"other","uid":"dep-1"`, 1), pod, false},
		{"wrong-owner-uid", dep, rs, strings.Replace(pod, `"uid":"rs-1"`, `"uid":"rs-2"`, 1), false},
		{"not-controller", dep, strings.Replace(rs, `"controller":true`, `"controller":false`, 1), pod, false},
		{"missing-controller", dep, rs, strings.Replace(pod, `,"controller":true`, "", 1), false},
		{"null-controller", dep, rs, strings.Replace(pod, `"controller":true`, `"controller":null`, 1), false},
		{"two-controllers", dep, rs, strings.Replace(pod, `true}]`, `true},{"apiVersion":"v1","kind":"ConfigMap","name":"other","uid":"cm-1","controller":true}]`, 1), false},
		{"duplicate-owner-uid", dep, rs, strings.Replace(pod, `true}]`, `true},{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"checkout-rs","uid":"rs-1","controller":false}]`, 1), false},
		{"missing-owner-list", dep, rs, strings.Replace(pod, `"ownerReferences"`, `"otherReferences"`, 1), false},
		{"alias-owner-list", dep, rs, strings.Replace(pod, `"ownerReferences"`, `"OwnerReferences"`, 1), false},
		{"alias-controller", dep, rs, strings.Replace(pod, `"controller"`, `"Controller"`, 1), false},
		{"duplicate-controller", dep, rs, strings.Replace(pod, `"controller":true`, `"controller":false,"controller":true`, 1), false},
		{"wrong-kind", dep, strings.Replace(rs, `"kind":"ReplicaSet"`, `"kind":"Deployment"`, 1), pod, false},
		{"null-rv", dep, rs, strings.Replace(pod, `"resourceVersion":"12"`, `"resourceVersion":null`, 1), false},
		{"malformed-unicode", dep, rs, strings.Replace(pod, `"resourceVersion":"12"`, `"resourceVersion":"\ud800"`, 1), false},
		{"trailing-json", dep, rs, pod + `{}`, false},
		{"cross-kind-uid-reuse", dep, strings.Replace(rs, `"uid":"rs-1"`, `"uid":"dep-1"`, 1), strings.Replace(pod, `"uid":"rs-1"`, `"uid":"dep-1"`, 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, r, p := pin(tc.d), pin(tc.r), pin(tc.p)
			got, err := Verify(target(), d, r, p)
			if !tc.valid {
				if err == nil || got.Status != "" || len(got.Sources) != 0 {
					t.Fatalf("invalid chain admitted: %+v %v", got, err)
				}
				return
			}
			if err != nil || got.Status != "LINKED" || len(got.Sources) != 3 || got.Sources[0].UID != "dep-1" || got.Sources[1].UID != "rs-1" || got.Sources[2].UID != "pod-1" || got.Sources[0].SHA256 != d.SHA256 || got.Sources[1].SHA256 != r.SHA256 || got.Sources[2].SHA256 != p.SHA256 || got.SourceAuthenticated || got.RootCauseVerified || got.RecoveryVerified {
				t.Fatalf("wrong report: %+v %v", got, err)
			}
		})
	}
}
func TestPinsAndTargetAreRequired(t *testing.T) {
	for _, name := range []string{"missing-pin", "wrong-pin", "changed-bytes", "missing-target", "oversize"} {
		t.Run(name, func(t *testing.T) {
			d, r, p := pin(dep), pin(rs), pin(pod)
			expected := target()
			switch name {
			case "missing-pin":
				p.SHA256 = ""
			case "wrong-pin":
				p.SHA256 = strings.Repeat("0", 64)
			case "changed-bytes":
				p.Raw = append(p.Raw, '\n')
			case "missing-target":
				expected.PodUID = ""
			case "oversize":
				p = pin(strings.Repeat(" ", MaxSnapshotBytes+1))
			}
			got, err := Verify(expected, d, r, p)
			if err == nil || got.Status != "" || len(got.Sources) != 0 {
				t.Fatalf("invalid source admitted: %+v %v", got, err)
			}
		})
	}
}
