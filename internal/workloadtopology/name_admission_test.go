package workloadtopology

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// Build a consistently re-pinned ownership chain, so rejection cannot be
// attributed to a stale digest or mismatching controller reference.
func TestOwnershipNameAdmission(t *testing.T) {
	for _, tc := range []struct {
		label, ns, deployment, replicaSet, pod string
		valid                                  bool
	}{
		{"valid", "demo", "checkout", "checkout-rs", "checkout-pod", true},
		{"valid-subdomain", "demo", "checkout.v2", "checkout.v2-rs", "checkout.v2-pod", true},
		{"namespace-uppercase", "Demo", "checkout", "checkout-rs", "checkout-pod", false},
		{"namespace-dot", "demo.prod", "checkout", "checkout-rs", "checkout-pod", false},
		{"deployment-uppercase", "demo", "Checkout", "checkout-rs", "checkout-pod", false},
		{"deployment-trailing-dot", "demo", "checkout.", "checkout-rs", "checkout-pod", false},
		{"replicaset-underscore", "demo", "checkout", "checkout_rs", "checkout-pod", false},
		{"pod-dotdot", "demo", "checkout", "checkout-rs", "checkout..pod", false},
		{"pod-percent", "demo", "checkout", "checkout-rs", "checkout%2f", false},
		{"pod-leading-hyphen", "demo", "checkout", "checkout-rs", "-checkout", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			makeSnapshot := func(raw string) Snapshot {
				return Snapshot{Raw: []byte(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))}
			}
			d := makeSnapshot(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"namespace":%q,"name":%q,"uid":"d","resourceVersion":"1"}}`, tc.ns, tc.deployment))
			r := makeSnapshot(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"namespace":%q,"name":%q,"uid":"r","resourceVersion":"2","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":%q,"uid":"d","controller":true}]}}`, tc.ns, tc.replicaSet, tc.deployment))
			p := makeSnapshot(fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":%q,"name":%q,"uid":"p","resourceVersion":"3","ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":%q,"uid":"r","controller":true}]}}`, tc.ns, tc.pod, tc.replicaSet))
			expected := Target{Namespace: tc.ns, DeploymentName: tc.deployment, DeploymentUID: "d", PodName: tc.pod, PodUID: "p"}
			report, err := Verify(expected, d, r, p)
			if tc.valid {
				if err != nil || report.Status != "LINKED" || len(report.Sources) != 3 {
					t.Fatalf("valid chain refused: %+v %v", report, err)
				}
			} else if err == nil || report.Status != "" || len(report.Sources) != 0 {
				t.Fatalf("invalid name admitted: %+v %v", report, err)
			}
		})
	}
}
