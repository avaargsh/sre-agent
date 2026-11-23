package alertintake

import (
 "strings"
 "testing"
)

// Alertmanager commonLabels represents the intersection across all members,
// but the webhook bytes are untrusted and can be forged. Never route an alert
// to an operator-selected cluster if one member omitted the cluster label.
func TestAlertMemberMustCarryIndependentlyScopedCluster(t *testing.T){
 raw := strings.Replace(firingFixture,
  `"labels":{"cluster":"lab-a","namespace":"golden-demo","deployment":"checkout-api"`,
  `"labels":{"namespace":"golden-demo","deployment":"checkout-api"`,1)
 if raw==firingFixture {t.Fatal("missing alert fixture mutation")}
 plan,err:=Parse([]byte(raw),intended)
 if err==nil {t.Fatalf("accepted missing member cluster despite commonLabels: %+v",plan)}
}
