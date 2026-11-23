package alertintake

import (
 "strings"
 "testing"
)

// encoding/json accepts case-insensitive aliases of struct fields. A payload
// with "status" + "Status" may change the effective event type even though
// the keys are not exactly duplicate according to JSON. Reject such aliases
// before decoding into the Alertmanager wire struct.
func TestRejectsCaseAliasOverridesOfTrustBoundaryFields(t *testing.T) {
 cases:=map[string]string{
  "top-level-status":strings.Replace(firingFixture, `"status":"firing",`, `"status":"resolved","Status":"firing",`,1),
  "top-level-group-key":strings.Replace(firingFixture, `"groupKey":"{}:{alertname=\"CheckoutLatency\"}",`,`"groupKey":"group-a","GroupKey":"{}:{alertname=\"CheckoutLatency\"}",`,1),
  "alert-status":strings.Replace(firingFixture, `"status":"firing","fingerprint"`,`"status":"resolved","Status":"firing","fingerprint"`,1),
  "alert-fingerprint":strings.Replace(firingFixture, `"fingerprint":"abcdef1234567890"`,`"fingerprint":"ffffffffffffffff","Fingerprint":"abcdef1234567890"`,1),
  "ambiguous-namespace":strings.Replace(firingFixture,`"namespace":"golden-demo"`,`"namespace":"golden-demo","Namespace":"different"`,1),
  "ambiguous-cluster":strings.Replace(firingFixture,`"cluster":"lab-a"`,`"cluster":"lab-a","Cluster":"different"`,1),
 }
 for name,payload:=range cases {
  t.Run(name,func(t *testing.T) {
   if payload==firingFixture{t.Fatal("fixture mutation did not happen")}
   plan,err:=Parse([]byte(payload),intended)
   if err==nil{t.Fatalf("accepted ambiguous case-folded source fields: %+v",plan)}
  })
 }
}
