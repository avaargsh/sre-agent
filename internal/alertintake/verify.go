package alertintake

import (
 "bytes"
 "encoding/json"
)

// MaxPlanBytes bounds the review artifact independently of Alertmanager's
// original payload size. A v1 Plan is a small, fixed-schema JSON object.
const MaxPlanBytes = 16 << 10

// VerifyPlan recomputes a plan from the original bounded Alertmanager bytes
// and the operator's independently supplied scope. Exact canonical comparison
// rejects stale notifications, mutated metadata, extra or ambiguous keys and
// forged source/permission flags before any network read is allowed.
//
// This is consistency checking only. Neither the alert nor the operator scope
// is cryptographically authenticated here; it grants no ability to act.
func VerifyPlan(rawAlert, frozenPlan []byte, target Target) (Plan, error) {
 if len(frozenPlan)==0 || len(frozenPlan)>MaxPlanBytes {
  return Plan{},unknown("missing or oversized alert plan")
 }
 expected,err:=Parse(rawAlert,target)
 if err!=nil {return Plan{},err}
 canonical,err:=json.MarshalIndent(expected,"","  ")
 if err!=nil{return Plan{},unknown("cannot encode canonical plan")}
 canonical=append(canonical,'\n')
 if !bytes.Equal(frozenPlan,canonical) {
  return Plan{},unknown("alert plan differs from original alert bytes or trusted target")
 }
 return expected,nil
}
