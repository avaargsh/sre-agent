package endpointoracle

import (
 "reflect"
 "testing"
)

type canonicalSelectorEnvelope struct {
 Selector map[string]string `json:"selector"`
}

func TestCanonicalJSONFieldValidationLeavesMapKeysAsData(t *testing.T) {
 raw:=[]byte(`{"selector":{"SCHEMA_VERSION":"application-label"}}`)
 if err:=validateCanonicalJSONFields(raw,reflect.TypeOf(canonicalSelectorEnvelope{}));err!=nil{
  t.Fatalf("selector map key was treated as an envelope field: %v",err)
 }
}
