package endpointoracle

import (
	"reflect"
	"testing"
)

type canonicalSelectorEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	Phase         canonicalPhase    `json:"phase"`
	Selector      map[string]string `json:"selector"`
}

type canonicalPhase struct {
	Probes []int `json:"probes"`
}

func TestCanonicalJSONFieldValidationRejectsCaseFoldedStructAliases(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{
			name: "root alias",
			raw:  `{"SCHEMA_VERSION":"v1"}`,
		},
		{
			name: "nested alias",
			raw:  `{"phase":{"PROBES":[200,200,200]}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateCanonicalJSONFields([]byte(tc.raw), reflect.TypeOf(canonicalSelectorEnvelope{})); err == nil {
				t.Fatal("case-folded alias accepted as a canonical struct field")
			}
		})
	}
}

func TestCanonicalJSONFieldValidationLeavesMapKeysAsData(t *testing.T) {
	raw := []byte(`{
		"schema_version":"v1",
		"phase":{"probes":[200,200,200]},
		"selector":{"SCHEMA_VERSION":"application-label"}
	}`)
	if err := validateCanonicalJSONFields(raw, reflect.TypeOf(canonicalSelectorEnvelope{})); err != nil {
		t.Fatalf("selector map key was treated as an envelope field: %v", err)
	}
}
