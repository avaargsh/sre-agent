package endpointoracle

import (
	"testing"

	"github.com/avaargsh/sre-agent/internal/sourcejson"
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
			if err := sourcejson.ValidateCanonicalFields([]byte(tc.raw), &canonicalSelectorEnvelope{}); err == nil {
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
	if err := sourcejson.ValidateCanonicalFields(raw, &canonicalSelectorEnvelope{}); err != nil {
		t.Fatalf("selector map key was treated as an envelope field: %v", err)
	}
}

type canonicalEndpointSliceEnvelope struct {
	Items []struct {
		Metadata struct {
			OwnerReferences []struct {
				UID string `json:"uid"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
	} `json:"items"`
}

func TestCanonicalJSONFieldValidationRejectsNestedOwnerReferenceAlias(t *testing.T) {
	raw := []byte(`{"items":[{"metadata":{"ownerReferences":[{"UID":"service-uid"}]}}]}`)
	if err := sourcejson.ValidateCanonicalFields(raw, &canonicalEndpointSliceEnvelope{}); err == nil {
		t.Fatal("case-folded owner reference UID alias accepted")
	}
}

