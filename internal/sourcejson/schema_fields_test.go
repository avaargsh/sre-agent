package sourcejson

import (
	"encoding/json"
	"testing"
)

type schemaFieldEnvelope struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []struct {
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
	Labels map[string]string `json:"labels"`
	Raw json.RawMessage `json:"raw"`
}

func TestValidateCanonicalFieldsRejectsSingleCaseInsensitiveAliases(t *testing.T) {
	cases := map[string]string{
		"root field":       `{"Metadata":{"resourceVersion":"rv1"}}`,
		"nested field":     `{"metadata":{"ResourceVersion":"rv1"}}`,
		"array item field": `{"items":[{"Status":{"phase":"Running"}}]}`,
		"deep nested field": `{"items":[{"status":{"Phase":"Running"}}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate([]byte(raw)); err != nil {
				t.Fatalf("single alias should be syntactically valid JSON: %v", err)
			}
			if err := ValidateCanonicalFields([]byte(raw), &schemaFieldEnvelope{}); err == nil {
				t.Fatalf("accepted noncanonical typed-source field: %s", raw)
			}
		})
	}
}

func TestValidateCanonicalFieldsLeavesMapKeysAndRawMessagesAsData(t *testing.T) {
	raw := []byte(`{
		"metadata":{"resourceVersion":"rv1"},
		"labels":{"ResourceVersion":"application-label"},
		"raw":{"ResourceVersion":"opaque"}
	}`)
	if err := ValidateCanonicalFields(raw, &schemaFieldEnvelope{}); err != nil {
		t.Fatalf("map keys or opaque RawMessage were treated as schema fields: %v", err)
	}
}

func TestValidateCanonicalFieldsLeavesUnknownFieldsToTypedDecoder(t *testing.T) {
	raw := []byte(`{"metadata":{"resourceVersion":"rv1"},"future":{"ResourceVersion":"opaque"}}`)
	if err := ValidateCanonicalFields(raw, &schemaFieldEnvelope{}); err != nil {
		t.Fatalf("unknown field policy belongs to the typed decoder: %v", err)
	}
}
