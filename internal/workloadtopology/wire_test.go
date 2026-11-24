package workloadtopology

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestObservationJSONRoundTrip(t *testing.T) {
	obs, pins := replayFixture(t)
	raw, err := MarshalObservationJSON(target(), "checkout-rs", pins, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyObservationJSON(target(), "checkout-rs", pins, raw); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["schema_version"] != "sre.workload-observation/v1" {
		t.Fatal("missing version")
	}
	formatted, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyObservationJSON(target(), "checkout-rs", pins, formatted); err != nil {
		t.Fatal(err)
	}
	obs.Report.RootCauseVerified = true
	if raw, err := MarshalObservationJSON(target(), "checkout-rs", pins, obs); err == nil || raw != nil {
		t.Fatal("invalid claim serialized")
	}
}

func TestObservationJSONStrictAdmission(t *testing.T) {
	obs, pins := replayFixture(t)
	raw, err := MarshalObservationJSON(target(), "checkout-rs", pins, obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing-schema", func(m map[string]any) { delete(m, "schema_version") }},
		{"wrong-schema", func(m map[string]any) { m["schema_version"] = "sre.workload-observation/v2" }},
		{"alias-schema", func(m map[string]any) { m["Schema_Version"] = m["schema_version"]; delete(m, "schema_version") }},
		{"unknown-field", func(m map[string]any) { m["extra"] = true }},
		{"missing-false", func(m map[string]any) { delete(m["report"].(map[string]any), "recovery_verified") }},
		{"null-false", func(m map[string]any) { m["report"].(map[string]any)["source_authenticated"] = nil }},
		{"false-as-string", func(m map[string]any) { m["report"].(map[string]any)["source_authenticated"] = "false" }},
		{"forged-rca", func(m map[string]any) { m["report"].(map[string]any)["root_cause_verified"] = true }},
		{"unknown-source-field", func(m map[string]any) {
			m["report"].(map[string]any)["sources"].([]any)[0].(map[string]any)["extra"] = true
		}},
		{"alias-source-field", func(m map[string]any) {
			s := m["report"].(map[string]any)["sources"].([]any)[0].(map[string]any)
			s["UID"] = s["uid"]
			delete(s, "uid")
		}},
		{"null-snapshot", func(m map[string]any) { m["snapshots"].([]any)[0] = nil }},
		{"missing-confirmations", func(m map[string]any) { delete(m, "confirmations") }},
		{"extra-confirmation", func(m map[string]any) { a := m["confirmations"].([]any); m["confirmations"] = append(a, a[0]) }},
		{"wrong-digest", func(m map[string]any) { m["snapshots"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64) }},
		{"invalid-base64", func(m map[string]any) { m["snapshots"].([]any)[0].(map[string]any)["raw_base64"] = "!" }},
		{"noncanonical-base64", func(m map[string]any) {
			s := m["snapshots"].([]any)[0].(map[string]any)
			s["raw_base64"] = s["raw_base64"].(string) + "\n"
		}},
		{"oversize-base64", func(m map[string]any) {
			m["snapshots"].([]any)[0].(map[string]any)["raw_base64"] = strings.Repeat("A", MaxSnapshotBytes*2)
		}},
		{"snapshot-extra", func(m map[string]any) { m["snapshots"].([]any)[0].(map[string]any)["extra"] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			tc.mutate(body)
			bad, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if VerifyObservationJSON(target(), "checkout-rs", pins, bad) == nil {
				t.Fatal("invalid wire claim accepted")
			}
		})
	}
	for name, bad := range map[string][]byte{
		"duplicate":          []byte(strings.Replace(string(raw), `"schema_version":`, `"schema_version":"wrong","schema_version":`, 1)),
		"casefold-duplicate": []byte(strings.Replace(string(raw), `"schema_version":`, `"Schema_Version":"wrong","schema_version":`, 1)),
		"invalid-unicode":    []byte(strings.Replace(string(raw), `"status":"LINKED"`, `"status":"\ud800"`, 1)),
		"trailing":           append(append([]byte(nil), raw...), []byte(`{}`)...),
		"empty":              nil,
		"oversize":           []byte(strings.Repeat(" ", MaxObservationJSONBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyObservationJSON(target(), "checkout-rs", pins, bad) == nil {
				t.Fatal("invalid bytes admitted")
			}
		})
	}
	wrong := pins
	wrong[0] = strings.Repeat("0", 64)
	if VerifyObservationJSON(target(), "checkout-rs", wrong, raw) == nil {
		t.Fatal("external pin ignored")
	}
}
