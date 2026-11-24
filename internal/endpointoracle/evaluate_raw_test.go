package endpointoracle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateRawBindsExactInputBytes(t *testing.T) {
	e, p := episode(t, false)
	episodeRaw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	predictionRaw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EvaluateRaw(episodeRaw, predictionRaw)
	if err != nil {
		t.Fatal(err)
	}
	eh := sha256.Sum256(episodeRaw)
	ph := sha256.Sum256(predictionRaw)
	if got.EpisodeSHA256 != hex.EncodeToString(eh[:]) {
		t.Fatalf("episode digest not bound to exact bytes: %s", got.EpisodeSHA256)
	}
	if got.PredictionSHA256 != hex.EncodeToString(ph[:]) {
		t.Fatalf("prediction digest not bound to exact bytes: %s", got.PredictionSHA256)
	}
	reformatted := append([]byte(" \n"), episodeRaw...)
	second, err := EvaluateRaw(reformatted, predictionRaw)
	if err != nil {
		t.Fatal(err)
	}
	if second.EpisodeSHA256 == got.EpisodeSHA256 {
		t.Fatal("digest must bind original bytes, not normalized typed object")
	}
}

// replaceJSONOnce makes a malformed-input fixture fail during test setup if
// its source key is absent. This prevents a no-op strings.Replace from
// accidentally testing the unchanged, valid JSON document.
func replaceJSONOnce(t *testing.T, raw, old, replacement string) []byte {
	t.Helper()
	if !strings.Contains(raw, old) {
		t.Fatalf("JSON mutation anchor %q not found", old)
	}
	changed := strings.Replace(raw, old, replacement, 1)
	if changed == raw {
		t.Fatalf("JSON mutation %q did not change the fixture", old)
	}
	return []byte(changed)
}

func appendJSONRootField(t *testing.T, raw, field string) []byte {
	t.Helper()
	if !strings.HasSuffix(raw, "}") {
		t.Fatal("JSON object fixture has no closing brace")
	}
	return []byte(strings.TrimSuffix(raw, "}") + "," + field + "}")
}

func TestEvaluateRawRejectsAmbiguousEnvelopes(t *testing.T) {
	validPrediction := []byte(`{}`)
	for _, tc := range []struct {
		name                  string
		episode, prediction   []byte
	}{
		{"duplicate episode key", []byte(`{"schema_version":"sre.endpoint-oracle/v1","schema_version":"bad"}`), validPrediction},
		{"case-fold episode key", []byte(`{"schema_version":"sre.endpoint-oracle/v1","SchemaVersion":"bad"}`), validPrediction},
		{"trailing episode value", []byte(`{} {}`), validPrediction},
		{"duplicate prediction key", []byte(`{}`), []byte(`{"classification":"READY","classification":"UNKNOWN"}`)},
		{"invalid UTF-8 episode", []byte{0xff}, validPrediction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EvaluateRaw(tc.episode, tc.prediction); err == nil {
				t.Fatal("ambiguous raw evidence accepted")
			}
		})
	}
}

func TestEvaluateRawRejectsUnconsumedFields(t *testing.T) {
	e, p := episode(t, false)
	episodeRaw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	predictionRaw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	episodeText := string(episodeRaw)
	predictionText := string(predictionRaw)
	cases := []struct {
		name                string
		episode, prediction []byte
	}{
		{
			"unknown episode field",
			appendJSONRootField(t, episodeText, `"operator_approval":true`),
			predictionRaw,
		},
		{
			"unknown nested phase field",
			replaceJSONOnce(t, episodeText, `"probes":[200,200,200]`,
				`"probes":[200,200,200],"sampled_at":"2026-11-24T00:00:00Z"`),
			predictionRaw,
		},
		{
			"unknown prediction field",
			episodeRaw,
			appendJSONRootField(t, predictionText, `"evidence_attestation":"signed"`),
		},
		{
			"noncanonical root field alias",
			replaceJSONOnce(t, episodeText, `"schema_version":`, `"SCHEMA_VERSION":`),
			predictionRaw,
		},
		{
			"noncanonical nested field alias",
			replaceJSONOnce(t, episodeText, `"probes":`, `"PROBES":`),
			predictionRaw,
		},
		{
			"noncanonical prediction root alias",
			episodeRaw,
			replaceJSONOnce(t, predictionText, `"classification":`, `"CLASSIFICATION":`),
		},
		{
			"noncanonical nested prediction alias",
			episodeRaw,
			replaceJSONOnce(t, predictionText, `"service_uid":`, `"SERVICE_UID":`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EvaluateRaw(tc.episode, tc.prediction); err == nil {
				t.Fatal("unconsumed or non-canonical envelope field accepted")
			}
		})
	}
}

func TestEvaluateRawEnforcesEnvelopeByteBudgets(t *testing.T) {
	if _, err := EvaluateRaw(make([]byte, (12<<20)+1), []byte(`{}`)); err == nil {
		t.Fatal("oversized episode accepted")
	}
	if _, err := EvaluateRaw([]byte(`{}`), make([]byte, (6<<20)+1)); err == nil {
		t.Fatal("oversized prediction accepted")
	}
}
