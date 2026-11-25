package endpointarchive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type report struct {
	SchemaVersion string            `json:"schema_version"`
	Labels        map[string]string `json:"labels"`
}

func archive(t *testing.T, changes map[string]any) []byte {
	t.Helper()
	fields := map[string]any{
		"schema_version":      "sre.service-endpoints-capture/v1",
		"report":              map[string]any{"schema_version": "sre.service-endpoints/v3", "labels": map[string]string{"App": "a", "app": "b"}},
		"service_before_raw":  []byte(`{"kind":"Service"}`),
		"endpoint_slices_raw": []byte(`{"items":[]}`),
		"service_after_raw":   []byte(`{"kind":"Service"}`),
	}
	for k, v := range changes {
		fields[k] = v
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodePreservesBytes(t *testing.T) {
	raw := append(archive(t, nil), '\n')
	got, err := Decode[report](raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ServiceBeforeRaw) != `{"kind":"Service"}` || string(got.EndpointSlicesRaw) != `{"items":[]}` || !bytes.Equal(got.ServiceBeforeRaw, got.ServiceAfterRaw) {
		t.Fatal("source bytes changed")
	}
	if got.Report.SchemaVersion != "sre.service-endpoints/v3" || len(got.Report.Labels) != 2 {
		t.Fatal("report changed")
	}
	sum := sha256.Sum256(raw)
	if got.ArchiveSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("digest did not bind original envelope")
	}
}

func TestDecodeRejectsInvalidArchive(t *testing.T) {
	valid := archive(t, nil)
	cases := map[string][]byte{
		"empty":                nil,
		"wrong schema":         archive(t, map[string]any{"schema_version": "other"}),
		"unknown field":        archive(t, map[string]any{"extra": true}),
		"case alias":           []byte(strings.Replace(string(valid), `"schema_version":`, `"SCHEMA_VERSION":`, 1)),
		"duplicate key":        append([]byte(`{"report":{},`), valid[1:]...),
		"trailing document":    append(append([]byte{}, valid...), []byte(`{}`)...),
		"null report":          archive(t, map[string]any{"report": nil}),
		"nonobject report":     archive(t, map[string]any{"report": []any{}}),
		"unknown report field": archive(t, map[string]any{"report": map[string]any{"extra": true}}),
		"invalid base64":       archive(t, map[string]any{"service_before_raw": "!"}),
		"noncanonical base64":  archive(t, map[string]any{"service_before_raw": "e30=\n"}),
		"null source":          archive(t, map[string]any{"service_before_raw": nil}),
		"empty source":         archive(t, map[string]any{"service_before_raw": ""}),
		"oversized source":     archive(t, map[string]any{"service_before_raw": bytes.Repeat([]byte{'x'}, MaxSourceBytes+1)}),
		"oversized archive":    bytes.Repeat([]byte{' '}, MaxArchiveBytes+1),
		"invalid UTF8":         append([]byte{0xff}, valid...),
		"unpaired surrogate":   archive(t, map[string]any{"report": json.RawMessage(`{"schema_version":"\uD800"}`)}),
		"duplicate nested key": archive(t, map[string]any{"report": json.RawMessage(`{"schema_version":"a","schema_version":"b"}`)}),
	}
	var fields map[string]any
	if err := json.Unmarshal(valid, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "service_after_raw")
	cases["missing source"], _ = json.Marshal(fields)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode[report](raw); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}

func TestDecodeDoesNotClaimNativeSemantics(t *testing.T) {
	// An archive decoder binds bytes, not an independently verified incident.
	raw := archive(t, map[string]any{"service_after_raw": []byte(`{"kind":"Other"}`)})
	got, err := Decode[report](raw)
	if err != nil || bytes.Equal(got.ServiceAfterRaw, got.ServiceBeforeRaw) {
		t.Fatal("decoder must preserve distinct snapshots for the native oracle")
	}
}

func TestDecodeReportSchema(t *testing.T) {
	for _, fields := range []map[string]any{
		{"SCHEMA_VERSION": "sre.service-endpoints/v3"},
		{"schema_version": 123},
		{"schema_version": "v3", "SCHEMA_VERSION": "v2"},
	} {
		if _, err := Decode[report](archive(t, map[string]any{"report": fields})); err == nil {
			t.Fatal("invalid typed report accepted")
		}
	}
	if _, err := Decode[map[string]any](archive(t, nil)); err == nil {
		t.Fatal("untyped report accepted")
	}
}

func TestDecodeSourceSizeBoundary(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, MaxSourceBytes)
	raw := archive(t, map[string]any{"service_before_raw": body})
	got, err := Decode[report](raw)
	if err != nil || !bytes.Equal(got.ServiceBeforeRaw, body) {
		t.Fatal("valid maximum size source rejected")
	}
}

type requiredReport struct {
	Ready  int               `json:"ready"`
	Auth   bool              `json:"auth"`
	Target requiredTarget    `json:"target"`
	Reads  []requiredTarget  `json:"reads"`
	Labels map[string]string `json:"labels"`
}

type requiredTarget struct {
	UID   string `json:"uid"`
	Extra string `json:"extra,omitempty"`
}

func TestDecodeRejectsMissingOrNullReportFields(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"ready": 0, "auth": false, "target": map[string]any{"uid": "u"}, "reads": []any{map[string]any{"uid": "u"}}, "labels": map[string]any{"app": "x"}}
	}
	for _, key := range []string{"ready", "auth", "target", "reads", "labels"} {
		for _, missing := range []bool{true, false} {
			name := key + "/null"
			if missing {
				name = key + "/missing"
			}
			t.Run(name, func(t *testing.T) {
				fields := good()
				if missing {
					delete(fields, key)
				} else {
					fields[key] = nil
				}
				if _, err := Decode[requiredReport](archive(t, map[string]any{"report": fields})); err == nil {
					t.Fatal("missing or null report field accepted")
				}
			})
		}
	}
	for name, changes := range map[string]any{
		"missing nested uid":  map[string]any{},
		"null nested uid":     map[string]any{"uid": nil},
		"null optional field": map[string]any{"uid": "u", "extra": nil},
	} {
		t.Run(name, func(t *testing.T) {
			fields := good()
			fields["target"] = changes
			if _, err := Decode[requiredReport](archive(t, map[string]any{"report": fields})); err == nil {
				t.Fatal("invalid nested field accepted")
			}
		})
	}
	for name, changes := range map[string]any{"null item": []any{nil}, "missing item uid": []any{map[string]any{}}} {
		t.Run(name, func(t *testing.T) {
			fields := good()
			fields["reads"] = changes
			if _, err := Decode[requiredReport](archive(t, map[string]any{"report": fields})); err == nil {
				t.Fatal("invalid array item accepted")
			}
		})
	}
	t.Run("null map value", func(t *testing.T) {
		fields := good()
		fields["labels"] = map[string]any{"app": nil}
		if _, err := Decode[requiredReport](archive(t, map[string]any{"report": fields})); err == nil {
			t.Fatal("null map value accepted")
		}
	})
	if got, err := Decode[requiredReport](archive(t, map[string]any{"report": good()})); err != nil || got.Report.Ready != 0 || got.Report.Auth {
		t.Fatalf("explicit zero and false must remain valid: %v", err)
	}
}
