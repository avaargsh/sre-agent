package workloadtopology

import (
	"encoding/base64"
	"encoding/json"
	"reflect"

	"github.com/avaargsh/sre-agent/internal/sourcejson"
)

// MaxObservationJSONBytes accommodates six base64-encoded 2 MiB responses
// plus bounded report metadata. Readers must enforce this limit before decode.
const MaxObservationJSONBytes = 17 << 20
const observationSchema = "sre.workload-observation/v1"

type wireSnapshot struct {
	RawBase64 string `json:"raw_base64"`
	SHA256    string `json:"sha256"`
}
type wireObservation struct {
	SchemaVersion string         `json:"schema_version"`
	Report        Report         `json:"report"`
	Snapshots     []wireSnapshot `json:"snapshots"`
	Confirmations []wireSnapshot `json:"confirmations"`
}

func encodeRound(round []Snapshot) []wireSnapshot {
	out := make([]wireSnapshot, len(round))
	for i, s := range round {
		out[i] = wireSnapshot{RawBase64: base64.StdEncoding.EncodeToString(s.Raw), SHA256: s.SHA256}
	}
	return out
}
func decodeRound(round []wireSnapshot) ([]Snapshot, error) {
	if len(round) != 3 {
		return nil, errInvalid
	}
	out := make([]Snapshot, 3)
	for i, s := range round {
		if len(s.RawBase64) == 0 || len(s.RawBase64) > base64.StdEncoding.EncodedLen(MaxSnapshotBytes) || len(s.SHA256) != 64 {
			return nil, errInvalid
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(s.RawBase64)
		if err != nil || len(raw) == 0 || len(raw) > MaxSnapshotBytes || base64.StdEncoding.EncodeToString(raw) != s.RawBase64 {
			return nil, errInvalid
		}
		out[i] = Snapshot{Raw: raw, SHA256: s.SHA256}
	}
	return out, nil
}

// MarshalObservationJSON emits a versioned claim only after typed replay.
// The caller must distinguish capture hashes from independent verification pins.
// Serialized bytes may contain sensitive configuration and are not attestation.
func MarshalObservationJSON(expected Target, replicaSetName string, pins [3]string, claimed Observation) ([]byte, error) {
	if VerifyObservation(expected, replicaSetName, pins, claimed) != nil {
		return nil, errInvalid
	}
	raw, err := json.Marshal(wireObservation{SchemaVersion: observationSchema, Report: claimed.Report, Snapshots: encodeRound(claimed.Snapshots), Confirmations: encodeRound(claimed.Confirmations)})
	if err != nil || len(raw) > MaxObservationJSONBytes {
		return nil, errInvalid
	}
	return raw, nil
}

// VerifyObservationJSON validates the exact wire contract and independently
// replays both read rounds against separately supplied target and digest pins.
// Field order and insignificant whitespace are allowed; extra, missing, null,
// aliased or duplicate fields and noncanonical base64 are rejected. A successful
// replay is content consistency only, not authentication, freshness or recovery.
func VerifyObservationJSON(expected Target, replicaSetName string, pins [3]string, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxObservationJSONBytes || sourcejson.Validate(raw) != nil {
		return errInvalid
	}
	var wire wireObservation
	if json.Unmarshal(raw, &wire) != nil || wire.SchemaVersion != observationSchema {
		return errInvalid
	}
	first, err := decodeRound(wire.Snapshots)
	if err != nil {
		return errInvalid
	}
	second, err := decodeRound(wire.Confirmations)
	if err != nil {
		return errInvalid
	}
	canonical, err := MarshalObservationJSON(expected, replicaSetName, pins, Observation{Report: wire.Report, Snapshots: first, Confirmations: second})
	if err != nil {
		return errInvalid
	}
	// Typed JSON decoding alone accepts aliases, unknown fields and absent/null
	// booleans. Compare full JSON values with the validated canonical claim.
	var want, got any
	if json.Unmarshal(canonical, &want) != nil || json.Unmarshal(raw, &got) != nil || !reflect.DeepEqual(want, got) {
		return errInvalid
	}
	return nil
}
