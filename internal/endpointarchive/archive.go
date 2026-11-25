// Package endpointarchive decodes the native Service endpoint capture envelope.
// Decoding is not native source replay or evidence authentication.
package endpointarchive

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/avaargsh/sre-agent/internal/sourcejson"
)

const (
	MaxSourceBytes  = 2 << 20
	MaxArchiveBytes = 10 << 20
)

// Capture retains the exact three source bodies and the digest of the archive.
// R is the caller's concrete, versioned report struct.
type Capture[R any] struct {
	Report            R
	ServiceBeforeRaw  []byte
	EndpointSlicesRaw []byte
	ServiceAfterRaw   []byte
	ArchiveSHA256     string
}

// Decode requires a bounded v1 capture envelope and canonical base64 source
// bodies. It rejects unknown report fields and noncanonical field names.
// The caller must independently select the expected identity/configuration
// and run the native Oracle on the returned report and source bytes.
func Decode[R any](raw []byte) (Capture[R], error) {
	var zero Capture[R]
	if len(raw) == 0 || len(raw) > MaxArchiveBytes {
		return zero, fmt.Errorf("invalid capture archive size")
	}
	if reflect.TypeFor[R]().Kind() != reflect.Struct {
		return zero, fmt.Errorf("report schema must be a struct")
	}
	if err := sourcejson.Validate(raw); err != nil {
		return zero, fmt.Errorf("invalid capture archive JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 5 {
		return zero, fmt.Errorf("invalid capture archive envelope")
	}
	var version string
	if err := json.Unmarshal(fields["schema_version"], &version); err != nil || version != "sre.service-endpoints-capture/v1" {
		return zero, fmt.Errorf("invalid capture archive schema")
	}
	var result Capture[R]
	report := bytes.TrimSpace(fields["report"])
	if len(report) == 0 || report[0] != '{' || sourcejson.ValidateCanonicalFields(report, &result.Report) != nil {
		return zero, fmt.Errorf("invalid capture report fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(report))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result.Report); err != nil {
		return zero, fmt.Errorf("invalid capture report")
	}
	for _, source := range []struct {
		name string
		dst  *[]byte
	}{
		{"service_before_raw", &result.ServiceBeforeRaw},
		{"endpoint_slices_raw", &result.EndpointSlicesRaw},
		{"service_after_raw", &result.ServiceAfterRaw},
	} {
		var encoded string
		if err := json.Unmarshal(fields[source.name], &encoded); err != nil || len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(MaxSourceBytes) {
			return zero, fmt.Errorf("invalid capture source %s", source.name)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) == 0 || len(decoded) > MaxSourceBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return zero, fmt.Errorf("invalid capture source %s", source.name)
		}
		*source.dst = decoded
	}
	sum := sha256.Sum256(raw)
	result.ArchiveSHA256 = hex.EncodeToString(sum[:])
	return result, nil
}
