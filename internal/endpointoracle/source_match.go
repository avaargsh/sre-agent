package endpointoracle

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// Both sources must already have passed the strict EndpointSlice parser.
// Compare complete JSON values, not just the version and derived count.
// Preserve number tokens to avoid float64 rounding in unmodeled fields.
func sameEndpointSource(observer, admin []byte) bool {
	decode := func(raw []byte) (any, bool) {
		if !json.Valid(raw) {
			return nil, false
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var value any
		err := d.Decode(&value)
		return value, err == nil
	}
	a, okA := decode(observer)
	b, okB := decode(admin)
	return okA && okB && reflect.DeepEqual(a, b)
}
