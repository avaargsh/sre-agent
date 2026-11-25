package endpointoracle

import (
 "bytes"
 "encoding/json"
 "reflect"
)

// Both raw sources must have passed their domain-specific strict parsers.
// Compare complete JSON values while preserving numeric tokens.
func sameJSONSource(observer, admin []byte) bool {
 decode := func(raw []byte) (any, bool) {
  if !json.Valid(raw) { return nil, false }
  d := json.NewDecoder(bytes.NewReader(raw))
  d.UseNumber()
  var value any
  err := d.Decode(&value)
  return value, err == nil
 }
 a, okA := decode(observer)
 b, okB := decode(admin)
 return okA && okB && reflect.DeepEqual(a,b)
}

// sameEndpointSource compares complete EndpointSlice snapshots. Callers must
// validate both byte streams with inspect before using this equality check.
func sameEndpointSource(observer, admin []byte) bool {
 return sameJSONSource(observer, admin)
}
