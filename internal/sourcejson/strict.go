package sourcejson

// Package sourcejson validates native Kubernetes and Prometheus JSON before typed decoding.
// Native Kubernetes and Prometheus JSON is untrusted evidence input. The
// standard library's typed decoder silently overwrites duplicate object keys,
// replaces malformed UTF-8, and converts unpaired UTF-16 escapes to U+FFFD.
// Reject those transformations before any observation is made from the bytes.
// This validates source syntax; it does not authenticate the remote source.
import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "strconv"
 "unicode/utf8"
)

var errInvalidSourceJSON = errors.New("malformed or contradictory native source JSON")

// Source responses are already byte-bounded. Keep the recursive token walker
// separately depth-bounded so a tiny deeply nested reply cannot consume an
// unbounded Go stack before typed decoding has a chance to reject it.
const maxSourceJSONDepth = 64

func Validate(raw []byte) error {
 if !utf8.Valid(raw) {
  return errInvalidSourceJSON
 }
 if err := validateSourceEscapes(raw); err != nil {
  return errInvalidSourceJSON
 }
 decoder := json.NewDecoder(bytes.NewReader(raw))
 decoder.UseNumber()
 if err := readUniqueSourceValue(decoder, 0); err != nil {
  return errInvalidSourceJSON
 }
 if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
  return errInvalidSourceJSON
 }
 return nil
}

// A high surrogate must be paired with the immediately following low
// surrogate escape. Escaped backslashes are skipped, so literal "\\uD800"
// text is accepted. The JSON decoder separately rejects all invalid syntax.
func validateSourceEscapes(raw []byte) error {
 inString := false
 for i := 0; i < len(raw); i++ {
  switch raw[i] {
  case '"':
   inString = !inString
  case '\\':
   if !inString { continue }
   if i+1 >= len(raw) { return errInvalidSourceJSON }
   if raw[i+1] != 'u' {
    i++ // Escaped quote/backslash/slash or simple JSON escape.
    continue
   }
   if i+6 > len(raw) { return errInvalidSourceJSON }
   code, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
   if err != nil { return errInvalidSourceJSON }
   switch {
   case code >= 0xd800 && code <= 0xdbff:
    if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
     return errInvalidSourceJSON
    }
    low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
    if err != nil || low < 0xdc00 || low > 0xdfff {
     return errInvalidSourceJSON
    }
    i += 11 // Consume both full Unicode escapes.
   case code >= 0xdc00 && code <= 0xdfff:
    return errInvalidSourceJSON
   default:
    i += 5
   }
  }
 }
 return nil
}

// Walk the decoder token stream before typed decoding; decoding into a map
// or struct would already have discarded exact duplicate original keys.
// Case-insensitive aliases are schema-dependent and are rejected separately
// by ValidateCanonicalFields. Map keys remain case-sensitive data.
func readUniqueSourceValue(decoder *json.Decoder, depth int) error {
 token, err := decoder.Token()
 if err != nil { return err }
 delim, ok := token.(json.Delim)
 if !ok { return nil }
 if depth >= maxSourceJSONDepth { return errInvalidSourceJSON }
 switch delim {
 case '{':
  keys := make(map[string]struct{})
  for decoder.More() {
   token, err := decoder.Token()
   if err != nil { return err }
   key, ok := token.(string)
   if !ok { return errInvalidSourceJSON }
   if _, exists := keys[key]; exists { return errInvalidSourceJSON }
   keys[key] = struct{}{}
   if err := readUniqueSourceValue(decoder, depth+1); err != nil { return err }
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim('}') { return errInvalidSourceJSON }
  return nil
 case '[':
  for decoder.More() {
   if err := readUniqueSourceValue(decoder, depth+1); err != nil { return err }
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim(']') { return errInvalidSourceJSON }
  return nil
 default:
  return errInvalidSourceJSON
 }
}
