// Package evidence validates the legacy aiops.evidence/v1 wire contract.
// It deliberately does not attest data provenance or establish RCA truth.
package evidence

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "math"
 "strconv"
 "strings"
)

const MaxBundleBytes = 8 << 20

// Result describes structural validation, not incident or recovery verification.
type Result struct {
 Status string `json:"status"`
 BundleSHA256 string `json:"bundle_sha256"`
 EvidenceCount int `json:"evidence_count"`
 SupportedHypotheses int `json:"supported_hypotheses"`
}

func object(v any, field string) (map[string]any, error) {
 out, ok := v.(map[string]any)
 if !ok || out == nil { return nil, fmt.Errorf("%s must be a JSON object", field) }
 return out, nil
}
func array(v any, field string) ([]any, error) {
 out, ok := v.([]any)
 if !ok { return nil, fmt.Errorf("%s must be a JSON array", field) }
 return out, nil
}
func requiredString(obj map[string]any, field, location string) (string, error) {
 s, ok := obj[field].(string)
 if !ok || strings.TrimSpace(s) == "" { return "", fmt.Errorf("%s.%s must be a nonempty string", location, field) }
 return s, nil
}
// pythonJSONNumber matches Python json.loads -> json.dumps float spelling.
// Input integer tokens retain arbitrary precision, except -0, which Python
// converts to integer zero. Fractional/exponent tokens are binary64 floats:
// Python emits fixed notation in [1e-4, 1e16) and 2-digit-pad exponents outside.
func pythonJSONNumber(n json.Number) (json.Number,error) {
 raw := n.String()
 if !strings.ContainsAny(raw, ".eE") {
  if raw == "-0" { return json.Number("0"),nil }
  return n,nil
 }
 value,err := strconv.ParseFloat(raw,64)
 if err != nil || math.IsInf(value,0) || math.IsNaN(value) {
  return "",errors.New("JSON float outside finite Python compatibility range")
 }
 magnitude := math.Abs(value)
 var canonical string
 if magnitude!=0 && (magnitude<1e-4 || magnitude>=1e16) {
  canonical = strconv.FormatFloat(value,'e',-1,64)
 } else {
  canonical = strconv.FormatFloat(value,'f',-1,64)
  if !strings.Contains(canonical,".") { canonical += ".0" }
 }
 return json.Number(canonical),nil
}

// decodeUniqueJSONValue walks the original token stream so that duplicate
// object keys cannot be erased by map decoding before canonical hashing.
// This includes nested evidence fields and scenario envelopes.
func decodeUniqueJSONValue(decoder *json.Decoder) (any, error) {
 token, err := decoder.Token()
 if err != nil { return nil, err }
 delimiter, ok := token.(json.Delim)
 if !ok {
  if number, ok := token.(json.Number); ok { return pythonJSONNumber(number) }
  return token, nil
 }
 switch delimiter {
 case '{':
  result := make(map[string]any)
  for decoder.More() {
   next, err := decoder.Token()
   if err != nil { return nil, err }
   key, ok := next.(string)
   if !ok { return nil, errors.New("JSON object key is not a string") }
   if _, exists := result[key]; exists {
    return nil, fmt.Errorf("duplicate JSON object key %q", key)
   }
   value, err := decodeUniqueJSONValue(decoder)
   if err != nil { return nil, err }
   result[key] = value
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim('}') { return nil, errors.New("malformed JSON object") }
  return result, nil
 case '[':
  result := make([]any, 0)
  for decoder.More() {
   value, err := decodeUniqueJSONValue(decoder)
   if err != nil { return nil, err }
   result = append(result, value)
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim(']') { return nil, errors.New("malformed JSON array") }
  return result, nil
 default:
  return nil, errors.New("unexpected JSON closing delimiter")
 }
}
func parseJSON(raw []byte) (map[string]any, error) {
 if len(raw) > MaxBundleBytes { return nil, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes) }
 decoder := json.NewDecoder(bytes.NewReader(raw))
 decoder.UseNumber()
 root, err := decodeUniqueJSONValue(decoder)
 if err != nil { return nil, fmt.Errorf("decode bundle: %w", err) }
 var trailing any
 if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return nil, errors.New("bundle contains trailing JSON") }
 return object(root, "bundle")
}

// pythonLineSeparators emulates Python's json.dumps(ensure_ascii=False).
// Go's encoding/json escapes U+2028/U+2029 even with SetEscapeHTML(false).
// Walk escape pairs rather than blindly replacing byte substrings: literal
// backslash-u sequences in source strings must not turn into Unicode.
func pythonLineSeparators(raw []byte) []byte {
 out := make([]byte, 0, len(raw))
 for i := 0; i < len(raw); {
  if raw[i] == '\\' && i+6 <= len(raw) {
   if string(raw[i+1:i+6]) == "u2028" {
    out = append(out, 0xe2, 0x80, 0xa8)
    i += 6
    continue
   }
   if string(raw[i+1:i+6]) == "u2029" {
    out = append(out, 0xe2, 0x80, 0xa9)
    i += 6
    continue
   }
  }
  if raw[i] == '\\' && i+1 < len(raw) {
   out = append(out, raw[i], raw[i+1])
   i += 2
   continue
  }
  out = append(out, raw[i])
  i++
 }
 return out
}

// Verify performs fail-closed structural and digest checks over the serialized
// Python EvidenceBundle.to_dict() shape. A valid SHA-256 does not authenticate
// the source, imply evidence correctness, or prove the incident recovered.
func Verify(raw []byte) (Result, error) {
 root, err := parseJSON(raw)
 if err != nil { return Result{}, err }
 required := map[string]bool{
  "incident": true, "evidence": true, "hypotheses": true,
  "entities": true, "edges": true, "changes": true, "metadata": true,
 }
 for k := range root { if !required[k] { return Result{}, fmt.Errorf("unexpected bundle field %q", k) } }
 for k := range required { if _, ok := root[k]; !ok { return Result{}, fmt.Errorf("missing bundle field %q", k) } }
 incident, err := object(root["incident"], "incident")
 if err != nil { return Result{}, err }
 for _, k := range []string{"incident_id", "summary", "severity"} {
  if _, err = requiredString(incident, k, "incident"); err != nil { return Result{}, err }
 }
 metadata, err := object(root["metadata"], "metadata")
 if err != nil { return Result{}, err }
 // Legacy Python EvidenceBundle.metadata is free-form; the committed
 // checkout benchmark has no schema_version. Only reject explicit versions
 // that claim a contract this v1 migration verifier does not implement.
 if v, ok := metadata["schema_version"]; ok && v != "aiops.evidence/v1" {
  return Result{}, errors.New("unsupported metadata.schema_version")
 }
 items, err := array(root["evidence"], "evidence")
 if err != nil { return Result{}, err }
 ids := make(map[string]bool, len(items))
 for i, item := range items {
  location := fmt.Sprintf("evidence[%d]", i)
  e, err := object(item, location)
  if err != nil { return Result{}, err }
  id, err := requiredString(e, "evidence_id", location)
  if err != nil { return Result{}, err }
  if ids[id] { return Result{}, fmt.Errorf("duplicate evidence_id %q", id) }
  ids[id] = true
  for _, k := range []string{"source", "observation"} {
   if _, err := requiredString(e, k, location); err != nil { return Result{}, err }
  }
 }
 hypotheses, err := array(root["hypotheses"], "hypotheses")
 if err != nil { return Result{}, err }
 seen := map[string]bool{}
 supported := 0
 for i, item := range hypotheses {
  location := fmt.Sprintf("hypotheses[%d]", i)
  h, err := object(item, location)
  if err != nil { return Result{}, err }
  id, err := requiredString(h, "hypothesis_id", location)
  if err != nil { return Result{}, err }
  if seen[id] { return Result{}, fmt.Errorf("duplicate hypothesis_id %q", id) }
  seen[id] = true
  if _, err := requiredString(h, "statement", location); err != nil { return Result{}, err }
  status, err := requiredString(h, "status", location)
  if err != nil { return Result{}, err }
  if status != "supported" && status != "rejected" && status != "unverified" {
   return Result{}, fmt.Errorf("invalid %s.status %q", location, status)
  }
  refs, err := array(h["evidence_ids"], location+".evidence_ids")
  if err != nil { return Result{}, err }
  if status == "supported" {
   supported++
   if len(refs) == 0 { return Result{}, fmt.Errorf("%s is supported without evidence", location) }
  }
  refSet := map[string]bool{}
  for _, ref := range refs {
   eid, ok := ref.(string)
   if !ok || !ids[eid] { return Result{}, fmt.Errorf("%s references unknown evidence %v", location, ref) }
   if refSet[eid] { return Result{}, fmt.Errorf("%s repeats evidence %q", location, eid) }
   refSet[eid] = true
  }
 }
 for _, key := range []string{"entities", "edges", "changes"} {
  if _, err := array(root[key], key); err != nil { return Result{}, err }
 }
 // Python EvidenceBundle.canonical_json excludes metadata.bundle_sha256.
 // Re-encode with sorted map keys and EscapeHTML(false) for golden vectors.
 clean := make(map[string]any, len(root))
 for k, v := range root { clean[k] = v }
 cleanMetadata := make(map[string]any, len(metadata))
 for k, v := range metadata { if k != "bundle_sha256" { cleanMetadata[k] = v } }
 clean["metadata"] = cleanMetadata
 var buf bytes.Buffer
 encoder := json.NewEncoder(&buf)
 encoder.SetEscapeHTML(false)
 if err := encoder.Encode(clean); err != nil { return Result{}, fmt.Errorf("encode canonical bundle: %w", err) }
 digest := sha256.Sum256(pythonLineSeparators(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))))
 sha := hex.EncodeToString(digest[:])
 if expected, ok := metadata["bundle_sha256"]; ok {
  s, ok := expected.(string)
  if !ok || len(s) != 64 || s != sha { return Result{}, errors.New("metadata.bundle_sha256 does not match canonical bundle digest") }
 }
 return Result{Status: "STRUCTURALLY_VALID", BundleSHA256: sha, EvidenceCount: len(items), SupportedHypotheses: supported}, nil
}

// VerifyScenario validates a benchmark scenario's frozen bundle, not its outcome.
func VerifyScenario(raw []byte) (Result, error) {
 root, err := parseJSON(raw)
 if err != nil { return Result{}, err }
 value, ok := root["bundle"]
 if !ok { return Result{}, errors.New("scenario is missing bundle") }
 var buf bytes.Buffer
 encoder := json.NewEncoder(&buf)
 encoder.SetEscapeHTML(false)
 if err := encoder.Encode(value); err != nil { return Result{}, err }
 return Verify(buf.Bytes())
}
