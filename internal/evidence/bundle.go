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
func parseJSON(raw []byte) (map[string]any, error) {
 if len(raw) > MaxBundleBytes { return nil, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes) }
 decoder := json.NewDecoder(bytes.NewReader(raw))
 decoder.UseNumber()
 var root any
 if err := decoder.Decode(&root); err != nil { return nil, fmt.Errorf("decode bundle: %w", err) }
 var trailing any
 if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return nil, errors.New("bundle contains trailing JSON") }
 return object(root, "bundle")
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
 if v, ok := metadata["schema_version"]; ok && v != "aiops.evidence/v1" { return Result{}, errors.New("unsupported metadata.schema_version") }
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
 digest := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
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
