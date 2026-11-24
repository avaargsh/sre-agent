package evidence

// ValidateUniqueJSONObject checks the existing bounded evidence JSON syntax
// contract without requiring the EvidenceBundle schema or claiming provenance.
// Callers must independently validate their own object schema and authority.
func ValidateUniqueJSONObject(raw []byte) error {
 _, err := parseJSON(raw)
 return err
}
