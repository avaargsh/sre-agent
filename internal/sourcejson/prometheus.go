package sourcejson

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
)

// CheckPrometheusCompleteness checks the top-level completeness metadata of a
// Prometheus-compatible response. Call Validate on the bounded raw bytes first
// to reject duplicate keys and malformed JSON. Missing optional flags, false
// flags and an empty warnings array are valid; explicit nulls are not.
// This check does not establish source authenticity or query coverage.
func CheckPrometheusCompleteness(raw []byte) error {
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(raw,&fields);err!=nil||fields==nil{return errors.New("invalid Prometheus response object")}
 for key,value:=range fields {
  for _,canonical:=range []string{"warnings","isPartial","partialResponse"} {
   if key!=canonical&&strings.EqualFold(key,canonical){return errors.New("noncanonical Prometheus completeness field")}
  }
  switch key {
  case "warnings":
   var warnings []json.RawMessage
   if json.Unmarshal(value,&warnings)!=nil||warnings==nil||len(warnings)!=0{return errors.New("warned or invalid Prometheus response")}
  case "isPartial","partialResponse":
   if !bytes.Equal(bytes.TrimSpace(value),[]byte("false")){return errors.New("partial or invalid Prometheus response")}
  }
 }
 return nil
}
