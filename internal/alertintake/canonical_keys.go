package alertintake

import (
 "encoding/json"
 "strings"
)

// Go's struct JSON decoder accepts case-insensitive field spellings, so
// "status" and "Status" are distinct keys to JSON but target one Go field.
// Enforce exact field casing in privileged routing inputs before typed decode.
func checkCanonicalObject(obj map[string]json.RawMessage, fields ...string) error {
 for key:=range obj {
  for _,field:=range fields {
   if strings.EqualFold(key,field)&&key!=field {
    return unknown("noncanonical alert field alias")
   }
  }
 }
 return nil
}

func checkCanonicalFields(raw []byte) error {
 var root map[string]json.RawMessage
 if err:=json.Unmarshal(raw,&root);err!=nil||root==nil {
  return unknown("invalid Alertmanager root object")
 }
 if err:=checkCanonicalObject(root,"receiver","status","groupKey","truncatedAlerts","commonLabels","commonAnnotations","alerts");err!=nil{return err}
 // Alertmanager may truncate the group before computing common labels.
 // An explicitly incomplete group cannot prove that every member is scoped.
 if value,ok:=root["truncatedAlerts"];ok && strings.TrimSpace(string(value))!="0" {
  return unknown("truncated or invalid Alertmanager alert count")
 }
 var common map[string]json.RawMessage
 if bytes,ok:=root["commonLabels"];ok {
  if err:=json.Unmarshal(bytes,&common);err!=nil{return unknown("invalid common label object")}
  if err:=checkCanonicalObject(common,"cluster","namespace","deployment","severity","alertname");err!=nil{return err}
 }
 var annotations map[string]json.RawMessage
 if bytes,ok:=root["commonAnnotations"];ok {
  if err:=json.Unmarshal(bytes,&annotations);err!=nil{return unknown("invalid annotation object")}
  if err:=checkCanonicalObject(annotations,"summary","description");err!=nil{return err}
 }
 var alerts []map[string]json.RawMessage
 if bytes,ok:=root["alerts"];ok {
  if err:=json.Unmarshal(bytes,&alerts);err!=nil{return unknown("invalid alerts array")}
 }
 for _,item:=range alerts {
  if err:=checkCanonicalObject(item,"status","fingerprint","labels","annotations","startsAt","endsAt");err!=nil{return err}
  var labels map[string]json.RawMessage
  if bytes,ok:=item["labels"];ok {
   if err:=json.Unmarshal(bytes,&labels);err!=nil{return unknown("invalid alert label object")}
   if err:=checkCanonicalObject(labels,"cluster","namespace","deployment","severity","alertname");err!=nil{return err}
  }
 }
 return nil
}
