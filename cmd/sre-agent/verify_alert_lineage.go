package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "strconv"
)

// verifyReadOnlyEvidenceLineage independently reconstructs the v1 observer's
// deterministic content ID and human-readable observation from the exact
// source attributes. A self-consistent, self-rehashed bundle remains
// unauthenticated; this is NOT an operator permit or trusted provenance.
func verifyReadOnlyEvidenceLineage(item map[string]any,source string,attrs map[string]any)error{
 refs,ok:=item["entity_refs"].([]any)
 if !ok||len(refs)!=0 {
  return fmt.Errorf("read-only evidence must have an explicit empty entity_refs array")
 }
 if attrs==nil{return fmt.Errorf("source attributes must be a JSON object")}
 for key,val:=range attrs{
  if _,ok:=val.(string);!ok{
   return fmt.Errorf("source attribute %q must be a string",key)
  }
 }
 encoded,err:=json.Marshal(attrs)
 if err!=nil{return fmt.Errorf("cannot canonicalize source attributes")}
 // Match the Go read-only collector's source-name-delimited SHA-256 prefix.
 material:=append([]byte(source+":"),encoded...)
 digest:=sha256.Sum256(material)
 id:="obs-"+hex.EncodeToString(digest[:12])
 if exactText(item,"evidence_id")!=id{
  return fmt.Errorf("evidence_id does not match source attributes")
 }
 var observation string
 switch source {
 case "kubernetes":
  // These are the exact fields emitted by readKubernetes. An attacker can
  // rehash both evidence_id and bundle digest, so presence and value checks
  // must independently fail closed rather than relying on checksum mismatch.
  for _,key:=range []string{"generation","observed_generation"}{
   raw:=exactText(attrs,key)
   number,err:=strconv.ParseInt(raw,10,64)
   if err!=nil||number<0||strconv.FormatInt(number,10)!=raw {
    return fmt.Errorf("invalid Kubernetes %s",key)
   }
  }
  if exactText(attrs,"pod_list_resource_version")==""{
   return fmt.Errorf("missing Kubernetes Pod list resource version")
  }
  desiredRaw,readyRaw:=exactText(attrs,"desired_replicas"),exactText(attrs,"ready_replicas")
  desired,err:=strconv.Atoi(desiredRaw)
  if err!=nil||desired<0||strconv.Itoa(desired)!=desiredRaw {
   return fmt.Errorf("invalid desired replica count")
  }
  ready,err:=strconv.Atoi(readyRaw)
  if err!=nil||ready<0||strconv.Itoa(ready)!=readyRaw {
   return fmt.Errorf("invalid ready replica count")
  }
  observation=fmt.Sprintf("deployment %s/%s desired=%d ready=%d",
   exactText(attrs,"namespace"),exactText(attrs,"deployment"),desired,ready)
 case "prometheus":
  countRaw:=exactText(attrs,"series_count")
  count,err:=strconv.Atoi(countRaw)
  if err!=nil||count<=0||count>32||strconv.Itoa(count)!=countRaw{
   return fmt.Errorf("invalid source series count")
  }
  observation=fmt.Sprintf("PromQL %s: %d fresh finite series",
   exactText(attrs,"promql"),count)
 default:
  return fmt.Errorf("unknown read-only source %q",source)
 }
 if exactText(item,"observation")!=observation{
  return fmt.Errorf("read-only observation description contradicts source attributes")
 }
 return nil
}
