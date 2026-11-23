package observe

import "fmt"

// validatePodProjection enforces the same independently replayable Pod snapshot
// contract as the offline evidence verifier. An inconsistent source cannot be
// advertised as a complete read-only observation.
func validatePodProjection(pods []map[string]string) error {
 seenUIDs := make(map[string]struct{}, len(pods))
 seenNames := make(map[string]struct{}, len(pods))
 for _, pod := range pods {
  uid, name, phase := pod["uid"], pod["name"], pod["phase"]
  if uid == "" || name == "" { return fmt.Errorf("pod has missing UID or name") }
  switch phase {
  case "Pending", "Running", "Succeeded", "Failed", "Unknown":
  default: return fmt.Errorf("pod has unknown or missing phase")
  }
  if _, exists := seenUIDs[uid]; exists { return fmt.Errorf("duplicate pod UID") }
  if _, exists := seenNames[name]; exists { return fmt.Errorf("duplicate pod name") }
  seenUIDs[uid] = struct{}{}
  seenNames[name] = struct{}{}
 }
 return nil
}
