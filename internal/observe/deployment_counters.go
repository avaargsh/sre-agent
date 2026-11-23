package observe

import "fmt"

// validateDeploymentCounters mirrors the offline evidence verifier's numeric
// invariants before any Pod/metric read or complete Evidence Bundle emission.
// It does not assume ready replicas are bounded by desired during rollouts.
func validateDeploymentCounters(generation, observedGeneration int64, desiredReplicas, readyReplicas int) error {
 if generation < 0 || observedGeneration < 0 || observedGeneration > generation {
  return fmt.Errorf("inconsistent Deployment generation counters")
 }
 if desiredReplicas < 0 || readyReplicas < 0 {
  return fmt.Errorf("negative Deployment replica counters")
 }
 return nil
}
