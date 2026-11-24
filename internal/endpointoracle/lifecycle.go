package endpointoracle

import (
	"encoding/json"
	"errors"
)

// The v1 oracle supports only ordinary Service readiness policy. The caller
// validates native source JSON before invoking this guard.
func validateServiceReadinessPolicy(raw []byte) error {
	var svc struct {
		Spec *struct {
			PublishNotReadyAddresses json.RawMessage `json:"publishNotReadyAddresses"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &svc); err != nil || svc.Spec == nil {
		return errors.New("invalid Service readiness policy")
	}
	flag := svc.Spec.PublishNotReadyAddresses
	if len(flag) != 0 && string(flag) != "false" {
		return errors.New("unsupported Service publishNotReadyAddresses policy")
	}
	return nil
}

// Terminating endpoints may still serve traffic. The steady-state oracle
// cannot classify those transitions as healthy or as a confirmed outage.
// Preserve legacy observations with omitted optional conditions.
func validateEndpointLifecycle(ready bool, serving, terminating *bool) error {
	if terminating != nil && *terminating {
		return errors.New("terminating endpoint outside steady-state oracle scope")
	}
	if serving != nil && *serving != ready {
		return errors.New("EndpointSlice ready and serving conditions disagree")
	}
	return nil
}
