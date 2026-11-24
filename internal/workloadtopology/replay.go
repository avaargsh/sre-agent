package workloadtopology

import (
	"bytes"
	"reflect"
)

// VerifyObservation independently replays a typed ownership observation using
// caller-selected target identities, ReplicaSet name and three separately
// obtained SHA-256 pins in Deployment, ReplicaSet, Pod order. Both read rounds
// must match these pins and each other byte for byte. It proves only content
// consistency, not collection order, source authenticity, freshness or recovery.
// Callers must not derive the expected pins from the observation being verified.
func VerifyObservation(expected Target, replicaSetName string, pins [3]string, claimed Observation) error {
	if !validName(replicaSetName) || len(claimed.Snapshots) != 3 || len(claimed.Confirmations) != 3 {
		return errInvalid
	}
	for i, pin := range pins {
		first, second := claimed.Snapshots[i], claimed.Confirmations[i]
		if len(pin) != 64 || first.SHA256 != pin || second.SHA256 != pin || len(first.Raw) == 0 || len(first.Raw) > MaxSnapshotBytes || len(second.Raw) != len(first.Raw) || !bytes.Equal(first.Raw, second.Raw) {
			return errInvalid
		}
	}
	replayed, err := Verify(expected, claimed.Snapshots[0], claimed.Snapshots[1], claimed.Snapshots[2])
	if err != nil || replayed.Sources[1].Name != replicaSetName || !reflect.DeepEqual(replayed, claimed.Report) {
		return errInvalid
	}
	return nil
}
