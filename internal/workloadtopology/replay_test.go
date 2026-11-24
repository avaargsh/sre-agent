package workloadtopology

import (
	"strings"
	"testing"
)

func replayFixture(t *testing.T) (Observation, [3]string) {
	t.Helper()
	first := []Snapshot{pin(dep), pin(rs), pin(pod)}
	second := []Snapshot{pin(dep), pin(rs), pin(pod)}
	report, err := Verify(target(), first[0], first[1], first[2])
	if err != nil {
		t.Fatal(err)
	}
	return Observation{Report: report, Snapshots: first, Confirmations: second}, [3]string{first[0].SHA256, first[1].SHA256, first[2].SHA256}
}

func TestVerifyObservation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Target, *string, *[3]string, *Observation)
	}{
		{"valid", nil},
		{"wrong-target", func(t *Target, _ *string, _ *[3]string, _ *Observation) { t.PodUID = "other" }},
		{"wrong-replicaset", func(_ *Target, n *string, _ *[3]string, _ *Observation) { *n = "other" }},
		{"missing-replicaset", func(_ *Target, n *string, _ *[3]string, _ *Observation) { *n = "" }},
		{"missing-pin", func(_ *Target, _ *string, p *[3]string, _ *Observation) { p[0] = "" }},
		{"wrong-pin", func(_ *Target, _ *string, p *[3]string, _ *Observation) { p[1] = strings.Repeat("0", 64) }},
		{"uppercase-pin", func(_ *Target, _ *string, p *[3]string, _ *Observation) { p[2] = strings.ToUpper(p[2]) }},
		{"missing-first", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Snapshots = o.Snapshots[:2] }},
		{"missing-confirmation", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Confirmations = o.Confirmations[:2] }},
		{"extra-confirmation", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Confirmations = append(o.Confirmations, o.Confirmations[0])
		}},
		{"reordered-first", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Snapshots[0], o.Snapshots[1] = o.Snapshots[1], o.Snapshots[0]
		}},
		{"reordered-confirmation", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Confirmations[0], o.Confirmations[1] = o.Confirmations[1], o.Confirmations[0]
		}},
		{"first-bytes", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Snapshots[2].Raw = append(o.Snapshots[2].Raw, '\n')
		}},
		{"confirmation-bytes", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Confirmations[2].Raw = append(o.Confirmations[2].Raw, '\n')
		}},
		{"confirmation-digest", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			o.Confirmations[1].SHA256 = strings.Repeat("0", 64)
		}},
		{"first-digest", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Snapshots[1].SHA256 = strings.Repeat("0", 64) }},
		{"rehashed-both-rounds", func(_ *Target, _ *string, _ *[3]string, o *Observation) {
			s := pin(strings.Replace(pod, `"12"`, `"13"`, 1))
			o.Snapshots[2] = s
			o.Confirmations[2] = s
			o.Report.Sources[2].SHA256 = s.SHA256
			o.Report.Sources[2].ResourceVersion = "13"
		}},
		{"forged-source", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.SourceAuthenticated = true }},
		{"forged-rca", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.RootCauseVerified = true }},
		{"forged-recovery", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.RecoveryVerified = true }},
		{"forged-status", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.Status = "HEALTHY" }},
		{"forged-resource-version", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.Sources[1].ResourceVersion = "99" }},
		{"missing-report-source", func(_ *Target, _ *string, _ *[3]string, o *Observation) { o.Report.Sources = o.Report.Sources[:2] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, pins := replayFixture(t)
			expected := target()
			name := "checkout-rs"
			if tc.mutate != nil {
				tc.mutate(&expected, &name, &pins, &obs)
			}
			err := VerifyObservation(expected, name, pins, obs)
			if (err == nil) != (tc.mutate == nil) {
				t.Fatalf("replay admission mismatch: %v", err)
			}
		})
	}
}
