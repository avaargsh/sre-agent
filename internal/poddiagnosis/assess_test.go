package poddiagnosis

import "testing"

func fixture() (Target, Snapshot) {
 t := Target{Namespace:"demo", Name:"checkout-1", UID:"pod-uid-1"}
 return t, Snapshot{Target:t, ResourceVersion:"42", Phase:"Running", Containers:[]string{"app"}, Statuses:[]ContainerStatus{{Name:"app", State:"running", Ready:true}}}
}

func TestRunningPodCrashLoopIsNotHealthy(t *testing.T) {
 target, snapshot := fixture()
 snapshot.Statuses[0] = ContainerStatus{Name:"app", State:"waiting", Reason:"CrashLoopBackOff", RestartCount:5}
 report := Assess(target,snapshot)
 if report.Status != "SIGNALS_PRESENT" || len(report.Findings)!=1 || report.Findings[0].Code!="CrashLoopBackOff" || report.RootCauseVerified || report.RecoveryVerified { t.Fatalf("wrong report: %+v",report) }
}

func TestHistoricalOOMIsNotCurrentFailure(t *testing.T) {
 target, snapshot := fixture()
 snapshot.Statuses[0].LastTerminationReason="OOMKilled"
 snapshot.Statuses[0].RestartCount=1
 report := Assess(target,snapshot)
 if report.Status!="SIGNALS_PRESENT" || len(report.Findings)!=1 || report.Findings[0].Code!="OOMKilled" || report.Findings[0].TemporalScope!="historical" { t.Fatalf("wrong report: %+v",report) }
}

func TestNoSignalDoesNotVerifyHealth(t *testing.T) {
 target,snapshot:=fixture()
 report:=Assess(target,snapshot)
 if report.Status!="UNKNOWN" || len(report.Findings)!=0 || report.RootCauseVerified || report.RecoveryVerified { t.Fatalf("wrong report: %+v",report) }
}

func TestIncompleteOrMismatchedSnapshotReturnsUnknown(t *testing.T) {
 for name, mutate:=range map[string]func(*Snapshot){
  "wrong-uid":func(s *Snapshot){s.UID="replacement"},
  "missing-status":func(s *Snapshot){s.Statuses=nil},
  "missing-resource-version":func(s *Snapshot){s.ResourceVersion=""},
  "duplicate-status":func(s *Snapshot){s.Statuses=append(s.Statuses,s.Statuses[0])},
  "foreign-container":func(s *Snapshot){s.Statuses[0].Name="other"},
  "invalid-state":func(s *Snapshot){s.Statuses[0].State="unknown"},
  "negative-restarts":func(s *Snapshot){s.Statuses[0].RestartCount=-1},
 } {
  t.Run(name,func(t *testing.T){target,snapshot:=fixture();mutate(&snapshot);report:=Assess(target,snapshot);if report.Status!="UNKNOWN" || len(report.Findings)!=0 || report.RootCauseVerified || report.RecoveryVerified {t.Fatalf("invalid snapshot promoted: %+v",report)}})
 }
}
