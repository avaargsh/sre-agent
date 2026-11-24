package poddiagnosis

import (
 "encoding/json"
 "reflect"

 "github.com/avaargsh/sre-agent/internal/sourcejson"
)

const MaxEventReportBytes = 256 << 10

// VerifyEventReportJSON recomputes the report from independently pinned raw
// bytes and Pod identity. Exact keys, values and event array order must match;
// JSON whitespace and object ordering are immaterial. Success verifies only
// structural consistency, not source authenticity, freshness or causality.
func VerifyEventReportJSON(expected Target, raw []byte, expectedRawSHA256 string, claimed []byte) error {
 if len(claimed)==0 || len(claimed)>MaxEventReportBytes || sourcejson.Validate(claimed)!=nil {return errInvalidPod}
 replayed,err:=AssessEvents(expected,raw)
 if err!=nil || replayed.RawSHA256!=expectedRawSHA256 {return errInvalidPod}
 canonical,err:=json.Marshal(replayed)
 if err!=nil {return errInvalidPod}
 var want,got any
 if json.Unmarshal(canonical,&want)!=nil || json.Unmarshal(claimed,&got)!=nil || !reflect.DeepEqual(want,got) {return errInvalidPod}
 return nil
}
