package poddiagnosis

import (
 "encoding/json"
 "reflect"

 "github.com/avaargsh/sre-agent/internal/sourcejson"
)

const MaxNativeReportBytes = 256 << 10

// VerifyNativeReportJSON checks the serialized claim before any typed decode.
// Exact JSON keys, values and array order must match the recomputed report;
// object field ordering and insignificant whitespace are not significant.
// Independent target and raw digest pins are required. No source or authority
// attestation follows from a successful structural replay.
func VerifyNativeReportJSON(expected Target, raw []byte, expectedRawSHA256 string, claimed []byte) error {
 if len(claimed)==0 || len(claimed)>MaxNativeReportBytes || sourcejson.Validate(claimed)!=nil {return errInvalidPod}
 replayed,err:=AssessNative(expected,raw)
 if err!=nil || replayed.RawSHA256!=expectedRawSHA256 {return errInvalidPod}
 canonical,err:=json.Marshal(replayed)
 if err!=nil {return errInvalidPod}
 var want,got any
 if json.Unmarshal(canonical,&want)!=nil || json.Unmarshal(claimed,&got)!=nil || !reflect.DeepEqual(want,got) {return errInvalidPod}
 return nil
}
