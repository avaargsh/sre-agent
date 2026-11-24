package poddiagnosis

import (
 "crypto/sha256"
 "encoding/hex"
 "reflect"
)

// VerifyNativeReport independently recomputes a typed diagnostic receipt from
// original bytes and a separately trusted target and SHA-256 pin. It verifies
// content consistency only, not wire-format admission, issuer, freshness,
// causality, recovery, or permission. Do not derive the pin from the claim.
func VerifyNativeReport(expected Target, raw []byte, expectedRawSHA256 string, claimed NativeReport) error {
 if len(raw)==0 || len(raw)>MaxNativePodBytes || len(expectedRawSHA256)!=64 {return errInvalidPod}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=expectedRawSHA256 {return errInvalidPod}
 replayed,err:=AssessNative(expected,raw)
 if err!=nil || !reflect.DeepEqual(replayed,claimed) {return errInvalidPod}
 return nil
}
