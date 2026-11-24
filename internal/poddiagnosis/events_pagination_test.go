package poddiagnosis

import (
 "crypto/sha256"
 "fmt"
 "strings"
 "testing"
)

func TestEventListRemainingItemCount(t *testing.T) {
 for _,tc:=range []struct{name,metadata string;valid bool}{
  {"absent",`"resourceVersion":"43"`,true},
  {"zero",`"resourceVersion":"43","remainingItemCount":0`,true},
  {"zero and empty continuation",`"resourceVersion":"43","remainingItemCount":0,"continue":""`,true},
  {"positive",`"resourceVersion":"43","remainingItemCount":1`,false},
  {"negative",`"resourceVersion":"43","remainingItemCount":-1`,false},
  {"null",`"resourceVersion":"43","remainingItemCount":null`,false},
  {"string",`"resourceVersion":"43","remainingItemCount":"0"`,false},
  {"fractional",`"resourceVersion":"43","remainingItemCount":0.0`,false},
  {"overflow",`"resourceVersion":"43","remainingItemCount":9223372036854775808`,false},
  {"alias",`"resourceVersion":"43","RemainingItemCount":0`,false},
  {"duplicate",`"resourceVersion":"43","remainingItemCount":1,"remainingItemCount":0`,false},
  {"continuation despite zero",`"resourceVersion":"43","remainingItemCount":0,"continue":"next"`,false},
 } {t.Run(tc.name,func(t *testing.T){
  raw:=[]byte(strings.Replace(eventsFixture,`"resourceVersion":"43"`,tc.metadata,1))
  report,err:=AssessEvents(eventTarget(),raw)
  if tc.valid {
   if err!=nil || report.RawSHA256!=fmt.Sprintf("%x",sha256.Sum256(raw)) || len(report.Events)!=1 || report.SourceAuthenticated {t.Fatalf("valid list rejected: %+v %v",report,err)}
  } else if err==nil || report.RawSHA256!="" || len(report.Events)!=0 {t.Fatalf("incomplete or invalid list admitted: %+v %v",report,err)}
 })}
}
