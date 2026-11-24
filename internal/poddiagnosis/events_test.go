package poddiagnosis

import (
 "crypto/sha256"
 "fmt"
 "strings"
 "testing"
)

const eventsFixture = `{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43"},"items":[{"metadata":{"uid":"event-1","namespace":"demo"},"involvedObject":{"apiVersion":"v1","kind":"Pod","namespace":"demo","name":"checkout-1","uid":"pod-uid-1"},"type":"Warning","reason":"BackOff","message":"private diagnostic text"}]}`

func eventTarget() Target { return Target{Namespace:"demo",Name:"checkout-1",UID:"pod-uid-1"} }

func TestEventListPinsScopedFacts(t *testing.T) {
 r,err:=AssessEvents(eventTarget(),[]byte(eventsFixture))
 if err!=nil || r.RawSHA256!=fmt.Sprintf("%x",sha256.Sum256([]byte(eventsFixture))) || r.ResourceVersion!="43" || len(r.Events)!=1 || r.Events[0].Reason!="BackOff" || r.SourceAuthenticated {t.Fatalf("unexpected report: %+v %v",r,err)}
}

func TestEventListRejectsIncompleteOrForeignEvidence(t *testing.T) {
 for name,raw:=range map[string]string{
  "foreign-uid":strings.Replace(eventsFixture,"pod-uid-1","pod-uid-2",1),
  "foreign-name":strings.Replace(eventsFixture,"checkout-1","other",1),
  "foreign-namespace":strings.Replace(eventsFixture,`"namespace":"demo"`,`"namespace":"other"`,1),
  "pagination":strings.Replace(eventsFixture,`"resourceVersion":"43"`,`"resourceVersion":"43","continue":"next"`,1),
  "alias":strings.Replace(eventsFixture,`"involvedObject"`,`"InvolvedObject"`,1),
  "duplicate":strings.Replace(eventsFixture,`"reason":"BackOff"`,`"reason":"BackOff","reason":"Failed"`,1),
  "duplicate-event":strings.Replace(eventsFixture,`]}`,`,{`+strings.SplitN(strings.SplitN(eventsFixture,`[{`,2)[1],`]}`,2)[0]+`]}`,1),
  "null-items":`{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43"},"items":null}`,
 } {t.Run(name,func(t *testing.T){r,err:=AssessEvents(eventTarget(),[]byte(raw));if err==nil || r.RawSHA256!="" || len(r.Events)!=0 {t.Fatalf("invalid list admitted: %+v %v",r,err)}})}
}

func TestEmptyEventListIsNotHealthProof(t *testing.T) {
 r,err:=AssessEvents(eventTarget(),[]byte(`{"apiVersion":"v1","kind":"EventList","metadata":{"resourceVersion":"43"},"items":[]}`))
 if err!=nil || r.Events==nil || len(r.Events)!=0 || r.SourceAuthenticated {t.Fatalf("unexpected empty list: %+v %v",r,err)}
}
