package evidence

import (
 "strings"
 "testing"
)

func TestValidateUniqueJSONObject(t *testing.T) {
 for _,tc:=range []struct{name,raw string;valid bool}{
  {"object",`{"x":[{"y":1}],"z":true}`,true},
  {"empty-object",`{}`,true},
  {"paired-surrogate",`{"x":"\ud83d\ude00"}`,true},
  {"duplicate",`{"x":1,"x":2}`,false},
  {"nested-escaped-duplicate",`{"a":[{"x":1,"\u0078":2}]}`,false},
  {"trailing",`{} {}`,false},
  {"array-root",`[]`,false},
  {"null-root",`null`,false},
  {"invalid-utf8",string([]byte{'{','"','x','"',':','"',0xff,'"','}'}),false},
  {"unpaired-surrogate",`{"x":"\ud800"}`,false},
  {"oversize",strings.Repeat(" ",MaxBundleBytes+1),false},
 } {t.Run(tc.name,func(t *testing.T){if got:=ValidateUniqueJSONObject([]byte(tc.raw))==nil;got!=tc.valid {t.Fatalf("valid=%v; want %v",got,tc.valid)}})}
}
