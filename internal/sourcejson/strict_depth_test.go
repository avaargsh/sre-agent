package sourcejson

import (
    "strings"
    "testing"
)

// Upstream native JSON is bounded in bytes, but long chains of nested arrays
// are otherwise allowed to recurse through the token walker unchecked.
func TestValidateSourceJSONDepthBudget(t *testing.T) {
    const maxDepth = 64
    cases := []struct {
        name string
        raw string
        wantValid bool
    }{
        {"normal-source", `{"status":"success","data":{"resultType":"vector","result":[]}}`, true},
        {"array-at-limit", strings.Repeat("[", maxDepth) + `"ok"` + strings.Repeat("]", maxDepth), true},
        {"array-over-limit", strings.Repeat("[", maxDepth+1) + `"ok"` + strings.Repeat("]", maxDepth+1), false},
        {"object-at-limit", strings.Repeat(`{"next":`,maxDepth) + `"ok"` + strings.Repeat("}",maxDepth), true},
        {"object-over-limit", strings.Repeat(`{"next":`,maxDepth+1) + `"ok"` + strings.Repeat("}",maxDepth+1), false},
        {"very-deep-array", strings.Repeat("[", 4096) + `0` + strings.Repeat("]",4096), false},
        {"duplicate-key-still-rejected", `{"status":"success","status":"failure"}`, false},
    }
    for _,tc := range cases {
        t.Run(tc.name,func(t *testing.T) {
            err:=Validate([]byte(tc.raw))
            if (err==nil)!=tc.wantValid {t.Fatalf("Validate(%s) accepted=%v want=%v, err=%v",tc.name,err==nil,tc.wantValid,err)}
        })
    }
}
