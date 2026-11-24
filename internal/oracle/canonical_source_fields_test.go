package oracle

import (
	"strings"
	"testing"
)

func TestDiagnoseRejectsSingleCaseInsensitiveServiceFieldAliases(t *testing.T) {
	_, raw := source(t, 8080)
	cases := map[string]string{
		"metadata": strings.Replace(raw, `"metadata":`, `"Metadata":`, 1),
		"resourceVersion": strings.Replace(raw, `"resourceVersion":`, `"ResourceVersion":`, 1),
		"spec": strings.Replace(raw, `"spec":`, `"Spec":`, 1),
		"targetPort": strings.Replace(raw, `"targetPort":`, `"TargetPort":`, 1),
	}
	for name, changed := range cases {
		t.Run(name, func(t *testing.T) {
			if changed == raw {
				t.Fatal("fixture alias mutation did not apply")
			}
			if _, err := Diagnose([]byte(changed), 8080); err == nil {
				t.Fatalf("accepted noncanonical Service field alias: %s", changed)
			}
		})
	}
}

func TestDiagnoseKeepsServiceSelectorMapKeysAsData(t *testing.T) {
	_, raw := source(t, 8080)
	changed := strings.Replace(raw, `"app":"checkout-api"`, `"App":"checkout-api"`, 1)
	if changed == raw {
		t.Fatal("selector map fixture mutation did not apply")
	}
	if _, err := Diagnose([]byte(changed), 8080); err != nil {
		t.Fatalf("case-sensitive selector map key was treated as a schema alias: %v", err)
	}
}
