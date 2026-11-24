package endpointoracle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectEndpointSliceListsWithoutExplicitItemsArray(t *testing.T) {
	_, _, service, _ := fixture(t, 1)
	for name, raw := range map[string]string{
		"omitted": `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"}}`,
		"null":    `{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Diagnose(service, []byte(raw), 8080, map[string]string{"app": "checkout-api"}); err == nil {
				t.Fatal("accepted EndpointSliceList without an explicit complete items array")
			}
		})
	}
}

func TestRejectEndpointSliceDuplicateNamesAndMissingMetadataLabels(t *testing.T) {
	_, _, service, _ := fixture(t, 1)
	base := map[string]any{
		"kind": "EndpointSliceList",
		"metadata": map[string]any{"resourceVersion": "25", "continue": ""},
		"items": []any{
			map[string]any{
				"metadata": map[string]any{"uid": "slice-1", "name": "same", "namespace": "golden-demo", "labels": map[string]string{"kubernetes.io/service-name": "checkout-api"}},
				"addressType": "IPv4", "endpoints": []any{},
			},
			map[string]any{
				"metadata": map[string]any{"uid": "slice-2", "name": "same", "namespace": "golden-demo", "labels": map[string]string{"kubernetes.io/service-name": "checkout-api"}},
				"addressType": "IPv4", "endpoints": []any{},
			},
		},
	}
	raw, err := json.Marshal(base)
	if err != nil { t.Fatal(err) }
	if _, err := Diagnose(service, raw, 8080, map[string]string{"app": "checkout-api"}); err == nil {
		t.Fatal("accepted duplicate EndpointSlice names")
	}
	base["items"] = []any{map[string]any{
		"metadata": map[string]any{"uid": "slice-3", "name": "slice", "namespace": "golden-demo"},
		"addressType": "IPv4", "endpoints": []any{},
	}}
	raw, err = json.Marshal(base)
	if err != nil { t.Fatal(err) }
	if _, err := Diagnose(service, raw, 8080, map[string]string{"app": "checkout-api"}); err == nil {
		t.Fatal("accepted EndpointSlice without explicit service ownership labels")
	}
}

func TestRejectMalformedUTF8AndCaseFoldConflicts(t *testing.T) {
	_, _, service, _ := fixture(t, 1)
	cases := map[string][]byte{
		"invalid-utf8": []byte{0xff, 0xfe},
		"casefold-conflict": []byte(`{"kind":"EndpointSliceList","Kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},"items":[]}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Diagnose(service, raw, 8080, map[string]string{"app": "checkout-api"}); err == nil {
				t.Fatal("accepted malformed or ambiguous EndpointSlice JSON")
			}
		})
	}
}

func TestRejectEndpointSliceListWithZeroResourceVersion(t *testing.T) {
	raw := []byte(`{"kind":"EndpointSliceList","metadata":{"resourceVersion":"0"},"items":[]}`)
	if _, err := inspect(raw, "golden-demo", "checkout-api", "svc-1"); err == nil {
		t.Fatal("accepted zero resourceVersion, which cannot serve as a cross-resource snapshot")
	}
}

func TestRejectEndpointSliceListWithOversizedResourceVersion(t *testing.T) {
	raw := []byte(`{"kind":"EndpointSliceList","metadata":{"resourceVersion":"` + strings.Repeat("β", 129) + `"},"items":[]}`)
	if _, err := inspect(raw, "golden-demo", "checkout-api", "svc-1"); err == nil {
		t.Fatal("accepted oversized opaque EndpointSlice resourceVersion")
	}
}



func TestDiagnoseRejectsServiceResourceVersionsOutsideSnapshotBudget(t *testing.T) {
	_, _, service, endpointSlices := fixture(t, 1)
	cases := map[string]string{
		"zero": "0",
		"oversized": strings.Repeat("β", 129), // 258 UTF-8 bytes.
	}
	for name, version := range cases {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(
				string(service),
				`"resourceVersion":"19"`,
				`"resourceVersion":"`+version+`"`,
				1,
			)
			if changed == string(service) {
				t.Fatal("Service resourceVersion fixture mutation did not apply")
			}
			if _, err := Diagnose(
				[]byte(changed), endpointSlices, 8080,
				map[string]string{"app": "checkout-api"},
			); err == nil {
				t.Fatal("accepted Service resourceVersion outside the cross-resource snapshot budget")
			}
		})
	}
}

func TestDiagnoseAcceptsOpaqueServiceResourceVersionAtByteLimit(t *testing.T) {
	_, _, service, endpointSlices := fixture(t, 1)
	version := strings.Repeat("β", 128) // Exactly 256 UTF-8 bytes.
	changed := strings.Replace(
		string(service),
		`"resourceVersion":"19"`,
		`"resourceVersion":"`+version+`"`,
		1,
	)
	if changed == string(service) {
		t.Fatal("Service resourceVersion fixture mutation did not apply")
	}
	if _, err := Diagnose(
		[]byte(changed), endpointSlices, 8080,
		map[string]string{"app": "checkout-api"},
	); err != nil {
		t.Fatalf("accepted opaque Service resourceVersion at the documented byte limit: %v", err)
	}
}

func TestEvaluateRejectsInvalidServiceResourceVersionInEveryPhase(t *testing.T) {
	for _, phaseName := range []string{"before", "during", "after"} {
		t.Run(phaseName, func(t *testing.T) {
			episode, prediction := episode(t, false)
			var phase *Phase
			switch phaseName {
			case "before":
				phase = &episode.Before
			case "during":
				phase = &episode.During
			case "after":
				phase = &episode.After
			}
			raw, err := checkedRaw(phase.Service)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(
				string(raw),
				`"resourceVersion":"19"`,
				`"resourceVersion":"0"`,
				1,
			)
			if changed == string(raw) {
				t.Fatal("Service resourceVersion fixture mutation did not apply")
			}
			phase.Service = snap([]byte(changed))
			if _, err := Evaluate(episode, prediction); err == nil {
				t.Fatal("accepted an Episode phase with zero Service resourceVersion")
			}
		})
	}
}
