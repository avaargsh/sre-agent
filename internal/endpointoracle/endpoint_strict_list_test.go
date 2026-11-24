package endpointoracle

import (
	"encoding/json"
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
