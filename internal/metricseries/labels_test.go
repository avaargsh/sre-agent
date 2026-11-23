package metricseries

import "testing"

func TestKeyDistinguishesUniqueInstantVectorLabelsets(t *testing.T) {
	a, err := Key(map[string]string{"namespace": "golden-demo", "pod": "checkout-0"})
	if err != nil { t.Fatal(err) }
	b, err := Key(map[string]string{"pod": "checkout-0", "namespace": "golden-demo"})
	if err != nil { t.Fatal(err) }
	if a != b { t.Fatalf("label order changed canonical identity: %q != %q", a, b) }
	c, err := Key(map[string]string{"namespace": "golden-demo", "pod": "checkout-1"})
	if err != nil { t.Fatal(err) }
	if a == c { t.Fatal("different labelsets have equal series identity") }
}

func TestKeyRejectsMissingAndInvalidMetricLabels(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"missing": nil,
		"empty label name": {"":"bad"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Key(labels); err == nil { t.Fatal("invalid metric labelset accepted") }
		})
	}
	if _, err := Key(map[string]string{}); err != nil {
		t.Fatalf("valid unlabeled aggregate rejected: %v", err)
	}
}

func TestUniqueRejectsRepeatedInstantVectorSeries(t *testing.T) {
	if err := Unique([]map[string]string{{"pod":"a"}, {"pod":"b"}}); err != nil { t.Fatal(err) }
	if err := Unique([]map[string]string{{"namespace":"n","pod":"a"}, {"pod":"a","namespace":"n"}}); err == nil {
		t.Fatal("duplicate Prometheus instant vector series accepted")
	}
	if err := Unique([]map[string]string{{}, {}}); err == nil {
		t.Fatal("duplicate empty-label vector series accepted")
	}
	if err := Unique([]map[string]string{nil}); err == nil {
		t.Fatal("missing metric labels accepted")
	}
}
