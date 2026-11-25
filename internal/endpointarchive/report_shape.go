package endpointarchive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// validateReportShape closes encoding/json's missing/null-to-zero ambiguity
// for plain report structs. The strict JSON parser runs before this walk;
// the typed decoder still checks value types and unknown fields afterward.
func validateReportShape(raw []byte, typ reflect.Type) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("missing or null report value")
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return fmt.Errorf("invalid report object")
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			parts := strings.Split(field.Tag.Get("json"), ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if field.Anonymous || name == "" {
				return fmt.Errorf("unsupported report field schema")
			}
			optional := false
			for _, option := range parts[1:] {
				optional = optional || option == "omitempty"
			}
			value, present := fields[name]
			if !present && optional {
				continue
			}
			if err := validateReportShape(value, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || items == nil {
			return fmt.Errorf("invalid report array")
		}
		for _, item := range items {
			if err := validateReportShape(item, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		if typ.Key().Kind() != reflect.String {
			return fmt.Errorf("unsupported report map key schema")
		}
		var items map[string]json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || items == nil {
			return fmt.Errorf("invalid report map")
		}
		for _, item := range items {
			if err := validateReportShape(item, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		// The typed decoder validates scalar values.
	default:
		return fmt.Errorf("unsupported report value schema")
	}
	return nil
}
