package endpointoracle

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// validateCanonicalJSONFields rejects case-insensitive aliases that
// encoding/json would otherwise match to a struct field. Map keys are data,
// not schema fields, so their names remain unrestricted.
func validateCanonicalJSONFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return nil // The typed decoder reports shape/type errors.
		}
		fields := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, value := range object {
			fieldType, ok := fields[name]
			if !ok {
				for canonical := range fields {
					if strings.EqualFold(name, canonical) {
						return fmt.Errorf("non-canonical field %q; expected %q", name, canonical)
					}
				}
				continue // Unknown fields are left to the caller's typed decoder policy.
			}
			if err := validateCanonicalJSONFields(value, fieldType); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil
		}
		for _, value := range values {
			if err := validateCanonicalJSONFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		if typ.Key().Kind() != reflect.String {
			return nil
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil || values == nil {
			return nil
		}
		for _, value := range values {
			if err := validateCanonicalJSONFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
