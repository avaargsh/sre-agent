package sourcejson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// ValidateCanonicalFields rejects case-insensitive aliases for fields in a
// typed JSON schema. Go's encoding/json accepts such aliases even when the
// canonical spelling is absent, which can silently populate a struct field.
//
// Call Validate first: it rejects duplicate/case-fold-colliding keys before
// this function decodes objects into maps. Unknown fields are left to the
// caller's typed decoder policy. Map keys and json.RawMessage values remain
// data, not schema field names.
func ValidateCanonicalFields(raw []byte, target any) error {
	if target == nil {
		return fmt.Errorf("nil target schema")
	}
	return validateCanonicalFields(raw, reflect.TypeOf(target))
}

func validateCanonicalFields(raw []byte, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == rawMessageType {
		return nil
	}

	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			// The typed decoder owns malformed shapes and null-to-struct
			// behavior. This pass only checks field-name ambiguity.
			return nil
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
						return fmt.Errorf("noncanonical field %q; expected %q", name, canonical)
					}
				}
				continue
			}
			if err := validateCanonicalFields(value, fieldType); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil
		}
		for _, value := range values {
			if err := validateCanonicalFields(value, typ.Elem()); err != nil {
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
			if err := validateCanonicalFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
