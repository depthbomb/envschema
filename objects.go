package envschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/token"
	"reflect"
	"strings"
	"unicode"
)

// ObjectField defines a named JSON property and its generated Go field.
type ObjectField struct {
	Name   string `json:"name"`
	GoName string `json:"goName,omitempty"`
	Rule   Rule   `json:"rule"`
}

const KindObject Kind = "object"

func objectFieldName(field ObjectField) string {
	if field.GoName != "" {
		return field.GoName
	}
	var builder strings.Builder
	upper := true
	for _, r := range field.Name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

func validateObjectFields(fields []ObjectField, path string) error {
	seen := make(map[string]bool)
	names := make(map[string]bool)
	for _, field := range fields {
		goName := objectFieldName(field)
		if field.Name == "" || seen[field.Name] || names[goName] || !token.IsIdentifier(goName) || !unicode.IsUpper([]rune(goName)[0]) {
			return fmt.Errorf("envschema: %s has invalid or duplicate object field %q", path, field.Name)
		}
		seen[field.Name] = true
		names[goName] = true
		if field.Rule.Kind == KindCustom {
			return fmt.Errorf("envschema: object custom fields are not supported")
		}
		if err := validateRule(field.Rule, path+"."+field.Name); err != nil {
			return err
		}
		if field.Rule.HasDefault {
			if _, err := parseRule(field.Rule, field.Rule.Default, path+"."+field.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseObject(rule Rule, raw any, path string) (any, error) {
	var object map[string]any
	switch value := raw.(type) {
	case map[string]any:
		object = value
	default:
		var data []byte
		switch value := raw.(type) {
		case string:
			data = []byte(value)
		case json.RawMessage:
			data = value
		default:
			var err error
			data, err = json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("[%s] invalid object", path)
			}
		}
		if _, err := parseJSON(JSON().ObjectOnly().UniqueObjectKeys(), string(data), path); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			return nil, fmt.Errorf("[%s] invalid object", path)
		}
	}
	if object == nil {
		return nil, fmt.Errorf("[%s] expected object", path)
	}
	result := make(map[string]any)
	known := make(map[string]bool)
	for _, field := range rule.Fields {
		known[field.Name] = true
		raw, present := object[field.Name]
		if !present {
			if field.Rule.HasDefault {
				raw = field.Rule.Default
			} else if field.Rule.Required {
				return nil, fmt.Errorf("[%s.%s] required field is missing", path, field.Name)
			} else {
				continue
			}
		}
		value, err := parseRule(field.Rule, raw, path+"."+field.Name)
		if err != nil {
			return nil, err
		}
		result[field.Name] = value
	}
	if !rule.UnknownFields {
		for name := range object {
			if !known[name] {
				return nil, fmt.Errorf("[%s] unknown object field %q", path, name)
			}
		}
	}

	return result, nil
}

func assignObject(target reflect.Value, source reflect.Value) error {
	for i := 0; i < target.NumField(); i++ {
		field := target.Type().Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		value := source.MapIndex(reflect.ValueOf(name))
		if !value.IsValid() {
			continue
		}
		if err := assignValue(target.Field(i), value); err != nil {
			return fmt.Errorf("field %s: %w", name, err)
		}
	}

	return nil
}

// Field defines a JSON object property.
func Field(name string, rule Rule) ObjectField {
	return ObjectField{Name: name, Rule: rule}
}

// Named sets the generated Go field name.
func (field ObjectField) Named(name string) ObjectField {
	field.GoName = name

	return field
}

// Object parses a JSON object into validated fields and generates a concrete struct.
func Object(fields ...ObjectField) Rule {
	result := rule(KindObject)
	result.Fields = append([]ObjectField(nil), fields...)

	return result
}

// AllowUnknownFields accepts and discards undeclared object properties.
func (rule Rule) AllowUnknownFields() Rule {
	rule.UnknownFields = true

	return rule
}

// ObjectFieldName returns the generated exported field name.
func ObjectFieldName(field ObjectField) string {
	return objectFieldName(field)
}
