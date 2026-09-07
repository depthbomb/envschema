package envschema

import (
	"encoding"
	"fmt"
	"reflect"
)

// Protected holds a parsed value and redacts formatting and serialization.
// Release is the explicit access point for sensitive data.
type Protected[T any] struct {
	value T
}

func (value *Protected[T]) assignProtected(raw any) error {
	if decoder, ok := any(&value.value).(encoding.TextUnmarshaler); ok {
		if text, ok := raw.(string); ok {
			if err := decoder.UnmarshalText([]byte(text)); err != nil {
				return fmt.Errorf("invalid sensitive custom value")
			}

			return nil
		}
	}

	return assignValue(reflect.ValueOf(&value.value).Elem(), reflect.ValueOf(raw))
}

func (value Protected[T]) protectedValue() any {
	return value.value
}

func identityValue(value any) any {
	if protected, ok := value.(interface{ protectedValue() any }); ok {
		return identityValue(protected.protectedValue())
	}

	if secret, ok := value.(SecretValue); ok {
		return secret.Release()
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		items := make([]any, reflected.Len())
		for i := range items {
			items[i] = identityValue(reflected.Index(i).Interface())
		}

		return items
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return value
		}
		items := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			items[iterator.Key().String()] = identityValue(iterator.Value().Interface())
		}

		return items
	}

	return value
}

// Sensitive wraps this rule's parsed result in Protected and hides parser errors.
func (rule Rule) Sensitive() Rule {
	rule.Redact = true

	return rule
}

func (value Protected[T]) Release() T {
	return value.value
}

func (value Protected[T]) String() string {
	return redactedSecret
}

func (value Protected[T]) GoString() string {
	return redactedSecret
}

func (value Protected[T]) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedSecret))
}

func (value Protected[T]) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted]"`), nil
}

func (value Protected[T]) MarshalText() ([]byte, error) {
	return []byte(redactedSecret), nil
}
