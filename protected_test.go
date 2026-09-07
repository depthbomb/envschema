package envschema_test

import (
	"encoding/json"
	"fmt"
	"github.com/depthbomb/envschema"
	"strings"
	"testing"
)

type protectedText string

func (value *protectedText) UnmarshalText(text []byte) error {
	*value = protectedText(text)

	return nil
}

func TestProtectedReaderMismatch(t *testing.T) {
	_, _, err := envschema.ReadText[protectedText](envschema.String().Sensitive(), "TOKEN", func(string) (string, bool) {
		return "private-value", true
	})
	if err == nil {
		t.Fatal("unprotected reader accepted a sensitive value")
	}
}

func TestProtectedFormatting(t *testing.T) {
	t.Parallel()

	value, present, err := envschema.Read[envschema.Protected[string]](envschema.String().Sensitive(), "TOKEN", lookup(map[string]string{
		"TOKEN": "private-value",
	}))
	if err != nil || !present || value.Release() != "private-value" {
		t.Fatalf("Read() = %v, %t, %v", value, present, err)
	}
	for _, text := range []string{value.String(), value.GoString(), fmt.Sprintf("%v", value), fmt.Sprintf("%#v", value), fmt.Sprintf("%s", value)} {
		if text != "[redacted]" {
			t.Fatalf("formatting exposed sensitive data: %q", text)
		}
	}
	text, err := value.MarshalText()
	if err != nil || string(text) != "[redacted]" {
		t.Fatalf("MarshalText() = %q, %v", text, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != `"[redacted]"` {
		t.Fatalf("MarshalJSON() = %q, %v", encoded, err)
	}
}

func TestProtectedCustomConversion(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("LEVEL", envschema.Custom[customLevel]().Sensitive()))
	for _, input := range []string{"debug", "private-invalid-value"} {
		values, err := envschema.LoadFrom(schema, lookup(map[string]string{
			"LEVEL": input,
		}))
		if err != nil {
			t.Fatal(err)
		}
		value, err := envschema.ValueAs[envschema.Protected[customLevel]](values, "LEVEL")
		if input == "debug" {
			if err != nil || value.Release() != "debug" {
				t.Fatalf("custom conversion = %v, %v", value, err)
			}
		} else if err == nil || strings.Contains(err.Error(), input) {
			t.Fatalf("custom conversion error = %v", err)
		}
	}
}

func TestProtectedNestedUniqueness(t *testing.T) {
	t.Parallel()

	rule := envschema.Array(envschema.List(envschema.Secret()).Sensitive()).UniqueItems()
	schema := envschema.Must(envschema.Var("TOKENS", rule))
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"TOKENS": `["first,second","third,fourth"]`,
	}))
	if err != nil {
		t.Fatalf("distinct sensitive lists rejected: %v", err)
	}
	items, err := envschema.ValueAs[[]envschema.Protected[[]envschema.SecretValue]](values, "TOKENS")
	if err != nil || len(items) != 2 || items[1].Release()[0].Release() != "third" {
		t.Fatalf("nested conversion = %v, %v", items, err)
	}

	if _, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"TOKENS": `["first,second","first,second"]`,
	})); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate sensitive lists error = %v", err)
	}
}
