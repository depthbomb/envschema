package envschema_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

type objectConfig struct {
	Port    int64         `json:"port,omitempty"`
	Timeout time.Duration `json:"timeout"`
	Label   string
	Missing *bool `json:"missing"`
}

func TestObjectTypedConversion(t *testing.T) {
	t.Parallel()

	rule := envschema.Object(
		envschema.Field("port", envschema.Port()),
		envschema.Field("timeout", envschema.Duration().DefaultTo("2s")),
		envschema.Field("Label", envschema.String()),
		envschema.Field("missing", envschema.Boolean().Optional()),
	)
	schema := envschema.Must(envschema.Var("CONFIG", rule))
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"CONFIG": `{"port":8080,"Label":"service"}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := envschema.ValueAs[objectConfig](values, "CONFIG")
	expected := objectConfig{
		Port:    8080,
		Timeout: 2 * time.Second,
		Label:   "service",
	}
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("ValueAs() = %+v, %v; want %+v", actual, err, expected)
	}

	_, err = envschema.ValueAs[struct {
		Port bool `json:"port"`
	}](values, "CONFIG")
	if err == nil || !strings.Contains(err.Error(), "field port") {
		t.Fatalf("incompatible field error = %v", err)
	}
}

func TestObjectUnknownFields(t *testing.T) {
	t.Parallel()

	strict := envschema.Object(envschema.Field("port", envschema.Port()))
	input := lookup(map[string]string{
		"CONFIG": `{"port":8080,"extra":"discard me"}`,
	})
	_, err := envschema.LoadFrom(envschema.Must(envschema.Var("CONFIG", strict)), input)
	var failures *envschema.ValidationErrors
	if !errors.As(err, &failures) || len(failures.Issues) != 1 || failures.Issues[0].Path != "CONFIG.extra" || failures.Issues[0].Code != "unknown" {
		t.Fatalf("unknown field error = %v", err)
	}
	values, err := envschema.LoadFrom(envschema.Must(envschema.Var("CONFIG", strict.AllowUnknownFields())), input)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]any{
		"port": int64(8080),
	}
	if !reflect.DeepEqual(values["CONFIG"], expected) {
		t.Fatalf("unknown field was not discarded: %v", values["CONFIG"])
	}

	if strict.UnknownFields {
		t.Fatal("AllowUnknownFields mutated the original rule")
	}
}

func TestObjectDefaults(t *testing.T) {
	t.Parallel()

	for _, value := range []any{
		json.RawMessage(`{"port":8080}`),
		map[string]int{
			"port": 8080,
		},
	} {
		rule := envschema.Object(envschema.Field("port", envschema.Port()))
		rule.Default = value
		rule.HasDefault = true
		schema := envschema.Must(envschema.Var("CONFIG", rule))
		values, err := envschema.LoadFrom(schema, lookup(nil))
		if err != nil {
			t.Fatal(err)
		}
		config, err := envschema.ValueAs[objectConfig](values, "CONFIG")
		if err != nil || config.Port != 8080 {
			t.Fatalf("default %T: config = %+v, error = %v", value, config, err)
		}
	}

	for _, value := range []any{make(chan int), map[string]any(nil)} {
		rule := envschema.Object(envschema.Field("port", envschema.Port()))
		rule.Default = value
		rule.HasDefault = true
		if _, err := envschema.New(envschema.Var("CONFIG", rule)); err == nil {
			t.Fatalf("accepted invalid object default %T", value)
		}
	}
}

func TestObjectFieldNames(t *testing.T) {
	t.Parallel()

	field := envschema.Field("http-port", envschema.Port())
	if actual := envschema.ObjectFieldName(field); actual != "HttpPort" {
		t.Fatalf("ObjectFieldName() = %q", actual)
	}
	named := field.Named("HTTPPort")
	if actual := envschema.ObjectFieldName(named); actual != "HTTPPort" || field.GoName != "" {
		t.Fatalf("named field = %q, original = %+v", actual, field)
	}

	if _, err := envschema.New(envschema.Var("CONFIG", envschema.Object(named))); err != nil {
		t.Fatalf("explicit field name rejected: %v", err)
	}
}
