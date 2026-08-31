package envschema_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

func lookup(values map[string]string) envschema.LookupFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]

		return value, ok
	}
}

func TestLoadFromParsesTypedValues(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("NAME", envschema.String(envschema.Trim, envschema.MinLength(2))),
		envschema.Var("COUNT", envschema.Int(envschema.Min(1))),
		envschema.Var("RATIO", envschema.Float()),
		envschema.Var("ENABLED", envschema.Boolean()),
		envschema.Var("MODE", envschema.Enum([]string{"dev", "prod"})),
		envschema.Var("TIMEOUT", envschema.Duration(envschema.Max(60_000))),
		envschema.Var("LIMIT", envschema.Bytes()),
		envschema.Var("STARTED", envschema.Date(
			envschema.MinDate("2026-01-01"),
			envschema.MaxDate("2026-12-31T23:59:59Z"),
		)),
		envschema.Var("PORT", envschema.Port()),
		envschema.Var("TAGS", envschema.List(envschema.String(), envschema.Unique)),
		envschema.Var("NUMBERS", envschema.Array(envschema.Int())),
		envschema.Var("PAYLOAD", envschema.JSON()),
		envschema.Var("TOKEN", envschema.Secret()),
	)
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"NAME":    "  api  ",
		"COUNT":   "3",
		"RATIO":   "1.25",
		"ENABLED": "yes",
		"MODE":    "prod",
		"TIMEOUT": "1 second and 500ms",
		"LIMIT":   "1.5GiB",
		"STARTED": "2026-08-29T12:30:00Z",
		"PORT":    "8080",
		"TAGS":    "go, config",
		"NUMBERS": `[1, "2", 3]`,
		"PAYLOAD": `{"ok":true}`,
		"TOKEN":   "do-not-print",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	assertValue(t, values, "NAME", "api")
	assertValue(t, values, "COUNT", int64(3))
	assertValue(t, values, "RATIO", 1.25)
	assertValue(t, values, "ENABLED", true)
	assertValue(t, values, "MODE", "prod")
	assertValue(t, values, "TIMEOUT", 1500*time.Millisecond)
	assertValue(t, values, "LIMIT", int64(1_610_612_736))
	assertValue(t, values, "PORT", int64(8080))

	tags, err := envschema.ValueAs[[]string](values, "TAGS")
	if err != nil {
		t.Fatalf("ValueAs[[]string]() error = %v", err)
	}
	if fmt.Sprint(tags) != "[go config]" {
		t.Fatalf("tags = %v", tags)
	}

	numbers, err := envschema.ValueAs[[]int64](values, "NUMBERS")
	if err != nil {
		t.Fatalf("ValueAs[[]int64]() error = %v", err)
	}
	if fmt.Sprint(numbers) != "[1 2 3]" {
		t.Fatalf("numbers = %v", numbers)
	}

	secret, err := envschema.ValueAs[envschema.SecretValue](values, "TOKEN")
	if err != nil {
		t.Fatalf("ValueAs[SecretValue]() error = %v", err)
	}
	if secret.String() != "[redacted]" || secret.Release() != "do-not-print" {
		t.Fatalf("secret redaction or release failed")
	}
	encoded, _ := json.Marshal(secret)
	if string(encoded) != `"[redacted]"` {
		t.Fatalf("json.Marshal(secret) = %s", encoded)
	}
}

func TestLoadFromParsesPlainStringList(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("VALUES", envschema.List(envschema.String())))
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{"VALUES": " one, two , "}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	parsed, err := envschema.ValueAs[[]string](values, "VALUES")
	if err != nil {
		t.Fatalf("ValueAs[[]string]() error = %v", err)
	}
	expected := []string{"one", "two", ""}
	if !reflect.DeepEqual(parsed, expected) {
		t.Fatalf("ValueAs[[]string]() = %#v, want %#v", parsed, expected)
	}
}

func TestOptionalAndDefaultSemantics(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("OPTIONAL", envschema.String(envschema.Optional)),
		envschema.Var("DEFAULTED", envschema.Int(envschema.Optional, envschema.Default(42))),
	)
	values, err := envschema.LoadFrom(schema, lookup(nil))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if _, ok := values.Value("OPTIONAL"); ok {
		t.Fatal("optional value unexpectedly exists")
	}
	assertValue(t, values, "DEFAULTED", int64(42))
}

func TestSpecializedStringValidation(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("EMAIL", envschema.Email()),
		envschema.Var("URL", envschema.URL()),
		envschema.Var("HOST", envschema.Host()),
		envschema.Var("UUID", envschema.UUID(envschema.UUIDVersioned(envschema.UUIDv4))),
		envschema.Var("IP", envschema.IPAddress(envschema.IP(envschema.IPv4))),
		envschema.Var("HASH", envschema.Hash(envschema.SHA256)),
		envschema.Var("HEX", envschema.Hex()),
		envschema.Var("VERSION", envschema.SemVer()),
		envschema.Var("ZONE", envschema.TimeZone()),
		envschema.Var("BASE64", envschema.Base64(envschema.Base64Padding(envschema.PaddingRequired))),
	)
	_, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"EMAIL":   "user@example.com",
		"URL":     "https://example.com/path",
		"HOST":    "example.com",
		"UUID":    "217188c7-30e9-4f89-8355-0427832955ea",
		"IP":      "127.0.0.1",
		"HASH":    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"HEX":     "deadBEEF",
		"VERSION": "1.2.3-beta.1",
		"ZONE":    "America/Chicago",
		"BASE64":  "SGVsbG8=",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
}

func TestRequiredValueErrorIncludesName(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("DATABASE_URL", envschema.URL()))
	_, err := envschema.LoadFrom(schema, lookup(nil))
	if err == nil || err.Error() != `environment variable "DATABASE_URL" is required but not defined` {
		t.Fatalf("LoadFrom() error = %v", err)
	}
}

func TestFluentRulesAreImmutable(t *testing.T) {
	t.Parallel()

	base := envschema.Int().AtLeast(1)
	optional := base.Optional().DefaultTo(5)
	if !base.Required || base.HasDefault {
		t.Fatalf("base rule was mutated: %+v", base)
	}
	if optional.Required || !optional.HasDefault {
		t.Fatalf("fluent modifiers were not applied: %+v", optional)
	}
}

func TestURLValidationRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("URL", envschema.URL()))
	for _, value := range []string{"notaurl", "1http://example.com", "https://", "https://bad host"} {
		_, err := envschema.LoadFrom(schema, lookup(map[string]string{"URL": value}))
		if err == nil {
			t.Fatalf("LoadFrom(URL=%q) error = nil", value)
		}
	}
}

func assertValue[T comparable](t *testing.T, values envschema.Values, name string, expected T) {
	t.Helper()

	actual, err := envschema.ValueAs[T](values, name)
	if err != nil {
		t.Fatalf("ValueAs(%s) error = %v", name, err)
	}
	if actual != expected {
		t.Fatalf("ValueAs(%s) = %v, want %v", name, actual, expected)
	}
}
