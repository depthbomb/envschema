package envschema_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/depthbomb/envschema"
)

func TestSecretValueRedactsEveryFormattingVerb(t *testing.T) {
	t.Parallel()

	values, err := envschema.LoadFrom(envschema.Must(
		envschema.Var("TOKEN", envschema.Secret()),
	), lookup(map[string]string{"TOKEN": "release-secret"}))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := envschema.ValueAs[envschema.SecretValue](values, "TOKEN")
	if err != nil {
		t.Fatal(err)
	}

	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}
	for _, format := range formats {
		formatted := fmt.Sprintf(format, secret)
		if strings.Contains(formatted, "release-secret") {
			t.Fatalf("format %q exposed the secret: %s", format, formatted)
		}
		if !strings.Contains(formatted, "[redacted]") {
			t.Fatalf("format %q = %q, want redaction marker", format, formatted)
		}
	}
	if got := fmt.Sprintf("%#v", secret); got != "[redacted]" {
		t.Fatalf("Go-syntax formatting = %q", got)
	}
}

func TestConditionalConstraintsUseNormalizedValues(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("MODE", envschema.OneOf("local", "remote").CaseInsensitive()),
		envschema.Var("TOKEN", envschema.String().Optional()),
	).RequiredWhen("MODE", "remote", "TOKEN")

	_, err := envschema.LoadFrom(schema, lookup(map[string]string{"MODE": "REMOTE"}))
	if err == nil || !strings.Contains(err.Error(), "TOKEN is required") {
		t.Fatalf("LoadFrom() error = %v, want normalized conditional constraint failure", err)
	}
}

func TestMapDefaultRejectsCanonicalKeyCollisions(t *testing.T) {
	t.Parallel()

	key := envschema.OneOf("primary", "secondary").CaseInsensitive().Alias("main", "primary")
	rule := envschema.Map(key, envschema.Int()).DefaultTo(map[string]int{
		"PRIMARY": 1,
		"main":    2,
	})

	_, err := envschema.New(envschema.Var("ROUTES", rule))
	if err == nil || !strings.Contains(err.Error(), `duplicate map key "primary"`) {
		t.Fatalf("New() error = %v, want canonical key collision", err)
	}
}
