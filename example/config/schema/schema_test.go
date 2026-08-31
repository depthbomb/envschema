package schema

import "testing"

func TestEnvironmentSchemaAndLogLevel(t *testing.T) {
	t.Parallel()

	definition := (Environment{}).EnvSchema()
	if len(definition.Variables) != 7 {
		t.Fatalf("schema variables = %d", len(definition.Variables))
	}

	var level LogLevel
	if err := level.UnmarshalText([]byte("debug")); err != nil || level != "debug" {
		t.Fatalf("UnmarshalText(debug) = %q, %v", level, err)
	}
	if err := level.UnmarshalText([]byte("invalid")); err == nil {
		t.Fatal("UnmarshalText(invalid) error = nil")
	}
}
