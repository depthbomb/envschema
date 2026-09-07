package generate_test

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/depthbomb/envschema"
	"github.com/depthbomb/envschema/generate"
)

func testGeneratedPackage(t *testing.T, schema envschema.Schema, testSource string) {
	t.Helper()
	source, err := generate.Source(schema, generate.Options{
		Package: "config",
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "config_gen.go")
	fixture := filepath.Join(directory, "config_test.go")
	if err := os.WriteFile(filename, source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte(testSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", filename, fixture)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated package failed: %v\n%s\n%s", err, output, source)
	}
}

func TestGeneratedNumericDefaults(t *testing.T) {
	schema := envschema.Must(
		envschema.Var("UINT", envschema.Uint().DefaultTo(uint64(math.MaxUint64))),
		envschema.Var("INT", envschema.Int().DefaultTo(int64(math.MaxInt64))),
		envschema.Var("DURATION", envschema.Duration().DefaultTo(int64(1000))),
		envschema.Var("FLOAT", envschema.Float().DefaultTo(float64(2))),
		envschema.Var("ARRAY", envschema.Array(envschema.Uint()).DefaultTo([]uint64{math.MaxUint64})),
	)
	const fixture = `package config
import (
	"math"
	"testing"
	"time"
)
func TestDefaults(t *testing.T) {
	value, err := LoadFrom(func(string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.Uint != math.MaxUint64 || value.Int != math.MaxInt64 || value.Duration != time.Second || value.Float != 2 || value.Array[0] != math.MaxUint64 {
		t.Fatalf("defaults changed: %+v", value)
	}
}


`
	testGeneratedPackage(t, schema, fixture)
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	testGeneratedPackage(t, envschema.MustSchemaJSON(string(encoded)), fixture)
}

func TestGeneratedEmptySchema(t *testing.T) {
	testGeneratedPackage(t, envschema.Must(), `package config
import "testing"
func TestEmpty(t *testing.T) {
	_, err := LoadFrom(func(string) (string, bool) {
		t.Fatal("empty schema performed a lookup")

		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
}
`)
}

func TestGeneratedConstrainedValues(t *testing.T) {
	schema := envschema.Must(
		envschema.Var("LEFT", envschema.Array(envschema.Int())),
		envschema.Var("RIGHT", envschema.Array(envschema.Int())),
		envschema.Var("TEXT", envschema.String().Optional()).FallbackTo("OLD_TEXT"),
		envschema.Var("PATTERN", envschema.Regexp().Optional()),
		envschema.Var("LABELS", envschema.Map(envschema.String(), envschema.Int()).Optional()),
		envschema.Var("LEVEL", envschema.CustomNamed("github.com/depthbomb/envschema/example/config/schema", "LogLevel").Optional()).FallbackTo("OLD_LEVEL"),
	).EqualValues("LEFT", "RIGHT")
	testGeneratedPackage(t, schema, `package config
import "testing"
func TestConstrainedValues(t *testing.T) {
	values := map[string]string{
		"LEFT": "[1,2]",
		"RIGHT": "[1,2]",
	}
	lookup := func(name string) (string, bool) {
		value, exists := values[name]

		return value, exists
	}
	config, err := LoadFrom(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if config.Text != nil || config.Pattern != nil || config.Labels != nil || config.Level != nil {
		t.Fatalf("absent optionals gained values: %+v", config)
	}
	values["OLD_TEXT"] = "fallback"
	values["OLD_LEVEL"] = "debug"
	values["PATTERN"] = "^ok$"
	values["LABELS"] = "workers=3"
	config, err = LoadFrom(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if *config.Text != "fallback" || *config.Level != "debug" || !config.Pattern.MatchString("ok") || (*config.Labels)["workers"] != 3 {
		t.Fatalf("constrained conversion changed values: %+v", config)
	}
	values["RIGHT"] = "[2,3]"
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("unequal arrays satisfied equality")
	}
	values["RIGHT"] = "[1,2]"
	values["OLD_LEVEL"] = "invalid"
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("custom validation was skipped")
	}
}
`)
}
