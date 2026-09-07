package envschema_test

import (
	"errors"
	"github.com/depthbomb/envschema"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestProcessSourceSnapshot(t *testing.T) {
	const name = "ENVSCHEMA_TEST_SNAPSHOT"
	t.Setenv(name, "before=change")
	source := envschema.ProcessSource()
	t.Setenv(name, "after")
	value, present := source.Lookup(name)
	if !present || value != "before=change" || source.Origin(name) != "process" {
		t.Fatalf("snapshot = %q, %t, origin = %q", value, present, source.Origin(name))
	}
	names := source.Names()
	if !slices.IsSorted(names) || !slices.Contains(names, name) {
		t.Fatalf("snapshot names are unsorted or missing %s", name)
	}
}

func TestEnvFileSourceErrors(t *testing.T) {
	t.Parallel()

	for _, filename := range []string{".env", ".env.local"} {
		t.Run(filename, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, filename)
			if err := os.WriteFile(path, []byte("INVALID LINE\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := envschema.EnvFileSource(directory, nil); err == nil || !strings.Contains(err.Error(), filename) {
				t.Fatalf("malformed dotenv error = %v", err)
			}

			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}

			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}

			if _, err := envschema.EnvFileSource(directory, nil); err == nil {
				t.Fatal("accepted directory as dotenv file")
			}
		})
	}
}

func TestSourceLoadersRejectNilAndInvalidSchema(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("VALUE", envschema.String()))
	if _, _, err := envschema.LoadWithReport(schema, nil); err == nil || !strings.Contains(err.Error(), "nil source") {
		t.Fatalf("LoadWithReport(nil) error = %v", err)
	}

	if err := envschema.ValidateKnownVariables(schema, nil); err == nil || !strings.Contains(err.Error(), "nil source") {
		t.Fatalf("ValidateKnownVariables(nil) error = %v", err)
	}
	invalid := envschema.Schema{
		Variables: []envschema.Variable{
			envschema.Var("VALUE", envschema.Rule{
				Kind: "invalid",
			}),
		},
	}
	input := envschema.MapSource{}
	if _, _, err := envschema.LoadWithReport(invalid, input); err == nil {
		t.Fatal("LoadWithReport accepted an invalid schema")
	}

	if err := envschema.ValidateKnownVariables(invalid, input); err == nil {
		t.Fatal("ValidateKnownVariables accepted an invalid schema")
	}
}

func TestFileSources(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(filename, []byte(" 123 "), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []envschema.FileConflict{envschema.FileConflictError, envschema.PreferValue, envschema.PreferFile} {
		schema := envschema.Must(envschema.Var("TOKEN", envschema.String().Trimmed().FromFile("TOKEN_FILE", mode)))
		lookup := func(name string) (string, bool) {
			if name == "TOKEN_FILE" {
				return filename, true
			}

			return "456", true
		}
		values, err := envschema.LoadFrom(schema, lookup)
		if mode == envschema.FileConflictError {
			if err == nil {
				t.Fatal("accepted conflicting sources")
			}
			continue
		}
		expected := "456"
		if mode == envschema.PreferFile {
			expected = "123"
		}

		if err != nil || values["TOKEN"] != expected {
			t.Fatalf("%v %v", values, err)
		}
	}
	schema := envschema.Must(envschema.Var("TOKEN", envschema.String().FromFile("TOKEN_FILE", envschema.PreferFile)), envschema.Var("OTHER", envschema.String().Optional())).RequiredTogether("TOKEN", "OTHER")
	if _, err := envschema.LoadFrom(schema, func(name string) (string, bool) { return filename, name == "TOKEN_FILE" }); err == nil {
		t.Fatal("file source omitted from presence constraint")
	}
}

func TestSourceReport(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("A=file\nB=file\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(directory, ".env.local"), []byte("A=local\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := envschema.EnvFileSource(directory, envschema.MapSource{
		Values: map[string]string{
			"OLD": "secret",
			"B":   "process",
		},
		Label: "process",
	})
	if err != nil {
		t.Fatal(err)
	}
	schema := envschema.Must(envschema.Var("A", envschema.String()), envschema.Var("B", envschema.String()), envschema.Var("C", envschema.Secret()).FallbackTo("OLD").Deprecated("use TOKEN"), envschema.Var("D", envschema.Int().DefaultTo(3)))
	values, report, err := envschema.LoadWithReport(schema, source)
	if err != nil || values["A"] != "local" || report.Origins["A"].Source != ".env.local" || report.Origins["B"].Source != "process" || !report.Origins["D"].Default || len(report.Notices) != 2 {
		t.Fatalf("%v %#v %v", values, report, err)
	}
}

func TestUnknownVariables(t *testing.T) {
	schema := envschema.Must(envschema.Var("APP_TIMEOUT", envschema.Int()).FallbackTo("APP_OLD"))
	source := envschema.MapSource{
		Values: map[string]string{
			"APP_OLD": "3",
			"PATH":    "other",
		},
	}
	if _, err := envschema.LoadSource(schema, source, "APP_"); err != nil {
		t.Fatal(err)
	}
	source.Values["APP_TIMOUT"] = "4"
	if _, err := envschema.LoadSource(schema, source, "APP_"); err == nil {
		t.Fatal("accepted typo")
	}
}

func TestSchemaDocumentation(t *testing.T) {
	schema := envschema.Must(envschema.Var("PORT", envschema.Port().DefaultTo(8080)).DescribedAs("HTTP | port"), envschema.Var("TOKEN", envschema.String().DefaultTo("do-not-leak").Sensitive()))
	example, err := envschema.Example(schema)
	if err != nil || strings.Contains(example, "do-not-leak") || !strings.Contains(example, "PORT=") {
		t.Fatalf("%s %v", example, err)
	}
	documentation, err := envschema.Documentation(schema)
	if err != nil || strings.Contains(documentation, "do-not-leak") || !strings.Contains(documentation, "[redacted]") {
		t.Fatalf("%s %v", documentation, err)
	}
}

func TestFileSnapshotAndAbsentFallbackReport(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(filename, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	schema := envschema.Must(envschema.Var("A", envschema.String().FromFile("A_FILE", envschema.PreferFile)), envschema.Var("B", envschema.String())).EqualValues("A", "B")
	calls := 0
	_, err := envschema.LoadFrom(schema, func(name string) (string, bool) {
		if name == "A_FILE" {
			calls++

			return filename, true
		}

		if name == "B" {
			if err := os.WriteFile(filename, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}

			return "initial", true
		}

		return "", false
	})
	if err != nil || calls != 1 {
		t.Fatalf("file resolved %d times: %v", calls, err)
	}
	optional := envschema.Must(envschema.Var("OPTIONAL", envschema.String().Optional()).FallbackTo("A"), envschema.Var("A", envschema.String().FromFile("A_FILE", envschema.PreferFile)))
	source := envschema.MapSource{
		Values: map[string]string{
			"A_FILE": filename,
		},
	}
	direct, err := envschema.LoadFrom(optional, source.Lookup)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := direct["OPTIONAL"]; exists {
		t.Fatal("file source changed fallback lookup")
	}
	values, report, err := envschema.LoadWithReport(optional, source)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := values["OPTIONAL"]; exists {
		t.Fatalf("absent fallback populated: %v %+v", values, report)
	}
}

func TestReportAggregatesSourceFailures(t *testing.T) {
	schema := envschema.Must(envschema.Var("A", envschema.String().FromFile("A_FILE", envschema.PreferFile)), envschema.Var("B", envschema.Int()))
	_, _, err := envschema.LoadWithReport(schema, envschema.MapSource{
		Values: map[string]string{
			"A_FILE": filepath.Join(t.TempDir(), "missing"),
			"B":      "bad",
		},
	})
	var failures *envschema.ValidationErrors
	if !errors.As(err, &failures) || len(failures.Issues) != 2 || failures.Issues[0].Code != "source" {
		t.Fatalf("%v", err)
	}
}

func TestReportSourceFailurePreservesUnrelatedConstraints(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("TOKEN", envschema.String().FromFile("TOKEN_FILE", envschema.PreferFile)),
		envschema.Var("OTHER", envschema.String().Optional()),
		envschema.Var("LEFT", envschema.Int()),
		envschema.Var("RIGHT", envschema.Int()),
	).RequiredTogether("OTHER", "TOKEN").EqualValues("LEFT", "RIGHT")
	input := envschema.MapSource{
		Values: map[string]string{
			"TOKEN_FILE": filepath.Join(t.TempDir(), "missing"),
			"LEFT":       "1",
			"RIGHT":      "2",
		},
		Label: "test",
	}
	if err := envschema.ValidateKnownVariables(schema, input, ""); err != nil {
		t.Fatalf("companion file name rejected: %v", err)
	}
	_, report, err := envschema.LoadWithReport(schema, input)
	var failures *envschema.ValidationErrors
	if !errors.As(err, &failures) || len(failures.Issues) != 2 || failures.Issues[0].Code != "source" || !strings.Contains(failures.Issues[1].Error(), "equal") {
		t.Fatalf("source and unrelated constraint errors = %v", err)
	}

	if report.Origins["LEFT"].Source != "test" || report.Origins["RIGHT"].Source != "test" {
		t.Fatalf("unrelated origins missing: %+v", report)
	}
	input.Values["RIGHT"] = "1"
	_, _, err = envschema.LoadWithReport(schema, input)
	if !errors.As(err, &failures) || len(failures.Issues) != 1 || failures.Issues[0].Path != "TOKEN" {
		t.Fatalf("constraint involving failed source was not skipped: %v", err)
	}
}

func TestExampleRoundTrip(t *testing.T) {
	schema := envschema.Must(envschema.Var("URL", envschema.URL().DefaultTo("https://host?a=1&b=2")), envschema.Var("MAP", envschema.Map(envschema.String(), envschema.Int()).DefaultTo(map[string]any{"a": 1})))
	example, err := envschema.Example(schema)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte(example), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := envschema.EnvFileSource(directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	values, err := envschema.LoadSource(schema, source)
	if err != nil || values["URL"] != "https://host?a=1&b=2" {
		t.Fatalf("%s: %v %v", example, values, err)
	}
}
