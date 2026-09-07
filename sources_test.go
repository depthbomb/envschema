package envschema_test

import (
	"github.com/depthbomb/envschema"
	"os"
	"path/filepath"
	"testing"
)

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
	source, err := envschema.EnvFileSource(directory, envschema.MapSource{Values: map[string]string{"OLD": "secret", "B": "process"}, Label: "process"})
	if err != nil {
		t.Fatal(err)
	}
	schema := envschema.Must(envschema.Var("A", envschema.String()), envschema.Var("B", envschema.String()), envschema.Var("C", envschema.Secret()).FallbackTo("OLD").Deprecated("use TOKEN"), envschema.Var("D", envschema.Int().DefaultTo(3)))
	values, report, err := envschema.LoadWithReport(schema, source)
	if err != nil || values["A"] != "local" || report.Origins["A"].Source != ".env.local" || report.Origins["B"].Source != "process" || !report.Origins["D"].Default || len(report.Notices) != 2 {
		t.Fatalf("%v %#v %v", values, report, err)
	}
}
