package envschema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var benchmarkEnvLookup LookupFunc

func writeEnvFile(t *testing.T, directory string, name string, contents string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestLookupEnvFilesFromLoadsFilesInOrder(t *testing.T) {
	directory := t.TempDir()

	writeEnvFile(t, directory, ".env", "BASE=base\nFILE_ORDER=env\nORDER=env\n")
	writeEnvFile(t, directory, ".env.local", "LOCAL=local\nFILE_ORDER=local\nORDER=local\n")

	process := func(name string) (string, bool) {
		if name == "ORDER" {
			return "process", true
		}

		return "", false
	}
	lookup, err := lookupEnvFilesFrom(directory, process)
	if err != nil {
		t.Fatalf("lookupEnvFilesFrom() error = %v", err)
	}

	for name, expected := range map[string]string{
		"BASE":       "base",
		"FILE_ORDER": "local",
		"LOCAL":      "local",
		"ORDER":      "process",
	} {
		actual, exists := lookup(name)
		if !exists || actual != expected {
			t.Errorf("lookup(%q) = %q, %v; want %q, true", name, actual, exists, expected)
		}
	}
}

func TestLookupEnvFilesFromIgnoresModeFiles(t *testing.T) {
	directory := t.TempDir()

	writeEnvFile(t, directory, ".env", "VALUE=base\n")
	writeEnvFile(t, directory, ".env.test", "VALUE=test\nMODE_ONLY=set\n")

	lookup, err := lookupEnvFilesFrom(directory, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("lookupEnvFilesFrom() error = %v", err)
	}

	if value, _ := lookup("VALUE"); value != "base" {
		t.Fatalf("lookup(VALUE) = %q, want base", value)
	}
	if _, exists := lookup("MODE_ONLY"); exists {
		t.Fatal("lookup(MODE_ONLY) found a mode-specific value without a mode")
	}
}

func TestLookupEnvFilesFromReportsInvalidFile(t *testing.T) {
	directory := t.TempDir()

	writeEnvFile(t, directory, ".env", "BROKEN='unterminated\n")

	_, err := lookupEnvFilesFrom(directory, func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), ".env") {
		t.Fatalf("lookupEnvFilesFrom() error = %v, want file context", err)
	}
}

func TestParseEnvFileSupportsConventionalSyntax(t *testing.T) {
	contents := []byte("\xef\xbb\xbf# comment\nexport PLAIN = value # comment\nSINGLE='literal # value'\nDOUBLE=\"line\\nquoted\"\nEMPTY=\nURL=https://example.com/#fragment\nMULTILINE='first\nsecond'\n")
	values, err := parseEnvFile(contents)
	if err != nil {
		t.Fatalf("parseEnvFile() error = %v", err)
	}

	expected := map[string]string{
		"PLAIN":     "value",
		"SINGLE":    "literal # value",
		"DOUBLE":    "line\nquoted",
		"EMPTY":     "",
		"URL":       "https://example.com/#fragment",
		"MULTILINE": "first\nsecond",
	}
	for name, expectedValue := range expected {
		if values[name] != expectedValue {
			t.Errorf("parseEnvFile()[%q] = %q, want %q", name, values[name], expectedValue)
		}
	}
}

func BenchmarkLookupEnvFiles(b *testing.B) {
	directory := b.TempDir()
	contents := "DATABASE_URL=https://localhost:5432/app\nPORT=8080\nDEBUG=true\nREQUEST_TIMEOUT=5s\nALLOWED_HOSTS=localhost,example.com\nAPI_TOKEN=secret\nLOG_LEVEL=info\n"
	for _, filename := range []string{".env", ".env.local"} {
		if err := os.WriteFile(filepath.Join(directory, filename), []byte(contents), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	process := func(string) (string, bool) {
		return "", false
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		lookup, err := lookupEnvFilesFrom(directory, process)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkEnvLookup = lookup
	}
}
