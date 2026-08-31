package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesFromGoPackage(t *testing.T) {
	directory := t.TempDir()
	outputFilename := filepath.Join(directory, "config_gen.go")

	var stderr bytes.Buffer
	arguments := []string{
		"generate",
		"-target", directory,
		"-package", "config",
		"../../example/config/schema",
	}
	if err := run(arguments, &stderr); err != nil {
		t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
	}

	generated, err := os.ReadFile(outputFilename)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Contains(generated, []byte(`envschema.Read[int64](generatedSchema.Variables[1].Rule, "PORT", lookup)`)) {
		t.Fatalf("generated output did not contain typed Port field:\n%s", generated)
	}
}

func TestUsagePackageNameAndRunErrors(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	usage(&output)
	if !strings.Contains(output.String(), "Usage: envschema generate") {
		t.Fatalf("usage output = %q", output.String())
	}
	for input, expected := range map[string]string{
		"config-dir": "configdir",
		"123config":  "config",
		"my_config":  "my_config",
	} {
		if actual := packageName(input); actual != expected {
			t.Fatalf("packageName(%q) = %q, want %q", input, actual, expected)
		}
	}

	tests := [][]string{
		nil,
		{"unknown"},
		{"generate", "-unknown"},
		{"generate"},
		{"generate", "one", "two"},
		{"generate", "./missing-package"},
	}
	for _, arguments := range tests {
		var stderr bytes.Buffer
		if err := run(arguments, &stderr); err == nil {
			t.Fatalf("run(%q) error = nil", arguments)
		}
	}
}

func TestRunUsesDefaultPackageAndAbsoluteOutput(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "settings.go")
	arguments := []string{
		"generate",
		"-target", directory,
		"-output", filename,
		"-type", "Settings",
		"../../example/config/schema",
	}
	var stderr bytes.Buffer
	if err := run(arguments, &stderr); err != nil {
		t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
	}
	generated, err := os.ReadFile(filename)
	if err != nil || !bytes.Contains(generated, []byte("type Settings struct")) {
		t.Fatalf("generated file = %q, %v", generated, err)
	}
}

func TestRunUsesDefaultTarget(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.go")
	arguments := []string{
		"generate",
		"-output", filename,
		"-package", "config",
		"../../example/config/schema",
	}
	var stderr bytes.Buffer
	if err := run(arguments, &stderr); err != nil {
		t.Fatalf("run() error = %v, stderr = %s", err, stderr.String())
	}
}
