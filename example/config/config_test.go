package config

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

var benchmarkConfig Config

func TestGeneratedConfig(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"DATABASE_URL":  "postgres://localhost/app",
		"DEBUG":         "true",
		"ALLOWED_HOSTS": "example.com, api.example.com",
		"API_TOKEN":     "secret",
	}
	config, err := LoadFrom(func(name string) (string, bool) {
		value, ok := values[name]

		return value, ok
	})
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if config.Port != 8080 || config.RequestTimeout != 5*time.Second {
		t.Fatalf("defaults were not applied: %+v", config)
	}
	if config.Debug == nil || !*config.Debug {
		t.Fatalf("Debug = %v", config.Debug)
	}
	if config.ApiToken.String() != "[redacted]" {
		t.Fatalf("ApiToken = %s", config.ApiToken)
	}
	if config.LogLevel != "info" {
		t.Fatalf("LogLevel = %q", config.LogLevel)
	}
}

func TestGeneratedConfigReportsEveryFieldError(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"DATABASE_URL":    "postgres://localhost/app",
		"PORT":            "8080",
		"DEBUG":           "true",
		"REQUEST_TIMEOUT": "5s",
		"ALLOWED_HOSTS":   "example.com",
		"API_TOKEN":       "secret",
		"LOG_LEVEL":       "info",
	}
	invalid := map[string]string{
		"DATABASE_URL":    "invalid",
		"PORT":            "invalid",
		"DEBUG":           "invalid",
		"REQUEST_TIMEOUT": "invalid",
		"ALLOWED_HOSTS":   "bad host",
		"LOG_LEVEL":       "invalid",
	}
	for name, value := range invalid {
		values := make(map[string]string, len(valid))
		for key, validValue := range valid {
			values[key] = validValue
		}
		values[name] = value
		if _, err := LoadFrom(func(key string) (string, bool) {
			result, exists := values[key]

			return result, exists
		}); err == nil {
			t.Fatalf("LoadFrom() accepted invalid %s", name)
		}
	}

	if _, err := LoadFrom(func(name string) (string, bool) {
		if name == "API_TOKEN" {
			return "", false
		}
		value, exists := valid[name]

		return value, exists
	}); err == nil {
		t.Fatal("LoadFrom() accepted a missing API token")
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load() unexpectedly found a complete binary-adjacent environment")
	}
}

func TestGeneratedSourceLoaders(t *testing.T) {
	t.Parallel()

	for _, debug := range []bool{false, true} {
		t.Run("debug="+strconv.FormatBool(debug), func(t *testing.T) {
			input := envschema.MapSource{
				Values: map[string]string{
					"DATABASE_URL":  "postgres://localhost/app",
					"ALLOWED_HOSTS": "example.com,api.example.com",
					"API_TOKEN":     "test-secret",
				},
				Label: "test",
			}
			if debug {
				input.Values["DEBUG"] = "true"
			}
			expected, err := LoadFrom(input.Lookup)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := LoadSource(input, "")
			if err != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("LoadSource() = %+v, %v; want %+v", actual, err, expected)
			}
			actual, report, err := LoadWithReport(input)
			if err != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("LoadWithReport() = %+v, %v; want %+v", actual, err, expected)
			}
			for _, name := range []string{"PORT", "REQUEST_TIMEOUT", "LOG_LEVEL"} {
				if origin := report.Origins[name]; !origin.Default || origin.Source != "default" {
					t.Fatalf("default origin for %s = %+v", name, origin)
				}
			}
			for name := range input.Values {
				if origin := report.Origins[name]; origin.Name != name || origin.Source != "test" || origin.Default {
					t.Fatalf("input origin for %s = %+v", name, origin)
				}
			}
			if _, present := report.Origins["DEBUG"]; present != debug {
				t.Fatalf("DEBUG origin present = %t, want %t", present, debug)
			}
			if len(report.Notices) != 0 {
				t.Fatalf("unexpected notices: %v", report.Notices)
			}

			input.Values["API_TYPO"] = "value"
			if _, err := LoadSource(input, "API_"); err == nil || !strings.Contains(err.Error(), "API_TYPO") {
				t.Fatalf("unknown variable error = %v", err)
			}

			if _, err := LoadSource(input, "DATABASE_"); err != nil {
				t.Fatalf("unrelated variable rejected: %v", err)
			}
		})
	}
}

func TestGeneratedReportErrors(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"PORT", "LOG_LEVEL"} {
		t.Run(name, func(t *testing.T) {
			input := envschema.MapSource{
				Values: map[string]string{
					"DATABASE_URL":  "postgres://localhost/app",
					"ALLOWED_HOSTS": "example.com",
					"API_TOKEN":     "test-secret",
					name:            "invalid",
				},
				Label: "test",
			}
			config, report, err := LoadWithReport(input)
			var failures *envschema.ValidationErrors
			if !errors.As(err, &failures) || len(failures.Issues) != 1 || failures.Issues[0].Path != name {
				t.Fatalf("LoadWithReport() error = %v", err)
			}

			if !reflect.DeepEqual(config, Config{}) || report.Origins[name].Source != "test" {
				t.Fatalf("failed load returned config %+v, report %+v", config, report)
			}
		})
	}
}

func BenchmarkGeneratedLoadFrom(b *testing.B) {
	values := map[string]string{
		"DATABASE_URL":  "postgres://localhost/app",
		"DEBUG":         "true",
		"ALLOWED_HOSTS": "example.com, api.example.com",
		"API_TOKEN":     "secret",
	}
	lookup := func(name string) (string, bool) {
		value, ok := values[name]

		return value, ok
	}

	b.ReportAllocs()
	for range b.N {
		config, err := LoadFrom(lookup)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkConfig = config
	}
}
