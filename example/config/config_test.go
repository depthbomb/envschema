package config

import (
	"testing"
	"time"
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
