package envschema_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

var benchmarkValues envschema.Values

var benchmarkSchemaJSON string

func init() {
	schema, _ := benchmarkSchema(10)
	encoded, _ := json.Marshal(schema)
	benchmarkSchemaJSON = string(encoded)
}

func benchmarkDefinition(size int) envschema.Schema {
	variables := make([]envschema.Variable, 0, size)
	for index := range size {
		name := fmt.Sprintf("VALUE_%03d", index)
		switch index % 5 {
		case 0:
			variables = append(variables, envschema.Var(name, envschema.String().Trimmed()))
		case 1:
			variables = append(variables, envschema.Var(name, envschema.Int().AtLeast(0)))
		case 2:
			variables = append(variables, envschema.Var(name, envschema.Boolean()))
		case 3:
			variables = append(variables, envschema.Var(name, envschema.Duration()))
		case 4:
			variables = append(variables, envschema.Var(name, envschema.List(envschema.String())))
		}
	}

	return envschema.Must(variables...)
}

func benchmarkSchema(size int) (envschema.Schema, map[string]string) {
	schema := benchmarkDefinition(size)
	values := make(map[string]string, size)
	for index := range size {
		name := fmt.Sprintf("VALUE_%03d", index)
		switch index % 5 {
		case 0:
			values[name] = " value "
		case 1:
			values[name] = strconv.Itoa(index)
		case 2:
			values[name] = "true"
		case 3:
			values[name] = "1m30s"
		case 4:
			values[name] = "one,two,three"
		}
	}

	return schema, values
}

func benchmarkLoadFrom(b *testing.B, size int) {
	schema, raw := benchmarkSchema(size)
	lookup := func(name string) (string, bool) {
		value, ok := raw[name]

		return value, ok
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		values, err := envschema.LoadFrom(schema, lookup)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkValues = values
	}
}

func BenchmarkLoadFrom10(b *testing.B) {
	benchmarkLoadFrom(b, 10)
}

func BenchmarkLoadFrom100(b *testing.B) {
	benchmarkLoadFrom(b, 100)
}

func BenchmarkSchemaInitializationJSON(b *testing.B) {
	for range b.N {
		_ = envschema.MustSchemaJSON(benchmarkSchemaJSON)
	}
}

func BenchmarkSchemaInitializationNative(b *testing.B) {
	for range b.N {
		_ = benchmarkDefinition(10)
	}
}

func BenchmarkAdvancedLoadFrom(b *testing.B) {
	schema := envschema.Must(
		envschema.Var("TEXT", envschema.String().Matching(`^[a-z0-9_-]+$`).WithMinLength(3)),
		envschema.Var("URL", envschema.URL().HTTPSOnly().WithoutCredentials().WithoutQuery()),
		envschema.Var("CIDR", envschema.CIDR().IPVersionIs(envschema.IPv4)),
		envschema.Var("ENDPOINT", envschema.Endpoint()),
		envschema.Var("COUNT", envschema.Uint().GreaterThan(0).MultipleOf(4)),
		envschema.Var("TIMEOUT", envschema.Duration().AtLeastDuration(time.Second).AtMostDuration(time.Minute)),
		envschema.Var("LABELS", envschema.Map(envschema.String(), envschema.Int()).AtLeastItems(2)),
		envschema.Var("HOSTS", envschema.List(envschema.Host()).AtLeastItems(2).UniqueItems()),
	).AtLeastOneOf("TEXT", "URL")
	raw := map[string]string{
		"TEXT": "api_worker", "URL": "https://example.com/path", "CIDR": "10.0.0.0/8",
		"ENDPOINT": "example.com:443", "COUNT": "8", "TIMEOUT": "5s",
		"LABELS": "workers=4,retries=2", "HOSTS": "api.example.com,db.example.com",
	}
	lookup := func(name string) (string, bool) {
		value, ok := raw[name]

		return value, ok
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		values, err := envschema.LoadFrom(schema, lookup)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkValues = values
	}
}

func BenchmarkPolicyRichLoadFrom(b *testing.B) {
	schema := envschema.Must(
		envschema.Var("TEXT", envschema.String().Containing("worker").WithoutControlCharacters().SingleLine()),
		envschema.Var("JSON", envschema.JSON().ObjectOnly().RequiredKeys("name").AllowedKeys("name", "count").AtMostDepth(3).UniqueObjectKeys()),
		envschema.Var("LIST", envschema.List(envschema.String()).RejectEmptyItems().CaseInsensitiveUniqueItems().AtLeastDistinctItems(3).Sorted()),
		envschema.Var("URI", envschema.URI().RequireHost().WithHosts("api.example.com").RequirePath().WithoutUserPassword()),
		envschema.Var("IP", envschema.IPAddress().PrivateOnly().WithoutLoopback()),
		envschema.Var("CIDR", envschema.CIDR().CanonicalOnly().PrefixLengthBetween(8, 24).ContainingAddresses("10.1.2.3")),
		envschema.Var("ENDPOINT", envschema.Endpoint().HostnameOnly().ValidateHostname().NonZeroPort().PortBetween(1024, 65535)),
		envschema.Var("UUID", envschema.UUID().Versions(envschema.UUIDv4, envschema.UUIDv7).NonNil().RFC9562VariantOnly()),
		envschema.Var("VERSION", envschema.SemVer().WithoutPrerelease().AtLeastVersion("1.0.0").LessThanVersion("3.0.0")),
		envschema.Var("DATA", envschema.Base64().ExactlyDecodedBytes(4)),
		envschema.Var("TIME", envschema.Timestamp().RequireOffset().WithoutFractionalSeconds().Precision(time.Second)),
		envschema.Var("BIG", envschema.BigInt().PositiveOnly()),
		envschema.Var("DECIMAL", envschema.Decimal().PositiveOnly()),
		envschema.Var("MEDIA", envschema.MediaType().RequireMediaTypeParameters()),
		envschema.Var("MAC", envschema.MACAddress()),
	).LessThanVariable("BIG", "DECIMAL")
	raw := map[string]string{
		"TEXT": "api_worker", "JSON": `{"name":"api","count":3}`, "LIST": "alpha,beta,gamma",
		"URI": "https://api.example.com/v1", "IP": "10.1.2.3", "CIDR": "10.0.0.0/8",
		"ENDPOINT": "api.example.com:8443", "UUID": "550e8400-e29b-41d4-a716-446655440000",
		"VERSION": "2.1.0", "DATA": "dGVzdA==", "TIME": "2026-08-30T12:00:00-05:00",
		"BIG": "100000000000000000000", "DECIMAL": "100000000000000000000.5",
		"MEDIA": "application/json; charset=utf-8", "MAC": "02:00:5e:10:00:00",
	}
	lookup := func(name string) (string, bool) {
		value, ok := raw[name]

		return value, ok
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		values, err := envschema.LoadFrom(schema, lookup)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkValues = values
	}
}
func BenchmarkConstraints(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			variables := make([]envschema.Variable, size)
			constraints := make([]envschema.Constraint, size-1)
			for index := range size {
				variables[index] = envschema.Var(fmt.Sprintf("V%d", index), envschema.String())
				if index > 0 {
					constraints[index-1] = envschema.Constraint{
						Kind:  envschema.ConstraintRequiredTogether,
						Names: []string{"V0", variables[index].Name},
					}
				}
			}
			schema := envschema.Schema{
				Variables:   variables,
				Constraints: constraints,
			}
			encoded, err := json.Marshal(schema)
			if err != nil {
				b.Fatal(err)
			}
			schema = envschema.MustSchemaJSON(string(encoded))
			lookup := func(string) (string, bool) {
				return "x", true
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := envschema.LoadFrom(schema, lookup); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
