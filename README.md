# envschema

`envschema` defines and validates an application's environment contract, then generates a concrete Go configuration
type. It is a Go adaptation of the schema model in `@depthbomb/env`: variables are required by default, defaults are
validated, collections recursively validate their items, and secrets redact themselves.

## Define and generate

Define an exported provider in a dedicated schema package. Keeping the definition in a child package avoids an import
cycle with the generated parent package:

```go
package schema

import (
	"time"

	"github.com/depthbomb/envschema"
)

type Environment struct{}

func (Environment) EnvSchema() envschema.Schema {
	return envschema.Must(
		envschema.Var("DATABASE_URL", envschema.URL()),
		envschema.Var("PORT", envschema.Port().DefaultTo(8080)),
		envschema.Var("DEBUG", envschema.Boolean().Optional()),
		envschema.Var("REQUEST_TIMEOUT", envschema.Duration().DefaultTo(5*time.Second)),
		envschema.Var("ALLOWED_HOSTS", envschema.List(envschema.Host()).UniqueItems()),
		envschema.Var("API_TOKEN", envschema.Secret()),
	)
}
```

Register the generator as a module tool:

```shell
go get -tool github.com/depthbomb/envschema/cmd/envschema@latest
```

The command discovers the exported `envschema.Provider`, compiles and executes it in a temporary loader, validates its
result, and generates the parent package:

```shell
go tool envschema generate ./schema
```

To integrate it with the Go toolchain, add a directive to the generated package:

```go
// Package config loads the application's environment configuration.
//
//go:generate go tool envschema generate ./schema
package config
```

Then normal generation is:

```shell
go generate
```

The resulting API is ordinary typed Go code:

```go
config, err := config.Load()
if err != nil {
	log.Fatal(err)
}

dbURL := config.DatabaseUrl          // string
port := config.Port                  // int64
debug := config.Debug                // *bool: nil when absent
timeout := config.RequestTimeout     // time.Duration
hosts := config.AllowedHosts         // []string
token := config.ApiToken.Release()   // explicit access to the secret
```

`Load()` reads files alongside the running binary in this order, with values in `.env.local` overriding values from
`.env`:

```text
.env
.env.local
```

Existing process environment variables override both files. Missing files are ignored, while malformed or unreadable
files cause loading to fail. `.env.local` should be ignored by version control.

Use `envschema.Named("LEGACY_NAME", "PreferredName", rule)` when automatic environment-name conversion is not suitable.
`LoadFrom` accepts an `envschema.LookupFunc`, which makes tests independent of global process state.

Fallback names support safe environment-variable migrations:

```go
envschema.Var("DATABASE_URL", envschema.URL()).FallbackTo("LEGACY_DATABASE_URL")
```

See [example/config/schema/schema.go](example/config/schema/schema.go) and its checked-in [generated output](example/config/config_gen.go) for a complete example.

The command accepts `-name`, `-target`, `-output`, `-package`, and `-type` overrides. If a package contains multiple
providers, select one with `-name`. The `generate` package remains available for custom tooling.

## Rules and generated types

| Schema rule                                                               | Generated Go type                          | Main options                                                                                                        |
|---------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `String`                                                                  | `string`                                   | trimming, byte/rune length, pattern, prefix/suffix, empty values, casing, ASCII, printable, and whitespace policies |
| `Number`, `Float`                                                         | `float64`                                  | inclusive/exclusive bounds, sign, non-zero, and `MultipleOf`                                                        |
| `BigInt`, `Decimal`                                                       | `big.Int`, `big.Rat`                       | exact arbitrary-precision values, bounds, sign, non-zero, and multiples                                             |
| `Int`, `Bytes`, `Port`                                                    | `int64`                                    | numeric constraints; byte strings accept decimal and IEC units                                                      |
| `Uint`                                                                    | `uint64`                                   | unsigned integer with numeric constraints                                                                           |
| `Boolean`                                                                 | `bool`                                     | friendly spellings by default; `Strict` accepts only true/false                                                     |
| `Enum`, `OneOf`                                                           | `string`                                   | fixed choices, case-insensitive matching, and canonical aliases                                                     |
| `JSON`                                                                    | `json.RawMessage`                          | object/array/scalar restrictions, key allowlists, size/depth limits, and duplicate-key rejection                    |
| `Array`, `List`                                                           | `[]T`                                      | recursive items, CSV, counts, uniqueness, distinctness, ordering, separators, and whitespace control                |
| `Map`                                                                     | `map[K]V`                                  | string/enum keys, typed values, CSV, counts, separators, and empty-key/value rejection                              |
| `Duration`                                                                | `time.Duration`                            | millisecond numeric bounds or typed `AtLeastDuration`/`AtMostDuration` bounds                                       |
| `Date`, `Timestamp`                                                       | `time.Time`                                | date/RFC 3339 parsing, bounds, and UTC-only timestamps                                                              |
| `TimeOfDay`                                                               | `string`                                   | `HH:MM` or `HH:MM:SS`                                                                                               |
| `Path`, `UnixSocket`                                                      | `string`                                   | kind/existence, locality, containment, extension/glob, symlink, and executable policies                             |
| `FileMode`                                                                | `fs.FileMode`                              | octal Unix permission and special-mode bits                                                                         |
| `CIDR`                                                                    | `netip.Prefix`                             | IPv4/IPv6, canonical form, prefix bounds, containment, and contained-address policies                               |
| `Endpoint`                                                                | `string`                                   | host type, hostname validation, IP class, and port-range policies                                                   |
| `Regexp`                                                                  | `*regexp.Regexp`                           | compiled regular expression                                                                                         |
| `PEM`                                                                     | `[]byte`                                   | one validated PEM block                                                                                             |
| `Certificate`, `CertificateBundle`                                        | `*x509.Certificate`, `[]*x509.Certificate` | validity, hostname, CA/leaf, usage, key algorithm, and RSA-size policies                                            |
| `PublicKey`                                                               | `envschema.PublicKeyValue`                 | parsed PKIX/PKCS#1/certificate public key with algorithm and RSA-size policies                                      |
| `PrivateKey`, `Secret`                                                    | `envschema.SecretValue`                    | redacted formatting and JSON; `Release` explicitly reveals the source                                               |
| `Base64`                                                                  | `string`                                   | URL-safe alphabet and padding policy                                                                                |
| `MACAddress`                                                              | `net.HardwareAddr`                         | IEEE MAC-48, EUI-48, EUI-64, and other forms accepted by `net.ParseMAC`                                             |
| `URI`, `URL`, `HTTPURL`                                                   | `string`                                   | absolute/relative form, scheme, host, path, query, credential, and canonical-form policies                          |
| `MediaType`, `ULID`, `Glob`                                               | `string`                                   | MIME media types, canonical ULIDs, and platform filepath glob syntax                                                |
| `Email`, `Host`, `UUID`, `IPAddress`, `Hash`, `Hex`, `SemVer`, `TimeZone` | `string`                                   | format-specific policies                                                                                            |

Every rule is required unless `.Optional()` is used. An optional rule without a default generates a pointer. An optional
rule with a default generates the normal non-pointer type because a value is guaranteed after loading.

Rules use immutable fluent modifiers, so reusable base rules remain safe and schema declarations read from left to
right:

```go
envschema.String().Trimmed().Matching(`^[a-z]+$`)
envschema.Int().Between(1, 10)
envschema.Path().File().Existing()
envschema.Base64().URLSafeEncoding().WithPadding(envschema.PaddingForbidden)
envschema.UUID().UUIDVersionIs(envschema.UUIDv4)
envschema.IPAddress().IPVersionIs(envschema.IPv6)
envschema.Hash(envschema.SHA256)
envschema.URL().HTTPSOnly().WithoutCredentials().RequirePort().WithoutFragment()
envschema.Duration().AtLeastDuration(time.Second).AtMostDuration(time.Minute)
envschema.List(envschema.Host()).AtLeastItems(1).AtMostItems(10).UniqueItems()
envschema.Map(envschema.String(), envschema.Int()).KeyValueSeparatedBy(":")
envschema.JSON().ObjectOnly().RequiredKeys("name").AtMostDepth(8).UniqueObjectKeys()
envschema.Path().LocalOnly().Within("config").WithExtensions(".json", ".yaml")
envschema.URI().RequireHost().WithHosts("api.example.com").WithoutUserPassword()
envschema.IPAddress().PrivateOnly().WithoutLoopback()
envschema.Certificate().CurrentlyValid().ForHostname("api.example.com").ServerAuth()
```

Less common and forward-compatible modifiers are represented in `Rule.Policies`. `WithPolicy` is public so generated
schemas and JSON definitions preserve these options, but schema validation rejects unknown, malformed, or inapplicable
policy metadata.

Rules can be configured with either functional options or fluent modifiers. Defaults use the same representations
accepted from the environment; typed `time.Duration` and `time.Time` defaults are preserved by code generation.

Duration values use [`github.com/depthbomb/duration`](https://github.com/depthbomb/duration), supporting compound and human-readable values such as
`1 day 3h 15m`. A bare number is interpreted as milliseconds.

### Cross-variable contracts

Constraints compose after `Must` and are enforced by both dynamic and generated loaders:

```go
return envschema.Must(
	envschema.Var("API_TOKEN", envschema.Secret().Optional()),
	envschema.Var("USERNAME", envschema.String().Optional()),
	envschema.Var("PASSWORD", envschema.Secret().Optional()),
	envschema.Var("MODE", envschema.OneOf("local", "remote")),
).
	ExactlyOneOf("API_TOKEN", "USERNAME").
	RequiredTogether("USERNAME", "PASSWORD").
	RequiredWhen("MODE", "remote", "API_TOKEN").
	ForbiddenWhen("MODE", "local", "PASSWORD")
```

Presence contracts include `AtLeastOneOf`, `AtMostOneOf`/`MutuallyExclusive`, `RequiredUnless`, and `RequiredIfPresent`.
Value contracts include `EqualValues`, `DifferentValues`, and `LessThanVariable`; they apply when both values are
present. `TLSKeyPair` verifies that a certificate's public key matches its private key. Defaults count as present.
Constraint declarations and references are validated when the schema is built.

### Custom domain types

Named types whose pointer implements `encoding.TextUnmarshaler` can be generated directly:

```go
type LogLevel string

func (level *LogLevel) UnmarshalText(text []byte) error {
	// Validate and assign level.
	return nil
}

envschema.Var("LOG_LEVEL", envschema.Custom[LogLevel]())
```

The generated field has type `LogLevel`. Custom rules are intentionally limited to top-level variables so generated
parsing remains static and type safe.

## Composing configuration contracts

Conditional validation applies an additional rule when another variable's parsed value matches.
It must preserve the target's kind and cannot introduce defaults or change its source:

```go
schema.ValidateWhen("MODE", "production", "PUBLIC_URL", envschema.URL().HTTPSOnly())
schema.MemberOf("DEFAULT_REGION", "ENABLED_REGIONS")
schema.SubsetOf("ACTIVE_REGIONS", "ENABLED_REGIONS")
schema.DisjointWith("ALLOWED_HOSTS", "BLOCKED_HOSTS")
```

Relationships compare parsed values, using list/array items and map keys. They apply when both variables are present.
Combine them with presence constraints when both are mandatory.

`Object` validates JSON properties recursively and generates a concrete struct. Missing optional fields become pointers;
defaults populate fields. Unknown properties and duplicate JSON keys are rejected. `AllowUnknownFields` explicitly
accepts and discards undeclared properties.

```go
envschema.Var("BACKEND", envschema.Object(
    envschema.Field("endpoint", envschema.URL()),
    envschema.Field("timeout", envschema.Duration().DefaultTo("5s")),
    envschema.Field("retries", envschema.Int().Between(0, 10).Optional()),
))
```

Use `Field(...).Named("GoFieldName")` to override a generated property name. Objects can nest inside objects and
collections. Custom domain types retain their top-level restriction.

`Sensitive()` wraps a rule's result in `Protected[T]` in generated code. Formatting and serialization redact it;
`Release()` returns the parsed `T`. Dynamic loaders return `Protected[any]`, convertible with `ValueAs[Protected[T]]`.
Validation errors for protected values omit the underlying parser message.

```go
envschema.Var("DATABASE_URL", envschema.URL().WithSchemes("postgres").Sensitive())
envschema.Var("TOKEN", envschema.Base64().ExactlyDecodedBytes(32).Sensitive())
```

Reusable groups prefix primary names, fallbacks, companion file names, and constraint references. Generated fields
are nested, for example `config.Primary.Port`:

```go
database := envschema.Must(
    envschema.Var("HOST", envschema.Host()),
    envschema.Var("PORT", envschema.Port().DefaultTo(5432)),
)
schema := envschema.Must().WithGroup("Primary", "PRIMARY_DB_", database).WithGroup("Replica", "REPLICA_DB_", database)
```

Additional numeric, collection, and query contracts include:

```go
envschema.Uint().AtMostUint64(18446744073709551614)
envschema.Int().AtLeastInt64(-9223372036854775807)
envschema.BigInt().AtLeastDecimal("100000000000000000000")
envschema.Decimal().AtMostDecimal("999.99").MultipleOfDecimal("0.01").WithPrecision(5).WithScale(2)
envschema.Map(envschema.String(), envschema.Int()).RequiredKeys("primary").AllowedKeys("primary", "replica").UniqueKeys()
envschema.List(envschema.CIDR()).NonOverlapping().SubnetsOf("10.0.0.0/8")
envschema.URL().QueryParameter("timeout", envschema.Int().Between(1, 60))
```

Exact bounds and multiples accept decimal or rational text. Precision and scale use the shortest exact fixed-point
representation, ignoring leading zeros and fractional trailing zeros; zero has precision one. Non-terminating rational
values fail precision and scale constraints. Maps reject duplicate normalized keys even without `UniqueKeys()`.

Scalar query parameters must occur once. An `Array` query rule validates repeated occurrences. Parameter defaults
participate in validation but do not rewrite the URL or insert query values.

## Sources and diagnostics

`FromFile` reads a file named by a companion variable. Choose `FileConflictError`, `PreferValue`, or `PreferFile`.
Contents are preserved; use `Trimmed()` on text rules if desired.

```go
envschema.Var("API_TOKEN", envschema.String().Trimmed().Sensitive().FromFile("API_TOKEN_FILE", envschema.FileConflictError))
envschema.Var("DEPLOYMENT_ID", envschema.String().DefaultTo("development").ExplicitInput())
```

`ExplicitInput()` requires supplied input even when a default exists. Fallback and file sources can satisfy it;
disallowed empty values cannot. File sources and explicit-input requirements belong to top-level variables.

`EnvFileSource(directory, ProcessSource())` reads `.env`, then `.env.local`, with process values taking precedence.
`MapSource{Values: values, Label: "test"}` provides an enumerable source for tests.

- `LoadWithReport(schema, source)` returns values, an origin report, and an error. Reports identify selected names,
  source labels, defaults, and file sources without recording values or file contents.
- Fallback use produces migration notices. `Var(...).Deprecated("migration guidance")` adds deprecation notices.
- `LoadSource(schema, source, "MYAPP_")` rejects undeclared variables within supplied prefixes. Primary names,
  fallbacks, and companion file names are recognized. With no prefixes, unrelated variables are allowed.
- Generated packages expose typed `LoadSource` and `LoadWithReport` functions too.

File contents are resolved once per load before constraints run. Load failures aggregate independent errors:
use `errors.As` with `*envschema.ValidationErrors` to inspect `Issues`. Each `ValidationError` includes a `Code`,
a `Path` such as `BACKENDS[1].timeout`, and a cause. Codes include `required`, `explicit_input`, `source`, `invalid`,
`unknown`, and `constraint`. Constraints depending on invalid values are skipped. No partial configuration is returned
on failure.

## Configuration tooling

Add descriptions with `Var(...).DescribedAs("description")`.

```shell
go tool envschema check -directory . -prefix MYAPP_ ./schema
go tool envschema example ./schema
go tool envschema describe ./schema
```

`check` compiles and executes a temporary generated loader, including custom domain validation. It reads dotenv files
from `-directory` (the current directory by default), with process values taking precedence, and requires the Go toolchain.
`example` prints dotenv defaults and commented placeholders. `describe` prints a Markdown table. Both omit secret defaults,
including defaults containing nested secrets. Output goes to standard output; redirect it to the desired destination.
All three commands accept `-name` to select a provider.

## Validation

```shell
go test ./...
go generate ./example/config
go test ./...
```

Generated files embed the validated schema that produced them, so applications do not need to retain or execute the
generator source at runtime. Options that do not apply to a rule are rejected during schema validation instead of being
silently ignored.

See [PERFORMANCE.md](PERFORMANCE.md) for benchmark methodology, current reference results, and reproducible commands.
