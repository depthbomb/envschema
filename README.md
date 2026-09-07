# envschema

`envschema` lets you describe the environment variables your app needs, validate them, and generate a concrete Go
configuration type. It brings the schema model from `@depthbomb/env` to Go: variables are required by default,
defaults get validated too, collections validate their items recursively, and secrets redact themselves.

## Define and generate

Start with an exported provider in its own schema package. Put it in a child package to avoid an import cycle with
the generated parent package:

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

Add the generator as a module tool:

```shell
go get -tool github.com/depthbomb/envschema/cmd/envschema@latest
```

Run the generator to find your exported `envschema.Provider`, compile and run it in a temporary loader, validate the
result, and generate the parent package:

```shell
go tool envschema generate ./schema
```

To hook this into the Go toolchain, add a directive to the generated package:

```go
// Package config loads the application's environment configuration.
//
//go:generate go tool envschema generate ./schema
package config
```

After that, just run:

```shell
go generate
```

You get ordinary typed Go code:

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

`Load()` looks for these files next to the running binary, in this order. Values in `.env.local` override those in
`.env`:

```text
.env
.env.local
```

Existing process environment variables override both files. Missing files are fine, but loading fails if a file is
malformed or can't be read. Keep `.env.local` out of version control.

If the automatic field name isn't what you want, use `envschema.Named("LEGACY_NAME", "PreferredName", rule)`.
For tests, `LoadFrom` accepts an `envschema.LookupFunc` so you don't have to change the global process environment.

Fallback names let you migrate environment variables without breaking existing setups:

```go
envschema.Var("DATABASE_URL", envschema.URL()).FallbackTo("LEGACY_DATABASE_URL")
```

See [example/config/schema/schema.go](example/config/schema/schema.go) and its checked-in [generated output](example/config/config_gen.go) for a complete example.

You can customize the command with `-name`, `-target`, `-output`, `-package`, and `-type`. If your package has more than
one provider, pick one with `-name`. You can also use the `generate` package to build your own tooling.

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

Every rule is required unless you add `.Optional()`. Optional rules without defaults generate pointers. If an optional
rule has a default, it gets the normal non-pointer type, since a value will always be available after loading.

Chain modifiers to build up a rule from left to right. Each modifier returns a copy, so you can safely reuse a base
rule elsewhere:

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

Less common modifiers live in `Rule.Policies`, which also leaves room for future options. The public `WithPolicy`
method lets generated schemas and JSON definitions keep those options intact. Schema validation still rejects policy
metadata that's unknown, malformed, or doesn't apply to the rule.

You can configure rules with functional options or chained modifiers. Defaults accept the same representations as
environment values, and code generation preserves typed `time.Duration` and `time.Time` defaults.

Duration parsing uses [`github.com/depthbomb/duration`](https://github.com/depthbomb/duration), so you can write compound, human-readable values like
`1 day 3h 15m`. A number on its own means milliseconds.

### Cross-variable contracts

Chain constraints after `Must` to add checks across variables. Both dynamic and generated loaders enforce them:

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

For presence checks, you also have `AtLeastOneOf`, `AtMostOneOf`/`MutuallyExclusive`, `RequiredUnless`, and `RequiredIfPresent`.
To compare values, use `EqualValues`, `DifferentValues`, or `LessThanVariable`; these checks run when both values are
present. `TLSKeyPair` checks that a certificate's public key matches its private key. Defaults count as present.
Building the schema also validates the constraint declarations and the variables they refer to.

### Custom domain types

You can generate fields with your own named types, as long as a pointer to the type implements `encoding.TextUnmarshaler`:

```go
type LogLevel string

func (level *LogLevel) UnmarshalText(text []byte) error {
	// Validate and assign level.
	return nil
}

envschema.Var("LOG_LEVEL", envschema.Custom[LogLevel]())
```

The generated field is a `LogLevel`. Custom rules work only on top-level variables, keeping the generated parsing
static and type safe.

## Composing configuration contracts

Use conditional validation to add a rule when another variable's parsed value matches. The extra rule must keep
the target's kind, and it can't add defaults or change where the value comes from:

```go
schema.ValidateWhen("MODE", "production", "PUBLIC_URL", envschema.URL().HTTPSOnly())
schema.MemberOf("DEFAULT_REGION", "ENABLED_REGIONS")
schema.SubsetOf("ACTIVE_REGIONS", "ENABLED_REGIONS")
schema.DisjointWith("ALLOWED_HOSTS", "BLOCKED_HOSTS")
```

These relationships compare parsed values: items for lists and arrays, keys for maps. They run when both variables
are present. Add presence constraints too if both variables need to be present.

Use `Object` to validate JSON properties recursively and generate a concrete struct. Optional fields without
defaults get pointers, and defaults fill in missing values. Unknown properties and duplicate JSON keys are rejected.
Add `AllowUnknownFields` if you want to accept and discard properties that aren't in the schema.

```go
envschema.Var("BACKEND", envschema.Object(
    envschema.Field("endpoint", envschema.URL()),
    envschema.Field("timeout", envschema.Duration().DefaultTo("5s")),
    envschema.Field("retries", envschema.Int().Between(0, 10).Optional()),
))
```

Use `Field(...).Named("GoFieldName")` to choose a generated property name. You can nest objects inside other objects
and collections. Custom domain types still work only at the top level.

Add `Sensitive()` to wrap a rule's result in `Protected[T]` in generated code. Formatting and serialization redact
the value; call `Release()` to get the parsed `T`. Dynamic loaders return `Protected[any]`, which you can convert with
`ValueAs[Protected[T]]`. Validation errors for protected values leave out the underlying parser message.

```go
envschema.Var("DATABASE_URL", envschema.URL().WithSchemes("postgres").Sensitive())
envschema.Var("TOKEN", envschema.Base64().ExactlyDecodedBytes(32).Sensitive())
```

Groups let you reuse a schema with a prefix on its primary names, fallbacks, companion file names, and constraint
references. The generated fields are nested, so you can access them as `config.Primary.Port`, for example:

```go
database := envschema.Must(
    envschema.Var("HOST", envschema.Host()),
    envschema.Var("PORT", envschema.Port().DefaultTo(5432)),
)
schema := envschema.Must().WithGroup("Primary", "PRIMARY_DB_", database).WithGroup("Replica", "REPLICA_DB_", database)
```

Here are a few more checks for numbers, collections, and query parameters:

```go
envschema.Uint().AtMostUint64(18446744073709551614)
envschema.Int().AtLeastInt64(-9223372036854775807)
envschema.BigInt().AtLeastDecimal("100000000000000000000")
envschema.Decimal().AtMostDecimal("999.99").MultipleOfDecimal("0.01").WithPrecision(5).WithScale(2)
envschema.Map(envschema.String(), envschema.Int()).RequiredKeys("primary").AllowedKeys("primary", "replica").UniqueKeys()
envschema.List(envschema.CIDR()).NonOverlapping().SubnetsOf("10.0.0.0/8")
envschema.URL().QueryParameter("timeout", envschema.Int().Between(1, 60))
```

For exact bounds and multiples, you can pass decimal or rational text. Precision and scale use the shortest exact
fixed-point representation, ignoring leading zeros and trailing zeros in the fractional part. Zero has precision one.
Non-terminating rational values fail precision and scale checks. Maps reject duplicate normalized keys even if you
don't add `UniqueKeys()`.

Scalar query parameters must occur once. Use an `Array` query rule for repeated parameters. Parameter defaults are
checked during validation, but they don't rewrite the URL or add query values.

## Sources and diagnostics

Use `FromFile` to read a file whose path comes from a companion variable. Choose `FileConflictError`, `PreferValue`,
or `PreferFile` to handle cases where both sources are set. File contents are kept as-is; add `Trimmed()` to text
rules if you want to trim whitespace.

```go
envschema.Var("API_TOKEN", envschema.String().Trimmed().Sensitive().FromFile("API_TOKEN_FILE", envschema.FileConflictError))
envschema.Var("DEPLOYMENT_ID", envschema.String().DefaultTo("development").ExplicitInput())
```

Add `ExplicitInput()` when a value must be supplied, even if the rule has a default. Fallback and file sources count;
empty values that the rule doesn't allow do not. File sources and explicit-input requirements work on top-level
variables only.

`EnvFileSource(directory, ProcessSource())` reads `.env`, then `.env.local`, with process values taking precedence.
For tests, `MapSource{Values: values, Label: "test"}` gives you a source whose names you can enumerate.

- `LoadWithReport(schema, source)` returns values, an origin report, and an error. The report tells you which names,
  source labels, defaults, and file sources were used, without recording values or file contents.
- Using a fallback produces a migration notice. Add `Var(...).Deprecated("migration guidance")` for deprecation notices.
- `LoadSource(schema, source, "MYAPP_")` catches undeclared variables under the prefixes you supply. It recognizes
  primary names, fallbacks, and companion file names. Without prefixes, unrelated variables are allowed.
- Generated packages give you typed `LoadSource` and `LoadWithReport` functions too.

File contents are read once per load, before constraints run. If loading fails, independent errors are collected
together. Use `errors.As` with `*envschema.ValidationErrors` to inspect `Issues`. Each `ValidationError` has a `Code`,
a `Path` like `BACKENDS[1].timeout`, and a cause. Codes include `required`, `explicit_input`, `source`, `invalid`,
`unknown`, and `constraint`. Constraints that depend on invalid values are skipped, and a failed load won't return
a partial configuration.

## Configuration tooling

Give variables a description with `Var(...).DescribedAs("description")`.

```shell
go tool envschema check -directory . -prefix MYAPP_ ./schema
go tool envschema example ./schema
go tool envschema describe ./schema
```

`check` compiles and runs a temporary generated loader, including custom domain validation, so you'll need the Go
toolchain. It reads dotenv files from `-directory` (the current directory by default), with process values taking precedence.
`example` prints dotenv defaults and commented placeholders, while `describe` prints a Markdown table. Both leave out
secret defaults, including defaults with nested secrets. Output goes to standard output, so you can redirect it wherever
you need it. Use `-name` with any of the three commands to pick a provider.

## Validation

```shell
go test ./...
go generate ./example/config
go test ./...
```

Generated files include the validated schema that produced them, so your app doesn't need to keep or run the generator
source at runtime. If an option doesn't apply to a rule, schema validation rejects it instead of silently ignoring it.

See [PERFORMANCE.md](PERFORMANCE.md) for how the benchmarks are run, the current reference results, and commands to reproduce them.
