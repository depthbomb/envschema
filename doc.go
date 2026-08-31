// Package envschema defines, validates, and loads typed environment contracts.
//
// Schemas are assembled from immutable Rule values. Variables are required unless marked Optional, defaults are
// validated with the same parser used at load time, and cross-variable constraints operate on normalized values.
// Load reads the process environment and binary-adjacent dotenv files; LoadFrom accepts an explicit LookupFunc for
// deterministic tests and alternate sources.
//
// Secret and private-key rules return SecretValue. Its formatting and marshaling methods always emit a redaction
// marker; Release is the only supported way to obtain the underlying text.
//
// The generate subpackage produces a concrete configuration struct and typed loading functions. The module supports Go
// 1.26 and later. API stability details are documented in API.md in the module repository.
package envschema
