package envschema

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Kind identifies the parser and generated Go type for a rule.
type Kind string

// PathKind restricts a path to a file, directory, or either kind.
type PathKind string

// Padding describes the accepted padding form for Base64 input.
type Padding string

// IPVersion selects IPv4 or IPv6 input.
type IPVersion string

// UUIDVersion selects an accepted UUID version.
type UUIDVersion string

// HashAlgorithm identifies the digest algorithm accepted by a hash rule.
type HashAlgorithm string

// ConstraintKind identifies a cross-variable constraint.
type ConstraintKind string

// Constraint is the serializable representation of a cross-variable contract.
type Constraint struct {
	Kind  ConstraintKind `json:"kind"`
	Names []string       `json:"names"`
	Value string         `json:"value,omitempty"`
}

// Rule is the serializable, immutable-by-convention definition of one value.
// Prefer constructors and fluent modifiers over populating its fields directly.
type Rule struct {
	Kind                Kind                `json:"kind"`
	Required            bool                `json:"required"`
	Default             any                 `json:"default,omitempty"`
	HasDefault          bool                `json:"hasDefault,omitempty"`
	Trim                bool                `json:"trim,omitempty"`
	Pattern             string              `json:"pattern,omitempty"`
	MinLength           *int                `json:"minLength,omitempty"`
	MaxLength           *int                `json:"maxLength,omitempty"`
	Min                 *float64            `json:"min,omitempty"`
	Max                 *float64            `json:"max,omitempty"`
	MinDate             string              `json:"minDate,omitempty"`
	MaxDate             string              `json:"maxDate,omitempty"`
	Positive            bool                `json:"positive,omitempty"`
	Negative            bool                `json:"negative,omitempty"`
	Choices             []string            `json:"choices,omitempty"`
	Item                *Rule               `json:"item,omitempty"`
	Separator           string              `json:"separator,omitempty"`
	ListTrim            bool                `json:"listTrim"`
	Unique              bool                `json:"unique,omitempty"`
	PathKind            PathKind            `json:"pathKind,omitempty"`
	Exists              bool                `json:"exists,omitempty"`
	URLSafe             bool                `json:"urlSafe,omitempty"`
	Padding             Padding             `json:"padding,omitempty"`
	IPVersion           IPVersion           `json:"ipVersion,omitempty"`
	UUID                UUIDVersion         `json:"uuidVersion,omitempty"`
	Hash                HashAlgorithm       `json:"hash,omitempty"`
	EmptyAllowed        bool                `json:"allowEmpty,omitempty"`
	MinItems            *int                `json:"minItems,omitempty"`
	MaxItems            *int                `json:"maxItems,omitempty"`
	MinDuration         string              `json:"minDuration,omitempty"`
	MaxDuration         string              `json:"maxDuration,omitempty"`
	ExclusiveMin        *float64            `json:"exclusiveMin,omitempty"`
	ExclusiveMax        *float64            `json:"exclusiveMax,omitempty"`
	Multiple            *float64            `json:"multipleOf,omitempty"`
	RejectZero          bool                `json:"nonZero,omitempty"`
	Schemes             []string            `json:"schemes,omitempty"`
	URLCredentials      *bool               `json:"urlCredentials,omitempty"`
	URLPort             *bool               `json:"urlPort,omitempty"`
	URLQuery            *bool               `json:"urlQuery,omitempty"`
	URLFragment         *bool               `json:"urlFragment,omitempty"`
	Prefix              string              `json:"prefix,omitempty"`
	Suffix              string              `json:"suffix,omitempty"`
	ASCII               bool                `json:"ascii,omitempty"`
	Printable           bool                `json:"printable,omitempty"`
	NoWhitespace        bool                `json:"noWhitespace,omitempty"`
	Lowercase           bool                `json:"lowercase,omitempty"`
	Uppercase           bool                `json:"uppercase,omitempty"`
	EnumCaseInsensitive bool                `json:"caseInsensitive,omitempty"`
	Aliases             map[string]string   `json:"aliases,omitempty"`
	Key                 *Rule               `json:"key,omitempty"`
	KeyValueSeparator   string              `json:"keyValueSeparator,omitempty"`
	Absolute            *bool               `json:"absolute,omitempty"`
	UTC                 bool                `json:"utc,omitempty"`
	StrictBoolean       bool                `json:"strictBoolean,omitempty"`
	RuneLength          bool                `json:"runeLength,omitempty"`
	NoSurroundingSpace  bool                `json:"noSurroundingSpace,omitempty"`
	CustomPackage       string              `json:"customPackage,omitempty"`
	CustomName          string              `json:"customName,omitempty"`
	Policies            map[string][]string `json:"policies,omitempty"`
}

// Variable associates an environment name and optional fallbacks with a rule.
type Variable struct {
	Name      string   `json:"name"`
	GoName    string   `json:"goName,omitempty"`
	Rule      Rule     `json:"rule"`
	Fallbacks []string `json:"fallbacks,omitempty"`
}

// Schema is a validated collection of variables and cross-variable constraints.
type Schema struct {
	Variables   []Variable   `json:"variables"`
	Constraints []Constraint `json:"constraints,omitempty"`
	validated   bool
}

// Provider supplies a schema to the source generator.
type Provider interface {
	EnvSchema() Schema
}

// Option configures a rule during construction.
type Option func(*Rule)

// Supported rule kinds.
const (
	KindString      Kind = "string"
	KindNumber      Kind = "number"
	KindInt         Kind = "int"
	KindFloat       Kind = "float"
	KindBoolean     Kind = "boolean"
	KindEnum        Kind = "enum"
	KindJSON        Kind = "json"
	KindArray       Kind = "array"
	KindList        Kind = "list"
	KindDuration    Kind = "duration"
	KindDate        Kind = "date"
	KindBytes       Kind = "bytes"
	KindPath        Kind = "path"
	KindBase64      Kind = "base64"
	KindSecret      Kind = "secret"
	KindEmail       Kind = "email"
	KindPort        Kind = "port"
	KindURL         Kind = "url"
	KindHost        Kind = "host"
	KindUUID        Kind = "uuid"
	KindIP          Kind = "ipAddress"
	KindHash        Kind = "hash"
	KindHex         Kind = "hexadecimal"
	KindSemVer      Kind = "semver"
	KindTimeZone    Kind = "timezone"
	KindUInt        Kind = "uint"
	KindCIDR        Kind = "cidr"
	KindEndpoint    Kind = "endpoint"
	KindUnixSocket  Kind = "unixSocket"
	KindTimestamp   Kind = "timestamp"
	KindTimeOfDay   Kind = "timeOfDay"
	KindMap         Kind = "map"
	KindRegexp      Kind = "regexp"
	KindPEM         Kind = "pem"
	KindCertificate Kind = "certificate"
	KindPrivateKey  Kind = "privateKey"
	KindCustom      Kind = "custom"
	KindURI         Kind = "uri"
	KindMACAddress  Kind = "macAddress"
	KindPublicKey   Kind = "publicKey"
	KindCertBundle  Kind = "certificateBundle"
	KindBigInt      Kind = "bigInt"
	KindDecimal     Kind = "decimal"
	KindMediaType   Kind = "mediaType"
	KindFileMode    Kind = "fileMode"
	KindULID        Kind = "ulid"
	KindGlob        Kind = "glob"
)

// Supported cross-variable constraint kinds.
const (
	ConstraintExactlyOne        ConstraintKind = "exactlyOne"
	ConstraintAtLeastOne        ConstraintKind = "atLeastOne"
	ConstraintMutuallyExclusive ConstraintKind = "mutuallyExclusive"
	ConstraintRequiredTogether  ConstraintKind = "requiredTogether"
	ConstraintRequiredWhen      ConstraintKind = "requiredWhen"
	ConstraintForbiddenWhen     ConstraintKind = "forbiddenWhen"
	ConstraintRequiredUnless    ConstraintKind = "requiredUnless"
	ConstraintRequiredIfPresent ConstraintKind = "requiredIfPresent"
	ConstraintEqualValues       ConstraintKind = "equalValues"
	ConstraintDifferentValues   ConstraintKind = "differentValues"
	ConstraintLessThanVariable  ConstraintKind = "lessThanVariable"
	ConstraintTLSKeyPair        ConstraintKind = "tlsKeyPair"
)

// Supported path-kind restrictions.
const (
	PathAny       PathKind = "any"
	PathFile      PathKind = "file"
	PathDirectory PathKind = "dir"
)

// Supported Base64 padding policies.
const (
	PaddingOptional  Padding = "optional"
	PaddingRequired  Padding = "required"
	PaddingForbidden Padding = "forbidden"
)

// Supported IP address families.
const (
	IPv4 IPVersion = "4"
	IPv6 IPVersion = "6"
)

// Supported UUID versions.
const (
	UUIDAny UUIDVersion = "any"
	UUIDv1  UUIDVersion = "1"
	UUIDv2  UUIDVersion = "2"
	UUIDv3  UUIDVersion = "3"
	UUIDv4  UUIDVersion = "4"
	UUIDv5  UUIDVersion = "5"
	UUIDv6  UUIDVersion = "6"
	UUIDv7  UUIDVersion = "7"
	UUIDv8  UUIDVersion = "8"
)

// Supported hash algorithms.
const (
	MD5        HashAlgorithm = "MD5"
	SHA1       HashAlgorithm = "SHA1"
	SHA224     HashAlgorithm = "SHA224"
	SHA256     HashAlgorithm = "SHA256"
	SHA384     HashAlgorithm = "SHA384"
	SHA512     HashAlgorithm = "SHA512"
	SHA512_224 HashAlgorithm = "SHA512_224"
	SHA512_256 HashAlgorithm = "SHA512_256"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var compiledPatterns sync.Map

var parsedSemanticVersions sync.Map

func rule(kind Kind, options ...Option) Rule {
	rule := Rule{Kind: kind, Required: true, ListTrim: true, Padding: PaddingOptional, PathKind: PathAny, UUID: UUIDAny}
	for _, option := range options {
		option(&rule)
	}

	return rule
}

// Var declares a variable whose generated field name is derived from name.
func Var(name string, rule Rule) Variable {
	return Variable{Name: name, Rule: rule}
}

// Named declares a variable with an explicit generated Go field name.
func Named(name string, goName string, rule Rule) Variable {
	return Variable{Name: name, GoName: goName, Rule: rule}
}

// FallbackTo returns a copy that consults names in order when the primary name is absent.
func (variable Variable) FallbackTo(names ...string) Variable {
	variable.Fallbacks = append(append([]string(nil), variable.Fallbacks...), names...)

	return variable
}

// New validates variables and returns a schema.
func New(variables ...Variable) (Schema, error) {
	schema := Schema{Variables: append([]Variable(nil), variables...)}

	if err := schema.Validate(); err != nil {
		return Schema{}, err
	}

	schema.validated = true

	return schema, nil
}

// Must validates variables and panics on failure.
func Must(variables ...Variable) Schema {
	schema, err := New(variables...)
	if err != nil {
		panic(err)
	}

	return schema
}

// ExactlyOneOf returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) ExactlyOneOf(names ...string) Schema {
	return schema.withConstraint(ConstraintExactlyOne, "", names...)
}

// AtLeastOneOf returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) AtLeastOneOf(names ...string) Schema {
	return schema.withConstraint(ConstraintAtLeastOne, "", names...)
}

// MutuallyExclusive returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) MutuallyExclusive(names ...string) Schema {
	return schema.withConstraint(ConstraintMutuallyExclusive, "", names...)
}

// RequiredTogether returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) RequiredTogether(names ...string) Schema {
	return schema.withConstraint(ConstraintRequiredTogether, "", names...)
}

// RequiredWhen returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) RequiredWhen(name string, value string, required ...string) Schema {
	names := append([]string{name}, required...)

	return schema.withConstraint(ConstraintRequiredWhen, value, names...)
}

// ForbiddenWhen returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) ForbiddenWhen(name string, value string, forbidden ...string) Schema {
	names := append([]string{name}, forbidden...)

	return schema.withConstraint(ConstraintForbiddenWhen, value, names...)
}

// RequiredUnless returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) RequiredUnless(name string, value string, required ...string) Schema {
	names := append([]string{name}, required...)

	return schema.withConstraint(ConstraintRequiredUnless, value, names...)
}

// RequiredIfPresent returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) RequiredIfPresent(name string, required ...string) Schema {
	names := append([]string{name}, required...)

	return schema.withConstraint(ConstraintRequiredIfPresent, "", names...)
}

// EqualValues returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) EqualValues(first string, second string) Schema {
	return schema.withConstraint(ConstraintEqualValues, "", first, second)
}

// DifferentValues returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) DifferentValues(first string, second string) Schema {
	return schema.withConstraint(ConstraintDifferentValues, "", first, second)
}

// LessThanVariable returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) LessThanVariable(first string, second string) Schema {
	return schema.withConstraint(ConstraintLessThanVariable, "", first, second)
}

// TLSKeyPair returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) TLSKeyPair(certificate string, privateKey string) Schema {
	return schema.withConstraint(ConstraintTLSKeyPair, "", certificate, privateKey)
}

// AtMostOneOf returns a copy of the schema with the corresponding cross-variable constraint applied.
func (schema Schema) AtMostOneOf(names ...string) Schema {
	return schema.MutuallyExclusive(names...)
}

func (schema Schema) withConstraint(kind ConstraintKind, value string, names ...string) Schema {
	schema.Constraints = append(append([]Constraint(nil), schema.Constraints...), Constraint{Kind: kind, Names: append([]string(nil), names...), Value: value})
	if err := schema.Validate(); err != nil {
		panic(err)
	}
	schema.validated = true

	return schema
}

// MustSchemaJSON decodes and validates a schema, panicking on failure.
func MustSchemaJSON(data string) Schema {
	var schema Schema
	if err := json.Unmarshal([]byte(data), &schema); err != nil {
		panic(fmt.Errorf("envschema: decode generated schema: %w", err))
	}

	if err := schema.Validate(); err != nil {
		panic(err)
	}

	schema.validated = true

	return schema
}

// Validate checks the complete schema contract without loading values.
func (schema Schema) Validate() error {
	seen := make(map[string]struct{}, len(schema.Variables))
	rules := make(map[string]Rule, len(schema.Variables))
	for _, variable := range schema.Variables {
		if !envNamePattern.MatchString(variable.Name) {
			return fmt.Errorf("envschema: invalid environment variable name %q", variable.Name)
		}

		if _, ok := seen[variable.Name]; ok {
			return fmt.Errorf("envschema: duplicate environment variable %q", variable.Name)
		}
		seen[variable.Name] = struct{}{}
		rules[variable.Name] = variable.Rule
		for _, fallback := range variable.Fallbacks {
			if !envNamePattern.MatchString(fallback) {
				return fmt.Errorf("envschema: %s has invalid fallback name %q", variable.Name, fallback)
			}
			if fallback == variable.Name {
				return fmt.Errorf("envschema: %s cannot fall back to itself", variable.Name)
			}
		}

		if err := validateRule(variable.Rule, variable.Name); err != nil {
			return err
		}
		if variable.Rule.HasDefault {
			if _, err := parseRule(variable.Rule, variable.Rule.Default, variable.Name+" default"); err != nil {
				return fmt.Errorf("envschema: invalid default for %s: %w", variable.Name, err)
			}
		}
	}
	for _, constraint := range schema.Constraints {
		switch constraint.Kind {
		case ConstraintExactlyOne, ConstraintAtLeastOne, ConstraintMutuallyExclusive, ConstraintRequiredTogether,
			ConstraintRequiredWhen, ConstraintForbiddenWhen, ConstraintRequiredUnless, ConstraintRequiredIfPresent,
			ConstraintEqualValues, ConstraintDifferentValues, ConstraintLessThanVariable, ConstraintTLSKeyPair:
		default:
			return fmt.Errorf("envschema: unsupported constraint %q", constraint.Kind)
		}
		exactlyTwo := constraint.Kind == ConstraintEqualValues || constraint.Kind == ConstraintDifferentValues ||
			constraint.Kind == ConstraintLessThanVariable || constraint.Kind == ConstraintTLSKeyPair
		if len(constraint.Names) < 2 || exactlyTwo && len(constraint.Names) != 2 {
			expected := "at least two"
			if exactlyTwo {
				expected = "exactly two"
			}

			return fmt.Errorf("envschema: %s constraint needs %s variables", constraint.Kind, expected)
		}
		constraintNames := make(map[string]struct{}, len(constraint.Names))
		for _, name := range constraint.Names {
			if _, ok := seen[name]; !ok {
				return fmt.Errorf("envschema: %s constraint refers to unknown variable %q", constraint.Kind, name)
			}
			if _, duplicate := constraintNames[name]; duplicate {
				return fmt.Errorf("envschema: %s constraint repeats variable %q", constraint.Kind, name)
			}
			constraintNames[name] = struct{}{}
		}
		if constraint.Kind == ConstraintTLSKeyPair {
			if rules[constraint.Names[0]].Kind != KindCertificate || rules[constraint.Names[1]].Kind != KindPrivateKey {
				return fmt.Errorf("envschema: TLS key pair requires certificate then private key variables")
			}
		}
	}

	return nil
}

func validateRule(rule Rule, path string) error {
	switch rule.Kind {
	case KindString, KindNumber, KindInt, KindFloat, KindBoolean, KindEnum, KindJSON,
		KindArray, KindList, KindDuration, KindDate, KindBytes, KindPath, KindBase64,
		KindSecret, KindEmail, KindPort, KindURL, KindHost, KindUUID, KindIP, KindHash,
		KindHex, KindSemVer, KindTimeZone, KindUInt, KindCIDR, KindEndpoint,
		KindUnixSocket, KindTimestamp, KindTimeOfDay, KindMap, KindRegexp, KindPEM,
		KindCertificate, KindPrivateKey, KindCustom, KindURI, KindMACAddress,
		KindPublicKey, KindCertBundle, KindBigInt, KindDecimal, KindMediaType,
		KindFileMode, KindULID, KindGlob:
	default:
		return fmt.Errorf("envschema: %s has unsupported rule kind %q", path, rule.Kind)
	}

	if rule.Min != nil && rule.Max != nil && *rule.Min > *rule.Max {
		return fmt.Errorf("envschema: %s has a minimum greater than its maximum", path)
	}
	if rule.ExclusiveMin != nil && rule.ExclusiveMax != nil && *rule.ExclusiveMin >= *rule.ExclusiveMax {
		return fmt.Errorf("envschema: %s has incompatible exclusive bounds", path)
	}
	if rule.Multiple != nil && *rule.Multiple <= 0 {
		return fmt.Errorf("envschema: %s has a non-positive multiple", path)
	}
	if rule.MinItems != nil && *rule.MinItems < 0 || rule.MaxItems != nil && *rule.MaxItems < 0 {
		return fmt.Errorf("envschema: %s has a negative item count", path)
	}
	if rule.MinItems != nil && rule.MaxItems != nil && *rule.MinItems > *rule.MaxItems {
		return fmt.Errorf("envschema: %s has a minimum item count greater than its maximum", path)
	}
	minimumDuration, err := parseDurationBound(rule.MinDuration)
	if err != nil {
		return fmt.Errorf("envschema: %s has an invalid minimum duration: %w", path, err)
	}
	maximumDuration, err := parseDurationBound(rule.MaxDuration)
	if err != nil {
		return fmt.Errorf("envschema: %s has an invalid maximum duration: %w", path, err)
	}
	if minimumDuration != nil && maximumDuration != nil && *minimumDuration > *maximumDuration {
		return fmt.Errorf("envschema: %s has a minimum duration greater than its maximum", path)
	}

	if rule.MinLength != nil && rule.MaxLength != nil && *rule.MinLength > *rule.MaxLength {
		return fmt.Errorf("envschema: %s has a minimum length greater than its maximum length", path)
	}
	if rule.MinLength != nil && *rule.MinLength < 0 || rule.MaxLength != nil && *rule.MaxLength < 0 {
		return fmt.Errorf("envschema: %s has a negative string length", path)
	}

	if rule.Kind == KindDate || rule.Kind == KindTimestamp {
		minimum, err := parseDateBound(rule.MinDate)
		if err != nil {
			return fmt.Errorf("envschema: %s has an invalid minimum date: %w", path, err)
		}
		maximum, err := parseDateBound(rule.MaxDate)
		if err != nil {
			return fmt.Errorf("envschema: %s has an invalid maximum date: %w", path, err)
		}
		if !minimum.IsZero() && !maximum.IsZero() && minimum.After(maximum) {
			return fmt.Errorf("envschema: %s has a minimum date after its maximum date", path)
		}
	}

	if rule.Pattern != "" {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("envschema: %s has an invalid pattern: %w", path, err)
		}
		compiledPatterns.Store(rule.Pattern, compiled)
	}

	if rule.Kind == KindEnum && len(rule.Choices) == 0 {
		return fmt.Errorf("envschema: %s enum has no choices", path)
	}
	if rule.Kind == KindEnum {
		choices := make(map[string]struct{}, len(rule.Choices))
		for _, choice := range rule.Choices {
			key := choice
			if rule.EnumCaseInsensitive {
				key = strings.ToLower(choice)
			}
			if _, exists := choices[key]; exists {
				return fmt.Errorf("envschema: %s enum has duplicate choice %q", path, choice)
			}
			choices[key] = struct{}{}
		}
		for alias, canonical := range rule.Aliases {
			key := canonical
			if rule.EnumCaseInsensitive {
				key = strings.ToLower(canonical)
			}
			if _, exists := choices[key]; !exists {
				return fmt.Errorf("envschema: %s enum alias %q targets unknown choice %q", path, alias, canonical)
			}
		}
	}

	if rule.Kind == KindArray || rule.Kind == KindList {
		if rule.Item == nil {
			return fmt.Errorf("envschema: %s has no item rule", path)
		}

		if err := validateRule(*rule.Item, path+"[]"); err != nil {
			return err
		}
		if rule.Item.Kind == KindCustom {
			return fmt.Errorf("envschema: %s custom rules are only supported as top-level variables", path)
		}
	}
	if rule.Kind == KindMap {
		if rule.Key == nil || rule.Item == nil {
			return fmt.Errorf("envschema: %s map needs key and value rules", path)
		}
		if rule.Key.Kind != KindString && rule.Key.Kind != KindEnum {
			return fmt.Errorf("envschema: %s map keys must be strings or enums", path)
		}
		if rule.Separator == "" || rule.KeyValueSeparator == "" || rule.Separator == rule.KeyValueSeparator {
			return fmt.Errorf("envschema: %s map needs distinct non-empty separators", path)
		}
		if err := validateRule(*rule.Key, path+"{key}"); err != nil {
			return err
		}
		if err := validateRule(*rule.Item, path+"{value}"); err != nil {
			return err
		}
		if rule.Item.Kind == KindCustom {
			return fmt.Errorf("envschema: %s custom rules are only supported as top-level variables", path)
		}
	}
	if rule.Lowercase && rule.Uppercase {
		return fmt.Errorf("envschema: %s cannot require both lowercase and uppercase", path)
	}
	for _, scheme := range rule.Schemes {
		if scheme == "" || strings.ToLower(scheme) != scheme {
			return fmt.Errorf("envschema: %s has invalid URL scheme %q", path, scheme)
		}
	}

	if rule.Kind == KindHash {
		switch rule.Hash {
		case MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256:
		default:
			return fmt.Errorf("envschema: %s has an unsupported hash algorithm %q", path, rule.Hash)
		}
	}

	switch rule.PathKind {
	case "", PathAny, PathFile, PathDirectory:
	default:
		return fmt.Errorf("envschema: %s has unsupported path type %q", path, rule.PathKind)
	}

	switch rule.Padding {
	case "", PaddingOptional, PaddingRequired, PaddingForbidden:
	default:
		return fmt.Errorf("envschema: %s has unsupported base64 padding %q", path, rule.Padding)
	}

	switch rule.IPVersion {
	case "", IPv4, IPv6:
	default:
		return fmt.Errorf("envschema: %s has unsupported IP version %q", path, rule.IPVersion)
	}

	switch rule.UUID {
	case "", UUIDAny, UUIDv1, UUIDv2, UUIDv3, UUIDv4, UUIDv5, UUIDv6, UUIDv7, UUIDv8:
	default:
		return fmt.Errorf("envschema: %s has unsupported UUID version %q", path, rule.UUID)
	}

	if err := validateApplicableOptions(rule, path); err != nil {
		return err
	}

	return validatePolicies(rule, path)
}

func parseDurationBound(value string) (*time.Duration, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return nil, err
	}

	return &parsed, nil
}

func validateApplicableOptions(rule Rule, path string) error {
	collection := rule.Kind == KindArray || rule.Kind == KindList || rule.Kind == KindMap
	numeric := rule.Kind == KindNumber || rule.Kind == KindFloat || rule.Kind == KindInt || rule.Kind == KindUInt || rule.Kind == KindBytes || rule.Kind == KindPort || rule.Kind == KindDuration || rule.Kind == KindBigInt || rule.Kind == KindDecimal
	stringLike := rule.Kind == KindString || rule.Kind == KindSecret
	if (rule.MinItems != nil || rule.MaxItems != nil || rule.Unique) && !collection {
		return fmt.Errorf("envschema: %s uses collection options on %s", path, rule.Kind)
	}
	if (rule.ExclusiveMin != nil || rule.ExclusiveMax != nil || rule.Multiple != nil || rule.RejectZero || rule.Positive || rule.Negative) && !numeric {
		return fmt.Errorf("envschema: %s uses numeric options on %s", path, rule.Kind)
	}
	if (rule.MinDuration != "" || rule.MaxDuration != "") && rule.Kind != KindDuration {
		return fmt.Errorf("envschema: %s uses duration options on %s", path, rule.Kind)
	}
	if (len(rule.Schemes) != 0 || rule.URLCredentials != nil || rule.URLPort != nil || rule.URLQuery != nil || rule.URLFragment != nil) && rule.Kind != KindURL {
		return fmt.Errorf("envschema: %s uses URL options on %s", path, rule.Kind)
	}
	if (rule.Prefix != "" || rule.Suffix != "" || rule.ASCII || rule.Printable || rule.NoWhitespace || rule.EmptyAllowed) && !stringLike {
		return fmt.Errorf("envschema: %s uses string options on %s", path, rule.Kind)
	}
	if (rule.Lowercase || rule.Uppercase) && !stringLike && rule.Kind != KindHost && rule.Kind != KindHex && rule.Kind != KindHash {
		return fmt.Errorf("envschema: %s uses casing options on %s", path, rule.Kind)
	}
	if (rule.EnumCaseInsensitive || len(rule.Aliases) != 0) && rule.Kind != KindEnum {
		return fmt.Errorf("envschema: %s uses enum options on %s", path, rule.Kind)
	}
	if rule.Absolute != nil && rule.Kind != KindPath && rule.Kind != KindUnixSocket && rule.Kind != KindURL {
		return fmt.Errorf("envschema: %s uses path options on %s", path, rule.Kind)
	}
	if rule.UTC && rule.Kind != KindTimestamp {
		return fmt.Errorf("envschema: %s uses UTCOnly on %s", path, rule.Kind)
	}
	if rule.StrictBoolean && rule.Kind != KindBoolean {
		return fmt.Errorf("envschema: %s uses Strict on %s", path, rule.Kind)
	}
	if (rule.RuneLength || rule.NoSurroundingSpace) && !stringLike {
		return fmt.Errorf("envschema: %s uses text options on %s", path, rule.Kind)
	}
	if (rule.Trim || rule.Pattern != "" || rule.MinLength != nil || rule.MaxLength != nil) && !stringLike {
		return fmt.Errorf("envschema: %s uses text options on %s", path, rule.Kind)
	}
	if (rule.Min != nil || rule.Max != nil) && !numeric {
		return fmt.Errorf("envschema: %s uses bounds on %s", path, rule.Kind)
	}
	if (rule.MinDate != "" || rule.MaxDate != "") && rule.Kind != KindDate && rule.Kind != KindTimestamp {
		return fmt.Errorf("envschema: %s uses date bounds on %s", path, rule.Kind)
	}
	if rule.Separator != "" && rule.Kind != KindList && rule.Kind != KindMap {
		return fmt.Errorf("envschema: %s uses a separator on %s", path, rule.Kind)
	}
	if (rule.PathKind != "" && rule.PathKind != PathAny || rule.Exists) && rule.Kind != KindPath && rule.Kind != KindUnixSocket {
		return fmt.Errorf("envschema: %s uses path options on %s", path, rule.Kind)
	}
	if (rule.URLSafe || rule.Padding != "" && rule.Padding != PaddingOptional) && rule.Kind != KindBase64 {
		return fmt.Errorf("envschema: %s uses base64 options on %s", path, rule.Kind)
	}
	if rule.IPVersion != "" && rule.Kind != KindIP && rule.Kind != KindCIDR && rule.Kind != KindEndpoint {
		return fmt.Errorf("envschema: %s uses an IP version on %s", path, rule.Kind)
	}
	if rule.UUID != "" && rule.UUID != UUIDAny && rule.Kind != KindUUID {
		return fmt.Errorf("envschema: %s uses a UUID version on %s", path, rule.Kind)
	}
	if rule.Kind == KindCustom && (rule.CustomPackage == "" || rule.CustomName == "") {
		return fmt.Errorf("envschema: %s has incomplete custom type metadata", path)
	}

	return nil
}

// UnmarshalJSON returns a copy of the rule with the corresponding validation setting applied.
func (rule *Rule) UnmarshalJSON(data []byte) error {
	defaults := Rule{
		Required: true,
		ListTrim: true,
		PathKind: PathAny,
		Padding:  PaddingOptional,
		UUID:     UUIDAny,
	}
	type ruleJSON Rule
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode((*ruleJSON)(&defaults)); err != nil {
		return err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	allowedFields := map[string]struct{}{
		"kind": {}, "type": {}, "required": {}, "default": {}, "hasDefault": {},
		"trim": {}, "pattern": {}, "minLength": {}, "maxLength": {}, "min": {},
		"max": {}, "minDate": {}, "maxDate": {}, "positive": {}, "negative": {},
		"choices": {}, "item": {}, "separator": {}, "listTrim": {}, "unique": {},
		"pathKind": {}, "exists": {}, "urlSafe": {}, "padding": {}, "ipVersion": {},
		"uuidVersion": {}, "hash": {},
		"allowEmpty": {}, "minItems": {}, "maxItems": {}, "minDuration": {}, "maxDuration": {},
		"exclusiveMin": {}, "exclusiveMax": {}, "multipleOf": {}, "nonZero": {}, "schemes": {},
		"urlCredentials": {}, "urlPort": {}, "urlQuery": {}, "urlFragment": {}, "prefix": {},
		"suffix": {}, "ascii": {}, "printable": {}, "noWhitespace": {}, "lowercase": {},
		"uppercase": {}, "caseInsensitive": {}, "aliases": {}, "key": {}, "keyValueSeparator": {},
		"absolute": {}, "utc": {},
		"customPackage": {}, "customName": {},
		"strictBoolean": {}, "runeLength": {}, "noSurroundingSpace": {},
		"policies": {},
	}
	for field := range fields {
		if _, ok := allowedFields[field]; !ok {
			return fmt.Errorf("unknown rule field %q", field)
		}
	}
	if defaults.Kind == "" {
		if rawType, ok := fields["type"]; ok {
			if err := json.Unmarshal(rawType, &defaults.Kind); err != nil {
				return fmt.Errorf("decode rule type: %w", err)
			}
		}
	}
	if _, ok := fields["default"]; ok {
		defaults.HasDefault = true
	}

	*rule = defaults

	return nil
}

func normalizedDefault(value any) any {
	switch value := value.(type) {
	case time.Duration:
		return value.String()
	case time.Time:
		return value.Format(time.RFC3339Nano)
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return nil
	}
	if reflected.Kind() == reflect.Slice || reflected.Kind() == reflect.Array {
		items := make([]any, reflected.Len())
		for index := range reflected.Len() {
			items[index] = normalizedDefault(reflected.Index(index).Interface())
		}

		return items
	}
	if reflected.Kind() == reflect.Map && reflected.Type().Key().Kind() == reflect.String {
		items := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			items[iterator.Key().String()] = normalizedDefault(iterator.Value().Interface())
		}

		return items
	}

	return value
}

// String returns an environment-schema value configured by its arguments.
func String(options ...Option) Rule { return rule(KindString, options...) }

// Number returns an environment-schema value configured by its arguments.
func Number(options ...Option) Rule { return rule(KindNumber, options...) }

// Int returns an environment-schema value configured by its arguments.
func Int(options ...Option) Rule { return rule(KindInt, options...) }

// Float returns an environment-schema value configured by its arguments.
func Float(options ...Option) Rule { return rule(KindFloat, options...) }

// Boolean returns an environment-schema value configured by its arguments.
func Boolean(options ...Option) Rule { return rule(KindBoolean, options...) }

// JSON returns an environment-schema value configured by its arguments.
func JSON(options ...Option) Rule { return rule(KindJSON, options...) }

// Duration returns an environment-schema value configured by its arguments.
func Duration(options ...Option) Rule { return rule(KindDuration, options...) }

// Date returns an environment-schema value configured by its arguments.
func Date(options ...Option) Rule { return rule(KindDate, options...) }

// Bytes returns an environment-schema value configured by its arguments.
func Bytes(options ...Option) Rule { return rule(KindBytes, options...) }

// Path returns an environment-schema value configured by its arguments.
func Path(options ...Option) Rule { return rule(KindPath, options...) }

// Base64 returns an environment-schema value configured by its arguments.
func Base64(options ...Option) Rule { return rule(KindBase64, options...) }

// Secret returns an environment-schema value configured by its arguments.
func Secret(options ...Option) Rule { return rule(KindSecret, options...) }

// Email returns an environment-schema value configured by its arguments.
func Email(options ...Option) Rule { return rule(KindEmail, options...) }

// Port returns an environment-schema value configured by its arguments.
func Port(options ...Option) Rule { return rule(KindPort, options...) }

// URL returns an environment-schema value configured by its arguments.
func URL(options ...Option) Rule { return rule(KindURL, options...) }

// Host returns an environment-schema value configured by its arguments.
func Host(options ...Option) Rule { return rule(KindHost, options...) }

// UUID returns an environment-schema value configured by its arguments.
func UUID(options ...Option) Rule { return rule(KindUUID, options...) }

// IPAddress returns an environment-schema value configured by its arguments.
func IPAddress(options ...Option) Rule { return rule(KindIP, options...) }

// Hex returns an environment-schema value configured by its arguments.
func Hex(options ...Option) Rule { return rule(KindHex, options...) }

// SemVer returns an environment-schema value configured by its arguments.
func SemVer(options ...Option) Rule { return rule(KindSemVer, options...) }

// TimeZone returns an environment-schema value configured by its arguments.
func TimeZone(options ...Option) Rule { return rule(KindTimeZone, options...) }

// Uint returns an environment-schema value configured by its arguments.
func Uint(options ...Option) Rule { return rule(KindUInt, options...) }

// CIDR returns an environment-schema value configured by its arguments.
func CIDR(options ...Option) Rule { return rule(KindCIDR, options...) }

// Endpoint returns an environment-schema value configured by its arguments.
func Endpoint(options ...Option) Rule { return rule(KindEndpoint, options...) }

// UnixSocket returns an environment-schema value configured by its arguments.
func UnixSocket(options ...Option) Rule { return rule(KindUnixSocket, options...) }

// Timestamp returns an environment-schema value configured by its arguments.
func Timestamp(options ...Option) Rule { return rule(KindTimestamp, options...) }

// TimeOfDay returns an environment-schema value configured by its arguments.
func TimeOfDay(options ...Option) Rule { return rule(KindTimeOfDay, options...) }

// Regexp returns an environment-schema value configured by its arguments.
func Regexp(options ...Option) Rule { return rule(KindRegexp, options...) }

// PEM returns an environment-schema value configured by its arguments.
func PEM(options ...Option) Rule { return rule(KindPEM, options...) }

// Certificate returns an environment-schema value configured by its arguments.
func Certificate(options ...Option) Rule { return rule(KindCertificate, options...) }

// PrivateKey returns an environment-schema value configured by its arguments.
func PrivateKey(options ...Option) Rule { return rule(KindPrivateKey, options...) }

// URI returns an environment-schema value configured by its arguments.
func URI(options ...Option) Rule { return rule(KindURI, options...) }

// MACAddress returns an environment-schema value configured by its arguments.
func MACAddress(options ...Option) Rule { return rule(KindMACAddress, options...) }

// PublicKey returns an environment-schema value configured by its arguments.
func PublicKey(options ...Option) Rule { return rule(KindPublicKey, options...) }

// CertificateBundle returns an environment-schema value configured by its arguments.
func CertificateBundle(options ...Option) Rule { return rule(KindCertBundle, options...) }

// BigInt returns an environment-schema value configured by its arguments.
func BigInt(options ...Option) Rule { return rule(KindBigInt, options...) }

// Decimal returns an environment-schema value configured by its arguments.
func Decimal(options ...Option) Rule { return rule(KindDecimal, options...) }

// MediaType returns an environment-schema value configured by its arguments.
func MediaType(options ...Option) Rule { return rule(KindMediaType, options...) }

// FileMode returns an environment-schema value configured by its arguments.
func FileMode(options ...Option) Rule { return rule(KindFileMode, options...) }

// ULID returns an environment-schema value configured by its arguments.
func ULID(options ...Option) Rule { return rule(KindULID, options...) }

// Glob returns an environment-schema value configured by its arguments.
func Glob(options ...Option) Rule { return rule(KindGlob, options...) }

// Custom returns an environment-schema value configured by its arguments.
func Custom[T any](options ...Option) Rule {
	typeOf := reflect.TypeFor[T]()
	if typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	textUnmarshaler := reflect.TypeFor[encoding.TextUnmarshaler]()
	if typeOf.Name() == "" || typeOf.PkgPath() == "" || !reflect.PointerTo(typeOf).Implements(textUnmarshaler) {
		panic(fmt.Sprintf("envschema: custom type %s must be a named type whose pointer implements encoding.TextUnmarshaler", typeOf))
	}
	rule := rule(KindCustom, options...)
	rule.CustomPackage = typeOf.PkgPath()
	rule.CustomName = typeOf.Name()

	return rule
}

// CustomNamed returns an environment-schema value configured by its arguments.
func CustomNamed(packagePath string, name string, options ...Option) Rule {
	rule := rule(KindCustom, options...)
	rule.CustomPackage = packagePath
	rule.CustomName = name

	return rule
}

// HTTPURL returns an environment-schema value configured by its arguments.
func HTTPURL(options ...Option) Rule {
	return URL(options...).WithSchemes("http", "https")
}

// Enum returns an environment-schema value configured by its arguments.
func Enum(choices []string, options ...Option) Rule {
	rule := rule(KindEnum, options...)
	rule.Choices = append([]string(nil), choices...)

	return rule
}

// Array returns an environment-schema value configured by its arguments.
func Array(item Rule, options ...Option) Rule {
	rule := rule(KindArray, options...)
	rule.Item = &item

	return rule
}

// List returns an environment-schema value configured by its arguments.
func List(item Rule, options ...Option) Rule {
	rule := rule(KindList, options...)
	rule.Item = &item

	return rule
}

// Map returns an environment-schema value configured by its arguments.
func Map(key Rule, value Rule, options ...Option) Rule {
	rule := rule(KindMap, options...)
	rule.Key = &key
	rule.Item = &value
	rule.Separator = ","
	rule.KeyValueSeparator = "="

	return rule
}

// OneOf returns an environment-schema value configured by its arguments.
func OneOf(choices ...string) Rule {
	return Enum(choices)
}

// Hash returns an environment-schema value configured by its arguments.
func Hash(algorithm HashAlgorithm, options ...Option) Rule {
	rule := rule(KindHash, options...)
	rule.Hash = algorithm

	return rule
}

// Optional returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Optional() Rule {
	rule.Required = false

	return rule
}

// DefaultTo returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) DefaultTo(value any) Rule {
	rule.Default = normalizedDefault(value)
	rule.HasDefault = true

	return rule
}

// Trimmed returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Trimmed() Rule {
	rule.Trim = true

	return rule
}

// Matching returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Matching(expression string) Rule {
	rule.Pattern = expression

	return rule
}

// WithMinLength returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithMinLength(value int) Rule {
	rule.MinLength = &value

	return rule
}

// WithMaxLength returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithMaxLength(value int) Rule {
	rule.MaxLength = &value

	return rule
}

// WithExactLength returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithExactLength(value int) Rule {
	rule.MinLength = &value
	rule.MaxLength = &value

	return rule
}

// CountRunes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CountRunes() Rule {
	rule.RuneLength = true

	return rule
}

// AllowEmpty returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AllowEmpty() Rule {
	rule.EmptyAllowed = true

	return rule
}

// NonEmpty returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonEmpty() Rule {
	value := 1
	rule.MinLength = &value

	return rule
}

// WithPrefix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithPrefix(value string) Rule {
	rule.Prefix = value

	return rule
}

// WithSuffix returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithSuffix(value string) Rule {
	rule.Suffix = value

	return rule
}

// ASCIIOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ASCIIOnly() Rule {
	rule.ASCII = true

	return rule
}

// PrintableOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PrintableOnly() Rule {
	rule.Printable = true

	return rule
}

// WithoutWhitespace returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutWhitespace() Rule {
	rule.NoWhitespace = true

	return rule
}

// WithoutSurroundingWhitespace returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutSurroundingWhitespace() Rule {
	rule.NoSurroundingSpace = true

	return rule
}

// LowercaseOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LowercaseOnly() Rule {
	rule.Lowercase = true

	return rule
}

// UppercaseOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) UppercaseOnly() Rule {
	rule.Uppercase = true

	return rule
}

// AtLeast returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeast(value float64) Rule {
	rule.Min = &value

	return rule
}

// AtMost returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMost(value float64) Rule {
	rule.Max = &value

	return rule
}

// Between returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Between(minimum float64, maximum float64) Rule {
	rule.Min = &minimum
	rule.Max = &maximum

	return rule
}

// GreaterThan returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) GreaterThan(value float64) Rule {
	rule.ExclusiveMin = &value

	return rule
}

// LessThan returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) LessThan(value float64) Rule {
	rule.ExclusiveMax = &value

	return rule
}

// MultipleOf returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) MultipleOf(value float64) Rule {
	rule.Multiple = &value

	return rule
}

// NonZero returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonZero() Rule {
	rule.RejectZero = true

	return rule
}

// NonNegative returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonNegative() Rule {
	value := float64(0)
	rule.Min = &value

	return rule
}

// NonPositive returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NonPositive() Rule {
	value := float64(0)
	rule.Max = &value

	return rule
}

// PositiveOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PositiveOnly() Rule {
	rule.Positive = true

	return rule
}

// NegativeOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) NegativeOnly() Rule {
	rule.Negative = true

	return rule
}

// StartingAt returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) StartingAt(value string) Rule {
	rule.MinDate = value

	return rule
}

// EndingAt returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) EndingAt(value string) Rule {
	rule.MaxDate = value

	return rule
}

// AtLeastDuration returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastDuration(value time.Duration) Rule {
	rule.MinDuration = value.String()
	return rule
}

// AtMostDuration returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostDuration(value time.Duration) Rule {
	rule.MaxDuration = value.String()
	return rule
}

// SeparatedBy returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) SeparatedBy(value string) Rule {
	rule.Separator = value

	return rule
}

// PreserveWhitespace returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) PreserveWhitespace() Rule {
	rule.ListTrim = false

	return rule
}

// UniqueItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) UniqueItems() Rule {
	rule.Unique = true

	return rule
}

// AtLeastItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtLeastItems(value int) Rule {
	rule.MinItems = &value

	return rule
}

// AtMostItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AtMostItems(value int) Rule {
	rule.MaxItems = &value

	return rule
}

// ExactlyItems returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) ExactlyItems(value int) Rule {
	rule.MinItems = &value
	rule.MaxItems = &value
	return rule
}

// KeyValueSeparatedBy returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) KeyValueSeparatedBy(value string) Rule {
	rule.KeyValueSeparator = value

	return rule
}

// File returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) File() Rule {
	rule.PathKind = PathFile

	return rule
}

// Directory returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Directory() Rule {
	rule.PathKind = PathDirectory

	return rule
}

// Existing returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Existing() Rule {
	rule.Exists = true

	return rule
}

// AbsoluteOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) AbsoluteOnly() Rule {
	value := true
	rule.Absolute = &value

	return rule
}

// RelativeOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RelativeOnly() Rule {
	value := false
	rule.Absolute = &value

	return rule
}

// URLSafeEncoding returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) URLSafeEncoding() Rule {
	rule.URLSafe = true

	return rule
}

// WithPadding returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithPadding(value Padding) Rule {
	rule.Padding = value

	return rule
}

// IPVersionIs returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) IPVersionIs(value IPVersion) Rule {
	rule.IPVersion = value

	return rule
}

// UUIDVersionIs returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) UUIDVersionIs(value UUIDVersion) Rule {
	rule.UUID = value

	return rule
}

// WithSchemes returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithSchemes(values ...string) Rule {
	rule.Schemes = append([]string(nil), values...)

	return rule
}

// HTTPSOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) HTTPSOnly() Rule { return rule.WithSchemes("https") }

// HTTPOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) HTTPOnly() Rule { return rule.WithSchemes("http", "https") }

// Strict returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Strict() Rule {
	rule.StrictBoolean = true

	return rule
}

// RequireCredentials returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireCredentials() Rule {
	value := true
	rule.URLCredentials = &value

	return rule
}

// WithoutCredentials returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutCredentials() Rule {
	value := false
	rule.URLCredentials = &value

	return rule
}

// RequirePort returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequirePort() Rule {
	value := true
	rule.URLPort = &value

	return rule
}

// WithoutPort returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutPort() Rule {
	value := false
	rule.URLPort = &value

	return rule
}

// RequireQuery returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireQuery() Rule {
	value := true
	rule.URLQuery = &value

	return rule
}

// WithoutQuery returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutQuery() Rule {
	value := false
	rule.URLQuery = &value

	return rule
}

// RequireFragment returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) RequireFragment() Rule {
	value := true
	rule.URLFragment = &value

	return rule
}

// WithoutFragment returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) WithoutFragment() Rule {
	value := false
	rule.URLFragment = &value

	return rule
}

// CaseInsensitive returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) CaseInsensitive() Rule {
	rule.EnumCaseInsensitive = true

	return rule
}

// Alias returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) Alias(alias string, canonical string) Rule {
	if rule.Aliases == nil {
		rule.Aliases = make(map[string]string)
	}
	rule.Aliases[alias] = canonical

	return rule
}

// UTCOnly returns a copy of the rule with the corresponding validation setting applied.
func (rule Rule) UTCOnly() Rule {
	rule.UTC = true

	return rule
}

// Optional returns an environment-schema value configured by its arguments.
func Optional(rule *Rule) { rule.Required = false }

// Default returns an environment-schema value configured by its arguments.
func Default(value any) Option {
	return func(rule *Rule) {
		rule.Default = normalizedDefault(value)
		rule.HasDefault = true
	}
}

// Trim returns an environment-schema value configured by its arguments.
func Trim(rule *Rule) { rule.Trim = true }

// Pattern returns an environment-schema value configured by its arguments.
func Pattern(expression string) Option {
	return func(rule *Rule) { rule.Pattern = expression }
}

// MinLength returns an environment-schema value configured by its arguments.
func MinLength(value int) Option {
	return func(rule *Rule) { rule.MinLength = &value }
}

// MaxLength returns an environment-schema value configured by its arguments.
func MaxLength(value int) Option {
	return func(rule *Rule) { rule.MaxLength = &value }
}

// Min returns an environment-schema value configured by its arguments.
func Min(value float64) Option {
	return func(rule *Rule) { rule.Min = &value }
}

// Max returns an environment-schema value configured by its arguments.
func Max(value float64) Option {
	return func(rule *Rule) { rule.Max = &value }
}

// Range returns an environment-schema value configured by its arguments.
func Range(minimum float64, maximum float64) Option {
	return func(rule *Rule) {
		rule.Min = &minimum
		rule.Max = &maximum
	}
}

// MinDate returns an environment-schema value configured by its arguments.
func MinDate(value string) Option {
	return func(rule *Rule) { rule.MinDate = value }
}

// MaxDate returns an environment-schema value configured by its arguments.
func MaxDate(value string) Option {
	return func(rule *Rule) { rule.MaxDate = value }
}

// Positive returns an environment-schema value configured by its arguments.
func Positive(rule *Rule) { rule.Positive = true }

// Negative returns an environment-schema value configured by its arguments.
func Negative(rule *Rule) { rule.Negative = true }

// Separator returns an environment-schema value configured by its arguments.
func Separator(value string) Option {
	return func(rule *Rule) { rule.Separator = value }
}

// PreserveListWhitespace returns an environment-schema value configured by its arguments.
func PreserveListWhitespace(rule *Rule) { rule.ListTrim = false }

// Unique returns an environment-schema value configured by its arguments.
func Unique(rule *Rule) { rule.Unique = true }

// PathType returns an environment-schema value configured by its arguments.
func PathType(value PathKind) Option {
	return func(rule *Rule) { rule.PathKind = value }
}

// MustExist returns an environment-schema value configured by its arguments.
func MustExist(rule *Rule) { rule.Exists = true }

// URLSafe returns an environment-schema value configured by its arguments.
func URLSafe(rule *Rule) { rule.URLSafe = true }

// Base64Padding returns an environment-schema value configured by its arguments.
func Base64Padding(value Padding) Option {
	return func(rule *Rule) { rule.Padding = value }
}

// IP returns an environment-schema value configured by its arguments.
func IP(value IPVersion) Option {
	return func(rule *Rule) { rule.IPVersion = value }
}

// UUIDVersioned returns an environment-schema value configured by its arguments.
func UUIDVersioned(value UUIDVersion) Option {
	return func(rule *Rule) { rule.UUID = value }
}
