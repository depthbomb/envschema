package generate

import (
	"encoding/json"
	"go/token"
	"go/types"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depthbomb/envschema"
	"golang.org/x/tools/go/packages"
)

func pointer[T any](value T) *T {
	return &value
}

func TestTypeAndLiteralMatrices(t *testing.T) {
	t.Parallel()

	rules := []envschema.Rule{
		envschema.String(), envschema.Number(), envschema.Int(), envschema.Uint(), envschema.Boolean(),
		envschema.JSON(), envschema.Duration(), envschema.Date(), envschema.CIDR(), envschema.Regexp(),
		envschema.PEM(), envschema.Certificate(), envschema.PrivateKey(), envschema.MACAddress(),
		envschema.PublicKey(), envschema.CertificateBundle(), envschema.BigInt(), envschema.Decimal(),
		envschema.FileMode(), envschema.Endpoint(), envschema.List(envschema.Int()),
		envschema.Map(envschema.String(), envschema.Int()), envschema.Secret(),
	}
	for _, rule := range rules {
		if _, err := typeFor(rule); err != nil {
			t.Fatalf("typeFor(%s) error = %v", rule.Kind, err)
		}
	}
	invalidRules := []envschema.Rule{
		{Kind: envschema.Kind("unknown")},
		{Kind: envschema.KindList},
		{Kind: envschema.KindMap},
		envschema.List(envschema.CustomNamed("example.com/custom", "Value")),
		envschema.CustomNamed("example.com/custom", "Value"),
	}
	for _, rule := range invalidRules {
		if _, err := typeFor(rule); err == nil {
			t.Fatalf("typeFor(%s) error = nil", rule.Kind)
		}
	}

	integer := *big.NewInt(-255)
	decimal := *big.NewRat(3, 2)
	literals := []any{
		nil, "text", true, int(1), int8(1), int16(1), int32(1), int64(1),
		uint(1), uint8(1), uint16(1), uint32(1), uint64(1), float32(1.5), float64(1.5),
		json.Number("1.25"), json.RawMessage(`{"a":1}`), integer, decimal, fs.FileMode(0o755),
		net.HardwareAddr{1, 2, 3}, []any{"a", int64(1)}, map[string]any{"b": 2, "a": 1},
	}
	for _, value := range literals {
		if _, err := valueLiteral(value); err != nil {
			t.Fatalf("valueLiteral(%T) error = %v", value, err)
		}
	}
	for _, value := range []any{make(chan int), []any{make(chan int)}, map[string]any{"x": make(chan int)}} {
		if _, err := valueLiteral(value); err == nil {
			t.Fatalf("valueLiteral(%T) error = nil", value)
		}
	}
}

func TestRuleLiteralCoversAllMetadata(t *testing.T) {
	t.Parallel()

	rule := envschema.Rule{
		Kind: envschema.KindString, Required: false, Default: "value", HasDefault: true,
		Trim: true, Pattern: "x", MinLength: pointer(1), MaxLength: pointer(4),
		Min: pointer(1.0), Max: pointer(4.0), ExclusiveMin: pointer(0.0), ExclusiveMax: pointer(5.0),
		Multiple: pointer(1.0), RejectZero: true, Positive: true, Negative: true,
		MinDate: "2026-01-01", MaxDate: "2026-12-31", MinDuration: "1s", MaxDuration: "2s",
		Separator: ";", ListTrim: false, Unique: true, MinItems: pointer(1), MaxItems: pointer(2),
		PathKind: envschema.PathFile, Exists: true, Absolute: pointer(true), URLSafe: true,
		Padding: envschema.PaddingRequired, IPVersion: envschema.IPv4, UUID: envschema.UUIDv4,
		Schemes: []string{"https"}, URLCredentials: pointer(true), URLPort: pointer(false),
		URLQuery: pointer(true), URLFragment: pointer(false), Prefix: "a", Suffix: "z",
		ASCII: true, Printable: true, NoWhitespace: true, NoSurroundingSpace: true,
		RuneLength: true, Lowercase: true, Uppercase: true, EnumCaseInsensitive: true,
		Aliases: map[string]string{"alias": "canonical"}, UTC: true, StrictBoolean: true,
		Policies: map[string][]string{"string.contains": {"x"}},
	}
	literal, err := ruleLiteral(rule)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{".Optional()", ".DefaultTo", ".Trimmed()", ".WithPolicy", ".RequireCredentials()"} {
		if !strings.Contains(literal, fragment) {
			t.Fatalf("rule literal does not contain %q: %s", fragment, literal)
		}
	}

	kinds := []envschema.Rule{
		envschema.Float(), envschema.Enum([]string{"a"}), envschema.Array(envschema.String()),
		envschema.Bytes(), envschema.Path(), envschema.Base64(), envschema.Email(), envschema.Port(),
		envschema.URL(), envschema.Host(), envschema.UUID(), envschema.IPAddress(), envschema.Hash(envschema.SHA1),
		envschema.Hex(), envschema.SemVer(), envschema.TimeZone(), envschema.UnixSocket(), envschema.Timestamp(),
		envschema.TimeOfDay(), envschema.URI(), envschema.MediaType(), envschema.ULID(), envschema.Glob(),
		envschema.CustomNamed("example.com/custom", "Value"),
	}
	for _, candidate := range kinds {
		if _, err := ruleLiteral(candidate); err != nil {
			t.Fatalf("ruleLiteral(%s) error = %v", candidate.Kind, err)
		}
	}
	if _, err := ruleLiteral(envschema.Rule{Kind: "invalid"}); err == nil {
		t.Fatal("ruleLiteral(invalid) error = nil")
	}
}

func TestGeneratorValidationAndCustomImports(t *testing.T) {
	t.Parallel()

	for _, options := range []Options{{}, {Package: "bad-name"}, {Package: "config", Type: "private"}} {
		if _, err := normalizedOptions(options); err == nil {
			t.Fatalf("normalizedOptions(%+v) error = nil", options)
		}
	}
	options, err := normalizedOptions(Options{Package: "config"})
	if err != nil || options.Type != "Config" {
		t.Fatalf("normalizedOptions() = %+v, %v", options, err)
	}

	imports := map[string]string{"custom": "example.com/first"}
	name, err := sourceTypeFor(envschema.CustomNamed("example.com/second", "Value"), imports)
	if err != nil || name != "custom1.Value" {
		t.Fatalf("sourceTypeFor() = %q, %v", name, err)
	}
}

func TestLoadAndFileErrorBranches(t *testing.T) {
	t.Parallel()

	if err := packageErrors(&packages.Package{Errors: []packages.Error{{Msg: "first"}, {Msg: "second"}}}); err == nil {
		t.Fatal("packageErrors() error = nil")
	}
	if err := packageErrors(&packages.Package{}); err != nil {
		t.Fatal(err)
	}
	if _, err := providerInterface(&packages.Package{Imports: map[string]*packages.Package{}}); err == nil {
		t.Fatal("providerInterface() accepted a package without envschema")
	}
	dependencyTypes := types.NewPackage("github.com/depthbomb/envschema", "envschema")
	dependency := &packages.Package{Types: dependencyTypes}
	pkg := &packages.Package{Imports: map[string]*packages.Package{"github.com/depthbomb/envschema": dependency}}
	if _, err := providerInterface(pkg); err == nil {
		t.Fatal("providerInterface() accepted a package without Provider")
	}
	dependencyTypes.Scope().Insert(types.NewVar(token.NoPos, dependencyTypes, "Provider", types.Typ[types.Int]))
	if _, err := providerInterface(pkg); err == nil {
		t.Fatal("providerInterface() accepted a non-interface Provider")
	}

	discovered := []providerType{{name: "One"}, {name: "Two", pointer: true}}
	if selected, err := selectProvider(discovered, "Two"); err != nil || selected.name != "Two" || !selected.pointer {
		t.Fatalf("selectProvider() = %+v, %v", selected, err)
	}
	for _, requested := range []string{"Missing", ""} {
		if _, err := selectProvider(discovered, requested); err == nil {
			t.Fatalf("selectProvider(%q) error = nil", requested)
		}
	}
	if _, err := selectProvider(nil, ""); err == nil {
		t.Fatal("selectProvider(nil) error = nil")
	}

	directory := t.TempDir()
	config, pattern, err := packageConfig(directory)
	if err != nil || config.Dir == "" || pattern != "." {
		t.Fatalf("packageConfig(directory) = %q, %+v, %v", pattern, config, err)
	}
	config, pattern, err = packageConfig("example.com/module/package")
	if err != nil || config.Dir != "" || pattern == "" {
		t.Fatalf("packageConfig(pattern) = %q, %+v, %v", pattern, config, err)
	}

	if _, err := executeLoader(&packages.Package{}, providerType{name: "Provider"}); err == nil {
		t.Fatal("executeLoader() error = nil without module")
	}
	if _, err := LoadPackage(filepath.Join(directory, "missing"), ""); err == nil {
		t.Fatal("LoadPackage() error = nil for missing package")
	}

	schema := envschema.Must(envschema.Var("VALUE", envschema.String()))
	filename := filepath.Join(directory, "config_gen.go")
	if err := File(filename, schema, Options{Package: "config"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filename); err != nil || !strings.Contains(string(data), "type Config struct") {
		t.Fatalf("generated file = %q, %v", data, err)
	}
	if err := File(filepath.Join(directory, "missing", "config.go"), schema, Options{Package: "config"}); err == nil {
		t.Fatal("File() error = nil for missing target directory")
	}
	invalid := envschema.Schema{Variables: []envschema.Variable{envschema.Var("VALUE", envschema.Rule{Kind: "invalid"})}}
	if err := File(filename, invalid, Options{Package: "config"}); err == nil {
		t.Fatal("File() accepted an invalid schema")
	}
}

func TestSourceRejectsInvalidNamesAndTypes(t *testing.T) {
	t.Parallel()

	valid := envschema.Must(envschema.Var("VALUE", envschema.String()))
	if _, err := Source(valid, Options{}); err == nil {
		t.Fatal("Source() accepted an empty package")
	}
	invalidField := envschema.Must(envschema.Named("VALUE", "private", envschema.String()))
	if _, err := Source(invalidField, Options{Package: "config"}); err == nil {
		t.Fatal("Source() accepted an unexported field")
	}

	for _, provider := range []providerType{{name: "Value"}, {name: "Value", pointer: true}} {
		source, err := loaderSource("github.com/depthbomb/envschema", "example.com/schema", provider, "schema.json")
		if err != nil || len(source) == 0 {
			t.Fatalf("loaderSource(%+v) = %q, %v", provider, source, err)
		}
	}
}
