package generate_test

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/depthbomb/envschema"
	"github.com/depthbomb/envschema/generate"
)

func TestSourceGeneratesTypedConfig(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("DATABASE_URL", envschema.URL()),
		envschema.Var("PORT", envschema.Port(envschema.Default(8080))),
		envschema.Var("LABEL", envschema.String(envschema.Optional)),
		envschema.Var("DELAYS", envschema.List(envschema.Duration())),
		envschema.Var("DATA", envschema.JSON()),
	)
	source, err := generate.Source(schema, generate.Options{Package: "config", Type: "Environment"})
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}

	if _, err := parser.ParseFile(token.NewFileSet(), "config_gen.go", source, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v\n%s", err, source)
	}

	for _, expected := range [][]byte{
		[]byte("type Environment struct"),
		[]byte("DatabaseUrl string"),
		[]byte(`envschema.Read[int64](generatedSchema.Variables[1].Rule, "PORT", lookup)`),
		[]byte(`envschema.Read[string](generatedSchema.Variables[2].Rule, "LABEL", lookup)`),
		[]byte(`envschema.Read[[]time.Duration](generatedSchema.Variables[3].Rule, "DELAYS", lookup)`),
		[]byte(`envschema.Read[json.RawMessage](generatedSchema.Variables[4].Rule, "DATA", lookup)`),
		[]byte("func Load() (Environment, error)"),
		[]byte("envschema.LookupEnvFiles()"),
		[]byte("func LoadFrom(lookup envschema.LookupFunc) (Environment, error)"),
	} {
		if !bytes.Contains(source, expected) {
			t.Fatalf("generated source does not contain %q\n%s", expected, source)
		}
	}
}

func TestSourceRejectsCollidingFieldNames(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("API_URL", envschema.String()),
		envschema.Var("API__URL", envschema.String()),
	)
	_, err := generate.Source(schema, generate.Options{Package: "config"})
	if err == nil {
		t.Fatal("Source() error = nil, want a field collision error")
	}
}

func TestSourceGeneratesExtendedTypesAndConstraints(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("CIDR", envschema.CIDR()),
		envschema.Var("PATTERN", envschema.Regexp()),
		envschema.Var("CERTIFICATE", envschema.Certificate()),
		envschema.Var("VALUES", envschema.Map(envschema.String(), envschema.Uint())),
		envschema.Var("STAMP", envschema.Timestamp()),
		envschema.Var("OLD", envschema.String().Optional()).FallbackTo("LEGACY_OLD"),
	).AtLeastOneOf("CIDR", "PATTERN")
	source, err := generate.Source(schema, generate.Options{Package: "config"})
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}

	for _, expected := range [][]byte{
		[]byte(`"crypto/x509"`),
		[]byte(`"net/netip"`),
		[]byte(`"regexp"`),
		[]byte("netip.Prefix"),
		[]byte("*regexp.Regexp"),
		[]byte("*x509.Certificate"),
		[]byte("map[string]uint64"),
		[]byte(`FallbackTo("LEGACY_OLD")`),
		[]byte(`AtLeastOneOf("CIDR", "PATTERN")`),
		[]byte("envschema.LoadFrom"),
		[]byte("envschema.ValueAs[string]"),
	} {
		if !bytes.Contains(source, expected) {
			t.Fatalf("generated source does not contain %q\n%s", expected, source)
		}
	}
}

func TestSourceGeneratesAdvancedTypesPoliciesAndConstraints(t *testing.T) {
	t.Parallel()

	defaultInteger := *big.NewInt(255)
	defaultDecimal := *big.NewRat(5, 4)
	schema := envschema.Must(
		envschema.Var("URI", envschema.URI().RequireHost()),
		envschema.Var("MAC", envschema.MACAddress().DefaultTo("02:00:5e:10:00:00")),
		envschema.Var("PUBLIC", envschema.PublicKey()),
		envschema.Var("BUNDLE", envschema.CertificateBundle()),
		envschema.Var("BIG", envschema.BigInt().DefaultTo(defaultInteger)),
		envschema.Var("DECIMAL", envschema.Decimal().DefaultTo(defaultDecimal)),
		envschema.Var("MEDIA", envschema.MediaType().WithoutMediaTypeParameters()),
		envschema.Var("MODE", envschema.FileMode()),
		envschema.Var("ULID", envschema.ULID()),
		envschema.Var("GLOB", envschema.Glob()),
		envschema.Var("LIMIT", envschema.BigInt().Optional()),
	).LessThanVariable("BIG", "LIMIT")
	source, err := generate.Source(schema, generate.Options{Package: "config", Type: "Advanced"})
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "config_gen.go", source, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v\n%s", err, source)
	}
	for _, expected := range [][]byte{
		[]byte("net.HardwareAddr"),
		[]byte("envschema.PublicKeyValue"),
		[]byte("[]*x509.Certificate"),
		[]byte("big.Int"),
		[]byte("Decimal big.Rat"),
		[]byte("fs.FileMode"),
		[]byte(`WithPolicy("url.requireHost")`),
		[]byte(`LessThanVariable("BIG", "LIMIT")`),
		[]byte("new(big.Int).SetBytes"),
		[]byte("new(big.Rat).SetFrac"),
		[]byte(`DefaultTo("02:00:5e:10:00:00")`),
	} {
		if !bytes.Contains(source, expected) {
			t.Fatalf("generated source does not contain %q\n%s", expected, source)
		}
	}

	directory := t.TempDir()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	module := fmt.Sprintf("module generatedtest\n\ngo 1.26\n\nrequire github.com/depthbomb/envschema v0.0.0\n\nreplace github.com/depthbomb/envschema => %s\n", filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config_gen.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-mod=mod", ".")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated source does not compile: %v\n%s\n%s", err, output, source)
	}
}

func TestLoadPackageExecutesGoSchemaProvider(t *testing.T) {
	loaded, err := generate.LoadPackage("../example/config/schema", "")
	if err != nil {
		t.Fatalf("LoadPackage() error = %v", err)
	}
	if loaded.ProviderName != "Environment" {
		t.Fatalf("ProviderName = %q, want Environment", loaded.ProviderName)
	}
	if len(loaded.Schema.Variables) != 7 {
		t.Fatalf("loaded %d variables, want 7", len(loaded.Schema.Variables))
	}
}
