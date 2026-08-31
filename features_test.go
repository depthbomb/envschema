package envschema_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

type customLevel string

func (level *customLevel) UnmarshalText(value []byte) error {
	if string(value) != "info" && string(value) != "debug" {
		return fmt.Errorf("invalid level")
	}
	*level = customLevel(value)

	return nil
}

func TestNewRuleFamilies(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("EMPTY", envschema.String().AllowEmpty()),
		envschema.Var("TEXT", envschema.String().WithPrefix("app_").WithSuffix("_id").ASCIIOnly().WithoutWhitespace()),
		envschema.Var("UINT", envschema.Uint().GreaterThan(0).MultipleOf(4)),
		envschema.Var("CIDR", envschema.CIDR().IPVersionIs(envschema.IPv4)),
		envschema.Var("ENDPOINT", envschema.Endpoint()),
		envschema.Var("TIMESTAMP", envschema.Timestamp().UTCOnly()),
		envschema.Var("CLOCK", envschema.TimeOfDay()),
		envschema.Var("MAP", envschema.Map(envschema.String(), envschema.Int()).AtLeastItems(2)),
		envschema.Var("PATTERN", envschema.Regexp()),
		envschema.Var("VALUES", envschema.List(envschema.String()).ExactlyItems(2)),
		envschema.Var("MODE", envschema.OneOf("development", "production").CaseInsensitive().Alias("prod", "production")),
		envschema.Var("DURATION", envschema.Duration().AtLeastDuration(time.Second).AtMostDuration(time.Minute)),
	)
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"EMPTY":     "",
		"TEXT":      "app_worker_id",
		"UINT":      "8",
		"CIDR":      "10.0.0.0/8",
		"ENDPOINT":  "example.com:443",
		"TIMESTAMP": "2026-08-29T12:00:00Z",
		"CLOCK":     "12:30:45",
		"MAP":       "workers=4,retries=2",
		"PATTERN":   `^api-[0-9]+$`,
		"VALUES":    "a,b",
		"MODE":      "PROD",
		"DURATION":  "5s",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	assertValue(t, values, "EMPTY", "")
	assertValue(t, values, "UINT", uint64(8))
	assertValue(t, values, "CIDR", netip.MustParsePrefix("10.0.0.0/8"))
	assertValue(t, values, "MODE", "production")

	parsedMap, err := envschema.ValueAs[map[string]int64](values, "MAP")
	if err != nil || parsedMap["workers"] != 4 || parsedMap["retries"] != 2 {
		t.Fatalf("ValueAs[map]() = %v, %v", parsedMap, err)
	}
	pattern, err := envschema.ValueAs[*regexp.Regexp](values, "PATTERN")
	if err != nil || !pattern.MatchString("api-12") {
		t.Fatalf("ValueAs[*regexp.Regexp]() = %v, %v", pattern, err)
	}
}

func TestFallbacksAndConstraints(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("TOKEN", envschema.Secret().Optional()).FallbackTo("OLD_TOKEN"),
		envschema.Var("USER", envschema.String().Optional()),
		envschema.Var("PASSWORD", envschema.Secret().Optional()),
		envschema.Var("MODE", envschema.OneOf("local", "remote")),
	).ExactlyOneOf("TOKEN", "USER").RequiredTogether("USER", "PASSWORD").RequiredWhen("MODE", "remote", "TOKEN")
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{"OLD_TOKEN": "secret", "MODE": "remote"}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	secret, err := envschema.ValueAs[envschema.SecretValue](values, "TOKEN")
	if err != nil || secret.Release() != "secret" {
		t.Fatalf("fallback secret = %v, %v", secret, err)
	}

	_, err = envschema.LoadFrom(schema, lookup(map[string]string{"USER": "me", "MODE": "local"}))
	if err == nil || !strings.Contains(err.Error(), "defined together") {
		t.Fatalf("constraint error = %v", err)
	}
}

func TestCustomTextRule(t *testing.T) {
	t.Parallel()

	rule := envschema.Custom[customLevel]()
	value, present, err := envschema.ReadText[customLevel](rule, "LEVEL", lookup(map[string]string{"LEVEL": "debug"}))
	if err != nil || !present || value != "debug" {
		t.Fatalf("ReadText() = %q, %v, %v", value, present, err)
	}
}

func TestCryptographicRules(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	schema := envschema.Must(
		envschema.Var("PEM", envschema.PEM()),
		envschema.Var("CERT", envschema.Certificate()),
		envschema.Var("KEY", envschema.PrivateKey()),
	)
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{"PEM": string(certificatePEM), "CERT": string(certificatePEM), "KEY": string(keyPEM)}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	certificate, err := envschema.ValueAs[*x509.Certificate](values, "CERT")
	if err != nil || certificate.Subject.CommonName != "test" {
		t.Fatalf("certificate = %v, %v", certificate, err)
	}
	secret, err := envschema.ValueAs[envschema.SecretValue](values, "KEY")
	if err != nil || secret.String() != "[redacted]" {
		t.Fatalf("private key = %v, %v", secret, err)
	}
}

func TestStrictNumericAndURLRules(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("NUMBER", envschema.Int().PositiveOnly().LessThan(10)),
		envschema.Var("URL", envschema.URL().HTTPSOnly().WithoutCredentials().RequirePort().WithoutQuery().WithoutFragment()),
	)
	_, err := envschema.LoadFrom(schema, lookup(map[string]string{"NUMBER": "4", "URL": "https://example.com:443/path"}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	_, err = envschema.LoadFrom(schema, lookup(map[string]string{"NUMBER": "0", "URL": "https://example.com:443/path"}))
	if err == nil {
		t.Fatal("PositiveOnly accepted zero")
	}
}

func TestRelativeURLAndStrictBoolean(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("URL", envschema.URL().RelativeOnly()),
		envschema.Var("BOOL", envschema.Boolean().Strict()),
	)
	_, err := envschema.LoadFrom(schema, lookup(map[string]string{"URL": "/health?full=true", "BOOL": "true"}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	_, err = envschema.LoadFrom(schema, lookup(map[string]string{"URL": "https://example.com", "BOOL": "yes"}))
	if err == nil {
		t.Fatal("strict or relative rule accepted invalid input")
	}
}

func TestSchemaRejectsInvalidOptionsAndDefaults(t *testing.T) {
	t.Parallel()

	for _, variable := range []envschema.Variable{
		envschema.Var("VALUE", envschema.Int().WithPrefix("x")),
		envschema.Var("VALUE", envschema.String().UniqueItems()),
		envschema.Var("VALUE", envschema.Duration().AtLeastDuration(time.Minute).AtMostDuration(time.Second)),
		envschema.Var("VALUE", envschema.Int().DefaultTo("not-an-integer")),
		envschema.Var("VALUE", envschema.OneOf("a").Alias("b", "missing")),
	} {
		if _, err := envschema.New(variable); err == nil {
			t.Fatalf("New(%+v) error = nil", variable.Rule)
		}
	}
}
