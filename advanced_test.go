package envschema_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/depthbomb/envschema"
)

func TestAdvancedRuleFamilies(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("URI", envschema.URI().RequireHost().WithHosts("example.com").CanonicalOnly()),
		envschema.Var("MAC", envschema.MACAddress()),
		envschema.Var("BIG", envschema.BigInt().Base(16).PositiveOnly().MultipleOf(2)),
		envschema.Var("DECIMAL", envschema.Decimal().GreaterThan(1).LessThan(2)),
		envschema.Var("MEDIA", envschema.MediaType().RequireMediaTypeParameters()),
		envschema.Var("MODE", envschema.FileMode()),
		envschema.Var("ULID", envschema.ULID()),
		envschema.Var("GLOB", envschema.Glob()),
	)
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"URI":     "urn://example.com/path",
		"MAC":     "02:00:5e:10:00:00",
		"BIG":     "10000000000000000000000000000000",
		"DECIMAL": "1.25",
		"MEDIA":   "application/json; charset=utf-8",
		"MODE":    "4750",
		"ULID":    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"GLOB":    "config/*.json",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	address, err := envschema.ValueAs[net.HardwareAddr](values, "MAC")
	if err != nil || address.String() != "02:00:5e:10:00:00" {
		t.Fatalf("MAC = %v, %v", address, err)
	}
	integer, err := envschema.ValueAs[big.Int](values, "BIG")
	if err != nil || integer.BitLen() < 100 {
		t.Fatalf("BIG = %v, %v", integer, err)
	}
	decimal, err := envschema.ValueAs[big.Rat](values, "DECIMAL")
	if err != nil || decimal.RatString() != "5/4" {
		t.Fatalf("DECIMAL = %v, %v", decimal, err)
	}
	mode, err := envschema.ValueAs[fs.FileMode](values, "MODE")
	if err != nil || mode.Perm() != 0o750 || mode&fs.ModeSetuid == 0 {
		t.Fatalf("MODE = %v, %v", mode, err)
	}
}

func TestAdvancedPoliciesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rule  envschema.Rule
		value string
	}{
		{"string", envschema.String().ValidUTF8().WithoutControlCharacters().SingleLine().Containing("token"), "token\n"},
		{"json duplicate", envschema.JSON().ObjectOnly().UniqueObjectKeys(), `{"a":1,"a":2}`},
		{"json keys", envschema.JSON().ObjectOnly().RequiredKeys("name").AllowedKeys("name"), `{"other":true}`},
		{"list order", envschema.List(envschema.String()).StrictlySorted(), "a,a"},
		{"host suffix", envschema.Host().WithDomainSuffix(".example.com"), "example.net"},
		{"private IP", envschema.IPAddress().PrivateOnly(), "8.8.8.8"},
		{"canonical CIDR", envschema.CIDR().CanonicalOnly(), "10.0.0.1/24"},
		{"endpoint port", envschema.Endpoint().NonZeroPort().PortBetween(1000, 2000), "example.com:0"},
		{"UUID version", envschema.UUID().Versions(envschema.UUIDv7).NonNil().RFC9562VariantOnly(), "550e8400-e29b-41d4-a716-446655440000"},
		{"semver prerelease", envschema.SemVer().WithoutPrerelease(), "1.2.3-beta.1"},
		{"base64 bytes", envschema.Base64().ExactlyDecodedBytes(4), "YWJj"},
		{"timestamp offset", envschema.Timestamp().RequireOffset().WithoutFractionalSeconds(), "2026-01-02T03:04:05Z"},
		{"media parameters", envschema.MediaType().WithoutMediaTypeParameters(), "text/plain; charset=utf-8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := envschema.Must(envschema.Var("VALUE", test.rule))
			if _, err := envschema.LoadFrom(schema, lookup(map[string]string{"VALUE": test.value})); err == nil {
				t.Fatalf("LoadFrom() accepted %q", test.value)
			}
		})
	}
}

func TestStringItemPoliciesApplyInsideCollections(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(envschema.Var("VALUES", envschema.List(envschema.String().Containing("ok"))))
	if _, err := envschema.LoadFrom(schema, lookup(map[string]string{"VALUES": "ok,bad"})); err == nil {
		t.Fatal("LoadFrom() ignored the nested string policy")
	}
}

func TestCollectionPoliciesUseParsedItemValues(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("ORDERED", envschema.List(envschema.Int()).StrictlySorted()),
		envschema.Var("DISTINCT", envschema.List(envschema.Int()).AtLeastDistinctItems(2)),
	)
	if _, err := envschema.LoadFrom(schema, lookup(map[string]string{"ORDERED": "2,10", "DISTINCT": "1,2"})); err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if _, err := envschema.LoadFrom(schema, lookup(map[string]string{"ORDERED": "10,2", "DISTINCT": "1,2"})); err == nil {
		t.Fatal("LoadFrom() accepted numerically unsorted values")
	}
	if _, err := envschema.LoadFrom(schema, lookup(map[string]string{"ORDERED": "2,10", "DISTINCT": "1,01"})); err == nil {
		t.Fatal("LoadFrom() counted equivalent parsed integers as distinct")
	}
}

func TestPolicyMetadataIsValidated(t *testing.T) {
	t.Parallel()

	tests := []envschema.Rule{
		envschema.Int().WithPolicy("number.base", "1"),
		envschema.JSON().WithPolicy("json.maxDepth"),
		envschema.Endpoint().WithPolicy("endpoint.portBounds", "1"),
		envschema.UUID().Versions(envschema.UUIDVersion("9")),
		envschema.Boolean().TrueValues("yes").FalseValues("YES"),
	}
	for _, rule := range tests {
		if _, err := envschema.New(envschema.Var("VALUE", rule)); err == nil {
			t.Fatalf("New() accepted malformed policies %#v", rule.Policies)
		}
	}
}

func TestAdvancedSchemaJSONRoundTrip(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("URI", envschema.URI().RequireHost().WithoutUserPassword()),
		envschema.Var("BIG", envschema.BigInt().Base(16)),
	).EqualValues("URI", "BIG")
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded envschema.Schema
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if _, exists := decoded.Variables[0].Rule.Policies["url.requireHost"]; !exists {
		t.Fatalf("URI policies were not preserved: %s", encoded)
	}
}

func TestAdvancedConstraints(t *testing.T) {
	t.Parallel()

	schema := envschema.Must(
		envschema.Var("MODE", envschema.String()),
		envschema.Var("A", envschema.Int().Optional()),
		envschema.Var("B", envschema.Int().Optional()),
		envschema.Var("C", envschema.String().Optional()),
	).ForbiddenWhen("MODE", "locked", "C").RequiredUnless("MODE", "open", "A").RequiredIfPresent("A", "B").LessThanVariable("A", "B")

	_, err := envschema.LoadFrom(schema, lookup(map[string]string{"MODE": "locked", "A": "1", "B": "2", "C": "set"}))
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("forbidden constraint error = %v", err)
	}
	_, err = envschema.LoadFrom(schema, lookup(map[string]string{"MODE": "closed", "A": "3", "B": "2"}))
	if err == nil || !strings.Contains(err.Error(), "less than") {
		t.Fatalf("comparison constraint error = %v", err)
	}
}

func TestPublicKeyCertificateBundleAndTLSConstraint(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	schema := envschema.Must(
		envschema.Var("CERT", envschema.Certificate().CurrentlyValid().ForHostname("example.com").ServerAuth().RSAOnly().AtLeastRSABits(2048)),
		envschema.Var("BUNDLE", envschema.CertificateBundle().AllowedBlockTypes("CERTIFICATE").LeafOnly()),
		envschema.Var("PUBLIC", envschema.PublicKey().RSAOnly().AtLeastRSABits(2048)),
		envschema.Var("PRIVATE", envschema.PrivateKey().PKCS8Only().RSAOnly().AtLeastRSABits(2048)),
	).TLSKeyPair("CERT", "PRIVATE")
	values, err := envschema.LoadFrom(schema, lookup(map[string]string{
		"CERT":    string(certificatePEM),
		"BUNDLE":  string(certificatePEM) + string(certificatePEM),
		"PUBLIC":  string(publicPEM),
		"PRIVATE": string(privatePEM),
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	bundle, err := envschema.ValueAs[[]*x509.Certificate](values, "BUNDLE")
	if err != nil || len(bundle) != 2 {
		t.Fatalf("bundle = %v, %v", len(bundle), err)
	}
	publicKey, err := envschema.ValueAs[envschema.PublicKeyValue](values, "PUBLIC")
	if err != nil || publicKey.Key() == nil {
		t.Fatalf("public key = %v, %v", publicKey.Key(), err)
	}
}
